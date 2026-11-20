# -*- coding: utf-8 -*-
"""JS Supply-Chain & Crypto-Clipper Guard — защита от подмены скриптов CDN (кейс Optimizely и 32 банков).

Проверяет целевой сайт (или оффлайн HTML/заголовки/скрипты за $0):
1. Сторонние <script src> без Subresource Integrity (integrity="sha384-...") и crossorigin.
2. Отсутствие или слабость Content-Security-Policy ('unsafe-inline', 'unsafe-eval', *, http:/data:).
3. Мониторинг дрейфа SHA-256 эталонов CDN-скриптов (shield_js_baselines): ловит подмену содержимого без смены URL.
4. Сигнатуры Crypto-Clipper (подмена кошельков в буфере/провайдерах), Magecart-скиммеров карт и обфусцированных лоадеров.
5. Автогенерация точных HTML-патчей (<script integrity="sha384-...">) и строгого заголовка CSP + 1-страничный чекап для клиента.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import html as _html
from html.parser import HTMLParser
import json
import os
import re
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid

from . import net_guard

_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS shield_js_baselines (
    domain TEXT NOT NULL,
    script_url TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    sri_sha384 TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_hash_changed_at TEXT,
    PRIMARY KEY (domain, script_url)
);
CREATE TABLE IF NOT EXISTS shield_supply_scans (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shield_header_baselines (
    domain TEXT NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_changed_at TEXT,
    PRIMARY KEY (domain, header_name)
);
"""

# Вендоры, компрометация CDN которых даёт массовую атаку на посетителей (Optimizely, тег-менеджеры, платёжные виджеты)
_HIGH_RISK_VENDOR_HOSTS = (
    "optimizely.com",
    "googletagmanager.com",
    "google-analytics.com",
    "segment.com",
    "segment.io",
    "launchdarkly.com",
    "visualwebsiteoptimizer.com",
    "vwo.com",
    "hotjar.com",
    "intercom.io",
    "intercomcdn.com",
    "zendesk.com",
    "zdassets.com",
    "clarity.ms",
    "amplitude.com",
    "mixpanel.com",
    "stripe.com",
    "paypal.com",
    "braintreegateway.com",
    "adyen.com",
    "polyfill.io",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
)

_MAX_SCRIPT_BYTES = 2 * 1024 * 1024
_MAX_HTML_BYTES = 2 * 1024 * 1024

_CLIPPER_RE = re.compile(
    r"(?:navigator\.clipboard\.writeText|execCommand\s*\(\s*['\"]copy['\"]|"
    r"on(?:copy|paste)\s*=|clipboardData\.setData)",
    re.IGNORECASE,
)
_CRYPTO_HINT_RE = re.compile(
    r"(?:\b0x[a-fA-F0-9]{40}\b|\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,62}\b|"
    r"ethereum\.request|solana\.(?:sign|send)|walletAddress|cryptoWallet|recipientAddress)",
    re.IGNORECASE,
)
_SKIMMER_FIELD_RE = re.compile(
    r"(?:cardnumber|card_number|cc-number|creditcard|cvv|cvc|card_exp|billing)",
    re.IGNORECASE,
)
_EXFIL_SINK_RE = re.compile(
    r"(?:navigator\.sendBeacon|fetch\s*\(|XMLHttpRequest|new\s+WebSocket\s*\(|new\s+Image\s*\(\s*\)\.src)",
    re.IGNORECASE,
)
_OBFUSCATED_DROPPER_RE = re.compile(
    r"(?:eval\s*\(\s*atob\s*\(|Function\s*\(\s*atob\s*\(|document\.write\s*\(\s*unescape\s*\(|"
    r"String\.fromCharCode\s*\([^)]{20,}\).{0,80}\beval\s*\()",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_tables(memory: Any) -> None:
    if memory is None:
        return
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_supply_guard_ready", False):
        return
    with store._lock:
        store.conn.executescript(_SCHEMA_DDL)
        store.conn.commit()
        store._supply_guard_ready = True


class _ScriptAndCspParser(HTMLParser):
    """Извлекает теги <script>, мета-CSP и ссылки без regex-разбора HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict[str, Any]] = []
        self.hidden_iframes: list[dict[str, str]] = []
        self.meta_csps: list[str] = []
        self._in_script = False
        self._cur_script: dict[str, Any] | None = None
        self._inline_buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        amap = {str(k).lower(): ("" if v is None else str(v)) for k, v in attrs}
        if t == "meta":
            if amap.get("http-equiv", "").strip().lower() == "content-security-policy":
                c = amap.get("content", "").strip()
                if c:
                    self.meta_csps.append(c)
        elif t == "iframe":
            st = amap.get("style", "").lower()
            w_attr = amap.get("width", "").strip()
            h_attr = amap.get("height", "").strip()
            if ("display:none" in st.replace(" ", "") or "opacity:0" in st.replace(" ", "")
                    or w_attr in ("0", "0px", "1", "1px") or h_attr in ("0", "0px", "1", "1px")):
                self.hidden_iframes.append({"src": amap.get("src", "")[:200], "style": st[:120]})
        elif t == "script":
            self._in_script = True
            self._inline_buf = []
            self._cur_script = {
                "src": amap.get("src", "").strip(),
                "integrity": amap.get("integrity", "").strip(),
                "crossorigin": amap.get("crossorigin", None),
                "type": amap.get("type", "").strip(),
                "async": "async" in amap,
                "defer": "defer" in amap,
            }

    def handle_data(self, data: str) -> None:
        if self._in_script and data:
            self._inline_buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script and self._cur_script is not None:
            inline = "".join(self._inline_buf)
            self._cur_script["inline_len"] = len(inline)
            self._cur_script["inline_text"] = inline if not self._cur_script["src"] else ""
            self.scripts.append(self._cur_script)
            self._in_script = False
            self._cur_script = None
            self._inline_buf = []


def _parse_csp(csp_value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in str(csp_value or "").split(";"):
        toks = part.strip().split()
        if not toks:
            continue
        directives[toks[0].lower()] = toks[1:]
    return directives


def _host_matches_domain(host: str, base_host: str) -> bool:
    h = (host or "").lower().split(":")[0]
    b = (base_host or "").lower().split(":")[0]
    return bool(h and b and (h == b or h.endswith("." + b)))


def _is_high_risk_vendor(host: str) -> bool:
    low = (host or "").lower()
    return any(low == v or low.endswith("." + v) for v in _HIGH_RISK_VENDOR_HOSTS)


def _compute_sri_and_sha256(raw: bytes) -> tuple[str, str]:
    sha256_hex = hashlib.sha256(raw).hexdigest()
    sha384_b64 = base64.b64encode(hashlib.sha384(raw).digest()).decode("ascii")
    return sha256_hex, f"sha384-{sha384_b64}"


def _verify_declared_integrity(declared: str, raw: bytes) -> bool:
    """Проверяет, совпадает ли хотя бы один алгоритм из атрибута integrity с фактическими байтами."""
    tokens = [tok.strip() for tok in str(declared or "").split() if "-" in tok]
    if not tokens:
        return False
    for tok in tokens:
        alg, b64_val = tok.split("-", 1)
        alg = alg.lower()
        if alg == "sha256":
            got = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")
        elif alg == "sha384":
            got = base64.b64encode(hashlib.sha384(raw).digest()).decode("ascii")
        elif alg == "sha512":
            got = base64.b64encode(hashlib.sha512(raw).digest()).decode("ascii")
        else:
            continue
        if got == b64_val.strip():
            return True
    return False


def _scan_js_for_threats(js_text: str, source_label: str) -> list[dict[str, str]]:
    """Ищет в JS-коде признаки крипто-клипперов, скиммеров и скрытых загрузчиков."""
    findings: list[dict[str, str]] = []
    if not js_text:
        return findings
    if _CLIPPER_RE.search(js_text) and _CRYPTO_HINT_RE.search(js_text):
        findings.append({
            "code": "crypto_clipper_signature",
            "severity": "critical",
            "source": source_label,
            "detail": "Обнаружен доступ к буферу обмена/кошельку рядом с шаблоном криптоадресов (риск Crypto-Clipper).",
        })
    if _SKIMMER_FIELD_RE.search(js_text) and _EXFIL_SINK_RE.search(js_text):
        findings.append({
            "code": "payment_skimmer_signature",
            "severity": "critical",
            "source": source_label,
            "detail": "Обнаружено чтение полей банковской карты рядом с сетевой отправкой (риск Magecart-скиммера).",
        })
    if _OBFUSCATED_DROPPER_RE.search(js_text):
        findings.append({
            "code": "obfuscated_js_loader",
            "severity": "high",
            "source": source_label,
            "detail": "Обфусцированный динамический загрузчик кода (eval/atob/unescape).",
        })
    if re.search(r"(?:document\.forms\[[^\]]+\]\.action\s*=|\.action\s*=\s*['\"]https?:|XMLHttpRequest\.prototype\.open\s*=|window\.fetch\s*=)", js_text, re.I):
        findings.append({
            "code": "dom_hook_or_form_hijack",
            "severity": "critical",
            "source": source_label,
            "detail": "Обнаружен перехват window.fetch/XMLHttpRequest или подмена form.action в DOM (вектор скрытой эксфильтрации).",
        })
    if re.search(r"new\s+WebSocket\s*\(\s*['\"]wss?://", js_text, re.I) and _SKIMMER_FIELD_RE.search(js_text):
        findings.append({
            "code": "websocket_exfil_channel",
            "severity": "critical",
            "source": source_label,
            "detail": "Создаётся WebSocket-канал рядом с платёжными полями — риск потоковой эксфильтрации.",
        })
    return findings


def _grade(score: int) -> str:
    if score >= 95:
        return "S"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _build_recommendations(
    base_host: str,
    third_party_scripts: list[dict[str, Any]],
    csp_present: bool,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    sri_patches: list[dict[str, str]] = []
    allowed_origins: set[str] = {"'self'"}
    for sc in third_party_scripts:
        origin = sc.get("origin")
        if origin:
            allowed_origins.add(origin)
        if not sc.get("has_sri") or sc.get("hash_changed") or sc.get("sri_mismatch"):
            sri_val = sc.get("computed_sri_sha384") or "sha384-<ВЫЧИСЛИТЕ_ХЭШ_СКРИПТА>"
            tag = (
                f'<script src="{_html.escape(sc["url"], quote=True)}" '
                f'integrity="{sri_val}" crossorigin="anonymous"></script>'
            )
            sri_patches.append({
                "script_url": sc["url"],
                "host": sc.get("host", ""),
                "patch_html": tag,
            })
    origins_str = " ".join(sorted(allowed_origins))
    recommended_csp = (
        f"Content-Security-Policy: default-src 'self'; "
        f"script-src {origins_str}; "
        f"object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests"
    )
    summary_actions: list[str] = []
    if not csp_present:
        summary_actions.append("Внедрить строгий HTTP-заголовок Content-Security-Policy без 'unsafe-inline' и 'unsafe-eval'.")
    elif any(f["code"] in ("csp_unsafe_inline", "csp_unsafe_eval", "csp_wildcard_script") for f in findings):
        summary_actions.append("Удалить 'unsafe-inline', 'unsafe-eval' и '*' из директивы script-src в CSP.")
    if sri_patches:
        summary_actions.append(
            f"Закрепить integrity (SRI sha384) и crossorigin='anonymous' на {len(sri_patches)} сторонних скриптах."
        )
    if any(f["code"] == "cdn_script_hash_changed" for f in findings):
        summary_actions.append(
            "СРОЧНО: обнаружено изменение хэша CDN-скрипта без смены URL — немедленно сравнить diff на CDN и заблокировать загрузку до проверки!"
        )
    return {
        "recommended_csp_header": recommended_csp,
        "sri_script_patches": sri_patches[:25],
        "actions": summary_actions,
    }


def render_supply_chain_html(report: dict[str, Any]) -> str:
    """Формирует автономный 1-страничный HTML-чекап для клиента / CISO."""
    url = _html.escape(str(report.get("url") or ""))
    grade = _html.escape(str(report.get("grade") or "F"))
    score = int(report.get("score") or 0)
    checked_at = _html.escape(str(report.get("checked_at") or ""))

    findings = report.get("findings") or []
    f_rows = "".join(
        "<tr>"
        f"<td><b>{_html.escape(str(f.get('severity', '')).upper())}</b></td>"
        f"<td><code>{_html.escape(str(f.get('code', '')))}</code></td>"
        f"<td>{_html.escape(str(f.get('source', '')))}</td>"
        f"<td>{_html.escape(str(f.get('detail', '')))}</td>"
        "</tr>"
        for f in findings[:40]
    ) or "<tr><td colspan='4'>Критических проблем цепочки поставки JS не выявлено.</td></tr>"

    scripts = report.get("third_party_scripts") or []
    s_rows = "".join(
        "<tr>"
        f"<td><code>{_html.escape(str(s.get('url', '')))}</code></td>"
        f"<td>{'Да' if s.get('has_sri') else 'НЕТ'}</td>"
        f"<td>{'Да' if s.get('high_risk_vendor') else 'Обычный'}</td>"
        f"<td><code>{_html.escape(str(s.get('sha256') or '—')[:16])}</code></td>"
        f"<td>{'ИЗМЕНЁН!' if s.get('hash_changed') else ('Эталон' if s.get('baseline_status') == 'pinned' else 'OK')}</td>"
        "</tr>"
        for s in scripts[:40]
    ) or "<tr><td colspan='5'>Сторонние скрипты не обнаружены.</td></tr>"

    rec = report.get("recommendations") or {}
    csp_line = _html.escape(str(rec.get("recommended_csp_header") or ""))
    patches = "".join(
        f"<li><pre>{_html.escape(str(p.get('patch_html', '')))}</pre></li>"
        for p in (rec.get("sri_script_patches") or [])[:15]
    )

    return (
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        f"<title>JS Supply-Chain &amp; SRI/CSP Audit: {url}</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:980px;margin:28px auto;padding:0 16px;color:#0f172a;line-height:1.5}"
        "h1,h2{margin-top:22px}table{width:100%;border-collapse:collapse;margin-top:10px}"
        "th,td{border:1px solid #cbd5e1;padding:8px;text-align:left;vertical-align:top;font-size:13px}"
        "th{background:#f1f5f9}pre,code{background:#f8fafc;padding:2px 4px;border-radius:4px;font-size:12px;overflow-wrap:anywhere}"
        "pre{padding:10px;border:1px solid #e2e8f0;white-space:pre-wrap}.badge{display:inline-block;padding:4px 10px;border-radius:6px;background:#0f172a;color:#fff;font-weight:700}</style>"
        "</head><body>"
        f"<h1>PADAM Agentic Shield — JS Supply-Chain &amp; SRI/CSP Чекап</h1>"
        f"<p><b>Цель:</b> {url} &nbsp;|&nbsp; <b>Оценка:</b> <span class='badge'>{grade} ({score}/100)</span>"
        f" &nbsp;|&nbsp; <b>Дата (UTC):</b> {checked_at}</p>"
        f"<p><b>Сторонних скриптов:</b> {report.get('third_party_count', 0)} · "
        f"<b>Без SRI (integrity):</b> {report.get('missing_sri_count', 0)} · "
        f"<b>Смен хэша CDN:</b> {report.get('hash_changed_count', 0)} · "
        f"<b>Сигнатур скиммеров/клипперов:</b> {report.get('malware_signatures_count', 0)}</p>"
        "<h2>Обнаруженные риски</h2>"
        f"<table><thead><tr><th>Уровень</th><th>Код</th><th>Источник</th><th>Описание</th></tr></thead><tbody>{f_rows}</tbody></table>"
        "<h2>Инвентаризация сторонних скриптов (CDN / Vendor Guard)</h2>"
        f"<table><thead><tr><th>Script URL</th><th>SRI</th><th>Риск вендора</th><th>SHA-256</th><th>Целостность</th></tr></thead><tbody>{s_rows}</tbody></table>"
        "<h2>Готовые патчи защиты (Remediation)</h2>"
        f"<p><b>Рекомендуемый заголовок CSP:</b></p><pre>{csp_line}</pre>"
        + (f"<p><b>Готовые теги &lt;script&gt; с SRI:</b></p><ol>{patches}</ol>" if patches else "")
        + "<hr><p><small>Отчёт сформирован локальным двигателем PADAM Agentic Shield ($0, без передачи секретов в облако).</small></p></body></html>"
    )


def analyze_supply_chain_snapshot(
    url: str,
    html_text: str,
    *,
    headers: dict[str, str] | None = None,
    script_bodies: dict[str, str | bytes] | None = None,
    memory: Any = None,
) -> dict[str, Any]:
    """Оффлайн и детерминированный аудит HTML + заголовков + тел скриптов на Supply-Chain / SRI / CSP / Clipper."""
    _ensure_tables(memory)
    parsed_base = urllib.parse.urlsplit(str(url or "https://example.com/"))
    base_host = parsed_base.netloc.lower()
    base_scheme = parsed_base.scheme or "https"
    domain = base_host.split(":")[0] or "unknown"

    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    parser = _ScriptAndCspParser()
    parser.feed(str(html_text or ""))
    parser.close()

    findings: list[dict[str, str]] = []
    score = 100
    checked_at = _utc_now()

    # 1. Анализ HTTPS и заголовков безопасности
    if base_scheme == "http" and domain not in ("127.0.0.1", "localhost"):
        score -= 15
        findings.append({
            "code": "insecure_http_transport",
            "severity": "high",
            "source": url,
            "detail": "Страница открывается по незашифрованному HTTP — возможна подмена любого JS-скрипта в пути (MITM).",
        })

    csp_val = hdrs.get("content-security-policy") or (parser.meta_csps[0] if parser.meta_csps else "")
    csp_present = bool(csp_val.strip())
    if not csp_present:
        score -= 22
        findings.append({
            "code": "missing_csp",
            "severity": "high",
            "source": "HTTP Headers",
            "detail": "Отсутствует заголовок Content-Security-Policy (CSP): браузер не ограничивает загрузку и выполнение скриптов.",
        })
    else:
        dirs = _parse_csp(csp_val)
        script_src = dirs.get("script-src") or dirs.get("default-src") or []
        if not script_src:
            score -= 12
            findings.append({
                "code": "csp_missing_script_src",
                "severity": "medium",
                "source": "Content-Security-Policy",
                "detail": "В политике CSP не задана директива script-src или default-src.",
            })
        if "'unsafe-inline'" in script_src:
            score -= 10
            findings.append({
                "code": "csp_unsafe_inline",
                "severity": "high",
                "source": "Content-Security-Policy",
                "detail": "CSP разрешает 'unsafe-inline' в script-src — упрощает XSS и подмену DOM.",
            })
        if "'unsafe-eval'" in script_src:
            score -= 8
            findings.append({
                "code": "csp_unsafe_eval",
                "severity": "medium",
                "source": "Content-Security-Policy",
                "detail": "CSP разрешает 'unsafe-eval' — возможен запуск обфусцированных пейлоадов через eval/Function.",
            })
        if "*" in script_src or "http:" in script_src or "data:" in script_src:
            score -= 12
            findings.append({
                "code": "csp_wildcard_script",
                "severity": "high",
                "source": "Content-Security-Policy",
                "detail": "CSP допускает wildcard '*', 'http:' или 'data:' для скриптов — защита от посторонних JS ослаблена.",
            })

    if "strict-transport-security" not in hdrs and base_scheme == "https":
        score -= 4
        findings.append({
            "code": "missing_hsts",
            "severity": "low",
            "source": "HTTP Headers",
            "detail": "Отсутствует заголовок Strict-Transport-Security (HSTS).",
        })
    if hdrs.get("x-content-type-options", "").lower() != "nosniff":
        score -= 3
        findings.append({
            "code": "missing_xcto_nosniff",
            "severity": "low",
            "source": "HTTP Headers",
            "detail": "Отсутствует X-Content-Type-Options: nosniff.",
        })

    # 2. Инвентаризация скриптов, проверка SRI, дрейфа хэшей CDN и сигнатур скиммеров/клипперов
    bodies_map = {str(k): (v.encode("utf-8", "replace") if isinstance(v, str) else bytes(v))
                  for k, v in (script_bodies or {}).items()}

    third_party_scripts: list[dict[str, Any]] = []
    missing_sri_count = 0
    hash_changed_count = 0
    malware_signatures_count = 0
    inline_count = 0

    for idx, sc in enumerate(parser.scripts):
        src = sc["src"]
        if not src:
            inline_count += 1
            inline_txt = sc.get("inline_text") or ""
            threats = _scan_js_for_threats(inline_txt, f"inline-script#{inline_count}")
            for th in threats:
                malware_signatures_count += 1
                score -= 25 if th["severity"] == "critical" else 12
                findings.append(th)
            continue

        abs_url = urllib.parse.urljoin(f"{base_scheme}://{base_host}{parsed_base.path or '/'}", src)
        sp = urllib.parse.urlsplit(abs_url)
        s_host = sp.netloc.lower()
        is_third_party = bool(s_host and not _host_matches_domain(s_host, base_host))
        if not is_third_party:
            raw_local = bodies_map.get(abs_url) or bodies_map.get(src)
            if raw_local:
                for th in _scan_js_for_threats(raw_local.decode("utf-8", "replace"), abs_url):
                    malware_signatures_count += 1
                    score -= 25 if th["severity"] == "critical" else 12
                    findings.append(th)
            continue

        has_sri = bool(sc.get("integrity"))
        high_risk = _is_high_risk_vendor(s_host)
        raw_bytes = bodies_map.get(abs_url) or bodies_map.get(src)
        sha256_hex = None
        sri_sha384 = None
        sri_mismatch = False
        hash_changed = False
        baseline_status = "not_fetched"

        if not has_sri:
            missing_sri_count += 1
            score -= 14 if high_risk else 8
            findings.append({
                "code": "missing_sri",
                "severity": "critical" if high_risk else "high",
                "source": abs_url,
                "detail": (
                    f"Сторонний скрипт повышенного риска ({s_host}) подключён без integrity= (SRI): "
                    "при взломе CDN злоумышленник подменит код у всех посетителей (вектор Optimizely)."
                    if high_risk else
                    f"Сторонний скрипт ({s_host}) подключён без атрибута integrity= (SRI)."
                ),
            })
        elif sc.get("crossorigin") is None:
            score -= 4
            findings.append({
                "code": "sri_missing_crossorigin",
                "severity": "medium",
                "source": abs_url,
                "detail": "Есть integrity=, но отсутствует атрибут crossorigin='anonymous' (браузер отклонит или не проверит CORS SRI).",
            })

        if sp.scheme == "http":
            score -= 15
            findings.append({
                "code": "insecure_third_party_script_http",
                "severity": "critical",
                "source": abs_url,
                "detail": "Сторонний скрипт загружается по открытому HTTP.",
            })

        if raw_bytes is not None:
            sha256_hex, sri_sha384 = _compute_sri_and_sha256(raw_bytes)
            if has_sri and not _verify_declared_integrity(sc["integrity"], raw_bytes):
                sri_mismatch = True
                score -= 30
                findings.append({
                    "code": "sri_integrity_mismatch",
                    "severity": "critical",
                    "source": abs_url,
                    "detail": "Хэш загруженного скрипта НЕ СОВПАДАЕТ с указанным integrity= на странице!",
                })
            # Проверка угроз внутри внешнего JS
            for th in _scan_js_for_threats(raw_bytes.decode("utf-8", "replace"), abs_url):
                malware_signatures_count += 1
                score -= 25 if th["severity"] == "critical" else 12
                findings.append(th)

            # Baseline pinning в БД
            if memory is not None:
                store = memory.store
                with store._lock:
                    prev = store.one(
                        "SELECT sha256, first_seen FROM shield_js_baselines WHERE domain = ? AND script_url = ?",
                        (domain, abs_url),
                    )
                    if prev is None:
                        baseline_status = "pinned"
                        store.conn.execute(
                            """INSERT INTO shield_js_baselines
                               (domain, script_url, sha256, sri_sha384, first_seen, last_seen, last_hash_changed_at)
                               VALUES (?, ?, ?, ?, ?, ?, NULL)""",
                            (domain, abs_url, sha256_hex, sri_sha384, checked_at, checked_at),
                        )
                    elif str(prev["sha256"]) != sha256_hex:
                        hash_changed = True
                        hash_changed_count += 1
                        baseline_status = "changed"
                        score -= 30
                        findings.append({
                            "code": "cdn_script_hash_changed",
                            "severity": "critical",
                            "source": abs_url,
                            "detail": (
                                f"ИЗМЕНИЛСЯ SHA-256 стороннего скрипта на CDN без смены URL: "
                                f"{str(prev['sha256'])[:12]}… -> {sha256_hex[:12]}… (риск supply-chain компрометации!)."
                            ),
                        })
                        store.conn.execute(
                            """UPDATE shield_js_baselines
                               SET sha256 = ?, sri_sha384 = ?, last_seen = ?, last_hash_changed_at = ?
                               WHERE domain = ? AND script_url = ?""",
                            (sha256_hex, sri_sha384, checked_at, checked_at, domain, abs_url),
                        )
                    else:
                        baseline_status = "verified"
                        store.conn.execute(
                            "UPDATE shield_js_baselines SET last_seen = ? WHERE domain = ? AND script_url = ?",
                            (checked_at, domain, abs_url),
                        )
                    store.conn.commit()

        third_party_scripts.append({
            "url": abs_url,
            "host": s_host,
            "origin": f"{sp.scheme}://{sp.netloc}" if sp.scheme and sp.netloc else "",
            "has_sri": has_sri,
            "has_crossorigin": sc.get("crossorigin") is not None,
            "high_risk_vendor": high_risk,
            "sha256": sha256_hex,
            "computed_sri_sha384": sri_sha384,
            "sri_mismatch": sri_mismatch,
            "hash_changed": hash_changed,
            "baseline_status": baseline_status,
        })

    for hif in parser.hidden_iframes:
        score -= 15
        findings.append({
            "code": "hidden_iframe_detected",
            "severity": "high",
            "source": hif.get("src") or "DOM iframe",
            "detail": "Обнаружен скрытый <iframe> (width/height<=1, display:none или opacity:0) — возможный загрузчик скиммера/эксплойта.",
        })

    # Мониторинг дрейфа критических HTTP-заголовков безопасности (PCI DSS v4.0.1 Req 11.6.1)
    monitored_hdrs = ("content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")
    header_drift_count = 0
    if hdrs and memory is not None:
        with memory.store._lock:
            for hname in monitored_hdrs:
                hval = hdrs.get(hname, "")
                prev_h = memory.store.one(
                    "SELECT header_value FROM shield_header_baselines WHERE domain = ? AND header_name = ?",
                    (domain, hname),
                )
                if prev_h is None and hval:
                    memory.store.conn.execute(
                        """INSERT INTO shield_header_baselines (domain, header_name, header_value, first_seen, last_seen, last_changed_at)
                           VALUES (?, ?, ?, ?, ?, NULL)""",
                        (domain, hname, hval[:2000], checked_at, checked_at),
                    )
                elif prev_h is not None and str(prev_h["header_value"]) != hval:
                    header_drift_count += 1
                    score -= 18
                    findings.append({
                        "code": "http_header_tamper_drift",
                        "severity": "critical" if hname == "content-security-policy" else "high",
                        "source": hname,
                        "detail": f"Зафиксирован дрейф защитного HTTP-заголовка {hname} (требование PCI DSS v4.0.1 Req 11.6.1).",
                    })
                    memory.store.conn.execute(
                        """UPDATE shield_header_baselines SET header_value = ?, last_seen = ?, last_changed_at = ?
                           WHERE domain = ? AND header_name = ?""",
                        (hval[:2000], checked_at, checked_at, domain, hname),
                    )
                elif prev_h is not None:
                    memory.store.conn.execute(
                        "UPDATE shield_header_baselines SET last_seen = ? WHERE domain = ? AND header_name = ?",
                        (checked_at, domain, hname),
                    )
            memory.store.conn.commit()

    req_643_ok = (missing_sri_count == 0 and hash_changed_count == 0 and malware_signatures_count == 0)
    req_1161_ok = (csp_present and header_drift_count == 0 and hash_changed_count == 0)
    compliance = {
        "pci_dss_4_0_1": {
            "req_6_4_3": "pass" if req_643_ok else "action_required",
            "req_11_6_1": "pass" if req_1161_ok else "action_required",
            "header_drift_count": header_drift_count,
            "unverified_scripts_count": missing_sri_count,
        }
    }

    final_score = max(0, min(100, int(score)))
    grade = _grade(final_score)
    recommendations = _build_recommendations(base_host, third_party_scripts, csp_present, findings)

    report = {
        "ok": True,
        "url": str(url),
        "domain": domain,
        "checked_at": checked_at,
        "score": final_score,
        "grade": grade,
        "csp_present": csp_present,
        "total_scripts": len(parser.scripts),
        "inline_scripts": inline_count,
        "third_party_count": len(third_party_scripts),
        "missing_sri_count": missing_sri_count,
        "hash_changed_count": hash_changed_count,
        "header_drift_count": header_drift_count,
        "malware_signatures_count": malware_signatures_count,
        "compliance": compliance,
        "findings": findings,
        "third_party_scripts": third_party_scripts,
        "recommendations": recommendations,
    }
    report["html_report"] = render_supply_chain_html(report)

    if memory is not None:
        compact = {k: v for k, v in report.items() if k != "html_report"}
        scan_id = f"sc-{uuid.uuid4().hex[:12]}"
        report["scan_id"] = scan_id
        with memory.store._lock:
            memory.store.conn.execute(
                """INSERT INTO shield_supply_scans (id, user_id, url, domain, score, grade, summary_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, memory.user_id, str(url), domain, final_score, grade,
                 json.dumps(compact, ensure_ascii=False), checked_at),
            )
            memory.store.conn.commit()
    return report


def _fetch_bytes_safe(url: str, *, allow_localhost: bool, timeout_s: int = 10, max_bytes: int = _MAX_SCRIPT_BYTES) -> tuple[dict[str, str], bytes]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PADAM-Agentic-Shield/1.0 (+https://aifa.works)"},
        method="GET",
    )
    with net_guard.safe_urlopen(
        req,
        timeout=timeout_s,
        allow_localhost=allow_localhost,
        allow_http_localhost=allow_localhost,
        require_https=False,
    ) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            data = data[:max_bytes]
        return headers, data


def scan_url_supply_chain(
    url: str,
    *,
    memory: Any = None,
    use_playwright: bool = False,
    fetch_scripts: bool = True,
    allow_localhost: bool = False,
    timeout_s: int = 10,
) -> dict[str, Any]:
    """Сканирует живой сайт по URL (через SSRF-фильтр net_guard) и проверяет SRI, CSP, хэши CDN и скрипты."""
    if os.environ.get("PYTEST_CURRENT_TEST") and not allow_localhost:
        return {
            "ok": False,
            "skipped": True,
            "reason": "pytest_network_blocked",
            "url": str(url or ""),
        }
    raw = str(url or "").strip()
    if not raw:
        raise ValueError("Пустой URL для проверки JS Supply-Chain.")
    if "://" not in raw:
        low = raw.lower()
        scheme = "http" if (allow_localhost and (low.startswith("127.0.0.1") or low.startswith("localhost"))) else "https"
        raw = f"{scheme}://{raw}"
    clean_url = net_guard.validate_outbound_url(
        raw,
        allow_localhost=allow_localhost,
        allow_http_localhost=allow_localhost,
        require_https=False,
    )

    headers: dict[str, str] = {}
    html_text = ""
    extra_script_urls: list[str] = []

    try:
        headers, body_bytes = _fetch_bytes_safe(clean_url, allow_localhost=allow_localhost, timeout_s=timeout_s, max_bytes=_MAX_HTML_BYTES)
        html_text = body_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        return {"ok": False, "url": clean_url, "error": f"fetch_failed: {exc}"}

    if use_playwright:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    page = browser.new_page()
                    page.goto(clean_url, wait_until="domcontentloaded", timeout=timeout_s * 1000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=1500)
                    except Exception:
                        pass
                    dom_html = page.content()
                    if dom_html and len(dom_html) >= len(html_text):
                        html_text = dom_html
                    dyn_srcs = page.evaluate(
                        "() => Array.from(document.querySelectorAll('script[src]')).map(s => s.src || '')"
                    )
                    extra_script_urls = [str(u) for u in (dyn_srcs or []) if u]
                finally:
                    browser.close()
        except Exception:
            pass

    parsed_base = urllib.parse.urlsplit(clean_url)
    base_host = parsed_base.netloc.lower()
    base_scheme = parsed_base.scheme or "https"
    parser = _ScriptAndCspParser()
    parser.feed(html_text)
    parser.close()

    candidate_urls: list[str] = []
    for sc in parser.scripts:
        if sc["src"]:
            candidate_urls.append(urllib.parse.urljoin(clean_url, sc["src"]))
    for eu in extra_script_urls:
        if eu not in candidate_urls:
            candidate_urls.append(eu)

    script_bodies: dict[str, bytes] = {}
    if fetch_scripts:
        for s_url in candidate_urls[:25]:
            sp = urllib.parse.urlsplit(s_url)
            if sp.scheme not in ("http", "https"):
                continue
            if _host_matches_domain(sp.netloc, base_host) and sp.netloc.lower() == base_host:
                # Локальные скрипты при необходимости тоже проверяем на скиммеры (с лимитом до 10)
                if len(script_bodies) >= 15:
                    continue
            try:
                safe_s_url = net_guard.validate_outbound_url(
                    s_url,
                    allow_localhost=allow_localhost,
                    allow_http_localhost=allow_localhost,
                    require_https=False,
                )
                _, js_bytes = _fetch_bytes_safe(safe_s_url, allow_localhost=allow_localhost, timeout_s=min(timeout_s, 6))
                script_bodies[s_url] = js_bytes
            except Exception:
                continue

    return analyze_supply_chain_snapshot(
        clean_url,
        html_text,
        headers=headers,
        script_bodies=script_bodies,
        memory=memory,
    )


def list_recent_supply_scans(memory: Any, limit: int = 10) -> list[dict[str, Any]]:
    _ensure_tables(memory)
    rows = memory.store.query(
        "SELECT id, url, domain, score, grade, summary_json, created_at FROM shield_supply_scans "
        "WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (memory.user_id, max(1, min(50, int(limit)))),
    )
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["summary"] = json.loads(d.pop("summary_json") or "{}")
        except Exception:
            d["summary"] = {}
        out.append(d)
    return out


def supply_chain_to_sarif(report: dict[str, Any], *, target_file: str = "index.html") -> dict[str, Any]:
    """Конвертирует отчёт Supply-Chain / SRI / CSP в стандарт SARIF 2.1.0 для GitHub Security Code Scanning."""
    lvl_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in (report.get("findings") or []):
        code = str(f.get("code") or "supply_chain_issue")
        sev = str(f.get("severity") or "medium").lower()
        if code not in rules_seen:
            rules_seen[code] = {
                "id": f"PADAM-SC-{code.upper()}",
                "name": code,
                "shortDescription": {"text": str(f.get("detail") or code)[:140]},
                "defaultConfiguration": {"level": lvl_map.get(sev, "warning")},
            }
        results.append({
            "ruleId": f"PADAM-SC-{code.upper()}",
            "level": lvl_map.get(sev, "warning"),
            "message": {"text": f"{f.get('detail', '')} (source: {f.get('source', '')})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": target_file}, "region": {"startLine": 1}}}],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PADAM Agentic Shield (Supply-Chain & PCI DSS 4.0.1)",
                    "version": "0.6.5",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
        }],
    }
