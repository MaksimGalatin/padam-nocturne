"""Локальный многостраничный сканер доступности (WCAG) на базе Playwright + axe-core ($0.00)."""
from __future__ import annotations

from collections import deque
import html
import os
from pathlib import Path
from typing import Any
import urllib.parse

from . import net_guard

_IMPACT_ORDER = {"critical": 0, "serious": 1, "moderate": 2, "minor": 3}

_FALLBACK_DOM_AUDIT_JS = """
() => {
  const violations = [];
  if (!document.documentElement.getAttribute('lang')) {
    violations.push({
      id: 'html-has-lang',
      impact: 'serious',
      description: 'У тега <html> отсутствует атрибут lang.',
      help: 'Добавьте атрибут lang, например <html lang="en"> или <html lang="ru">.',
      nodes: [{ target: ['html'], html: '<html>' }]
    });
  }
  if (!document.title || !document.title.trim()) {
    violations.push({
      id: 'document-title',
      impact: 'serious',
      description: 'Страница не содержит непустого заголовка <title>.',
      help: 'Добавьте осмысленный <title> в <head>.',
      nodes: [{ target: ['head > title'], html: '<title></title>' }]
    });
  }
  const imgs = Array.from(document.querySelectorAll('img:not([alt])'));
  if (imgs.length > 0) {
    violations.push({
      id: 'image-alt',
      impact: 'critical',
      description: 'Изображения не имеют альтернативного текста alt.',
      help: 'Добавьте осмысленный атрибут alt="" каждому <img>.',
      nodes: imgs.slice(0, 5).map((el, i) => ({
        target: ['img:nth-of-type(' + (i + 1) + ')'],
        html: (el.outerHTML || '').slice(0, 160)
      }))
    });
  }
  const unlabeled = Array.from(document.querySelectorAll('input, select, textarea')).filter((el) => {
    const t = (el.getAttribute('type') || '').toLowerCase();
    if (t === 'hidden' || t === 'submit' || t === 'button') return false;
    if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby')) return false;
    if (el.id && document.querySelector('label[for="' + el.id.replace(/"/g, '\\"') + '"]')) return false;
    if (el.closest('label')) return false;
    return true;
  });
  if (unlabeled.length > 0) {
    violations.push({
      id: 'label',
      impact: 'critical',
      description: 'Поля формы не связаны с <label> или aria-label.',
      help: 'Свяжите каждое поле с <label for="..."> или добавьте aria-label.',
      nodes: unlabeled.slice(0, 5).map((el, i) => ({
        target: [el.tagName.toLowerCase() + '#' + (el.id || i)],
        html: (el.outerHTML || '').slice(0, 160)
      }))
    });
  }
  return { violations };
}
"""


def _find_axe_script() -> Path | None:
    """Возвращает путь к локальному axe.min.js, если он есть."""
    cand = Path(__file__).resolve().parent / "assets" / "axe.min.js"
    if cand.is_file() and cand.stat().st_size > 10_000:
        return cand
    return None


def _normalize_target_url(raw_url: str, *, allow_localhost: bool = False) -> str:
    """Нормализует URL сайта и проверяет его через единый SSRF-фильтр net_guard."""
    raw = str(raw_url or "").strip()
    if not raw:
        raise ValueError("Пустой URL сайта для сканирования.")
    if "://" not in raw:
        lower = raw.lower()
        scheme = "http" if (allow_localhost and (lower.startswith("127.0.0.1") or lower.startswith("localhost"))) else "https"
        raw = f"{scheme}://{raw}"
    return net_guard.validate_outbound_url(
        raw,
        allow_localhost=allow_localhost,
        allow_http_localhost=True,
        require_https=False,
    )


def _same_origin_url(base_parsed: urllib.parse.SplitResult, href: str, *, allow_localhost: bool) -> str | None:
    """Превращает href в абсолютный URL того же домена или возвращает None."""
    h = str(href or "").strip()
    if not h or h.startswith("#") or h.startswith("mailto:") or h.startswith("tel:") or h.startswith("javascript:"):
        return None
    joined = urllib.parse.urljoin(
        f"{base_parsed.scheme}://{base_parsed.netloc}{base_parsed.path or '/'}",
        h,
    )
    parsed = urllib.parse.urlsplit(joined)
    if parsed.scheme not in ("http", "https"):
        return None
    if parsed.netloc.lower() != base_parsed.netloc.lower():
        return None
    clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    try:
        return net_guard.validate_outbound_url(
            clean,
            allow_localhost=allow_localhost,
            allow_http_localhost=True,
            require_https=False,
        )
    except Exception:
        return None


_RULE_PATCH_TEMPLATES: dict[str, str] = {
    "html-has-lang": '<html lang="en"> <!-- укажите основной язык страницы -->',
    "document-title": "<title>Название компании — Главная</title>",
    "image-alt": '<img src="..." alt="Краткое описание изображения" />',
    "label": '<label for="field-id">Подпись поля</label>\n<input id="field-id" ... />',
    "color-contrast": "/* Увеличьте контраст текста минимум до 4.5:1 */\n{sel} {{ color: #111827; background-color: #ffffff; }}",
    "button-name": '<button type="button" aria-label="Понятное название действия">...</button>',
    "link-name": '<a href="..." aria-label="Куда ведёт ссылка">Понятный текст ссылки</a>',
    "landmark-one-main": '<main id="main-content"><!-- Основное содержимое страницы --></main>',
    "page-has-heading-one": "<h1>Главный заголовок страницы</h1>",
    "region": '<section aria-label="Название раздела">...</section>',
}


def build_fix_patches(issues_by_rule: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Генерирует готовые HTML/CSS-патчи по найденным нарушениям axe-core."""
    patches: list[dict[str, str]] = []
    for item in issues_by_rule[:15]:
        rid = str(item.get("id") or "")
        sel = str(item.get("sample_selector") or rid or "selector")
        tpl = _RULE_PATCH_TEMPLATES.get(
            rid,
            f"<!-- Исправьте правило {rid} для элемента {sel}: {item.get('help', '')} -->",
        )
        snippet = tpl.format(sel=sel) if "{sel}" in tpl else tpl
        patches.append({"rule_id": rid, "selector": sel, "patch": snippet})
    return patches


def _render_reports(
    target_url: str,
    pages: list[dict[str, Any]],
    issues_by_rule: list[dict[str, Any]],
    counts: dict[str, int],
) -> tuple[str, str]:
    """Строит текстовую сводку и печатный HTML-отчёт по итогам скана."""
    total_v = sum(counts.values())
    lines = [
        f"Локальный многостраничный аудит WCAG для {target_url}",
        f"Проверено страниц: {len(pages)}. Всего нарушений: {total_v} "
        f"(critical: {counts['critical']}, serious: {counts['serious']}, "
        f"moderate: {counts['moderate']}, minor: {counts['minor']}).",
    ]
    if issues_by_rule:
        lines.append("Ключевые проблемы и что исправить:")
        for idx, item in enumerate(issues_by_rule[:10], start=1):
            lines.append(
                f"{idx}. [{item['impact']}] {item['id']} — узлов: {item['nodes_count']} "
                f"(страниц: {item['pages_count']}). {item['help']}"
            )
    else:
        lines.append("Критических и видимых нарушений WCAG по проверенным страницам не выявлено.")

    rows_html = []
    for item in issues_by_rule[:20]:
        sample = html.escape(str(item.get("sample_selector") or ""))
        rows_html.append(
            "<tr>"
            f"<td><strong>{html.escape(item['id'])}</strong></td>"
            f"<td>{html.escape(item['impact'])}</td>"
            f"<td>{item['nodes_count']}</td>"
            f"<td>{html.escape(item['help'])}<br><code>{sample}</code></td>"
            "</tr>"
        )
    table_body = "\n".join(rows_html) or '<tr><td colspan="4">Нарушений не обнаружено.</td></tr>'
    html_report = (
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        f"<title>WCAG-отчёт: {html.escape(target_url)}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:920px;margin:24px auto;padding:0 16px;color:#111}"
        "table{width:100%;border-collapse:collapse;margin-top:16px}"
        "th,td{border:1px solid #d4d4d8;padding:8px;text-align:left;vertical-align:top}"
        "th{background:#f4f4f5}code{font-size:12px;color:#52525b}</style></head><body>"
        f"<h1>Технический аудит доступности WCAG: {html.escape(target_url)}</h1>"
        f"<p>Проверено страниц: <b>{len(pages)}</b> · Нарушений: <b>{total_v}</b> "
        f"(Critical: {counts['critical']}, Serious: {counts['serious']}, "
        f"Moderate: {counts['moderate']}, Minor: {counts['minor']})</p>"
        "<table><thead><tr><th>Правило</th><th>Уровень</th><th>Узлов</th><th>Рекомендация и пример</th></tr></thead>"
        f"<tbody>{table_body}</tbody></table></body></html>"
    )
    patches = build_fix_patches(issues_by_rule)
    if patches:
        lines.append("")
        lines.append("Готовые HTML/CSS-патчи (скопируй и вставь):")
        for pt in patches[:8]:
            lines.append(f"- [{pt['rule_id']}] ({pt['selector']}):\n{pt['patch']}")
        patches_html = "".join(
            f"<li><strong>{html.escape(pt['rule_id'])}</strong> (<code>{html.escape(pt['selector'])}</code>)"
            f"<pre style='background:#f4f4f5;padding:8px;border-radius:6px;overflow:auto'>{html.escape(pt['patch'])}</pre></li>"
            for pt in patches[:10]
        )
        html_report = html_report.replace(
            "</body></html>",
            f"<h2>Готовые HTML/CSS-патчи</h2><ol>{patches_html}</ol></body></html>",
        )
    return "\n".join(lines), html_report


def scan_website_accessibility(
    url: str,
    *,
    max_pages: int = 25,
    allow_localhost: bool = False,
    timeout_ms: int = 12000,
) -> dict[str, Any]:
    """Сканирует до 25 внутренних страниц сайта через Playwright + axe-core."""
    if os.environ.get("PYTEST_CURRENT_TEST") and not allow_localhost:
        return {
            "ok": False,
            "skipped": True,
            "reason": "pytest_network_blocked",
            "url": str(url or ""),
            "pages_scanned": 0,
            "total_violations": 0,
            "critical_count": 0,
            "serious_count": 0,
            "issues_by_rule": [],
            "pages": [],
            "text_summary": "",
            "html_report": "",
        }

    try:
        start_url = _normalize_target_url(url, allow_localhost=allow_localhost)
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "url": str(url or ""),
            "pages_scanned": 0,
            "total_violations": 0,
            "critical_count": 0,
            "serious_count": 0,
            "issues_by_rule": [],
            "pages": [],
            "text_summary": f"Не удалось проверить URL {url}: {exc}",
            "html_report": "",
        }

    limit_pages = max(1, min(25, int(max_pages or 25)))
    base_parsed = urllib.parse.urlsplit(start_url)
    axe_path = _find_axe_script()

    queue: deque[str] = deque([start_url])
    queued_set: set[str] = {start_url}
    visited: set[str] = set()
    pages_result: list[dict[str, Any]] = []
    agg_rules: dict[str, dict[str, Any]] = {}
    counts = {"critical": 0, "serious": 0, "moderate": 0, "minor": 0}

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return {
            "ok": False,
            "error": f"playwright_unavailable: {exc}",
            "url": start_url,
            "pages_scanned": 0,
            "total_violations": 0,
            "critical_count": 0,
            "serious_count": 0,
            "issues_by_rule": [],
            "pages": [],
            "text_summary": "",
            "html_report": "",
        }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(viewport={"width": 1280, "height": 800})
            page = context.new_page()
            while queue and len(visited) < limit_pages:
                cur_url = queue.popleft()
                if cur_url in visited:
                    continue
                visited.add(cur_url)
                page_violations: list[dict[str, Any]] = []
                page_title = ""
                try:
                    page.goto(cur_url, wait_until="domcontentloaded", timeout=timeout_ms)
                    try:
                        page.wait_for_load_state("networkidle", timeout=1500)
                    except Exception:
                        pass
                    page_title = str(page.title() or "")

                    axe_raw = None
                    if axe_path is not None:
                        try:
                            page.add_script_tag(path=str(axe_path))
                            axe_raw = page.evaluate(
                                "async () => (window.axe ? await window.axe.run(document, { resultTypes: ['violations'] }) : null)"
                            )
                        except Exception:
                            axe_raw = None
                    if not isinstance(axe_raw, dict) or not isinstance(axe_raw.get("violations"), list):
                        axe_raw = page.evaluate(_FALLBACK_DOM_AUDIT_JS)

                    raw_v = axe_raw.get("violations") if isinstance(axe_raw, dict) else []
                    for v in (raw_v or []):
                        if not isinstance(v, dict):
                            continue
                        rule_id = str(v.get("id") or "unknown")
                        impact = str(v.get("impact") or "moderate").lower()
                        if impact not in counts:
                            impact = "moderate"
                        nodes = v.get("nodes") if isinstance(v.get("nodes"), list) else []
                        node_count = max(1, len(nodes))
                        counts[impact] += node_count
                        sample_sel = ""
                        if nodes and isinstance(nodes[0], dict):
                            tgt = nodes[0].get("target")
                            if isinstance(tgt, list) and tgt:
                                sample_sel = str(tgt[0])
                        page_violations.append(
                            {
                                "id": rule_id,
                                "impact": impact,
                                "help": str(v.get("help") or v.get("description") or rule_id),
                                "nodes_count": node_count,
                                "sample_selector": sample_sel,
                            }
                        )
                        entry = agg_rules.get(rule_id)
                        if entry is None:
                            agg_rules[rule_id] = {
                                "id": rule_id,
                                "impact": impact,
                                "help": str(v.get("help") or v.get("description") or rule_id),
                                "nodes_count": node_count,
                                "pages_count": 1,
                                "sample_selector": sample_sel,
                            }
                        else:
                            entry["nodes_count"] += node_count
                            entry["pages_count"] += 1

                    # Собираем внутренние ссылки того же домена для BFS до limit_pages
                    if len(visited) + len(queue) < limit_pages * 3:
                        hrefs = page.evaluate("() => Array.from(document.querySelectorAll('a[href]')).map(a => a.getAttribute('href') || '')")
                        for href in (hrefs or [])[:80]:
                            next_url = _same_origin_url(base_parsed, str(href), allow_localhost=allow_localhost)
                            if next_url and next_url not in visited and next_url not in queued_set:
                                queued_set.add(next_url)
                                queue.append(next_url)
                except Exception as page_exc:
                    pages_result.append({"url": cur_url, "title": page_title, "error": str(page_exc), "violations": []})
                    continue

                pages_result.append(
                    {
                        "url": cur_url,
                        "title": page_title,
                        "violations_count": sum(x["nodes_count"] for x in page_violations),
                        "violations": page_violations,
                    }
                )
        finally:
            browser.close()

    issues_sorted = sorted(
        agg_rules.values(),
        key=lambda r: (_IMPACT_ORDER.get(r["impact"], 9), -int(r["nodes_count"]), r["id"]),
    )
    text_summary, html_report = _render_reports(start_url, pages_result, issues_sorted, counts)
    total_v = sum(counts.values())
    return {
        "ok": True,
        "url": start_url,
        "engine": "axe-core" if axe_path is not None else "dom-fallback",
        "pages_scanned": len(pages_result),
        "total_violations": total_v,
        "critical_count": counts["critical"],
        "serious_count": counts["serious"],
        "moderate_count": counts["moderate"],
        "minor_count": counts["minor"],
        "issues_by_rule": issues_sorted,
        "patches": build_fix_patches(issues_sorted),
        "pages": pages_result,
        "text_summary": text_summary,
        "html_report": html_report,
    }
