#!/usr/bin/env python3
"""Проверка доступности (accessibility) PADAM Studio с помощью axe-core (пункт 2.9).

Открывает все 14 экранов Studio в тёмной и светлой темах на живом сервере с демо-базой,
проверяет также открытое модальное окно быстрого добавления и требует 0 нарушений
уровня serious/critical.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from padam import api  # noqa: E402
from padam.demo import build_demo_memory  # noqa: E402

TABS = ["family", "bench", 
    "overview",
    "feed",
    "search",
    "ask",
    "review",
    "asof",
    "forget",
    "graph",
    "entities",
    "l3",
    "team",
    "backup",
    "settings",
    "quickstart",
]


def _resolve_axe_js(explicit_path: str | None) -> pathlib.Path:
    candidates = []
    if explicit_path:
        candidates.append(pathlib.Path(explicit_path))
    env_p = os.environ.get("AXE_JS_PATH", "").strip()
    if env_p:
        candidates.append(pathlib.Path(env_p))
    candidates.append(ROOT / "node_modules" / "axe-core" / "axe.min.js")
    for p in candidates:
        if p.is_file():
            return p
    raise FileNotFoundError(
        "axe.min.js not found. Install axe-core (npm install --no-save axe-core) or pass --axe-js <path>."
    )


def run_a11y_check(axe_js_path: str | None = None) -> dict:
    """Прогоняет axe-core по всем 14 экранам Studio в dark и light темах."""
    from playwright.sync_api import sync_playwright

    axe_js = _resolve_axe_js(axe_js_path).read_text(encoding="utf-8")
    issues: list[dict] = []
    checked_targets: list[str] = []

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        mem, _ = build_demo_memory(pathlib.Path(td) / "demo_a11y.db")
        try:
            mem.create_workspace("Accessibility Check Team")
        except Exception:
            pass
        srv, url = api.make_studio_server(memory=mem, port=0)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            mt = re.match(r"^(http://127\.0\.0\.1:\d+)/studio#t=(.+)$", url)
            assert mt, f"Unexpected studio URL: {url}"
            base, tok = mt.group(1), mt.group(2)

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    for theme in ("dark", "light"):
                        ctx = browser.new_context(bypass_csp=True, viewport={"width": 1360, "height": 860})
                        page = ctx.new_page()
                        page.goto(f"{base}/studio#t={tok}&lang=en&theme={theme}", wait_until="networkidle")
                        # 18.11.2026: стартовая вкладка — «Семья», мелкие вкладки свёрнуты в группы меню
                        page.wait_for_selector("#tab-family[aria-selected='true']")
                        page.add_script_tag(content=axe_js)

                        for tab in TABS:
                            page.evaluate(f"switchTab('{tab}')")  # то же, что кнопка группы или переключатель вверху
                            page.wait_for_selector(f"#panel-{tab}:not([hidden])")
                            page.wait_for_timeout(450)  # после переходов CSS, иначе контраст меряется на полупрозрачном кадре
                            res = page.evaluate("async () => await axe.run()")
                            checked_targets.append(f"{theme}:{tab}")
                            for v in res.get("violations", []):
                                if v.get("impact") in ("serious", "critical"):
                                    issues.append({
                                        "theme": theme,
                                        "tab": tab,
                                        "id": v["id"],
                                        "impact": v["impact"],
                                        "description": v.get("description"),
                                        "nodes": [n.get("target") for n in v.get("nodes", [])[:5]],
                                    })

                        # Проверка модального окна быстрого добавления
                        page.click("#btn-quick-add")
                        page.wait_for_selector("#quick-add-modal:not([hidden])")
                        page.wait_for_timeout(80)
                        res_modal = page.evaluate("async () => await axe.run()")
                        checked_targets.append(f"{theme}:quick-add-modal")
                        for v in res_modal.get("violations", []):
                            if v.get("impact") in ("serious", "critical"):
                                issues.append({
                                    "theme": theme,
                                    "tab": "quick-add-modal",
                                    "id": v["id"],
                                    "impact": v["impact"],
                                    "description": v.get("description"),
                                    "nodes": [n.get("target") for n in v.get("nodes", [])[:5]],
                                })
                        page.click("#quick-add-cancel")
                        ctx.close()
                finally:
                    browser.close()
        finally:
            srv.shutdown()
            srv.server_close()
            mem.close()

    return {
        "ok": len(issues) == 0,
        "tabs_checked": len(TABS),
        "themes_checked": ["dark", "light"],
        "scans_total": len(checked_targets),
        "violations_serious_critical": len(issues),
        "issues": issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run axe-core accessibility check on all PADAM Studio tabs & themes")
    parser.add_argument("--axe-js", default=None, help="Path to axe.min.js")
    args = parser.parse_args()
    report = run_a11y_check(args.axe_js)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
