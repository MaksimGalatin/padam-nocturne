"""Studio, обзор: пока сервер запускается, карточки показывают «…» и запрос повторяется — не «0», будто память пропала."""
import threading

import pytest

from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store

pw = pytest.importorskip("playwright.sync_api")


def test_обзор_дожидается_сервера(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "ov.db"))
    for i in range(3):
        m.remember(f"Запись номер {i} про чай и книги", kind="fact", origin="user")
    srv, url = make_studio_server(m, port=0)
    исходный = srv.RequestHandlerClass.do_GET
    счёт = {"n": 0}

    def стартующий(self):
        if self.path.startswith("/overview"):
            счёт["n"] += 1
            if счёт["n"] <= 2:
                self.send_response(503); self.send_header("Content-Length", "0"); self.end_headers(); return
        return исходный(self)

    srv.RequestHandlerClass.do_GET = стартующий
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pw.sync_playwright() as p:
            br = p.chromium.launch()
            page = br.new_page()
            page.goto(url, wait_until="domcontentloaded")
            первое = page.locator("#kpi-active").inner_text()
            assert первое in ("…", "3"), первое          # никогда не «0» до ответа
            page.evaluate("() => switchTab('overview')")
            page.wait_for_function("() => document.querySelector('#kpi-active').textContent === '3'", timeout=15000)
            assert счёт["n"] >= 3                          # были повторы после 503
            br.close()
    finally:
        srv.RequestHandlerClass.do_GET = исходный
        srv.shutdown(); srv.server_close(); m.close()
