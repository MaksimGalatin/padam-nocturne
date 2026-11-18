"""Studio, лента: запоздалый ответ на старый запрос не затирает только что сохранённую запись (18.11)."""
import threading
import time

import pytest

from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store

pw = pytest.importorskip("playwright.sync_api")


def test_запоздалый_ответ_не_затирает_новую_запись(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "race.db"))
    m.remember("Старая запись ленты", kind="fact", origin="user")
    srv, url = make_studio_server(m, port=0)
    исходный = srv.RequestHandlerClass.do_GET
    счёт = {"n": 0}

    def медленный_get(self):
        if self.path.startswith("/records?view=") and "limit=100" in self.path:
            счёт["n"] += 1
            if счёт["n"] == 1:
                time.sleep(1.5)                # первый (старый) ответ приходит последним
        return исходный(self)

    srv.RequestHandlerClass.do_GET = медленный_get
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pw.sync_playwright() as p:
            br = p.chromium.launch()
            page = br.new_page(viewport={"width": 1280, "height": 900})
            page.goto(url, wait_until="networkidle")
            счёт["n"] = 0
            page.evaluate("() => { switchTab('feed'); }")
            page.fill("#feed-new-text", "Новая запись гонка-проверка")
            page.click("#feed-new-save")
            page.wait_for_timeout(3500)       # дождаться и свежего, и запоздалого ответа
            text = page.locator("#feed-list").inner_text()
            assert "гонка-проверка" in text, "запоздалый ответ затёр новую запись"
            assert text.count("Старая запись ленты") == 1, "в ленте дубли"
            assert счёт["n"] >= 2, "сценарий гонки не сложился"
            br.close()
    finally:
        srv.RequestHandlerClass.do_GET = исходный     # подмена не должна протечь в другие тесты (общий класс Handler)
        srv.shutdown(); srv.server_close(); m.close()
