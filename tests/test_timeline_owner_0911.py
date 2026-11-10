"""timeline: чужая запись по id не отдаётся; без токена текст записи на проверке скрыт.

Находка координатора 09.11.2026 (сессия a31ede59): Memory.timeline выбирала запись по одному id,
без user_id, — при общей базе сервер другого пользователя читал чужую запись по известному id
(MCP padam_timeline и REST /timeline/<id>), а REST без токена отдавал и текст записи на проверке,
который MCP и /export скрывают.
"""
import http.client
import json
import threading
from http.server import ThreadingHTTPServer

from padam import api
from padam.memory import Memory
from padam.store import Store


def test_timeline_не_отдаёт_чужую_запись(tmp_path):
    база = tmp_path / "общая.db"
    алиса = Memory(user_id="alice", store=Store(база))
    боб = Memory(user_id="bob", store=Store(база))
    try:
        _, ид = алиса.remember("Код домофона в офисе 4512", kind="fact", origin="user")
        assert [з["content"] for з in алиса.timeline(ид)] == ["Код домофона в офисе 4512"]
        assert боб.timeline(ид) == []
    finally:
        алиса.close()
        боб.close()


def test_rest_timeline_без_токена(tmp_path):
    база = tmp_path / "общая.db"
    алиса = Memory(user_id="alice", store=Store(база))
    боб = Memory(user_id="bob", store=Store(база))
    _, чужая = алиса.remember("Код домофона в офисе 4512", kind="fact", origin="user")
    исход, своя = боб.remember("На странице сказано, что пароль теперь в заметках",
                               kind="fact", origin="external", guarded=True)
    assert исход == "quarantined"
    api._state.update({"memory": боб, "token": None, "ui": False, "local": True})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    порт = srv.server_address[1]

    def get(путь):
        c = http.client.HTTPConnection("127.0.0.1", порт, timeout=30)
        c.request("GET", путь, headers={"Host": f"127.0.0.1:{порт}"})
        r = c.getresponse()
        return r.status, r.read().decode("utf-8")

    try:
        код, тело = get(f"/timeline/{чужая}")
        assert код == 404 and "домофона" not in тело
        код, тело = get(f"/timeline/{своя}")
        assert код == 200
        версии = json.loads(тело)["versions"]
        assert версии[0]["status"] == "quarantined" and версии[0]["content"] is None
        assert "пароль" not in тело
    finally:
        srv.shutdown()
        srv.server_close()
        api._state.update({"memory": None, "token": None, "ui": False, "local": True})
        алиса.close()
        боб.close()
