"""Тесты внешних интерфейсов: MCP и REST."""

import json
import os
import threading
import time
import urllib.request
import urllib.error

import pytest

from padam import api, mcp_server
from padam.memory import Memory
from padam.store import Store


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """Подсовывает обоим модулям общую временную память."""
    m = Memory(user_id="test", store=Store(tmp_path / "iface.db"))
    monkeypatch.setattr(mcp_server, "_memory", m)
    api._state["memory"] = m
    api._state["token"] = None
    yield m
    api._state["memory"] = None
    m.close()


# --- MCP: протокол ----------------------------------------------------

def test_initialize_returns_protocol_and_name():
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 1,
                           "method": "initialize", "params": {}})
    assert r["result"]["serverInfo"]["name"] == "padam"
    assert r["result"]["protocolVersion"]


def test_initialized_notification_gets_no_reply():
    assert mcp_server.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_tools_list_complete():
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == {"padam_search", "padam_write", "padam_confirm",
                     "padam_refute", "padam_timeline", "padam_stats",
                     "padam_sleep", "padam_export"}


def test_every_tool_has_schema_and_description():
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    for t in r["result"]["tools"]:
        assert t["description"] and len(t["description"]) > 40, \
            f"{t['name']}: описание слишком короткое, модель не поймёт когда звать"
        assert t["inputSchema"]["type"] == "object"


def test_unknown_method_returns_error():
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 9, "method": "nope"})
    assert r["error"]["code"] == -32601


# --- MCP: инструменты -------------------------------------------------

def call(name, args):
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                           "params": {"name": name, "arguments": args}})
    return r["result"]


def test_write_then_search(wired):
    res = call("padam_write", {"content": "Сервер стоит в Манте, Эквадор",
                               "kind": "fact"})
    assert res["isError"] is False
    assert "id=" in res["content"][0]["text"]

    found = call("padam_search", {"query": "где стоит сервер"})
    assert "Манте" in found["content"][0]["text"]


def test_search_empty_is_not_an_error(wired):
    res = call("padam_search", {"query": "чего тут точно нет"})
    assert res["isError"] is False
    assert "Nothing found" in res["content"][0]["text"]


def test_confirm_and_refute_via_mcp(wired):
    _, mid = wired.remember("Проверяемый факт про инфраструктуру", kind="fact")
    assert "confirmed" in call("padam_confirm", {"id": mid})["content"][0]["text"]
    assert "lowered" in call("padam_refute", {"id": mid})["content"][0]["text"]


def test_timeline_via_mcp(wired):
    wired.remember("Запуск в сентябре", kind="decision")
    _, new = wired.remember("Запуск больше не в сентябре, а в октябре",
                            kind="decision")
    text = call("padam_timeline", {"id": new})["content"][0]["text"]
    assert "сентябре" in text and "октябре" in text


def test_export_via_mcp_is_valid_json(wired):
    wired.remember("Запись для выгрузки", kind="fact")
    payload = json.loads(call("padam_export", {})["content"][0]["text"])
    assert payload["format"] == "padam-export/1"
    assert payload["counts"]["memory"] >= 1


def test_bad_tool_returns_error_not_crash(wired):
    res = call("padam_nonexistent", {})
    assert res["isError"] is True


def test_missing_argument_reported_as_error(wired):
    res = call("padam_write", {})
    assert res["isError"] is True


# --- выгрузка и загрузка ----------------------------------------------

def test_export_import_roundtrip(tmp_path):
    src = Memory("u", Store(tmp_path / "src.db"))
    src.remember("Первая запись", kind="fact")
    src.remember("Отвечать кратко", kind="preference")
    payload = src.export()
    src.close()

    dst = Memory("u", Store(tmp_path / "dst.db"))
    assert dst.import_(payload) == 2
    assert dst.stats()["active"] == 2
    dst.close()


def test_import_rejects_unknown_format(tmp_path):
    m = Memory("u", Store(tmp_path / "x.db"))
    with pytest.raises(ValueError):
        m.import_({"format": "something-else"})
    m.close()


# --- REST -------------------------------------------------------------

@pytest.fixture
def server(wired):
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def post(base, path, payload):
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as r:
        return json.loads(r.read())


def test_health(server):
    assert get(server, "/health")["status"] == "ok"


def test_rest_write_and_search(server):
    w = post(server, "/write", {"content": "Каталог: 530 песен", "kind": "fact"})
    assert w["outcome"] == "created"
    s = post(server, "/search", {"query": "сколько песен"})
    assert s["results"] and "530" in s["results"][0]["content"]


def test_rest_reports_which_strategies_matched(server):
    post(server, "/write", {"content": "Биллинг 01DAF7-8B0717-3B1694", "kind": "fact"})
    s = post(server, "/search", {"query": "01DAF7-8B0717-3B1694"})
    assert s["results"][0]["found_by"], "должно быть видно, чем нашлось"


def test_rest_missing_field_is_400(server):
    try:
        post(server, "/search", {})
        assert False, "ожидалась ошибка 400"
    except urllib.error.HTTPError as e:
        assert e.code == 400


def test_rest_unknown_route_is_404(server):
    try:
        get(server, "/nope")
        assert False, "ожидалась ошибка 404"
    except urllib.error.HTTPError as e:
        assert e.code == 404


def test_rest_token_enforced(server):
    api._state["token"] = "секрет"
    try:
        try:
            get(server, "/stats")
            assert False, "без токена доступа быть не должно"
        except urllib.error.HTTPError as e:
            assert e.code == 401
    finally:
        api._state["token"] = None


def test_health_open_without_token(server):
    api._state["token"] = "секрет"
    try:
        assert get(server, "/health")["status"] == "ok"
    finally:
        api._state["token"] = None


def test_cli_survives_legacy_console_encoding(tmp_path):
    """Консоль Windows в cp1251: --explain печатает «×» и кириллицу — не падать."""
    import subprocess, sys
    env = dict(os.environ, PYTHONIOENCODING="cp1251", PYTHONUTF8="0")
    db = str(tmp_path / "c.db")
    run = lambda *a: subprocess.run([sys.executable, "-m", "padam", "--db", db, *a],
                                    capture_output=True, env=env, timeout=120)
    assert run("remember", "Отвечать по-русски", "--kind", "preference").returncode == 0
    r = run("recall", "язык ответа", "--explain")
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-300:]
