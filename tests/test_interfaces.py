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


def test_protocol_version_is_negotiated():
    """Клиент получает свою версию, если сервер её знает, иначе — самую новую из поддерживаемых."""
    for asked in mcp_server.SUPPORTED_PROTOCOL_VERSIONS:
        r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": asked}})
        assert r["result"]["protocolVersion"] == asked
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "1999-01-01"}})
    assert r["result"]["protocolVersion"] == mcp_server.SUPPORTED_PROTOCOL_VERSIONS[0]
    assert r["result"]["instructions"]


def test_server_version_matches_package_metadata():
    """serverInfo.version, padam.__version__ и pyproject.toml — одно число (было 0.1.0 против 0.2.0)."""
    import re
    from pathlib import Path
    import padam
    toml = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert padam.__version__ == re.search(r'^version\s*=\s*"([^"]+)"', toml, re.M).group(1)
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert r["result"]["serverInfo"]["version"] == padam.__version__


def test_every_tool_has_a_title():
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert all(t.get("title") for t in r["result"]["tools"])


def test_stdio_parse_error_is_reported(tmp_path):
    """Битая строка JSON — ответ -32700 с id = null, следующий запрос обрабатывается."""
    import subprocess, sys
    env = dict(os.environ, PADAM_DB=str(tmp_path / "p.db"))
    вход = '{not json\n{"jsonrpc": "2.0", "id": 7, "method": "ping"}\n'
    out = subprocess.run([sys.executable, "-m", "padam.mcp_server"], input=вход, capture_output=True,
                         text=True, encoding="utf-8", env=env, timeout=60).stdout.strip().splitlines()
    assert json.loads(out[0]) == {"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32700, "message": "parse error"}}
    assert json.loads(out[1])["id"] == 7


def test_stdio_is_utf8_even_on_legacy_console(tmp_path):
    """Кодировка трубы cp1252 (Windows): кириллица пишется и читается целой, сервер не падает."""
    import subprocess, sys
    env = dict(os.environ, PADAM_DB=str(tmp_path / "u.db"), PYTHONIOENCODING="cp1252", PYTHONUTF8="0")
    запрос = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": "padam_write", "arguments": {"content": "Отвечать по-русски", "kind": "preference"}}}
    поиск = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "padam_search", "arguments": {"query": "по-русски"}}}
    вход = json.dumps(запрос, ensure_ascii=False) + "\n" + json.dumps(поиск, ensure_ascii=False) + "\n"
    r = subprocess.run([sys.executable, "-m", "padam.mcp_server"], input=вход.encode("utf-8"),
                       capture_output=True, env=env, timeout=120)
    строки = r.stdout.decode("utf-8").strip().splitlines()
    assert len(строки) == 2, r.stderr.decode("utf-8", "replace")[-400:]
    assert "Отвечать по-русски" in json.loads(строки[1])["result"]["content"][0]["text"]


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


def test_every_tool_has_m8ven_annotations():
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    hints = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
    for t in r["result"]["tools"]:
        assert "annotations" in t, f"{t['name']} lacks annotations object"
        for h in hints:
            assert h in t["annotations"] and isinstance(t["annotations"][h], bool), \
                f"{t['name']} missing boolean annotation {h}"
            assert h in t and isinstance(t[h], bool), \
                f"{t['name']} missing top-level hint {h}"


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


def test_search_compact_shortens_long_rounds(wired):
    """compact=true: реплика человека остаётся, длинный ответ ассистента
    сокращается; без compact запись отдаётся целиком (поведение по умолчанию
    не меняется)."""
    раунд = ("[2026/10/13] user: Я купил три модели самолётов для сборки\n"
             "assistant: " + "Отличный выбор, вот подробности о масштабах. " * 60)
    call("padam_write", {"content": раунд, "kind": "event"})
    полный = call("padam_search", {"query": "модели самолётов"})["content"][0]["text"]
    сжатый = call("padam_search", {"query": "модели самолётов",
                                   "compact": True})["content"][0]["text"]
    assert "Я купил три модели самолётов" in сжатый
    assert len(сжатый) < len(полный) - 1500
    assert "Отличный выбор" in сжатый            # начало ответа сохранено


def test_compact_text_keeps_short_records_intact():
    from padam.retrieval import compact_text
    assert compact_text("короткая запись") == "короткая запись"
    assert compact_text("x" * 800).endswith("…") and len(compact_text("x" * 800)) == 701


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


def test_bad_tool_returns_protocol_error_not_crash(wired):
    """MCP: неизвестный инструмент — ошибка протокола -32602, сервер не падает."""
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                           "params": {"name": "padam_nonexistent", "arguments": {}}})
    assert r["error"]["code"] == -32602


def test_missing_argument_reported_as_error(wired):
    res = call("padam_write", {})
    assert res["isError"] is True
    assert "missing required argument(s): content" in res["content"][0]["text"]


def test_arguments_must_be_an_object(wired):
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                           "params": {"name": "padam_search", "arguments": ["not", "an", "object"]}})
    assert r["error"]["code"] == -32602


def test_sleep_note_is_english(wired):
    report = json.loads(call("padam_sleep", {})["content"][0]["text"])
    assert report.get("note") == "episode buffer is empty"


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
