# Параллельные сессии одного агента (18.11.2026): каждая видна отдельно, хранится только имя инструмента.
from padam import sibling_registry as sr
from padam.memory import Memory
from padam.store import Store


def _mem(tmp_path):
    return Memory(user_id="owner", store=Store(tmp_path / "s.db"))


def test_три_сессии_одного_агента_видны_отдельно(tmp_path):
    m = _mem(tmp_path)
    sr.register_sibling(m, "aifa_claude", display_name="AIfa (Claude Code)")
    for i in range(3):
        sr.touch_session(m, session_id=f"{100 + i}@1", agent_id="aifa_claude", client_name="claude-code", action="padam_search")
    sr.touch_session(m, session_id="100@1", agent_id="aifa_claude", client_name="claude-code", action="padam_write")
    ss = sr.list_sessions(m)
    assert len(ss) == 3 and {s["agent_id"] for s in ss} == {"aifa_claude"}
    first = next(s for s in ss if s["session_id"] == "100@1")
    assert first["calls"] == 2 and first["last_action"] == "padam_write"
    # основная база памяти не тронута: учёт в отдельном файле
    names = {r[0] for r in m.store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "ark_sibling_session" not in names


def test_в_действии_нет_аргументов_и_мусора(tmp_path):
    m = _mem(tmp_path)
    sr.touch_session(m, session_id="7@1", agent_id="x", action='padam_write {"content": "secret sk-123"}')
    s = sr.list_sessions(m)[0]
    assert "secret" not in s["last_action"] and " " not in s["last_action"] and "{" not in s["last_action"]


def test_сервер_mcp_отмечает_сессию_и_не_падает(tmp_path, monkeypatch):
    import padam.mcp_server as ms
    monkeypatch.setenv("PADAM_AGENT_ID", "aifa_claude")
    m = _mem(tmp_path)
    monkeypatch.setattr(ms, "mem", lambda: m)
    ms._remember_client({"name": "claude-code", "version": "2.0"})
    ms._SESSION_LAST_TOUCH[0] = 0.0
    ms._touch_session("padam_stats")
    s = sr.list_sessions(m)
    assert s and s[0]["agent_id"] == "aifa_claude" and s[0]["client_name"] == "claude-code" and s[0]["last_action"] == "padam_stats"
    monkeypatch.setattr(ms, "mem", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    ms._SESSION_LAST_TOUCH[0] = 0.0
    ms._touch_session("padam_search")  # ошибка учёта не ломает вызов
