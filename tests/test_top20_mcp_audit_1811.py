# -*- coding: utf-8 -*-
"""ТОП-20 Сестры, п. 4: вызов MCP-инструмента, меняющего данные, пишется в хэш-цепь аудита — без самих аргументов."""
from padam import audit_chain, mcp_server
from padam.memory import Memory
from padam.store import Store


def test_вызов_mcp_в_цепи_аудита(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = Memory(user_id="u", store=Store(tmp_path / "a.db"))
    prev = mcp_server._memory
    mcp_server._memory = m
    try:
        def call(tool, args):
            return mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})["result"]
        call("padam_write", {"content": "секретная фраза Альфа-Бета-Гамма"})
        call("padam_search", {"query": "Альфа"})
        rows = m.store.conn.execute("SELECT * FROM ark_audit_chain WHERE user_id = ? AND action = 'mcp_call'", ("u",)).fetchall()
        записи = [dict(r) for r in rows]
        assert len(записи) == 1, записи                       # только padam_write; поиск (только чтение) не пишется
        текст = str(записи[0])
        assert "padam_write" in текст and "args_sha256" in текст
        assert "Альфа-Бета-Гамма" not in текст                 # аргументы не хранятся
        assert audit_chain.verify_audit_chain(m)["ok"]
    finally:
        mcp_server._memory = prev
