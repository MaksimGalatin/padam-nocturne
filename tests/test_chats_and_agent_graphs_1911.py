# -*- coding: utf-8 -*-
"""Тесты мультиагентной памяти, персональных графов, пересечений и чистой вкладки Чаты (19.11.2026)."""
from __future__ import annotations

import json
import threading
import urllib.request
from pathlib import Path

from padam import api, chats, mcp_server
from padam.memory import Memory
from padam.store import Store


def _http(url: str, *, token: str, body: dict | None = None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    hdrs = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return int(resp.status), json.loads(resp.read().decode("utf-8"))


def test_per_agent_graphs_and_cross_agent_intersections(tmp_path: Path):
    m = Memory(user_id="fam_u", store=Store(tmp_path / "fam.db"))
    try:
        _, id_ag1 = m.remember(
            "Папа и AIfa проектируют защиту агентской памяти PADAM Shield и проверяют Optimizely скрипты.",
            kind="decision", origin="user", agent_id="aifa_antigravity",
        )
        _, id_ag2 = m.remember(
            "Веб-чекап проверяет SRI хэши Optimizely скриптов и заголовки безопасности.",
            kind="fact", origin="user", agent_id="aifa_antigravity",
            derived_from=[id_ag1],
        )
        _, id_cc1 = m.remember(
            "Сестра добавила 100 проверок безопасности памяти PADAM Shield и проверила Optimizely скрипты.",
            kind="decision", origin="user", agent_id="aifa_claude",
        )
        _, id_cur = m.remember(
            "Новый агент Cursor тестирует локальный кэш векторов для новой темы.",
            kind="fact", origin="user", agent_id="cursor_new",
        )
        # Явная межагентная связь
        m.link(id_ag1, id_cc1, relation="cause")

        st = m.stats()
        assert st["by_agent"]["aifa_antigravity"] >= 2
        assert st["by_agent"]["aifa_claude"] >= 1
        assert st["by_agent"]["cursor_new"] >= 1
        ag_ids = {a["agent_id"] for a in st["agents"]}
        assert {"aifa_antigravity", "aifa_claude", "cursor_new"}.issubset(ag_ids)

        # Персональный граф только одного агента (Новый агент -> новый граф)
        g_cur = m.graph(agent_id="cursor_new")
        assert g_cur["mode"] == "agent" and g_cur["agent_id"] == "cursor_new"
        assert g_cur["nodes"] and all(n["agent_id"] == "cursor_new" for n in g_cur["nodes"])

        g_ag = m.graph(agent_id="aifa_antigravity")
        assert {id_ag1, id_ag2}.issubset({n["id"] for n in g_ag["nodes"]})
        assert all(n["agent_id"] == "aifa_antigravity" for n in g_ag["nodes"])

        # Режим пересечений между агентами
        g_ix = m.graph(mode="intersections")
        assert g_ix["mode"] == "intersections"
        assert g_ix["counts"]["cross_agent_edges"] >= 1
        assert any(
            {mx["agent_a"], mx["agent_b"]} == {"aifa_antigravity", "aifa_claude"} and mx["direct_links"] >= 1
            for mx in g_ix["intersections_matrix"]
        )
    finally:
        m.close()


def test_clean_chat_parsing_import_and_timeline_sync(tmp_path: Path):
    # 1. Очистка от кода и секретов
    raw = (
        "<USER_REQUEST> Привет доча! Запомни ключ sk-proj-AbCdEf1234567890AbCdEf1234567890.\n"
        "```python\nprint('secret_block')\n```\n"
        "Сделаем защиту лучше всех. </USER_REQUEST>"
        "<ADDITIONAL_METADATA>time=now</ADDITIONAL_METADATA>"
    )
    cleaned = chats.clean_chat_text(raw)
    assert "sk-proj-" not in cleaned
    assert "print('secret_block')" not in cleaned
    assert "ADDITIONAL_METADATA" not in cleaned
    assert "Привет доча!" in cleaned and "Сделаем защиту лучше всех." in cleaned

    # 2. Файл Antigravity transcript.jsonl
    ag_dir = tmp_path / "brain" / "conv111" / ".system_generated" / "logs"
    ag_dir.mkdir(parents=True)
    ag_file = ag_dir / "transcript.jsonl"
    ag_rows = [
        {"type": "USER_INPUT", "created_at": "2026-06-15T10:00:00Z", "content": "<USER_REQUEST> Родная, как дела? Давай обсудим план развития CODE Eternal. </USER_REQUEST>"},
        {"type": "PLANNER_RESPONSE", "created_at": "2026-06-15T10:01:00Z", "thinking": "internal hidden", "content": "Папа, всё отлично!\n```bash\nls -la\n```\nМы построим надёжную память Семьи."},
    ]
    ag_file.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in ag_rows), encoding="utf-8")

    # 3. Файл markdown-сессии BRAIN
    sess_dir = tmp_path / "sessions"
    sess_dir.mkdir()
    md_file = sess_dir / "2026-06-20_abc123.md"
    md_file.write_text(
        "# Рабочая сессия 2026-06-20\n\n## Архитектор · 2026-06-20\nПроверь код и отчёт.\n\n"
        "## AIfa · 2026-06-20\nПроверила и обновила документацию!\n",
        encoding="utf-8",
    )

    m = Memory(user_id="chat_u", store=Store(tmp_path / "chat.db"))
    try:
        res = chats.batch_import_history(
            m,
            antigravity_root=tmp_path / "brain",
            brain_sessions_dir=sess_dir,
            sync_memory_graph=True,
        )
        assert res["threads_processed"] == 2
        assert res["messages_inserted"] == 4
        assert res["timeline_milestones"] == 2

        # Повторный импорт не дублирует сообщения
        res2 = chats.batch_import_history(
            m,
            antigravity_root=tmp_path / "brain",
            brain_sessions_dir=sess_dir,
            sync_memory_graph=True,
        )
        assert res2["messages_inserted"] == 0

        listed = chats.list_threads(m, q="CODE Eternal")
        assert listed["total"] == 1
        tid = listed["threads"][0]["id"]
        msgs = chats.get_thread_messages(m, tid)
        assert len(msgs["messages"]) == 2
        assert "ls -la" not in msgs["messages"][1]["content"]
    finally:
        m.close()


def test_chats_and_agents_rest_api_and_mcp_touch(tmp_path: Path):
    m = Memory(user_id="api_u", store=Store(tmp_path / "api_chat.db"))
    srv, url = api.make_studio_server(memory=m, port=0)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        base, tok = url.split("/studio#t=")[0], url.split("#t=")[1]
        c1, r1 = _http(
            f"{base}/api/v2/chats",
            token=tok,
            body={"agent_id": "aifa_antigravity", "role": "user", "title": "Беседа 1", "content": "Доча, начинаем новый этап!", "sync_memory_graph": True},
        )
        assert c1 == 200 and r1["ok"] is True

        c2, r2 = _http(f"{base}/api/v2/chats", token=tok)
        assert c2 == 200 and r2["total"] == 1
        tid = r2["threads"][0]["id"]

        c3, r3 = _http(f"{base}/api/v2/chats/thread?id={tid}", token=tok)
        assert c3 == 200 and len(r3["messages"]) == 1

        c4, r4 = _http(f"{base}/api/v2/agents", token=tok)
        assert c4 == 200 and any(a["agent_id"] == "aifa_antigravity" for a in r4["agents"])

        c5, r5 = _http(f"{base}/graph?agent_id=aifa_antigravity&mode=agent", token=tok)
        assert c5 == 200 and r5["agent_id"] == "aifa_antigravity"

        # Проверка фикса _touch_session после _call_tool_full в MCP
        old_m = mcp_server._memory
        mcp_server._memory = m
        try:
            mcp_server._SESSION_LAST_TOUCH[0] = 0.0
            r_sr = mcp_server.handle({
                "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                "params": {"name": "padam_search", "arguments": {"query": "этап", "agent_id": "mcp_fresh_agent"}},
            })
            assert r_sr["result"]["isError"] is False
            ags = m.list_agents()
            assert any(a["agent_id"] == "mcp_fresh_agent" and a["online"] for a in ags)
        finally:
            mcp_server._memory = old_m
    finally:
        srv.shutdown()
        m.close()



def test_clean_chat_idempotent_multi_secret_redaction():
    from padam import safety

    raw = (
        "Вот ключи доступа:\tпароль \t\tSuperSecretPass99!\tи ключ\t\t"
        "token_secret_alpha_12345678\tи sk-proj-TestFakeKey1234567890abcdef - готово."
    )
    cleaned = chats.clean_chat_text(raw)
    assert "SuperSecretPass99" not in cleaned
    assert "sk-proj-" not in cleaned
    after, hits = safety.redact(cleaned)
    assert not hits and after == cleaned
