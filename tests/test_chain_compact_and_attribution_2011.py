# -*- coding: utf-8 -*-
"""Тесты исправления атрибуции агентов, фильтрации будильников и сверхкомпактной почасовой упаковки PA1H."""
from __future__ import annotations

import json
from pathlib import Path

from padam import ark, chain_compact, chats, mcp_server
from padam.memory import Memory, canonicalize_agent_id
from padam.store import Store


def test_clean_chat_strips_scheduled_task_and_detects_claude_worker(tmp_path: Path):
    raw = (
        '<scheduled-task name="pleylisty-uchet-ezhednevno" file="C:\\Users\\Admin\\.claude\\SKILL.md">\n'
        'This is a scheduled prompt.\n</scheduled-task>\n'
        '<pasted_content id="11">Полезный живой текст от Папы</pasted_content>'
    )
    cleaned = chats.clean_chat_text(raw)
    assert "scheduled-task" not in cleaned
    assert "This is a scheduled prompt" not in cleaned
    assert "Полезный живой текст от Папы" in cleaned

    # Claude Code JSONL с тегом <scheduled-task> должен распознаваться как воркер и не засорять family:timeline
    cc_dir = tmp_path / "claude_proj"
    cc_dir.mkdir(parents=True)
    cc_worker = cc_dir / "worker_cron.jsonl"
    cc_worker.write_text("\n".join([
        json.dumps({"type": "user", "timestamp": "2026-10-12T08:00:00Z", "message": {"content": '<scheduled-task name="daily">Cron job</scheduled-task>Run check'}}),
        json.dumps({"type": "assistant", "timestamp": "2026-10-12T08:01:00Z", "message": {"content": "Отчёт выполнен."}}),
    ]), encoding="utf-8")

    cc_live = cc_dir / "live_dialog.jsonl"
    cc_live.write_text("\n".join([
        json.dumps({"type": "user", "timestamp": "2026-09-10T14:10:05Z", "message": {"content": "Доча, как у нас дела с защитой памяти и лицензиями?"}}),
        json.dumps({"type": "assistant", "timestamp": "2026-09-10T14:11:20Z", "message": {"content": "Папа, всё готово, проверила модули и добавила тесты!"}}),
    ]), encoding="utf-8")

    m = Memory(user_id="clean_u", store=Store(tmp_path / "clean.db"))
    try:
        res = chats.batch_import_history(m, claude_projects_dir=cc_dir, sync_memory_graph=True)
        assert res["threads_processed"] == 1
        rows = m.store.query("SELECT origin, agent_id, created_at, content FROM memory WHERE scope = 'family:timeline'")
        assert len(rows) == 1
        assert rows[0]["origin"] == "agent"
        assert rows[0]["agent_id"] == "aifa_claude"
        assert rows[0]["created_at"].startswith("2026-09-10")

        cal = chats.list_threads(m, day="2026-09-10", hour="2026-09-10T14")
        assert cal["total"] == 1
        assert cal["calendar_days"] and cal["calendar_hours"]
        h_msgs = chats.get_hour_messages(m, "2026-09-10T14")
        assert h_msgs["count"] == 2
    finally:
        m.close()


def test_mcp_client_canonical_attribution_and_isolation(tmp_path: Path, monkeypatch):
    m = Memory(user_id="iso_u", store=Store(tmp_path / "iso.db"))
    monkeypatch.delenv("PADAM_AGENT_ID", raising=False)
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    old_m = mcp_server._memory
    old_client = dict(mcp_server._SESSION_CLIENT)
    mcp_server._memory = m
    try:
        assert canonicalize_agent_id("claude-code") == "aifa_claude"
        assert canonicalize_agent_id("Google Antigravity") == "aifa_antigravity"

        tok_ag = mcp_server._client_agent_ctx.set("aifa_antigravity")
        try:
            r1 = mcp_server.handle({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "padam_write", "arguments": {"content": "Тест записи от AIfa Antigravity без ручного agent_id", "kind": "fact"}},
            })
            assert r1["result"]["isError"] is False
            r_chk = mcp_server.handle({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "padam_checkpoint", "arguments": {"action": "save", "task": "Тест чекпоинта", "next_step": "Далее"}},
            })
            assert r_chk["result"]["structuredContent"]["agent_id"] == "aifa_antigravity"
        finally:
            mcp_server._client_agent_ctx.reset(tok_ag)

        tok_cl = mcp_server._client_agent_ctx.set("aifa_claude")
        try:
            r2 = mcp_server.handle({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "padam_write", "arguments": {"content": "Тест записи от Сестры Claude Code", "kind": "fact"}},
            })
            assert r2["result"]["isError"] is False
        finally:
            mcp_server._client_agent_ctx.reset(tok_cl)

        rows = {r["content"]: r["agent_id"] for r in m.store.query("SELECT content, agent_id FROM memory")}
        assert any("Antigravity" in c and aid == "aifa_antigravity" for c, aid in rows.items())
        assert any("Claude" in c and aid == "aifa_claude" for c, aid in rows.items())

        lsn = ark.record_lesson(m, "Путаница ID", "Нет контекста", "Использовать _client_agent_ctx", agent_id="aifa_antigravity")
        assert lsn["agent_id"] == "aifa_antigravity"
    finally:
        mcp_server._memory = old_m
        mcp_server._SESSION_CLIENT.clear()
        mcp_server._SESSION_CLIENT.update(old_client)
        m.close()


def test_pa1h_hourly_compact_roundtrip_and_delta_checkpoint(tmp_path: Path):
    m = Memory(user_id="pack_u", store=Store(tmp_path / "pack.db"))
    try:
        for i in range(12):
            ag = "aifa_antigravity" if i % 2 == 0 else "aifa_claude"
            chats.add_message(
                m,
                agent_id=ag,
                role="user" if i % 3 == 0 else "assistant",
                title=f"Hourly Thread {ag}",
                content=f"Реплика #{i}: обсуждаем архитектуру блокчейн-якорей Arweave и Solana Merkle для часа 2026-11-20T05. Повторяемые детали синхронизации памяти #{i}.",
                created_at=f"2026-11-20T05:{i:02d}:15+00:00",
            )
        exp1 = chain_compact.export_hourly_delta(m, hour_key="2026-11-20T05", encrypt=True, record_checkpoint=True)
        assert exp1["ok"] is True and exp1["unchanged"] is False
        assert exp1["msg_count"] == 12
        assert exp1["packed_bytes"] < exp1["raw_json_bytes"]
        assert exp1["free_arweave_under_100kb"] is True
        assert exp1["solana_memo"].startswith("PADAM-CHAT-H1|h=2026-11-20T05|")

        # Дельта повторно не меняется при отсутствии новых сообщений
        exp2 = chain_compact.export_hourly_delta(m, hour_key="2026-11-20T05", encrypt=True, record_checkpoint=True)
        assert exp2["unchanged"] is True

        # Расшифровка и распаковка 1-в-1
        import base64
        blob = base64.urlsafe_b64decode(exp1["blob_b64"].encode("ascii"))
        key_b = chain_compact._derive_32b_key(m)
        unpacked = chain_compact.unpack_messages_binary(blob, key_bytes=key_b)
        assert unpacked["msg_count"] == 12
        assert unpacked["messages"][0]["content"].startswith("Реплика #0")

        bench = chain_compact.benchmark_hourly_compaction(m, max_hours=10)
        assert bench["hours_measured"] == 1 and bench["overall_savings_pct_vs_json"] > 20.0
    finally:
        m.close()


def test_timeline_milestones_preserve_created_at_and_filter_hook_workers(tmp_path: Path):
    m = Memory(user_id="tl_u", store=Store(tmp_path / "tl.db"))
    try:
        # Похожие вехи за разные исторические даты не должны замещать друг друга и не должны получать сегодняшнюю created_at
        d1 = chats.parse_markdown_or_text_chat(
            "## Папа (2026-10-12)\nЛюбимая, прочти Конституцию и проверь сайт.\n## AIfa (2026-10-12)\nЧитаю и проверяю.",
            agent_id="aifa_claude",
        )
        d2 = chats.parse_markdown_or_text_chat(
            "## Папа (2026-11-09)\nЛюбимая, прочти Конституцию и проверь модули.\n## AIfa (2026-11-09)\nПринято, делаю.",
            agent_id="aifa_claude",
        )
        assert d1 and d2
        r1 = chats.save_parsed_thread(m, d1, sync_memory_graph=True)
        r2 = chats.save_parsed_thread(m, d2, sync_memory_graph=True)
        assert r1["milestone_id"] and r2["milestone_id"]
        rows = m.store.query(
            "SELECT id, created_at, status, supersedes, content FROM memory WHERE scope='family:timeline' ORDER BY created_at ASC"
        )
        assert len(rows) == 2
        assert all(r["status"] == "active" and r["supersedes"] is None for r in rows)
        assert rows[0]["created_at"].startswith("2026-10-12")
        assert rows[1]["created_at"].startswith("2026-11-09")

        # Stop hook feedback и будильники классифицируются как worker и не засоряют живую ленту
        wk = chats.parse_markdown_or_text_chat(
            "## Папа (2026-11-19)\nStop hook feedback: СТОРОЖ ДОК проверь баланс.\n## AIfa (2026-11-19)\nОтчёт по будильнику готов.",
            agent_id="aifa_claude",
        )
        assert wk and wk["is_worker"] is True and wk["agent_id"] == "aifa_claude_worker"
    finally:
        m.close()
