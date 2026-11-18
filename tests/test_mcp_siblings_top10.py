# -*- coding: utf-8 -*-
"""Тесты ТОП-10 доработок MCP-сервера и координации Братьев и Сестёр (17.11.2026)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from padam import (
    code_anchor,
    conflict_arbiter,
    coop_broker,
    mcp_server,
    mcp_telemetry,
    session_pack,
    sibling_registry,
)
from padam.memory import Memory
from padam.store import Store


def _mem(tmp_path: Path, name: str = "sib.db") -> Memory:
    return Memory(user_id="family_owner", store=Store(tmp_path / name))


def test_top1_3_10_sibling_registry_provenance_and_passport(tmp_path):
    mem = _mem(tmp_path)
    try:
        # Нельзя выдать себя за владельца
        with pytest.raises(PermissionError, match="impersonate"):
            sibling_registry.register_sibling(mem, "owner")

        reg = sibling_registry.register_sibling(
            mem, "lance",
            display_name="Lance-Audit",
            role="Security Auditor",
            client_type="claude_code",
            permission_role="contributor",
            scopes=["project:code"],
            capabilities=["security", "review"],
        )
        assert reg["ok"] is True and reg["agent_id"] == "lance"
        hb = sibling_registry.heartbeat_sibling(mem, "lance", status="busy", current_task="Audit ML-KEM")
        assert hb["status"] == "busy"

        # Паспорт онбординга без раскрытия owner_key
        passport = sibling_registry.spawn_sibling_passport(mem, "aria", role="Memory Analyst", permission_role="auditor")
        assert passport["secrets_exposed"] is False
        assert passport["mcp_config_snippet"]["mcpServers"]["padam"]["env"]["PADAM_AGENT_ID"] == "aria"
        assert "owner.key" not in json.dumps(passport)

        # Защита происхождения (Agent Provenance Guard)
        env = sibling_registry.sign_sibling_envelope(mem, "lance", "Tests passed 100%")
        assert env["trust_level"] == "sibling_verified"
        assert sibling_registry.verify_sibling_envelope(mem, env)["valid"] is True

        # Попытка подделать уровень доверия на owner_signed отклоняется
        forged_owner = dict(env, trust_level="owner_signed")
        assert sibling_registry.verify_sibling_envelope(mem, forged_owner)["valid"] is False
        forged_sig = dict(env, content="Malicious edit")
        assert sibling_registry.verify_sibling_envelope(mem, forged_sig)["valid"] is False
    finally:
        mem.close()


def test_top2_9_coop_lease_broker_tasks_and_topic_updates(tmp_path):
    mem = _mem(tmp_path)
    try:
        now = 1_700_000_000.0
        l1 = coop_broker.acquire_lease(mem, "aifa", "padam\\mcp_server.py", purpose="Edit tools", ttl_s=60, now_ts=now)
        assert l1["acquired"] is True and l1["resource_key"] == "padam/mcp_server.py"

        # Второй брат не может перезатереть тот же файл пока аренда жива
        l2 = coop_broker.acquire_lease(mem, "lance", "padam/mcp_server.py", purpose="Edit tools", ttl_s=60, now_ts=now + 10)
        assert l2["acquired"] is False and l2["conflict"] is True and l2["holder_agent"] == "aifa"

        # Чужой не может снять аренду
        rel_bad = coop_broker.release_lease(mem, "lance", "padam/mcp_server.py")
        assert rel_bad["released"] is False

        # После истечения TTL другой брат спокойно забирает аренду
        l3 = coop_broker.acquire_lease(mem, "lance", "padam/mcp_server.py", purpose="Audit", ttl_s=60, now_ts=now + 120)
        assert l3["acquired"] is True and l3["holder_agent"] == "lance"

        # Доска задач Роя
        t = coop_broker.create_task(mem, "Verify Android build", topic="android", created_by="aifa")
        c_ok = coop_broker.claim_task(mem, t["task_id"], "pixel")
        assert c_ok["claimed"] is True
        c_conflict = coop_broker.claim_task(mem, t["task_id"], "lance")
        assert c_conflict["claimed"] is False
        u_ok = coop_broker.update_task(mem, t["task_id"], status="done", agent_id="pixel", summary="APK OK")
        assert u_ok["status"] == "done" and len(coop_broker.list_tasks(mem, topic="android", status="done")) == 1
    finally:
        mem.close()


def test_top4_session_pack_within_token_budget(tmp_path):
    mem = _mem(tmp_path)
    try:
        mem.remember("Owner is Maksim Galatin", kind="identity", origin="user")
        mem.remember("Always run pytest before commit", kind="preference", origin="user")
        coop_broker.acquire_lease(mem, "lance", "padam/pqc_mlkem.py", purpose="Review PQC")
        coop_broker.create_task(mem, "Check LAN beacon", topic="mesh")

        pack = session_pack.build_session_pack(mem, agent_id="aria", topic="mesh", max_tokens=200)
        assert pack["ok"] is True
        assert pack["estimated_tokens"] <= 200 + 20
        assert pack["active_leases_count"] == 1
        assert "<memory-data nonce=" in pack["fenced_context"]
        assert "Maksim Galatin" in pack["fenced_context"]
    finally:
        mem.close()


def test_top5_code_anchor_stale_detection_and_path_traversal_guard(tmp_path):
    mem = _mem(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    src = repo / "sample.py"
    src.write_text("def hello():\n    return 1\n", encoding="utf-8")
    try:
        _, mid = mem.remember("hello() returns 1", kind="fact", origin="user")

        # Path traversal за пределы repo_root запрещён
        with pytest.raises(PermissionError, match="Path traversal"):
            code_anchor.anchor_fact_to_file(mem, mid, "../outside.txt", repo_root=repo)

        anc = code_anchor.anchor_fact_to_file(mem, mid, "sample.py", repo_root=repo, symbol_name="hello")
        assert anc["status"] == "fresh"

        c1 = code_anchor.check_stale_anchors(mem, repo_root=repo)
        assert c1["fresh_count"] == 1 and c1["stale_count"] == 0

        # Изменяем файл -> якорь автоматически помечается stale!
        src.write_text("def hello():\n    return 2\n", encoding="utf-8")
        c2 = code_anchor.check_stale_anchors(mem, repo_root=repo)
        assert c2["stale_count"] == 1 and c2["stale"][0]["reason"] == "file_hash_changed"
    finally:
        mem.close()


def test_top7_conflict_arbiter_lifecycle(tmp_path):
    mem = _mem(tmp_path)
    try:
        c = conflict_arbiter.open_conflict_case(
            mem,
            "SQLite backup strategy",
            agent_a="aifa", position_a="Use sqlite3.Connection.backup",
            agent_b="lance", position_b="Copy raw bytes",
        )
        ev = conflict_arbiter.add_case_evidence(mem, c["case_id"], agent_id="aifa", note="Raw bytes misses WAL file", ref="commit fa19361")
        assert ev["evidence_count"] == 1
        res = conflict_arbiter.resolve_conflict_case(mem, c["case_id"], decision="Approved Connection.backup across codebase", resolved_by="aifa")
        assert res["status"] == "resolved"
        cases = conflict_arbiter.list_conflict_cases(mem, status="resolved")
        assert len(cases) == 1 and len(cases[0]["evidence"]) == 1
    finally:
        mem.close()


def test_top6_8_9_10_mcp_batch_cache_telemetry_topics_and_9_default_gating(monkeypatch, tmp_path):
    mem = _mem(tmp_path)
    prev_mem = mcp_server._memory
    mcp_server._memory = mem
    try:
        # 1. При выключенных флагах tools/list ОБЯЗАН содержать ровно 9 базовых инструментов (AS-092)
        monkeypatch.delenv("PADAM_MCP_ARK_TOOLS", raising=False)
        monkeypatch.delenv("PADAM_MCP_ROLLBACK_TOOL", raising=False)
        monkeypatch.delenv("PADAM_MCP_CABINET_TOOL", raising=False)
        monkeypatch.delenv("PADAM_MCP_BRAIN_STATUS_TOOL", raising=False)
        monkeypatch.delenv("PADAM_MCP_SOVEREIGN_SYNC_TOOL", raising=False)
        monkeypatch.delenv("PADAM_MCP_COMPAT", raising=False)

        default_tools = mcp_server._list_tools_payload()
        assert len(default_tools) == 9
        for hidden_name in (
            "padam_sibling_hub", "padam_coop_lock", "padam_session_pack",
            "padam_code_anchor", "padam_batch", "padam_conflict_arbiter", "padam_mcp_telemetry",
        ):
            with pytest.raises(ValueError, match="PADAM_MCP_ARK_TOOLS=1"):
                mcp_server.call_tool(hidden_name, {})

        # 2. Включаем PADAM_MCP_ARK_TOOLS=1 и проверяем все 7 новых инструментов, padam_batch, stamp-кэш и топики
        monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
        mem.remember("Architect is Maksim Galatin", kind="identity", origin="user")

        # batch запрещает write-инструменты и рекурсию
        with pytest.raises(PermissionError, match="not allowed"):
            mcp_server.call_tool("padam_batch", {"calls": [{"name": "padam_write", "arguments": {"content": "evil"}}]})
        with pytest.raises(PermissionError, match="not allowed"):
            mcp_server.call_tool("padam_batch", {"calls": [{"name": "padam_batch", "arguments": {"calls": []}}]})

        batch_out = json.loads(mcp_server.call_tool("padam_batch", {"calls": [
            {"name": "padam_stats", "arguments": {}},
            {"name": "padam_session_pack", "arguments": {"agent_id": "aifa", "topic": "Architect", "max_tokens": 500}},
            {"name": "padam_mcp_telemetry", "arguments": {}},
        ]}))
        assert batch_out["ok"] is True and batch_out["count"] == 3

        # Топик-уведомление и ресурс padam://swarm/topic/{topic}
        sub_resp = mcp_server.handle({"jsonrpc": "2.0", "id": 77, "method": "resources/subscribe", "params": {"uri": "padam://swarm/topic/release"}})
        assert "error" not in sub_resp
        t_res = json.loads(mcp_server.call_tool("padam_coop_lock", {"action": "create_task", "title": "Tag release", "topic": "release", "agent_id": "aifa"}))
        assert t_res["topic"] == "release"
        topic_read = json.loads(mcp_server.read_resource("padam://swarm/topic/release")["text"])
        assert len(topic_read["tasks"]) == 1 and topic_read["tasks"][0]["title"] == "Tag release"
        notifs = mcp_server.pop_notifications()
        assert any(n.get("params", {}).get("uri") == "padam://swarm/topic/release" for n in notifs)

        sp_read = json.loads(mcp_server.read_resource("padam://session-pack?agent_id=aifa&max_tokens=400")["text"])
        assert sp_read["ok"] is True and "Maksim Galatin" in sp_read["fenced_context"]

        tel_read = json.loads(mcp_server.read_resource("padam://mcp-telemetry")["text"])
        assert tel_read["ok"] is True and tel_read["total_schema_approx_tokens"] > 100
    finally:
        mcp_server._memory = prev_mem
        mem.close()
