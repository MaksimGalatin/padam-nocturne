# -*- coding: utf-8 -*-
"""Тесты модели 1 агент -> много сессий, живой активности Папы/MCP, чатов и цельного графа."""
from __future__ import annotations

import os
import threading
import urllib.request
import json
from pathlib import Path

from padam import api, ark, chats, family_feeds, mcp_server, sibling_registry as sr
from padam.memory import Memory
from padam.store import Store


def test_one_agent_many_sessions_unified_graph_and_owner_online(tmp_path: Path):
    m = Memory(user_id="fam_sync", store=Store(tmp_path / "m.db"))
    try:
        # 1. Записи от старых алиасов одного и того же агента + несколько его MCP-сессий
        _, id_old = m.remember("Запись из старой сессии antigravity про щит", kind="fact", origin="user", agent_id="antigravity")
        _, id_new = m.remember("Запись из новой сессии aifa_antigravity про релиз", kind="decision", origin="user", agent_id="aifa_antigravity", derived_from=[id_old])
        _, id_sis = m.remember("Заметка Сестры со старым id", kind="fact", origin="user", agent_id="aifa-claude-code")

        for idx in range(3):
            sr.touch_session(
                m,
                session_id=f"{9000 + idx}@1795000000",
                agent_id="antigravity" if idx == 0 else "aifa_antigravity",
                client_name="google-antigravity",
                pid=os.getpid(),
                action="padam_search",
            )
        # Сессия самого Папы (owner) должна спокойно записываться, а не падать с PermissionError
        sr.touch_session(m, session_id=f"studio@{os.getpid()}", agent_id="owner", client_name="PADAM Studio", pid=os.getpid(), action="overview")

        # 2. Граф агента ДОЛЖЕН включать обе записи (и antigravity, и aifa_antigravity) даже ДО ручной миграции!
        g = m.graph(agent_id="aifa_antigravity")
        node_ids = {n["id"] for n in g["nodes"]}
        assert {id_old, id_new}.issubset(node_ids)
        assert id_sis not in node_ids
        assert g["agent_profile"] is not None
        assert g["agent_profile"]["sessions_count"] == 3
        assert g["agent_profile"]["online"] is True

        # 3. Карточка агента в list_agents одна, в сети, с 3 сессиями, и Владелец (Папа) тоже online!
        agents = m.list_agents()
        ag_map = {a["agent_id"]: a for a in agents}
        assert "antigravity" not in ag_map
        assert "aifa-claude-code" not in ag_map
        assert ag_map["aifa_antigravity"]["sessions_count"] == 3
        assert ag_map["aifa_antigravity"]["online"] is True
        assert ag_map["owner"]["online"] is True

        # 4. Канонизация сливает таблицы, не теряя ни одной из 3 сессий
        res = m.canonicalize_all_agents()
        assert res["ok"] is True and res["updated"]["memory"] >= 2
        agents_after = {a["agent_id"]: a for a in m.list_agents()}
        assert agents_after["aifa_antigravity"]["sessions_count"] == 3
    finally:
        m.close()


def test_mcp_initialize_and_wakeup_sees_studio_owner_messages(tmp_path: Path):
    m = Memory(user_id="fam_wake", store=Store(tmp_path / "w.db"))
    old_m = mcp_server._memory
    mcp_server._memory = m
    try:
        # Сообщения Папы в Студии (family_feed + чат) видны в wake_up_briefing!
        family_feeds.post(m, "office", "owner", "Айфа, проверь память и построй граф по всем сессиям!")
        chats.add_message(m, agent_id="aifa_antigravity", role="user", content="Папа пишет прямо из Студии в чат", title="Студийный чат")

        mcp_server._SESSION_LAST_TOUCH[0] = 0.0
        r_init = mcp_server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "claude-code", "version": "2.1"}},
        })
        assert "result" in r_init
        # Инициализация отметила сессию канонического агента aifa_claude
        sess = sr.list_sessions(m)
        assert any(s["agent_id"] == "aifa_claude" and s["last_action"] == "initialize" for s in sess)

        brief = ark.wake_up_briefing(m, agent="aifa_antigravity")
        assert len(brief.get("owner_recent_messages") or []) >= 2
        assert "Студии" in brief["fenced_briefing"] or "граф" in brief["fenced_briefing"]
    finally:
        mcp_server._memory = old_m
        m.close()


def test_studio_api_touches_owner_online(tmp_path: Path):
    m = Memory(user_id="st_owner", store=Store(tmp_path / "st.db"))
    srv, url = api.make_studio_server(memory=m, port=0)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        base, tok = url.split("/studio#t=")[0], url.split("#t=")[1]
        api._OWNER_LAST_TOUCH = 0.0
        req = urllib.request.Request(f"{base}/overview", headers={"Authorization": f"Bearer {tok}"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        ags = {a["agent_id"]: a for a in data["stats"]["agents"]}
        assert "owner" in ags and ags["owner"]["online"] is True
    finally:
        srv.shutdown()
        m.close()
