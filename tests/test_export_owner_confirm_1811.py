"""Аудит GLM MCP-01 (18.11.2026): агент под инъекцией не выгружает всю память без «да» человека в клиенте."""
from __future__ import annotations

import json

from padam import mcp_server
from padam.memory import Memory
from padam.store import Store


def _с_памятью(tmp_path, monkeypatch, ответ, caps={"elicitation": {}}):
    mem = Memory(user_id="u", store=Store(tmp_path / "e.db"))
    mem.remember("Секретный факт владельца", kind="fact", origin="user")
    monkeypatch.setattr(mcp_server, "_memory", mem)
    вопросы = []

    def cb(req):
        вопросы.append(req)
        return ответ
    mcp_server.set_client_capabilities(caps)
    mcp_server.set_elicitation_callback(cb if ответ is not None else None)
    return mem, вопросы


def _сброс():
    mcp_server.set_client_capabilities({})
    mcp_server.set_elicitation_callback(None)


def test_человек_отказал_выгрузки_нет(tmp_path, monkeypatch):
    monkeypatch.delenv("PADAM_MCP_EXPORT_CONFIRM", raising=False)
    try:
        _, вопросы = _с_памятью(tmp_path, monkeypatch, {"result": {"action": "accept", "content": {"decision": "deny"}}})
        out = mcp_server.call_tool("padam_export", {})
        assert out.startswith("Permission denied") and "Секретный" not in out
        assert len(вопросы) == 1 and вопросы[0]["method"] == "elicitation/create"
    finally:
        _сброс()


def test_человек_разрешил_выгрузка_есть(tmp_path, monkeypatch):
    monkeypatch.delenv("PADAM_MCP_EXPORT_CONFIRM", raising=False)
    try:
        _с_памятью(tmp_path, monkeypatch, {"result": {"action": "accept", "content": {"decision": "allow"}}})
        out = json.loads(mcp_server.call_tool("padam_export", {}))
        assert any("Секретный" in r["content"] for r in out["memory"])
    finally:
        _сброс()


def test_закрыл_диалог_значит_нет(tmp_path, monkeypatch):
    monkeypatch.delenv("PADAM_MCP_EXPORT_CONFIRM", raising=False)
    try:
        _с_памятью(tmp_path, monkeypatch, {"result": {"action": "cancel"}})
        assert mcp_server.call_tool("padam_export", {}).startswith("Permission denied")
    finally:
        _сброс()


def test_строгий_режим_без_диалога_отказ(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_EXPORT_CONFIRM", "strict")
    try:
        _с_памятью(tmp_path, monkeypatch, None, caps={})
        out = mcp_server.call_tool("padam_export", {})
        assert out.startswith("Permission denied") and "padam export" in out
    finally:
        _сброс()
