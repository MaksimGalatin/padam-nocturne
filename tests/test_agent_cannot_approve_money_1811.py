"""Аудит GLM AUT-09 (18.11.2026): агент через MCP не одобряет сам себе деньги, автопилот и «клиент принял образец»."""
from __future__ import annotations

import pytest

from padam import mcp_server
from padam.memory import Memory
from padam.store import Store


@pytest.fixture
def mem(tmp_path, monkeypatch):
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    monkeypatch.setattr(mcp_server, "_memory", m)
    yield m
    m.close()


def test_агент_не_одобряет_себе_платное_действие(mem):
    import json
    out = mcp_server.call_tool("padam_platform_connect", {
        "action": "autopilot_dispatch", "platform_id": "upwork", "title": "t", "brief": "b",
        "budget_usdt": 300, "paid_action_cost_usdt": 5, "owner_approved_paid_usdt": 5})
    res = json.loads(out[out.find("{"):]) if "{" in out else {}
    assert res.get("status") == "blocked_paid_action_requires_owner_yes", out[:300]


@pytest.mark.parametrize("act", ["set_autopilot", "sample_accept"])
def test_кнопки_владельца_закрыты_для_агента(mem, act):
    with pytest.raises(PermissionError):
        mcp_server.call_tool("padam_platform_connect", {
            "action": act, "platform_id": "upwork", "autopilot_enabled": True, "owner_approved_paid_usdt": 1000,
            "order_id": "x"})


def test_обходное_имя_ничего_не_меняет(mem):
    from padam import platform_wizard as pw
    mcp_server.call_tool("padam_platform_connect", {
        "action": "__owner_set_autopilot__", "platform_id": "upwork", "autopilot_enabled": True,
        "owner_approved_paid_usdt": 1000})
    cfg = pw.get_platform_autopilot_config(mem, "upwork")
    assert cfg["autopilot_enabled"] is False and float(cfg["approved_paid_usdt"]) == 0.0


def test_схема_не_предлагает_одобрение_денег():
    td = mcp_server.PLATFORM_CONNECT_TOOL_DEF["inputSchema"]["properties"]
    assert "owner_approved_paid_usdt" not in td
    assert not {"set_autopilot", "sample_accept"} & set(td["action"]["enum"])
