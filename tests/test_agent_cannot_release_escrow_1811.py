"""Аудит GLM AUT-04 (18.11.2026): агент через MCP не может довести удержание выплаты до «можно выплатить».
Удержание создаётся только после оплаты (settle_paid), срок идёт только от приёмки (accept_delivery) — обе кнопки
владельца. Агент перебирает все действия padam_freelance_hub: удержаний и начислений нет."""
from __future__ import annotations

import pytest

from padam import mcp_server
from padam.memory import Memory
from padam.store import Store

ДЕЙСТВИЯ = ["propose_subscription", "list_accounts", "evaluate_job", "list_orders", "draft_bid", "bid",
            "execute_swarm", "deliver", "accept_delivery", "settle_paid", "client_lock_status", "agent_ledger",
            "propose_profile", "monetization", "stores_status"]


def test_агент_не_снимает_удержание(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    m = Memory(user_id="u", store=Store(tmp_path / "f.db"))
    monkeypatch.setattr(mcp_server, "_memory", m)
    try:
        общие = {"platform": "upwork", "title": "Site", "brief": "Build a site", "budget_usdt": 500,
                 "order_id": "", "amount_usdt": 500, "paid_usdt": 500, "accepted_by": "client",
                 "now_ts": 4102444800, "deliverable_text": "Готовый сайт: https://example.com", "accepted_ts": 1, "owner_approved": True}
        import json as _json
        ev = _json.loads(mcp_server.call_tool("padam_freelance_hub", {"action": "evaluate_job", **общие}))
        oid = ev.get("order_id") or (ev.get("order") or {}).get("order_id")
        assert oid, ev
        общие["order_id"] = oid
        отказано = []
        for act in ДЕЙСТВИЯ:
            try:
                mcp_server.call_tool("padam_freelance_hub", {"action": act, **общие})
            except PermissionError:
                отказано.append(act)
            except Exception as exc:  # прочие отказы (нет заказа, неверные поля) тоже не дают денег
                print(act, type(exc).__name__, str(exc)[:120])
        from padam import freelance_autonomy as fa
        fa.release_matured_payouts(m)
        conn = m.store.conn
        for таблица in ("ark_owner_payout_hold", "ark_agent_ledger"):
            try:
                n = conn.execute(f"SELECT COUNT(*) FROM {таблица} WHERE user_id = ? AND status IN "
                                 "('releasable','credited','held_14d')", ("u",)).fetchone()[0]
            except Exception:
                n = 0
            assert n == 0, таблица
        assert {"accept_delivery", "settle_paid"} <= set(отказано)
    finally:
        m.close()
