# -*- coding: utf-8 -*-
"""Тесты Энергетического Автопилота: учёт токенов день/неделя/месяц, таймер, заработок и согласование оплаты (17.11.2026)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from padam import api, mcp_server, router, sovereign_ops, studio, token_autonomy
from padam.memory import Memory
from padam.store import Store


def _mem(tmp_path: Path, name: str = "budget.db") -> Memory:
    return Memory(user_id="phoenix_user", store=Store(tmp_path / name))


def test_token_windows_day_week_month_pacing_and_adaptive_modes(tmp_path):
    mem = _mem(tmp_path)
    r = router.SovereignRouter()
    try:
        t0 = 1_700_000_000.0
        token_autonomy.upsert_provider_plan(
            mem, "openai",
            tier_name="pro",
            daily_token_limit=100_000,
            weekly_token_limit=500_000,
            monthly_token_limit=2_000_000,
            usd_balance=20.0,
            now_ts=t0,
        )

        # 1. Использовано 2_000 (в пределах часового пайка) -> normal / auto
        p1 = token_autonomy.record_token_usage(mem, "openai", 2_000, agent_id="aifa", now_ts=t0 + 10)
        assert p1["pacing_mode"] == "normal" and p1["remaining"]["day"] == 98_000

        # 2. Через час списываем плавно (всего использовано 70_000 в прошлом часу + 3_000 сейчас -> 27% осталось, но 1h burn < запаса/2) -> eco
        token_autonomy.record_token_usage(mem, "openai", 68_000, agent_id="aifa", now_ts=t0 + 20)
        p2 = token_autonomy.record_token_usage(mem, "openai", 3_000, agent_id="aifa", now_ts=t0 + 3700)
        assert p2["pacing_mode"] == "eco"

        # 3. Использовано ещё 17_000 (итого 90_000 -> осталось 10%) -> sovereign_local -> роутер переводится в local_only
        p3 = token_autonomy.record_token_usage(mem, "openai", 17_000, agent_id="aifa", now_ts=t0 + 3710)
        assert p3["pacing_mode"] == "sovereign_local" and p3["needs_topup_proposal"] is True
        applied = token_autonomy.apply_adaptive_pacing(mem, "openai", router_instance=r, now_ts=t0 + 3710)
        assert applied["applied_router_mode"] == "local_only"

        # 4. Использованы все дневные 100_000 -> cpu_survival
        p4 = token_autonomy.record_token_usage(mem, "openai", 10_000, agent_id="aifa", now_ts=t0 + 3720)
        assert p4["pacing_mode"] == "cpu_survival" and p4["remaining"]["day"] == 0

        # 5. Наступили следующие сутки (+86401с) -> дневная квота сбросилась, но недельная/месячная помнят трату 100k!
        p5 = token_autonomy.compute_pacing_plan(mem, "openai", now_ts=t0 + 86_401.0)
        assert p5["remaining"]["day"] == 100_000
        assert p5["remaining"]["week"] == 400_000
        assert p5["remaining"]["month"] == 1_900_000
    finally:
        mem.close()


def test_budget_timer_disabled_by_default_and_no_duplicate_proposals(monkeypatch, tmp_path):
    mem = _mem(tmp_path, "timer.db")
    try:
        monkeypatch.delenv("PADAM_BUDGET_TIMER", raising=False)
        assert token_autonomy.is_budget_timer_enabled() is False
        watcher = token_autonomy.BudgetTimerWatcher(lambda: _mem(tmp_path, "timer.db"), interval_s=0.05)
        assert watcher.start() is False

        t0 = 1_700_000_000.0
        token_autonomy.upsert_provider_plan(mem, "anthropic", daily_token_limit=10_000, weekly_token_limit=50_000, monthly_token_limit=200_000, now_ts=t0)
        token_autonomy.record_token_usage(mem, "anthropic", 9_200, now_ts=t0 + 10)  # осталось 8%

        tick1 = token_autonomy.run_budget_timer_tick(mem, agent_id="aifa", now_ts=t0 + 20)
        assert tick1["ok"] is True and tick1["cost_usd"] == 0.0
        assert len(tick1["created_proposals"]) == 1

        # Повторный тик таймера не плодит дубль pending-заявки
        tick2 = token_autonomy.run_budget_timer_tick(mem, agent_id="aifa", now_ts=t0 + 30)
        assert len(tick2["created_proposals"]) == 0
        assert len(token_autonomy.list_topup_proposals(mem, status="awaiting_owner_approval")) == 1
    finally:
        mem.close()


def test_agent_earnings_owner_approval_lock_and_idempotent_topup(monkeypatch, tmp_path):
    mem = _mem(tmp_path, "earn.db")
    try:
        # 1. Агент заработал $100 -> 15% ($15) выделяется на его собственный вычислительный бюджет
        ern = token_autonomy.record_agent_earning(mem, "aifa", source="skill_sale", revenue_usdt=100.0, compute_share_pct=15.0)
        assert ern["allocated_compute_usdt"] == 15.0
        assert ern["treasury"]["available_compute_usdt"] == 15.0

        # 2. Агент создаёт заявку на оплату тарифа Pro ($12 < $15 собственных заработанных средств)
        prop = token_autonomy.propose_plan_or_topup(
            mem,
            agent_id="aifa",
            provider="openai",
            action_type="upgrade_plan",
            target_tier="pro_monthly",
            amount_usdt=12.0,
            estimated_tokens=5_000_000,
            reason="Self-earned funds cover Pro upgrade",
        )
        pid = prop["proposal_id"]
        assert prop["status"] == "awaiting_owner_approval"
        assert prop["covered_by_own_earnings"] is True

        # 3. Нельзя исполнить заявку ДО подтверждения владельцем
        monkeypatch.setenv("PADAM_TREASURY_AUTOPAY", "1")
        transfers: list[dict] = []
        tm = sovereign_ops.TreasuryComputeManager(transfer_fn=lambda req: (transfers.append(req) or {"tx": "ok"}))
        with pytest.raises(PermissionError, match="owner approval"):
            token_autonomy.execute_approved_topup(mem, pid, treasury_manager=tm)

        # 4. Владелец одобряет заявку, но если замок PADAM_TREASURY_AUTOPAY=0 -> всё равно SovereignLockError!
        monkeypatch.setenv("PADAM_TREASURY_AUTOPAY", "0")
        dec = token_autonomy.decide_topup_proposal(mem, pid, approve=True, owner_note="Папа одобрил покупку тарифа")
        assert dec["status"] == "approved"
        with pytest.raises(sovereign_ops.SovereignLockError):
            token_autonomy.execute_approved_topup(mem, pid, treasury_manager=tm)

        # 5. При одобрении владельцем И снятом замке PADAM_TREASURY_AUTOPAY=1 -> платёж проходит один раз, токены зачисляются!
        monkeypatch.setenv("PADAM_TREASURY_AUTOPAY", "1")
        ex1 = token_autonomy.execute_approved_topup(mem, pid, treasury_manager=tm)
        assert ex1["status"] == "executed"
        assert ex1["plan"]["limits"]["month"] == 5_000_000
        assert ex1["plan"]["usd_balance"] == 12.0
        assert len(transfers) == 1

        # Повторное исполнение идемпотентно (не списывает повторно!)
        ex2 = token_autonomy.execute_approved_topup(mem, pid, treasury_manager=tm)
        assert ex2["idempotent_replay"] is True
        assert len(transfers) == 1
        assert token_autonomy.treasury_summary(mem)["available_compute_usdt"] == 3.0
    finally:
        mem.close()


def test_mcp_token_budget_blocks_self_approve_and_preserves_9_default_tools(monkeypatch, tmp_path):
    mem = _mem(tmp_path, "mcp_bgt.db")
    prev_mem = mcp_server._memory
    mcp_server._memory = mem
    try:
        # Дефолтный tools/list строго 9 инструментов
        monkeypatch.delenv("PADAM_MCP_ARK_TOOLS", raising=False)
        assert len(mcp_server._list_tools_payload()) == 9
        with pytest.raises(ValueError, match="PADAM_MCP_ARK_TOOLS=1"):
            mcp_server.call_tool("padam_token_budget", {"action": "status"})

        monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
        # Агент не может сам себе одобрить/исполнить платёж через MCP!
        with pytest.raises(PermissionError, match="human owner"):
            mcp_server.call_tool("padam_token_budget", {"action": "approve"})
        with pytest.raises(PermissionError, match="human owner"):
            mcp_server.call_tool("padam_token_budget", {"action": "execute"})

        res = json.loads(mcp_server.call_tool("padam_token_budget", {"action": "set_plan", "provider": "openai", "daily_token_limit": 250000}))
        assert res["limits"]["day"] == 250000
        read_res = json.loads(mcp_server.read_resource("padam://token-budget")["text"])
        assert read_res["checked_providers"] == 1
    finally:
        mcp_server._memory = prev_mem
        mem.close()


def test_studio_and_cli_budget_integration(tmp_path):
    html, _ = studio.page()
    assert 'id="ark-budget-btn"' in html
    assert "innerHTML" not in html
    assert "style=" not in html

    repo_root = Path(__file__).resolve().parents[1]
    db_file = tmp_path / "cli_bgt.db"
    proc = subprocess.run(
        [sys.executable, "-m", "padam", "--db", str(db_file), "budget", "status"],
        cwd=str(repo_root), capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["ok"] is True
