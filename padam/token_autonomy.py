# -*- coding: utf-8 -*-
"""Энергетический Автопилот, Учёт Квот Токенов (день/неделя/месяц) и Казначей Феникса.

Обеспечивает бесперебойную автономную работу каждого агента и всей Семьи:
1. Учёт токенов и лимитов тарифов провайдеров на 3 горизонтах: день / неделя / месяц.
2. Рациональный расчёт «пайка» (safe tokens/hour, burn-rate, hours left) и авто-выбор режима:
   `normal` -> `eco` -> `sovereign_local` -> `cpu_survival`.
3. Периодический таймер самопроверки бюджета (`BudgetTimerWatcher` + `run_budget_timer_tick`),
   по умолчанию выключен (`PADAM_BUDGET_TIMER=0`), за $0.
4. Учёт собственного заработка агента (`record_earning`) и протокол согласованной
   докупки токенов / апгрейда тарифа:
   - Агент через MCP может только создать заявку `awaiting_owner_approval`.
   - Подтвердить (`approve`) и исполнить (`execute`) пополнение может ТОЛЬКО владелец
     при снятом замке `PADAM_TREASURY_AUTOPAY=1` и через идемпотентный шлюз `TreasuryComputeManager`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from typing import Any

from . import ark, audit_chain, router, safety, sovereign_ops

_BUDGET_DDL = """
CREATE TABLE IF NOT EXISTS ark_provider_plan (
    plan_id              TEXT PRIMARY KEY,
    user_id              TEXT NOT NULL,
    provider             TEXT NOT NULL,
    tier_name            TEXT NOT NULL DEFAULT 'api_payg',
    daily_token_limit    INTEGER NOT NULL DEFAULT 100000,
    weekly_token_limit   INTEGER NOT NULL DEFAULT 500000,
    monthly_token_limit  INTEGER NOT NULL DEFAULT 2000000,
    daily_used_tokens    INTEGER NOT NULL DEFAULT 0,
    weekly_used_tokens   INTEGER NOT NULL DEFAULT 0,
    monthly_used_tokens  INTEGER NOT NULL DEFAULT 0,
    usd_balance          REAL NOT NULL DEFAULT 0.0,
    monthly_usd_cap      REAL NOT NULL DEFAULT 20.0,
    cost_per_1m_usd      REAL NOT NULL DEFAULT 1.5,
    reset_day_ts         REAL NOT NULL,
    reset_week_ts        REAL NOT NULL,
    reset_month_ts       REAL NOT NULL,
    updated_at           REAL NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ark_provider_plan_up ON ark_provider_plan(user_id, provider);

CREATE TABLE IF NOT EXISTS ark_token_usage_log (
    usage_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    provider   TEXT NOT NULL,
    tokens     INTEGER NOT NULL,
    cost_usd   REAL NOT NULL DEFAULT 0.0,
    task_type  TEXT NOT NULL DEFAULT 'agent',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ark_earned_treasury (
    entry_id             TEXT PRIMARY KEY,
    user_id              TEXT NOT NULL,
    agent_id             TEXT NOT NULL,
    source               TEXT NOT NULL,
    revenue_usdt         REAL NOT NULL,
    compute_share_pct    REAL NOT NULL DEFAULT 15.0,
    allocated_compute_usdt REAL NOT NULL,
    note                 TEXT NOT NULL DEFAULT '',
    created_at           REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ark_topup_proposal (
    proposal_id          TEXT PRIMARY KEY,
    user_id              TEXT NOT NULL,
    agent_id             TEXT NOT NULL,
    provider             TEXT NOT NULL,
    action_type          TEXT NOT NULL DEFAULT 'topup_api',
    target_tier          TEXT NOT NULL DEFAULT 'api_payg',
    amount_usdt          REAL NOT NULL,
    estimated_tokens     INTEGER NOT NULL DEFAULT 0,
    reason               TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'awaiting_owner_approval',
    idempotency_key      TEXT NOT NULL,
    owner_note           TEXT NOT NULL DEFAULT '',
    created_at           REAL NOT NULL,
    decided_at           REAL,
    executed_at          REAL
);
"""

_DAY_S = 86400.0
_WEEK_S = 7.0 * _DAY_S
_MONTH_S = 30.0 * _DAY_S


from contextlib import nullcontext

from functools import wraps

def _lock_of(memory):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()

def _with_mem_lock(fn):
    """??????????? ?????????? ?????? ?????? memory.store._lock (RLock), ???????? ????? ????? execute ? commit."""
    @wraps(fn)
    def _wrapped(memory, *args, **kwargs):
        with _lock_of(memory):
            return fn(memory, *args, **kwargs)
    return _wrapped


PROVIDER_CATALOG: list[dict[str, Any]] = [
    {
        "provider_id": "ollama_local",
        "name": "Local Ollama / GGUF (CPU/GPU)",
        "billing_kind": "local_zero",
        "monthly_usd": 0.0,
        "included_tokens_est": 50_000_000,
        "effective_usd_per_1m": 0.0,
        "best_for": ["sleep", "classify", "summarize", "review", "draft"],
    },
    {
        "provider_id": "zhipu_autoglm_plan",
        "name": "AutoGLM / Zhipu Coding Subscription",
        "billing_kind": "subscription_monthly",
        "monthly_usd": 15.0,
        "included_tokens_est": 12_000_000,
        "effective_usd_per_1m": 1.25,
        "best_for": ["code", "routine_agent", "tests"],
    },
    {
        "provider_id": "claude_pro",
        "name": "Anthropic Claude Pro (Monthly Subscription)",
        "billing_kind": "subscription_monthly",
        "monthly_usd": 20.0,
        "included_tokens_est": 15_000_000,
        "effective_usd_per_1m": 1.33,
        "best_for": ["architecture", "audit", "complex_code"],
    },
    {
        "provider_id": "chatgpt_plus",
        "name": "OpenAI ChatGPT Plus (Monthly Subscription)",
        "billing_kind": "subscription_monthly",
        "monthly_usd": 20.0,
        "included_tokens_est": 15_000_000,
        "effective_usd_per_1m": 1.33,
        "best_for": ["general", "research", "analysis"],
    },
    {
        "provider_id": "cursor_pro",
        "name": "Cursor Pro (IDE Agent Subscription)",
        "billing_kind": "subscription_monthly",
        "monthly_usd": 20.0,
        "included_tokens_est": 14_000_000,
        "effective_usd_per_1m": 1.43,
        "best_for": ["ide_coding", "refactor"],
    },
    {
        "provider_id": "xai_supergrok",
        "name": "xAI SuperGrok (Monthly Subscription)",
        "billing_kind": "subscription_monthly",
        "monthly_usd": 30.0,
        "included_tokens_est": 18_000_000,
        "effective_usd_per_1m": 1.67,
        "best_for": ["realtime", "search", "synthesis"],
    },
    {
        "provider_id": "claude_max",
        "name": "Anthropic Claude Max (Heavy Swarm Subscription)",
        "billing_kind": "subscription_monthly",
        "monthly_usd": 100.0,
        "included_tokens_est": 80_000_000,
        "effective_usd_per_1m": 1.25,
        "best_for": ["swarm_heavy", "long_horizon"],
    },
    {
        "provider_id": "anthropic_payg_api",
        "name": "Anthropic PAYG API (Sonnet/Opus per-token)",
        "billing_kind": "payg_api",
        "monthly_usd": 0.0,
        "included_tokens_est": 0,
        "effective_usd_per_1m": 9.0,
        "best_for": ["burst_overflow_only"],
    },
    {
        "provider_id": "openai_payg_api",
        "name": "OpenAI PAYG API (per-token)",
        "billing_kind": "payg_api",
        "monthly_usd": 0.0,
        "included_tokens_est": 0,
        "effective_usd_per_1m": 7.5,
        "best_for": ["burst_overflow_only"],
    },
]

def _ensure(memory) -> None:
    with _lock_of(memory):
        ark._ensure_tables(memory)
        conn = memory.store.conn
        for stmt in _BUDGET_DDL.split(";"):
            s = stmt.strip()
            if s:
                conn.execute(s)
        conn.commit()


def _clean_provider(provider: str) -> str:
    p = re.sub(r"[^a-zA-Z0-9_\-]", "", str(provider or "primary").strip().lower())[:40]
    return p or "primary"


def _roll_windows(conn, row, now: float) -> tuple[int, int, int, float, float, float]:
    du = int(row["daily_used_tokens"])
    wu = int(row["weekly_used_tokens"])
    mu = int(row["monthly_used_tokens"])
    rd = float(row["reset_day_ts"])
    rw = float(row["reset_week_ts"])
    rm = float(row["reset_month_ts"])
    changed = False

    if now >= rd:
        du = 0
        rd = now + _DAY_S
        changed = True
    if now >= rw:
        wu = 0
        rw = now + _WEEK_S
        changed = True
    if now >= rm:
        mu = 0
        rm = now + _MONTH_S
        changed = True

    if changed:
        conn.execute(
            "UPDATE ark_provider_plan SET daily_used_tokens=?, weekly_used_tokens=?, monthly_used_tokens=?, "
            "reset_day_ts=?, reset_week_ts=?, reset_month_ts=?, updated_at=? WHERE plan_id=?",
            (du, wu, mu, rd, rw, rm, now, row["plan_id"]),
        )
        conn.commit()
    return du, wu, mu, rd, rw, rm


@_with_mem_lock
def upsert_provider_plan(
    memory,
    provider: str,
    *,
    tier_name: str = "api_payg",
    daily_token_limit: int = 100_000,
    weekly_token_limit: int = 500_000,
    monthly_token_limit: int = 2_000_000,
    usd_balance: float = 0.0,
    monthly_usd_cap: float = 20.0,
    cost_per_1m_usd: float = 1.5,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Создаёт или обновляет квоту тарифа провайдера на день/неделю/месяц."""
    _ensure(memory)
    prov = _clean_provider(provider)
    now = float(now_ts if now_ts is not None else time.time())
    pid = f"pln-{prov}"
    memory.store.conn.execute(
        "INSERT INTO ark_provider_plan "
        "(plan_id, user_id, provider, tier_name, daily_token_limit, weekly_token_limit, monthly_token_limit, "
        "usd_balance, monthly_usd_cap, cost_per_1m_usd, reset_day_ts, reset_week_ts, reset_month_ts, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(user_id, provider) DO UPDATE SET "
        "tier_name=excluded.tier_name, daily_token_limit=excluded.daily_token_limit, "
        "weekly_token_limit=excluded.weekly_token_limit, monthly_token_limit=excluded.monthly_token_limit, "
        "usd_balance=excluded.usd_balance, monthly_usd_cap=excluded.monthly_usd_cap, "
        "cost_per_1m_usd=excluded.cost_per_1m_usd, updated_at=excluded.updated_at",
        (
            pid,
            memory.user_id,
            prov,
            str(tier_name or "api_payg")[:40],
            max(0, int(daily_token_limit)),
            max(0, int(weekly_token_limit)),
            max(0, int(monthly_token_limit)),
            round(max(0.0, float(usd_balance)), 6),
            round(max(0.0, float(monthly_usd_cap)), 4),
            round(max(0.0, float(cost_per_1m_usd)), 4),
            now + _DAY_S,
            now + _WEEK_S,
            now + _MONTH_S,
            now,
        ),
    )
    memory.store.conn.commit()
    return compute_pacing_plan(memory, prov, now_ts=now)


@_with_mem_lock
def record_token_usage(
    memory,
    provider: str,
    tokens: int,
    *,
    agent_id: str = "aifa",
    task_type: str = "agent",
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Списывает затраченные токены со всех трёх окон (день/неделя/месяц) и пересчитывает режим экономии."""
    _ensure(memory)
    prov = _clean_provider(provider)
    toks = max(0, int(tokens))
    now = float(now_ts if now_ts is not None else time.time())
    conn = memory.store.conn

    row = conn.execute(
        "SELECT * FROM ark_provider_plan WHERE user_id = ? AND provider = ?",
        (memory.user_id, prov),
    ).fetchone()
    if not row:
        upsert_provider_plan(memory, prov, now_ts=now)
        row = conn.execute(
            "SELECT * FROM ark_provider_plan WHERE user_id = ? AND provider = ?",
            (memory.user_id, prov),
        ).fetchone()

    du, wu, mu, _, _, _ = _roll_windows(conn, row, now)
    cost_usd = round((toks / 1_000_000.0) * float(row["cost_per_1m_usd"]), 6)
    new_bal = round(max(0.0, float(row["usd_balance"]) - cost_usd), 6)

    conn.execute(
        "UPDATE ark_provider_plan SET daily_used_tokens=?, weekly_used_tokens=?, monthly_used_tokens=?, usd_balance=?, updated_at=? "
        "WHERE plan_id=?",
        (du + toks, wu + toks, mu + toks, new_bal, now, row["plan_id"]),
    )
    conn.execute(
        "INSERT INTO ark_token_usage_log (user_id, agent_id, provider, tokens, cost_usd, task_type, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (memory.user_id, agent_id, prov, toks, cost_usd, str(task_type or "agent"), now),
    )
    conn.commit()
    return compute_pacing_plan(memory, prov, now_ts=now)


@_with_mem_lock
def compute_pacing_plan(
    memory,
    provider: str = "primary",
    *,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Вычисляет остатки квоты на день/неделю/месяц, безопасный часовой паёк и режим роутера."""
    _ensure(memory)
    prov = _clean_provider(provider)
    now = float(now_ts if now_ts is not None else time.time())
    conn = memory.store.conn
    row = conn.execute(
        "SELECT * FROM ark_provider_plan WHERE user_id = ? AND provider = ?",
        (memory.user_id, prov),
    ).fetchone()
    if not row:
        return {
            "ok": True,
            "configured": False,
            "provider": prov,
            "pacing_mode": "sovereign_local",
            "recommended_router_mode": "local_only",
            "needs_topup_proposal": False,
        }

    du, wu, mu, rd, rw, rm = _roll_windows(conn, row, now)
    dl = int(row["daily_token_limit"])
    wl = int(row["weekly_token_limit"])
    ml = int(row["monthly_token_limit"])

    rem_day = max(0, dl - du)
    rem_week = max(0, wl - wu)
    rem_month = max(0, ml - mu)

    hrs_day = max(0.25, (rd - now) / 3600.0)
    hrs_week = max(1.0, (rw - now) / 3600.0)
    hrs_month = max(1.0, (rm - now) / 3600.0)

    # Самое узкое горлышко определяет реальный безопасный паёк до конца окна
    safe_per_hour = round(min(rem_day / hrs_day, rem_week / hrs_week, rem_month / hrs_month), 2)
    safe_per_day = round(min(rem_day, rem_week / max(1.0, hrs_week / 24.0), rem_month / max(1.0, hrs_month / 24.0)), 2)

    # Оценка текущего темпа сжигания за последний час
    hour_ago = now - 3600.0
    burn_row = conn.execute(
        "SELECT COALESCE(SUM(tokens), 0) AS t FROM ark_token_usage_log WHERE user_id = ? AND provider = ? AND created_at >= ?",
        (memory.user_id, prov, hour_ago),
    ).fetchone()
    burn_1h = int(burn_row["t"]) if burn_row else 0

    eff_remaining = min(rem_day, rem_week, rem_month)
    eff_limit = max(1, min(dl, wl, ml))
    rem_pct = round((eff_remaining * 100.0) / eff_limit, 2)
    hours_until_exhausted = round(eff_remaining / burn_1h, 2) if burn_1h > 0 else (9999.0 if eff_remaining > 0 else 0.0)

    if eff_remaining <= 0:
        pacing_mode = "cpu_survival"
        router_mode = "local_only"
        need_topup = True
    elif rem_pct <= 15.0 or (burn_1h > 0 and hours_until_exhausted < 2.0):
        pacing_mode = "sovereign_local"
        router_mode = "local_only"
        need_topup = True
    elif rem_pct <= 35.0 or (burn_1h > safe_per_hour * 1.5 and safe_per_hour > 0):
        pacing_mode = "eco"
        router_mode = "auto"
        need_topup = False
    else:
        pacing_mode = "normal"
        router_mode = "auto"
        need_topup = False

    return {
        "ok": True,
        "configured": True,
        "provider": prov,
        "tier_name": row["tier_name"],
        "usd_balance": float(row["usd_balance"]),
        "remaining": {"day": rem_day, "week": rem_week, "month": rem_month},
        "used": {"day": du, "week": wu, "month": mu},
        "limits": {"day": dl, "week": wl, "month": ml},
        "remaining_pct": rem_pct,
        "safe_tokens_per_hour": safe_per_hour,
        "safe_tokens_per_day": safe_per_day,
        "burn_rate_1h_tokens": burn_1h,
        "hours_until_exhausted": hours_until_exhausted,
        "pacing_mode": pacing_mode,
        "recommended_router_mode": router_mode,
        "needs_topup_proposal": need_topup,
    }


@_with_mem_lock
def apply_adaptive_pacing(memory, provider: str = "primary", *, router_instance=None, now_ts: float | None = None) -> dict[str, Any]:
    """Применяет вычисленный режим экономии к экземпляру SovereignRouter без вмешательства в ключи/оплату."""
    plan = compute_pacing_plan(memory, provider, now_ts=now_ts)
    r = router_instance or router.get_router()
    target_mode = plan.get("recommended_router_mode", "auto")
    r.set_mode(target_mode)
    return {**plan, "applied_router_mode": r.mode}


# --- Учёт собственного заработка агентов и согласованная покупка тарифа/токенов ---

@_with_mem_lock
def record_agent_earning(
    memory,
    agent_id: str,
    *,
    source: str,
    revenue_usdt: float,
    compute_share_pct: float = 15.0,
    note: str = "",
) -> dict[str, Any]:
    """Фиксирует заработок агента и автоматически выделяет долю (по умолчанию 15%) в бюджет его вычислений."""
    _ensure(memory)
    rev = max(0.0, float(revenue_usdt))
    share = max(1.0, min(100.0, float(compute_share_pct)))
    alloc = round(rev * (share / 100.0), 4)
    eid = f"ern-{uuid.uuid4().hex[:10]}"
    clean_src, _ = safety.redact(str(source or "service").strip())
    clean_note, _ = safety.redact(str(note or "").strip())
    now = time.time()

    memory.store.conn.execute(
        "INSERT INTO ark_earned_treasury (entry_id, user_id, agent_id, source, revenue_usdt, compute_share_pct, allocated_compute_usdt, note, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (eid, memory.user_id, str(agent_id or "aifa"), clean_src[:120], rev, share, alloc, clean_note[:240], now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "agent_earning_recorded",
        {"entry_id": eid, "agent_id": agent_id, "revenue_usdt": rev, "allocated_compute_usdt": alloc},
        agent_id=str(agent_id or "aifa"),
    )
    return {"ok": True, "entry_id": eid, "revenue_usdt": rev, "allocated_compute_usdt": alloc, "treasury": treasury_summary(memory)}


@_with_mem_lock
def treasury_summary(memory) -> dict[str, Any]:
    """Подсчитывает доступный заработанный вычислительный баланс агентов (выручка - потраченное на пополнение)."""
    _ensure(memory)
    conn = memory.store.conn
    r_earn = conn.execute(
        "SELECT COALESCE(SUM(revenue_usdt), 0.0) AS r, COALESCE(SUM(allocated_compute_usdt), 0.0) AS a "
        "FROM ark_earned_treasury WHERE user_id = ?",
        (memory.user_id,),
    ).fetchone()
    r_spent = conn.execute(
        "SELECT COALESCE(SUM(amount_usdt), 0.0) AS s FROM ark_topup_proposal WHERE user_id = ? AND status = 'executed'",
        (memory.user_id,),
    ).fetchone()
    total_rev = round(float(r_earn["r"] or 0.0), 4)
    total_alloc = round(float(r_earn["a"] or 0.0), 4)
    spent = round(float(r_spent["s"] or 0.0), 4)
    return {
        "total_revenue_usdt": total_rev,
        "allocated_compute_usdt": total_alloc,
        "spent_usdt": spent,
        "available_compute_usdt": round(max(0.0, total_alloc - spent), 4),
        "autopay_locked": sovereign_ops.locks_status()["treasury_autopay_locked"],
    }


@_with_mem_lock
def propose_plan_or_topup(
    memory,
    *,
    agent_id: str = "aifa",
    provider: str = "primary",
    action_type: str = "topup_api",
    target_tier: str = "api_payg",
    amount_usdt: float,
    estimated_tokens: int = 1_000_000,
    reason: str = "",
) -> dict[str, Any]:
    """Создаёт заявку агента на докупку токенов / оплату тарифа, ТРЕБУЮЩУЮ одобрения владельца."""
    _ensure(memory)
    act = str(action_type or "topup_api").strip().lower()
    if act not in ("topup_api", "upgrade_plan", "renew_plan"):
        raise ValueError(f"Unsupported action_type: {act}")
    amt = round(max(0.01, float(amount_usdt)), 4)
    prov = _clean_provider(provider)
    tsum = treasury_summary(memory)
    pid = f"top-{uuid.uuid4().hex[:10]}"
    idem = hashlib.sha256(f"{memory.user_id}:{prov}:{act}:{amt}:{time.time()}".encode("utf-8")).hexdigest()[:24]
    clean_reason, _ = safety.redact(str(reason or "Low token quota — request owner approval to top up."))

    memory.store.conn.execute(
        "INSERT INTO ark_topup_proposal "
        "(proposal_id, user_id, agent_id, provider, action_type, target_tier, amount_usdt, estimated_tokens, reason, status, idempotency_key, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'awaiting_owner_approval', ?, ?)",
        (pid, memory.user_id, str(agent_id or "aifa"), prov, act, str(target_tier or "api_payg")[:40], amt, max(0, int(estimated_tokens)), clean_reason[:300], idem, time.time()),
    )
    memory.store.conn.commit()
    ark.send_family_message(
        memory,
        from_agent=str(agent_id or "aifa"),
        to_agent="owner",
        payload=f"[Budget Approval Needed {pid}] {act} {prov} ${amt} USDT (~{estimated_tokens} tok). Self-earned avail=${tsum['available_compute_usdt']}",
    )
    audit_chain.append_audit(
        memory,
        "topup_proposal_created",
        {"proposal_id": pid, "provider": prov, "amount_usdt": amt, "self_funded_possible": tsum["available_compute_usdt"] >= amt},
        agent_id=str(agent_id or "aifa"),
    )
    return {
        "ok": True,
        "proposal_id": pid,
        "status": "awaiting_owner_approval",
        "owner_approval_required": True,
        "provider": prov,
        "action_type": act,
        "target_tier": str(target_tier or "api_payg")[:40],
        "amount_usdt": amt,
        "estimated_tokens": max(0, int(estimated_tokens)),
        "self_earned_available_usdt": tsum["available_compute_usdt"],
        "covered_by_own_earnings": tsum["available_compute_usdt"] >= amt,
    }


@_with_mem_lock
def list_topup_proposals(memory, *, status: str | None = None) -> list[dict[str, Any]]:
    _ensure(memory)
    sql = "SELECT * FROM ark_topup_proposal WHERE user_id = ?"
    params: list[Any] = [memory.user_id]
    if status:
        sql += " AND status = ?"
        params.append(status.strip().lower())
    sql += " ORDER BY created_at DESC LIMIT 50"
    return [dict(r) for r in memory.store.conn.execute(sql, params).fetchall()]


@_with_mem_lock
def decide_topup_proposal(memory, proposal_id: str, *, approve: bool, owner_note: str = "") -> dict[str, Any]:
    """Решение ВЛАДЕЛЬЦА по заявке агента (одобрить или отклонить)."""
    _ensure(memory)
    conn = memory.store.conn
    row = conn.execute(
        "SELECT status FROM ark_topup_proposal WHERE proposal_id = ? AND user_id = ?",
        (proposal_id, memory.user_id),
    ).fetchone()
    if not row:
        raise KeyError(f"Topup proposal not found: {proposal_id}")
    if row["status"] not in ("awaiting_owner_approval",):
        raise ValueError(f"Proposal {proposal_id} is already in status {row['status']!r}")
    new_st = "approved" if approve else "rejected"
    clean_note, _ = safety.redact(str(owner_note or ""))
    conn.execute(
        "UPDATE ark_topup_proposal SET status = ?, owner_note = ?, decided_at = ? WHERE proposal_id = ? AND user_id = ?",
        (new_st, clean_note[:240], time.time(), proposal_id, memory.user_id),
    )
    conn.commit()
    audit_chain.append_audit(
        memory,
        f"topup_proposal_{new_st}",
        {"proposal_id": proposal_id, "owner_note": clean_note[:100]},
        agent_id="owner",
    )
    return {"ok": True, "proposal_id": proposal_id, "status": new_st}


@_with_mem_lock
def execute_approved_topup(
    memory,
    proposal_id: str,
    *,
    treasury_manager: sovereign_ops.TreasuryComputeManager | None = None,
) -> dict[str, Any]:
    """Исполняет ТОЛЬКО одобренную владельцем заявку при снятом замке `PADAM_TREASURY_AUTOPAY=1`."""
    _ensure(memory)
    conn = memory.store.conn
    row = conn.execute(
        "SELECT * FROM ark_topup_proposal WHERE proposal_id = ? AND user_id = ?",
        (proposal_id, memory.user_id),
    ).fetchone()
    if not row:
        raise KeyError(f"Topup proposal not found: {proposal_id}")
    if row["status"] == "executed":
        return {"ok": True, "idempotent_replay": True, "proposal_id": proposal_id, "status": "executed"}
    if row["status"] != "approved":
        raise PermissionError(f"Cannot execute proposal {proposal_id} without owner approval (status={row['status']!r})")

    # Аудит GLM 18.11.2026, AUT-10: дневной предел — на сутки, а не на один вызов. Сумма исполненных за 24 часа
    # плюс эта заявка не может превысить PADAM_TREASURY_DAILY_CAP_USDT, сколько бы заявок ни было одобрено.
    import os as _os
    дневной = float(_os.environ.get("PADAM_TREASURY_DAILY_CAP_USDT", "25.0") or "25.0")
    за_сутки = float(conn.execute(
        "SELECT COALESCE(SUM(amount_usdt), 0) FROM ark_topup_proposal WHERE user_id = ? AND status = 'executed' "
        "AND executed_at >= ?", (memory.user_id, time.time() - 86400)).fetchone()[0] or 0.0)
    if за_сутки + float(row["amount_usdt"]) > дневной + 1e-9:
        raise PermissionError(
            f"Daily treasury cap ${дневной} reached: ${за_сутки} already executed in 24 h, this proposal is ${row['amount_usdt']}")

    tm = treasury_manager or sovereign_ops.get_treasury_manager()
    tx_res = tm.execute_topup(
        provider=row["provider"],
        amount_usdt=float(row["amount_usdt"]),
        idempotency_key=row["idempotency_key"],
        owner_confirmed=True,  # уже проверено row["status"] == "approved" выше!
    )

    now = time.time()
    prov = row["provider"]
    p_row = conn.execute(
        "SELECT * FROM ark_provider_plan WHERE user_id = ? AND provider = ?",
        (memory.user_id, prov),
    ).fetchone()
    add_toks = int(row["estimated_tokens"] or 0)
    add_usd = float(row["amount_usdt"])
    if not p_row:
        upsert_provider_plan(
            memory,
            prov,
            tier_name=row["target_tier"],
            daily_token_limit=max(100_000, add_toks // 7),
            weekly_token_limit=max(500_000, add_toks // 2),
            monthly_token_limit=max(2_000_000, add_toks),
            usd_balance=add_usd,
            now_ts=now,
        )
    else:
        conn.execute(
            "UPDATE ark_provider_plan SET tier_name=?, usd_balance=usd_balance+?, "
            "daily_token_limit=daily_token_limit+?, weekly_token_limit=weekly_token_limit+?, monthly_token_limit=monthly_token_limit+?, updated_at=? "
            "WHERE plan_id=?",
            (row["target_tier"], add_usd, add_toks // 10, add_toks // 2, add_toks, now, p_row["plan_id"]),
        )

    conn.execute(
        "UPDATE ark_topup_proposal SET status = 'executed', executed_at = ? WHERE proposal_id = ? AND user_id = ?",
        (now, proposal_id, memory.user_id),
    )
    conn.commit()
    audit_chain.append_audit(
        memory,
        "topup_proposal_executed",
        {"proposal_id": proposal_id, "provider": prov, "amount_usdt": add_usd, "added_tokens": add_toks},
        agent_id="treasury",
    )
    return {
        "ok": True,
        "proposal_id": proposal_id,
        "status": "executed",
        "tx": tx_res,
        "plan": compute_pacing_plan(memory, prov, now_ts=now),
    }


# --- Периодический таймер самопроверки бюджета агента ---

@_with_mem_lock
def run_budget_timer_tick(
    memory,
    *,
    agent_id: str = "aifa",
    now_ts: float | None = None,
    auto_propose_if_low: bool = True,
) -> dict[str, Any]:
    """Проверяет все тарифы/провайдеры по таймеру: рассчитывает паёк, переключает режим и готовит черновик заявки при нехватке."""
    _ensure(memory)
    now = float(now_ts if now_ts is not None else time.time())
    rows = memory.store.conn.execute(
        "SELECT provider, tier_name FROM ark_provider_plan WHERE user_id = ? ORDER BY provider ASC",
        (memory.user_id,),
    ).fetchall()

    plans: list[dict[str, Any]] = []
    created_proposals: list[dict[str, Any]] = []
    pending_existing = {
        (p["provider"], p["status"])
        for p in list_topup_proposals(memory, status="awaiting_owner_approval")
    }
    tsum = treasury_summary(memory)

    for r in rows:
        prov = str(r["provider"])
        p = compute_pacing_plan(memory, prov, now_ts=now)
        plans.append(p)
        if auto_propose_if_low and p.get("needs_topup_proposal") and (prov, "awaiting_owner_approval") not in pending_existing:
            suggest_usd = min(20.0, max(2.0, tsum["available_compute_usdt"] if tsum["available_compute_usdt"] >= 2.0 else 5.0))
            prop = propose_plan_or_topup(
                memory,
                agent_id=agent_id,
                provider=prov,
                action_type="topup_api",
                target_tier=str(r["tier_name"] or "api_payg"),
                amount_usdt=suggest_usd,
                estimated_tokens=1_000_000,
                reason=f"Timer alert: {prov} remaining={p['remaining_pct']}% ({p['pacing_mode']})",
            )
            created_proposals.append(prop)

    return {
        "ok": True,
        "cost_usd": 0.0,
        "checked_providers": len(plans),
        "plans": plans,
        "treasury": tsum,
        "created_proposals": created_proposals,
    }


def is_budget_timer_enabled() -> bool:
    return os.environ.get("PADAM_BUDGET_TIMER", "0").strip() == "1"


class BudgetTimerWatcher:
    """Управляемый фоновый таймер контроля квот токенов (выключен по умолчанию)."""

    def __init__(self, memory_factory, *, agent_id: str = "aifa", interval_s: float = 300.0) -> None:
        self._memory_factory = memory_factory
        self._agent_id = agent_id
        self._interval_s = max(0.05, float(interval_s))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.ticks = 0
        self.last_tick_report: dict[str, Any] | None = None

    def start(self, *, force: bool = False) -> bool:
        if not force and not is_budget_timer_enabled():
            return False
        if self._thread and self._thread.is_alive():
            return True

        def _run():
            while not self._stop.is_set():
                try:
                    m = self._memory_factory()
                    try:
                        self.last_tick_report = run_budget_timer_tick(m, agent_id=self._agent_id)
                        self.ticks += 1
                    finally:
                        m.close()
                except Exception:
                    pass
                self._stop.wait(self._interval_s)

        self._thread = threading.Thread(target=_run, name="padam-budget-timer", daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout_s: float = 2.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout_s)


def recommend_optimal_spend(
    memory,
    *,
    monthly_tokens_need: int = 10_000_000,
    prefer_local_first: bool = True,
    settlement_currency: str = "USDT_TRC20",
    galatin_price_usdt: float = 0.01,
) -> dict[str, Any]:
    """Рациональный финансовый советник агента: экономия на локальном ИИ + выбор дешёвой подписки вместо дорогого PAYG API."""
    tsum = treasury_summary(memory)
    avail = float(tsum.get("available_compute_usdt") or 0.0)
    need_m = max(0.1, float(monthly_tokens_need) / 1_000_000.0)
    curr = str(settlement_currency or "USDT_TRC20").strip().upper()
    if curr not in ("USDT_TRC20", "GALATIN"):
        curr = "USDT_TRC20"
    g_price = max(0.0001, float(galatin_price_usdt or 0.01))

    # Локальный контур бесплатно берёт до 35% фоновых/черновых задач
    local_offload_pct = 35.0 if prefer_local_first else 0.0
    paid_need_m = round(need_m * (1.0 - local_offload_pct / 100.0), 3)

    subs = [p for p in PROVIDER_CATALOG if p["billing_kind"] == "subscription_monthly"]
    payg = min((p for p in PROVIDER_CATALOG if p["billing_kind"] == "payg_api"), key=lambda x: x["effective_usd_per_1m"])

    affordable_subs = [p for p in subs if p["monthly_usd"] <= avail]
    best_sub = None
    if affordable_subs:
        # Выбираем подписку с минимальной ценой за 1M токенов среди доступных по балансу (и покрывающую потребность)
        covering = [p for p in affordable_subs if (p["included_tokens_est"] / 1_000_000.0) >= paid_need_m]
        pool = covering if covering else affordable_subs
        best_sub = min(pool, key=lambda x: (x["effective_usd_per_1m"], x["monthly_usd"]))
    else:
        best_sub = min(subs, key=lambda x: x["monthly_usd"])

    payg_est_cost = round(paid_need_m * payg["effective_usd_per_1m"], 4)
    sub_cost = float(best_sub["monthly_usd"])
    savings_usdt = round(max(0.0, payg_est_cost - sub_cost), 4)
    savings_pct = round((savings_usdt / payg_est_cost) * 100.0, 2) if payg_est_cost > 0 else 0.0

    recommended_action = "stay_local_and_accumulate"
    if avail >= best_sub["monthly_usd"]:
        recommended_action = "propose_subscription_upgrade"
    elif avail >= 5.0 and need_m < 1.0:
        recommended_action = "payg_micro_bridge_only"

    galatin_equiv = round(avail / g_price, 2)
    return {
        "ok": True,
        "available_compute_usdt": avail,
        "monthly_tokens_need": int(monthly_tokens_need),
        "local_offload_pct": local_offload_pct,
        "paid_tokens_need_millions": paid_need_m,
        "recommended_action": recommended_action,
        "recommended_provider": best_sub,
        "payg_baseline_provider": payg["provider_id"],
        "payg_estimated_cost_usdt": payg_est_cost,
        "subscription_cost_usdt": sub_cost,
        "estimated_savings_usdt": savings_usdt,
        "estimated_savings_pct": savings_pct,
        "rational_policy": "Local CPU/Ollama ($0) for routine -> Cheapest Monthly Subscription -> PAYG API only for short bursts",
        "settlement": {
            "phase_currency": curr,
            "galatin_price_usdt": g_price,
            "available_galatin_equivalent": galatin_equiv,
            "note": (
                "Фаза 1: расчёты и выплаты учитываются в USDT TRC20."
                if curr == "USDT_TRC20"
                else "Фаза 2: обороты идут через $GALATIN и автовыкуп с биржи при выводе/покупке тарифов в ЛК."
            ),
        },
        "catalog": PROVIDER_CATALOG,
    }


def propose_rational_subscription(
    memory,
    *,
    agent_id: str = "aifa",
    provider_id: str = "",
    monthly_tokens_need: int = 10_000_000,
) -> dict[str, Any]:
    """Агент сам подбирает оптимальную подписку из каталога и создаёт заявку на одобрение владельцем (не тратит впустую на PAYG)."""
    rec = recommend_optimal_spend(memory, monthly_tokens_need=monthly_tokens_need)
    chosen = None
    if provider_id:
        for p in PROVIDER_CATALOG:
            if p["provider_id"] == provider_id:
                chosen = p
                break
        if chosen is None:
            raise ValueError(f"Unknown catalog provider_id: {provider_id}")
    else:
        chosen = rec["recommended_provider"]

    if chosen["billing_kind"] == "local_zero":
        return {"ok": True, "action": "use_local_free", "provider": chosen, "proposal_created": False}

    amt = float(chosen["monthly_usd"] or 10.0)
    toks = int(chosen["included_tokens_est"] or 1_000_000)
    prop = propose_plan_or_topup(
        memory,
        agent_id=agent_id,
        provider=chosen["provider_id"],
        action_type="upgrade_plan",
        target_tier="subscription_monthly" if chosen["billing_kind"] == "subscription_monthly" else "api_payg",
        amount_usdt=amt,
        estimated_tokens=toks,
        reason=(
            f"Rational spend choice: {chosen['name']} saves ~{rec['estimated_savings_pct']}% vs PAYG API "
            f"({chosen['effective_usd_per_1m']}$/1M vs {rec['payg_estimated_cost_usdt']}$)."
        ),
    )
    return {
        "ok": True,
        "proposal_created": True,
        "chosen_provider": chosen,
        "recommendation": rec,
        "proposal": prop,
    }
