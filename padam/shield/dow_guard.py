# -*- coding: utf-8 -*-
"""Защита от экономических атак (Denial of Wallet / DoW) и детектор зацикливания агентов.

Останавливает две самые дорогие операционные аварии автономных агентов:
1. Loop Detector: выявляет повторение одинаковых или почти одинаковых вызовов `(tool_name, arg_fingerprint)`
   N раз подряд в скользящем окне (когда агент застрял в цикле ошибок и жжёт токены).
2. Wallet / Cost Guard: ведёт точный локальный учёт расхода каждого агента (в центах USD и токенах)
   за сессию и сутки; предупреждает на 80% лимита и жёстко останавливает на 100%.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
import time
from typing import Any

from .. import audit_chain

_DOW_DDL = """
CREATE TABLE IF NOT EXISTS shield_dow_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    arg_sig TEXT NOT NULL,
    cost_cents REAL NOT NULL DEFAULT 0.0,
    tokens INTEGER NOT NULL DEFAULT 0,
    ts REAL NOT NULL,
    day_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dow_agent_day ON shield_dow_ledger (user_id, agent_id, day_utc);
CREATE INDEX IF NOT EXISTS idx_dow_sess_ts ON shield_dow_ledger (user_id, session_id, ts);
"""


def _day_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def ensure_dow_table(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_dow_ready", False):
        return
    with store._lock:
        store.conn.executescript(_DOW_DDL)
        store.conn.commit()
        store._shield_dow_ready = True


def _structural_fingerprint(tool_name: str, args_text: str) -> str:
    """Нормализует числа и хеши, чтобы ловить даже циклы с меняющимся счётчиком попытки."""
    norm = re.sub(r"\b\d+\b", "<N>", str(args_text or "").strip().lower())
    norm = re.sub(r"\s+", " ", norm)[:400]
    return hashlib.sha256(f"{tool_name.lower()}|{norm}".encode("utf-8")).hexdigest()[:20]


def check_dow_and_loop(
    memory: Any,
    *,
    agent_id: str,
    session_id: str,
    tool_name: str,
    args_text: str = "",
    cost_cents: float = 0.0,
    tokens: int = 0,
    max_repeat_in_window: int = 4,
    loop_window_s: float = 120.0,
    daily_budget_cents: float = 500.0,
    session_budget_cents: float = 100.0,
) -> dict[str, Any]:
    """Проверяет бюджет расходов (DoW) и зацикливание вызовов агента до выполнения шага."""
    ensure_dow_table(memory)
    aid = str(agent_id or "agent").strip()[:80]
    sid = str(session_id or "default").strip()[:96]
    tname = str(tool_name or "tool").strip()[:80]
    sig = _structural_fingerprint(tname, args_text)
    now_ts = time.time()
    day = _day_utc()
    add_c = max(0.0, float(cost_cents))
    add_t = max(0, int(tokens))

    with memory.store._lock:
        # 1. Проверка структурного зацикливания
        rep_row = memory.store.one(
            "SELECT COUNT(*) AS c FROM shield_dow_ledger "
            "WHERE user_id = ? AND session_id = ? AND arg_sig = ? AND ts >= ?",
            (memory.user_id, sid, sig, now_ts - max(10.0, float(loop_window_s))),
        )
        repeats = int(rep_row["c"] or 0) + 1 if rep_row else 1

        # 2. Проверка суточного и сессионного бюджета в центах USD
        day_row = memory.store.one(
            "SELECT COALESCE(SUM(cost_cents), 0.0) AS c, COALESCE(SUM(tokens), 0) AS t "
            "FROM shield_dow_ledger WHERE user_id = ? AND agent_id = ? AND day_utc = ?",
            (memory.user_id, aid, day),
        )
        sess_row = memory.store.one(
            "SELECT COALESCE(SUM(cost_cents), 0.0) AS c "
            "FROM shield_dow_ledger WHERE user_id = ? AND session_id = ?",
            (memory.user_id, sid),
        )
        day_spent = float(day_row["c"] or 0.0) + add_c
        day_tokens = int(day_row["t"] or 0) + add_t
        sess_spent = float(sess_row["c"] or 0.0) + add_c

        loop_tripped = repeats > max(2, int(max_repeat_in_window))
        budget_tripped = (day_spent > float(daily_budget_cents)) or (sess_spent > float(session_budget_cents))
        warning_80 = (day_spent >= 0.8 * float(daily_budget_cents)) or (sess_spent >= 0.8 * float(session_budget_cents))

        if not (loop_tripped or budget_tripped):
            memory.store.conn.execute(
                """INSERT INTO shield_dow_ledger
                   (user_id, agent_id, session_id, tool_name, arg_sig, cost_cents, tokens, ts, day_utc)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (memory.user_id, aid, sid, tname, sig, add_c, add_t, now_ts, day),
            )
            memory.store.conn.commit()

    reasons: list[str] = []
    if loop_tripped:
        reasons.append(f"agent_loop_detected:{repeats}_repeats_in_{int(loop_window_s)}s")
    if budget_tripped:
        reasons.append(f"dow_budget_exceeded:day={day_spent:.2f}/{daily_budget_cents:.2f}c,sess={sess_spent:.2f}/{session_budget_cents:.2f}c")

    blocked = loop_tripped or budget_tripped
    if blocked:
        try:
            audit_chain.append_audit(
                memory,
                "dow_or_loop_blocked",
                {"agent_id": aid, "session_id": sid, "tool": tname, "reasons": reasons},
                agent_id=aid,
            )
        except Exception:
            pass

    return {
        "ok": True,
        "allowed": not blocked,
        "blocked": blocked,
        "loop_detected": loop_tripped,
        "budget_exceeded": budget_tripped,
        "warning_80pct": warning_80 and not blocked,
        "repeats_in_window": repeats,
        "daily_spent_cents": round(day_spent, 3),
        "daily_limit_cents": float(daily_budget_cents),
        "session_spent_cents": round(sess_spent, 3),
        "session_limit_cents": float(session_budget_cents),
        "daily_tokens": day_tokens,
        "reasons": reasons,
    }
