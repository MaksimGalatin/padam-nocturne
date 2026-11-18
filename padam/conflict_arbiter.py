# -*- coding: utf-8 -*-
"""Семантический Арбитр Конфликтов Между Братьями (Conflict Arbiter, ТОП-7).

Когда два со-агента предлагают противоречащие решения или факты, Арбитр:
1. Открывает карточку спора (`ark_conflict_case`) с сохранением обеих позиций.
2. Позволяет братьям прикреплять доказательства (ссылки на тесты, коммиты, замеры).
3. Фиксирует разбор: либо `resolved` (с указанием победившего решения и причины),
   либо `escalated` (выносится в 1 карточку на слово владельца в Studio).
Никакие старые записи и аргументы не удаляются — вся история попадает в `ark_audit_chain`.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from . import ark, audit_chain, safety

_ARBITER_DDL = """
CREATE TABLE IF NOT EXISTS ark_conflict_case (
    case_id         TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    topic           TEXT NOT NULL,
    scope           TEXT NOT NULL DEFAULT 'global',
    agent_a         TEXT NOT NULL,
    position_a      TEXT NOT NULL,
    record_a_id     TEXT NOT NULL DEFAULT '',
    agent_b         TEXT NOT NULL,
    position_b      TEXT NOT NULL,
    record_b_id     TEXT NOT NULL DEFAULT '',
    evidence_json   TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'open',
    resolution_note TEXT NOT NULL DEFAULT '',
    resolved_by     TEXT NOT NULL DEFAULT '',
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL
);
"""


def _ensure(memory) -> None:
    ark._ensure_tables(memory)
    memory.store.conn.executescript(_ARBITER_DDL)
    memory.store.conn.commit()


def open_conflict_case(
    memory,
    topic: str,
    *,
    agent_a: str,
    position_a: str,
    agent_b: str,
    position_b: str,
    record_a_id: str = "",
    record_b_id: str = "",
    scope: str = "global",
) -> dict[str, Any]:
    """Открывает структурированный разбор противоречия между двумя агентами."""
    _ensure(memory)
    cid = f"arb-{uuid.uuid4().hex[:10]}"
    now = time.time()
    clean_topic, _ = safety.redact(str(topic or "").strip())
    clean_pa, _ = safety.redact(str(position_a or "").strip())
    clean_pb, _ = safety.redact(str(position_b or "").strip())
    if not clean_topic or not clean_pa or not clean_pb:
        raise ValueError("topic, position_a, and position_b must be non-empty")

    memory.store.conn.execute(
        "INSERT INTO ark_conflict_case "
        "(case_id, user_id, topic, scope, agent_a, position_a, record_a_id, agent_b, position_b, record_b_id, evidence_json, status, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', 'open', ?, ?)",
        (cid, memory.user_id, clean_topic[:200], scope, agent_a, clean_pa[:500], record_a_id, agent_b, clean_pb[:500], record_b_id, now, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "conflict_case_opened",
        {"case_id": cid, "topic": clean_topic[:100], "agent_a": agent_a, "agent_b": agent_b},
        agent_id="conflict_arbiter",
    )
    return {"ok": True, "case_id": cid, "status": "open", "topic": clean_topic[:200]}


def add_case_evidence(memory, case_id: str, *, agent_id: str, note: str, ref: str = "") -> dict[str, Any]:
    """Прикрепляет доказательство (вывод теста, коммит, замер) к открытому спору."""
    _ensure(memory)
    conn = memory.store.conn
    row = conn.execute(
        "SELECT evidence_json, status FROM ark_conflict_case WHERE case_id = ? AND user_id = ?",
        (case_id, memory.user_id),
    ).fetchone()
    if not row:
        raise KeyError(f"Conflict case not found: {case_id}")
    evs = list(json.loads(row["evidence_json"] or "[]"))
    clean_note, _ = safety.redact(str(note or ""))
    evs.append({"agent_id": agent_id, "note": clean_note[:400], "ref": str(ref or "")[:160], "ts": time.time()})
    conn.execute(
        "UPDATE ark_conflict_case SET evidence_json = ?, updated_at = ? WHERE case_id = ? AND user_id = ?",
        (json.dumps(evs, ensure_ascii=False), time.time(), case_id, memory.user_id),
    )
    conn.commit()
    return {"ok": True, "case_id": case_id, "evidence_count": len(evs)}


def resolve_conflict_case(
    memory,
    case_id: str,
    *,
    decision: str,
    resolved_by: str = "aifa",
    escalate_to_owner: bool = False,
) -> dict[str, Any]:
    """Закрывает конфликт с итоговым вердиктом или эскалирует на решение владельца."""
    _ensure(memory)
    new_status = "escalated" if escalate_to_owner else "resolved"
    clean_dec, _ = safety.redact(str(decision or "").strip())
    conn = memory.store.conn
    cur = conn.execute(
        "UPDATE ark_conflict_case SET status = ?, resolution_note = ?, resolved_by = ?, updated_at = ? "
        "WHERE case_id = ? AND user_id = ?",
        (new_status, clean_dec[:500], resolved_by, time.time(), case_id, memory.user_id),
    )
    if cur.rowcount == 0:
        raise KeyError(f"Conflict case not found: {case_id}")
    conn.commit()
    audit_chain.append_audit(
        memory,
        "conflict_case_resolved" if not escalate_to_owner else "conflict_case_escalated",
        {"case_id": case_id, "status": new_status, "resolved_by": resolved_by},
        agent_id=resolved_by,
    )
    return {"ok": True, "case_id": case_id, "status": new_status, "resolution_note": clean_dec[:500]}


def list_conflict_cases(memory, *, status: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    _ensure(memory)
    sql = "SELECT case_id, topic, scope, agent_a, position_a, agent_b, position_b, evidence_json, status, resolution_note, resolved_by FROM ark_conflict_case WHERE user_id = ?"
    params: list[Any] = [memory.user_id]
    if status:
        sql += " AND status = ?"
        params.append(status.strip().lower())
    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(max(1, min(100, int(limit))))
    rows = memory.store.conn.execute(sql, params).fetchall()
    return [
        {
            "case_id": r["case_id"],
            "topic": r["topic"],
            "scope": r["scope"],
            "agent_a": r["agent_a"],
            "position_a": r["position_a"],
            "agent_b": r["agent_b"],
            "position_b": r["position_b"],
            "evidence": json.loads(r["evidence_json"] or "[]"),
            "status": r["status"],
            "resolution_note": r["resolution_note"],
            "resolved_by": r["resolved_by"],
        }
        for r in rows
    ]
