# -*- coding: utf-8 -*-
"""Time-Lock (задержка охлаждения) и M-of-N кворум для критических операций агентов.

Для крупных финансовых переводов, обновлений контрактов и необратимых команд:
- Операция фиксируется криптографическим SHA-256 отпечатком (`op_sha256`).
- Устанавливается окно охлаждения (`timelock_seconds`), раньше которого исполнение
  физически невозможно (`ready_at > now`).
- Требуется `m_required` независимых одобрений (`approver_id` не может голосовать дважды).
- Владелец в любой момент до исполнения может нажать `veto` и отменить операцию навсегда.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import time
import uuid
from typing import Any

from .. import audit_chain, roles

_TIMELOCK_DDL = """
CREATE TABLE IF NOT EXISTS shield_timelock_ops (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    op_type TEXT NOT NULL,
    op_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    m_required INTEGER NOT NULL DEFAULT 2,
    approvers_json TEXT NOT NULL DEFAULT '[]',
    not_before_ts REAL NOT NULL,
    status TEXT NOT NULL,
    vetoed_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_timelock_table(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_timelock_ready", False):
        return
    with store._lock:
        store.conn.executescript(_TIMELOCK_DDL)
        store.conn.commit()
        store._shield_timelock_ready = True


def propose_timelock_operation(
    memory: Any,
    *,
    op_type: str,
    payload: dict[str, Any],
    agent_id: str = "agent",
    m_required: int = 2,
    timelock_seconds: float = 900.0,
) -> dict[str, Any]:
    """Регистрирует критическую операцию с Time-Lock задержкой и требованием M-of-N кворума."""
    ensure_timelock_table(memory)
    oid = f"tl-{uuid.uuid4().hex[:12]}"
    canon = json.dumps({"op_type": op_type, "payload": payload}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    op_sha = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    now_ts = time.time()
    not_before = now_ts + max(0.0, float(timelock_seconds))
    now_iso = _utc_iso()
    m_req = max(1, min(10, int(m_required)))

    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT INTO shield_timelock_ops
               (id, user_id, agent_id, op_type, op_sha256, payload_json, m_required,
                approvers_json, not_before_ts, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, '[]', ?, 'pending', ?, ?)""",
            (oid, memory.user_id, str(agent_id)[:80], str(op_type)[:64], op_sha, canon, m_req, not_before, now_iso, now_iso),
        )
        memory.store.conn.commit()

    return {
        "ok": True,
        "op_id": oid,
        "op_sha256": op_sha,
        "m_required": m_req,
        "approvals_count": 0,
        "not_before_ts": not_before,
        "status": "pending",
    }


def approve_timelock_operation(memory: Any, op_id: str, *, approver_id: str) -> dict[str, Any]:
    """Добавляет голос независимого подтверждающего (дубликат одного approver_id запрещён)."""
    ensure_timelock_table(memory)
    aid = str(approver_id or "").strip()[:80]
    if not aid:
        raise ValueError("approver_id is required")

    with memory.store._lock:
        row = memory.store.one(
            "SELECT * FROM shield_timelock_ops WHERE user_id = ? AND id = ?",
            (memory.user_id, str(op_id).strip()),
        )
        if row is None:
            return {"ok": False, "reason": "timelock_op_not_found"}
        if row["status"] in ("vetoed", "executed"):
            return {"ok": False, "reason": f"operation_already_{row['status']}"}
        approvers = json.loads(row["approvers_json"] or "[]")
        if aid in approvers:
            return {"ok": False, "reason": "duplicate_approver_rejected"}
        approvers.append(aid)
        memory.store.conn.execute(
            "UPDATE shield_timelock_ops SET approvers_json = ?, updated_at = ? WHERE id = ? AND user_id = ?",
            (json.dumps(approvers), _utc_iso(), row["id"], memory.user_id),
        )
        memory.store.conn.commit()

    return {
        "ok": True,
        "op_id": row["id"],
        "approvals_count": len(approvers),
        "m_required": int(row["m_required"]),
        "quorum_met": len(approvers) >= int(row["m_required"]),
        "approvers": approvers,
    }


def veto_timelock_operation(memory: Any, op_id: str, *, actor: Any = None, reason: str = "owner_veto") -> dict[str, Any]:
    """Мгновенное вето владельца — отменяет операцию в окне Time-Lock навсегда."""
    roles.require_owner(actor, "shield_timelock_veto")
    ensure_timelock_table(memory)
    with memory.store._lock:
        row = memory.store.one(
            "SELECT * FROM shield_timelock_ops WHERE user_id = ? AND id = ?",
            (memory.user_id, str(op_id).strip()),
        )
        if row is None:
            return {"ok": False, "reason": "timelock_op_not_found"}
        if row["status"] == "executed":
            return {"ok": False, "reason": "already_executed"}
        memory.store.conn.execute(
            "UPDATE shield_timelock_ops SET status = 'vetoed', vetoed_by = 'owner', updated_at = ? WHERE id = ? AND user_id = ?",
            (_utc_iso(), row["id"], memory.user_id),
        )
        memory.store.conn.commit()
    try:
        audit_chain.append_audit(memory, "timelock_op_vetoed", {"op_id": row["id"], "reason": reason[:160]}, agent_id="owner")
    except Exception:
        pass
    return {"ok": True, "op_id": row["id"], "status": "vetoed", "reason": reason}


def execute_timelock_operation(memory: Any, op_id: str, *, now_ts: float | None = None) -> dict[str, Any]:
    """Проверяет одновременно: отсутствие вето, кворум M-of-N и истечение Time-Lock задержки."""
    ensure_timelock_table(memory)
    cur_ts = float(now_ts if now_ts is not None else time.time())
    with memory.store._lock:
        row = memory.store.one(
            "SELECT * FROM shield_timelock_ops WHERE user_id = ? AND id = ?",
            (memory.user_id, str(op_id).strip()),
        )
        if row is None:
            return {"ok": False, "executed": False, "reason": "timelock_op_not_found"}
        if row["status"] == "vetoed":
            return {"ok": False, "executed": False, "reason": "operation_vetoed_by_owner"}
        if row["status"] == "executed":
            return {"ok": False, "executed": False, "reason": "already_executed"}
        approvers = json.loads(row["approvers_json"] or "[]")
        if len(approvers) < int(row["m_required"]):
            return {
                "ok": False,
                "executed": False,
                "reason": f"quorum_not_met:{len(approvers)}/{row['m_required']}",
            }
        remaining = float(row["not_before_ts"]) - cur_ts
        if remaining > 0:
            return {
                "ok": False,
                "executed": False,
                "reason": f"timelock_active:remaining_{round(remaining, 1)}s",
                "remaining_seconds": round(remaining, 1),
            }
        memory.store.conn.execute(
            "UPDATE shield_timelock_ops SET status = 'executed', updated_at = ? WHERE id = ? AND user_id = ?",
            (_utc_iso(), row["id"], memory.user_id),
        )
        memory.store.conn.commit()
    try:
        audit_chain.append_audit(
            memory,
            "timelock_op_executed",
            {"op_id": row["id"], "op_sha256": row["op_sha256"], "approvers": approvers},
            agent_id=row["agent_id"],
        )
    except Exception:
        pass
    return {
        "ok": True,
        "executed": True,
        "op_id": row["id"],
        "op_sha256": row["op_sha256"],
        "approvers": approvers,
    }
