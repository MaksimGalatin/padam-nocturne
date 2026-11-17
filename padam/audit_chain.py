# -*- coding: utf-8 -*-
"""Криптографическая хэш-цепочка аудита действий агента (SHA-256 Hash Chain).

Каждое событие сцепляется с предыдущим (`prev_hash -> entry_hash`): подмена или удаление записи в середине
журнала обнаруживается `verify_audit_chain`.

Граница (17.11.2026, честно): цепочка не подписана ключом. Тот, у кого есть доступ на запись к SQLite, может
незаметно отрезать последние записи или пересчитать всю цепочку заново. Это защита от случайной порчи и
несогласованной правки, а не от злоумышленника с доступом к базе; для этого нужен якорь головы цепочки
(подпись ключом владельца или внешняя отметка времени).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

_AUDIT_DDL = """
CREATE TABLE IF NOT EXISTS ark_audit_chain (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    action     TEXT NOT NULL,
    details    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _compute_entry_hash(user_id: str, agent_id: str, action: str, details: str, prev_hash: str, created_at: str) -> str:
    payload = json.dumps(
        {
            "user_id": user_id,
            "agent_id": agent_id,
            "action": action,
            "details": details,
            "prev_hash": prev_hash,
            "created_at": created_at,
        },
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def append_audit(memory, action: str, details: dict[str, Any] | str, *, agent_id: str = "aifa") -> dict[str, Any]:
    conn = memory.store.conn
    conn.executescript(_AUDIT_DDL)
    last = conn.execute(
        "SELECT entry_hash FROM ark_audit_chain WHERE user_id = ? ORDER BY seq DESC LIMIT 1",
        (memory.user_id,),
    ).fetchone()
    prev_hash = str(last["entry_hash"]) if last else ("0" * 64)
    created_at = datetime.now(timezone.utc).isoformat()
    det_str = details if isinstance(details, str) else json.dumps(details, ensure_ascii=False, sort_keys=True)
    entry_hash = _compute_entry_hash(memory.user_id, agent_id, action, det_str, prev_hash, created_at)
    cur = conn.execute(
        "INSERT INTO ark_audit_chain (user_id, agent_id, action, details, prev_hash, entry_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (memory.user_id, agent_id, action, det_str, prev_hash, entry_hash, created_at),
    )
    conn.commit()
    return {
        "seq": int(cur.lastrowid),
        "action": action,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "created_at": created_at,
    }


def verify_audit_chain(memory) -> dict[str, Any]:
    conn = memory.store.conn
    conn.executescript(_AUDIT_DDL)
    rows = conn.execute(
        "SELECT seq, user_id, agent_id, action, details, prev_hash, entry_hash, created_at "
        "FROM ark_audit_chain WHERE user_id = ? ORDER BY seq ASC",
        (memory.user_id,),
    ).fetchall()
    expected_prev = "0" * 64
    for r in rows:
        if str(r["prev_hash"]) != expected_prev:
            return {"ok": False, "length": len(rows), "broken_seq": r["seq"], "reason": "prev_hash_mismatch"}
        recalc = _compute_entry_hash(
            str(r["user_id"]),
            str(r["agent_id"]),
            str(r["action"]),
            str(r["details"]),
            str(r["prev_hash"]),
            str(r["created_at"]),
        )
        if str(r["entry_hash"]) != recalc:
            return {"ok": False, "length": len(rows), "broken_seq": r["seq"], "reason": "entry_hash_mismatch"}
        expected_prev = str(r["entry_hash"])
    return {"ok": True, "length": len(rows), "head_hash": expected_prev}
