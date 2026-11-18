# -*- coding: utf-8 -*-
"""Криптографическая хэш-цепочка аудита действий агента с якорем головы (HMAC-SHA256).

Каждое событие сцепляется с предыдущим (`prev_hash -> entry_hash`), а голова цепочки
подписывается ключом владельца (`HMAC-SHA256` в `ark_audit_anchor`).
`verify_audit_chain` обнаруживает:
1. Подмену или удаление записи в середине (`entry_hash_mismatch` / `prev_hash_mismatch`).
2. Отрезанный хвост (`tail_truncated`).
3. Пересчитанную с нуля цепочку или подделанный якорь (`anchor_hmac_mismatch` / `missing_anchor`).

Опционально при `PADAM_AUDIT_OTS=1` ставится бесплатная отметка OpenTimestamps раз в сутки
(по умолчанию выключено — без сетевых запросов).
Граница (17.11.2026): если стереть и всю цепочку, и якорь, проверка увидит пустую цепочку как целую;
это ловит только внешняя отметка (OpenTimestamps по флагу) или сверка длины с копией.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any

from . import integrity

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
CREATE TABLE IF NOT EXISTS ark_audit_anchor (
    user_id     TEXT PRIMARY KEY,
    head_seq    INTEGER NOT NULL,
    head_hash   TEXT NOT NULL,
    head_hmac   TEXT NOT NULL,
    ots_receipt TEXT,
    ots_date    TEXT,
    updated_at  TEXT NOT NULL
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


def _sign_head(key: bytes, user_id: str, head_seq: int, head_hash: str) -> str:
    msg = f"{user_id}:{head_seq}:{head_hash}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


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
    seq = int(cur.lastrowid)

    key, _ = integrity.owner_key(memory.store)
    head_hmac = _sign_head(key, memory.user_id, seq, entry_hash)

    ots_receipt = None
    ots_date = None
    if os.environ.get("PADAM_AUDIT_OTS", "0").strip() == "1":
        today = created_at[:10]
        prev_anc = conn.execute(
            "SELECT ots_date, ots_receipt FROM ark_audit_anchor WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
        if not prev_anc or prev_anc["ots_date"] != today:
            try:
                from . import ots
                stamp_bytes = ots.stamp(bytes.fromhex(entry_hash))
                ots_receipt = base64.b64encode(stamp_bytes).decode("ascii")
                ots_date = today
            except Exception:
                ots_receipt = prev_anc["ots_receipt"] if prev_anc else None
                ots_date = prev_anc["ots_date"] if prev_anc else None
        else:
            ots_receipt = prev_anc["ots_receipt"]
            ots_date = prev_anc["ots_date"]

    conn.execute(
        "INSERT INTO ark_audit_anchor (user_id, head_seq, head_hash, head_hmac, ots_receipt, ots_date, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET "
        "head_seq=excluded.head_seq, head_hash=excluded.head_hash, head_hmac=excluded.head_hmac, "
        "ots_receipt=COALESCE(excluded.ots_receipt, ark_audit_anchor.ots_receipt), "
        "ots_date=COALESCE(excluded.ots_date, ark_audit_anchor.ots_date), "
        "updated_at=excluded.updated_at",
        (memory.user_id, seq, entry_hash, head_hmac, ots_receipt, ots_date, created_at),
    )
    conn.commit()
    return {
        "seq": seq,
        "action": action,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "head_hmac": head_hmac,
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
    last_seq = 0
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
        last_seq = int(r["seq"])

    anchor = conn.execute(
        "SELECT head_seq, head_hash, head_hmac, ots_date FROM ark_audit_anchor WHERE user_id = ?",
        (memory.user_id,),
    ).fetchone()

    if not rows:
        if anchor and int(anchor["head_seq"]) > 0:
            return {"ok": False, "length": 0, "broken_seq": int(anchor["head_seq"]), "reason": "tail_truncated"}
        return {"ok": True, "length": 0, "head_hash": expected_prev, "anchored": False}

    if not anchor:
        return {"ok": False, "length": len(rows), "broken_seq": last_seq, "reason": "missing_anchor"}

    if int(anchor["head_seq"]) != last_seq or str(anchor["head_hash"]) != expected_prev:
        return {"ok": False, "length": len(rows), "broken_seq": last_seq, "reason": "tail_truncated"}

    key, _ = integrity.owner_key(memory.store)
    expected_hmac = _sign_head(key, memory.user_id, last_seq, expected_prev)
    if not hmac.compare_digest(str(anchor["head_hmac"] or ""), expected_hmac):
        return {"ok": False, "length": len(rows), "broken_seq": last_seq, "reason": "anchor_hmac_mismatch"}

    return {
        "ok": True,
        "length": len(rows),
        "head_hash": expected_prev,
        "head_seq": last_seq,
        "anchored": True,
        "ots_date": anchor["ots_date"],
    }
