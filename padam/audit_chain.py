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
from pathlib import Path
from typing import Any

from . import integrity, net_guard

# 18.11.2026: кэш живёт на самом объекте хранилища, а не в словаре по id(): Python выдаёт тот же id новому объекту
# после сборки мусора, и новая база наследовала состояние умершей (Совет видел «цепь стёрта»).
def _mem_wm(store) -> dict:
    return store.__dict__.setdefault("_padam_audit_watermarks", {})

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
    _save_audit_watermark(memory, seq, entry_hash, key)
    return {
        "seq": seq,
        "action": action,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "head_hmac": head_hmac,
        "created_at": created_at,
    }


def _watermark_path(store) -> Path | None:
    if str(store.path) == ":memory:":
        return None
    return Path(str(store.path) + ".audit.state.json")


def _save_audit_watermark(memory, seq: int, head_hash: str, key: bytes) -> None:
    store = memory.store
    prev = _mem_wm(store).get(memory.user_id, 0)
    if seq > prev:
        _mem_wm(store)[memory.user_id] = seq
    wpath = _watermark_path(store)
    if wpath is None:
        return
    try:
        data = json.loads(wpath.read_text(encoding="utf-8")) if wpath.exists() else {}
    except Exception:
        data = {}
    users = dict(data.get("users") or {})
    u_rec = {"head_seq": int(seq), "head_hash": head_hash}
    u_rec["hmac"] = hmac.new(key, f"wm|{memory.user_id}|{seq}|{head_hash}".encode("utf-8"), hashlib.sha256).hexdigest()
    users[memory.user_id] = u_rec
    wpath.write_text(json.dumps({"users": users}, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    net_guard.restrict_file_to_owner(wpath)


def _load_audit_watermark_seq(memory) -> int:
    store = memory.store
    mem_wm = _mem_wm(store).get(memory.user_id, 0)
    wpath = _watermark_path(store)
    if wpath is None or not wpath.exists():
        return mem_wm
    try:
        data = json.loads(wpath.read_text(encoding="utf-8"))
        u_rec = (data.get("users") or {}).get(memory.user_id)
        if not isinstance(u_rec, dict):
            return mem_wm
        seq = int(u_rec.get("head_seq") or 0)
        head_hash = str(u_rec.get("head_hash") or "")
        key, _ = integrity.owner_key(store)
        expected = hmac.new(key, f"wm|{memory.user_id}|{seq}|{head_hash}".encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, str(u_rec.get("hmac") or "")):
            return max(mem_wm, seq)
    except Exception:
        pass
    return mem_wm


# Аудит GLM фаза 2, MEM-02 (работа Antigravity из _wt_sister_live_1811, перенесено 19.11.2026): журнал audit_log
# связан хэш-цепью с HMAC-якорем. Поправки при переносе: записи до цепи (seq IS NULL) — история, проверяются
# только связанные; кэш водяного знака — на объекте хранилища, не по id().
def compute_audit_log_hash(
    *,
    ev_id: str,
    user_id: str,
    created_at: str,
    action: str,
    memory_id: str | None,
    actor: str | None,
    agent_id: str | None,
    scope: str | None,
    kind: str | None,
    outcome: str | None,
    detail: str | None,
    prev_hash: str,
    seq: int,
) -> str:
    payload = json.dumps(
        {
            "id": str(ev_id),
            "user_id": str(user_id),
            "created_at": str(created_at),
            "action": str(action),
            "memory_id": memory_id,
            "actor": actor or "user",
            "agent_id": agent_id,
            "scope": scope or "global",
            "kind": kind,
            "outcome": outcome,
            "detail": detail,
            "prev_hash": str(prev_hash),
            "seq": int(seq),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(b"auditlog-v1|" + payload.encode("utf-8")).hexdigest()


def sign_audit_log_head(key: bytes, user_id: str, head_seq: int, head_hash: str) -> str:
    return hmac.new(
        key,
        f"auditlog-anchor-v1|{user_id}|{int(head_seq)}|{head_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def save_audit_log_watermark(memory, seq: int, head_hash: str, key: bytes) -> None:
    store = memory.store
    prev = store.__dict__.setdefault("_padam_auditlog_watermarks", {}).get(memory.user_id, 0)
    if seq > prev:
        store.__dict__.setdefault("_padam_auditlog_watermarks", {})[memory.user_id] = seq
    wpath = _watermark_path(store)
    if wpath is None:
        return
    try:
        data = json.loads(wpath.read_text(encoding="utf-8")) if wpath.exists() else {}
    except Exception:
        data = {}
    al_users = dict(data.get("audit_log_users") or {})
    rec = {"head_seq": int(seq), "head_hash": head_hash}
    rec["hmac"] = hmac.new(key, f"alwm|{memory.user_id}|{seq}|{head_hash}".encode("utf-8"), hashlib.sha256).hexdigest()
    al_users[memory.user_id] = rec
    data["audit_log_users"] = al_users
    wpath.write_text(json.dumps(data, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    net_guard.restrict_file_to_owner(wpath)


def _load_audit_log_watermark_seq(memory) -> int:
    store = memory.store
    mem_wm = store.__dict__.setdefault("_padam_auditlog_watermarks", {}).get(memory.user_id, 0)
    wpath = _watermark_path(store)
    if wpath is None or not wpath.exists():
        return mem_wm
    try:
        data = json.loads(wpath.read_text(encoding="utf-8"))
        u_rec = (data.get("audit_log_users") or {}).get(memory.user_id)
        if not isinstance(u_rec, dict):
            return mem_wm
        seq = int(u_rec.get("head_seq") or 0)
        head_hash = str(u_rec.get("head_hash") or "")
        key, _ = integrity.owner_key(store)
        expected = hmac.new(key, f"alwm|{memory.user_id}|{seq}|{head_hash}".encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, str(u_rec.get("hmac") or "")):
            return max(mem_wm, seq)
    except Exception:
        pass
    return mem_wm


def verify_audit_log_chain(memory) -> dict[str, Any]:
    conn = memory.store.conn
    has_tbl = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_log'"
    ).fetchone()
    if not has_tbl:
        return {"audit_log_ok": True, "audit_log_length": 0}
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    if not {"seq", "prev_hash", "entry_hash"} <= cols:
        return {"audit_log_ok": False, "audit_log_length": 0, "audit_log_reason": "audit_log_missing_chain_columns"}

    rows = conn.execute(
        "SELECT id, user_id, created_at, action, memory_id, actor, agent_id, scope, kind, outcome, detail, "
        "seq, prev_hash, entry_hash FROM audit_log WHERE user_id = ? AND seq IS NOT NULL ORDER BY seq ASC, rowid ASC",
        (memory.user_id,),
    ).fetchall()
    has_anchor_tbl = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_log_anchor'"
    ).fetchone()
    anchor = (
        conn.execute(
            "SELECT head_seq, head_hash, head_hmac FROM audit_log_anchor WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
        if has_anchor_tbl
        else None
    )

    if not rows:
        if anchor and int(anchor["head_seq"]) > 0:
            return {"audit_log_ok": False, "audit_log_length": 0, "audit_log_reason": "audit_log_tail_truncated"}
        wm_seq = _load_audit_log_watermark_seq(memory)
        if wm_seq > 0:
            return {
                "audit_log_ok": False,
                "audit_log_length": 0,
                "audit_log_expected_min_seq": wm_seq,
                "audit_log_reason": "audit_log_wiped",
            }
        return {"audit_log_ok": True, "audit_log_length": 0, "audit_log_head_hash": "0" * 64}

    expected_prev = "0" * 64
    expected_seq = 1
    for r in rows:
        if r["seq"] is None or not r["prev_hash"] or not r["entry_hash"]:
            return {"audit_log_ok": False, "audit_log_length": len(rows), "audit_log_reason": "audit_log_unchained_row"}
        if int(r["seq"]) != expected_seq:
            return {
                "audit_log_ok": False,
                "audit_log_length": len(rows),
                "audit_log_broken_seq": expected_seq,
                "audit_log_reason": "audit_log_seq_gap",
            }
        if str(r["prev_hash"]) != expected_prev:
            return {
                "audit_log_ok": False,
                "audit_log_length": len(rows),
                "audit_log_broken_seq": expected_seq,
                "audit_log_reason": "audit_log_prev_hash_mismatch",
            }
        recalc = compute_audit_log_hash(
            ev_id=str(r["id"]),
            user_id=str(r["user_id"]),
            created_at=str(r["created_at"]),
            action=str(r["action"]),
            memory_id=r["memory_id"],
            actor=r["actor"],
            agent_id=r["agent_id"],
            scope=r["scope"],
            kind=r["kind"],
            outcome=r["outcome"],
            detail=r["detail"],
            prev_hash=str(r["prev_hash"]),
            seq=expected_seq,
        )
        if str(r["entry_hash"]) != recalc:
            return {
                "audit_log_ok": False,
                "audit_log_length": len(rows),
                "audit_log_broken_seq": expected_seq,
                "audit_log_reason": "audit_log_entry_hash_mismatch",
            }
        expected_prev = str(r["entry_hash"])
        expected_seq += 1

    last_seq = expected_seq - 1
    if not anchor:
        return {
            "audit_log_ok": False,
            "audit_log_length": len(rows),
            "audit_log_broken_seq": last_seq,
            "audit_log_reason": "audit_log_missing_anchor",
        }
    if int(anchor["head_seq"]) != last_seq or str(anchor["head_hash"]) != expected_prev:
        return {
            "audit_log_ok": False,
            "audit_log_length": len(rows),
            "audit_log_broken_seq": last_seq,
            "audit_log_reason": "audit_log_tail_truncated",
        }
    key, _ = integrity.owner_key(memory.store)
    expected_hmac = sign_audit_log_head(key, memory.user_id, last_seq, expected_prev)
    if not hmac.compare_digest(str(anchor["head_hmac"] or ""), expected_hmac):
        return {
            "audit_log_ok": False,
            "audit_log_length": len(rows),
            "audit_log_broken_seq": last_seq,
            "audit_log_reason": "audit_log_anchor_hmac_mismatch",
        }
    return {
        "audit_log_ok": True,
        "audit_log_length": len(rows),
        "audit_log_head_seq": last_seq,
        "audit_log_head_hash": expected_prev,
    }


def _verify_ark_chain_only(memory) -> dict[str, Any]:
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
        wm_seq = _load_audit_watermark_seq(memory)
        if wm_seq > 0:
            return {
                "ok": False,
                "length": 0,
                "expected_min_seq": wm_seq,
                "reason": "chain_and_anchor_wiped",
            }
        return {"ok": True, "length": 0, "head_hash": expected_prev, "anchored": False, "empty": True, "tamper_evident": False}

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


def verify_audit_chain(memory) -> dict[str, Any]:
    res = _verify_ark_chain_only(memory)
    al = verify_audit_log_chain(memory)
    res.update(al)
    if not al.get("audit_log_ok", True):
        if res.get("ok"):
            res["reason"] = str(al.get("audit_log_reason") or "audit_log_tampered")
        res["ok"] = False
    return res
