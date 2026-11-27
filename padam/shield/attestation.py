# -*- coding: utf-8 -*-
"""Криптографическая цепь доказательств исполнения (Signed Proof-of-Execution Attestation).

Создаёт неопровержимую хеш-цепь (`shield_attestations`), связывающую:
- SHA-256 входа (`input_sha256`),
- SHA-256 аргументов/действия (`args_sha256`),
- вердикт PADAM Agentic Shield (`verdict`, `rules_triggered`),
- ссылку на хеш предыдущей записи (`prev_hash`) и подпись HMAC-SHA256 ключом владельца.

Также выдаёт автономную переносимую квитанцию `PADAMATT1.<b64>.<hmac>` и
проверяет целостность всей цепи (`verify_attestation_chain`) — любое удаление,
вставка или правка 1 байта в истории мгновенно выявляется.
Все операции потокобезопасны (`store._lock`) и изолированы по `user_id`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional

from .. import integrity as _integrity
from ..store import add_column_safe


ATTEST_PREFIX = "PADAMATT1"
GENESIS_HASH = "0" * 64


def _ensure_tables(memory: Any) -> None:
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_attestations (
                seq INTEGER NOT NULL,
                user_id TEXT NOT NULL DEFAULT '',
                agent_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                action TEXT NOT NULL,
                verdict TEXT NOT NULL,
                input_sha256 TEXT NOT NULL,
                args_sha256 TEXT NOT NULL,
                rules_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                hmac_sig TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (user_id, seq)
            )
            """
        )
        add_column_safe(conn, "shield_attestations", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.commit()


def _owner_key(memory: Any) -> bytes:
    key, _ = _integrity.owner_key(memory.store)
    return key if isinstance(key, bytes) else str(key).encode("utf-8")


def _sha256_any(val: Any) -> str:
    if isinstance(val, bytes):
        raw = val
    elif isinstance(val, str):
        raw = val.encode("utf-8")
    else:
        raw = json.dumps(val, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _compute_entry_hash(
    *,
    seq: int,
    user_id: str,
    agent_id: str,
    session_id: str,
    action: str,
    verdict: str,
    input_sha256: str,
    args_sha256: str,
    rules_json: str,
    prev_hash: str,
    created_at: float,
) -> str:
    body = "|".join(
        [
            "padam-att-v1",
            str(seq),
            user_id,
            agent_id,
            session_id,
            action,
            verdict,
            input_sha256,
            args_sha256,
            rules_json,
            prev_hash,
            f"{created_at:.6f}",
        ]
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def record_execution_attestation(
    memory: Any,
    *,
    agent_id: str,
    session_id: str,
    action: str,
    verdict: str,
    input_data: Any = "",
    args_data: Any = "",
    rules_triggered: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Записывает подписанное доказательство исполнения в хеш-цепь и выдаёт квитанцию."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    aid = str(agent_id or "agent")
    sid = str(session_id or "default")
    act = str(action or "tool_call")
    verd = str(verdict or "allow").lower()
    in_h = _sha256_any(input_data)
    ar_h = _sha256_any(args_data)
    rules_j = json.dumps(sorted(str(x) for x in (rules_triggered or [])), separators=(",", ":"), ensure_ascii=False)
    now = round(time.time(), 6)
    key = _owner_key(memory)

    with memory.store._lock:
        conn = memory.store.conn
        last = conn.execute(
            "SELECT seq, entry_hash FROM shield_attestations WHERE user_id = ? ORDER BY seq DESC LIMIT 1",
            (uid,),
        ).fetchone()
        seq = (int(last[0]) + 1) if last else 1
        prev_hash = str(last[1]) if last else GENESIS_HASH

        entry_hash = _compute_entry_hash(
            seq=seq,
            user_id=uid,
            agent_id=aid,
            session_id=sid,
            action=act,
            verdict=verd,
            input_sha256=in_h,
            args_sha256=ar_h,
            rules_json=rules_j,
            prev_hash=prev_hash,
            created_at=now,
        )
        sig = hmac.new(key, entry_hash.encode("ascii"), hashlib.sha256).hexdigest()
        conn.execute(
            """
            INSERT INTO shield_attestations
                (seq, user_id, agent_id, session_id, action, verdict, input_sha256,
                 args_sha256, rules_json, prev_hash, entry_hash, hmac_sig, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (seq, uid, aid, sid, act, verd, in_h, ar_h, rules_j, prev_hash, entry_hash, sig, now),
        )
        conn.commit()

    receipt_obj = {
        "v": 1,
        "seq": seq,
        "uid": uid,
        "aid": aid,
        "sid": sid,
        "act": act,
        "verdict": verd,
        "in": in_h,
        "args": ar_h,
        "prev": prev_hash,
        "hash": entry_hash,
        "ts": now,
    }
    raw = json.dumps(receipt_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    r_sig = hmac.new(key, raw, hashlib.sha256).hexdigest()
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    receipt = f"{ATTEST_PREFIX}.{b64}.{r_sig}"

    return {
        "ok": True,
        "seq": seq,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "hmac_sig": sig,
        "receipt": receipt,
    }


def verify_attestation_receipt(memory: Any, receipt: str) -> Dict[str, Any]:
    """Проверяет автономную квитанцию доказательства исполнения `PADAMATT1`."""
    parts = str(receipt or "").strip().split(".")
    if len(parts) != 3 or parts[0] != ATTEST_PREFIX:
        return {"ok": False, "valid": False, "reason": "Неверный формат квитанции PADAMATT1"}
    b64, sig = parts[1], parts[2]
    pad = "=" * (-len(b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(b64 + pad)
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return {"ok": False, "valid": False, "reason": f"Ошибка декодирования: {exc}"}
    expected = hmac.new(_owner_key(memory), raw, hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(expected, sig)
    return {
        "ok": valid,
        "valid": valid,
        "seq": obj.get("seq") if isinstance(obj, dict) else None,
        "verdict": obj.get("verdict") if isinstance(obj, dict) else None,
        "entry_hash": obj.get("hash") if isinstance(obj, dict) else None,
        "reason": "" if valid else "Подпись квитанции недействительна",
    }


def verify_attestation_chain(memory: Any) -> Dict[str, Any]:
    """Проверяет неразрывность и HMAC каждой записи цепи доказательств текущего владельца."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    key = _owner_key(memory)
    with memory.store._lock:
        rows = memory.store.conn.execute(
            "SELECT seq, agent_id, session_id, action, verdict, input_sha256, args_sha256, "
            "rules_json, prev_hash, entry_hash, hmac_sig, created_at "
            "FROM shield_attestations WHERE user_id = ? ORDER BY seq ASC",
            (uid,),
        ).fetchall()

    expected_prev = GENESIS_HASH
    expected_seq = 1
    broken_at: Optional[int] = None
    reason = ""
    head_hash = GENESIS_HASH

    for r in rows:
        seq, aid, sid, act, verd, in_h, ar_h, rules_j, prev_h, ent_h, sig, ts = r
        if int(seq) != expected_seq:
            broken_at = int(seq)
            reason = f"Пропущен или нарушен порядковый номер (ожидался {expected_seq}, найден {seq})"
            break
        if str(prev_h) != expected_prev:
            broken_at = int(seq)
            reason = f"Разорвана ссылка prev_hash на записи #{seq}"
            break
        recalc = _compute_entry_hash(
            seq=int(seq),
            user_id=uid,
            agent_id=str(aid),
            session_id=str(sid),
            action=str(act),
            verdict=str(verd),
            input_sha256=str(in_h),
            args_sha256=str(ar_h),
            rules_json=str(rules_j),
            prev_hash=str(prev_h),
            created_at=float(ts),
        )
        if not hmac.compare_digest(recalc, str(ent_h)):
            broken_at = int(seq)
            reason = f"Подмена содержимого записи #{seq} (entry_hash не совпадает)"
            break
        exp_sig = hmac.new(key, recalc.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(exp_sig, str(sig)):
            broken_at = int(seq)
            reason = f"Недействительная HMAC-подпись на записи #{seq}"
            break
        expected_prev = recalc
        head_hash = recalc
        expected_seq += 1

    valid = broken_at is None
    return {
        "ok": valid,
        "valid": valid,
        "entries_checked": len(rows),
        "head_hash": head_hash,
        "broken_at_seq": broken_at,
        "reason": reason,
    }
