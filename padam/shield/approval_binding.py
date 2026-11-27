# -*- coding: utf-8 -*-
"""Криптографическая привязка согласия человека к действию (Anti-TOCTOU Approval Binding).

Закрывает атаки Approval TOCTOU / Bait-and-Switch и Replay:
1. Когда человек подтверждает критическое действие (платёж, удаление, перевод),
   выдаётся одноразовая подписанная квитанция `PADAMAPP1.<payload>.<hmac>`,
   криптографически привязанная к точному SHA-256 хешу `(action_type, target,
   canonical_args, amount, agent_id, user_id)`.
2. На границе исполнения агент предъявляет квитанцию вместе с фактическими
   параметрами: подмена даже одного символа суммы, адреса или аргумента вызывает
   мгновенный `APPROVAL-PAYLOAD-MISMATCH`, а повторная подача той же квитанции —
   `APPROVAL-REPLAY-BLOCKED`. Все операции атомарны под `store._lock` и изолированы по `user_id`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from .. import integrity as _integrity
from ..store import add_column_safe


APPROVAL_PREFIX = "PADAMAPP1"


def _ensure_tables(memory: Any) -> None:
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_approval_receipts (
                receipt_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL DEFAULT '',
                agent_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                consumed_at REAL,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                hmac_sig TEXT NOT NULL
            )
            """
        )
        add_column_safe(conn, "shield_approval_receipts", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_approval_user ON shield_approval_receipts(user_id, consumed)"
        )
        conn.commit()


def _owner_key(memory: Any) -> bytes:
    key, _ = _integrity.owner_key(memory.store)
    return key if isinstance(key, bytes) else str(key).encode("utf-8")


def compute_action_binding_hash(
    *,
    user_id: str,
    agent_id: str,
    action_type: str,
    target: str,
    args: Any = None,
    amount: Optional[float] = None,
) -> str:
    """Вычисляет детерминированный SHA-256 отпечаток точных параметров действия."""
    canonical = {
        "user_id": str(user_id or ""),
        "agent_id": str(agent_id or ""),
        "action_type": str(action_type or "").strip().lower(),
        "target": str(target or "").strip(),
        "args": args if args is not None else {},
        "amount": round(float(amount), 8) if amount is not None else None,
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def issue_approval_receipt(
    memory: Any,
    *,
    agent_id: str,
    action_type: str,
    target: str,
    args: Any = None,
    amount: Optional[float] = None,
    approved_by: str = "owner",
    ttl_sec: int = 300,
) -> Dict[str, Any]:
    """Выпускает одноразовую криптографическую квитанцию согласия человека на точное действие."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    now = time.time()
    expires_at = now + max(5, min(86400, int(ttl_sec)))
    receipt_id = "apr_" + secrets.token_hex(8)
    binding_hash = compute_action_binding_hash(
        user_id=uid,
        agent_id=agent_id,
        action_type=action_type,
        target=target,
        args=args,
        amount=amount,
    )
    payload = {
        "v": 1,
        "rid": receipt_id,
        "uid": uid,
        "aid": str(agent_id or ""),
        "act": str(action_type or "").strip().lower(),
        "h": binding_hash,
        "by": str(approved_by or "owner"),
        "iat": round(now, 3),
        "exp": round(expires_at, 3),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(_owner_key(memory), raw, hashlib.sha256).hexdigest()
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    token = f"{APPROVAL_PREFIX}.{b64}.{sig}"

    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            INSERT INTO shield_approval_receipts
                (receipt_id, user_id, agent_id, action_type, target, payload_sha256,
                 approved_by, consumed, consumed_at, expires_at, created_at, hmac_sig)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)
            """,
            (
                receipt_id,
                uid,
                str(agent_id or ""),
                str(action_type or "").strip().lower(),
                str(target or "").strip(),
                binding_hash,
                str(approved_by or "owner"),
                expires_at,
                now,
                sig,
            ),
        )
        conn.commit()

    return {
        "ok": True,
        "receipt_id": receipt_id,
        "payload_sha256": binding_hash,
        "expires_at": expires_at,
        "receipt": token,
    }


def _decode_receipt(token: str) -> Tuple[Optional[Dict[str, Any]], Optional[bytes], Optional[str], str]:
    parts = str(token or "").strip().split(".")
    if len(parts) != 3 or parts[0] != APPROVAL_PREFIX:
        return None, None, None, "Неверный формат квитанции одобрения (ожидается PADAMAPP1.<payload>.<sig>)"
    b64, sig = parts[1], parts[2]
    pad = "=" * (-len(b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(b64 + pad)
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            return None, None, None, "Некорректная структура квитанции"
        return obj, raw, sig, ""
    except Exception as exc:
        return None, None, None, f"Ошибка декодирования квитанции: {exc}"


def verify_and_consume_approval(
    memory: Any,
    *,
    receipt: str,
    agent_id: str,
    action_type: str,
    target: str,
    args: Any = None,
    amount: Optional[float] = None,
) -> Dict[str, Any]:
    """Атомарно проверяет квитанцию против фактических параметров и погашает её (одноразовость)."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    payload, raw, sig, err = _decode_receipt(receipt)
    if err or payload is None or raw is None or sig is None:
        return {"ok": False, "allowed": False, "blocked": True, "rule_id": "APPROVAL-INVALID-FORMAT", "reason": err}

    expected_sig = hmac.new(_owner_key(memory), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, sig):
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": "APPROVAL-SIGNATURE-INVALID",
            "reason": "Криптографическая подпись квитанции недействительна",
        }

    rid = str(payload.get("rid") or "")
    actual_hash = compute_action_binding_hash(
        user_id=uid,
        agent_id=agent_id,
        action_type=action_type,
        target=target,
        args=args,
        amount=amount,
    )
    now = time.time()

    with memory.store._lock:
        conn = memory.store.conn
        row = conn.execute(
            "SELECT payload_sha256, consumed, expires_at, hmac_sig, approved_by "
            "FROM shield_approval_receipts WHERE receipt_id = ? AND user_id = ?",
            (rid, uid),
        ).fetchone()
        if not row:
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "APPROVAL-NOT-FOUND",
                "reason": "Квитанция одобрения не найдена у текущего владельца",
            }
        db_hash, consumed, expires_at, db_sig, approved_by = row
        if not hmac.compare_digest(str(db_sig), sig):
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "APPROVAL-SIGNATURE-MISMATCH",
                "reason": "Подпись квитанции не совпадает с реестром",
            }
        if int(consumed) != 0:
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "APPROVAL-REPLAY-BLOCKED",
                "reason": "Квитанция одобрения уже была использована (попытка Replay-атаки)",
            }
        if now >= float(expires_at):
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "APPROVAL-EXPIRED",
                "reason": "Срок действия квитанции одобрения истёк",
            }
        if not hmac.compare_digest(str(db_hash), actual_hash) or not hmac.compare_digest(str(payload.get("h") or ""), actual_hash):
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "APPROVAL-PAYLOAD-MISMATCH",
                "reason": "Параметры действия изменены после одобрения человеком (атака TOCTOU / Bait-and-Switch!)",
            }

        conn.execute(
            "UPDATE shield_approval_receipts SET consumed = 1, consumed_at = ? WHERE receipt_id = ? AND user_id = ?",
            (now, rid, uid),
        )
        conn.commit()

    return {
        "ok": True,
        "allowed": True,
        "blocked": False,
        "receipt_id": rid,
        "approved_by": str(approved_by),
        "payload_sha256": actual_hash,
    }
