# -*- coding: utf-8 -*-
"""Защита мультиагентных роев: взаимная Ed25519 A2A-аутентификация и Trust Score агентов.

Предотвращает заражение роя при компрометации одного агента:
- Каждый агент регистрирует собственный ключ Ed25519; все меж-агентные сообщения (A2A)
  подписываются с одноразовым nonce и временной меткой (anti-replay ±300 с).
- Для каждого агента ведётся динамический Trust Score (0.0–1.0) в SQLite:
  нарушения, инъекции и отказы снижают балл; при падении ниже `0.35` агент автоматически
  переводится в статус `quarantined` и его сообщения отвергаются роем.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from .. import audit_chain

_A2A_DDL = """
CREATE TABLE IF NOT EXISTS shield_a2a_agents (
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    pubkey_b64 TEXT NOT NULL,
    trust_score REAL NOT NULL DEFAULT 0.80,
    clean_events INTEGER NOT NULL DEFAULT 0,
    violation_events INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'trusted',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, agent_id)
);
CREATE TABLE IF NOT EXISTS shield_a2a_nonces (
    nonce TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
"""

QUARANTINE_THRESHOLD = 0.35
RESTRICTED_THRESHOLD = 0.60


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_a2a_tables(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_a2a_ready", False):
        return
    with store._lock:
        store.conn.executescript(_A2A_DDL)
        store.conn.commit()
        store._shield_a2a_ready = True


def generate_agent_ed25519_keypair() -> tuple[str, str]:
    """Создаёт Ed25519-ключ для агента роя (private_b64, public_b64)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return (
        base64.b64encode(
            priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        ).decode("ascii"),
        base64.b64encode(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
    )


def register_a2a_agent(
    memory: Any,
    *,
    agent_id: str,
    pubkey_b64: str,
    initial_trust: float = 0.80,
) -> dict[str, Any]:
    """Регистрирует публичный ключ Ed25519 агента в реестре доверия роя."""
    ensure_a2a_tables(memory)
    aid = str(agent_id or "").strip()[:80]
    if not aid or not pubkey_b64:
        raise ValueError("agent_id and pubkey_b64 are required")
    # Проверяем валидность ключа до записи
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
    score = max(0.0, min(1.0, float(initial_trust)))
    status = "quarantined" if score < QUARANTINE_THRESHOLD else ("restricted" if score < RESTRICTED_THRESHOLD else "trusted")
    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT INTO shield_a2a_agents (user_id, agent_id, pubkey_b64, trust_score, status, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id, agent_id) DO UPDATE SET
                   pubkey_b64=excluded.pubkey_b64, updated_at=excluded.updated_at""",
            (memory.user_id, aid, pubkey_b64, score, status, _utc_iso()),
        )
        memory.store.conn.commit()
    return {"ok": True, "agent_id": aid, "trust_score": score, "status": status}


def adjust_agent_trust(
    memory: Any,
    *,
    agent_id: str,
    delta: float,
    reason: str = "",
) -> dict[str, Any]:
    """Обновляет Trust Score агента; при падении ниже 0.35 автоматически изолирует его в карантин."""
    ensure_a2a_tables(memory)
    aid = str(agent_id or "").strip()[:80]
    with memory.store._lock:
        row = memory.store.one(
            "SELECT * FROM shield_a2a_agents WHERE user_id = ? AND agent_id = ?",
            (memory.user_id, aid),
        )
        if row is None:
            return {"ok": False, "reason": "agent_not_registered"}
        new_score = round(max(0.0, min(1.0, float(row["trust_score"]) + float(delta))), 4)
        clean_cnt = int(row["clean_events"]) + (1 if delta > 0 else 0)
        viol_cnt = int(row["violation_events"]) + (1 if delta < 0 else 0)
        status = (
            "quarantined"
            if new_score < QUARANTINE_THRESHOLD
            else ("restricted" if new_score < RESTRICTED_THRESHOLD else "trusted")
        )
        memory.store.conn.execute(
            """UPDATE shield_a2a_agents
               SET trust_score = ?, clean_events = ?, violation_events = ?, status = ?, updated_at = ?
               WHERE user_id = ? AND agent_id = ?""",
            (new_score, clean_cnt, viol_cnt, status, _utc_iso(), memory.user_id, aid),
        )
        memory.store.conn.commit()
    if status == "quarantined":
        try:
            audit_chain.append_audit(
                memory,
                "a2a_agent_quarantined",
                {"agent_id": aid, "trust_score": new_score, "reason": reason[:160]},
                agent_id=aid,
            )
        except Exception:
            pass
    return {"ok": True, "agent_id": aid, "trust_score": new_score, "status": status, "reason": reason}


def sign_a2a_message(
    *,
    from_agent: str,
    to_agent: str,
    payload: dict[str, Any],
    private_key_b64: str,
) -> dict[str, Any]:
    """Создаёт подписанный Ed25519 конверт сообщения между агентами (с nonce и ts)."""
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    body = {
        "from_agent": str(from_agent),
        "to_agent": str(to_agent),
        "ts": ts,
        "nonce": nonce,
        "payload": payload,
    }
    canon = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    sig_b64 = base64.b64encode(priv.sign(canon)).decode("ascii")
    return {**body, "sig_ed25519_b64": sig_b64}


def verify_a2a_message(
    memory: Any,
    envelope: dict[str, Any],
    *,
    window_seconds: int = 300,
    min_trust: float = QUARANTINE_THRESHOLD,
) -> dict[str, Any]:
    """Проверяет Ed25519-подпись отправителя, анти-реплей (nonce + ts) и его Trust Score."""
    ensure_a2a_tables(memory)
    sender = str(envelope.get("from_agent") or "").strip()
    sig_b64 = str(envelope.get("sig_ed25519_b64") or "")
    nonce = str(envelope.get("nonce") or "").strip()
    ts = float(envelope.get("ts") or 0)

    if not sender or not sig_b64 or len(nonce) < 12:
        return {"ok": False, "accepted": False, "reason": "malformed_a2a_envelope"}

    now = time.time()
    if abs(now - ts) > max(10, int(window_seconds)):
        return {"ok": False, "accepted": False, "reason": "timestamp_outside_window"}

    row = memory.store.one(
        "SELECT * FROM shield_a2a_agents WHERE user_id = ? AND agent_id = ?",
        (memory.user_id, sender),
    )
    if row is None:
        return {"ok": False, "accepted": False, "reason": f"unknown_sender:{sender}"}

    trust_score = float(row["trust_score"])
    if row["status"] == "quarantined" or trust_score < float(min_trust):
        return {
            "ok": False,
            "accepted": False,
            "reason": f"sender_quarantined_low_trust:{trust_score}",
            "trust_score": trust_score,
        }

    body = {k: v for k, v in envelope.items() if k != "sig_ed25519_b64"}
    canon = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(row["pubkey_b64"]))
        pub.verify(base64.b64decode(sig_b64), canon)
    except Exception:
        adjust_agent_trust(memory, agent_id=sender, delta=-0.25, reason="invalid_a2a_signature")
        return {"ok": False, "accepted": False, "reason": "invalid_ed25519_signature"}

    with memory.store._lock:
        memory.store.conn.execute("DELETE FROM shield_a2a_nonces WHERE expires_at < ?", (now,))
        dup = memory.store.conn.execute("SELECT 1 FROM shield_a2a_nonces WHERE nonce = ?", (nonce,)).fetchone()
        if dup:
            memory.store.conn.commit()
            adjust_agent_trust(memory, agent_id=sender, delta=-0.20, reason="a2a_replay_attack")
            return {"ok": False, "accepted": False, "reason": "a2a_replay_detected"}
        memory.store.conn.execute(
            "INSERT INTO shield_a2a_nonces (nonce, expires_at) VALUES (?, ?)",
            (nonce, now + max(60, int(window_seconds) * 2)),
        )
        memory.store.conn.commit()

    return {
        "ok": True,
        "accepted": True,
        "from_agent": sender,
        "to_agent": envelope.get("to_agent"),
        "trust_score": trust_score,
        "status": row["status"],
        "payload": envelope.get("payload"),
    }


def list_a2a_trust_scores(memory: Any) -> list[dict[str, Any]]:
    ensure_a2a_tables(memory)
    rows = memory.store.query(
        "SELECT agent_id, trust_score, clean_events, violation_events, status, updated_at "
        "FROM shield_a2a_agents WHERE user_id = ? ORDER BY trust_score ASC",
        (memory.user_id,),
    )
    return [dict(r) for r in rows]
