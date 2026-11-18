# -*- coding: utf-8 -*-
"""Живая мульти-устройственная синхронизация «Одна Душа на всех экранах» (Live PQC Multi-Device Mesh).

Обеспечивает синхронизацию дельт памяти, целей, чекпоинтов и эстафеты Семьи между
ПК, ноутбуком, планшетом и смартфоном поверх постквантового шифрования X-Wing
(`ML-KEM-768 + X25519 + AES-256-GCM`) и HMAC-подписи владельца.

Ключевое правило: квитанции забывания (`forget_receipt`) имеют безусловный приоритет —
забытая хотя бы на одном устройстве запись затирается на всех остальных и никогда
не воскрешается при обратном обмене.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from . import ark, audit_chain, integrity, pqc_mlkem, safety

_MESH_DDL = """
CREATE TABLE IF NOT EXISTS ark_mesh_peer (
    peer_id      TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    device_name  TEXT NOT NULL,
    device_type  TEXT NOT NULL DEFAULT 'pc',
    endpoint_url TEXT NOT NULL DEFAULT '',
    mlkem_pub    TEXT NOT NULL DEFAULT '',
    x25519_pub   TEXT NOT NULL DEFAULT '',
    trusted      INTEGER NOT NULL DEFAULT 1,
    last_sync_at TEXT,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_mesh_Identity (
    user_id      TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL,
    device_name  TEXT NOT NULL,
    device_type  TEXT NOT NULL,
    mlkem_priv   TEXT NOT NULL,
    mlkem_pub    TEXT NOT NULL,
    x25519_priv  TEXT NOT NULL,
    x25519_pub   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_mesh(memory) -> None:
    memory.store.conn.executescript(_MESH_DDL)
    ark._ensure_tables(memory)
    memory.store.conn.commit()


def get_or_create_node_identity(memory, *, device_name: str = "Primary-Node", device_type: str = "pc") -> dict[str, Any]:
    _ensure_mesh(memory)
    conn = memory.store.conn
    row = conn.execute("SELECT * FROM ark_mesh_Identity WHERE user_id = ?", (memory.user_id,)).fetchone()
    if row:
        return {
            "node_id": row["node_id"],
            "device_name": row["device_name"],
            "device_type": row["device_type"],
            "mlkem_public_b64": row["mlkem_pub"],
            "x25519_public_b64": row["x25519_pub"],
        }
    kp = pqc_mlkem.generate_xwing_keypair()
    node_id = f"node-{uuid.uuid4().hex[:12]}"
    now = _now()
    ml_priv_b64 = base64.b64encode(kp["mlkem_private"]).decode("ascii")
    ml_pub_b64 = base64.b64encode(kp["mlkem_public"]).decode("ascii")
    x_priv_b64 = base64.b64encode(kp["x25519_private"]).decode("ascii")
    x_pub_b64 = base64.b64encode(kp["x25519_public"]).decode("ascii")
    conn.execute(
        "INSERT INTO ark_mesh_Identity (user_id, node_id, device_name, device_type, mlkem_priv, mlkem_pub, x25519_priv, x25519_pub, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (memory.user_id, node_id, device_name, device_type, ml_priv_b64, ml_pub_b64, x_priv_b64, x_pub_b64, now),
    )
    conn.commit()
    return {
        "node_id": node_id,
        "device_name": device_name,
        "device_type": device_type,
        "mlkem_public_b64": ml_pub_b64,
        "x25519_public_b64": x_pub_b64,
    }


def register_peer(
    memory,
    peer_id: str,
    device_name: str,
    *,
    device_type: str = "phone",
    endpoint_url: str = "",
    mlkem_public_b64: str = "",
    x25519_public_b64: str = "",
) -> dict[str, Any]:
    _ensure_mesh(memory)
    now = _now()
    memory.store.conn.execute(
        "INSERT INTO ark_mesh_peer (peer_id, user_id, device_name, device_type, endpoint_url, mlkem_pub, x25519_pub, trusted, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?) "
        "ON CONFLICT(peer_id) DO UPDATE SET device_name=excluded.device_name, device_type=excluded.device_type, "
        "endpoint_url=excluded.endpoint_url, mlkem_pub=excluded.mlkem_pub, x25519_pub=excluded.x25519_pub",
        (peer_id, memory.user_id, device_name, device_type, endpoint_url, mlkem_public_b64, x25519_public_b64, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "mesh_peer_register", {"peer_id": peer_id, "device_type": device_type})
    return {"peer_id": peer_id, "device_name": device_name, "device_type": device_type, "trusted": True}


def list_peers(memory) -> list[dict[str, Any]]:
    _ensure_mesh(memory)
    rows = memory.store.conn.execute(
        "SELECT peer_id, device_name, device_type, endpoint_url, trusted, last_sync_at, created_at "
        "FROM ark_mesh_peer WHERE user_id = ? ORDER BY created_at ASC",
        (memory.user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def export_mesh_delta(
    memory,
    *,
    since_iso: str | None = None,
    recipient_mlkem_pub_b64: str | None = None,
    recipient_x25519_pub_b64: str | None = None,
) -> dict[str, Any]:
    """Собирает дельту изменений памяти, целей, чекпоинтов и квитанций забывания (с опциональным PQC-шифрованием)."""
    _ensure_mesh(memory)
    conn = memory.store.conn
    node = get_or_create_node_identity(memory)

    mem_sql = (
        "SELECT id, scope, kind, content, importance, confidence, created_at, last_seen_at, last_confirmed_at, status, origin, owner_sig "
        "FROM memory WHERE user_id = ? AND status = 'active'"
    )
    mem_params: list[Any] = [memory.user_id]
    if since_iso:
        mem_sql += " AND created_at >= ?"
        mem_params.append(since_iso)
    memories = [dict(r) for r in conn.execute(mem_sql, mem_params).fetchall()]

    # Квитанции забывания имеют наивысший приоритет
    has_fr = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='forget_receipt'").fetchone()
    forgotten_ids: list[str] = []
    if has_fr:
        fr_rows = conn.execute("SELECT memory_id FROM forget_receipt WHERE user_id = ?", (memory.user_id,)).fetchall()
        forgotten_ids = [str(r["memory_id"]) for r in fr_rows if r["memory_id"]]
    rev_rows = conn.execute(
        "SELECT id FROM memory WHERE user_id = ? AND status IN ('deleted', 'forgotten', 'revoked')",
        (memory.user_id,),
    ).fetchall()
    for r in rev_rows:
        if str(r["id"]) not in forgotten_ids:
            forgotten_ids.append(str(r["id"]))

    commitments = ark.list_commitments(memory, limit=50)
    chk = ark.latest_checkpoint(memory)

    delta_body = {
        "schema": "padam-live-mesh-delta-v1",
        "source_node": node["node_id"],
        "exported_at": _now(),
        "memories": memories,
        "forgotten_ids": forgotten_ids,
        "commitments": commitments,
        "latest_checkpoint": chk,
    }
    raw_bytes = json.dumps(delta_body, ensure_ascii=False, sort_keys=True).encode("utf-8")
    key, _ = integrity.owner_key(memory.store)
    sig = hmac.new(key, raw_bytes, hashlib.sha256).hexdigest()

    if recipient_mlkem_pub_b64 and recipient_x25519_pub_b64:
        sealed = pqc_mlkem.pqc_seal_bytes(
            raw_bytes,
            base64.b64decode(recipient_mlkem_pub_b64),
            base64.b64decode(recipient_x25519_pub_b64),
        )
        return {
            "encrypted": True,
            "source_node": node["node_id"],
            "hmac_sig": sig,
            "pqc_envelope": sealed,
        }

    return {
        "encrypted": False,
        "source_node": node["node_id"],
        "hmac_sig": sig,
        "delta": delta_body,
    }


def apply_mesh_delta(memory, packet: dict[str, Any], *, trust_hmac: bool = True) -> dict[str, Any]:
    """Применяет входящую дельту на устройстве; забытые записи (`forgotten_ids`) стираются безусловно."""
    _ensure_mesh(memory)
    conn = memory.store.conn

    if packet.get("encrypted"):
        id_row = conn.execute("SELECT mlkem_priv, x25519_priv FROM ark_mesh_Identity WHERE user_id = ?", (memory.user_id,)).fetchone()
        if not id_row:
            raise ValueError("Node PQC identity not initialized for decryption")
        raw_bytes = pqc_mlkem.pqc_open_bytes(
            packet["pqc_envelope"],
            base64.b64decode(id_row["mlkem_priv"]),
            base64.b64decode(id_row["x25519_priv"]),
        )
        delta_body = json.loads(raw_bytes.decode("utf-8"))
    else:
        delta_body = dict(packet.get("delta") or {})
        raw_bytes = json.dumps(delta_body, ensure_ascii=False, sort_keys=True).encode("utf-8")

    if trust_hmac:
        key, _ = integrity.owner_key(memory.store)
        expected_sig = hmac.new(key, raw_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(packet.get("hmac_sig") or ""), expected_sig):
            raise PermissionError("Mesh delta HMAC signature verification failed")

    forgotten_ids = set(str(x) for x in (delta_body.get("forgotten_ids") or []))
    erased_count = 0
    for fid in forgotten_ids:
        cur = conn.execute(
            "UPDATE memory SET content = NULL, embedding = NULL, status = 'forgotten' WHERE id = ? AND user_id = ? AND status != 'forgotten'",
            (fid, memory.user_id),
        )
        erased_count += cur.rowcount

    applied_memories = 0
    for m in (delta_body.get("memories") or []):
        mid = str(m.get("id") or "")
        if not mid or mid in forgotten_ids:
            continue
        exists = conn.execute("SELECT status FROM memory WHERE id = ? AND user_id = ?", (mid, memory.user_id)).fetchone()
        if exists and str(exists["status"]) in ("forgotten", "deleted", "revoked"):
            continue
        clean_content, _ = safety.redact(str(m.get("content") or ""))
        if not exists:
            conn.execute(
                "INSERT INTO memory (id, user_id, scope, kind, content, importance, confidence, created_at, last_seen_at, last_confirmed_at, status, origin, owner_sig) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                (
                    mid,
                    memory.user_id,
                    str(m.get("scope") or "global"),
                    str(m.get("kind") or "fact"),
                    clean_content,
                    float(m.get("importance") or 0.5),
                    float(m.get("confidence") or 1.0),
                    str(m.get("created_at") or _now()),
                    str(m.get("last_seen_at") or _now()),
                    str(m.get("last_confirmed_at") or _now()),
                    str(m.get("origin") or "user"),
                    m.get("owner_sig"),
                ),
            )
            applied_memories += 1

    applied_commitments = 0
    for c in (delta_body.get("commitments") or []):
        cid = str(c.get("id") or "")
        if not cid:
            continue
        ex_c = conn.execute("SELECT id FROM ark_commitment WHERE id = ? AND user_id = ?", (cid, memory.user_id)).fetchone()
        if not ex_c:
            conn.execute(
                "INSERT INTO ark_commitment (id, user_id, title, status, priority, due_at, context, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cid,
                    memory.user_id,
                    str(c.get("title") or ""),
                    str(c.get("status") or "open"),
                    int(c.get("priority") or 2),
                    c.get("due_at"),
                    str(c.get("context") or ""),
                    str(c.get("created_at") or _now()),
                    str(c.get("updated_at") or _now()),
                ),
            )
            applied_commitments += 1

    conn.commit()
    audit_chain.append_audit(
        memory,
        "mesh_delta_applied",
        {"applied_memories": applied_memories, "erased_forgotten": erased_count, "applied_commitments": applied_commitments},
    )
    return {
        "ok": True,
        "applied_memories": applied_memories,
        "erased_forgotten": erased_count,
        "applied_commitments": applied_commitments,
    }
