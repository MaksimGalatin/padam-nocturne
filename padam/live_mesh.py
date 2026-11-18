# -*- coding: utf-8 -*-
"""Живая мульти-устройственная синхронизация «Одна Душа на всех экранах» (Live PQC Multi-Device Mesh).

Архитектура безопасности (поправки приёмки 17.11):
1. Закрытые ключи узла (`mlkem_priv`, `x25519_priv`) и общие ключи синхронизации пиров (`sync_key`)
   НИКОГДА не хранятся в SQLite открытым текстом — они лежат в отдельном защищённом файле
   `<db>.node.key.json` (0600 на POSIX), дополнительно зашифрованном AES-256-GCM на ключе владельца.
   При наличии открытых ключей в старой таблице `ark_mesh_Identity` выполняется автоматическая миграция.
2. Разные устройства имеют разные `owner_key`, поэтому при первом знакомстве проводится
   криптографическое сопряжение (`initiate_pairing` -> `accept_pairing_invite` -> `confirm_peer_sas`)
   с обменом 32-байтного `sync_key` поверх X-Wing (ML-KEM-768 + X25519) и сверкой 6-значного SAS-кода.
   Несопряжённое устройство (`trusted = 0`) к обмену дельтами не допускается.
3. Подпись `HMAC-SHA256` общим `sync_key` проверяется ВСЕГДА (параметр отключения проверки удалён).
   Открытые (незашифрованные) дельты запрещены везде, кроме явного тестового режима.
4. Квитанции забывания (`forget_receipt` и статус `forgotten`/`revoked`) имеют абсолютный приоритет.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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
    trusted      INTEGER NOT NULL DEFAULT 0,
    sas_code     TEXT NOT NULL DEFAULT '',
    last_sync_at TEXT,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_mesh_Identity (
    user_id      TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL,
    device_name  TEXT NOT NULL,
    device_type  TEXT NOT NULL,
    mlkem_priv   TEXT NOT NULL DEFAULT 'external',
    mlkem_pub    TEXT NOT NULL,
    x25519_priv  TEXT NOT NULL DEFAULT 'external',
    x25519_pub   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
"""

_NODE_SECRETS_MEM: dict[int, dict[str, Any]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _node_key_path(store) -> Path | None:
    if str(store.path) == ":memory:":
        return None
    return store.path.with_name(store.path.name + ".node.key.json")


def _wrap_aes_key(store) -> bytes:
    raw_owner, _ = integrity.owner_key(store)
    return hashlib.sha256(b"padam-mesh-node-secrets-v1|" + raw_owner).digest()


def _load_node_secrets(memory) -> dict[str, Any]:
    store = memory.store
    p = _node_key_path(store)
    if p is None:
        return dict(_NODE_SECRETS_MEM.get(id(store)) or {"peers": {}})
    if not p.exists():
        return {"peers": {}}
    raw = json.loads(p.read_text(encoding="utf-8"))
    if raw.get("enc") == "aes256gcm-v1":
        nonce = base64.b64decode(raw["nonce_b64"])
        ct = base64.b64decode(raw["ct_b64"])
        pt = AESGCM(_wrap_aes_key(store)).decrypt(nonce, ct, b"padam-node-secrets")
        data = json.loads(pt.decode("utf-8"))
    else:
        data = dict(raw)
    data.setdefault("peers", {})
    return data


def _save_node_secrets(memory, data: dict[str, Any]) -> None:
    store = memory.store
    p = _node_key_path(store)
    if p is None:
        _NODE_SECRETS_MEM[id(store)] = json.loads(json.dumps(data))
        return
    nonce = secrets.token_bytes(12)
    pt = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ct = AESGCM(_wrap_aes_key(store)).encrypt(nonce, pt, b"padam-node-secrets")
    payload = {
        "enc": "aes256gcm-v1",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ct_b64": base64.b64encode(ct).decode("ascii"),
    }
    p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if os.name == "posix":
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass


def _ensure_mesh(memory) -> None:
    conn = memory.store.conn
    conn.executescript(_MESH_DDL)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(ark_mesh_peer)").fetchall()}
    if "sas_code" not in cols:
        conn.execute("ALTER TABLE ark_mesh_peer ADD COLUMN sas_code TEXT NOT NULL DEFAULT ''")
    ark._ensure_tables(memory)
    # Миграция открытых ключей из старой таблицы ark_mesh_Identity в внешний шифрованный файл
    rows = conn.execute(
        "SELECT user_id, mlkem_priv, x25519_priv FROM ark_mesh_Identity WHERE mlkem_priv NOT IN ('', 'external') OR x25519_priv NOT IN ('', 'external')"
    ).fetchall()
    if rows:
        sec = _load_node_secrets(memory)
        for r in rows:
            if r["user_id"] == memory.user_id:
                if r["mlkem_priv"] not in ("", "external"):
                    sec["mlkem_priv_b64"] = r["mlkem_priv"]
                if r["x25519_priv"] not in ("", "external"):
                    sec["x25519_priv_b64"] = r["x25519_priv"]
            conn.execute(
                "UPDATE ark_mesh_Identity SET mlkem_priv = 'external', x25519_priv = 'external' WHERE user_id = ?",
                (r["user_id"],),
            )
        _save_node_secrets(memory, sec)
    conn.commit()


def _compute_sas_code(pk_a_ml: bytes, pk_a_x: bytes, pk_b_ml: bytes, pk_b_x: bytes, sync_key: bytes) -> str:
    pair_a = pk_a_ml + pk_a_x
    pair_b = pk_b_ml + pk_b_x
    first, second = (pair_a, pair_b) if pair_a <= pair_b else (pair_b, pair_a)
    digest = hashlib.sha256(b"padam-mesh-sas-v2|" + first + b"|" + second + b"|" + sync_key).digest()
    val = int.from_bytes(digest[:4], "big") % 1_000_000
    return f"{val:06d}"


def get_or_create_node_identity(memory, *, device_name: str = "Primary-Node", device_type: str = "pc") -> dict[str, Any]:
    _ensure_mesh(memory)
    conn = memory.store.conn
    row = conn.execute("SELECT * FROM ark_mesh_Identity WHERE user_id = ?", (memory.user_id,)).fetchone()
    sec = _load_node_secrets(memory)
    if row and sec.get("mlkem_priv_b64") and sec.get("x25519_priv_b64"):
        return {
            "node_id": row["node_id"],
            "device_name": row["device_name"],
            "device_type": row["device_type"],
            "mlkem_public_b64": row["mlkem_pub"],
            "x25519_public_b64": row["x25519_pub"],
        }

    kp = pqc_mlkem.generate_xwing_keypair()
    node_id = str(row["node_id"]) if row else f"node-{uuid.uuid4().hex[:12]}"
    now = _now()
    ml_priv_b64 = base64.b64encode(bytes(kp["mlkem_private"])).decode("ascii")
    ml_pub_b64 = base64.b64encode(bytes(kp["mlkem_public"])).decode("ascii")
    x_priv_b64 = base64.b64encode(bytes(kp["x25519_private"])).decode("ascii")
    x_pub_b64 = base64.b64encode(bytes(kp["x25519_public"])).decode("ascii")

    sec["mlkem_priv_b64"] = ml_priv_b64
    sec["x25519_priv_b64"] = x_priv_b64
    _save_node_secrets(memory, sec)

    conn.execute(
        "INSERT OR REPLACE INTO ark_mesh_Identity (user_id, node_id, device_name, device_type, mlkem_priv, mlkem_pub, x25519_priv, x25519_pub, created_at) "
        "VALUES (?, ?, ?, ?, 'external', ?, 'external', ?, ?)",
        (memory.user_id, node_id, device_name, device_type, ml_pub_b64, x_pub_b64, now),
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
    """Регистрирует устройство-пир со статусом `trusted = 0` до прохождения сопряжения SAS."""
    _ensure_mesh(memory)
    now = _now()
    memory.store.conn.execute(
        "INSERT INTO ark_mesh_peer (peer_id, user_id, device_name, device_type, endpoint_url, mlkem_pub, x25519_pub, trusted, sas_code, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0, '', ?) "
        "ON CONFLICT(peer_id) DO UPDATE SET device_name=excluded.device_name, device_type=excluded.device_type, "
        "endpoint_url=excluded.endpoint_url, mlkem_pub=excluded.mlkem_pub, x25519_pub=excluded.x25519_pub",
        (peer_id, memory.user_id, device_name, device_type, endpoint_url, mlkem_public_b64, x25519_public_b64, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "mesh_peer_register", {"peer_id": peer_id, "device_type": device_type, "trusted": False})
    return {"peer_id": peer_id, "device_name": device_name, "device_type": device_type, "trusted": False}


def initiate_pairing(memory, peer_identity: dict[str, Any], *, endpoint_url: str = "") -> dict[str, Any]:
    """Шаг 1 сопряжения: генерирует общий 32B `sync_key`, шифрует его по X-Wing для пира и выдаёт 6-значный SAS."""
    _ensure_mesh(memory)
    self_node = get_or_create_node_identity(memory)
    peer_id = str(peer_identity["node_id"])
    peer_name = str(peer_identity.get("device_name") or peer_id)
    peer_type = str(peer_identity.get("device_type") or "phone")
    peer_ml_pub_b64 = str(peer_identity["mlkem_public_b64"])
    peer_x_pub_b64 = str(peer_identity["x25519_public_b64"])

    sync_key = secrets.token_bytes(32)
    sas_code = _compute_sas_code(
        base64.b64decode(self_node["mlkem_public_b64"]),
        base64.b64decode(self_node["x25519_public_b64"]),
        base64.b64decode(peer_ml_pub_b64),
        base64.b64decode(peer_x_pub_b64),
        sync_key,
    )

    invite_payload = {
        "schema": "padam-mesh-pair-invite-v2",
        "initiator_node": self_node,
        "target_peer_id": peer_id,
        "sync_key_b64": base64.b64encode(sync_key).decode("ascii"),
        "created_at": _now(),
    }
    envelope = pqc_mlkem.pqc_seal_bytes(
        json.dumps(invite_payload, ensure_ascii=False, sort_keys=True).encode("utf-8"),
        base64.b64decode(peer_ml_pub_b64),
        base64.b64decode(peer_x_pub_b64),
    )

    sec = _load_node_secrets(memory)
    sec["peers"][peer_id] = {
        "pending_sync_key_b64": base64.b64encode(sync_key).decode("ascii"),
        "sas_code": sas_code,
    }
    _save_node_secrets(memory, sec)

    memory.store.conn.execute(
        "INSERT INTO ark_mesh_peer (peer_id, user_id, device_name, device_type, endpoint_url, mlkem_pub, x25519_pub, trusted, sas_code, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?) "
        "ON CONFLICT(peer_id) DO UPDATE SET device_name=excluded.device_name, device_type=excluded.device_type, "
        "endpoint_url=excluded.endpoint_url, mlkem_pub=excluded.mlkem_pub, x25519_pub=excluded.x25519_pub, trusted=0, sas_code=excluded.sas_code",
        (peer_id, memory.user_id, peer_name, peer_type, endpoint_url, peer_ml_pub_b64, peer_x_pub_b64, sas_code, _now()),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "mesh_pairing_initiated", {"peer_id": peer_id})
    return {
        "ok": True,
        "peer_id": peer_id,
        "sas_code": sas_code,
        "trusted": False,
        "pairing_invite": {"from_node": self_node["node_id"], "envelope": envelope},
    }


def accept_pairing_invite(memory, pairing_invite: dict[str, Any], *, endpoint_url: str = "") -> dict[str, Any]:
    """Шаг 2 сопряжения на принимающем устройстве: расшифровывает приглашение и вычисляет 6-значный SAS."""
    _ensure_mesh(memory)
    self_node = get_or_create_node_identity(memory)
    sec = _load_node_secrets(memory)
    ml_priv = base64.b64decode(sec["mlkem_priv_b64"])
    x_priv = base64.b64decode(sec["x25519_priv_b64"])

    raw = pqc_mlkem.pqc_open_bytes(pairing_invite["envelope"], ml_priv, x_priv)
    payload = json.loads(raw.decode("utf-8"))
    if payload.get("schema") != "padam-mesh-pair-invite-v2":
        raise ValueError("Unsupported pairing invite schema")

    init_node = dict(payload["initiator_node"])
    peer_id = str(init_node["node_id"])
    sync_key = base64.b64decode(payload["sync_key_b64"])
    sas_code = _compute_sas_code(
        base64.b64decode(init_node["mlkem_public_b64"]),
        base64.b64decode(init_node["x25519_public_b64"]),
        base64.b64decode(self_node["mlkem_public_b64"]),
        base64.b64decode(self_node["x25519_public_b64"]),
        sync_key,
    )

    sec["peers"][peer_id] = {
        "pending_sync_key_b64": base64.b64encode(sync_key).decode("ascii"),
        "sas_code": sas_code,
    }
    _save_node_secrets(memory, sec)

    memory.store.conn.execute(
        "INSERT INTO ark_mesh_peer (peer_id, user_id, device_name, device_type, endpoint_url, mlkem_pub, x25519_pub, trusted, sas_code, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?) "
        "ON CONFLICT(peer_id) DO UPDATE SET device_name=excluded.device_name, device_type=excluded.device_type, "
        "endpoint_url=excluded.endpoint_url, mlkem_pub=excluded.mlkem_pub, x25519_pub=excluded.x25519_pub, trusted=0, sas_code=excluded.sas_code",
        (
            peer_id,
            memory.user_id,
            str(init_node.get("device_name") or peer_id),
            str(init_node.get("device_type") or "pc"),
            endpoint_url,
            str(init_node["mlkem_public_b64"]),
            str(init_node["x25519_public_b64"]),
            sas_code,
            _now(),
        ),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "mesh_pairing_received", {"peer_id": peer_id})
    return {"ok": True, "peer_id": peer_id, "sas_code": sas_code, "trusted": False}


def confirm_peer_sas(memory, peer_id: str, sas_code: str) -> dict[str, Any]:
    """Шаг 3 сопряжения: человек сверяет 6-значный SAS-код, после чего пир становится `trusted = 1`."""
    _ensure_mesh(memory)
    conn = memory.store.conn
    row = conn.execute(
        "SELECT peer_id, sas_code FROM ark_mesh_peer WHERE peer_id = ? AND user_id = ?",
        (peer_id, memory.user_id),
    ).fetchone()
    if not row:
        raise KeyError(f"Unknown mesh peer: {peer_id}")
    sec = _load_node_secrets(memory)
    psec = sec.get("peers", {}).get(peer_id) or {}
    expected = str(psec.get("sas_code") or row["sas_code"] or "")
    if not expected or not hmac.compare_digest(expected.strip(), str(sas_code or "").strip()):
        audit_chain.append_audit(memory, "mesh_pairing_sas_failed", {"peer_id": peer_id})
        raise PermissionError("SAS verification code mismatch")

    sync_b64 = psec.get("pending_sync_key_b64") or psec.get("sync_key_b64")
    if not sync_b64:
        raise ValueError("Missing sync_key for peer during SAS confirmation")
    sec["peers"][peer_id] = {"sync_key_b64": sync_b64, "sas_code": expected}
    _save_node_secrets(memory, sec)

    conn.execute(
        "UPDATE ark_mesh_peer SET trusted = 1 WHERE peer_id = ? AND user_id = ?",
        (peer_id, memory.user_id),
    )
    conn.commit()
    audit_chain.append_audit(memory, "mesh_pairing_confirmed", {"peer_id": peer_id})
    return {"ok": True, "peer_id": peer_id, "trusted": True}


def list_peers(memory) -> list[dict[str, Any]]:
    _ensure_mesh(memory)
    rows = memory.store.conn.execute(
        "SELECT peer_id, device_name, device_type, endpoint_url, trusted, last_sync_at, created_at "
        "FROM ark_mesh_peer WHERE user_id = ? ORDER BY created_at ASC",
        (memory.user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _peer_sync_key(memory, peer_id: str) -> bytes:
    row = memory.store.conn.execute(
        "SELECT trusted FROM ark_mesh_peer WHERE peer_id = ? AND user_id = ?",
        (peer_id, memory.user_id),
    ).fetchone()
    if not row or int(row["trusted"]) != 1:
        raise PermissionError(f"Mesh peer {peer_id!r} is not paired/trusted (SAS confirmation required)")
    sec = _load_node_secrets(memory)
    psec = sec.get("peers", {}).get(peer_id) or {}
    sync_b64 = psec.get("sync_key_b64")
    if not sync_b64:
        raise PermissionError(f"Missing pairing sync_key for trusted peer {peer_id!r}")
    return base64.b64decode(sync_b64)


def export_mesh_delta(
    memory,
    *,
    peer_id: str | None = None,
    since_iso: str | None = None,
    recipient_mlkem_pub_b64: str | None = None,
    recipient_x25519_pub_b64: str | None = None,
) -> dict[str, Any]:
    """Собирает дельту изменений; при `peer_id` шифрует PQC и подписывает общим `sync_key` пары."""
    _ensure_mesh(memory)
    conn = memory.store.conn
    node = get_or_create_node_identity(memory)

    resolved_peer_id = peer_id
    if not resolved_peer_id and recipient_mlkem_pub_b64:
        p_row = conn.execute(
            "SELECT peer_id FROM ark_mesh_peer WHERE user_id = ? AND mlkem_pub = ? LIMIT 1",
            (memory.user_id, recipient_mlkem_pub_b64),
        ).fetchone()
        if p_row:
            resolved_peer_id = str(p_row["peer_id"])

    if not resolved_peer_id:
        raise PermissionError("Target paired peer_id is required to export a trusted mesh delta")

    p_row = conn.execute(
        "SELECT mlkem_pub, x25519_pub, trusted FROM ark_mesh_peer WHERE peer_id = ? AND user_id = ?",
        (resolved_peer_id, memory.user_id),
    ).fetchone()
    if not p_row or int(p_row["trusted"]) != 1:
        raise PermissionError(f"Peer {resolved_peer_id!r} is not trusted/paired")

    sync_key = _peer_sync_key(memory, resolved_peer_id)
    target_ml_pub = recipient_mlkem_pub_b64 or str(p_row["mlkem_pub"])
    target_x_pub = recipient_x25519_pub_b64 or str(p_row["x25519_pub"])

    mem_sql = (
        "SELECT id, scope, kind, content, importance, confidence, created_at, last_seen_at, last_confirmed_at, status, origin, owner_sig "
        "FROM memory WHERE user_id = ? AND status = 'active'"
    )
    mem_params: list[Any] = [memory.user_id]
    if since_iso:
        mem_sql += " AND created_at >= ?"
        mem_params.append(since_iso)
    memories = [dict(r) for r in conn.execute(mem_sql, mem_params).fetchall()]

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
        "schema": "padam-live-mesh-delta-v2",
        "source_node": node["node_id"],
        "target_peer": resolved_peer_id,
        "exported_at": _now(),
        "memories": memories,
        "forgotten_ids": forgotten_ids,
        "commitments": commitments,
        "latest_checkpoint": chk,
    }
    raw_bytes = json.dumps(delta_body, ensure_ascii=False, sort_keys=True).encode("utf-8")
    sig = hmac.new(sync_key, raw_bytes, hashlib.sha256).hexdigest()

    sealed = pqc_mlkem.pqc_seal_bytes(
        raw_bytes,
        base64.b64decode(target_ml_pub),
        base64.b64decode(target_x_pub),
    )
    return {
        "encrypted": True,
        "source_node": node["node_id"],
        "hmac_sig": sig,
        "pqc_envelope": sealed,
    }


def apply_mesh_delta(memory, packet: dict[str, Any], *, allow_plaintext_for_tests: bool = False) -> dict[str, Any]:
    """Применяет входящую дельту: ВСЕГДА проверяет сопряжение (`trusted=1`) и подпись HMAC-SHA256."""
    _ensure_mesh(memory)
    conn = memory.store.conn

    if packet.get("encrypted"):
        sec = _load_node_secrets(memory)
        ml_b64 = sec.get("mlkem_priv_b64")
        x_b64 = sec.get("x25519_priv_b64")
        if not ml_b64 or not x_b64:
            raise ValueError("Node PQC identity not initialized in secure keyfile")
        raw_bytes = pqc_mlkem.pqc_open_bytes(
            packet["pqc_envelope"],
            base64.b64decode(ml_b64),
            base64.b64decode(x_b64),
        )
        delta_body = json.loads(raw_bytes.decode("utf-8"))
    elif allow_plaintext_for_tests:
        delta_body = dict(packet.get("delta") or {})
        raw_bytes = json.dumps(delta_body, ensure_ascii=False, sort_keys=True).encode("utf-8")
    else:
        raise PermissionError("Unencrypted mesh deltas are rejected; PQC envelope required")

    source_node = str(packet.get("source_node") or delta_body.get("source_node") or "")
    if not source_node:
        raise PermissionError("Missing source_node in mesh delta")

    sync_key = _peer_sync_key(memory, source_node)
    expected_sig = hmac.new(sync_key, raw_bytes, hashlib.sha256).hexdigest()
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

    conn.execute("UPDATE ark_mesh_peer SET last_sync_at = ? WHERE peer_id = ? AND user_id = ?", (_now(), source_node, memory.user_id))
    conn.commit()
    audit_chain.append_audit(
        memory,
        "mesh_delta_applied",
        {"source_node": source_node, "applied_memories": applied_memories, "erased_forgotten": erased_count, "applied_commitments": applied_commitments},
    )
    return {
        "ok": True,
        "applied_memories": applied_memories,
        "erased_forgotten": erased_count,
        "applied_commitments": applied_commitments,
    }
