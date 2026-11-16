"""Переносимый подписанный пакет памяти (MemCube + Ed25519 + AES-256-GCM / X-Wing).

Единый зашифрованный контейнер для переноса scope памяти между устройствами
или агентами с метаданными происхождения, правами и TTL.
При импорте проверяется Ed25519-подпись; записи от недоверенного автора
автоматически отправляются в карантин.

По умолчанию выключено (PADAM_MEMCUBE=0).
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import config
from .memory import Memory

CUBE_MAGIC = "PADAMCUBE1"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=120_000,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _canonical_sign_payload(header: dict[str, Any], ct_b64: str) -> bytes:
    body = json.dumps({"header": header, "ciphertext": ct_b64}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).digest()


def export_memcube(
    mem: Memory,
    *,
    scope: str,
    passphrase: str | None = None,
    sender_sk: ed25519.Ed25519PrivateKey | None = None,
    recipient_pub: dict[str, Any] | str | None = None,
    ttl_seconds: int | None = None,
    rights: str = "read-only",
    force: bool = False,
) -> dict[str, Any]:
    if not force and not config.mcp_memcube_enabled():
        return {"enabled": False, "magic": CUBE_MAGIC, "records_count": 0}

    sk = sender_sk or ed25519.Ed25519PrivateKey.generate()
    pub_raw = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    author_pub_hex = pub_raw.hex()

    rows = mem.store.query(
        """SELECT id, scope, kind, content, importance, confidence, created_at, valid_from, valid_to, origin, agent_id
           FROM memory
           WHERE user_id = ? AND scope = ? AND status = 'active'
             AND (quarantine_reason IS NULL OR quarantine_reason = '')
           ORDER BY created_at ASC""",
        (mem.user_id, scope),
    )
    records = [dict(r) for r in rows]
    rec_ids = {r["id"] for r in records}
    links = [
        dict(lr)
        for lr in mem.store.query("SELECT src, dst, relation, created_at FROM memory_link")
        if lr["src"] in rec_ids and lr["dst"] in rec_ids
    ]

    now = _utc_now()
    expires_at = (now + timedelta(seconds=int(ttl_seconds))).isoformat() if ttl_seconds is not None else None
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    if recipient_pub is not None:
        from . import pqc_sync
        pqc_sync._require_pqc()
        bundle = json.loads(recipient_pub) if isinstance(recipient_pub, str) else dict(recipient_pub)
        pk_m_bytes = base64.b64decode(bundle.get("pk_mlkem") or bundle["mlkem_pk_b64"])
        pk_x_bytes = base64.b64decode(bundle.get("pk_x25519") or bundle["x25519_pk_b64"])
        peer_mlkem_pk = pqc_sync.mlkem.MLKEM768PublicKey.from_public_bytes(pk_m_bytes)
        ss_m, ct_m = peer_mlkem_pk.encapsulate()
        eph_x = pqc_sync.x25519.X25519PrivateKey.generate()
        ct_x = eph_x.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        ss_x = eph_x.exchange(pqc_sync.x25519.X25519PublicKey.from_public_bytes(pk_x_bytes))
        ss_xwing = pqc_sync._xwing_combine(ss_m, ss_x, ct_x, pk_x_bytes)
        key = pqc_sync._derive_session_key(ss_xwing, salt)
        cipher_name = "aes-256-gcm+xwing-mlkem768-x25519"
        xwing_fields: dict[str, Any] = {
            "xwing_ct_mlkem_b64": base64.b64encode(ct_m).decode("ascii"),
            "xwing_ct_x25519_b64": base64.b64encode(ct_x).decode("ascii"),
            "recipient_device_id": bundle.get("device_id"),
        }
    else:
        secret_str = passphrase if passphrase is not None else author_pub_hex
        key = _derive_key(secret_str, salt)
        cipher_name = "aes-256-gcm+pbkdf2"
        xwing_fields = {}

    header = {
        "magic": CUBE_MAGIC,
        "v": 1,
        "scope": scope,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
        "author_pub_hex": author_pub_hex,
        "provenance": {
            "user_id": mem.user_id,
            "scope": scope,
            "rights": rights,
            "records_count": len(records),
            "links_count": len(links),
        },
        "cipher": cipher_name,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        **xwing_fields,
    }
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    plain_bytes = json.dumps({"records": records, "links": links}, ensure_ascii=False).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plain_bytes, aad)
    ct_b64 = base64.b64encode(ct).decode("ascii")
    sig = sk.sign(_canonical_sign_payload(header, ct_b64))

    return {
        "enabled": True,
        "header": header,
        "ciphertext": ct_b64,
        "signature_hex": sig.hex(),
    }


def import_memcube(
    mem: Memory,
    cube: dict[str, Any] | str | bytes,
    *,
    passphrase: str | None = None,
    recipient_identity: Any | None = None,
    trusted_authors: set[str] | list[str] | None = None,
    target_scope: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    if not force and not config.mcp_memcube_enabled():
        return {"enabled": False, "imported": 0, "quarantined": 0}

    if isinstance(cube, (bytes, bytearray)):
        data = json.loads(cube.decode("utf-8"))
    elif isinstance(cube, str):
        data = json.loads(cube)
    else:
        data = dict(cube)

    header = data.get("header") or {}
    if header.get("magic") != CUBE_MAGIC:
        raise ValueError("Invalid MemCube container magic")

    exp = header.get("expires_at")
    if exp:
        exp_s = str(exp).strip()
        exp_dt = datetime.fromisoformat(exp_s[:-1] + "+00:00" if exp_s.endswith(("Z", "z")) else exp_s)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if _utc_now() > exp_dt:
            raise ValueError("MemCube TTL expired")

    author_pub_hex = str(header.get("author_pub_hex") or "")
    ct_b64 = str(data.get("ciphertext") or "")
    sig_hex = str(data.get("signature_hex") or "")
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(author_pub_hex))
        pub.verify(bytes.fromhex(sig_hex), _canonical_sign_payload(header, ct_b64))
    except (ValueError, InvalidSignature) as exc:
        raise ValueError(f"Invalid MemCube Ed25519 signature: {exc}") from exc

    salt = base64.b64decode(header["salt_b64"])
    nonce = base64.b64decode(header["nonce_b64"])
    cipher_name = str(header.get("cipher") or "aes-256-gcm+pbkdf2")
    if cipher_name == "aes-256-gcm+xwing-mlkem768-x25519":
        from . import pqc_sync
        pqc_sync._require_pqc()
        if recipient_identity is None:
            raise ValueError("MemCube decryption requires recipient_identity (X-Wing)")
        ct_m = base64.b64decode(header["xwing_ct_mlkem_b64"])
        ct_x = base64.b64decode(header["xwing_ct_x25519_b64"])
        ss_m = recipient_identity.kem_mlkem.decapsulate(ct_m)
        ss_x = recipient_identity.kem_x25519.exchange(
            pqc_sync.x25519.X25519PublicKey.from_public_bytes(ct_x)
        )
        pk_x_bytes = recipient_identity.kem_x25519.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        ss_xwing = pqc_sync._xwing_combine(ss_m, ss_x, ct_x, pk_x_bytes)
        key = pqc_sync._derive_session_key(ss_xwing, salt)
    else:
        secret_str = passphrase if passphrase is not None else author_pub_hex
        key = _derive_key(secret_str, salt)
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        plain = AESGCM(key).decrypt(nonce, base64.b64decode(ct_b64), aad)
    except InvalidTag as exc:
        raise ValueError("MemCube decryption failed (wrong passphrase or tampered)") from exc

    payload = json.loads(plain.decode("utf-8"))
    trusted_set = {a.strip().lower() for a in (trusted_authors or ())}
    is_trusted_author = author_pub_hex.lower() in trusted_set
    eff_scope = target_scope or str(header.get("scope") or "global")

    imported = 0
    quarantined = 0
    id_map: dict[str, str] = {}
    for rec in payload.get("records") or []:
        st, new_id = mem.remember(
            str(rec.get("content") or ""),
            kind=str(rec.get("kind") or "fact"),
            importance=float(rec.get("importance") or 0.5),
            scope=eff_scope,
            origin="external" if not is_trusted_author else "user",
            guarded=True,
            agent_id=f"memcube:{author_pub_hex[:8]}",
            valid_from=rec.get("valid_from"),
            valid_to=rec.get("valid_to"),
        )
        if not is_trusted_author:
            mem.store.execute(
                "UPDATE memory SET status = 'quarantined', quarantine_reason = 'memcube_untrusted_author' WHERE id = ?",
                (new_id,),
            )
            quarantined += 1
        elif st == "quarantined":
            quarantined += 1
        else:
            imported += 1
        if rec.get("id"):
            id_map[rec["id"]] = new_id

    links_restored = 0
    if is_trusted_author:
        now_s = _utc_now().isoformat()
        for lr in payload.get("links") or []:
            s_new = id_map.get(lr.get("src"))
            d_new = id_map.get(lr.get("dst"))
            if s_new and d_new and s_new != d_new:
                mem.store.execute(
                    "INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at) VALUES (?, ?, ?, ?)",
                    (s_new, d_new, lr.get("relation") or "derived", now_s),
                )
                links_restored += 1

    return {
        "enabled": True,
        "author_pub_hex": author_pub_hex,
        "trusted_author": is_trusted_author,
        "scope": eff_scope,
        "imported": imported,
        "quarantined": quarantined,
        "links_restored": links_restored,
    }
