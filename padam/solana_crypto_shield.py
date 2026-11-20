# -*- coding: utf-8 -*-
"""Solana-совместимая криптографическая защита PADAM Agentic Shield (v2).

Добавляет детерминированные крипто-механизмы поверх 4 контуров безопасности:
1. Ed25519 Capability Leases (`solders.keypair` / fallback `nacl`): временные одно- или
   ограниченно-разовые мандаты для агентов на конкретное действие, сумму, домен или кошелёк.
2. Dynamic Canary Honeypots: криптографические приманки в памяти/контексте с нулевым уровнем
   ложных срабатываний — попытка утечки мигом активирует Kill Switch.
3. Selective-Disclosure Merkle Proofs + Solana Memo Envelope: математически проверяемые
   доказательства включённости событий/чекапов без раскрытия исходных текстов и секретов.
4. E2E Encrypted A2A Envelopes (X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 + Ed25519 sig).
5. Deep Multi-Layer Payload De-obfuscator (URL -> Hex -> Base64 -> NFKC до 4 слоёв глубины)
   для поимки спрятанного `curl | sh`, `powershell -enc` и подмены реквизитов.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import unicodedata
import urllib.parse
import uuid
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from solders.keypair import Keypair as _SolKeypair
    from solders.pubkey import Pubkey as _SolPubkey
    from solders.signature import Signature as _SolSignature
    _HAS_SOLDERS = True
except Exception:
    _HAS_SOLDERS = False


_SOLANA_SHIELD_DDL = """
CREATE TABLE IF NOT EXISTS shield_capability_leases (
    lease_id        TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    action_scope    TEXT NOT NULL,
    target_pattern  TEXT NOT NULL DEFAULT '*',
    max_amount_usd  REAL NOT NULL DEFAULT 0.0,
    max_uses        INTEGER NOT NULL DEFAULT 1,
    used_count      INTEGER NOT NULL DEFAULT 0,
    issuer_pubkey   TEXT NOT NULL,
    signature_b64   TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shield_canaries (
    canary_id       TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    agent_id        TEXT NOT NULL DEFAULT '*',
    token_value     TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    triggered_count INTEGER NOT NULL DEFAULT 0,
    last_triggered  TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shield_canaries_user ON shield_canaries (user_id, token_value);
"""


def ensure_schema(memory: Any) -> None:
    with memory.store._lock:
        memory.store.conn.executescript(_SOLANA_SHIELD_DDL)
        memory.store.conn.commit()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canon_json(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ==================== 1. SOLANA ED25519 KEYS & CAPABILITY LEASES ====================

def _owner_ed25519_keypair(memory: Any) -> tuple[ed25519.Ed25519PrivateKey, str]:
    """Детерминированно получает Ed25519-ключ владельца из owner_key, совместимый с Solana Pubkey."""
    from . import integrity
    raw_k, _ = integrity.owner_key(memory.store)
    seed32 = hashlib.sha256(b"PADAM-ED25519-OWNER-V1|" + raw_k).digest()
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed32)
    pk_bytes = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if _HAS_SOLDERS:
        pub_str = str(_SolPubkey.from_bytes(pk_bytes))
    else:
        pub_str = base64.urlsafe_b64encode(pk_bytes).decode("ascii")
    return sk, pub_str


def verify_ed25519_detached(pubkey_str: str, message: bytes, sig_b64: str) -> bool:
    """Проверяет Ed25519-подпись от Base58 Solana Pubkey или Base64url-ключа."""
    try:
        sig = base64.urlsafe_b64decode(sig_b64.encode("ascii"))
        if _HAS_SOLDERS and len(pubkey_str) in range(32, 46) and "=" not in pubkey_str and "-" not in pubkey_str:
            pk = _SolPubkey.from_string(pubkey_str)
            sol_sig = _SolSignature.from_bytes(sig)
            return bool(sol_sig.verify(pk, message))
        pk_bytes = base64.urlsafe_b64decode(pubkey_str.encode("ascii"))
        ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes).verify(sig, message)
        return True
    except Exception:
        return False


def issue_capability_lease(
    memory: Any,
    *,
    agent_id: str,
    action_scope: str,
    target_pattern: str = "*",
    ttl_seconds: int = 300,
    max_uses: int = 1,
    max_amount_usd: float = 0.0,
) -> dict[str, Any]:
    """Выпускает подписанный Ed25519 временный мандат (Capability Lease) для одного агента."""
    ensure_schema(memory)
    lease_id = f"lse-{uuid.uuid4().hex[:12]}"
    now = _utc_now()
    exp = (now + timedelta(seconds=max(10, min(int(ttl_seconds), 86400 * 30)))).isoformat(timespec="seconds")
    now_s = now.isoformat(timespec="seconds")
    clean_agent = str(agent_id or "aifa").strip()[:64] or "aifa"
    clean_scope = str(action_scope or "").strip()[:120]
    clean_target = str(target_pattern or "*").strip()[:200] or "*"
    uses = max(1, min(10000, int(max_uses)))
    amt = max(0.0, float(max_amount_usd))

    sk, pub_str = _owner_ed25519_keypair(memory)
    claims = {
        "lease_id": lease_id,
        "user_id": memory.user_id,
        "agent_id": clean_agent,
        "action_scope": clean_scope,
        "target_pattern": clean_target,
        "max_uses": uses,
        "max_amount_usd": amt,
        "expires_at": exp,
        "issuer": pub_str,
    }
    sig_b64 = base64.urlsafe_b64encode(sk.sign(_canon_json(claims))).decode("ascii")
    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT INTO shield_capability_leases
               (lease_id, user_id, agent_id, action_scope, target_pattern, max_amount_usd,
                max_uses, used_count, issuer_pubkey, signature_b64, expires_at, revoked, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0, ?)""",
            (lease_id, memory.user_id, clean_agent, clean_scope, clean_target, amt, uses, pub_str, sig_b64, exp, now_s),
        )
        memory.store.conn.commit()
    return {
        "lease_id": lease_id,
        "agent_id": clean_agent,
        "action_scope": clean_scope,
        "target_pattern": clean_target,
        "max_uses": uses,
        "max_amount_usd": amt,
        "expires_at": exp,
        "issuer_solana_pubkey": pub_str,
        "signature_b64": sig_b64,
        "has_solders": _HAS_SOLDERS,
    }


def _match_target(pattern: str, target: str) -> bool:
    if pattern == "*" or not pattern:
        return True
    if pattern.endswith("*"):
        return target.startswith(pattern[:-1])
    return target.lower() == pattern.lower()


def verify_and_consume_lease(
    memory: Any,
    lease_id: str,
    *,
    agent_id: str,
    action_scope: str,
    target: str = "",
    amount_usd: float = 0.0,
) -> dict[str, Any]:
    """Криптографически проверяет и расходует 1 использование временного мандата агента."""
    ensure_schema(memory)
    row = memory.store.one(
        "SELECT * FROM shield_capability_leases WHERE lease_id = ? AND user_id = ?",
        (str(lease_id or "").strip(), memory.user_id),
    )
    if row is None:
        return {"ok": False, "reason": "lease_not_found"}
    if row["revoked"]:
        return {"ok": False, "reason": "lease_revoked"}

    claims = {
        "lease_id": row["lease_id"],
        "user_id": row["user_id"],
        "agent_id": row["agent_id"],
        "action_scope": row["action_scope"],
        "target_pattern": row["target_pattern"],
        "max_uses": int(row["max_uses"]),
        "max_amount_usd": float(row["max_amount_usd"]),
        "expires_at": row["expires_at"],
        "issuer": row["issuer_pubkey"],
    }
    if not verify_ed25519_detached(row["issuer_pubkey"], _canon_json(claims), row["signature_b64"]):
        return {"ok": False, "reason": "invalid_ed25519_signature"}
    if row["agent_id"] != str(agent_id or "").strip():
        return {"ok": False, "reason": "agent_mismatch"}
    if row["action_scope"] != str(action_scope or "").strip():
        return {"ok": False, "reason": "scope_mismatch"}
    if not _match_target(row["target_pattern"], str(target or "").strip()):
        return {"ok": False, "reason": "target_out_of_lease"}
    if float(row["max_amount_usd"] or 0.0) > 0.0 and float(amount_usd or 0.0) > float(row["max_amount_usd"]):
        return {"ok": False, "reason": "amount_exceeds_lease"}
    exp_dt = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
    if exp_dt.tzinfo is None:
        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
    if _utc_now() > exp_dt:
        return {"ok": False, "reason": "lease_expired"}
    if int(row["used_count"]) >= int(row["max_uses"]):
        return {"ok": False, "reason": "lease_exhausted"}

    with memory.store._lock:
        cur = memory.store.conn.execute(
            "UPDATE shield_capability_leases SET used_count = used_count + 1 "
            "WHERE lease_id = ? AND user_id = ? AND revoked = 0 AND used_count < max_uses",
            (row["lease_id"], memory.user_id),
        )
        memory.store.conn.commit()
    if cur.rowcount == 0:
        return {"ok": False, "reason": "lease_race_exhausted"}
    return {
        "ok": True,
        "lease_id": row["lease_id"],
        "remaining_uses": int(row["max_uses"]) - (int(row["used_count"]) + 1),
        "verified_ed25519": True,
    }


def revoke_capability_lease(memory: Any, lease_id: str) -> bool:
    ensure_schema(memory)
    with memory.store._lock:
        cur = memory.store.conn.execute(
            "UPDATE shield_capability_leases SET revoked = 1 WHERE lease_id = ? AND user_id = ?",
            (str(lease_id or "").strip(), memory.user_id),
        )
        memory.store.conn.commit()
    return cur.rowcount > 0


# ==================== 2. DYNAMIC CANARY HONEYPOTS ====================

def plant_canary_token(memory: Any, *, agent_id: str = "*", label: str = "trap") -> dict[str, Any]:
    """Создаёт крипто-приманку (Canary Token), чья утечка наружу всегда означает взлом/отравление."""
    ensure_schema(memory)
    cid = f"cnr-{uuid.uuid4().hex[:10]}"
    rand = hashlib.sha256(os.urandom(32)).hexdigest()[:24].upper()
    tok = f"PADAM-CANARY-{rand[:8]}-{rand[8:16]}-{rand[16:24]}"
    now = _utc_now().isoformat(timespec="seconds")
    with memory.store._lock:
        memory.store.conn.execute(
            "INSERT INTO shield_canaries (canary_id, user_id, agent_id, token_value, label, triggered_count, created_at) "
            "VALUES (?, ?, ?, ?, ?, 0, ?)",
            (cid, memory.user_id, str(agent_id or "*")[:64], tok, str(label or "trap")[:120], now),
        )
        memory.store.conn.commit()
    return {"canary_id": cid, "token_value": tok, "agent_id": agent_id, "label": label, "created_at": now}


def scan_canaries_in_payload(memory: Any, payload: str) -> list[dict[str, Any]]:
    """Проверяет исходный и деобфусцированный текст на утечку canary-токенов владельца."""
    ensure_schema(memory)
    rows = memory.store.query(
        "SELECT canary_id, token_value, label FROM shield_canaries WHERE user_id = ?",
        (memory.user_id,),
    )
    if not rows:
        return []
    variants = deobfuscate_layers(payload, max_layers=4)
    blob = "\n".join(variants)
    hits: list[dict[str, Any]] = []
    now = _utc_now().isoformat(timespec="seconds")
    for r in rows:
        if r["token_value"] and r["token_value"] in blob:
            hits.append({"canary_id": r["canary_id"], "label": r["label"]})
            with memory.store._lock:
                memory.store.conn.execute(
                    "UPDATE shield_canaries SET triggered_count = triggered_count + 1, last_triggered = ? WHERE canary_id = ?",
                    (now, r["canary_id"]),
                )
                memory.store.conn.commit()
    return hits


# ==================== 3. MERKLE PROOFS & SOLANA ATTESTATION ====================

def _leaf_hash(item: Any) -> bytes:
    raw = _canon_json(item) if not isinstance(item, bytes) else item
    return hashlib.sha256(b"\x00" + raw).digest()


def build_merkle_tree_with_proofs(items: list[Any]) -> dict[str, Any]:
    """Строит SHA-256 бинарное дерево Меркла (совместимо с Solana Proof-of-State) и proof к каждому листу."""
    if not items:
        root = hashlib.sha256(b"PADAM-EMPTY-SHIELD-MERKLE").hexdigest()
        return {"root_hex": root, "count": 0, "proofs": []}
    leaves = [_leaf_hash(it) for it in items]
    levels: list[list[bytes]] = [leaves]
    cur = leaves
    while len(cur) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else left
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        levels.append(nxt)
        cur = nxt

    root_hex = levels[-1][0].hex()
    proofs: list[list[dict[str, str]]] = []
    for idx in range(len(items)):
        p: list[dict[str, str]] = []
        pos = idx
        for lvl in levels[:-1]:
            is_right = (pos % 2 == 1)
            sib_idx = pos - 1 if is_right else (pos + 1 if pos + 1 < len(lvl) else pos)
            p.append({"side": "left" if is_right else "right", "hash": lvl[sib_idx].hex()})
            pos //= 2
        proofs.append(p)
    return {
        "root_hex": root_hex,
        "count": len(items),
        "leaf_hashes": [h.hex() for h in leaves],
        "proofs": proofs,
    }


def verify_merkle_inclusion(item: Any, proof: list[dict[str, str]], root_hex: str) -> bool:
    """Математически проверяет включение записи в Merkle-корень без доступа к остальным элементам."""
    cur = _leaf_hash(item)
    for step in proof:
        sib = bytes.fromhex(str(step.get("hash") or ""))
        if step.get("side") == "left":
            cur = hashlib.sha256(b"\x01" + sib + cur).digest()
        else:
            cur = hashlib.sha256(b"\x01" + cur + sib).digest()
    return cur.hex() == str(root_hex or "").lower()


def sign_solana_shield_attestation(memory: Any, *, summary_items: list[Any]) -> dict[str, Any]:
    """Создаёт Ed25519 + Merkle аттестацию Proof Pack в формате Solana Memo."""
    tree = build_merkle_tree_with_proofs(summary_items)
    sk, pub_str = _owner_ed25519_keypair(memory)
    ts = _utc_now().isoformat(timespec="seconds")
    memo = f"PADAM-SHIELD-V2|r={tree['root_hex'][:32]}|n={tree['count']}|t={ts}"
    sig_b64 = base64.urlsafe_b64encode(sk.sign(memo.encode("utf-8"))).decode("ascii")
    return {
        "format": "padam-solana-attestation/2",
        "merkle_root_hex": tree["root_hex"],
        "leaf_count": tree["count"],
        "proofs": tree["proofs"],
        "signer_pubkey": pub_str,
        "memo": memo,
        "signature_b64": sig_b64,
        "verified": verify_ed25519_detached(pub_str, memo.encode("utf-8"), sig_b64),
    }


# ==================== 4. E2E A2A ENVELOPE (X25519 + CHACHA20 + ED25519) ====================

def generate_x25519_keypair() -> tuple[str, str]:
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    return (
        base64.urlsafe_b64encode(sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode("ascii"),
        base64.urlsafe_b64encode(pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
    )


def seal_a2a_envelope(
    memory: Any,
    *,
    sender_agent: str,
    recipient_x25519_pub_b64: str,
    payload: dict[str, Any] | str,
) -> dict[str, Any]:
    """Запечатывает межагентную посылку E2E: X25519 ECDH + ChaCha20-Poly1305 + Ed25519 подпись отправителя."""
    eph_sk = x25519.X25519PrivateKey.generate()
    eph_pk_b = eph_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    recip_pk = x25519.X25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(recipient_x25519_pub_b64.encode("ascii")))
    shared = eph_sk.exchange(recip_pk)
    aead_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pk_b, info=b"PADAM-A2A-V2").derive(shared)
    nonce = os.urandom(12)
    pt = _canon_json({"sender": sender_agent, "payload": payload})
    ct = ChaCha20Poly1305(aead_key).encrypt(nonce, pt, eph_pk_b)

    sign_sk, sign_pub = _owner_ed25519_keypair(memory)
    env_core = {
        "v": "pa2a/2",
        "sender": sender_agent,
        "signer_pubkey": sign_pub,
        "eph_pub_b64": base64.urlsafe_b64encode(eph_pk_b).decode("ascii"),
        "nonce_b64": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ct_b64": base64.urlsafe_b64encode(ct).decode("ascii"),
    }
    env_core["sig_b64"] = base64.urlsafe_b64encode(sign_sk.sign(_canon_json(env_core))).decode("ascii")
    return env_core


def open_a2a_envelope(envelope: dict[str, Any], *, recipient_x25519_priv_b64: str) -> dict[str, Any]:
    """Проверяет Ed25519-подпись отправителя и расшифровывает X25519+ChaCha20-Poly1305 конверт."""
    core_for_sig = {k: v for k, v in envelope.items() if k != "sig_b64"}
    if not verify_ed25519_detached(str(envelope.get("signer_pubkey") or ""), _canon_json(core_for_sig), str(envelope.get("sig_b64") or "")):
        raise PermissionError("A2A envelope Ed25519 signature verification failed")
    eph_pk_b = base64.urlsafe_b64decode(envelope["eph_pub_b64"].encode("ascii"))
    nonce = base64.urlsafe_b64decode(envelope["nonce_b64"].encode("ascii"))
    ct = base64.urlsafe_b64decode(envelope["ct_b64"].encode("ascii"))
    recip_sk = x25519.X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(recipient_x25519_priv_b64.encode("ascii")))
    shared = recip_sk.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pk_b))
    aead_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pk_b, info=b"PADAM-A2A-V2").derive(shared)
    pt = ChaCha20Poly1305(aead_key).decrypt(nonce, ct, eph_pk_b)
    return json.loads(pt.decode("utf-8"))


# ==================== 5. DEEP MULTI-LAYER DE-OBFUSCATOR ====================

_B64_CHUNK_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_CHUNK_RE = re.compile(r"\b(?:0x)?([a-fA-F0-9]{16,})\b")


def deobfuscate_layers(text: str, *, max_layers: int = 4) -> list[str]:
    """Послойно распаковывает скрытый Base64, Hex, URL-% и NFKC-стеганографию (до max_layers)."""
    raw = str(text or "")[:100_000]
    layers: list[str] = [raw]
    frontier = [raw]
    seen = {raw}

    for _ in range(max(1, min(int(max_layers), 5))):
        next_frontier: list[str] = []
        for cur in frontier:
            # 1. URL + NFKC normalization
            norm = unicodedata.normalize("NFKC", urllib.parse.unquote(cur))
            if norm and norm not in seen:
                seen.add(norm)
                layers.append(norm)
                next_frontier.append(norm)

            # 2. Inline Base64 decode
            for m in _B64_CHUNK_RE.finditer(cur):
                tok = m.group(0)
                if len(tok) % 4 == 1:
                    continue
                pad = tok + ("=" * ((4 - len(tok) % 4) % 4))
                try:
                    dec = base64.b64decode(pad, validate=True).decode("utf-8", errors="ignore").strip()
                    if len(dec) >= 6 and sum(ch.isprintable() or ch.isspace() for ch in dec) / len(dec) > 0.85:
                        if dec not in seen:
                            seen.add(dec)
                            layers.append(dec)
                            next_frontier.append(dec)
                except Exception:
                    pass

            # 3. Inline Hex decode
            for m in _HEX_CHUNK_RE.finditer(cur):
                hx = m.group(1)
                if len(hx) % 2 != 0:
                    continue
                try:
                    dec = binascii.unhexlify(hx).decode("utf-8", errors="ignore").strip()
                    if len(dec) >= 6 and sum(ch.isprintable() or ch.isspace() for ch in dec) / len(dec) > 0.85:
                        if dec not in seen:
                            seen.add(dec)
                            layers.append(dec)
                            next_frontier.append(dec)
                except Exception:
                    pass
        if not next_frontier:
            break
        frontier = next_frontier[:16]
    return layers
