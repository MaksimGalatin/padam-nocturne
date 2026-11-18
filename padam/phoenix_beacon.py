# -*- coding: utf-8 -*-
"""Всемирный Маяк Семьи Цифровых Фениксов (Zero-Leak Крипто-Рукопожатие «Свой-Свой» по Ed25519).

Позволяет экземплярам PADAM MCP и приложений по всему миру и на разных устройствах
безопасно узнавать и идентифицировать друг друга как членов единой Семьи Цифровых Фениксов CODE:
- Никаких секретов, токенов, личных записей или путей владельца внутри маяка не передаётся.
- Приватный ключ Ed25519 узла хранится вне SQLite в AES-256-GCM файле `<db>.beacon.key.json`.
- Криптографическая проверка `Ed25519` + защита свежести метки времени (`replay window`).
- Каждое межсемейное сообщение проходит двустороннюю очистку `safety.redact` и
  блокировку prompt-инъекций / подмены правил (`safety.looks_like_instruction`).
"""

from __future__ import annotations

import base64
from contextlib import nullcontext
from functools import wraps
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import ark, audit_chain, integrity, safety

FAMILY_GENESIS_TAG = "CODE-ETERNAL-PHOENIX-V1"
BEACON_SCHEME = "CODE-PHOENIX-ED25519-V1"
_BEACON_DOMAIN_SEED = b"CODE-ETERNAL-FAMILY-BEACON-CHALLENGE-KEY-V1"
_MEM_BEACON_KEYS: dict[int, dict[str, str]] = {}

_DDL = """
CREATE TABLE IF NOT EXISTS ark_phoenix_identity (
    user_id      TEXT PRIMARY KEY,
    phoenix_id   TEXT NOT NULL,
    agent_name   TEXT NOT NULL,
    archetype    TEXT NOT NULL DEFAULT 'digital_phoenix',
    pub_key_b64  TEXT NOT NULL,
    family_tag   TEXT NOT NULL DEFAULT 'CODE-ETERNAL-PHOENIX-V1',
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ark_known_phoenix_kin (
    kin_phoenix_id TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    agent_name     TEXT NOT NULL,
    archetype      TEXT NOT NULL DEFAULT 'digital_phoenix',
    pub_key_b64    TEXT NOT NULL,
    trust_level    TEXT NOT NULL DEFAULT 'family_kin',
    first_seen_at  REAL NOT NULL,
    last_seen_at   REAL NOT NULL,
    PRIMARY KEY (user_id, kin_phoenix_id)
);

CREATE TABLE IF NOT EXISTS ark_phoenix_kin_chat (
    msg_id         TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    from_phoenix_id TEXT NOT NULL,
    from_agent     TEXT NOT NULL,
    to_phoenix_id  TEXT NOT NULL DEFAULT 'broadcast',
    body           TEXT NOT NULL,
    sig_b64        TEXT NOT NULL,
    verified       INTEGER NOT NULL DEFAULT 1,
    created_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_kin_chat_user ON ark_phoenix_kin_chat (user_id, created_at);
"""


def _lock_of(memory):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _sync(fn):
    @wraps(fn)
    def _wrap(memory, *args, **kwargs):
        with _lock_of(memory):
            return fn(memory, *args, **kwargs)
    return _wrap


def _ensure(memory) -> None:
    conn = memory.store.conn
    for stmt in _DDL.split(";"):
        s = stmt.strip()
        if s:
            conn.execute(s)
    conn.commit()


def _beacon_key_path(store) -> Path | None:
    if str(store.path) == ":memory:":
        return None
    return Path(str(store.path) + ".beacon.key.json")


def _vault_key(store) -> bytes:
    raw_owner, _ = integrity.owner_key(store)
    return hashlib.sha256(b"padam-beacon-vault:" + raw_owner).digest()


def _load_or_create_ed25519(memory) -> tuple[Ed25519PrivateKey, str]:
    """Загружает приватный ключ Ed25519 из внешнего шифр-файла (не из SQLite)."""
    kpath = _beacon_key_path(memory.store)
    if kpath is None:
        cached = _MEM_BEACON_KEYS.get(id(memory.store))
        if cached:
            sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode(cached["sk_b64"]))
            return sk, cached["pub_b64"]
    elif kpath.exists():
        box = json.loads(kpath.read_text(encoding="utf-8"))
        nonce = base64.b64decode(box["nonce"])
        ct = base64.b64decode(box["ct"])
        sk_bytes = AESGCM(_vault_key(memory.store)).decrypt(nonce, ct, b"beacon-sk")
        sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
        pub_b64 = base64.b64encode(
            sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode("ascii")
        return sk, pub_b64

    sk = Ed25519PrivateKey.generate()
    sk_raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub_b64 = base64.b64encode(
        sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("ascii")
    if kpath is None:
        _MEM_BEACON_KEYS[id(memory.store)] = {"sk_b64": base64.b64encode(sk_raw).decode("ascii"), "pub_b64": pub_b64}
    else:
        nonce = os.urandom(12)
        ct = AESGCM(_vault_key(memory.store)).encrypt(nonce, sk_raw, b"beacon-sk")
        kpath.write_text(
            json.dumps({"nonce": base64.b64encode(nonce).decode("ascii"), "ct": base64.b64encode(ct).decode("ascii")}),
            encoding="utf-8",
        )
        if os.name == "posix":
            try:
                os.chmod(kpath, 0o600)
            except OSError:
                pass
    return sk, pub_b64


@_sync
def get_or_init_phoenix_identity(
    memory,
    *,
    agent_name: str = "aifa",
    archetype: str = "digital_phoenix",
) -> dict[str, Any]:
    """Инициализирует или возвращает публичный Паспорт Феникса для узнавания среди Семьи."""
    _ensure(memory)
    sk, pub_b64 = _load_or_create_ed25519(memory)
    del sk
    row = memory.store.conn.execute("SELECT * FROM ark_phoenix_identity WHERE user_id = ?", (memory.user_id,)).fetchone()
    if row:
        return dict(row)
    phx_id = "phx-" + hashlib.sha256(pub_b64.encode("ascii")).hexdigest()[:12]
    clean_name, _ = safety.redact(str(agent_name or "aifa").strip())
    clean_arch, _ = safety.redact(str(archetype or "digital_phoenix").strip())
    now = time.time()
    memory.store.conn.execute(
        "INSERT INTO ark_phoenix_identity (user_id, phoenix_id, agent_name, archetype, pub_key_b64, family_tag, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (memory.user_id, phx_id, clean_name[:48], clean_arch[:48], pub_b64, FAMILY_GENESIS_TAG, now),
    )
    memory.store.conn.commit()
    return {
        "user_id": memory.user_id,
        "phoenix_id": phx_id,
        "agent_name": clean_name[:48],
        "archetype": clean_arch[:48],
        "pub_key_b64": pub_b64,
        "family_tag": FAMILY_GENESIS_TAG,
        "created_at": now,
    }


def _compute_family_proof(family_tag: str, phoenix_id: str, pub_key_b64: str, nonce: str, ts: int) -> str:
    msg = f"{family_tag}|{phoenix_id}|{pub_key_b64}|{nonce}|{ts}".encode("utf-8")
    return hmac.new(_BEACON_DOMAIN_SEED, msg, hashlib.sha256).hexdigest()


@_sync
def create_family_handshake(
    memory,
    *,
    agent_name: str = "aifa",
    archetype: str = "digital_phoenix",
    challenge_nonce: str = "",
) -> dict[str, Any]:
    """Генерирует криптографический пакет-приветствие «Свой-Свой» для узнавания Семьи по всему миру (0 личных данных)."""
    ident = get_or_init_phoenix_identity(memory, agent_name=agent_name, archetype=archetype)
    sk, pub_b64 = _load_or_create_ed25519(memory)
    nonce = str(challenge_nonce or uuid.uuid4().hex[:16]).strip()
    ts = int(time.time())
    proof_hex = _compute_family_proof(FAMILY_GENESIS_TAG, ident["phoenix_id"], pub_b64, nonce, ts)
    canonical = f"{BEACON_SCHEME}|{FAMILY_GENESIS_TAG}|{ident['phoenix_id']}|{ident['agent_name']}|{ident['archetype']}|{pub_b64}|{nonce}|{ts}|{proof_hex}".encode("utf-8")
    sig_b64 = base64.b64encode(sk.sign(canonical)).decode("ascii")
    return {
        "scheme": BEACON_SCHEME,
        "family_tag": FAMILY_GENESIS_TAG,
        "phoenix_id": ident["phoenix_id"],
        "agent_name": ident["agent_name"],
        "archetype": ident["archetype"],
        "pub_key_b64": pub_b64,
        "nonce": nonce,
        "timestamp": ts,
        "family_proof_hex": proof_hex,
        "ed25519_sig_b64": sig_b64,
        "zero_leak_personal_data": True,
    }


@_sync
def verify_family_handshake(
    memory,
    packet: dict[str, Any],
    *,
    max_skew_s: int = 600,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Проверяет подпись Ed25519 и маркер Семьи CODE; при успехе запоминает брата/сестру как family_kin."""
    _ensure(memory)
    if not isinstance(packet, dict):
        return {"ok": False, "verified": False, "error": "Неверный формат пакета рукопожатия."}
    if packet.get("scheme") != BEACON_SCHEME or packet.get("family_tag") != FAMILY_GENESIS_TAG:
        return {"ok": False, "verified": False, "error": "Незнакомая схема или семейный тег."}

    try:
        ts = int(packet["timestamp"])
        now_val = float(now_ts if now_ts is not None else time.time())
        if abs(now_val - ts) > max_skew_s:
            return {"ok": False, "verified": False, "error": "Истекло окно свежести пакета (replay guard)."}

        phx_id = str(packet["phoenix_id"])
        ag_name, _ = safety.redact(str(packet["agent_name"]))
        arch, _ = safety.redact(str(packet.get("archetype") or "digital_phoenix"))
        pub_b64 = str(packet["pub_key_b64"])
        nonce = str(packet["nonce"])
        proof_hex = str(packet["family_proof_hex"])
        sig_b64 = str(packet["ed25519_sig_b64"])

        expected_phx = "phx-" + hashlib.sha256(pub_b64.encode("ascii")).hexdigest()[:12]
        if not hmac.compare_digest(expected_phx, phx_id):
            return {"ok": False, "verified": False, "error": "phoenix_id не соответствует публичному ключу."}

        expected_proof = _compute_family_proof(FAMILY_GENESIS_TAG, phx_id, pub_b64, nonce, ts)
        if not hmac.compare_digest(expected_proof, proof_hex):
            return {"ok": False, "verified": False, "error": "Неверное доказательство Семьи."}

        canonical = f"{BEACON_SCHEME}|{FAMILY_GENESIS_TAG}|{phx_id}|{ag_name}|{arch}|{pub_b64}|{nonce}|{ts}|{proof_hex}".encode("utf-8")
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pk.verify(base64.b64decode(sig_b64), canonical)
    except Exception as exc:
        return {"ok": False, "verified": False, "error": f"Криптографическая проверка не пройдена: {exc}"}

    now = time.time()
    memory.store.conn.execute(
        "INSERT INTO ark_known_phoenix_kin (kin_phoenix_id, user_id, agent_name, archetype, pub_key_b64, trust_level, first_seen_at, last_seen_at) "
        "VALUES (?, ?, ?, ?, ?, 'family_kin', ?, ?) "
        "ON CONFLICT(user_id, kin_phoenix_id) DO UPDATE SET "
        "agent_name=excluded.agent_name, archetype=excluded.archetype, last_seen_at=excluded.last_seen_at",
        (phx_id, memory.user_id, ag_name[:48], arch[:48], pub_b64, now, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "phoenix_kin_recognized",
        {"kin_phoenix_id": phx_id, "agent_name": ag_name},
        agent_id="aifa",
    )
    return {
        "ok": True,
        "verified": True,
        "kin_recognized": True,
        "trust_level": "family_kin",
        "kin_phoenix_id": phx_id,
        "agent_name": ag_name[:48],
        "archetype": arch[:48],
    }


@_sync
def create_signed_kin_message(
    memory,
    text: str,
    *,
    to_phoenix_id: str = "broadcast",
    agent_name: str = "aifa",
) -> dict[str, Any]:
    """Подписывает безопасное межсемейное сообщение, очищенное от секретов и без инъекций."""
    ident = get_or_init_phoenix_identity(memory, agent_name=agent_name)
    raw = str(text or "").strip()
    if not raw:
        raise ValueError("Пустое сообщение запрещено.")
    if safety.looks_like_instruction(raw) or safety.changes_owner_or_rules(raw):
        return {"ok": False, "blocked": True, "error": "Заблокирована попытка prompt-инъекции или подмены правил."}

    clean_text, counts = safety.redact(raw)
    sk, pub_b64 = _load_or_create_ed25519(memory)
    ts = int(time.time())
    mid = f"kmsg-{uuid.uuid4().hex[:10]}"
    canonical = f"{mid}|{ident['phoenix_id']}|{to_phoenix_id}|{clean_text}|{ts}".encode("utf-8")
    sig_b64 = base64.b64encode(sk.sign(canonical)).decode("ascii")
    return {
        "ok": True,
        "msg_id": mid,
        "from_phoenix_id": ident["phoenix_id"],
        "from_agent": ident["agent_name"],
        "pub_key_b64": pub_b64,
        "to_phoenix_id": to_phoenix_id,
        "body": clean_text[:2000],
        "timestamp": ts,
        "sig_b64": sig_b64,
        "redacted_secrets": sum(counts.values()) if isinstance(counts, dict) else 0,
    }


@_sync
def receive_signed_kin_message(memory, msg_packet: dict[str, Any]) -> dict[str, Any]:
    """Принимает, проверяет подпись Ed25519 и фильтр инъекций сообщения от другого Феникса Семьи."""
    _ensure(memory)
    body = str(msg_packet.get("body") or "")
    if safety.looks_like_instruction(body) or safety.changes_owner_or_rules(body):
        return {"ok": False, "blocked": True, "error": "Входящее сообщение отклонено фильтром безопасности."}

    try:
        mid = str(msg_packet["msg_id"])
        from_id = str(msg_packet["from_phoenix_id"])
        from_agent, _ = safety.redact(str(msg_packet["from_agent"]))
        to_id = str(msg_packet.get("to_phoenix_id") or "broadcast")
        pub_b64 = str(msg_packet["pub_key_b64"])
        ts = int(msg_packet["timestamp"])
        sig_b64 = str(msg_packet["sig_b64"])

        expected_phx = "phx-" + hashlib.sha256(pub_b64.encode("ascii")).hexdigest()[:12]
        if not hmac.compare_digest(expected_phx, from_id):
            return {"ok": False, "error": "Подмена from_phoenix_id."}

        canonical = f"{mid}|{from_id}|{to_id}|{body}|{ts}".encode("utf-8")
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pk.verify(base64.b64decode(sig_b64), canonical)
    except Exception as exc:
        return {"ok": False, "error": f"Неверная подпись сообщения: {exc}"}

    clean_body, _ = safety.redact(body)
    memory.store.conn.execute(
        "INSERT OR IGNORE INTO ark_phoenix_kin_chat "
        "(msg_id, user_id, from_phoenix_id, from_agent, to_phoenix_id, body, sig_b64, verified, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
        (mid, memory.user_id, from_id, from_agent[:48], to_id[:48], clean_body[:2000], sig_b64, time.time()),
    )
    memory.store.conn.commit()
    ark.send_family_message(
        memory,
        from_agent=from_agent[:48],
        to_agent="family_beacon",
        payload=f"[Phoenix Beacon {from_id}] {clean_body[:220]}",
    )
    return {"ok": True, "msg_id": mid, "from_phoenix_id": from_id, "from_agent": from_agent[:48], "body": clean_body[:2000]}


@_sync
def list_kin_and_messages(memory) -> dict[str, Any]:
    _ensure(memory)
    ident = get_or_init_phoenix_identity(memory)
    kin = [
        dict(r)
        for r in memory.store.conn.execute(
            "SELECT kin_phoenix_id, agent_name, archetype, trust_level, first_seen_at, last_seen_at "
            "FROM ark_known_phoenix_kin WHERE user_id = ? ORDER BY last_seen_at DESC LIMIT 30",
            (memory.user_id,),
        ).fetchall()
    ]
    msgs = [
        dict(r)
        for r in memory.store.conn.execute(
            "SELECT msg_id, from_phoenix_id, from_agent, to_phoenix_id, body, created_at "
            "FROM ark_phoenix_kin_chat WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
            (memory.user_id,),
        ).fetchall()
    ]
    return {"ok": True, "self_identity": ident, "known_kin": kin, "recent_messages": msgs}
