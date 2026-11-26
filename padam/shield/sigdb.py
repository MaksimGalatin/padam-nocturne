# -*- coding: utf-8 -*-
"""Одностороннее обновление подписанных баз сигнатур угроз без телеметрии (`padam update-db`).

Аналог ClamAV / trivy-db для ИИ-агентов:
- Подписанный Ed25519 бандл `padam-sigdb.json` (сигнатуры джейлбрейков, вредоносные MCP-пакеты,
  фишинговые контракты, плохие домены).
- Строгая проверка криптографической подписи Ed25519 + SHA-256 + защита от downgrade (`version > prev`).
- Zero-Telemetry: клиент ничего не отправляет на сервер (без user_id, cookies, телеметрии).
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import urllib.request
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from .. import net_guard

_SIGDB_DDL = """
CREATE TABLE IF NOT EXISTS shield_sigdb_state (
    user_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0,
    bundle_sha256 TEXT NOT NULL DEFAULT '',
    publisher_pubkey_b64 TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
);
"""


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ensure_sigdb_table(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_sigdb_ready", False):
        return
    with store._lock:
        store.conn.executescript(_SIGDB_DDL)
        store.conn.commit()
        store._shield_sigdb_ready = True


def generate_publisher_keypair() -> tuple[str, str]:
    """Генерирует пару ключей Ed25519 (private_b64, public_b64) для подписи баз сигнатур."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(priv_raw).decode("ascii"), base64.b64encode(pub_raw).decode("ascii")


def sign_signature_bundle(
    *,
    version: int,
    jailbreak_signatures: list[str],
    malicious_mcp_packages: list[str],
    phishing_contracts: list[str],
    bad_domains: list[str],
    private_key_b64: str,
) -> dict[str, Any]:
    """Создаёт и подписывает Ed25519 бандл сигнатур `padam-sigdb`."""
    body = {
        "schema": "padam-sigdb/1.0",
        "version": int(version),
        "issued_at": _utc_iso(),
        "jailbreak_signatures": [str(x).strip() for x in jailbreak_signatures if str(x).strip()],
        "malicious_mcp_packages": [str(x).strip().lower() for x in malicious_mcp_packages if str(x).strip()],
        "phishing_contracts": [str(x).strip().lower() for x in phishing_contracts if str(x).strip()],
        "bad_domains": [str(x).strip().lower() for x in bad_domains if str(x).strip()],
    }
    canon = _canonical(body)
    sha = hashlib.sha256(canon).hexdigest()
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("ascii")
    sig_b64 = base64.b64encode(priv.sign(canon)).decode("ascii")
    return {
        **body,
        "bundle_sha256": sha,
        "publisher_pubkey_b64": pub_b64,
        "signature_ed25519_b64": sig_b64,
    }


def verify_signature_bundle(bundle: dict[str, Any], *, pinned_pubkey_b64: str) -> dict[str, Any]:
    """Проверяет целостность SHA-256 и подпись Ed25519 бандла сигнатур против закреплённого ключа."""
    if not isinstance(bundle, dict):
        return {"ok": False, "reason": "invalid_bundle_type"}
    sig_b64 = str(bundle.get("signature_ed25519_b64") or "")
    claimed_sha = str(bundle.get("bundle_sha256") or "")
    pub_b64 = str(pinned_pubkey_b64 or "").strip()
    if not sig_b64 or not claimed_sha or not pub_b64:
        return {"ok": False, "reason": "missing_signature_or_pinned_pubkey"}

    body = {
        k: v for k, v in bundle.items()
        if k not in ("bundle_sha256", "publisher_pubkey_b64", "signature_ed25519_b64")
    }
    canon = _canonical(body)
    actual_sha = hashlib.sha256(canon).hexdigest()
    if actual_sha != claimed_sha:
        return {"ok": False, "reason": "sha256_mismatch"}

    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(base64.b64decode(sig_b64), canon)
    except Exception:
        return {"ok": False, "reason": "ed25519_signature_invalid"}

    return {"ok": True, "version": int(body.get("version") or 0), "sha256": actual_sha, "body": body}


def apply_signature_bundle(
    memory: Any,
    bundle: dict[str, Any],
    *,
    pinned_pubkey_b64: str,
) -> dict[str, Any]:
    """Проверяет подпись Ed25519, защищает от отката версии и сохраняет базу сигнатур в SQLite."""
    ensure_sigdb_table(memory)
    v = verify_signature_bundle(bundle, pinned_pubkey_b64=pinned_pubkey_b64)
    if not v.get("ok"):
        return {"ok": False, "applied": False, "reason": v.get("reason")}

    new_ver = int(v["version"])
    with memory.store._lock:
        cur = memory.store.one(
            "SELECT version FROM shield_sigdb_state WHERE user_id = ?",
            (memory.user_id,),
        )
        cur_ver = int(cur["version"]) if cur else 0
        if new_ver <= cur_ver:
            return {
                "ok": False,
                "applied": False,
                "reason": f"downgrade_rejected: new={new_ver} <= current={cur_ver}",
            }
        body = v["body"]
        memory.store.conn.execute(
            """INSERT INTO shield_sigdb_state
               (user_id, version, bundle_sha256, publisher_pubkey_b64, payload_json, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                   version=excluded.version, bundle_sha256=excluded.bundle_sha256,
                   publisher_pubkey_b64=excluded.publisher_pubkey_b64,
                   payload_json=excluded.payload_json, updated_at=excluded.updated_at""",
            (memory.user_id, new_ver, v["sha256"], pinned_pubkey_b64, json.dumps(body, ensure_ascii=False), _utc_iso()),
        )
        memory.store.conn.commit()

    return {
        "ok": True,
        "applied": True,
        "version": new_ver,
        "sha256": v["sha256"],
        "counts": {
            "jailbreak_signatures": len(body.get("jailbreak_signatures") or []),
            "malicious_mcp_packages": len(body.get("malicious_mcp_packages") or []),
            "phishing_contracts": len(body.get("phishing_contracts") or []),
            "bad_domains": len(body.get("bad_domains") or []),
        },
        "zero_telemetry": True,
    }


def update_sigdb_from_source(
    memory: Any,
    *,
    source: str,
    pinned_pubkey_b64: str,
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Односторонне скачивает подписанный бандл сигнатур по локальному пути или HTTPS (без телеметрии)."""
    src = str(source or "").strip()
    if src.startswith(("http://", "https://")):
        safe_url = net_guard.validate_outbound_url(src, allow_localhost=allow_localhost)
        req = urllib.request.Request(safe_url, headers={"User-Agent": "padam-sigdb/1.0"}, method="GET")
        with net_guard.safe_urlopen(req, timeout=10, allow_localhost=allow_localhost) as resp:
            raw = resp.read(5 * 1024 * 1024)
        bundle = json.loads(raw.decode("utf-8"))
    else:
        p = Path(src[7:] if src.startswith("file://") else src)
        bundle = json.loads(p.read_text(encoding="utf-8"))
    return apply_signature_bundle(memory, bundle, pinned_pubkey_b64=pinned_pubkey_b64)


def get_active_sigdb(memory: Any) -> dict[str, Any]:
    """Возвращает текущую применённую базу сигнатур угроз."""
    ensure_sigdb_table(memory)
    row = memory.store.one(
        "SELECT version, bundle_sha256, payload_json, updated_at FROM shield_sigdb_state WHERE user_id = ?",
        (memory.user_id,),
    )
    if not row:
        return {
            "ok": True,
            "version": 0,
            "bundle_sha256": "",
            "jailbreak_signatures": [],
            "malicious_mcp_packages": [],
            "phishing_contracts": [],
            "bad_domains": [],
        }
    body = json.loads(row["payload_json"] or "{}")
    return {
        "ok": True,
        "version": int(row["version"]),
        "bundle_sha256": row["bundle_sha256"],
        "updated_at": row["updated_at"],
        "jailbreak_signatures": list(body.get("jailbreak_signatures") or []),
        "malicious_mcp_packages": list(body.get("malicious_mcp_packages") or []),
        "phishing_contracts": list(body.get("phishing_contracts") or []),
        "bad_domains": list(body.get("bad_domains") or []),
    }
