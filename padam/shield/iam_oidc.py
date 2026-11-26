# -*- coding: utf-8 -*-
"""Корпоративная авторизация OIDC / SSO, RBAC для MCP и «Два ключа» (Dual-Control) для Kill Switch.

Совместимо с Okta, Keycloak, Microsoft Entra ID и Google Workspace без отправки телеметрии:
- Локальная верификация JWT (`RS256`, `ES256`, `HS256` через `cryptography`, строгий запрет `alg:none`,
  проверка `iss`, `aud`, `exp`, `nbf`).
- Ролевой доступ (RBAC) к MCP-инструментам по ролям сотрудника (`SecurityAdmin`, `Developer`,
  `Finance`, `Auditor`, `ReadOnly`).
- Механизм «Двух ключей»: снятие Kill Switch в продакшн-режиме требует подписей ДВУХ разных
  офицеров безопасности (`sub_2 != sub_1`) с ролью `SecurityAdmin` и полной записью в `audit_chain`.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .. import audit_chain

_IAM_DDL = """
CREATE TABLE IF NOT EXISTS shield_oidc_providers (
    user_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    role_claim TEXT NOT NULL DEFAULT 'roles',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, issuer)
);
CREATE TABLE IF NOT EXISTS shield_rbac_policies (
    user_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    allowed_tools_json TEXT NOT NULL,
    denied_tools_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, role_name)
);
CREATE TABLE IF NOT EXISTS shield_dual_unlock_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    approver_1_sub TEXT NOT NULL,
    approver_1_email TEXT NOT NULL,
    approver_2_sub TEXT,
    approver_2_email TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);
"""

DEFAULT_RBAC_MATRIX: dict[str, dict[str, list[str]]] = {
    "SecurityAdmin": {"allow": ["*"], "deny": []},
    "Developer": {"allow": ["git_*", "read_*", "search_*", "padam_search", "padam_wake_up", "test_*"], "deny": ["unlock_kill_switch", "transfer_*", "approve_*"]},
    "Finance": {"allow": ["invoice_*", "ledger_*", "padam_search", "outbound_check"], "deny": ["bash", "shell", "exec", "unlock_kill_switch"]},
    "Auditor": {"allow": ["read_*", "audit_*", "proof_pack", "compliance_*", "padam_stats"], "deny": ["write_*", "delete_*", "transfer_*", "bash", "shell", "unlock_kill_switch"]},
    "ReadOnly": {"allow": ["read_*", "list_*", "padam_search", "padam_stats"], "deny": ["*write*", "*delete*", "*transfer*", "bash", "shell", "exec", "unlock_kill_switch"]},
}


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * ((4 - len(seg) % 4) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def ensure_iam_tables(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_iam_ready", False):
        return
    with store._lock:
        store.conn.executescript(_IAM_DDL)
        store.conn.commit()
        store._shield_iam_ready = True


def register_oidc_provider(
    memory: Any,
    *,
    issuer: str,
    audience: str,
    public_key_pem: str,
    algorithm: str = "RS256",
    role_claim: str = "roles",
) -> dict[str, Any]:
    """Регистрирует корпоративный OIDC-провайдер (Okta / Keycloak / Entra / Google Workspace)."""
    ensure_iam_tables(memory)
    alg = str(algorithm or "RS256").strip().upper()
    if alg not in ("RS256", "ES256", "HS256"):
        raise ValueError(f"Unsupported OIDC JWT algorithm: {alg!r}")
    iss = str(issuer or "").strip()
    aud = str(audience or "").strip()
    if not iss or not aud or not str(public_key_pem or "").strip():
        raise ValueError("issuer, audience and public_key_pem are required")
    now = _utc_iso()
    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT INTO shield_oidc_providers (user_id, issuer, audience, algorithm, public_key_pem, role_claim, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id, issuer) DO UPDATE SET
                   audience=excluded.audience, algorithm=excluded.algorithm,
                   public_key_pem=excluded.public_key_pem, role_claim=excluded.role_claim,
                   updated_at=excluded.updated_at""",
            (memory.user_id, iss, aud, alg, str(public_key_pem).strip(), str(role_claim or "roles").strip(), now),
        )
        memory.store.conn.commit()
    return {"ok": True, "issuer": iss, "audience": aud, "algorithm": alg}


def issue_test_oidc_jwt(
    *,
    private_key_pem: str,
    algorithm: str,
    issuer: str,
    audience: str,
    subject: str,
    email: str,
    roles: list[str],
    ttl_seconds: int = 300,
) -> str:
    """Формирует подписанный OIDC JWT (для локальных корпоративных тестов и CLI-интеграций)."""
    alg = algorithm.upper()
    now = int(time.time())
    hdr = {"alg": alg, "typ": "JWT"}
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "email": email,
        "roles": list(roles),
        "iat": now,
        "nbf": now - 5,
        "exp": now + int(ttl_seconds),
    }
    h_b64 = _b64url_encode(json.dumps(hdr, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    if alg == "HS256":
        sig = hmac.new(private_key_pem.encode("utf-8"), signing_input, hashlib.sha256).digest()
    elif alg == "RS256":
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("RS256 requires RSA private key")
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256":
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError("ES256 requires EC private key")
        sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported alg: {alg}")

    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def verify_oidc_jwt(memory: Any, token: str) -> dict[str, Any]:
    """Локально проверяет подпись и клеймы OIDC JWT по зарегистрированному провайдеру."""
    ensure_iam_tables(memory)
    parts = str(token or "").strip().split(".")
    if len(parts) != 3:
        return {"ok": False, "reason": "malformed_jwt"}
    try:
        hdr = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        sig = _b64url_decode(parts[2])
    except Exception:
        return {"ok": False, "reason": "invalid_jwt_encoding"}

    alg = str(hdr.get("alg") or "").upper()
    if alg in ("", "NONE"):
        return {"ok": False, "reason": "alg_none_rejected"}

    iss = str(claims.get("iss") or "").strip()
    prov = memory.store.one(
        "SELECT * FROM shield_oidc_providers WHERE user_id = ? AND issuer = ?",
        (memory.user_id, iss),
    )
    if prov is None:
        return {"ok": False, "reason": f"unknown_issuer:{iss}"}
    if str(prov["algorithm"]).upper() != alg:
        return {"ok": False, "reason": "algorithm_mismatch"}

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    pub_raw = str(prov["public_key_pem"])
    try:
        if alg == "HS256":
            expected = hmac.new(pub_raw.encode("utf-8"), signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, sig):
                return {"ok": False, "reason": "invalid_signature"}
        elif alg == "RS256":
            pub = serialization.load_pem_public_key(pub_raw.encode("utf-8"))
            pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
        elif alg == "ES256":
            pub = serialization.load_pem_public_key(pub_raw.encode("utf-8"))
            pub.verify(sig, signing_input, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
    except Exception:
        return {"ok": False, "reason": "invalid_signature"}

    now = time.time()
    aud = claims.get("aud")
    expected_aud = str(prov["audience"])
    aud_ok = (aud == expected_aud) if isinstance(aud, str) else (isinstance(aud, list) and expected_aud in aud)
    if not aud_ok:
        return {"ok": False, "reason": "audience_mismatch"}
    if float(claims.get("exp") or 0) <= now:
        return {"ok": False, "reason": "token_expired"}
    if claims.get("nbf") is not None and float(claims["nbf"]) > now + 30:
        return {"ok": False, "reason": "token_not_yet_valid"}

    role_claim = str(prov["role_claim"] or "roles")
    raw_roles = claims.get(role_claim) or []
    user_roles = [raw_roles] if isinstance(raw_roles, str) else [str(r) for r in raw_roles]
    return {
        "ok": True,
        "sub": str(claims.get("sub") or ""),
        "email": str(claims.get("email") or ""),
        "issuer": iss,
        "roles": user_roles,
        "claims": claims,
    }


def _match_glob(pattern: str, value: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(value.lower(), pattern.lower())


def check_tool_rbac(memory: Any, *, user_roles: list[str], tool_name: str) -> dict[str, Any]:
    """Проверяет корпоративное право доступа ролей сотрудника к MCP-инструменту (deny-override)."""
    ensure_iam_tables(memory)
    tname = str(tool_name or "").strip()
    if not user_roles:
        return {"ok": True, "allowed": False, "reason": "no_roles_assigned", "tool": tname}

    allowed = False
    for r in user_roles:
        row = memory.store.one(
            "SELECT allowed_tools_json, denied_tools_json FROM shield_rbac_policies WHERE user_id = ? AND role_name = ?",
            (memory.user_id, r),
        )
        if row:
            allow_pats = json.loads(row["allowed_tools_json"] or "[]")
            deny_pats = json.loads(row["denied_tools_json"] or "[]")
        else:
            preset = DEFAULT_RBAC_MATRIX.get(r, {"allow": [], "deny": []})
            allow_pats, deny_pats = preset["allow"], preset["deny"]

        if any(_match_glob(p, tname) for p in deny_pats):
            return {"ok": True, "allowed": False, "reason": f"role_{r}_explicitly_denies_{tname}", "tool": tname, "roles": user_roles}
        if any(_match_glob(p, tname) for p in allow_pats):
            allowed = True

    return {
        "ok": True,
        "allowed": allowed,
        "reason": "rbac_allowed" if allowed else "rbac_default_deny",
        "tool": tname,
        "roles": user_roles,
    }


def request_or_approve_dual_unlock(
    memory: Any,
    *,
    oidc_token: str,
    reason: str = "incident_resolved",
    request_id: str | None = None,
) -> dict[str, Any]:
    """Механизм «Двух ключей» для снятия Kill Switch через корпоративный OIDC/SSO.

    1-й SecurityAdmin создаёт заявку (`pending_second_key`).
    2-й ДРУГОЙ SecurityAdmin (`sub_2 != sub_1`) подтверждает её → Kill Switch снимается,
    обе личности пишутся в SHA-256 цепь аудита.
    """
    ensure_iam_tables(memory)
    v = verify_oidc_jwt(memory, oidc_token)
    if not v.get("ok"):
        return {"ok": False, "unlocked": False, "reason": f"oidc_rejected:{v.get('reason')}"}
    if "SecurityAdmin" not in (v.get("roles") or []):
        return {"ok": False, "unlocked": False, "reason": "missing_SecurityAdmin_role"}

    sub = v["sub"]
    email = v["email"]
    now = _utc_iso()

    if not request_id:
        rid = f"du-{uuid.uuid4().hex[:12]}"
        with memory.store._lock:
            memory.store.conn.execute(
                """INSERT INTO shield_dual_unlock_requests
                   (id, user_id, reason, approver_1_sub, approver_1_email, status, created_at)
                   VALUES (?, ?, ?, ?, ?, 'pending_second_key', ?)""",
                (rid, memory.user_id, str(reason or "")[:200], sub, email, now),
            )
            memory.store.conn.commit()
        audit_chain.append_audit(
            memory,
            "kill_switch_dual_unlock_initiated",
            {"request_id": rid, "approver_1_sub": sub, "approver_1_email": email, "reason": reason[:160]},
            agent_id=f"oidc:{sub}",
        )
        return {
            "ok": True,
            "unlocked": False,
            "status": "pending_second_key",
            "request_id": rid,
            "approver_1": {"sub": sub, "email": email},
        }

    with memory.store._lock:
        row = memory.store.one(
            "SELECT * FROM shield_dual_unlock_requests WHERE user_id = ? AND id = ?",
            (memory.user_id, str(request_id).strip()),
        )
        if row is None:
            return {"ok": False, "unlocked": False, "reason": "dual_unlock_request_not_found"}
        if row["status"] != "pending_second_key":
            return {"ok": False, "unlocked": False, "reason": f"request_already_{row['status']}"}
        if str(row["approver_1_sub"]) == sub:
            return {"ok": False, "unlocked": False, "reason": "second_approver_must_be_different_SecurityAdmin"}

        memory.store.conn.execute(
            """UPDATE shield_dual_unlock_requests
               SET approver_2_sub = ?, approver_2_email = ?, status = 'completed', completed_at = ?
               WHERE id = ? AND user_id = ?""",
            (sub, email, now, row["id"], memory.user_id),
        )
        memory.store.conn.commit()

    from .. import agentic_shield as _ash

    unlock_res = _ash.unlock_kill_switch(memory)
    audit_chain.append_audit(
        memory,
        "kill_switch_dual_unlock_completed",
        {
            "request_id": row["id"],
            "approver_1_sub": row["approver_1_sub"],
            "approver_1_email": row["approver_1_email"],
            "approver_2_sub": sub,
            "approver_2_email": email,
        },
        agent_id=f"oidc:{sub}",
    )
    return {
        "ok": True,
        "unlocked": True,
        "status": "completed",
        "request_id": row["id"],
        "approver_1": {"sub": row["approver_1_sub"], "email": row["approver_1_email"]},
        "approver_2": {"sub": sub, "email": email},
        "shield_state": unlock_res,
    }
