# -*- coding: utf-8 -*-
"""OAuth 2.1 (PKCE S256) и метаданные защищённого ресурса RFC 9728 для локального MCP HTTP-сервера.

Включается явно через ``PADAM_MCP_OAUTH=1`` или ``make_mcp_http_server(..., oauth=True)``.
По умолчанию выключено: сервер ограничивается локальным ``127.0.0.1`` и статическим Bearer-токеном.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import secrets
import threading
import time
from urllib.parse import urlencode, urlsplit

ALL_SCOPES: tuple[str, ...] = ("padam:read", "padam:write", "padam:sleep")

READ_TOOLS: frozenset[str] = frozenset({
    "padam_search",
    "padam_timeline",
    "padam_stats",
    "padam_export",
    "padam_profile",
    "padam_recent",
})
WRITE_TOOLS: frozenset[str] = frozenset({
    "padam_write",
    "padam_confirm",
    "padam_refute",
})
SLEEP_TOOLS: frozenset[str] = frozenset({
    "padam_sleep",
    "padam_rollback",
})


def required_scope_for_rpc(req: dict) -> str | None:
    """Возвращает требуемый OAuth scope для одиночного JSON-RPC запроса MCP или None для служебных."""
    method = req.get("method")
    if method == "tools/call":
        name = (req.get("params") or {}).get("name")
        if name in WRITE_TOOLS:
            return "padam:write"
        if name in SLEEP_TOOLS:
            return "padam:sleep"
        return "padam:read"
    if method in ("tasks/create", "tasks/cancel"):
        return "padam:sleep"
    if method in (
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "resources/subscribe",
        "resources/unsubscribe",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "tasks/get",
        "tasks/list",
        "tasks/result",
    ):
        return "padam:read"
    return None


def is_local_redirect_uri(uri: str) -> bool:
    """Разрешает только loopback redirect URI по OAuth 2.1 для нативных и локальных клиентов."""
    if not isinstance(uri, str) or not uri or len(uri) > 512:
        return False
    p = urlsplit(uri)
    if p.scheme not in ("http", "https") or p.fragment:
        return False
    host = (p.hostname or "").lower()
    if host not in ("127.0.0.1", "localhost", "::1") and not host.startswith("127."):
        return False
    return True


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _hash_token(salt: bytes, token: str) -> bytes:
    return hashlib.sha256(salt + token.encode("utf-8")).digest()


def _parse_scopes(raw: str | None) -> tuple[str, ...]:
    if not raw or not raw.strip():
        return ("padam:read",)
    parts = [s.strip() for s in raw.split() if s.strip()]
    out: list[str] = []
    for s in parts:
        if s not in ALL_SCOPES:
            raise ValueError(f"unsupported scope: {s}")
        if s not in out:
            out.append(s)
    return tuple(out) if out else ("padam:read",)


class LocalOAuth21Server:
    """Минимальный локальный сервер авторизации OAuth 2.1 (PKCE S256 + RFC 7591 + RFC 9728)."""

    def __init__(self, base_url: str, owner_token: str,
                 code_ttl: int = 300, token_ttl: int = 3600) -> None:
        self.base_url = base_url.rstrip("/")
        self._owner_token = owner_token
        self.code_ttl = code_ttl
        self.token_ttl = token_ttl
        self._lock = threading.Lock()
        self._clients: dict[str, dict] = {}
        self._codes: dict[str, dict] = {}
        self._tokens: dict[str, dict] = {}

    def protected_resource_metadata(self) -> dict:
        """RFC 9728: метаданные защищённого MCP-ресурса."""
        return {
            "resource": f"{self.base_url}/mcp",
            "authorization_servers": [self.base_url],
            "scopes_supported": list(ALL_SCOPES),
            "bearer_methods_supported": ["header"],
            "resource_name": "PADAM NOCTURNE MCP Server",
        }

    def authorization_server_metadata(self) -> dict:
        """RFC 8414: метаданные локального сервера авторизации OAuth 2.1."""
        return {
            "issuer": self.base_url,
            "authorization_endpoint": f"{self.base_url}/oauth/authorize",
            "token_endpoint": f"{self.base_url}/oauth/token",
            "registration_endpoint": f"{self.base_url}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": list(ALL_SCOPES),
        }

    def www_authenticate_header(self, error: str | None = None,
                                scope: str | None = None) -> str:
        """Формирует заголовок WWW-Authenticate со ссылкой на RFC 9728."""
        parts = [f'resource_metadata="{self.base_url}/.well-known/oauth-protected-resource"']
        if error:
            parts.append(f'error="{error}"')
        if scope:
            parts.append(f'scope="{scope}"')
        else:
            parts.append(f'scope="{" ".join(ALL_SCOPES)}"')
        return "Bearer " + ", ".join(parts)

    def register_client(self, payload: dict) -> dict:
        """RFC 7591: динамическая регистрация локального MCP-клиента."""
        if not isinstance(payload, dict):
            raise ValueError("registration payload must be an object")
        uris = payload.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(is_local_redirect_uri(u) for u in uris):
            raise ValueError("redirect_uris must be a non-empty list of loopback http(s) URIs")
        name = str(payload.get("client_name") or "MCP Client")[:120]
        client_id = "padam_cli_" + secrets.token_urlsafe(12)
        record = {
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": list(uris),
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "created_at": int(time.time()),
        }
        with self._lock:
            self._clients[client_id] = record
        return record

    def validate_authorize_request(self, params: dict) -> dict:
        """Проверяет параметры /oauth/authorize (OAuth 2.1: только code + PKCE S256)."""
        if params.get("response_type") != "code":
            raise ValueError("response_type must be 'code'")
        client_id = (params.get("client_id") or "").strip()
        redirect_uri = (params.get("redirect_uri") or "").strip()
        challenge = (params.get("code_challenge") or "").strip()
        method = (params.get("code_challenge_method") or "").strip()
        state = (params.get("state") or "").strip()
        if method != "S256" or not (43 <= len(challenge) <= 128):
            raise ValueError("PKCE code_challenge with S256 is required")
        with self._lock:
            client = self._clients.get(client_id)
        if not client:
            raise ValueError("unknown client_id")
        if redirect_uri not in client["redirect_uris"]:
            raise ValueError("redirect_uri mismatch")
        scopes = _parse_scopes(params.get("scope"))
        return {
            "client": client,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "scopes": scopes,
            "state": state,
        }

    def render_consent_html(self, auth_req: dict) -> str:
        """Страница согласия владельца для OAuth 2.1 авторизации."""
        cname = html.escape(auth_req["client"]["client_name"])
        scopes_str = " ".join(auth_req["scopes"])
        hidden = {
            "client_id": auth_req["client_id"],
            "redirect_uri": auth_req["redirect_uri"],
            "code_challenge": auth_req["code_challenge"],
            "code_challenge_method": "S256",
            "response_type": "code",
            "scope": scopes_str,
            "state": auth_req["state"],
        }
        inputs = "\n".join(
            f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
            for k, v in hidden.items()
        )
        scopes_li = "".join(f"<li><code>{html.escape(s)}</code></li>" for s in auth_req["scopes"])
        return (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<title>PADAM OAuth 2.1 Authorization</title></head><body>"
            f"<h1>Authorize {cname}</h1>"
            f"<p>Requested scopes:</p><ul>{scopes_li}</ul>"
            "<form method='post' action='/oauth/authorize'>"
            f"{inputs}"
            "<label>Owner token: <input type='password' name='owner_token' required></label><br><br>"
            "<button type='submit' name='decision' value='approve'>Approve</button> "
            "<button type='submit' name='decision' value='deny'>Deny</button>"
            "</form></body></html>"
        )

    def approve_or_deny(self, params: dict) -> str:
        """Подтверждает запрос владельцем (по owner_token) и возвращает redirect URI."""
        auth_req = self.validate_authorize_request(params)
        redirect_uri = auth_req["redirect_uri"]
        state = auth_req["state"]
        sep = "&" if "?" in redirect_uri else "?"

        decision = (params.get("decision") or "approve").strip().lower()
        if decision != "approve":
            q = {"error": "access_denied"}
            if state:
                q["state"] = state
            return f"{redirect_uri}{sep}{urlencode(q)}"

        supplied = (params.get("owner_token") or "").strip()
        if not hmac.compare_digest(supplied.encode("utf-8"), self._owner_token.encode("utf-8")):
            raise PermissionError("invalid owner_token")

        code = "padam_code_" + secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            self._purge_expired_locked(now)
            self._codes[code] = {
                "client_id": auth_req["client_id"],
                "redirect_uri": redirect_uri,
                "code_challenge": auth_req["code_challenge"],
                "scopes": auth_req["scopes"],
                "expires_at": now + self.code_ttl,
            }
        q = {"code": code}
        if state:
            q["state"] = state
        return f"{redirect_uri}{sep}{urlencode(q)}"

    def exchange_code(self, params: dict) -> dict:
        """Обменивает одноразовый authorization_code + PKCE code_verifier на короткоживущий Bearer-токен."""
        if (params.get("grant_type") or "") != "authorization_code":
            raise ValueError("unsupported_grant_type")
        code = (params.get("code") or "").strip()
        verifier = (params.get("code_verifier") or "").strip()
        redirect_uri = (params.get("redirect_uri") or "").strip()
        client_id = (params.get("client_id") or "").strip()
        if not code or not verifier or not (43 <= len(verifier) <= 128):
            raise ValueError("invalid_request")

        now = time.time()
        with self._lock:
            self._purge_expired_locked(now)
            rec = self._codes.pop(code, None)
        if not rec or rec["expires_at"] < now:
            raise ValueError("invalid_grant")
        if rec["client_id"] != client_id or rec["redirect_uri"] != redirect_uri:
            raise ValueError("invalid_grant")
        expected_challenge = _s256_challenge(verifier)
        if not hmac.compare_digest(expected_challenge.encode("ascii"), rec["code_challenge"].encode("ascii")):
            raise ValueError("invalid_grant: PKCE verification failed")

        token = "padam_oa_" + secrets.token_urlsafe(32)
        key_id = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
        salt = secrets.token_bytes(16)
        digest = _hash_token(salt, token)
        with self._lock:
            self._tokens[key_id] = {
                "salt": salt,
                "digest": digest,
                "scopes": set(rec["scopes"]),
                "client_id": client_id,
                "expires_at": now + self.token_ttl,
            }
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": self.token_ttl,
            "scope": " ".join(rec["scopes"]),
        }

    def verify_bearer(self, token: str) -> set[str] | None:
        """Проверяет OAuth Bearer-токен и возвращает его набор scope или None."""
        if not token:
            return None
        key_id = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
        now = time.time()
        with self._lock:
            self._purge_expired_locked(now)
            rec = self._tokens.get(key_id)
        if not rec or rec["expires_at"] < now:
            return None
        if not hmac.compare_digest(_hash_token(rec["salt"], token), rec["digest"]):
            return None
        return set(rec["scopes"])

    def _purge_expired_locked(self, now: float) -> None:
        for store in (self._codes, self._tokens):
            expired = [k for k, v in store.items() if v["expires_at"] < now]
            for k in expired:
                store.pop(k, None)
