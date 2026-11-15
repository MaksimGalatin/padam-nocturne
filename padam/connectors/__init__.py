"""Реестр и операции управления внешними коннекторами PADAM."""

from __future__ import annotations

import json
from typing import Any

from ..i18n import t
from ..store import now_iso
from .base import (
    BaseConnector,
    ConnectorDisabledError,
    ConnectorError,
    HttpCallable,
    RateLimitError,
    TokenRevokedError,
    encrypt_token,
)
from .gdrive import GoogleDriveConnector
from .github import GitHubConnector
from .notion import NotionConnector
from .slack import SlackConnector

CONNECTORS: dict[str, BaseConnector] = {
    "github": GitHubConnector(),
    "notion": NotionConnector(),
    "gdrive": GoogleDriveConnector(),
    "slack": SlackConnector(),
}

PROVIDERS = tuple(CONNECTORS.keys())


def _get_connector(provider: str) -> BaseConnector:
    key = (provider or "").strip().lower()
    if key not in CONNECTORS:
        raise ValueError(t(f"неизвестный коннектор: {provider}", f"unknown connector: {provider}"))
    return CONNECTORS[key]


def list_connectors(memory) -> list[dict[str, Any]]:
    """Возвращает состояние всех 4 коннекторов без раскрытия расшифрованного или сырого токена."""
    rows = {
        r["provider"]: r
        for r in memory.store.query(
            "SELECT * FROM connector_state WHERE user_id = ?",
            (memory.user_id,),
        )
    }
    out: list[dict[str, Any]] = []
    for provider in PROVIDERS:
        row = rows.get(provider)
        if not row:
            out.append({
                "provider": provider,
                "enabled": False,
                "has_token": False,
                "token_storage": None,
                "config": {},
                "cursor": None,
                "last_sync_at": None,
                "last_status": "disabled",
                "last_error": None,
                "imported_count": 0,
            })
            continue
        enc = row["token_enc"] or ""
        storage = "keyvault" if enc.startswith("w1:") else ("local" if enc.startswith("k1:") else None)
        cfg = json.loads(row["config_json"] or "{}")
        out.append({
            "provider": provider,
            "enabled": bool(row["enabled"]),
            "has_token": bool(enc),
            "token_storage": storage,
            "config": cfg,
            "cursor": row["cursor"],
            "last_sync_at": row["last_sync_at"],
            "last_status": row["last_status"] or ("enabled" if row["enabled"] else "disabled"),
            "last_error": row["last_error"],
            "imported_count": int(row["imported_count"] or 0),
        })
    return out


def configure_connector(
    memory,
    provider: str,
    *,
    enabled: bool | None = None,
    token: str | None = None,
    clear_token: bool = False,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Настраивает коннектор владельца: шифрует токен локально и сохраняет параметры."""
    conn = _get_connector(provider)
    prev = memory.store.one(
        "SELECT * FROM connector_state WHERE provider = ? AND user_id = ?",
        (conn.provider, memory.user_id),
    )
    prev_cfg = json.loads(prev["config_json"] or "{}") if prev else {}
    if config:
        for k, v in config.items():
            if v is None or v == "":
                prev_cfg.pop(k, None)
            else:
                prev_cfg[k] = v

    new_enabled = int(bool(prev["enabled"])) if (enabled is None and prev) else int(bool(enabled))
    token_enc = prev["token_enc"] if prev else None
    if clear_token:
        token_enc = None
    elif token is not None and token.strip():
        token_enc = encrypt_token(memory, conn.provider, token)

    ts = now_iso()
    status = "enabled" if new_enabled else "disabled"
    memory.store.execute(
        """INSERT INTO connector_state (
               provider, user_id, enabled, token_enc, config_json, cursor,
               last_sync_at, last_status, last_error, imported_count, updated_at
           ) VALUES (?,?,?,?,?,NULL,NULL,?,NULL,0,?)
           ON CONFLICT(provider, user_id) DO UPDATE SET
               enabled = excluded.enabled,
               token_enc = excluded.token_enc,
               config_json = excluded.config_json,
               last_status = excluded.last_status,
               last_error = CASE WHEN excluded.enabled = 0 THEN NULL ELSE connector_state.last_error END,
               updated_at = excluded.updated_at""",
        (
            conn.provider,
            memory.user_id,
            new_enabled,
            token_enc,
            json.dumps(prev_cfg, ensure_ascii=False),
            status,
            ts,
        ),
    )
    memory._log_audit(
        "connector_configure", conn.provider, actor="owner",
        outcome="ok", detail=f"enabled={bool(new_enabled)} has_token={bool(token_enc)}",
    )
    return next(item for item in list_connectors(memory) if item["provider"] == conn.provider)


def sync_connector(
    memory,
    provider: str,
    *,
    http_call: HttpCallable | None = None,
    rate_limit_s: float = 0.2,
    cancel_event=None,
    progress_cb=None,
) -> dict[str, Any]:
    """Запускает синхронизацию выбранного коннектора через ограду безопасности."""
    conn = _get_connector(provider)
    return conn.sync(
        memory,
        http_call=http_call,
        rate_limit_s=rate_limit_s,
        cancel_event=cancel_event,
        progress_cb=progress_cb,
    )


__all__ = [
    "CONNECTORS",
    "PROVIDERS",
    "ConnectorError",
    "ConnectorDisabledError",
    "TokenRevokedError",
    "RateLimitError",
    "list_connectors",
    "configure_connector",
    "sync_connector",
]
