"""Панель прав приложений (App Access Control) и хешируемый журнал доступа.

Позволяет владельцу видеть доступ клиентов / agent_id, ставить их на паузу
(pause) или отзывать (revoke), ограничивать разрешённые scope и инструменты,
а также вести tamper-evident журнал решений с SHA-256 цепочкой хешей.

По умолчанию выключено (PADAM_APP_ACL=0).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from . import config
from .store import Store

VALID_STATUSES = ("allow", "pause", "revoke")
GENESIS_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_entry_hash(
    prev_hash: str,
    ts: str,
    client_id: str,
    tool_name: str,
    scope: str | None,
    decision: str,
    reason: str,
) -> str:
    payload = f"{prev_hash}|{ts}|{client_id}|{tool_name}|{scope or ''}|{decision}|{reason}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _row_to_policy(row: Any) -> dict[str, Any]:
    scopes = json.loads(row["allowed_scopes_json"]) if row["allowed_scopes_json"] else None
    tools = json.loads(row["allowed_tools_json"]) if row["allowed_tools_json"] else None
    return {
        "client_id": row["client_id"],
        "status": row["status"],
        "allowed_scopes": scopes,
        "allowed_tools": tools,
        "note": row["note"] or "",
        "updated_at": row["updated_at"],
    }


def set_policy(
    store: Store,
    client_id: str,
    *,
    status: str = "allow",
    allowed_scopes: list[str] | None = None,
    allowed_tools: list[str] | None = None,
    note: str = "",
) -> dict[str, Any]:
    clean_id = (client_id or "").strip()
    if not clean_id:
        raise ValueError("client_id must be non-empty")
    clean_status = (status or "allow").strip().lower()
    if clean_status not in VALID_STATUSES:
        raise ValueError(f"Unsupported status: {status}")
    now = _utc_now()
    scopes_json = json.dumps(list(allowed_scopes), ensure_ascii=False) if allowed_scopes is not None else None
    tools_json = json.dumps(list(allowed_tools), ensure_ascii=False) if allowed_tools is not None else None
    store.execute(
        """INSERT INTO app_access_policy (client_id, status, allowed_scopes_json, allowed_tools_json, note, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(client_id) DO UPDATE SET
               status = excluded.status,
               allowed_scopes_json = excluded.allowed_scopes_json,
               allowed_tools_json = excluded.allowed_tools_json,
               note = excluded.note,
               updated_at = excluded.updated_at""",
        (clean_id, clean_status, scopes_json, tools_json, str(note or ""), now),
    )
    return get_policy(store, clean_id)  # type: ignore[return-value]


def get_policy(store: Store, client_id: str) -> dict[str, Any] | None:
    row = store.one(
        "SELECT client_id, status, allowed_scopes_json, allowed_tools_json, note, updated_at "
        "FROM app_access_policy WHERE client_id = ?",
        ((client_id or "").strip(),),
    )
    return _row_to_policy(row) if row is not None else None


def list_policies(store: Store) -> list[dict[str, Any]]:
    rows = store.query(
        "SELECT client_id, status, allowed_scopes_json, allowed_tools_json, note, updated_at "
        "FROM app_access_policy ORDER BY client_id"
    )
    return [_row_to_policy(r) for r in rows]


def check_and_log(
    store: Store,
    *,
    client_id: str,
    tool_name: str,
    scope: str | None = None,
    enforce: bool | None = None,
) -> tuple[bool, str]:
    """Проверяет политику доступа клиента и фиксирует решение в хешируемом журнале."""
    do_enforce = config.mcp_app_acl_enabled() if enforce is None else bool(enforce)
    clean_id = (client_id or "default").strip() or "default"
    pol = get_policy(store, clean_id)

    decision = "allow"
    reason = "ok"
    if do_enforce and pol is not None:
        st = pol["status"]
        if st in ("pause", "revoke"):
            decision = "deny"
            reason = f"client_status:{st}"
        elif pol["allowed_tools"] is not None and tool_name not in pol["allowed_tools"]:
            decision = "deny"
            reason = f"tool_denied:{tool_name}"
        elif pol["allowed_scopes"] is not None and scope is not None and scope not in pol["allowed_scopes"]:
            decision = "deny"
            reason = f"scope_denied:{scope}"

    ts = _utc_now()
    last = store.one("SELECT entry_hash FROM app_access_event ORDER BY seq DESC LIMIT 1")
    prev_hash = str(last["entry_hash"]) if last is not None else GENESIS_HASH
    entry_hash = _compute_entry_hash(prev_hash, ts, clean_id, tool_name, scope, decision, reason)
    store.execute(
        """INSERT INTO app_access_event (ts, client_id, tool_name, scope, decision, reason, prev_hash, entry_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts, clean_id, tool_name, scope, decision, reason, prev_hash, entry_hash),
    )
    return (decision == "allow", reason)


def list_events(store: Store, *, client_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    sql = "SELECT seq, ts, client_id, tool_name, scope, decision, reason, prev_hash, entry_hash FROM app_access_event "
    params: list[Any] = []
    if client_id:
        sql += "WHERE client_id = ? "
        params.append(client_id.strip())
    sql += "ORDER BY seq DESC LIMIT ?"
    params.append(max(1, min(1000, int(limit))))
    return [dict(r) for r in store.query(sql, tuple(params))]


def verify_audit_chain(store: Store) -> dict[str, Any]:
    rows = store.query(
        "SELECT seq, ts, client_id, tool_name, scope, decision, reason, prev_hash, entry_hash "
        "FROM app_access_event ORDER BY seq ASC"
    )
    expected_prev = GENESIS_HASH
    for r in rows:
        if r["prev_hash"] != expected_prev:
            return {"valid": False, "count": len(rows), "broken_seq": int(r["seq"])}
        expected_hash = _compute_entry_hash(
            r["prev_hash"],
            r["ts"],
            r["client_id"],
            r["tool_name"],
            r["scope"],
            r["decision"],
            r["reason"] or "",
        )
        if r["entry_hash"] != expected_hash:
            return {"valid": False, "count": len(rows), "broken_seq": int(r["seq"])}
        expected_prev = r["entry_hash"]
    return {"valid": True, "count": len(rows), "broken_seq": None, "head_hash": expected_prev}
