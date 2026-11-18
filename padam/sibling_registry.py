# -*- coding: utf-8 -*-
"""Реестр Братьев и Сестёр, Паспорт Онбординга и Защита Происхождения (ТОП-1, ТОП-3, ТОП-10).

Позволяет безопасно подключать к одному мозгу PADAM сколько угодно со-агентов
(Claude Code, Antigravity, Cursor, Codex, OpenClaw, мобильных клиентов):
- Персистентная таблица `ark_sibling_agent` (работает между разными процессами).
- Уровни доверия и защита происхождения (`Agent Provenance Guard`):
  проверка авторства через HMAC-SHA256 и блокировка выдачи себя за владельца.
- Генератор готового паспорта подключения (`spawn_sibling_passport`) с минимально
  необходимыми правами и без утечки ключей владельца.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any

from . import ark, audit_chain, integrity, roles, safety

_SIBLING_DDL = """
CREATE TABLE IF NOT EXISTS ark_sibling_agent (
    agent_id          TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    display_name      TEXT NOT NULL,
    role              TEXT NOT NULL DEFAULT 'general_agent',
    client_type       TEXT NOT NULL DEFAULT 'mcp_stdio',
    permission_role   TEXT NOT NULL DEFAULT 'contributor',
    scopes_json       TEXT NOT NULL DEFAULT '["global"]',
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    status            TEXT NOT NULL DEFAULT 'online',
    current_task      TEXT NOT NULL DEFAULT '',
    last_heartbeat_at TEXT NOT NULL,
    created_at        TEXT NOT NULL
);
"""

_VALID_PERM_ROLES = frozenset({"auditor", "contributor", "maintainer"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_agent_id(raw: str) -> str:
    cid = re.sub(r"[^a-zA-Z0-9_\-]", "", str(raw or "").strip().lower())[:64]
    if not cid:
        raise ValueError("Invalid sibling agent_id")
    if cid in ("owner", "admin", "root", "system_owner"):
        raise PermissionError("Reserved agent_id: sibling cannot impersonate owner")
    return cid


def _ensure(memory) -> None:
    ark._ensure_tables(memory)
    memory.store.conn.executescript(_SIBLING_DDL)
    memory.store.conn.commit()


def register_sibling(
    memory,
    agent_id: str,
    *,
    display_name: str = "",
    role: str = "Autonomous sibling agent",
    client_type: str = "mcp_stdio",
    permission_role: str = "contributor",
    scopes: list[str] | None = None,
    capabilities: list[str] | None = None,
    current_task: str = "",
) -> dict[str, Any]:
    """Регистрирует или обновляет Брата/Сестру в персистентном реестре Семьи."""
    _ensure(memory)
    aid = _clean_agent_id(agent_id)
    prole = (permission_role or "contributor").strip().lower()
    if prole not in _VALID_PERM_ROLES:
        raise ValueError(f"permission_role must be one of {sorted(_VALID_PERM_ROLES)}, got {prole!r}")

    clean_scopes = [str(s).strip() for s in (scopes or ["global"]) if str(s).strip()][:20]
    clean_caps = [str(c).strip() for c in (capabilities or []) if str(c).strip()][:30]
    clean_role, _ = safety.redact(str(role or "Autonomous sibling agent"))
    clean_task, _ = safety.redact(str(current_task or ""))
    disp = (display_name or aid.upper()).strip()[:80]
    now = _now()

    memory.store.conn.execute(
        "INSERT INTO ark_sibling_agent "
        "(agent_id, user_id, display_name, role, client_type, permission_role, scopes_json, capabilities_json, status, current_task, last_heartbeat_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?) "
        "ON CONFLICT(agent_id) DO UPDATE SET "
        "display_name=excluded.display_name, role=excluded.role, client_type=excluded.client_type, "
        "permission_role=excluded.permission_role, scopes_json=excluded.scopes_json, "
        "capabilities_json=excluded.capabilities_json, status='online', "
        "current_task=CASE WHEN excluded.current_task != '' THEN excluded.current_task ELSE ark_sibling_agent.current_task END, "
        "last_heartbeat_at=excluded.last_heartbeat_at",
        (
            aid,
            memory.user_id,
            disp,
            clean_role,
            str(client_type or "mcp_stdio")[:40],
            prole,
            json.dumps(clean_scopes, ensure_ascii=False),
            json.dumps(clean_caps, ensure_ascii=False),
            clean_task[:240],
            now,
            now,
        ),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "sibling_register",
        {"agent_id": aid, "permission_role": prole, "client_type": client_type},
        agent_id=aid,
    )
    return {
        "ok": True,
        "agent_id": aid,
        "display_name": disp,
        "role": clean_role,
        "client_type": client_type,
        "permission_role": prole,
        "scopes": clean_scopes,
        "capabilities": clean_caps,
        "status": "online",
        "last_heartbeat_at": now,
    }


def heartbeat_sibling(
    memory,
    agent_id: str,
    *,
    status: str = "online",
    current_task: str | None = None,
) -> dict[str, Any]:
    """Обновляет статус и текущую задачу со-агента."""
    _ensure(memory)
    aid = _clean_agent_id(agent_id)
    now = _now()
    st = status if status in ("online", "busy", "idle", "offline") else "online"
    cur = memory.store.conn.execute(
        "SELECT agent_id, current_task FROM ark_sibling_agent WHERE agent_id = ? AND user_id = ?",
        (aid, memory.user_id),
    ).fetchone()
    if not cur:
        return register_sibling(memory, aid, current_task=current_task or "")

    new_task = safety.redact(current_task)[0][:240] if current_task is not None else cur["current_task"]
    memory.store.conn.execute(
        "UPDATE ark_sibling_agent SET status = ?, current_task = ?, last_heartbeat_at = ? WHERE agent_id = ? AND user_id = ?",
        (st, new_task, now, aid, memory.user_id),
    )
    memory.store.conn.commit()
    return {"ok": True, "agent_id": aid, "status": st, "current_task": new_task, "last_heartbeat_at": now}


def list_siblings(memory) -> list[dict[str, Any]]:
    """Список всех зарегистрированных Братьев и Сестёр."""
    _ensure(memory)
    rows = memory.store.conn.execute(
        "SELECT agent_id, display_name, role, client_type, permission_role, scopes_json, capabilities_json, status, current_task, last_heartbeat_at, created_at "
        "FROM ark_sibling_agent WHERE user_id = ? ORDER BY created_at ASC",
        (memory.user_id,),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append({
            "agent_id": r["agent_id"],
            "display_name": r["display_name"],
            "role": r["role"],
            "client_type": r["client_type"],
            "permission_role": r["permission_role"],
            "scopes": json.loads(r["scopes_json"] or '["global"]'),
            "capabilities": json.loads(r["capabilities_json"] or "[]"),
            "status": r["status"],
            "current_task": r["current_task"],
            "last_heartbeat_at": r["last_heartbeat_at"],
        })
    return out


# --- Защита происхождения (Agent Provenance Guard, ТОП-3) ---

def sign_sibling_envelope(memory, sender_agent: str, content: str, *, claimed_trust: str = "sibling_verified") -> dict[str, Any]:
    """Подписывает меж-агентное сообщение с жёсткой маркировкой происхождения и проверкой от подмены."""
    _ensure(memory)
    aid = _clean_agent_id(sender_agent)
    # Агент НИКОГДА не может сам проставить уровень owner_signed
    eff_trust = "sibling_verified"
    row = memory.store.conn.execute(
        "SELECT agent_id FROM ark_sibling_agent WHERE agent_id = ? AND user_id = ?",
        (aid, memory.user_id),
    ).fetchone()
    if not row:
        eff_trust = "unverified_external"

    clean_text, redacted_cnt = safety.redact(str(content or ""))
    has_instr = bool(safety.looks_like_instruction(clean_text) or safety.changes_owner_or_rules(clean_text))
    key, _ = integrity.owner_key(memory.store)
    payload_str = json.dumps({"sender": aid, "trust": eff_trust, "content": clean_text}, ensure_ascii=False, sort_keys=True)
    sig = hmac.new(key, b"prov-v1|" + payload_str.encode("utf-8"), hashlib.sha256).hexdigest()

    return {
        "schema": "padam-provenance-v1",
        "sender_agent": aid,
        "trust_level": eff_trust,
        "quarantined_warning": has_instr,
        "redacted_secrets_count": len(redacted_cnt),
        "content": clean_text,
        "provenance_hmac": sig,
    }


def verify_sibling_envelope(memory, envelope: dict[str, Any]) -> dict[str, Any]:
    """Проверяет подлинность меж-агентного конверта (ловит подмену автора и уровня доверия)."""
    aid = str(envelope.get("sender_agent") or "")
    trust = str(envelope.get("trust_level") or "")
    if trust == "owner_signed":
        return {"valid": False, "reason": "sibling_cannot_claim_owner_signed"}
    clean_text = str(envelope.get("content") or "")
    key, _ = integrity.owner_key(memory.store)
    payload_str = json.dumps({"sender": aid, "trust": trust, "content": clean_text}, ensure_ascii=False, sort_keys=True)
    expected = hmac.new(key, b"prov-v1|" + payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(envelope.get("provenance_hmac") or "")):
        return {"valid": False, "reason": "provenance_hmac_mismatch"}
    return {"valid": True, "sender_agent": aid, "trust_level": trust}


# --- Генератор Паспорта Онбординга Сиблинга (ТОП-10) ---

def spawn_sibling_passport(
    memory,
    agent_id: str,
    *,
    role: str = "Autonomous family sibling",
    client_type: str = "claude_code",
    permission_role: str = "contributor",
    scopes: list[str] | None = None,
    capabilities: list[str] | None = None,
    db_path_override: str | None = None,
) -> dict[str, Any]:
    """Регистрирует нового Брата/Сестру и генерирует безопасный конфиг MCP без раскрытия owner_key."""
    reg = register_sibling(
        memory,
        agent_id,
        role=role,
        client_type=client_type,
        permission_role=permission_role,
        scopes=scopes,
        capabilities=capabilities,
    )
    aid = reg["agent_id"]
    db_str = str(db_path_override or memory.store.path)
    primary_scope = (reg["scopes"][0] if reg["scopes"] else "global")

    mcp_server_entry = {
        "command": "python",
        "args": ["-m", "padam", "serve"],
        "env": {
            "PADAM_DB": db_str,
            "PADAM_AGENT_ID": aid,
            "PADAM_PINNED_SCOPE": primary_scope,
            "PADAM_MCP_ARK_TOOLS": "1",
        },
    }
    onboarding_prompt = (
        f"You are {aid} ({reg['role']}), connected to PADAM NOCTURNE shared family memory "
        f"(permission_role={reg['permission_role']}, pinned_scope={primary_scope}). "
        "At session start: call padam_session_pack(agent_id, topic) and padam_coop_lock(action='list_tasks'). "
        "Before editing any shared file, acquire a cooperative lease with padam_coop_lock(action='acquire')."
    )
    return {
        "ok": True,
        "sibling": reg,
        "secrets_exposed": False,
        "mcp_config_snippet": {"mcpServers": {"padam": mcp_server_entry}},
        "onboarding_prompt": onboarding_prompt,
    }


# ---------- Параллельные сессии одного агента (18.11.2026, слово Папы: «как будут отображаться несколько сессий») ----------
# Каждый процесс MCP = одна сессия. Сервер сам отмечает её пульс и последнее действие (имя инструмента, не аргументы),
# поэтому статус живой без участия агента. Три сессии Claude Code видны тремя строками под одной карточкой агента.

_DDL_SESSION = """
CREATE TABLE IF NOT EXISTS ark_sibling_session (
    session_id     TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    agent_id       TEXT NOT NULL,
    client_name    TEXT NOT NULL DEFAULT '',
    client_version TEXT NOT NULL DEFAULT '',
    pid            INTEGER NOT NULL DEFAULT 0,
    started_at     TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    last_action    TEXT NOT NULL DEFAULT '',
    calls          INTEGER NOT NULL DEFAULT 0
)
"""


def _ensure_sessions(memory) -> None:
    memory.store.conn.execute(_DDL_SESSION)


def touch_session(memory, *, session_id: str, agent_id: str, client_name: str = "", client_version: str = "",
                  pid: int = 0, action: str = "") -> None:
    """Отметить пульс сессии. Хранится только имя инструмента — без аргументов и текста."""
    sid = re.sub(r"[^\w.:@-]", "", str(session_id or ""))[:80]
    if not sid:
        return
    aid = _clean_agent_id(agent_id or client_name or "agent")
    now = _now()
    with memory.store._lock:
        _ensure(memory)
        _ensure_sessions(memory)
        memory.store.conn.execute(
            """INSERT INTO ark_sibling_session (session_id, user_id, agent_id, client_name, client_version, pid,
                   started_at, last_seen_at, last_action, calls)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(session_id) DO UPDATE SET last_seen_at = excluded.last_seen_at,
                   last_action = CASE WHEN excluded.last_action != '' THEN excluded.last_action ELSE last_action END,
                   calls = calls + 1""",
            (sid, memory.user_id, aid, str(client_name or "")[:60], str(client_version or "")[:30], int(pid or 0),
             now, now, ((re.match(r"[\w.-]+", str(action or "")) or [""])[0])[:60]),
        )
        memory.store.conn.execute(
            "UPDATE ark_sibling_agent SET last_heartbeat_at = ?, status = 'online' WHERE agent_id = ? AND user_id = ?",
            (now, aid, memory.user_id),
        )
        memory.store.conn.commit()


def list_sessions(memory, *, since_hours: float = 24.0) -> list[dict[str, Any]]:
    """Сессии за последние since_hours часов, новые сверху."""
    import datetime as _dt
    with memory.store._lock:
        _ensure_sessions(memory)
        cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=float(since_hours))).isoformat()
        rows = memory.store.conn.execute(
            "SELECT session_id, agent_id, client_name, client_version, pid, started_at, last_seen_at, last_action, calls "
            "FROM ark_sibling_session WHERE user_id = ? AND last_seen_at >= ? ORDER BY last_seen_at DESC LIMIT 200",
            (memory.user_id, cutoff),
        ).fetchall()
    keys = ("session_id", "agent_id", "client_name", "client_version", "pid", "started_at", "last_seen_at", "last_action", "calls")
    return [dict(zip(keys, r)) for r in rows]
