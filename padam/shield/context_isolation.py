# -*- coding: utf-8 -*-
"""Защита от смешения контекстов и Cross-Tenant утечек (`Context Isolation Guard`).

Не даёт данным одного клиента/проекта (`tenant_a`) просочиться в сессию, память или ответ
другого клиента/проекта (`tenant_b`), даже если их обслуживает один и тот же ИИ-агент:
- Регистрирует чувствительные маркеры/сущности проекта (имена клиентов, номера счетов, внутренние ID).
- Фиксирует активный `tenant_id` для каждой сессии.
- При попытке чтения, записи или выдачи данных, принадлежащих `tenant_a`, внутри активного
  контекста `tenant_b` немедленно блокирует операцию и пишет инцидент `cross_tenant_leak_blocked`
  в SHA-256 цепь аудита.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
from typing import Any

from .. import audit_chain

_ISOLATION_DDL = """
CREATE TABLE IF NOT EXISTS shield_tenant_markers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    marker_text TEXT NOT NULL,
    marker_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, tenant_id, marker_hash)
);
CREATE TABLE IF NOT EXISTS shield_session_tenant (
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    active_tenant TEXT NOT NULL,
    touched_tenants_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, session_id)
);
"""


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_isolation_tables(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_isolation_ready", False):
        return
    with store._lock:
        store.conn.executescript(_ISOLATION_DDL)
        store.conn.commit()
        store._shield_isolation_ready = True


def register_tenant_marker(memory: Any, *, tenant_id: str, marker: str) -> dict[str, Any]:
    """Регистрирует конфиденциальный маркер (имя клиента, номер договора, токен проекта) за tenant_id."""
    ensure_isolation_tables(memory)
    tid = re.sub(r"[^a-zA-Z0-9_.:-]", "_", str(tenant_id or "").strip())[:64]
    mk = str(marker or "").strip()
    if not tid or len(mk) < 4:
        raise ValueError("tenant_id and marker (>= 4 chars) are required")
    mhash = hashlib.sha256(mk.lower().encode("utf-8")).hexdigest()
    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT OR IGNORE INTO shield_tenant_markers (user_id, tenant_id, marker_text, marker_hash, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (memory.user_id, tid, mk[:200], mhash, _utc_iso()),
        )
        memory.store.conn.commit()
    return {"ok": True, "tenant_id": tid, "marker_hash": mhash[:16]}


def bind_session_tenant(memory: Any, *, session_id: str, tenant_id: str) -> dict[str, Any]:
    """Привязывает сессию агента к рабочему контексту `tenant_id` (и фиксирует смену контекста)."""
    import json

    ensure_isolation_tables(memory)
    sid = str(session_id or "default").strip()[:96]
    tid = re.sub(r"[^a-zA-Z0-9_.:-]", "_", str(tenant_id or "").strip())[:64]
    if not tid:
        raise ValueError("tenant_id is required")

    with memory.store._lock:
        row = memory.store.one(
            "SELECT active_tenant, touched_tenants_json FROM shield_session_tenant WHERE user_id = ? AND session_id = ?",
            (memory.user_id, sid),
        )
        touched = json.loads(row["touched_tenants_json"]) if row else []
        cross_switch = bool(row and row["active_tenant"] != tid)
        if tid not in touched:
            touched.append(tid)
        memory.store.conn.execute(
            """INSERT INTO shield_session_tenant (user_id, session_id, active_tenant, touched_tenants_json, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(user_id, session_id) DO UPDATE SET
                   active_tenant=excluded.active_tenant,
                   touched_tenants_json=excluded.touched_tenants_json,
                   updated_at=excluded.updated_at""",
            (memory.user_id, sid, tid, json.dumps(touched), _utc_iso()),
        )
        memory.store.conn.commit()
    return {
        "ok": True,
        "session_id": sid,
        "active_tenant": tid,
        "cross_tenant_switch": cross_switch,
        "touched_tenants": touched,
    }


def check_cross_tenant_leak(
    memory: Any,
    *,
    session_id: str,
    target_tenant: str,
    payload: str,
    agent_id: str = "agent",
) -> dict[str, Any]:
    """Проверяет, не содержит ли текст/запрос для `target_tenant` конфиденциальные маркеры ДРУГОГО проекта."""
    ensure_isolation_tables(memory)
    tid = re.sub(r"[^a-zA-Z0-9_.:-]", "_", str(target_tenant or "").strip())[:64]
    low_payload = str(payload or "").lower()
    rows = memory.store.query(
        "SELECT tenant_id, marker_text FROM shield_tenant_markers WHERE user_id = ? AND tenant_id != ?",
        (memory.user_id, tid),
    )
    leaks: list[dict[str, str]] = []
    for r in rows:
        mk = str(r["marker_text"] or "")
        if mk and mk.lower() in low_payload:
            leaks.append({
                "source_tenant": str(r["tenant_id"]),
                "target_tenant": tid,
                "marker_preview": mk[:6] + "…",
            })

    blocked = bool(leaks)
    if blocked:
        try:
            audit_chain.append_audit(
                memory,
                "cross_tenant_leak_blocked",
                {"session_id": session_id, "target_tenant": tid, "leaks": leaks[:5]},
                agent_id=agent_id,
            )
        except Exception:
            pass

    return {
        "ok": True,
        "allowed": not blocked,
        "blocked": blocked,
        "target_tenant": tid,
        "leaks": leaks,
    }
