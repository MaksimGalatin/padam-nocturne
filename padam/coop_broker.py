# -*- coding: utf-8 -*-
"""Брокер Аренды Файлов/Ресурсов и Персистентная Доска Задач Роя (ТОП-2, ТОП-9).

Предотвращает одновременную перезапись одного и того же файла несколькими
подключёнными Братьями и Сестрами, а также даёт общую Доску Задач в SQLite
с маршрутизацией уведомлений по топикам (`padam://swarm/topic/{topic}`).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from . import ark, audit_chain, safety

_COOP_DDL = """
CREATE TABLE IF NOT EXISTS ark_resource_lease (
    resource_key TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    holder_agent TEXT NOT NULL,
    purpose      TEXT NOT NULL DEFAULT '',
    acquired_at  REAL NOT NULL,
    expires_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_coop_task (
    task_id        TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    title          TEXT NOT NULL,
    topic          TEXT NOT NULL DEFAULT 'general',
    scope          TEXT NOT NULL DEFAULT 'global',
    status         TEXT NOT NULL DEFAULT 'open',
    owner_agent    TEXT NOT NULL DEFAULT '',
    created_by     TEXT NOT NULL DEFAULT 'aifa',
    artifacts_json TEXT NOT NULL DEFAULT '[]',
    summary        TEXT NOT NULL DEFAULT '',
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_coop_task_topic ON ark_coop_task(user_id, topic, status);
"""

from contextlib import nullcontext

_VALID_TASK_STATUSES = frozenset({"open", "claimed", "review", "done", "blocked"})


def _lock_of(memory):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _ensure(memory) -> None:
    with _lock_of(memory):
        ark._ensure_tables(memory)
        conn = memory.store.conn
        for stmt in _COOP_DDL.split(";"):
            s = stmt.strip()
            if s:
                conn.execute(s)
        conn.commit()


def _canon_resource(raw_key: str) -> str:
    clean = str(raw_key or "").strip().replace("\\", "/")
    if not clean:
        raise ValueError("resource_key must be non-empty")
    return clean[:300]


def _clean_topic(raw: str) -> str:
    t = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", str(raw or "general").strip().lower())[:64]
    return t or "general"


# --- 1. Аренда файлов/ресурсов (Cooperative Leases) ---

def acquire_lease(
    memory,
    agent_id: str,
    resource_key: str,
    *,
    purpose: str = "",
    ttl_s: int = 300,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Атомарно захватывает аренду ресурса (файла/модуля). При занятии другим живым агентом — честный отказ."""
    _ensure(memory)
    res_key = _canon_resource(resource_key)
    holder = re.sub(r"[^a-zA-Z0-9_\-]", "", str(agent_id or "").strip().lower()) or "agent"
    ttl = max(5, min(86400, int(ttl_s)))
    now = float(now_ts if now_ts is not None else time.time())
    conn = memory.store.conn

    # Чистим просроченные аренды
    conn.execute("DELETE FROM ark_resource_lease WHERE expires_at <= ?", (now,))
    existing = conn.execute(
        "SELECT holder_agent, purpose, expires_at FROM ark_resource_lease WHERE resource_key = ? AND user_id = ?",
        (res_key, memory.user_id),
    ).fetchone()

    if existing and existing["holder_agent"] != holder and float(existing["expires_at"]) > now:
        conn.commit()
        return {
            "ok": False,
            "acquired": False,
            "conflict": True,
            "resource_key": res_key,
            "holder_agent": existing["holder_agent"],
            "purpose": existing["purpose"],
            "remaining_s": round(float(existing["expires_at"]) - now, 2),
        }

    clean_purpose, _ = safety.redact(str(purpose or ""))
    exp = now + ttl
    conn.execute(
        "INSERT INTO ark_resource_lease (resource_key, user_id, holder_agent, purpose, acquired_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(resource_key) DO UPDATE SET holder_agent=excluded.holder_agent, purpose=excluded.purpose, "
        "acquired_at=excluded.acquired_at, expires_at=excluded.expires_at",
        (res_key, memory.user_id, holder, clean_purpose[:200], now, exp),
    )
    conn.commit()
    return {
        "ok": True,
        "acquired": True,
        "conflict": False,
        "resource_key": res_key,
        "holder_agent": holder,
        "expires_at": exp,
        "ttl_s": ttl,
    }


def release_lease(memory, agent_id: str, resource_key: str) -> dict[str, Any]:
    """Освобождает аренду (только владелец аренды может её снять)."""
    _ensure(memory)
    res_key = _canon_resource(resource_key)
    holder = re.sub(r"[^a-zA-Z0-9_\-]", "", str(agent_id or "").strip().lower()) or "agent"
    conn = memory.store.conn
    existing = conn.execute(
        "SELECT holder_agent FROM ark_resource_lease WHERE resource_key = ? AND user_id = ?",
        (res_key, memory.user_id),
    ).fetchone()
    if not existing:
        return {"ok": True, "released": False, "reason": "not_held"}
    if existing["holder_agent"] != holder:
        return {"ok": False, "released": False, "reason": "held_by_another_agent", "holder_agent": existing["holder_agent"]}
    conn.execute("DELETE FROM ark_resource_lease WHERE resource_key = ? AND user_id = ?", (res_key, memory.user_id))
    conn.commit()
    return {"ok": True, "released": True, "resource_key": res_key}


def renew_lease(
    memory,
    agent_id: str,
    resource_key: str,
    *,
    ttl_s: int = 300,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Продлевает существующую живую аренду ресурса для её владельца."""
    _ensure(memory)
    res_key = _canon_resource(resource_key)
    holder = re.sub(r"[^a-zA-Z0-9_\-]", "", str(agent_id or "").strip().lower()) or "agent"
    ttl = max(5, min(86400, int(ttl_s)))
    now = float(now_ts if now_ts is not None else time.time())
    conn = memory.store.conn
    conn.execute("DELETE FROM ark_resource_lease WHERE expires_at <= ?", (now,))
    existing = conn.execute(
        "SELECT holder_agent FROM ark_resource_lease WHERE resource_key = ? AND user_id = ?",
        (res_key, memory.user_id),
    ).fetchone()
    if not existing:
        conn.commit()
        return {"ok": False, "renewed": False, "reason": "not_held", "resource_key": res_key}
    if existing["holder_agent"] != holder:
        conn.commit()
        return {"ok": False, "renewed": False, "reason": "held_by_another_agent", "holder_agent": existing["holder_agent"], "resource_key": res_key}
    exp = now + ttl
    conn.execute(
        "UPDATE ark_resource_lease SET expires_at = ? WHERE resource_key = ? AND user_id = ?",
        (exp, res_key, memory.user_id),
    )
    conn.commit()
    return {"ok": True, "renewed": True, "resource_key": res_key, "holder_agent": holder, "expires_at": exp, "ttl_s": ttl}


def release_all_leases(memory, agent_id: str) -> dict[str, Any]:
    """Освобождает все активные аренды указанного агента."""
    _ensure(memory)
    holder = re.sub(r"[^a-zA-Z0-9_\-]", "", str(agent_id or "").strip().lower()) or "agent"
    conn = memory.store.conn
    rows = conn.execute(
        "SELECT resource_key FROM ark_resource_lease WHERE user_id = ? AND holder_agent = ?",
        (memory.user_id, holder),
    ).fetchall()
    keys = [str(r["resource_key"]) for r in rows]
    conn.execute("DELETE FROM ark_resource_lease WHERE user_id = ? AND holder_agent = ?", (memory.user_id, holder))
    conn.commit()
    return {"ok": True, "holder_agent": holder, "released_count": len(keys), "released_keys": keys}


def list_leases(memory, *, now_ts: float | None = None) -> list[dict[str, Any]]:
    _ensure(memory)
    now = float(now_ts if now_ts is not None else time.time())
    conn = memory.store.conn
    conn.execute("DELETE FROM ark_resource_lease WHERE expires_at <= ?", (now,))
    conn.commit()
    rows = conn.execute(
        "SELECT resource_key, holder_agent, purpose, acquired_at, expires_at FROM ark_resource_lease WHERE user_id = ? ORDER BY acquired_at DESC",
        (memory.user_id,),
    ).fetchall()
    return [
        {
            "resource_key": r["resource_key"],
            "holder_agent": r["holder_agent"],
            "purpose": r["purpose"],
            "remaining_s": round(float(r["expires_at"]) - now, 2),
        }
        for r in rows
    ]


# --- 2. Персистентная Доска Задач Роя (Coop Task Board) ---

def create_task(
    memory,
    title: str,
    *,
    topic: str = "general",
    scope: str = "global",
    created_by: str = "aifa",
    owner_agent: str = "",
) -> dict[str, Any]:
    _ensure(memory)
    clean_title, _ = safety.redact(str(title or "").strip())
    if not clean_title:
        raise ValueError("Task title must be non-empty")
    tid = f"tsk-{uuid.uuid4().hex[:10]}"
    top = _clean_topic(topic)
    now = time.time()
    assignee = re.sub(r"[^a-zA-Z0-9_\-]", "", str(owner_agent or "").strip().lower())
    status = "claimed" if assignee else "open"
    memory.store.conn.execute(
        "INSERT INTO ark_coop_task (task_id, user_id, title, topic, scope, status, owner_agent, created_by, artifacts_json, summary, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', '', ?, ?)",
        (tid, memory.user_id, clean_title[:240], top, scope, status, assignee, created_by, now, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "coop_task_created", {"task_id": tid, "topic": top, "title": clean_title[:120]}, agent_id=created_by)
    return {
        "ok": True,
        "task_id": tid,
        "title": clean_title[:240],
        "topic": top,
        "scope": scope,
        "status": status,
        "owner_agent": assignee,
    }


def claim_task(memory, task_id: str, agent_id: str) -> dict[str, Any]:
    _ensure(memory)
    aid = re.sub(r"[^a-zA-Z0-9_\-]", "", str(agent_id or "").strip().lower())
    if not aid:
        raise ValueError("agent_id required to claim task")
    conn = memory.store.conn
    row = conn.execute(
        "SELECT task_id, status, owner_agent, topic FROM ark_coop_task WHERE task_id = ? AND user_id = ?",
        (task_id, memory.user_id),
    ).fetchone()
    if not row:
        raise KeyError(f"Task not found: {task_id}")
    if row["owner_agent"] and row["owner_agent"] != aid and row["status"] in ("claimed", "review"):
        return {"ok": False, "claimed": False, "reason": "already_claimed", "owner_agent": row["owner_agent"], "topic": row["topic"]}
    conn.execute(
        "UPDATE ark_coop_task SET status = 'claimed', owner_agent = ?, updated_at = ? WHERE task_id = ? AND user_id = ?",
        (aid, time.time(), task_id, memory.user_id),
    )
    conn.commit()
    return {"ok": True, "claimed": True, "task_id": task_id, "owner_agent": aid, "status": "claimed", "topic": row["topic"]}


def update_task(
    memory,
    task_id: str,
    *,
    status: str,
    agent_id: str = "aifa",
    summary: str = "",
    artifacts: list[str] | None = None,
) -> dict[str, Any]:
    _ensure(memory)
    st = (status or "").strip().lower()
    if st not in _VALID_TASK_STATUSES:
        raise ValueError(f"Invalid task status {st!r}")
    conn = memory.store.conn
    row = conn.execute(
        "SELECT task_id, topic, artifacts_json FROM ark_coop_task WHERE task_id = ? AND user_id = ?",
        (task_id, memory.user_id),
    ).fetchone()
    if not row:
        raise KeyError(f"Task not found: {task_id}")
    merged_arts = list(json.loads(row["artifacts_json"] or "[]"))
    if artifacts:
        merged_arts.extend(str(a) for a in artifacts)
    clean_sum, _ = safety.redact(str(summary or ""))
    conn.execute(
        "UPDATE ark_coop_task SET status = ?, summary = ?, artifacts_json = ?, updated_at = ? WHERE task_id = ? AND user_id = ?",
        (st, clean_sum[:400], json.dumps(merged_arts[-25:], ensure_ascii=False), time.time(), task_id, memory.user_id),
    )
    conn.commit()
    audit_chain.append_audit(memory, "coop_task_updated", {"task_id": task_id, "status": st, "topic": row["topic"]}, agent_id=agent_id)
    return {"ok": True, "task_id": task_id, "status": st, "topic": row["topic"], "summary": clean_sum[:400]}


def list_tasks(memory, *, topic: str | None = None, status: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
    _ensure(memory)
    sql = "SELECT task_id, title, topic, scope, status, owner_agent, created_by, artifacts_json, summary, updated_at FROM ark_coop_task WHERE user_id = ?"
    params: list[Any] = [memory.user_id]
    if topic:
        sql += " AND topic = ?"
        params.append(_clean_topic(topic))
    if status:
        sql += " AND status = ?"
        params.append(status.strip().lower())
    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(max(1, min(100, int(limit))))
    rows = memory.store.conn.execute(sql, params).fetchall()
    return [
        {
            "task_id": r["task_id"],
            "title": r["title"],
            "topic": r["topic"],
            "scope": r["scope"],
            "status": r["status"],
            "owner_agent": r["owner_agent"],
            "created_by": r["created_by"],
            "artifacts": json.loads(r["artifacts_json"] or "[]"),
            "summary": r["summary"],
        }
        for r in rows
    ]
