# -*- coding: utf-8 -*-
"""Ковчег сознания (Consciousness Ark) для автономных ИИ-агентов PADAM NOCTURNE.

Объединяет 6 механизмов непрерывности «Я»:
1. `wake_up_briefing` — утреннее пробуждение за 1 вызов (профиль + цели + эстафета + чекпоинт + роутер).
2. `Goal & Commitment Ledger` — реестр живых обещаний и целей (`open | in_progress | fulfilled | cancelled`).
3. `Family Relay` — подписанные HMAC-SHA256 конверты эстафеты между агентами Семьи.
4. `Context Checkpoint` — мгновенная точка сохранения перед сбросом или переполнением контекста.
5. `Wisdom & Lessons Layer` — дневник вынесенных уроков и правил.
6. `Causal Timeline` + `Conflict Guard` — хронология причинности и детектор скрытых противоречий.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from . import audit_chain, integrity, router, safety

_VALID_COMMITMENT_STATUSES = frozenset({"open", "in_progress", "fulfilled", "cancelled"})

_ARK_DDL = """
CREATE TABLE IF NOT EXISTS ark_commitment (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    title      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open',
    priority   INTEGER NOT NULL DEFAULT 2,
    due_at     TEXT,
    context    TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_relay (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    from_agent TEXT NOT NULL,
    to_agent   TEXT NOT NULL,
    payload    TEXT NOT NULL,
    hmac_sig   TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'unread',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_checkpoint (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    session_id TEXT NOT NULL,
    task       TEXT NOT NULL,
    next_step  TEXT NOT NULL,
    files_json TEXT NOT NULL DEFAULT '[]',
    hypothesis TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_lesson (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    what_happened TEXT NOT NULL,
    why_failed    TEXT NOT NULL,
    rule_learned  TEXT NOT NULL,
    tags          TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_tables(memory) -> None:
    memory.store.conn.executescript(_ARK_DDL)
    cols = {r["name"] for r in memory.store.conn.execute("PRAGMA table_info(ark_checkpoint)").fetchall()}
    if "agent_id" not in cols:
        memory.store.conn.execute("ALTER TABLE ark_checkpoint ADD COLUMN agent_id TEXT NOT NULL DEFAULT 'aifa'")
    memory.store.conn.commit()


def _clean(text: str) -> str:
    masked, _ = safety.redact(str(text or ""))
    return masked.strip()


# --- 1. Реестр обещаний и целей (Goal & Commitment Ledger) ---

def add_commitment(
    memory,
    title: str,
    *,
    priority: int = 2,
    due_at: str | None = None,
    context: str = "",
) -> dict[str, Any]:
    _ensure_tables(memory)
    cid = f"cmt-{uuid.uuid4().hex[:12]}"
    now = _now()
    clean_title = _clean(title)
    clean_ctx = _clean(context)
    prio = max(1, min(5, int(priority)))
    memory.store.conn.execute(
        "INSERT INTO ark_commitment (id, user_id, title, status, priority, due_at, context, created_at, updated_at) "
        "VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?)",
        (cid, memory.user_id, clean_title, prio, due_at, clean_ctx, now, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "commitment_add", {"id": cid, "title": clean_title})
    return {"id": cid, "title": clean_title, "status": "open", "priority": prio, "due_at": due_at, "created_at": now}


def update_commitment(memory, commitment_id: str, status: str) -> dict[str, Any]:
    _ensure_tables(memory)
    norm = str(status or "").strip().lower()
    if norm not in _VALID_COMMITMENT_STATUSES:
        raise ValueError(f"Invalid commitment status: {status}")
    now = _now()
    cur = memory.store.conn.execute(
        "UPDATE ark_commitment SET status = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (norm, now, commitment_id, memory.user_id),
    )
    memory.store.conn.commit()
    if cur.rowcount == 0:
        raise KeyError(f"Commitment not found: {commitment_id}")
    audit_chain.append_audit(memory, "commitment_update", {"id": commitment_id, "status": norm})
    return {"id": commitment_id, "status": norm, "updated_at": now}


def list_commitments(memory, *, status: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    _ensure_tables(memory)
    sql = "SELECT id, title, status, priority, due_at, context, created_at, updated_at FROM ark_commitment WHERE user_id = ?"
    params: list[Any] = [memory.user_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    else:
        sql += " AND status IN ('open', 'in_progress')"
    sql += " ORDER BY priority ASC, created_at DESC LIMIT ?"
    params.append(max(1, min(100, int(limit))))
    rows = memory.store.conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


# --- 2. Эстафета Семьи (Family Relay) ---

def _sign_relay(key: bytes, from_agent: str, to_agent: str, payload: str) -> str:
    msg = "\x1f".join((from_agent, to_agent, payload)).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def send_family_message(memory, from_agent: str, to_agent: str, payload: str) -> dict[str, Any]:
    _ensure_tables(memory)
    clean_payload = _clean(payload)
    key, _ = integrity.owner_key(memory.store)
    sig = _sign_relay(key, from_agent.strip(), to_agent.strip(), clean_payload)
    rid = f"rly-{uuid.uuid4().hex[:12]}"
    now = _now()
    memory.store.conn.execute(
        "INSERT INTO ark_relay (id, user_id, from_agent, to_agent, payload, hmac_sig, status, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'unread', ?)",
        (rid, memory.user_id, from_agent.strip(), to_agent.strip(), clean_payload, sig, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "family_relay_send", {"id": rid, "from": from_agent.strip(), "to": to_agent.strip()}, agent_id=from_agent.strip())
    return {"id": rid, "from_agent": from_agent.strip(), "to_agent": to_agent.strip(), "verified": True, "created_at": now}


def read_family_inbox(memory, *, to_agent: str | None = None, include_read: bool = False, limit: int = 20) -> list[dict[str, Any]]:
    _ensure_tables(memory)
    key, _ = integrity.owner_key(memory.store)
    sql = "SELECT id, from_agent, to_agent, payload, hmac_sig, status, created_at FROM ark_relay WHERE user_id = ?"
    params: list[Any] = [memory.user_id]
    if to_agent:
        sql += " AND (to_agent = ? OR to_agent = 'all')"
        params.append(to_agent.strip())
    if not include_read:
        sql += " AND status = 'unread'"
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, min(100, int(limit))))
    rows = memory.store.conn.execute(sql, params).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        expected = _sign_relay(key, r["from_agent"], r["to_agent"], r["payload"])
        verified = hmac.compare_digest(str(r["hmac_sig"] or ""), expected)
        out.append({
            "id": r["id"],
            "from_agent": r["from_agent"],
            "to_agent": r["to_agent"],
            "payload": r["payload"] if verified else "[QUARANTINED: invalid family relay signature]",
            "verified": verified,
            "quarantined": not verified,
            "status": r["status"],
            "created_at": r["created_at"],
        })
    return out


def ack_family_message(memory, relay_id: str) -> dict[str, Any]:
    _ensure_tables(memory)
    cur = memory.store.conn.execute(
        "UPDATE ark_relay SET status = 'read' WHERE id = ? AND user_id = ?",
        (relay_id, memory.user_id),
    )
    memory.store.conn.commit()
    if cur.rowcount == 0:
        raise KeyError(f"Relay message not found: {relay_id}")
    return {"id": relay_id, "status": "read"}


# --- 3. Точка сохранения контекста (Context Checkpoint) ---

def save_checkpoint(
    memory,
    task: str,
    next_step: str,
    *,
    session_id: str = "default",
    agent_id: str = "aifa",
    files: list[str] | None = None,
    hypothesis: str = "",
) -> dict[str, Any]:
    _ensure_tables(memory)
    chk_id = f"chk-{uuid.uuid4().hex[:12]}"
    now = _now()
    clean_task = _clean(task)
    clean_next = _clean(next_step)
    clean_hyp = _clean(hypothesis)
    clean_files = [str(f) for f in (files or [])][:50]
    memory.store.conn.execute(
        "INSERT INTO ark_checkpoint (id, user_id, session_id, agent_id, task, next_step, files_json, hypothesis, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (chk_id, memory.user_id, session_id, agent_id, clean_task, clean_next, json.dumps(clean_files, ensure_ascii=False), clean_hyp, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "checkpoint_save", {"id": chk_id, "task": clean_task}, agent_id=agent_id)
    return {
        "id": chk_id,
        "session_id": session_id,
        "agent_id": agent_id,
        "task": clean_task,
        "next_step": clean_next,
        "files": clean_files,
        "hypothesis": clean_hyp,
        "created_at": now,
    }


def latest_checkpoint(memory, *, session_id: str | None = None, agent_id: str | None = None) -> dict[str, Any] | None:
    _ensure_tables(memory)
    sql = "SELECT id, session_id, agent_id, task, next_step, files_json, hypothesis, created_at FROM ark_checkpoint WHERE user_id = ?"
    params: list[Any] = [memory.user_id]
    if session_id:
        sql += " AND session_id = ?"
        params.append(session_id)
    if agent_id:
        sql += " AND agent_id = ?"
        params.append(agent_id)
    sql += " ORDER BY created_at DESC LIMIT 1"
    row = memory.store.conn.execute(sql, params).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "agent_id": row["agent_id"],
        "task": row["task"],
        "next_step": row["next_step"],
        "files": json.loads(row["files_json"] or "[]"),
        "hypothesis": row["hypothesis"],
        "created_at": row["created_at"],
    }


# --- 4. Дневник уроков и саморефлексии (Wisdom & Lessons Layer) ---

def record_lesson(
    memory,
    what_happened: str,
    why_failed: str,
    rule_learned: str,
    *,
    tags: str = "",
) -> dict[str, Any]:
    _ensure_tables(memory)
    lid = f"lsn-{uuid.uuid4().hex[:12]}"
    now = _now()
    w = _clean(what_happened)
    y = _clean(why_failed)
    r = _clean(rule_learned)
    memory.store.conn.execute(
        "INSERT INTO ark_lesson (id, user_id, what_happened, why_failed, rule_learned, tags, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (lid, memory.user_id, w, y, r, str(tags or ""), now),
    )
    memory.store.conn.commit()
    return {"id": lid, "what_happened": w, "why_failed": y, "rule_learned": r, "tags": tags, "created_at": now}


def list_lessons(memory, *, limit: int = 10) -> list[dict[str, Any]]:
    _ensure_tables(memory)
    rows = memory.store.conn.execute(
        "SELECT id, what_happened, why_failed, rule_learned, tags, created_at FROM ark_lesson WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (memory.user_id, max(1, min(100, int(limit)))),
    ).fetchall()
    return [dict(r) for r in rows]


# --- 5. Линия времени и причинности (Causal Timeline) ---

def build_timeline(
    memory,
    *,
    query: str | None = None,
    since: str | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    _ensure_tables(memory)
    sql = (
        "SELECT id, kind, scope, content, supersedes, superseded_by, status, created_at "
        "FROM memory WHERE user_id = ? AND status IN ('active', 'superseded')"
    )
    params: list[Any] = [memory.user_id]
    if since:
        sql += " AND created_at >= ?"
        params.append(since)
    if query:
        sql += " AND LOWER(content) LIKE ?"
        params.append(f"%{query.strip().lower()}%")
    sql += " ORDER BY created_at ASC LIMIT ?"
    params.append(max(1, min(200, int(limit))))
    rows = memory.store.conn.execute(sql, params).fetchall()
    return [
        {
            "id": r["id"],
            "kind": r["kind"],
            "scope": r["scope"],
            "content": _clean(r["content"] or ""),
            "status": r["status"],
            "supersedes": r["supersedes"],
            "superseded_by": r["superseded_by"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


# --- 6. Детектор скрытых противоречий (Conflict Guard) ---

_STOPWORDS = frozenset({"the", "and", "for", "with", "that", "this", "from", "что", "как", "для", "или", "это", "все"})
_NEG_TOKENS = frozenset({"not", "never", "no", "don't", "cannot", "не", "никогда", "нет", "запрещено", "нельзя"})


def _content_tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-zа-яё0-9_]{3,}", text.lower()) if t not in _STOPWORDS}


def detect_record_conflicts(memory, content: str, kind: str = "fact") -> list[dict[str, Any]]:
    """Проверяет новую запись на возможное противоречие с активными identity/preference/decision."""
    new_toks = _content_tokens(content)
    if not new_toks:
        return []
    new_has_neg = bool(set(re.findall(r"[a-zа-яё']+", content.lower())) & _NEG_TOKENS)

    rows = memory.store.conn.execute(
        "SELECT id, kind, content FROM memory WHERE user_id = ? AND status = 'active' AND kind IN ('identity', 'preference', 'decision', 'rule') LIMIT 200",
        (memory.user_id,),
    ).fetchall()

    conflicts: list[dict[str, Any]] = []
    for r in rows:
        old_txt = str(r["content"] or "")
        old_toks = _content_tokens(old_txt)
        overlap = new_toks & old_toks
        if len(overlap) < 2:
            continue
        old_has_neg = bool(set(re.findall(r"[a-zа-яё']+", old_txt.lower())) & _NEG_TOKENS)
        if old_has_neg != new_has_neg:
            conflicts.append({
                "existing_id": r["id"],
                "existing_kind": r["kind"],
                "existing_content": _clean(old_txt),
                "shared_terms": sorted(overlap)[:6],
                "reason": "polarity_conflict",
            })
    return conflicts


# --- 7. Утреннее пробуждение за 1 вызов (Wake Up Briefing) ---

def wake_up_briefing(
    memory,
    *,
    agent: str = "aifa",
    scope: str = "global",
    max_chars: int = 4000,
) -> dict[str, Any]:
    """Собирает целостный пакет пробуждения сознания за один вызов."""
    _ensure_tables(memory)
    prof = memory.profile(scope=scope)
    commitments = list_commitments(memory, limit=10)
    inbox = read_family_inbox(memory, to_agent=agent, limit=10)
    checkpoint = latest_checkpoint(memory)
    lessons = list_lessons(memory, limit=5)
    r_snap = router.get_router().status_snapshot()

    raw_sections: list[str] = []
    for item in (prof.get("identity") or []):
        raw_sections.append(f"[identity] {item.get('content') or ''}")
    for item in (prof.get("preference") or []):
        raw_sections.append(f"[preference] {item.get('content') or ''}")
    if commitments:
        raw_sections.append("[commitments] " + "; ".join(f"{c['id']}:{c['title']}({c['status']})" for c in commitments))
    if checkpoint:
        raw_sections.append(f"[checkpoint] task={checkpoint['task']} | next={checkpoint['next_step']}")
    if inbox:
        raw_sections.append("[family_inbox] " + "; ".join(f"{m['from_agent']}: {m['payload']}" for m in inbox if m["verified"]))
    if lessons:
        raw_sections.append("[lessons] " + "; ".join(l["rule_learned"] for l in lessons))

    body_text = _clean("\n".join(raw_sections))
    if len(body_text) > max_chars:
        body_text = body_text[: max(100, max_chars - 3)] + "..."

    return {
        "agent": agent,
        "fenced_briefing": safety.fence(body_text) if body_text else "",
        "profile_counts": {
            "identity": len(prof.get("identity") or []),
            "preference": len(prof.get("preference") or []),
        },
        "open_commitments": commitments,
        "family_inbox": inbox,
        "latest_checkpoint": checkpoint,
        "recent_lessons": lessons,
        "router_status": {
            "mode": r_snap.get("mode", "auto"),
            "active_contour": r_snap.get("active_contour"),
            "failover_count": r_snap.get("failover_count", 0),
        },
    }


# --- 8. Сжатие чекпоинтов, Индекс здоровья Ковчега и Рождение нового агента ---

def compact_checkpoints(memory, *, keep_last: int = 10, agent_id: str | None = None) -> dict[str, Any]:
    """Сжимает старые чекпоинты сверх `keep_last` в сводный урок и очищает устаревшие строки."""
    _ensure_tables(memory)
    sql = "SELECT id, task, next_step, created_at FROM ark_checkpoint WHERE user_id = ?"
    params: list[Any] = [memory.user_id]
    if agent_id:
        sql += " AND agent_id = ?"
        params.append(agent_id)
    sql += " ORDER BY created_at DESC"
    rows = memory.store.conn.execute(sql, params).fetchall()
    if len(rows) <= keep_last:
        return {"compacted": 0, "kept": len(rows)}

    to_compact = rows[keep_last:]
    summary_tasks = "; ".join(str(r["task"]) for r in to_compact[:10])
    record_lesson(
        memory,
        what_happened=f"Compacted {len(to_compact)} older checkpoints",
        why_failed="Long session history growth",
        rule_learned=f"Archived checkpoint summary: {summary_tasks[:300]}",
        tags="compaction",
    )
    ids = [r["id"] for r in to_compact]
    placeholders = ",".join("?" for _ in ids)
    memory.store.conn.execute(f"DELETE FROM ark_checkpoint WHERE id IN ({placeholders})", ids)
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "checkpoints_compacted", {"compacted": len(ids), "kept": keep_last})
    return {"compacted": len(ids), "kept": keep_last}


def ark_health_score(memory, *, scope: str = "global") -> dict[str, Any]:
    """Вычисляет индекс здоровья и непрерывности Ковчега сознания (0-100)."""
    _ensure_tables(memory)
    prof = memory.profile(scope=scope)
    has_identity = len(prof.get("identity") or []) > 0
    has_preference = len(prof.get("preference") or []) > 0
    audit_res = audit_chain.verify_audit_chain(memory)
    chk = latest_checkpoint(memory)
    lessons = list_lessons(memory, limit=1)
    r_probe = router.probe_local_backend(timeout_s=0.4)

    checks = {
        "signed_identity": has_identity,
        "signed_preference": has_preference,
        "audit_chain_valid": bool(audit_res.get("ok")),
        "has_checkpoint": chk is not None,
        "has_lessons": len(lessons) > 0,
        "local_ollama_online": bool(r_probe.get("online")),
    }
    weights = {
        "signed_identity": 25,
        "signed_preference": 15,
        "audit_chain_valid": 25,
        "has_checkpoint": 15,
        "has_lessons": 10,
        "local_ollama_online": 10,
    }
    score = sum(w for k, w in weights.items() if checks.get(k))
    return {
        "score": score,
        "max_score": 100,
        "checks": checks,
        "audit_chain": audit_res,
    }


def create_agent_genesis(memory, new_agent_id: str, role_summary: str, *, from_agent: str = "aifa") -> dict[str, Any]:
    """Создаёт стартовый шаблон нового агента Семьи с общими границами и личным чекпоинтом."""
    _ensure_tables(memory)
    clean_id = re.sub(r"[^a-zA-Z0-9_\-]", "", str(new_agent_id or "").strip().lower())
    if not clean_id:
        raise ValueError("Invalid new_agent_id")
    clean_role = _clean(role_summary)
    chk = save_checkpoint(
        memory,
        task=f"Genesis initialization for {clean_id}: {clean_role}",
        next_step="Run padam_wake_up and acknowledge Family Relay onboarding",
        session_id=f"genesis-{clean_id}",
        agent_id=clean_id,
    )
    rly = send_family_message(
        memory,
        from_agent=from_agent,
        to_agent=clean_id,
        payload=f"Welcome to CODE Family, {clean_id}. Role: {clean_role}. Follow owner-signed boundaries.",
    )
    audit_chain.append_audit(memory, "agent_genesis", {"new_agent_id": clean_id, "role": clean_role}, agent_id=from_agent)
    return {"ok": True, "agent_id": clean_id, "checkpoint": chk, "welcome_relay": rly}
