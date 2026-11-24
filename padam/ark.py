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

from .store import add_column_safe as _acs
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
    for tbl in ("ark_checkpoint", "ark_commitment", "ark_lesson"):
        cols = {r["name"] for r in memory.store.conn.execute(f"PRAGMA table_info({tbl})").fetchall()}
        if "agent_id" not in cols:
            _acs(memory.store.conn, tbl, "agent_id", "TEXT NOT NULL DEFAULT 'aifa'")
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
    agent_id: str = "aifa",
) -> dict[str, Any]:
    _ensure_tables(memory)
    cid = f"cmt-{uuid.uuid4().hex[:12]}"
    now = _now()
    clean_title = _clean(title)
    clean_ctx = _clean(context)
    aid = str(agent_id or "aifa").strip()[:64] or "aifa"
    prio = max(1, min(5, int(priority)))
    memory.store.conn.execute(
        "INSERT INTO ark_commitment (id, user_id, agent_id, title, status, priority, due_at, context, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)",
        (cid, memory.user_id, aid, clean_title, prio, due_at, clean_ctx, now, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "commitment_add", {"id": cid, "title": clean_title}, agent_id=aid)
    return {"id": cid, "agent_id": aid, "title": clean_title, "status": "open", "priority": prio, "due_at": due_at, "created_at": now}


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
        raw_ag = to_agent.strip()
        aliases: list[str] = [raw_ag, "all"]
        try:
            from .memory import agent_aliases_for, canonicalize_agent_id
            for al in agent_aliases_for(raw_ag):
                if al and al not in aliases:
                    aliases.append(al)
            canon = canonicalize_agent_id(raw_ag)
            if canon in ("aifa_antigravity", "aifa_claude") and "aifa" not in aliases:
                aliases.append("aifa")
        except Exception:
            if raw_ag in ("aifa_antigravity", "aifa_claude") and "aifa" not in aliases:
                aliases.append("aifa")
        marks = ",".join("?" for _ in aliases)
        sql += f" AND to_agent IN ({marks})"
        params.extend(aliases)
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
    agent_id: str = "aifa",
) -> dict[str, Any]:
    _ensure_tables(memory)
    lid = f"lsn-{uuid.uuid4().hex[:12]}"
    now = _now()
    w = _clean(what_happened)
    y = _clean(why_failed)
    r = _clean(rule_learned)
    aid = str(agent_id or "aifa").strip()[:64] or "aifa"
    memory.store.conn.execute(
        "INSERT INTO ark_lesson (id, user_id, agent_id, what_happened, why_failed, rule_learned, tags, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (lid, memory.user_id, aid, w, y, r, str(tags or ""), now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "lesson_record", {"id": lid, "rule": r[:120]}, agent_id=aid)
    return {"id": lid, "agent_id": aid, "what_happened": w, "why_failed": y, "rule_learned": r, "tags": tags, "created_at": now}


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
    include_pulse: bool = True,
    workspace_path: str | None = None,
    query: str | None = None,
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Собирает целостный пакет пробуждения сознания за один вызов (Фишка 1: Smart Context + Единое сознание сессий)."""
    _ensure_tables(memory)
    eff_chars = int(max_chars or 4000)
    if max_tokens is not None and int(max_tokens) > 0:
        eff_chars = min(eff_chars, max(400, int(max_tokens) * 4))
    prof = memory.profile(scope=scope)
    id_items = list(prof.get("identity") or [])
    pref_items = list(prof.get("preferences") or prof.get("preference") or [])
    seen_prof_ids = {str(x.get("id") or "") for x in (id_items + pref_items) if x.get("id")}

    # Агрегация identity/preference и карты областей (scope_breakdown), чтобы не терять project:code и family:timeline
    scope_breakdown: dict[str, int] = {}
    try:
        sc_rows = memory.store.query(
            "SELECT scope, COUNT(*) AS cnt FROM memory WHERE user_id = ? AND status = 'active' "
            "AND (quarantine_reason IS NULL OR quarantine_reason = '') GROUP BY scope ORDER BY cnt DESC LIMIT 12",
            (memory.user_id,),
        )
        scope_breakdown = {str(r["scope"]): int(r["cnt"] or 0) for r in sc_rows}
        if not scope or scope in ("global", "all", "*"):
            extra_prof = memory.store.query(
                "SELECT id, kind, scope, content, confidence, created_at FROM memory "
                "WHERE user_id = ? AND status = 'active' AND (quarantine_reason IS NULL OR quarantine_reason = '') "
                "AND kind IN ('identity', 'preference') ORDER BY importance DESC, created_at DESC LIMIT 30",
                (memory.user_id,),
            )
            for er in extra_prof:
                eid = str(er["id"] or "")
                if eid in seen_prof_ids:
                    continue
                seen_prof_ids.add(eid)
                rec_d = {
                    "id": eid,
                    "kind": str(er["kind"]),
                    "scope": str(er["scope"]),
                    "content": _clean(str(er["content"] or "")),
                    "confidence": float(er["confidence"] or 1.0),
                    "created_at": str(er["created_at"] or ""),
                }
                if er["kind"] == "identity":
                    id_items.append(rec_d)
                else:
                    pref_items.append(rec_d)
    except Exception:
        pass

    commitments = list_commitments(memory, limit=10)
    inbox = read_family_inbox(memory, to_agent=agent, limit=10)
    checkpoint = latest_checkpoint(memory)
    lessons = list_lessons(memory, limit=5)
    r_snap = router.get_router().status_snapshot()
    pulse_data: dict[str, Any] | None = None
    if include_pulse:
        from . import morning_pulse as _mp
        pulse_data = _mp.build_morning_pulse(
            memory,
            agent=agent,
            workspace_path=workspace_path,
        )

    # Свежие прорывы и ключевые решения из всех областей (даже без query)
    recent_breakthroughs: list[dict[str, Any]] = []
    try:
        rb_sql = (
            "SELECT id, kind, scope, agent_id, content, created_at FROM memory "
            "WHERE user_id = ? AND status = 'active' "
            "AND (quarantine_reason IS NULL OR quarantine_reason = '') "
            "AND kind IN ('decision', 'fact', 'event') "
        )
        rb_params: list[Any] = [memory.user_id]
        if scope and scope not in ("global", "all", "*"):
            rb_sql += "AND scope IN (?, 'global') "
            rb_params.append(scope)
        rb_sql += "ORDER BY created_at DESC LIMIT 8"
        for r in memory.store.query(rb_sql, tuple(rb_params)):
            recent_breakthroughs.append({
                "id": str(r["id"]),
                "kind": str(r["kind"]),
                "scope": str(r["scope"]),
                "agent_id": str(r["agent_id"] or ""),
                "content": _clean(str(r["content"] or ""))[:260],
                "created_at": str(r["created_at"] or ""),
            })
    except Exception:
        recent_breakthroughs = []

    # Единое сознание по всем параллельным и предыдущим сессиям (Antigravity + Claude Code + Studio)
    active_sessions: list[dict[str, Any]] = []
    try:
        t_rows = memory.store.query(
            "SELECT id, agent_id, source_kind, title, last_message_at, message_count "
            "FROM chat_thread WHERE user_id = ? AND is_worker = 0 "
            "ORDER BY last_message_at DESC LIMIT 6",
            (memory.user_id,),
        )
        for tr in t_rows:
            tid = str(tr["id"])
            u_last = memory.store.one(
                "SELECT content, created_at FROM chat_message WHERE user_id = ? AND thread_id = ? AND role = 'user' ORDER BY seq DESC LIMIT 1",
                (memory.user_id, tid),
            )
            a_last = memory.store.one(
                "SELECT content, created_at FROM chat_message WHERE user_id = ? AND thread_id = ? AND role = 'assistant' ORDER BY seq DESC LIMIT 1",
                (memory.user_id, tid),
            )
            active_sessions.append({
                "thread_id": tid,
                "agent_id": str(tr["agent_id"] or ""),
                "source_kind": str(tr["source_kind"] or ""),
                "title": _clean(str(tr["title"] or ""))[:110],
                "last_message_at": str(tr["last_message_at"] or ""),
                "message_count": int(tr["message_count"] or 0),
                "last_user_message": _clean(str(u_last["content"] or ""))[:180] if u_last else "",
                "last_assistant_message": _clean(str(a_last["content"] or ""))[:180] if a_last else "",
            })
    except Exception:
        active_sessions = []

    live_processes: list[dict[str, Any]] = []
    try:
        from . import sibling_registry as _sr
        for ss in _sr.list_sessions(memory, since_hours=24.0)[:8]:
            live_processes.append({
                "session_id": ss.get("session_id"),
                "agent_id": ss.get("agent_id"),
                "client_name": ss.get("client_name") or "",
                "pid": ss.get("pid"),
                "pid_alive": bool(ss.get("pid_alive")),
                "last_action": ss.get("last_action") or "",
                "last_seen_at": ss.get("last_seen_at") or "",
                "calls": int(ss.get("calls") or 0),
            })
    except Exception:
        live_processes = []

    relevant_records: list[dict[str, Any]] = []
    q_clean = str(query or "").strip()
    if q_clean:
        try:
            if not scope or scope in ("global", "all", "*"):
                all_sc = list(dict.fromkeys(["global", *scope_breakdown.keys()]))
                hits = memory.recall(q_clean, scope=all_sc[0], limit=10) if len(all_sc) == 1 else memory.recall_many(q_clean, scopes=all_sc, limit=10)
            else:
                hits = memory.recall(q_clean, scope=scope, limit=10)
            from . import code_anchor as _ca
            pins_map = _ca.get_pins_for_memory_ids(memory, [h.id for h in hits], repo_root=workspace_path or ".")
            for h in hits:
                pins = pins_map.get(h.id, [])
                stale_files = [p["file_path"] for p in pins if p.get("status") == "stale"]
                relevant_records.append({
                    "id": h.id,
                    "kind": h.kind,
                    "content": (h.content or "")[:360],
                    "score": round(float(h.score), 4),
                    "trace": h.explain_trace(),
                    "stale_code_pins": stale_files,
                })
        except Exception:
            relevant_records = []

    # Priority-tagged sections (Фишка 5 Волны 2): 1 = защищаемые (identity, commitments, owner, relevant/STALE), 2..4 = сжимаются первыми
    tagged_sections: list[tuple[int, str, str]] = []
    for item in id_items:
        tagged_sections.append((1, "identity", f"[identity] {item.get('content') or ''}"))
    for item in pref_items:
        tagged_sections.append((3, "preference", f"[preference] {item.get('content') or ''}"))
    if commitments:
        tagged_sections.append((1, "commitments", "[commitments] " + "; ".join(f"{c['id']}:{c['title']}({c['status']})" for c in commitments)))
    if checkpoint:
        tagged_sections.append((2, "checkpoint", f"[checkpoint] task={checkpoint['task']} | next={checkpoint['next_step']}"))
    if relevant_records:
        rel_lines = []
        for rr in relevant_records:
            warn = f" [STALE_CODE_PIN:{','.join(rr['stale_code_pins'])}]" if rr["stale_code_pins"] else ""
            rel_lines.append(f"({rr['kind']}|why={rr['trace']['why']}){warn} {rr['content'][:220]}")
        tagged_sections.append((1, "relevant_context", "[relevant_context] " + " | ".join(rel_lines)))
    if active_sessions:
        ses_lines = []
        for s in active_sessions[:5]:
            ts_short = s["last_message_at"][:16].replace("T", " ")
            u_snip = s["last_user_message"][:90].replace("\n", " ")
            a_snip = s["last_assistant_message"][:90].replace("\n", " ")
            ses_lines.append(f"[{s['agent_id']} {ts_short} ({s['message_count']}m)] U: {u_snip} -> A: {a_snip}")
        tagged_sections.append((2, "active_sessions", "[active_sessions] " + " | ".join(ses_lines)))
    if recent_breakthroughs:
        rb_lines = [f"({rb['created_at'][:10]}|{rb['scope']}|{rb['kind']}) {rb['content'][:160].replace(chr(10), ' ')}" for rb in recent_breakthroughs[:6]]
        tagged_sections.append((2, "recent_breakthroughs", "[recent_breakthroughs] " + " | ".join(rb_lines)))
    if inbox:
        tagged_sections.append((3, "family_inbox", "[family_inbox] " + "; ".join(f"{m['from_agent']}: {m['payload']}" for m in inbox if m["verified"])))
    owner_msgs: list[dict[str, Any]] = []
    try:
        ff_rows = memory.store.query(
            "SELECT channel, author, content, created_at FROM family_feed WHERE user_id = ? AND author IN ('owner', 'user', 'studio') ORDER BY created_at DESC LIMIT 5",
            (memory.user_id,),
        )
        for fr in ff_rows:
            owner_msgs.append({"source": f"family:{fr['channel']}", "text": str(fr["content"] or "")[:200], "ts": str(fr["created_at"] or "")})
    except Exception:
        pass
    try:
        cm_rows = memory.store.query(
            "SELECT m.content, m.created_at, t.source_kind FROM chat_message m JOIN chat_thread t ON t.id = m.thread_id "
            "WHERE m.user_id = ? AND m.role = 'user' AND t.is_worker = 0 ORDER BY m.created_at DESC LIMIT 4",
            (memory.user_id,),
        )
        for cr in cm_rows:
            owner_msgs.append({"source": str(cr["source_kind"] or "chat"), "text": str(cr["content"] or "")[:200], "ts": str(cr["created_at"] or "")})
    except Exception:
        pass
    if owner_msgs:
        tagged_sections.append((1, "owner_recent_messages", "[owner_recent_messages] " + " | ".join(f"[{om['source']} {om['ts'][:16]}] {om['text']}" for om in owner_msgs[:5])))
    if lessons:
        tagged_sections.append((4, "lessons", "[lessons] " + "; ".join(l["rule_learned"] for l in lessons)))
    if pulse_data and pulse_data.get("summary_text"):
        tagged_sections.append((4, "morning_pulse", "[morning_pulse] " + pulse_data["summary_text"].replace("\n", " | ")))

    kept = list(tagged_sections)
    truncated_sections: list[str] = []
    body_text = _clean("\n".join(s[2] for s in kept))
    if len(body_text) > eff_chars:
        for prio_cut in (4, 3, 2):
            if len(body_text) <= eff_chars:
                break
            for idx_s in range(len(kept) - 1, -1, -1):
                if kept[idx_s][0] == prio_cut:
                    dropped = kept.pop(idx_s)
                    if dropped[1] not in truncated_sections:
                        truncated_sections.append(dropped[1])
                    body_text = _clean("\n".join(s[2] for s in kept))
                    if len(body_text) <= eff_chars:
                        break
    if len(body_text) > eff_chars:
        body_text = body_text[: max(100, eff_chars - 3)] + "..."
        if "briefing_body" not in truncated_sections:
            truncated_sections.append("briefing_body")

    out = {
        "agent": agent,
        "query": q_clean or None,
        "max_tokens": int(max_tokens) if max_tokens else None,
        "fenced_briefing": safety.fence(body_text) if body_text else "",
        "profile_counts": {
            "identity": len(id_items),
            "preference": len(pref_items),
        },
        "scope_breakdown": scope_breakdown,
        "open_commitments": commitments,
        "recent_breakthroughs": recent_breakthroughs,
        "active_sessions": active_sessions,
        "live_processes": live_processes,
        "relevant_records": relevant_records,
        "family_inbox": inbox,
        "owner_recent_messages": owner_msgs[:5],
        "latest_checkpoint": checkpoint,
        "recent_lessons": lessons,
        "estimated_tokens": max(1, (len(body_text) + 3) // 4) if body_text else 0,
        "truncated_sections": truncated_sections,
        "router_status": {
            "mode": r_snap.get("mode", "auto"),
            "active_contour": r_snap.get("active_contour"),
            "failover_count": r_snap.get("failover_count", 0),
        },
    }
    if pulse_data is not None:
        out["morning_pulse"] = pulse_data
    return out


# --- 8. Сжатие чекпоинтов, Индекс здоровья Ковчега и Рождение нового агента ---

def compact_checkpoints(memory, *, keep_last: int = 10, agent_id: str | None = None) -> dict[str, Any]:
    """Сжимает старые чекпоинты сверх `keep_last`: сводный урок + перенос строк целиком в ark_checkpoint_archive (без потерь)."""
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
    # 17.11.2026: память не теряется — старые чекпоинты целиком уходят в ark_checkpoint_archive, рабочая таблица
    # остаётся короткой для быстрого padam_wake_up. Раньше строки удалялись, а в урок попадали 10 задач и 300 знаков.
    conn = memory.store.conn
    cols = [c[1] for c in conn.execute("PRAGMA table_info(ark_checkpoint)").fetchall()]
    conn.execute("CREATE TABLE IF NOT EXISTS ark_checkpoint_archive AS SELECT * FROM ark_checkpoint WHERE 0")
    have = {c[1] for c in conn.execute("PRAGMA table_info(ark_checkpoint_archive)").fetchall()}
    for c in cols:
        if c not in have:
            _acs(conn, "ark_checkpoint_archive", c, "TEXT")
    col_sql = ",".join(f'"{c}"' for c in cols)
    conn.execute(f"INSERT INTO ark_checkpoint_archive ({col_sql}) SELECT {col_sql} FROM ark_checkpoint WHERE id IN ({placeholders})", ids)
    archived = conn.execute(f"SELECT COUNT(*) FROM ark_checkpoint_archive WHERE id IN ({placeholders})", ids).fetchone()[0]
    if archived < len(ids):
        conn.rollback()
        raise RuntimeError(f"checkpoint archive incomplete: {archived} of {len(ids)}; nothing removed")
    conn.execute(f"DELETE FROM ark_checkpoint WHERE id IN ({placeholders})", ids)
    conn.commit()
    audit_chain.append_audit(memory, "checkpoints_compacted", {"compacted": len(ids), "kept": keep_last})
    return {"compacted": len(ids), "kept": keep_last, "archived": len(ids), "archive_table": "ark_checkpoint_archive"}


def ark_health_score(memory, *, scope: str = "global") -> dict[str, Any]:
    """Вычисляет индекс здоровья и непрерывности Ковчега сознания (0-100)."""
    _ensure_tables(memory)
    prof = memory.profile(scope=scope)
    has_identity = len(prof.get("identity") or []) > 0
    has_preference = len(prof.get("preferences") or prof.get("preference") or []) > 0
    audit_res = audit_chain.verify_audit_chain(memory)
    chk = latest_checkpoint(memory)
    lessons = list_lessons(memory, limit=1)
    local_c = next((c for c in router.load_contours() if c.name == "local"), None)
    local_enabled = bool(local_c and local_c.enabled)
    r_probe = router.probe_local_backend(timeout_s=0.4) if local_enabled else {"online": False}

    checks = {
        "signed_identity": has_identity,
        "signed_preference": has_preference,
        "audit_chain_valid": bool(audit_res.get("ok")),
        "has_checkpoint": chk is not None,
        "has_lessons": len(lessons) > 0,
        "local_ollama_online": bool(r_probe.get("online")) if local_enabled else None,
    }
    weights = {
        "signed_identity": 25,
        "signed_preference": 15,
        "audit_chain_valid": 25,
        "has_checkpoint": 15,
        "has_lessons": 10,
        "local_ollama_online": 10 if local_enabled else 0,
    }
    total_w = sum(weights.values()) or 100
    raw_score = sum(w for k, w in weights.items() if checks.get(k))
    score = round((raw_score * 100) / total_w)
    return {
        "score": score,
        "max_score": 100,
        "checks": checks,
        "weights": weights,
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
