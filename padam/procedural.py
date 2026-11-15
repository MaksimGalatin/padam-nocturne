"""Процедурная память (навыки / Skills) с версионированием и карантином.

Позволяет хранить многошаговые процедуры (kind='procedure'), версионировать
их при обновлении, извлекать черновики из повторяющихся траекторий без LLM ($0)
и экспортировать одобренные владельцем навыки в SKILL.md или CLAUDE.md.

По умолчанию выключено (PADAM_PROCEDURAL_MEMORY=0).
Запись процедуры от агента (owner_approved=False) всегда уходит в карантин.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from . import config
from .memory import Memory


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9а-яА-ЯёЁ_-]+", "-", (name or "").strip().lower()).strip("-")
    return s or "unnamed-skill"


def _ensure_proc_table(mem: Memory) -> None:
    mem.store.execute(
        """CREATE TABLE IF NOT EXISTS procedure_meta (
               memory_id TEXT PRIMARY KEY,
               skill_name TEXT NOT NULL,
               version INTEGER NOT NULL,
               updated_at TEXT NOT NULL
           )"""
    )


def save_procedure(
    mem: Memory,
    *,
    name: str,
    steps: str | list[str],
    scope: str = "global",
    agent_id: str | None = None,
    owner_approved: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    if not force and not config.mcp_procedural_memory_enabled():
        return {"enabled": False, "id": None, "status": "disabled", "version": 0}

    _ensure_proc_table(mem)
    clean_name = (name or "").strip()
    if not clean_name:
        raise ValueError("procedure name must be non-empty")
    if isinstance(steps, (list, tuple)):
        steps_text = "\n".join(f"{i + 1}. {str(s).strip()}" for i, s in enumerate(steps) if str(s).strip())
    else:
        steps_text = str(steps or "").strip()
    if not steps_text:
        raise ValueError("procedure steps must be non-empty")

    body = f"[Skill: {clean_name}]\n{steps_text}"
    prev = mem.store.one(
        """SELECT pm.memory_id, pm.version, m.status
           FROM procedure_meta pm
           JOIN memory m ON m.id = pm.memory_id
           WHERE pm.skill_name = ? AND m.user_id = ? AND m.scope = ?
           ORDER BY pm.version DESC LIMIT 1""",
        (clean_name, mem.user_id, scope),
    )
    next_ver = (int(prev["version"]) + 1) if prev is not None else 1

    status_lbl, rec_id = mem.remember(
        body,
        kind="procedure",
        scope=scope,
        origin="user" if owner_approved else "agent",
        guarded=not owner_approved,
        agent_id=agent_id or ("owner" if owner_approved else "agent"),
    )
    # Гарантируем, что kind='procedure' сохранён в БД даже если force=True при выключенном env
    mem.store.execute("UPDATE memory SET kind = 'procedure' WHERE id = ?", (rec_id,))
    if not owner_approved:
        mem.store.execute(
            "UPDATE memory SET status = 'quarantined', quarantine_reason = 'procedure requires owner approval' WHERE id = ?",
            (rec_id,),
        )
        status_lbl = "quarantined"
    else:
        status_lbl = "active"

    mem.store.execute(
        "INSERT OR REPLACE INTO procedure_meta (memory_id, skill_name, version, updated_at) VALUES (?, ?, ?, ?)",
        (rec_id, clean_name, next_ver, _utc_now()),
    )

    if owner_approved and prev is not None and prev["memory_id"] != rec_id:
        mem.store.atomic([
            ("UPDATE memory SET status = 'superseded', superseded_by = ? WHERE id = ?", (rec_id, prev["memory_id"])),
            ("INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at) VALUES (?, ?, 'correction', ?)",
             (prev["memory_id"], rec_id, _utc_now())),
        ])

    return {
        "enabled": True,
        "id": rec_id,
        "name": clean_name,
        "slug": _slug(clean_name),
        "version": next_ver,
        "status": status_lbl,
        "scope": scope,
    }


def approve_procedure(mem: Memory, memory_id: str) -> dict[str, Any]:
    _ensure_proc_table(mem)
    row = mem.store.one(
        "SELECT id, scope, status FROM memory WHERE id = ? AND user_id = ? AND kind = 'procedure'",
        (memory_id, mem.user_id),
    )
    if row is None:
        raise KeyError(f"Procedure not found: {memory_id}")
    meta = mem.store.one("SELECT skill_name, version FROM procedure_meta WHERE memory_id = ?", (memory_id,))
    mem.store.execute("UPDATE memory SET status = 'active', quarantine_reason = NULL WHERE id = ?", (memory_id,))
    if meta is not None:
        mem.store.execute(
            """UPDATE memory SET status = 'superseded', superseded_by = ?
               WHERE id IN (
                   SELECT pm.memory_id FROM procedure_meta pm
                   JOIN memory m ON m.id = pm.memory_id
                   WHERE pm.skill_name = ? AND m.user_id = ? AND m.scope = ? AND pm.memory_id != ? AND m.status = 'active'
               )""",
            (memory_id, meta["skill_name"], mem.user_id, row["scope"], memory_id),
        )
    return {"id": memory_id, "status": "active", "version": int(meta["version"]) if meta else 1}


def list_procedures(mem: Memory, *, scope: str | None = None, include_quarantined: bool = False) -> list[dict[str, Any]]:
    _ensure_proc_table(mem)
    sql = (
        "SELECT m.id, m.scope, m.content, m.status, m.quarantine_reason, pm.skill_name, pm.version, pm.updated_at "
        "FROM memory m LEFT JOIN procedure_meta pm ON pm.memory_id = m.id "
        "WHERE m.user_id = ? AND m.kind = 'procedure' "
    )
    params: list[Any] = [mem.user_id]
    if not include_quarantined:
        sql += "AND m.status = 'active' "
    else:
        sql += "AND m.status IN ('active', 'quarantined') "
    if scope is not None:
        sql += "AND m.scope = ? "
        params.append(scope)
    sql += "ORDER BY COALESCE(pm.version, 1) DESC, m.created_at DESC"
    return [dict(r) for r in mem.store.query(sql, tuple(params))]


def export_skill_markdown(mem: Memory, *, scope: str | None = None, fmt: str = "skill") -> str:
    procs = list_procedures(mem, scope=scope, include_quarantined=False)
    clean_fmt = (fmt or "skill").strip().lower()
    if clean_fmt == "claude":
        lines = ["# CLAUDE.md — Approved Procedures", ""]
        if not procs:
            lines.append("_No active procedures._")
        for p in procs:
            title = p.get("skill_name") or p["id"][:8]
            ver = p.get("version") or 1
            lines.append(f"## {title} (v{ver}, scope: {p['scope']})")
            lines.append("")
            lines.append(p["content"].strip())
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    # SKILL.md format
    if not procs:
        return "---\nname: padam-skills\ndescription: Approved procedural skills from PADAM memory\n---\n\n_No active procedures._\n"
    first = procs[0]
    skill_slug = _slug(first.get("skill_name") or "padam-skills")
    lines = [
        "---",
        f"name: {skill_slug}",
        f"description: Exported {len(procs)} approved procedural skill(s) from PADAM",
        "---",
        "",
    ]
    for p in procs:
        title = p.get("skill_name") or p["id"][:8]
        ver = p.get("version") or 1
        lines.append(f"## {title} (v{ver})")
        lines.append("")
        lines.append(p["content"].strip())
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def extract_procedure_from_episodes(
    mem: Memory,
    *,
    title: str,
    episode_texts: list[str],
    scope: str = "global",
    agent_id: str = "rem-sleep",
) -> dict[str, Any]:
    """Без LLM ($0) выделяет шаги из траектории эпизодов и помещает черновик в карантин."""
    steps: list[str] = []
    seen_hashes: set[str] = set()
    for txt in episode_texts:
        for line in str(txt).splitlines():
            clean = line.strip(" -*\t")
            if len(clean) < 6:
                continue
            h = hashlib.sha256(clean.lower().encode("utf-8")).hexdigest()[:12]
            if h not in seen_hashes:
                seen_hashes.add(h)
                steps.append(clean)
            if len(steps) >= 8:
                break
        if len(steps) >= 8:
            break
    if not steps:
        steps = [f"Follow verified workflow for {title}"]
    return save_procedure(
        mem,
        name=title,
        steps=steps,
        scope=scope,
        agent_id=agent_id,
        owner_approved=False,
        force=True,
    )
