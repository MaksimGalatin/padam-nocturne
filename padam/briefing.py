"""Брифинг проекта на старте сессии (Project Briefing).

Формирует компактную безопасную сводку для старта сессии агента ($0, локально):
1) ключевые identity / preference / rule;
2) сводки сообществ графа памяти;
3) недавние решения и счётчики карантина / противоречий (без текстов карантина);
4) активные процедуры (skills).

Всё содержимое проходит DLP-очистку, бюджет токенов и оборачивается в safety.fence.
По умолчанию выключено (PADAM_BRIEFING=0).
"""
from __future__ import annotations

from typing import Any

from . import config, safety
from .memory import Memory


def _clean_text(mem: Memory, text: str) -> str:
    cleaned, _ = safety.redact(str(text or ""))
    if config.mcp_dlp_shield_enabled():
        from .dlp_shield import DlpShield
        cleaned, _ = DlpShield(mem).scrub(cleaned)
    return safety.clean(cleaned)


def _table_exists(mem: Memory, name: str) -> bool:
    row = mem.store.one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    )
    return row is not None


def build_project_briefing(
    mem: Memory,
    *,
    scope: str | None = None,
    token_budget: int = 1000,
    force: bool = False,
) -> dict[str, Any]:
    """Собирает структурированный безопасный брифинг проекта."""
    if not force and not config.mcp_briefing_enabled():
        return {
            "enabled": False,
            "scope": scope,
            "sections": {},
            "text": "",
            "fenced_text": "",
        }

    scope_sql = " AND scope = ?" if scope is not None else ""
    base_params: tuple[Any, ...] = (mem.user_id, scope) if scope is not None else (mem.user_id,)

    # 1. Identity / Preference / Rule
    core_rows = mem.store.query(
        "SELECT id, kind, scope, content FROM memory "
        "WHERE user_id = ? AND status = 'active' "
        "AND (quarantine_reason IS NULL OR quarantine_reason = '') "
        "AND kind IN ('identity', 'preference', 'rule')" + scope_sql + " "
        "ORDER BY created_at DESC LIMIT 10",
        base_params,
    )
    core_items = []
    for r in core_rows:
        txt = _clean_text(mem, r["content"])
        if txt:
            core_items.append({"id": r["id"], "kind": r["kind"], "scope": r["scope"], "text": txt})

    # 2. Сообщества графа
    community_items = []
    if _table_exists(mem, "graph_community"):
        comm_rows = mem.store.query(
            "SELECT community_id, scope, size, summary FROM graph_community "
            "WHERE user_id = ?" + scope_sql + " ORDER BY size DESC LIMIT 5",
            base_params,
        )
        for r in comm_rows:
            txt = _clean_text(mem, r["summary"])
            if txt:
                community_items.append({
                    "community_id": r["community_id"],
                    "scope": r["scope"],
                    "size": int(r["size"]),
                    "summary": txt,
                })

    # 3. Недавние решения/факты и открытые счётчики (без текстов карантина)
    dec_rows = mem.store.query(
        "SELECT id, kind, scope, content FROM memory "
        "WHERE user_id = ? AND status = 'active' "
        "AND (quarantine_reason IS NULL OR quarantine_reason = '') "
        "AND kind IN ('decision', 'fact')" + scope_sql + " "
        "ORDER BY created_at DESC LIMIT 6",
        base_params,
    )
    decision_items = []
    for r in dec_rows:
        txt = _clean_text(mem, r["content"])
        if txt:
            decision_items.append({"id": r["id"], "kind": r["kind"], "scope": r["scope"], "text": txt})

    q_row = mem.store.one(
        "SELECT COUNT(*) AS cnt FROM memory WHERE user_id = ? AND status = 'quarantined'" + scope_sql,
        base_params,
    )
    quarantined_count = int(q_row["cnt"]) if q_row else 0

    contradiction_count = 0
    if _table_exists(mem, "memory_link"):
        c_row = mem.store.one(
            "SELECT COUNT(*) AS cnt FROM memory_link ml "
            "JOIN memory m ON m.id = ml.src "
            "WHERE m.user_id = ? AND ml.relation = 'contradiction'" + (" AND m.scope = ?" if scope is not None else ""),
            base_params,
        )
        contradiction_count = int(c_row["cnt"]) if c_row else 0

    # 4. Активные процедуры
    proc_rows = mem.store.query(
        "SELECT id, scope, content FROM memory "
        "WHERE user_id = ? AND status = 'active' "
        "AND (quarantine_reason IS NULL OR quarantine_reason = '') "
        "AND kind = 'procedure'" + scope_sql + " "
        "ORDER BY created_at DESC LIMIT 6",
        base_params,
    )
    procedure_items = []
    for r in proc_rows:
        txt = _clean_text(mem, r["content"])
        if txt:
            procedure_items.append({"id": r["id"], "scope": r["scope"], "text": txt})

    # Сборка с учётом бюджета токенов
    max_chars = max(160, int(token_budget) * 4)
    lines: list[str] = [f"# PADAM Project Briefing (scope={scope or 'all'})"]
    lines.append(f"Counters: quarantined={quarantined_count}, contradictions={contradiction_count}")

    def _append_section(title: str, entries: list[str]) -> None:
        if not entries:
            return
        lines.append(f"## {title}")
        for e in entries:
            lines.append(f"- {e}")

    _append_section(
        "Core (identity/preference/rule)",
        [f"[{x['kind']}|{x['scope']}] {x['text']}" for x in core_items],
    )
    _append_section(
        "Communities",
        [f"[{x['scope']}|n={x['size']}] {x['summary']}" for x in community_items],
    )
    _append_section(
        "Recent decisions & facts",
        [f"[{x['kind']}|{x['scope']}] {x['text']}" for x in decision_items],
    )
    _append_section(
        "Active procedures",
        [f"[{x['scope']}] {x['text']}" for x in procedure_items],
    )

    body = "\n".join(lines)
    if len(body) > max_chars:
        body = body[:max_chars].rstrip() + "..."
    fenced = safety.fence(body) if body else ""

    return {
        "enabled": True,
        "scope": scope,
        "token_budget": int(token_budget),
        "sections": {
            "core": core_items,
            "communities": community_items,
            "decisions": decision_items,
            "procedures": procedure_items,
            "counters": {
                "quarantined": quarantined_count,
                "contradictions": contradiction_count,
            },
        },
        "text": body,
        "fenced_text": fenced,
    }
