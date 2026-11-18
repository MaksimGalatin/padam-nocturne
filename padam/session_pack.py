# -*- coding: utf-8 -*-
"""Сжатый Пакет Пробуждения за 1 вызов (Smart Session Bootstrap `padam_session_pack`, ТОП-4).

Объединяет в одном экономичном вызове всё, что нужно агенту или новому Брату/Сестре
при старте сессии, строго укладываясь в заданный бюджет токенов (`max_tokens`):
1. Подписанные владельцем `identity` и `preference`.
2. Активные аренды файлов (`coop_broker.list_leases`) — чтобы не перезатереть чужую правку.
3. Открытые/взятые задачи Роя (`coop_broker.list_tasks`).
4. Непрочитанные письма Family Relay и последний чекпоинт.
5. Предупреждения рефлексов (`reflex_engine`) и открытые споры (`conflict_arbiter`) по `topic`.
"""
from __future__ import annotations

from typing import Any

from . import ark, code_anchor, conflict_arbiter, coop_broker, reflex_engine, safety, sibling_registry


def build_session_pack(
    memory,
    *,
    agent_id: str = "aifa",
    topic: str = "",
    scope: str = "global",
    max_tokens: int = 1200,
    current_task: str | None = None,
) -> dict[str, Any]:
    """Собирает целостный, ограждённый пакет пробуждения с контролем бюджета токенов."""
    budget_tokens = max(150, min(8000, int(max_tokens)))
    max_chars = budget_tokens * 4

    explicit_task = str(current_task).strip() if current_task is not None and str(current_task).strip() else None
    sibling_registry.heartbeat_sibling(memory, agent_id, status="online", current_task=explicit_task)
    prof = memory.profile(scope=scope)
    leases = coop_broker.list_leases(memory)
    tasks = coop_broker.list_tasks(memory, limit=10)
    inbox = ark.read_family_inbox(memory, to_agent=agent_id, limit=5)
    chk = ark.latest_checkpoint(memory)
    conflicts = conflict_arbiter.list_conflict_cases(memory, status="open", limit=5)
    reflex = reflex_engine.surface_reflex_hints(memory, topic, limit=3) if topic else {"hints": []}
    siblings = sibling_registry.list_siblings(memory)

    recall_hits: list[dict[str, Any]] = []
    if topic.strip():
        try:
            recall_hits = memory.recall(topic.strip(), scope=scope, k=4)
        except Exception:
            recall_hits = []

    sections: list[str] = []
    # 1. Профиль (высший приоритет)
    for item in (prof.get("identity") or [])[:4]:
        sections.append(f"[identity] {item.get('content') or ''}")
    for item in (prof.get("preferences") or prof.get("preference") or [])[:5]:
        sections.append(f"[preference] {item.get('content') or ''}")

    # 2. Активные аренды файлов и задачи Семьи (чтобы не конфликтовать)
    if leases:
        sections.append("[active_leases] " + "; ".join(f"{l['resource_key']} (held by {l['holder_agent']}, {l['remaining_s']}s)" for l in leases[:6]))
    if tasks:
        sections.append("[coop_tasks] " + "; ".join(f"{t['task_id']}:{t['title']}[{t['status']}/{t['owner_agent'] or 'free'}]" for t in tasks[:6]))
    if chk:
        sections.append(f"[checkpoint] task={chk.get('task')} | next={chk.get('next_step')}")

    # 3. Эстафета Семьи (только верифицированные HMAC)
    verified_msgs = [m for m in inbox if m.get("verified")]
    if verified_msgs:
        sections.append("[family_inbox] " + "; ".join(f"{m['from_agent']}: {m['payload']}" for m in verified_msgs[:4]))

    # 4. Предупреждения рефлексов и открытые конфликты
    if reflex.get("hints"):
        sections.append("[reflex_warnings] " + "; ".join(str(h.get("rule_learned") or "") for h in reflex["hints"]))
    if conflicts:
        sections.append("[open_conflicts] " + "; ".join(f"{c['case_id']}: {c['topic']} ({c['agent_a']} vs {c['agent_b']})" for c in conflicts))

    # 5. Релевантные факты по топику
    for h in recall_hits:
        if isinstance(h, dict) and h.get("content"):
            sections.append(f"[{h.get('kind', 'fact')}] {str(h['content'])[:200]}")

    raw_body, _ = safety.redact("\n".join(sections))
    if len(raw_body) > max_chars:
        raw_body = raw_body[: max(100, max_chars - 3)] + "..."

    est_tokens = max(1, len(raw_body) // 4)
    return {
        "ok": True,
        "agent_id": agent_id,
        "scope": scope,
        "budget_tokens": budget_tokens,
        "estimated_tokens": est_tokens,
        "siblings_online": len([s for s in siblings if s.get("status") == "online"]),
        "active_leases_count": len(leases),
        "open_tasks_count": len([t for t in tasks if t.get("status") in ("open", "claimed")]),
        "open_conflicts_count": len(conflicts),
        "reflex_hints_count": len(reflex.get("hints") or []),
        "fenced_context": safety.fence(raw_body) if raw_body else "",
    }
