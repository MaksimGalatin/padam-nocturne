"""Reflect: разделение фактов (world_fact), опыта агента (agent_experience) и мнений (opinion).

Каждая запись получает эпистемическую метку, текущую уверенность (с учётом refute),
и список ID доказательств из memory_link. Весь вывод строго в safety.fence.

По умолчанию выключено (PADAM_REFLECT=0).
"""
from __future__ import annotations

import re
from typing import Any

from . import config, safety
from .memory import Memory

OPINION_RE = re.compile(
    r"\b(возможно|вероятно|похоже|кажется|думаю|мнение|гипотеза|предполож\w*|probably|maybe|perhaps|opinion|hypothesis|i think|seems)\b",
    re.IGNORECASE,
)


def classify_epistemic(
    *,
    kind: str,
    origin: str,
    content: str,
    agent_id: str | None = None,
    confidence: float = 1.0,
) -> str:
    clean_origin = (origin or "user").strip().lower()
    clean_kind = (kind or "fact").strip().lower()
    if clean_origin == "reflection" or OPINION_RE.search(content or "") or float(confidence) < 0.65:
        return "opinion"
    if clean_origin in ("agent", "rem-sleep", "external") or clean_kind in ("procedure", "state") or (
        agent_id and agent_id not in ("owner", "user")
    ):
        return "agent_experience"
    return "world_fact"


def build_reflect_view(
    mem: Memory,
    *,
    query: str = "",
    scope: str | None = None,
    limit: int = 12,
    actor: Any = None,
    force: bool = False,
) -> dict[str, Any]:
    if not force and not config.mcp_reflect_enabled():
        return {"enabled": False, "world_facts": [], "agent_experiences": [], "opinions": [], "fenced": ""}

    if query.strip():
        recs = mem.recall(query.strip(), scope=scope or "global", limit=limit, actor=actor)
        ids = [r.id for r in recs]
        if ids:
            rows = mem.store.query(
                f"SELECT id, kind, scope, content, origin, agent_id, confidence, refuted_count, status "
                f"FROM memory WHERE id IN ({','.join('?' * len(ids))})",
                tuple(ids),
            )
            by_id = {r["id"]: dict(r) for r in rows}
            items = [by_id[i] for i in ids if i in by_id]
        else:
            items = []
    else:
        sql = (
            "SELECT id, kind, scope, content, origin, agent_id, confidence, refuted_count, status "
            "FROM memory WHERE user_id = ? AND status = 'active' "
        )
        params: list[Any] = [mem.user_id]
        if scope is not None:
            sql += "AND scope = ? "
            params.append(scope)
        sql += "ORDER BY confidence DESC, created_at DESC LIMIT ?"
        items = [dict(r) for r in mem.store.query(sql, tuple(params + [limit]))]

    world_facts: list[dict[str, Any]] = []
    agent_experiences: list[dict[str, Any]] = []
    opinions: list[dict[str, Any]] = []
    lines: list[str] = []

    for it in items:
        ev_rows = mem.store.query(
            "SELECT src, dst, relation FROM memory_link WHERE src = ? OR dst = ? LIMIT 10",
            (it["id"], it["id"]),
        )
        evidence_ids = sorted({r["src"] if r["dst"] == it["id"] else r["dst"] for r in ev_rows})
        ep = classify_epistemic(
            kind=it["kind"],
            origin=it.get("origin") or "user",
            content=it.get("content") or "",
            agent_id=it.get("agent_id"),
            confidence=float(it.get("confidence") or 1.0),
        )
        entry = {
            "id": it["id"],
            "kind": it["kind"],
            "scope": it["scope"],
            "epistemic_type": ep,
            "confidence": round(float(it.get("confidence") or 1.0), 4),
            "refuted_count": int(it.get("refuted_count") or 0),
            "evidence_ids": evidence_ids,
            "content": it["content"],
        }
        if ep == "world_fact":
            world_facts.append(entry)
            tag = "WORLD_FACT"
        elif ep == "agent_experience":
            agent_experiences.append(entry)
            tag = "AGENT_EXPERIENCE"
        else:
            opinions.append(entry)
            tag = f"OPINION conf={entry['confidence']:.2f}"
        lines.append(f"[{tag} | ev={len(evidence_ids)}] {it['content']}")

    fenced = safety.fence("\n".join(lines)) if lines else ""
    return {
        "enabled": True,
        "scope": scope,
        "world_facts": world_facts,
        "agent_experiences": agent_experiences,
        "opinions": opinions,
        "fenced": fenced,
    }
