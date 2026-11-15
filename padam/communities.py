"""Сообщества графа памяти со сводками (Label Propagation, $0 локально).

Выделяет плотные кластеры связанных записей алгоритмом Label Propagation
строго внутри одного scope и только среди активных не-карантинных записей,
генерирует локальную сводку и публикует через `padam://communities/{scope}`.

По умолчанию выключено (PADAM_COMMUNITIES=0).
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from . import config, safety
from .memory import Memory

WORD_RE = re.compile(r"[a-zA-Zа-яА-ЯёЁ0-9_]{3,}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_table(mem: Memory) -> None:
    mem.store.execute(
        """CREATE TABLE IF NOT EXISTS graph_community (
               community_id TEXT PRIMARY KEY,
               user_id TEXT NOT NULL,
               scope TEXT NOT NULL,
               size INTEGER NOT NULL,
               keywords_json TEXT NOT NULL,
               member_ids_json TEXT NOT NULL,
               summary TEXT NOT NULL,
               updated_at TEXT NOT NULL
           )"""
    )


def _summarize_cluster(texts: list[str]) -> tuple[list[str], str]:
    freq: Counter[str] = Counter()
    for t in texts:
        for w in WORD_RE.findall(t.lower()):
            freq[w] += 1
    top_kw = [w for w, _ in freq.most_common(5)]
    snippets = [t.strip().splitlines()[0][:120] for t in texts[:3] if t.strip()]
    kw_part = ", ".join(top_kw) if top_kw else "general"
    summary = f"Topics ({kw_part}): " + " | ".join(snippets)
    return top_kw, summary


def detect_communities(
    mem: Memory,
    *,
    scope: str | None = None,
    max_iter: int = 12,
    force: bool = False,
) -> dict[str, Any]:
    """Строит сообщества графа методом Label Propagation и сохраняет сводки."""
    if not force and not config.mcp_communities_enabled():
        return {"enabled": False, "scope": scope, "communities": []}

    _ensure_table(mem)
    sql = (
        "SELECT id, scope, content FROM memory "
        "WHERE user_id = ? AND status = 'active' AND (quarantine_reason IS NULL OR quarantine_reason = '') "
    )
    params: list[Any] = [mem.user_id]
    if scope is not None:
        sql += "AND scope = ? "
        params.append(scope)
    sql += "ORDER BY id ASC"
    nodes = [dict(r) for r in mem.store.query(sql, tuple(params))]
    if not nodes:
        return {"enabled": True, "scope": scope, "communities": []}

    node_by_id = {n["id"]: n for n in nodes}
    node_ids = list(node_by_id.keys())
    node_set = set(node_ids)

    adj: dict[str, list[str]] = defaultdict(list)
    links = mem.store.query("SELECT src, dst FROM memory_link")
    for lr in links:
        s, d = lr["src"], lr["dst"]
        if s in node_set and d in node_set and s != d:
            # Никогда не связываем разные scope в одно сообщество
            if node_by_id[s]["scope"] == node_by_id[d]["scope"]:
                adj[s].append(d)
                adj[d].append(s)

    labels = {nid: nid for nid in node_ids}
    for _ in range(max_iter):
        changed = False
        for nid in node_ids:
            nbrs = adj.get(nid)
            if not nbrs:
                continue
            counts = Counter(labels[nb] for nb in nbrs)
            best_label = min(counts.keys(), key=lambda lb: (-counts[lb], lb))
            if labels[nid] != best_label:
                labels[nid] = best_label
                changed = True
        if not changed:
            break

    groups: dict[str, list[str]] = defaultdict(list)
    for nid in node_ids:
        groups[labels[nid]].append(nid)

    now = _utc_now()
    if scope is not None:
        mem.store.execute("DELETE FROM graph_community WHERE user_id = ? AND scope = ?", (mem.user_id, scope))
    else:
        mem.store.execute("DELETE FROM graph_community WHERE user_id = ?", (mem.user_id,))

    communities: list[dict[str, Any]] = []
    for root_lbl, members in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        sc = node_by_id[members[0]]["scope"]
        texts = [node_by_id[mid]["content"] or "" for mid in members]
        kws, raw_summary = _summarize_cluster(texts)
        fenced_summary = safety.fence(raw_summary)
        cid = f"comm:{sc}:{root_lbl[:12]}"
        mem.store.execute(
            """INSERT OR REPLACE INTO graph_community
               (community_id, user_id, scope, size, keywords_json, member_ids_json, summary, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (cid, mem.user_id, sc, len(members), json.dumps(kws, ensure_ascii=False), json.dumps(members), raw_summary, now),
        )
        communities.append({
            "community_id": cid,
            "scope": sc,
            "size": len(members),
            "keywords": kws,
            "member_ids": members,
            "summary": fenced_summary,
            "updated_at": now,
        })

    return {"enabled": True, "scope": scope, "count": len(communities), "communities": communities}


def get_communities(mem: Memory, *, scope: str | None = None, refresh: bool = True, force: bool = False) -> dict[str, Any]:
    if not force and not config.mcp_communities_enabled():
        return {"enabled": False, "scope": scope, "communities": []}
    if refresh:
        return detect_communities(mem, scope=scope, force=force)
    _ensure_table(mem)
    sql = "SELECT community_id, scope, size, keywords_json, member_ids_json, summary, updated_at FROM graph_community WHERE user_id = ? "
    params: list[Any] = [mem.user_id]
    if scope is not None:
        sql += "AND scope = ? "
        params.append(scope)
    sql += "ORDER BY size DESC, community_id ASC"
    rows = mem.store.query(sql, tuple(params))
    out = [
        {
            "community_id": r["community_id"],
            "scope": r["scope"],
            "size": int(r["size"]),
            "keywords": json.loads(r["keywords_json"]),
            "member_ids": json.loads(r["member_ids_json"]),
            "summary": safety.fence(r["summary"]),
            "updated_at": r["updated_at"],
        }
        for r in rows
    ]
    return {"enabled": True, "scope": scope, "count": len(out), "communities": out}
