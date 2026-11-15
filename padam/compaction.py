"""Иерархическая компакция старых эпизодов (Hierarchical Episode Compaction).

Локально ($0, без облачных LLM) сворачивает старые события (kind='event',
status='active', не карантинные) в плотные обобщённые факты (kind='fact')
со связями `derived` на исходные узлы и переводом исходников в `superseded`
с полной обратимостью по графу.

По умолчанию выключено (PADAM_COMPACTION=0).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from . import config, safety
from .memory import Memory


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _summarize_events_locally(contents: list[str], scope: str) -> str:
    """Формирует компактную локальную сводку пачки событий без LLM ($0)."""
    seen: set[str] = set()
    points: list[str] = []
    for raw in contents:
        cleaned, _ = safety.redact(str(raw or ""))
        line = " ".join(cleaned.strip().splitlines())
        line = line[:160].strip()
        if not line:
            continue
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        points.append(line)
        if len(points) >= 6:
            break
    joined = " ; ".join(points) if points else "compacted episode batch"
    return f"[Compacted {len(contents)} events in {scope}] {joined}"


def compact_events(
    mem: Memory,
    *,
    scope: str | None = None,
    min_age_days: int = 7,
    batch_size: int = 20,
    dry_run: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Сворачивает старые события в обобщённые факты со связями derived."""
    if not force and not config.mcp_compaction_enabled():
        return {
            "enabled": False,
            "compacted_groups": 0,
            "events_superseded": 0,
            "summary_ids": [],
        }

    cutoff = (_utc_now() - timedelta(days=max(0, int(min_age_days)))).isoformat()
    sql = (
        "SELECT id, scope, content, created_at FROM memory "
        "WHERE user_id = ? AND kind = 'event' AND status = 'active' "
        "AND (quarantine_reason IS NULL OR quarantine_reason = '') "
        "AND created_at <= ? "
    )
    params: list[Any] = [mem.user_id, cutoff]
    if scope is not None:
        sql += "AND scope = ? "
        params.append(scope)
    sql += "ORDER BY created_at ASC"

    rows = [dict(r) for r in mem.store.query(sql, tuple(params))]
    by_scope: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_scope[str(r["scope"] or "global")].append(r)

    eff_batch = max(2, int(batch_size))
    summary_ids: list[str] = []
    compacted_groups = 0
    events_superseded = 0
    now_iso = _utc_now().isoformat()

    for sc, items in by_scope.items():
        for i in range(0, len(items), eff_batch):
            chunk = items[i : i + eff_batch]
            if len(chunk) < 2:
                continue
            src_ids = [c["id"] for c in chunk]
            summary_text = _summarize_events_locally([c["content"] for c in chunk], sc)
            compacted_groups += 1
            events_superseded += len(chunk)
            if dry_run:
                continue

            _, sum_id = mem.remember(
                summary_text,
                kind="fact",
                importance=0.6,
                scope=sc,
                origin="user",
                derived_from=src_ids,
            )
            summary_ids.append(sum_id)
            placeholders = ",".join("?" * len(src_ids))
            mem.store.execute(
                f"UPDATE memory SET status = 'superseded', invalidated_at = ?, superseded_by = ? "
                f"WHERE id IN ({placeholders})",
                tuple([now_iso, sum_id, *src_ids]),
            )
            for sid in src_ids:
                mem.store.execute(
                    "INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at) VALUES (?, ?, 'derived', ?)",
                    (sid, sum_id, now_iso),
                )

    return {
        "enabled": True,
        "dry_run": bool(dry_run),
        "scope": scope,
        "min_age_days": int(min_age_days),
        "compacted_groups": compacted_groups,
        "events_superseded": events_superseded,
        "summary_ids": summary_ids,
    }
