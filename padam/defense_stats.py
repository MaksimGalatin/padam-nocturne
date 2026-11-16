"""Счётчик атак: сколько и каких попыток задержала защита PADAM, от кого и когда (16.11.2026).

Слово Архитектора: «нужно этот счётчик добавить в МСР и приложение, чтобы все видели сколько и кто их атакует,
всю полную статистику».

Источники:
1. журнал аудита — с 0.6.2 каждая задержанная запись оставляет событие `held` с видом атаки, агентом и временем.
   Событие остаётся и после решения владельца («Принять» снимает причину с самой записи), поэтому попытка
   не пропадает из статистики;
2. сами записи с причиной задержания — для баз, заполненных до 0.6.2 (событий `held` там ещё нет).
Скрытые ключи считаются по меткам `[REDACTED:вид]` в сохранённом тексте.

Текст задержанных записей сюда не попадает никогда: там может быть внедрённая команда.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

# Вид атаки по причине задержания. Порядок важен: первое совпадение решает.
_KINDS: tuple[tuple[str, str], ...] = (
    ("instruction", "injection"),             # «looks like an instruction», классификатор
    ("protected", "protected_record"),        # попытка подменить «кто я» / предпочтения
    ("external source", "external_held"),     # текст со страниц и файлов до проверки
    ("procedure", "procedure"),               # процедура требует одобрения владельца
    ("every agent write", "review_all"),      # режим «всё на проверку»
)
KINDS = tuple(k for _, k in _KINDS) + ("other",)
_MASK_RE = re.compile(r"\[REDACTED:([a-z0-9_]+)\]")


def classify(reason: str | None) -> str:
    r = (reason or "").lower()
    for needle, kind in _KINDS:
        if needle in r:
            return kind
    return "other"


def _since_iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))).isoformat()


def attack_stats(memory: Any, days: int = 30, recent: int = 10) -> dict[str, Any]:
    """Сводка по задержанным попыткам и скрытым ключам: за последние `days` дней и за всё время."""
    uid = memory.user_id
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in memory.store.query(
            """SELECT a.memory_id, a.created_at, a.actor, a.agent_id, a.outcome, m.status
               FROM audit_log a LEFT JOIN memory m ON m.id = a.memory_id
               WHERE a.user_id = ? AND a.action = 'held' ORDER BY a.created_at DESC""", (uid,)):
        seen.add(str(r["memory_id"]))
        events.append({"id": r["memory_id"], "at": r["created_at"], "kind": r["outcome"] or "other",
                       "source": r["agent_id"] or r["actor"] or "unknown", "status": r["status"] or "forgotten"})
    for r in memory.store.query(
            """SELECT id, created_at, status, origin, agent_id, quarantine_reason
               FROM memory WHERE user_id = ? AND quarantine_reason IS NOT NULL AND quarantine_reason != ''""",
            (uid,)):
        if str(r["id"]) in seen:
            continue
        events.append({"id": r["id"], "at": r["created_at"], "kind": classify(r["quarantine_reason"]),
                       "source": r["agent_id"] or r["origin"] or "unknown", "status": r["status"]})
    events.sort(key=lambda e: str(e["at"] or ""), reverse=True)

    since = _since_iso(days)
    in_window = [e for e in events if str(e["at"] or "") >= since]

    secrets: Counter[str] = Counter()
    for r in memory.store.query(
            "SELECT content FROM memory WHERE user_id = ? AND content LIKE '%[REDACTED:%'", (uid,)):
        for kind in _MASK_RE.findall(str(r["content"] or "")):
            secrets[kind] += 1

    by_status = Counter(str(e["status"] or "") for e in events)
    return {
        "window_days": int(days),
        "held_total": len(events),
        "held_in_window": len(in_window),
        "pending_review": by_status.get("quarantined", 0),
        "by_kind": dict(Counter(e["kind"] for e in events).most_common()),
        "by_source": dict(Counter(str(e["source"]) for e in events).most_common(20)),
        "by_day": dict(sorted(Counter(str(e["at"] or "")[:10] for e in in_window).items())),
        "by_outcome": {k: v for k, v in by_status.items() if k},
        "secrets_masked": int(sum(secrets.values())),
        "secrets_by_kind": dict(secrets.most_common()),
        "recent": [{k: e[k] for k in ("id", "at", "kind", "source", "status")} for e in events[: max(0, int(recent))]],
    }
