# -*- coding: utf-8 -*-
"""Книга рефлексов Ковчега («Грабли -> Подсказка до ошибки», пункт 8).

Превращает записанные владельцем и агентами уроки из `ark_lesson` в предупреждающие
подсказки перед действием. Только подсказывает и никогда ничего не блокирует сама.
"""
from __future__ import annotations

import re
from typing import Any

from . import ark

_STOP = frozenset({"the", "and", "for", "with", "that", "this", "from", "как", "для", "или", "что", "это", "при", "без", "под"})


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-zа-яё0-9_./:-]{3,}", (text or "").lower()) if t not in _STOP}


def surface_reflex_hints(
    memory,
    planned_action: str,
    *,
    limit: int = 3,
    min_overlap: int = 1,
) -> dict[str, Any]:
    """Ищет среди сохранённых уроков (`ark_lesson`) релевантные грабли и возвращает подсказки-рефлексы."""
    action_toks = _tokens(planned_action)
    lessons = ark.list_lessons(memory, limit=100)
    matches: list[dict[str, Any]] = []

    for lsn in lessons:
        corpus = " ".join([
            str(lsn.get("what_happened") or ""),
            str(lsn.get("why_failed") or ""),
            str(lsn.get("rule_learned") or ""),
            str(lsn.get("tags") or ""),
        ])
        lsn_toks = _tokens(corpus)
        shared = sorted(action_toks & lsn_toks)
        if len(shared) >= min_overlap:
            matches.append({
                "lesson_id": lsn.get("id"),
                "score": len(shared),
                "matched_terms": shared[:6],
                "what_happened": lsn.get("what_happened"),
                "why_failed": lsn.get("why_failed"),
                "rule_learned": lsn.get("rule_learned"),
            })

    matches.sort(key=lambda x: (-int(x["score"]), str(x["lesson_id"])))
    top = matches[: max(1, min(10, int(limit)))]
    return {
        "ok": True,
        "advisory_only": True,
        "hints_count": len(top),
        "hints": top,
    }
