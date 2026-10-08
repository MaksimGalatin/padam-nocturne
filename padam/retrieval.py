"""Гибридное извлечение.

Одна стратегия поиска всегда что-то упускает. Векторная не находит точных
совпадений — номер счёта, модель процессора, дату. Лексическая не понимает
переформулировок. Точное совпадение сущностей ловит идентификаторы, но
слепо к смыслу.

Здесь три стратегии работают параллельно, их результаты объединяются
методом обратного ранга (RRF): запись, попавшая в верх нескольких списков,
поднимается выше той, что заняла первое место в одном.
"""

from __future__ import annotations

import re
from collections import defaultdict

import numpy as np

from . import embeddings

# --- сущности: то, что нужно находить точно ---------------------------

_ENTITY_PATTERNS = [
    r"\b[A-Z]{2,}[A-Z0-9\-]*\b",          # GALATIN, GTX, ADA, WCAG
    r"\b[a-z]+\d[\w\-]*\b",                # i7, llama3, nomic-embed
    r"\b\d{4}-\d{2}-\d{2}\b",              # 2026-10-08
    r"\b\d[\d\s.,]*\d\b",                  # 14700, 10 000, 44,919
    r"\b[\w.\-]+@[\w.\-]+\b",              # почта
    r"https?://\S+",                       # ссылки
    r"\b[0-9A-F]{4,}-[0-9A-F\-]+\b",       # идентификаторы вроде 01DAF7-8B0717
]
_ENTITY_RE = re.compile("|".join(_ENTITY_PATTERNS), re.IGNORECASE)


def entities(text: str) -> set[str]:
    """Идентификаторы, которые должны совпадать буквально."""
    found = {m.group(0).strip(" .,").lower() for m in _ENTITY_RE.finditer(text)}
    return {e for e in found if len(e) >= 2}


# --- обратный ранг ----------------------------------------------------

RRF_K = 60          # сглаживание: чем больше, тем меньше вес первых мест


def reciprocal_rank_fusion(rankings: dict[str, list[str]],
                           weights: dict[str, float] | None = None
                           ) -> dict[str, float]:
    """rankings: {имя стратегии: [id по убыванию релевантности]}

    Возвращает {id: суммарный балл}. Формула: сумма по стратегиям от
    weight / (K + позиция). Запись, устойчиво попадающая в верх разных
    списков, обгоняет ту, что лидирует в одном.
    """
    weights = weights or {}
    scores: dict[str, float] = defaultdict(float)
    for strategy, ids in rankings.items():
        w = weights.get(strategy, 1.0)
        for pos, rid in enumerate(ids):
            scores[rid] += w / (RRF_K + pos + 1)
    return dict(scores)


# --- стратегии --------------------------------------------------------

def rank_semantic(query_vec: np.ndarray, rows: list, limit: int) -> list[str]:
    """Векторная близость. Понимает переформулировки, слепа к цифрам."""
    scored = []
    for r in rows:
        v = r["_vec"]
        if v is None:
            continue
        sim = embeddings.cosine(query_vec, v)
        if sim > 0:
            scored.append((sim, r["id"]))
    scored.sort(reverse=True)
    return [rid for _, rid in scored[:limit]]


def rank_lexical(store, user_id: str, scope: str, query: str,
                 limit: int) -> list[str]:
    """BM25 через FTS5. Промышленный лексический поиск, встроен в SQLite."""
    terms = [t for t in re.findall(r"\w+", query.lower()) if len(t) > 1]
    if not terms:
        return []
    # OR по терминам: пусть BM25 сам взвесит редкие выше частых
    match = " OR ".join(f'"{t}"*' for t in terms)
    try:
        rows = store.query(
            """SELECT m.id FROM memory_fts f
               JOIN memory m ON m.rowid = f.rowid
               WHERE memory_fts MATCH ? AND m.user_id = ? AND m.scope = ?
                 AND m.status = 'active'
               ORDER BY bm25(memory_fts) LIMIT ?""",
            (match, user_id, scope, limit))
        return [r["id"] for r in rows]
    except Exception:
        return []


def rank_entity(query: str, rows: list, limit: int) -> list[str]:
    """Точное совпадение идентификаторов. Ловит то, что теряют оба выше."""
    q_ent = entities(query)
    if not q_ent:
        return []
    scored = []
    for r in rows:
        overlap = q_ent & entities(r["content"] or "")
        if overlap:
            scored.append((len(overlap), r["id"]))
    scored.sort(reverse=True)
    return [rid for _, rid in scored[:limit]]


# --- объединение ------------------------------------------------------

DEFAULT_WEIGHTS = {
    "semantic": 1.0,
    "lexical": 1.0,
    "entity": 1.5,      # точное совпадение идентификатора — сильный сигнал
}


def hybrid_rank(store, user_id: str, scope: str, query: str,
                rows: list, pool: int = 50,
                weights: dict[str, float] | None = None
                ) -> tuple[dict[str, float], dict[str, list[str]]]:
    """Возвращает (баллы RRF, вклад каждой стратегии) — второе для --explain."""
    qvec = embeddings.embed(query)
    rankings = {
        "semantic": rank_semantic(qvec, rows, pool),
        "lexical": rank_lexical(store, user_id, scope, query, pool),
        "entity": rank_entity(query, rows, pool),
    }
    rankings = {k: v for k, v in rankings.items() if v}
    scores = reciprocal_rank_fusion(rankings, weights or DEFAULT_WEIGHTS)
    return scores, rankings
