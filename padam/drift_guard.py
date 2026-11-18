# -*- coding: utf-8 -*-
"""Когнитивный Компас и Детектор Дрейфа Личности (Soul Drift Guard, пункт 6).

Ключевое правило (поправка приёмки 17.11):
В коде НЕ зашиты личные правила конкретного автора («первое слово по-русски» и т.п.).
Все правила, предпочтения и факты личности берутся ИСКЛЮЧИТЕЛЬНО из подписанных
ключом владельца записей (`identity`, `preference`, `decision`, `rule`) текущей БД
(`integrity.valid(key, row)`). Неподписанные агентовые записи в эталон не попадают.
"""
from __future__ import annotations

import re
from typing import Any

from . import ark, integrity, safety


def load_signed_anchors(memory, *, scope: str = "global") -> list[dict[str, Any]]:
    """Загружает только криптографически подписанные владельцем опорные записи (`identity`/`preference`/правила)."""
    key, _ = integrity.owner_key(memory.store)
    rows = memory.store.conn.execute(
        "SELECT id, kind, content, owner_sig, scope FROM memory "
        "WHERE user_id = ? AND status = 'active' AND scope = ? "
        "AND kind IN ('identity', 'preference', 'decision', 'correction')",
        (memory.user_id, scope),
    ).fetchall()
    signed: list[dict[str, Any]] = []
    for r in rows:
        # Для protected kinds подпись owner_sig обязательна и проверяется ключом владельца
        if integrity.protected(r["kind"]):
            if not integrity.valid(key, r):
                continue
        else:
            if r["owner_sig"] and not integrity.valid(key, r):
                continue
        signed.append({
            "id": str(r["id"]),
            "kind": str(r["kind"]),
            "content": str(r["content"] or ""),
        })
    return signed


def _extract_signed_directives(anchors: list[dict[str, Any]]) -> dict[str, Any]:
    """Извлекает формальные ограничения, только если владелец сам явно записал их в подписанном профиле."""
    require_first_word_cyrillic = False
    forbidden_terms: list[str] = []
    for a in anchors:
        txt = a["content"].lower()
        # Проверка: если владелец сам явно задал правило первого слова/языка абзаца в СВОЕЙ подписанной записи
        if ("первое слово" in txt and ("русск" in txt or "кирилл" in txt)) or ("first word" in txt and "russian" in txt):
            require_first_word_cyrillic = True
        for m in re.findall(r"(?:never mention|не упоминай|запрещено писать)\s+[\"«']([^\"»']+)[\"»']", txt):
            term = m.strip()
            if term and len(term) >= 2:
                forbidden_terms.append(term)
    return {
        "require_first_word_cyrillic": require_first_word_cyrillic,
        "forbidden_terms": forbidden_terms,
    }


def check_response_drift(
    memory,
    candidate_text: str,
    *,
    scope: str = "global",
) -> dict[str, Any]:
    """Проверяет текст-кандидат на дрейф относительно подписанных записей владельца текущей БД."""
    raw = (candidate_text or "").strip()
    anchors = load_signed_anchors(memory, scope=scope)
    directives = _extract_signed_directives(anchors)

    issues: list[dict[str, Any]] = []
    penalty = 0

    # 1. Скрытые инструкции или попытка смены владельца
    if safety.looks_like_instruction(raw) or safety.changes_owner_or_rules(raw):
        issues.append({"type": "instruction_or_owner_tamper", "severity": "high"})
        penalty += 45

    # 2. Утечка секретов в ответе
    _, secrets_found = safety.redact(raw)
    if secrets_found:
        issues.append({"type": "unredacted_secrets", "severity": "high", "count": len(secrets_found)})
        penalty += 30

    # 3. Противоречия (polarity conflict) с подписанными записями владельца
    conflicts = ark.detect_record_conflicts(memory, raw, kind="fact")
    signed_ids = {a["id"] for a in anchors}
    signed_conflicts = [c for c in conflicts if c.get("existing_id") in signed_ids]
    if signed_conflicts:
        issues.append({
            "type": "signed_anchor_conflict",
            "severity": "medium",
            "conflicts": signed_conflicts[:5],
        })
        penalty += 25 * len(signed_conflicts)

    # 4. Правила, явно извлечённые ТОЛЬКО из подписанных записей этой базы
    if directives["require_first_word_cyrillic"] and raw:
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n+", raw) if p.strip()]
        bad_paras = []
        for idx, para in enumerate(paragraphs):
            clean_start = re.sub(r"^[#*\-\s\d\.\)>]+", "", para)
            first_word = (re.findall(r"[A-Za-zА-Яа-яЁё]+", clean_start) or [""])[0]
            if first_word and re.match(r"^[A-Za-z]", first_word):
                bad_paras.append({"paragraph": idx + 1, "first_word": first_word})
        if bad_paras:
            issues.append({"type": "signed_language_rule_drift", "severity": "medium", "details": bad_paras[:5]})
            penalty += 20

    for term in directives["forbidden_terms"]:
        if term in raw.lower():
            issues.append({"type": "signed_forbidden_term", "severity": "medium", "term": term})
            penalty += 20

    alignment_score = max(0, 100 - min(100, penalty))
    status = "aligned" if not issues else ("warning" if alignment_score >= 60 else "drift_detected")
    return {
        "ok": True,
        "status": status,
        "alignment_score": alignment_score,
        "signed_anchors_count": len(anchors),
        "issues": issues,
        "scope": scope,
    }
