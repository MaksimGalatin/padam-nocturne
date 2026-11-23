# -*- coding: utf-8 -*-
"""Голосовой движок команд и Wake Word «Айфа…» для PADAM Studio и Android (Фишка 19)."""
from __future__ import annotations

import re
from typing import Any

from . import ark, family_feeds

_WAKE_PREFIX_RE = re.compile(
    r"^\s*(?:(?:эй|привет|слушай|окей|ok|hey|hi)[,\s]+)?"
    r"(?:айфа|айфочка|айфуля|aifa|alpha)[,\s:!.-]*",
    re.IGNORECASE,
)

_CMD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("remember", re.compile(r"^(?:запиши|запомни|сохрани|remember|save|note)(?:\s+(?:в\s+память|что))?\s*[:,-]?\s*(.+)$", re.IGNORECASE | re.DOTALL)),
    ("search", re.compile(r"^(?:найди|найти|поищи|вспомни|search|find|recall|look\s+up)\s*[:,-]?\s*(.+)$", re.IGNORECASE | re.DOTALL)),
    ("task", re.compile(r"^(?:поставь\s+задачу|создай\s+задачу|задача|выполни|сделай|напомни|add\s+task|task|todo|remind\s+me)\s*[:,-]?\s*(.+)$", re.IGNORECASE | re.DOTALL)),
    ("status", re.compile(r"^(?:статус|отч[её]т|сводка|как\s+дела|status|report|summary)\s*[?!.]*$", re.IGNORECASE)),
)


def parse_voice_utterance(text: str, *, require_wake_word: bool = False) -> dict[str, Any]:
    """Разбирает голосовую фразу: проверяет wake-word «Айфа…» и определяет намерение."""
    raw = str(text or "").strip()
    if not raw:
        return {"ok": False, "woke": False, "wake_word_matched": False, "ignored": True, "intent": "empty", "payload": "", "raw": ""}

    m_wake = _WAKE_PREFIX_RE.match(raw)
    woke = bool(m_wake)
    body = raw[m_wake.end():].strip() if m_wake else raw

    if require_wake_word and not woke:
        return {"ok": True, "woke": False, "wake_word_matched": False, "ignored": True, "intent": "ignored", "payload": "", "raw": raw}

    if not body:
        return {"ok": True, "woke": woke, "wake_word_matched": woke, "ignored": False, "intent": "wake_only", "payload": "", "raw": raw}

    for intent, pat in _CMD_PATTERNS:
        m = pat.match(body)
        if m:
            payload = (m.group(1) if m.lastindex else "") or ""
            return {"ok": True, "woke": woke, "wake_word_matched": woke, "ignored": False, "intent": intent, "payload": payload.strip(), "raw": raw}

    return {"ok": True, "woke": woke, "wake_word_matched": woke, "ignored": False, "intent": "chat", "payload": body, "raw": raw}


def execute_voice_command(
    memory,
    text: str,
    *,
    require_wake_word: bool = False,
    scope: str = "global",
    lang: str = "ru",
    source: str = "voice_owner",
) -> dict[str, Any]:
    """Исполняет голосовую команду поверх памяти PADAM и возвращает ответ для озвучки TTS."""
    parsed = parse_voice_utterance(text, require_wake_word=require_wake_word)
    intent = parsed["intent"]
    payload = parsed["payload"]
    ru = str(lang or "ru").lower().startswith("ru")

    if not parsed["ok"] or intent == "ignored":
        return {**parsed, "executed": False, "speak": "", "spoken_reply": ""}

    if intent == "wake_only":
        sp = "Я здесь, слушаю тебя!" if ru else "I am here, listening!"
        return {**parsed, "executed": True, "speak": sp, "spoken_reply": sp}

    if intent == "remember":
        if not payload:
            sp = "Скажи, что именно записать в память." if ru else "Tell me what to save to memory."
            return {**parsed, "executed": False, "speak": sp, "spoken_reply": sp}
        outcome, mid = memory.remember(
            payload,
            kind="fact",
            importance=0.85,
            scope=scope,
            origin="user",
            guarded=True,
            agent_id="owner",
        )
        if outcome == "quarantined":
            sp = "Запись задержана щитом в карантин для твоей проверки." if ru else "Held in quarantine by Agentic Shield for your review."
        else:
            sp = f"Записала в память: {payload[:120]}" if ru else f"Saved to memory: {payload[:120]}"
        return {
            **parsed,
            "executed": True,
            "record_id": mid,
            "status": outcome,
            "speak": sp,
            "spoken_reply": sp,
        }

    if intent == "search":
        q = payload or parsed["raw"]
        hits = memory.recall(q, scope=scope, limit=5)
        items = [
            {
                "id": h.id,
                "content": (h.content or "")[:240],
                "kind": h.kind,
                "score": round(float(h.score), 4),
            }
            for h in hits
        ]
        if items:
            top = items[0]["content"]
            sp = f"Нашла {len(items)} записей. Главное: {top[:160]}" if ru else f"Found {len(items)} records. Top match: {top[:160]}"
        else:
            sp = "По этому запросу в памяти пока ничего не найдено." if ru else "Nothing found in memory for that query."
        return {
            **parsed,
            "executed": True,
            "count": len(items),
            "results": items,
            "speak": sp,
            "spoken_reply": sp,
        }

    if intent == "task":
        if not payload:
            sp = "Назови задачу, которую нужно поставить." if ru else "Please state the task to create."
            return {**parsed, "executed": False, "speak": sp, "spoken_reply": sp}
        cmt = ark.add_commitment(
            memory,
            title=payload[:200],
            priority=4,
            context=f"Голосовое поручение владельца ({source}): {payload}",
        )
        try:
            family_feeds.post_feed(
                memory,
                channel="office",
                content=f"[Голосовое поручение владельца] {payload}",
                author="owner",
                kind="task",
            )
        except Exception:
            pass
        sp = f"Задача принята и передана Семье: {payload[:120]}" if ru else f"Task accepted and dispatched to Family: {payload[:120]}"
        return {
            **parsed,
            "executed": True,
            "commitment": cmt,
            "speak": sp,
            "spoken_reply": sp,
        }

    if intent == "status":
        st = memory.stats()
        act = int(st.get("active") or 0)
        quar = int(st.get("quarantined") or 0)
        sp = (
            f"В памяти {act} активных записей, в карантине {quar}. Защита работает штатно."
            if ru else f"Memory has {act} active records and {quar} in quarantine. Shield is active."
        )
        return {
            **parsed,
            "executed": True,
            "active": act,
            "quarantined": quar,
            "speak": sp,
            "spoken_reply": sp,
        }

    # Свободная фраза: ищем контекст и отвечаем кратко
    hits = memory.recall(payload, scope=scope, limit=3)
    if hits:
        sp = f"Помню по этой теме: {(hits[0].content or '')[:160]}" if ru else f"From memory: {(hits[0].content or '')[:160]}"
    else:
        sp = f"Приняла: {payload[:120]}. Скажи «Айфа, запиши …», если нужно сохранить." if ru else f"Heard: {payload[:120]}. Say 'AIfa, remember ...' to save."
    return {
        **parsed,
        "executed": True,
        "count": len(hits),
        "speak": sp,
        "spoken_reply": sp,
    }
