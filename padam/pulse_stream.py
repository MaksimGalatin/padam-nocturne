# -*- coding: utf-8 -*-
"""Живой поток событий «Пульс Агентов» (Real-Time SSE + кольцевой буфер, Фишка 12).

Показывает владельцу в реальном времени, какой агент (Claude Code, Antigravity,
AutoClaw, Android, Owner) прямо сейчас обращается к памяти и какую операцию выполняет.
Весь текст перед публикацией прогоняется через safety.redact().
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

from . import safety

_MAX_EVENTS = 200
_COND = threading.Condition()
_EVENTS: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
_SEQ = 0


def emit_pulse(
    *,
    agent_id: str = "owner",
    event_type: str | None = None,
    action: str | None = None,
    summary: str = "",
    detail: Any = "",
    latency_ms: float | None = None,
    status: str = "ok",
    scope: str = "global",
) -> dict[str, Any]:
    """Публикует событие в живой поток Пульса Агентов (потокобезопасно, с маскировкой секретов)."""
    global _SEQ
    ev_kind = str(event_type or action or "event")[:40]
    raw_sum = str(summary or (detail if isinstance(detail, str) else "") or ev_kind)[:200]
    safe_summary, _ = safety.redact(raw_sum)
    safe_detail = detail if isinstance(detail, dict) else safe_summary
    with _COND:
        _SEQ += 1
        ev = {
            "seq": _SEQ,
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ts_epoch": round(time.time(), 3),
            "agent_id": str(agent_id or "owner")[:64],
            "event_type": ev_kind,
            "action": ev_kind,
            "summary": safe_summary,
            "detail": safe_detail,
            "latency_ms": round(float(latency_ms), 2) if latency_ms is not None else None,
            "status": str(status or "ok")[:24],
            "scope": str(scope or "global")[:64],
        }
        _EVENTS.append(ev)
        _COND.notify_all()
        return ev


def recent_pulse(limit: int = 30, *, since_seq: int = 0) -> list[dict[str, Any]]:
    """Возвращает последние события Пульса (новее since_seq)."""
    lim = max(1, min(int(limit or 30), _MAX_EVENTS))
    with _COND:
        items = [e for e in _EVENTS if e["seq"] > since_seq]
    return items[-lim:]


def get_recent_pulse(limit: int = 30, *, since_seq: int = 0) -> list[dict[str, Any]]:
    """Алиас recent_pulse для REST API."""
    return recent_pulse(limit=limit, since_seq=since_seq)


def format_sse_event(ev: dict[str, Any]) -> str:
    """Форматирует событие Пульса в кадр Server-Sent Events (text/event-stream)."""
    sid = int(ev.get("seq") or 0)
    data = json.dumps(ev, ensure_ascii=False)
    return f"id: {sid}\nevent: pulse\ndata: {data}\n\n"


def wait_for_pulse(last_seq: int, *, timeout: float = 12.0) -> list[dict[str, Any]]:
    """Блокирующее ожидание новых событий для SSE-подписчика (с таймаутом для keep-alive)."""
    with _COND:
        items = [e for e in _EVENTS if e["seq"] > last_seq]
        if items:
            return items
        _COND.wait(timeout=max(0.2, min(float(timeout), 30.0)))
        return [e for e in _EVENTS if e["seq"] > last_seq]


def current_seq() -> int:
    with _COND:
        return _SEQ
