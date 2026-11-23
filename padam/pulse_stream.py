# -*- coding: utf-8 -*-
"""Живой поток событий «Пульс Агентов» (Real-Time SSE + кросс-процессный sidecar pulse_events, Фишка 1 Волны 2).

Позволяет видеть в живом окне PADAM Studio вызовы MCP из внешних процессов
(Antigravity, Claude Code, Cursor, Codex, Android) за счёт общего sidecar `<db>.sessions.sqlite`.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import safety

_MAX_EVENTS = 200
_COND = threading.Condition()
_EVENTS: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
_SEQ = 0
_PULSE_DB_PATH: str | None = None
_DB_LOCK = threading.Lock()


def set_pulse_db_path(db_path: str | Path | None) -> None:
    """Закрепляет путь к основной БД, чтобы писать/читать кросс-процессный пульс в `<db>.sessions.sqlite`."""
    global _PULSE_DB_PATH
    if not db_path or str(db_path) == ":memory:":
        return
    p = str(db_path)
    with _DB_LOCK:
        _PULSE_DB_PATH = p


def _resolve_sessions_sqlite(db_path: str | Path | None = None) -> str | None:
    cand = str(db_path or _PULSE_DB_PATH or "").strip()
    if not cand or cand == ":memory:":
        return None
    if cand.endswith(".sessions.sqlite"):
        return cand
    p = Path(cand)
    if not p.parent.exists():
        return None
    return cand + ".sessions.sqlite"


def _connect_pulse_db(sessions_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(sessions_path, timeout=2.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pulse_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            ts_epoch REAL NOT NULL,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            detail_json TEXT NOT NULL DEFAULT '{}',
            latency_ms REAL,
            status TEXT NOT NULL DEFAULT 'ok',
            scope TEXT NOT NULL DEFAULT 'global'
        )"""
    )
    conn.execute("DELETE FROM pulse_events WHERE seq < (SELECT COALESCE(MAX(seq), 0) - 500 FROM pulse_events)")
    conn.commit()
    return conn


def _row_to_ev(r: sqlite3.Row) -> dict[str, Any]:
    raw_d = str(r["detail_json"] or "{}")
    try:
        det = json.loads(raw_d)
    except Exception:
        det = raw_d
    return {
        "seq": int(r["seq"]),
        "ts": str(r["ts"] or ""),
        "ts_epoch": float(r["ts_epoch"] or 0.0),
        "agent_id": str(r["agent_id"] or "owner"),
        "event_type": str(r["event_type"] or "event"),
        "action": str(r["event_type"] or "event"),
        "summary": str(r["summary"] or ""),
        "detail": det,
        "latency_ms": r["latency_ms"],
        "status": str(r["status"] or "ok"),
        "scope": str(r["scope"] or "global"),
    }


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
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Публикует событие в живой поток Пульса Агентов (RAM + кросс-процессный SQLite sidecar)."""
    global _SEQ
    ev_kind = str(event_type or action or "event")[:40]
    raw_sum = str(summary or (detail if isinstance(detail, str) else "") or ev_kind)[:200]
    safe_summary, _ = safety.redact(raw_sum)
    safe_detail = detail if isinstance(detail, dict) else safe_summary
    ts_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ts_ep = round(time.time(), 3)
    lat_val = round(float(latency_ms), 2) if latency_ms is not None else None
    ag_clean = str(agent_id or "owner")[:64]
    st_clean = str(status or "ok")[:24]
    sc_clean = str(scope or "global")[:64]

    db_seq: int | None = None
    sess_file = _resolve_sessions_sqlite(db_path)
    if sess_file:
        try:
            with _DB_LOCK:
                conn = _connect_pulse_db(sess_file)
                try:
                    cur = conn.execute(
                        "INSERT INTO pulse_events (ts, ts_epoch, agent_id, event_type, summary, detail_json, latency_ms, status, scope) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            ts_iso,
                            ts_ep,
                            ag_clean,
                            ev_kind,
                            safe_summary,
                            json.dumps(safe_detail, ensure_ascii=False)
                            if isinstance(safe_detail, dict)
                            else json.dumps({"text": str(safe_detail)}, ensure_ascii=False),
                            lat_val,
                            st_clean,
                            sc_clean,
                        ),
                    )
                    db_seq = int(cur.lastrowid or 0)
                    conn.commit()
                finally:
                    conn.close()
        except Exception:
            db_seq = None

    with _COND:
        _SEQ = max(_SEQ + 1, db_seq or 0)
        ev = {
            "seq": db_seq if db_seq else _SEQ,
            "ts": ts_iso,
            "ts_epoch": ts_ep,
            "agent_id": ag_clean,
            "event_type": ev_kind,
            "action": ev_kind,
            "summary": safe_summary,
            "detail": safe_detail,
            "latency_ms": lat_val,
            "status": st_clean,
            "scope": sc_clean,
        }
        _EVENTS.append(ev)
        _COND.notify_all()
        return ev


def recent_pulse(limit: int = 30, *, since_seq: int = 0, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Возвращает последние события Пульса из общего sidecar (если доступен) или RAM-кольца."""
    lim = max(1, min(int(limit or 30), _MAX_EVENTS))
    sess_file = _resolve_sessions_sqlite(db_path)
    if sess_file and os.path.exists(sess_file):
        try:
            with _DB_LOCK:
                conn = _connect_pulse_db(sess_file)
                try:
                    rows = conn.execute(
                        "SELECT * FROM pulse_events WHERE seq > ? ORDER BY seq DESC LIMIT ?",
                        (int(since_seq or 0), lim),
                    ).fetchall()
                finally:
                    conn.close()
            if rows:
                items = [_row_to_ev(r) for r in reversed(rows)]
                return items[-lim:]
        except Exception:
            pass
    with _COND:
        items = [e for e in _EVENTS if e["seq"] > since_seq]
    return items[-lim:]


def get_recent_pulse(limit: int = 30, *, since_seq: int = 0, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Алиас recent_pulse для REST API."""
    return recent_pulse(limit=limit, since_seq=since_seq, db_path=db_path)


def format_sse_event(ev: dict[str, Any]) -> str:
    """Форматирует событие Пульса в кадр Server-Sent Events (text/event-stream)."""
    sid = int(ev.get("seq") or 0)
    data = json.dumps(ev, ensure_ascii=False)
    return f"id: {sid}\nevent: pulse\ndata: {data}\n\n"


def wait_for_pulse(last_seq: int, *, timeout: float = 12.0, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Блокирующее ожидание новых событий для SSE-подписчика (с кросс-процессным чтением sidecar)."""
    items = recent_pulse(limit=20, since_seq=last_seq, db_path=db_path)
    if items:
        return items
    deadline = time.time() + max(0.2, min(float(timeout), 30.0))
    while time.time() < deadline:
        rem = min(0.5, max(0.05, deadline - time.time()))
        with _COND:
            _COND.wait(timeout=rem)
        items = recent_pulse(limit=20, since_seq=last_seq, db_path=db_path)
        if items:
            return items
    return []


def current_seq() -> int:
    with _COND:
        return _SEQ
