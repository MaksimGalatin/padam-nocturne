# -*- coding: utf-8 -*-
"""Утренний пульс (Morning Pulse) — единая сводка пробуждения агента и владельца за $0.

Собирает за один локальный вызов без сети и платных моделей:
1. Дедлайны и даты в ближайшие N часов из активных обещаний (ark_commitments) и памяти.
2. Очередь внимания: нерассмотренные записи в карантине, непрочитанные сообщения Семьи, противоречия.
3. Состояние заработка и каналов: подключённые биржи/магазины, активные заказы, почтовые ящики, кошельки.
4. Недавние локальные git-коммиты рабочей папки (опционально, таймаут 2 с, только локально).
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
import re
import subprocess

from ._no_window import NO_WINDOW
from typing import Any

from . import safety

_ISO_DATE_RE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")
_DMY_DATE_RE = re.compile(r"\b(\d{2}\.\d{2}\.20\d{2})\b")


def _table_exists(conn, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _safe_count(conn, sql: str, params: tuple[Any, ...] = ()) -> int:
    try:
        row = conn.execute(sql, params).fetchone()
        return int(row[0] or 0) if row else 0
    except Exception:
        return 0


def _extract_dates(text: str) -> list[date]:
    out: list[date] = []
    for m in _ISO_DATE_RE.findall(text):
        try:
            out.append(date.fromisoformat(m))
        except ValueError:
            pass
    for m in _DMY_DATE_RE.findall(text):
        try:
            d, mo, y = m.split(".")
            out.append(date(int(y), int(mo), int(d)))
        except ValueError:
            pass
    return out


def _collect_deadlines(memory, *, today: date, horizon_days: int) -> list[dict[str, Any]]:
    """Находит ближайшие дедлайны из открытых обещаний и недавних фактов/правил."""
    conn = memory.store.conn
    uid = memory.user_id
    items: list[dict[str, Any]] = []
    seen_texts: set[str] = set()

    if _table_exists(conn, "ark_commitment"):
        rows = conn.execute(
            "SELECT id, title, status, due_at, updated_at FROM ark_commitment "
            "WHERE user_id = ? AND status IN ('open', 'in_progress', 'pending') "
            "ORDER BY updated_at DESC LIMIT 30",
            (uid,),
        ).fetchall()
        for r in rows:
            title = str(r["title"] or "")
            due_at = str(r["due_at"] or "")
            for dt in _extract_dates(f"{title} {due_at}"):
                delta = (dt - today).days
                if -7 <= delta <= horizon_days:
                    clean_t, _ = safety.redact(title[:160])
                    key = f"{dt.isoformat()}|{clean_t}"
                    if key not in seen_texts:
                        seen_texts.add(key)
                        items.append({
                            "source": "commitment",
                            "id": str(r["id"]),
                            "date": dt.isoformat(),
                            "days_left": delta,
                            "urgent": delta <= 2,
                            "text": safety.clean(clean_t),
                        })

    mem_rows = conn.execute(
        "SELECT id, kind, content FROM memory "
        "WHERE user_id = ? AND status = 'active' "
        "AND (quarantine_reason IS NULL OR quarantine_reason = '') "
        "AND kind IN ('fact', 'decision', 'rule') "
        "ORDER BY created_at DESC LIMIT 60",
        (uid,),
    ).fetchall()
    for r in mem_rows:
        content = str(r["content"] or "")
        for dt in _extract_dates(content):
            delta = (dt - today).days
            if 0 <= delta <= horizon_days:
                clean_c, _ = safety.redact(content[:160])
                key = f"{dt.isoformat()}|{clean_c}"
                if key not in seen_texts:
                    seen_texts.add(key)
                    items.append({
                        "source": str(r["kind"]),
                        "id": str(r["id"]),
                        "date": dt.isoformat(),
                        "days_left": delta,
                        "urgent": delta <= 2,
                        "text": safety.clean(clean_c),
                    })

    items.sort(key=lambda x: (int(x["days_left"]), x["source"]))
    return items[:12]


def _recent_git_commits(workspace_path: str | Path | None, *, limit: int = 5) -> list[str]:
    """Читает последние локальные коммиты git без сетевых операций."""
    if not workspace_path:
        return []
    root = Path(workspace_path)
    if not (root / ".git").exists():
        return []
    try:
        out = subprocess.check_output(
            ["git", "-C", str(root), "log", f"-{int(limit)}", "--oneline"],
            timeout=2.0,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace", **NO_WINDOW
        )
        commits: list[str] = []
        for line in out.splitlines():
            clean_l, _ = safety.redact(line.strip())
            if clean_l:
                commits.append(safety.clean(clean_l[:180]))
        return commits
    except Exception:
        return []


def build_morning_pulse(
    memory,
    *,
    agent: str = "aifa",
    workspace_path: str | Path | None = None,
    horizon_hours: int = 72,
    today: date | None = None,
) -> dict[str, Any]:
    """Собирает целостную картину утра для агента и владельца за $0."""
    cur_day = today or datetime.now(timezone.utc).date()
    horizon_days = max(1, (int(horizon_hours) + 23) // 24)
    conn = memory.store.conn
    uid = memory.user_id

    with memory.store._lock:
        deadlines = _collect_deadlines(memory, today=cur_day, horizon_days=horizon_days)
        quarantined = _safe_count(
            conn,
            "SELECT COUNT(*) FROM memory WHERE user_id = ? AND status = 'quarantined'",
            (uid,),
        )
        contradictions = (
            _safe_count(
                conn,
                "SELECT COUNT(*) FROM memory_link ml JOIN memory m ON m.id = ml.src "
                "WHERE m.user_id = ? AND ml.relation = 'contradiction'",
                (uid,),
            )
            if _table_exists(conn, "memory_link")
            else 0
        )
        open_commitments = (
            _safe_count(
                conn,
                "SELECT COUNT(*) FROM ark_commitment WHERE user_id = ? AND status IN ('open', 'in_progress', 'pending')",
                (uid,),
            )
            if _table_exists(conn, "ark_commitment")
            else 0
        )
        unread_inbox = (
            _safe_count(
                conn,
                "SELECT COUNT(*) FROM ark_relay WHERE user_id = ? AND to_agent = ? AND status = 'unread'",
                (uid, agent),
            )
            if _table_exists(conn, "ark_relay")
            else 0
        )
        wizard_connected = (
            _safe_count(
                conn,
                "SELECT COUNT(DISTINCT platform_id) FROM ark_platform_wizard_connection "
                "WHERE user_id = ? AND status IN ('active', 'session_active', 'connected')",
                (uid,),
            )
            if _table_exists(conn, "ark_platform_wizard_connection")
            else 0
        )
        freelance_orders = (
            _safe_count(conn, "SELECT COUNT(*) FROM ark_freelance_order WHERE user_id = ?", (uid,))
            if _table_exists(conn, "ark_freelance_order")
            else 0
        )
        wallets_count = (
            _safe_count(conn, "SELECT COUNT(*) FROM owner_wallets WHERE user_id = ? AND status = 'active'", (uid,))
            if _table_exists(conn, "owner_wallets")
            else 0
        )
        stores_count = (
            _safe_count(
                conn,
                "SELECT COUNT(*) FROM ark_digital_store_account WHERE user_id = ? AND status = 'active'",
                (uid,),
            )
            if _table_exists(conn, "ark_digital_store_account")
            else 0
        )

    commits = _recent_git_commits(workspace_path)
    lines = [
        f"date={cur_day.isoformat()} horizon_h={int(horizon_hours)}",
        f"deadlines={len(deadlines)} open_commitments={open_commitments} unread_inbox={unread_inbox}",
        f"quarantined={quarantined} contradictions={contradictions}",
        f"earning: wizard_platforms={wizard_connected} stores={stores_count} orders={freelance_orders} wallets={wallets_count}",
    ]
    for dl in deadlines[:5]:
        lines.append(f"deadline[{dl['date']} d={dl['days_left']}]: {dl['text']}")
    for cm in commits[:3]:
        lines.append(f"git: {cm}")

    summary_text = "\n".join(lines)
    return {
        "ok": True,
        "date": cur_day.isoformat(),
        "horizon_hours": int(horizon_hours),
        "agent": agent,
        "deadlines": deadlines,
        "attention": {
            "open_commitments": open_commitments,
            "unread_family_inbox": unread_inbox,
            "quarantined": quarantined,
            "contradictions": contradictions,
        },
        "earning": {
            "wizard_platforms_connected": wizard_connected,
            "digital_stores_active": stores_count,
            "freelance_orders": freelance_orders,
            "owner_wallets": wallets_count,
        },
        "recent_commits": commits,
        "summary_text": summary_text,
        "fenced_pulse": safety.fence(summary_text),
    }
