# -*- coding: utf-8 -*-
"""Привязка фактов памяти к исходному коду и детектор устаревания по SHA-256 (ТОП-5).

Зачем: в разработке факт вида «функция X делает Y» часто устаревает в момент изменения
файла на диске. Якорь фиксирует `file_path` и `SHA-256` содержимого файла на момент
записи и мгновенно выявляет устаревшие факты без сети.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from . import ark, audit_chain

_CODE_ANCHOR_DDL = """
CREATE TABLE IF NOT EXISTS ark_code_anchor (
    anchor_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT NOT NULL,
    memory_id     TEXT NOT NULL,
    file_path     TEXT NOT NULL,
    symbol_name   TEXT NOT NULL DEFAULT '',
    file_sha256   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'fresh',
    stale_reason  TEXT NOT NULL DEFAULT '',
    checked_at    REAL NOT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_code_anchor_mem ON ark_code_anchor(user_id, memory_id);
"""


def _ensure(memory) -> None:
    ark._ensure_tables(memory)
    memory.store.conn.executescript(_CODE_ANCHOR_DDL)
    memory.store.conn.commit()


def _safe_resolve_under_root(repo_root: str | Path, rel_path: str) -> Path:
    root = Path(repo_root).resolve()
    raw = str(rel_path or "").strip()
    if not raw:
        raise ValueError("file_path must be a non-empty path inside repo_root")
    cand = Path(raw)
    target = cand.resolve() if cand.is_absolute() else (root / raw).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise PermissionError(f"Path traversal denied outside repo_root: {rel_path!r}") from exc
    return target


def anchor_fact_to_file(
    memory,
    memory_id: str,
    file_path: str,
    *,
    repo_root: str | Path = ".",
    symbol_name: str = "",
) -> dict[str, Any]:
    """Привязывает запись памяти `memory_id` к текущему SHA-256 файла на диске."""
    _ensure(memory)
    target = _safe_resolve_under_root(repo_root, file_path)
    if not target.is_file():
        raise FileNotFoundError(f"Anchor file not found: {target}")
    rel_norm = target.relative_to(Path(repo_root).resolve()).as_posix()
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    now = time.time()
    cur = memory.store.conn.execute(
        "INSERT INTO ark_code_anchor (user_id, memory_id, file_path, symbol_name, file_sha256, status, stale_reason, checked_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, 'fresh', '', ?, ?)",
        (memory.user_id, str(memory_id), rel_norm, str(symbol_name or "")[:120], digest, now, now),
    )
    memory.store.conn.commit()
    return {
        "ok": True,
        "anchor_id": cur.lastrowid,
        "memory_id": str(memory_id),
        "file_path": rel_norm,
        "symbol_name": str(symbol_name or ""),
        "file_sha256": digest,
        "status": "fresh",
    }


def check_stale_anchors(memory, *, repo_root: str | Path = ".") -> dict[str, Any]:
    """Проверяет все привязки к файлам в `repo_root` и отмечает те, чей файл изменён или удалён."""
    _ensure(memory)
    root = Path(repo_root).resolve()
    conn = memory.store.conn
    rows = conn.execute(
        "SELECT anchor_id, memory_id, file_path, symbol_name, file_sha256, status FROM ark_code_anchor WHERE user_id = ? ORDER BY anchor_id ASC",
        (memory.user_id,),
    ).fetchall()

    now = time.time()
    stale_items: list[dict[str, Any]] = []
    fresh_count = 0

    for r in rows:
        aid = int(r["anchor_id"])
        rel = str(r["file_path"])
        try:
            target = _safe_resolve_under_root(root, rel)
        except Exception:
            reason = "invalid_path"
            cur_sha = ""
            new_status = "stale"
        else:
            if not target.is_file():
                reason = "file_missing"
                cur_sha = ""
                new_status = "stale"
            else:
                cur_sha = hashlib.sha256(target.read_bytes()).hexdigest()
                if cur_sha != str(r["file_sha256"]):
                    reason = "file_hash_changed"
                    new_status = "stale"
                else:
                    reason = ""
                    new_status = "fresh"

        conn.execute(
            "UPDATE ark_code_anchor SET status = ?, stale_reason = ?, checked_at = ? WHERE anchor_id = ?",
            (new_status, reason, now, aid),
        )
        if new_status == "stale":
            stale_items.append({
                "anchor_id": aid,
                "memory_id": r["memory_id"],
                "file_path": rel,
                "symbol_name": r["symbol_name"],
                "reason": reason,
                "recorded_sha256": r["file_sha256"],
                "current_sha256": cur_sha,
            })
        else:
            fresh_count += 1

    conn.commit()
    if stale_items:
        audit_chain.append_audit(
            memory,
            "code_anchors_stale_detected",
            {"stale_count": len(stale_items), "fresh_count": fresh_count},
            agent_id="code_anchor",
        )
    return {
        "ok": True,
        "checked": len(rows),
        "fresh_count": fresh_count,
        "stale_count": len(stale_items),
        "stale": stale_items,
    }
