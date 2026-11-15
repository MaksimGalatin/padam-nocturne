"""Глубокий аудит и безопасное самолечение базы памяти (padam doctor --fix).

Проверяет:
1) PRAGMA integrity_check;
2) согласованность FTS5-индекса (memory_fts);
3) целостность SHA-256 аудит-цепи app_access_event;
4) висячие рёбра memory_link (отсутствующий или отозванный узел);
5) незаполненные битемпоральные метки learned_at.

При fix=True перед любым изменением ОБЯЗАТЕЛЬНО создаёт когнитивный снапшот.
"""
from __future__ import annotations

import time
from typing import Any

from .memory import Memory


def _table_exists(mem: Memory, name: str) -> bool:
    row = mem.store.one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    )
    return row is not None


def _check_fts(mem: Memory) -> tuple[bool, str]:
    if not _table_exists(mem, "memory_fts"):
        return True, "no_fts_table"
    try:
        with mem.store._lock:
            mem.store.conn.execute("INSERT INTO memory_fts(memory_fts) VALUES('integrity-check')")
        return True, "ok"
    except Exception as exc:
        return False, f"fts_error: {exc}"


def _count_dangling_links(mem: Memory) -> int:
    if not _table_exists(mem, "memory_link"):
        return 0
    row = mem.store.one(
        "SELECT COUNT(*) AS cnt FROM memory_link ml "
        "WHERE NOT EXISTS (SELECT 1 FROM memory m WHERE m.id = ml.src AND m.status != 'revoked') "
        "   OR NOT EXISTS (SELECT 1 FROM memory m WHERE m.id = ml.dst AND m.status != 'revoked')"
    )
    return int(row["cnt"]) if row else 0


def _count_missing_learned_at(mem: Memory) -> int:
    row = mem.store.one(
        "SELECT COUNT(*) AS cnt FROM memory WHERE learned_at IS NULL OR learned_at = ''"
    )
    return int(row["cnt"]) if row else 0


def run_doctor(mem: Memory, *, fix: bool = False) -> dict[str, Any]:
    """Выполняет глубокий аудит базы и при fix=True безопасно исправляет найденные дефекты."""
    with mem.store._lock:
        integrity_row = mem.store.conn.execute("PRAGMA integrity_check").fetchone()
    integrity_val = str(integrity_row[0]) if integrity_row else "unknown"
    integrity_ok = integrity_val.lower() == "ok"

    fts_ok, fts_detail = _check_fts(mem)

    audit_chain: dict[str, Any] = {"ok": True, "checked": 0}
    if _table_exists(mem, "app_access_event"):
        from . import app_acl
        audit_chain = app_acl.verify_audit_chain(mem.store)

    from . import config
    dangling_links = _count_dangling_links(mem)
    missing_learned_at = _count_missing_learned_at(mem)
    bitemporal_on = config.mcp_bitemporal_enabled()
    audit_ok = bool(audit_chain.get("valid", audit_chain.get("ok", True)))

    needs_fix = (not fts_ok) or (dangling_links > 0) or (missing_learned_at > 0)
    snapshot_id: str | None = None
    actions: list[str] = []

    if fix and needs_fix:
        snap = mem.snapshot(
            name=f"pre-doctor-fix-{int(time.time())}",
            note="auto-snapshot before padam doctor --fix",
        )
        snapshot_id = snap.get("snapshot_id") or snap.get("id")

        if not fts_ok and _table_exists(mem, "memory_fts"):
            with mem.store._lock:
                mem.store.conn.execute("INSERT INTO memory_fts(memory_fts) VALUES('rebuild')")
                mem.store.conn.commit()
            actions.append("rebuilt_memory_fts")
            fts_ok, fts_detail = _check_fts(mem)

        if dangling_links > 0 and _table_exists(mem, "memory_link"):
            mem.store.execute(
                "DELETE FROM memory_link "
                "WHERE NOT EXISTS (SELECT 1 FROM memory m WHERE m.id = memory_link.src AND m.status != 'revoked') "
                "   OR NOT EXISTS (SELECT 1 FROM memory m WHERE m.id = memory_link.dst AND m.status != 'revoked')"
            )
            actions.append(f"removed_dangling_links:{dangling_links}")
            dangling_links = _count_dangling_links(mem)

        if missing_learned_at > 0:
            mem.store.execute(
                "UPDATE memory SET learned_at = created_at WHERE learned_at IS NULL OR learned_at = ''"
            )
            actions.append(f"backfilled_learned_at:{missing_learned_at}")
            missing_learned_at = _count_missing_learned_at(mem)

    issues_found = (
        (0 if integrity_ok else 1)
        + (0 if fts_ok else 1)
        + (0 if audit_ok else 1)
        + (1 if dangling_links > 0 else 0)
    )

    return {
        "ok": issues_found == 0,
        "issues_count": issues_found,
        "fix_applied": bool(fix and actions),
        "snapshot_id": snapshot_id,
        "actions": actions,
        "checks": {
            "sqlite_integrity": {"ok": integrity_ok, "result": integrity_val},
            "fts5": {"ok": fts_ok, "detail": fts_detail},
            "app_access_audit_chain": audit_chain,
            "dangling_links": dangling_links,
            "missing_learned_at": missing_learned_at,
        },
    }
