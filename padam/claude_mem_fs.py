"""Бэкенд для нативного Memory Tool Claude (/memories).

Поддерживает команды `view`, `create`, `str_replace`, `insert`, `delete`, `rename`
над виртуальной иерархией `/memories/...`, отображая каждый файл на
версионированную запись в SQLite (`memory`), с защитой от path traversal,
карантином при `guarded=True`, ограждением содержимого в `safety.fence`
и настоящим криптографическим забвением (`mem.forget`) на `delete`.

По умолчанию выключено (PADAM_CLAUDE_MEMORY_FS=0).
"""
from __future__ import annotations

import posixpath
from datetime import datetime, timezone
from typing import Any

from . import config, safety
from .memory import Memory


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_memory_path(raw_path: str) -> str:
    if not isinstance(raw_path, str) or "\x00" in raw_path:
        raise ValueError("Invalid /memories path")
    p = raw_path.strip().replace("\\", "/")
    if not p.startswith("/memories"):
        raise ValueError("Path must be inside /memories")
    parts = [seg for seg in p.split("/") if seg and seg != "."]
    if ".." in parts:
        raise ValueError("Path traversal ('..') is forbidden")
    norm = "/" + posixpath.normpath("/".join(parts)).lstrip("/")
    if norm != "/memories" and not norm.startswith("/memories/"):
        raise ValueError("Path escapes /memories root")
    return norm


def _ensure_fs_table(mem: Memory) -> None:
    mem.store.execute(
        """CREATE TABLE IF NOT EXISTS claude_mem_fs_files (
               user_id TEXT NOT NULL,
               path TEXT NOT NULL,
               memory_id TEXT NOT NULL,
               version INTEGER NOT NULL DEFAULT 1,
               updated_at TEXT NOT NULL,
               PRIMARY KEY (user_id, path)
           )"""
    )


def _get_file_row(mem: Memory, norm_path: str) -> dict[str, Any] | None:
    _ensure_fs_table(mem)
    row = mem.store.one(
        """SELECT f.path, f.memory_id, f.version, f.updated_at, m.content, m.status
           FROM claude_mem_fs_files f
           JOIN memory m ON m.id = f.memory_id
           WHERE f.user_id = ? AND f.path = ? AND m.status = 'active'""",
        (mem.user_id, norm_path),
    )
    return dict(row) if row is not None else None


def _write_new_version(mem: Memory, norm_path: str, content: str, *, guarded: bool = True, agent_id: str = "claude") -> dict[str, Any]:
    _ensure_fs_table(mem)
    prev = mem.store.one(
        "SELECT memory_id, version FROM claude_mem_fs_files WHERE user_id = ? AND path = ?",
        (mem.user_id, norm_path),
    )
    prev_ver = int(prev["version"]) if prev is not None else 0
    scope = "memories:" + posixpath.dirname(norm_path).lstrip("/")
    status_lbl, rec_id = mem.remember(
        content,
        kind="fact",
        scope=scope,
        origin="agent" if guarded else "user",
        guarded=guarded,
        agent_id=agent_id,
    )
    if status_lbl == "quarantined":
        return {"status": "quarantined", "path": norm_path, "memory_id": rec_id}

    if prev is not None and prev["memory_id"] != rec_id:
        mem.store.execute(
            "UPDATE memory SET status = 'superseded', superseded_by = ? WHERE id = ?",
            (rec_id, prev["memory_id"]),
        )
    mem.store.execute(
        """INSERT INTO claude_mem_fs_files (user_id, path, memory_id, version, updated_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(user_id, path) DO UPDATE SET
               memory_id = excluded.memory_id,
               version = excluded.version,
               updated_at = excluded.updated_at""",
        (mem.user_id, norm_path, rec_id, prev_ver + 1, _utc_now()),
    )
    return {"status": "ok", "path": norm_path, "memory_id": rec_id, "version": prev_ver + 1}


def execute_memory_command(
    mem: Memory,
    payload: dict[str, Any],
    *,
    guarded: bool = True,
    agent_id: str = "claude",
    force: bool = False,
) -> dict[str, Any]:
    if not force and not config.mcp_claude_memory_fs_enabled():
        return {"enabled": False, "error": "Claude Memory FS is disabled (PADAM_CLAUDE_MEMORY_FS=0)"}

    cmd = str(payload.get("command") or "").strip().lower()
    if cmd == "view":
        norm = normalize_memory_path(str(payload.get("path") or "/memories"))
        row = _get_file_row(mem, norm)
        if row is not None:
            lines = (row["content"] or "").splitlines()
            vr = payload.get("view_range")
            start = 1
            end = len(lines)
            if isinstance(vr, (list, tuple)) and len(vr) == 2:
                start = max(1, int(vr[0]))
                end = min(len(lines), int(vr[1])) if int(vr[1]) != -1 else len(lines)
            numbered = "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1))
            return {
                "enabled": True,
                "type": "file",
                "path": norm,
                "version": row["version"],
                "content": safety.fence(numbered),
            }
        # Иначе пробуем как директорию
        _ensure_fs_table(mem)
        prefix = "/memories/" if norm == "/memories" else norm + "/"
        rows = mem.store.query(
            """SELECT f.path, LENGTH(m.content) AS size_bytes
               FROM claude_mem_fs_files f
               JOIN memory m ON m.id = f.memory_id
               WHERE f.user_id = ? AND m.status = 'active' AND (f.path = ? OR f.path LIKE ?)
               ORDER BY f.path""",
            (mem.user_id, norm, prefix + "%"),
        )
        entries = [{"path": r["path"], "size": int(r["size_bytes"] or 0)} for r in rows]
        listing = "\n".join(f"{e['size']}\t{e['path']}" for e in entries) or "(empty)"
        return {
            "enabled": True,
            "type": "directory",
            "path": norm,
            "entries": entries,
            "content": safety.fence(listing),
        }

    if cmd == "create":
        norm = normalize_memory_path(str(payload.get("path") or ""))
        if norm == "/memories":
            raise ValueError("Cannot create file at /memories root")
        if _get_file_row(mem, norm) is not None:
            raise FileExistsError(f"File already exists: {norm}")
        res = _write_new_version(mem, norm, str(payload.get("file_text") or ""), guarded=guarded, agent_id=agent_id)
        return {"enabled": True, **res}

    if cmd == "str_replace":
        norm = normalize_memory_path(str(payload.get("path") or ""))
        row = _get_file_row(mem, norm)
        if row is None:
            raise FileNotFoundError(f"File not found: {norm}")
        old_s = str(payload.get("old_str") or "")
        new_s = str(payload.get("new_str") or "")
        body = row["content"] or ""
        cnt = body.count(old_s) if old_s else 0
        if cnt == 0:
            raise ValueError("old_str not found in file")
        if cnt > 1:
            raise ValueError(f"old_str appears {cnt} times (must be unique)")
        res = _write_new_version(mem, norm, body.replace(old_s, new_s, 1), guarded=guarded, agent_id=agent_id)
        return {"enabled": True, **res}

    if cmd == "insert":
        norm = normalize_memory_path(str(payload.get("path") or ""))
        row = _get_file_row(mem, norm)
        if row is None:
            raise FileNotFoundError(f"File not found: {norm}")
        lines = (row["content"] or "").splitlines()
        ins_line = max(0, min(len(lines), int(payload.get("insert_line") or 0)))
        ins_text = str(payload.get("insert_text") or "")
        new_lines = lines[:ins_line] + ins_text.splitlines() + lines[ins_line:]
        res = _write_new_version(mem, norm, "\n".join(new_lines), guarded=guarded, agent_id=agent_id)
        return {"enabled": True, **res}

    if cmd == "delete":
        norm = normalize_memory_path(str(payload.get("path") or ""))
        if norm == "/memories":
            raise ValueError("Cannot delete /memories root")
        _ensure_fs_table(mem)
        rows = mem.store.query(
            "SELECT path, memory_id FROM claude_mem_fs_files WHERE user_id = ? AND (path = ? OR path LIKE ?)",
            (mem.user_id, norm, norm + "/%"),
        )
        if not rows:
            raise FileNotFoundError(f"Path not found: {norm}")
        forgotten: list[dict[str, Any]] = []
        for r in rows:
            fg = mem.revoke(r["memory_id"])
            mem.store.execute("DELETE FROM claude_mem_fs_files WHERE user_id = ? AND path = ?", (mem.user_id, r["path"]))
            forgotten.append({"path": r["path"], "memory_id": r["memory_id"], "receipt": fg})
        return {"enabled": True, "status": "deleted", "forgotten": forgotten}

    if cmd == "rename":
        old_p = normalize_memory_path(str(payload.get("old_path") or ""))
        new_p = normalize_memory_path(str(payload.get("new_path") or ""))
        if old_p == "/memories" or new_p == "/memories":
            raise ValueError("Cannot rename /memories root")
        if _get_file_row(mem, old_p) is None:
            raise FileNotFoundError(f"Source file not found: {old_p}")
        if _get_file_row(mem, new_p) is not None:
            raise FileExistsError(f"Destination already exists: {new_p}")
        mem.store.execute(
            "UPDATE claude_mem_fs_files SET path = ?, updated_at = ? WHERE user_id = ? AND path = ?",
            (new_p, _utc_now(), mem.user_id, old_p),
        )
        return {"enabled": True, "status": "renamed", "old_path": old_p, "new_path": new_p}

    raise ValueError(f"Unsupported memory tool command: {cmd}")
