# -*- coding: utf-8 -*-
"""Привязка фактов памяти к исходному коду и детектор устаревания по SHA-256 (Фишка 4).

Зачем: в разработке факт вида «функция X делает Y» часто устаревает в момент изменения
файла на диске. Якорь фиксирует `file_path` и `SHA-256` содержимого файла на момент
записи и мгновенно выявляет устаревшие факты без сети.
"""
from __future__ import annotations

import ast
import hashlib
import re
import time
from pathlib import Path
from typing import Any

from . import ark, audit_chain

_CODE_ANCHOR_STMTS = (
    """CREATE TABLE IF NOT EXISTS ark_code_anchor (
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
    )""",
    "CREATE INDEX IF NOT EXISTS idx_ark_code_anchor_mem ON ark_code_anchor(user_id, memory_id)",
)


def _extract_symbol_hash(target: Path, symbol_name: str) -> str:
    """Вычисляет SHA-256 тела конкретной функции/класса (AST для .py или декларация блока)."""
    sym = str(symbol_name or "").strip()
    if not sym:
        return ""
    try:
        src = target.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    lines = src.splitlines()
    if target.suffix == ".py":
        try:
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == sym:
                    start = max(0, int(node.lineno) - 1)
                    end = int(getattr(node, "end_lineno", node.lineno))
                    chunk = "\n".join(lines[start:end])
                    return hashlib.sha256(chunk.encode("utf-8")).hexdigest()
        except SyntaxError:
            pass
    pat = re.compile(rf"(?:def|async\s+def|class|function|const|let|fn|fun|struct|impl)\s+{re.escape(sym)}\b")
    for i, ln in enumerate(lines):
        if pat.search(ln):
            chunk = "\n".join(lines[i : min(len(lines), i + 80)])
            return hashlib.sha256(chunk.encode("utf-8")).hexdigest()
    return ""


def _ensure(memory) -> None:
    ark._ensure_tables(memory)
    with memory.store._lock:
        for stmt in _CODE_ANCHOR_STMTS:
            memory.store.conn.execute(stmt)
        cols = {r[1] for r in memory.store.conn.execute('PRAGMA table_info(ark_code_anchor)').fetchall()}
        if 'symbol_sha256' not in cols:
            memory.store.conn.execute("ALTER TABLE ark_code_anchor ADD COLUMN symbol_sha256 TEXT NOT NULL DEFAULT ''")
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
    with memory.store._lock:
        cur = memory.store.conn.execute(
            "INSERT INTO ark_code_anchor (user_id, memory_id, file_path, symbol_name, file_sha256, symbol_sha256, status, stale_reason, checked_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'fresh', '', ?, ?)",
            (memory.user_id, str(memory_id), rel_norm, str(symbol_name or "")[:120], digest, _extract_symbol_hash(target, symbol_name), now, now),
        )
        memory.store.conn.commit()
        aid = cur.lastrowid
    return {
        "ok": True,
        "anchor_id": aid,
        "memory_id": str(memory_id),
        "file_path": rel_norm,
        "symbol_name": str(symbol_name or ""),
        "file_sha256": digest,
        "symbol_sha256": _extract_symbol_hash(target, symbol_name),
        "status": "fresh",
    }


def get_pins_for_memory_ids(
    memory,
    memory_ids: list[str],
    *,
    repo_root: str | Path = ".",
) -> dict[str, list[dict[str, Any]]]:
    """Возвращает живой статус кодовых якорей для набора memory_id (свежий или устарел)."""
    clean_ids = [str(mid) for mid in memory_ids if mid]
    if not clean_ids:
        return {}
    try:
        with memory.store._lock:
            has_tbl = memory.store.conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ark_code_anchor'"
            ).fetchone()
            if not has_tbl:
                return {}
            placeholders = ",".join("?" * len(clean_ids))
            rows = memory.store.conn.execute(
                f"SELECT anchor_id, memory_id, file_path, symbol_name, file_sha256, symbol_sha256 "
                f"FROM ark_code_anchor WHERE user_id = ? AND memory_id IN ({placeholders}) "
                f"ORDER BY anchor_id DESC",
                (memory.user_id, *clean_ids),
            ).fetchall()
    except Exception:
        return {}
    if not rows:
        return {}
    root = Path(repo_root).resolve()
    sha_cache: dict[str, tuple[str, str]] = {}
    out: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        rel = str(r["file_path"])
        if rel not in sha_cache:
            try:
                target = _safe_resolve_under_root(root, rel)
                if not target.is_file():
                    sha_cache[rel] = ("file_missing", "")
                else:
                    sha_cache[rel] = ("", hashlib.sha256(target.read_bytes()).hexdigest())
            except Exception:
                sha_cache[rel] = ("invalid_path", "")
        err_reason, cur_sha = sha_cache[rel]
        if err_reason:
            status = "stale"
            reason = err_reason
        elif cur_sha != str(r["file_sha256"]):
            sym_name = str(r["symbol_name"] or "")
            old_sym_sha = str(r["symbol_sha256"] or "") if "symbol_sha256" in r.keys() else ""
            if sym_name and old_sym_sha:
                cur_sym_sha = _extract_symbol_hash(_safe_resolve_under_root(root, rel), sym_name)
                if cur_sym_sha and cur_sym_sha == old_sym_sha:
                    status = "symbol_fresh"
                    reason = "other_lines_changed"
                else:
                    status = "stale"
                    reason = "file_hash_changed"
            else:
                status = "stale"
                reason = "file_hash_changed"
        else:
            status = "fresh"
            reason = ""
        out.setdefault(str(r["memory_id"]), []).append({
            "anchor_id": int(r["anchor_id"]),
            "file_path": rel,
            "symbol_name": str(r["symbol_name"] or ""),
            "status": status,
            "reason": reason,
        })
    return out


def check_stale_anchors(memory, *, repo_root: str | Path = ".") -> dict[str, Any]:
    """Проверяет все привязки к файлам в `repo_root` и отмечает те, чей файл изменён или удалён."""
    _ensure(memory)
    root = Path(repo_root).resolve()
    with memory.store._lock:
        rows = memory.store.conn.execute(
            "SELECT anchor_id, memory_id, file_path, symbol_name, file_sha256, symbol_sha256, status FROM ark_code_anchor WHERE user_id = ? ORDER BY anchor_id ASC",
            (memory.user_id,),
        ).fetchall()

    now = time.time()
    stale_items: list[dict[str, Any]] = []
    fresh_count = 0
    updates: list[tuple[str, str, float, int]] = []

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
                    sym_name = str(r["symbol_name"] or "")
                    old_sym_sha = str(r["symbol_sha256"] or "") if "symbol_sha256" in r.keys() else ""
                    if sym_name and old_sym_sha:
                        cur_sym_sha = _extract_symbol_hash(target, sym_name)
                        if cur_sym_sha and cur_sym_sha == old_sym_sha:
                            reason = "other_lines_changed"
                            new_status = "symbol_fresh"
                        else:
                            reason = "file_hash_changed"
                            new_status = "stale"
                    else:
                        reason = "file_hash_changed"
                        new_status = "stale"
                else:
                    reason = ""
                    new_status = "fresh"

        updates.append((new_status, reason, now, aid))
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

    with memory.store._lock:
        for upd in updates:
            memory.store.conn.execute(
                "UPDATE ark_code_anchor SET status = ?, stale_reason = ?, checked_at = ? WHERE anchor_id = ?",
                upd,
            )
        memory.store.conn.commit()

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


def verify_claim_with_memory_and_code(
    memory,
    claim: str,
    *,
    scope: str = "global",
    repo_root: str | Path = ".",
    limit: int = 8,
) -> dict[str, Any]:
    """Проверяет утверждение агента: ищет подтверждения, противоречия и свежесть кодовых якорей."""
    q = str(claim or "").strip()
    if not q:
        raise ValueError("claim must be non-empty")
    hits = memory.recall(q, scope=scope, limit=max(1, min(int(limit or 8), 20)))
    mids = [h.id for h in hits]
    pins_map = get_pins_for_memory_ids(memory, mids, repo_root=repo_root)
    stale_pins: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    for h in hits:
        pins = pins_map.get(h.id, [])
        for p in pins:
            if p.get("status") == "stale":
                stale_pins.append({"memory_id": h.id, **p})
        if getattr(h, "conflict", False) or h.kind == "contradiction":
            conflicts.append({"memory_id": h.id, "content": (h.content or "")[:240], "kind": h.kind})
        evidence.append({
            "id": h.id,
            "kind": h.kind,
            "score": round(float(h.score), 4),
            "trace": h.explain_trace(),
            "pins": pins,
            "snippet": (h.content or "")[:240],
        })

    if stale_pins:
        verdict = "stale_code_drift"
    elif conflicts:
        verdict = "conflict_detected"
    elif evidence and float(evidence[0]["score"]) >= 0.01:
        verdict = "verified"
    else:
        verdict = "unverified"

    return {
        "ok": True,
        "claim": q[:260],
        "scope": scope,
        "verdict": verdict,
        "evidence_count": len(evidence),
        "stale_pins_count": len(stale_pins),
        "conflicts_count": len(conflicts),
        "stale_pins": stale_pins,
        "conflicts": conflicts,
        "evidence": evidence[:5],
    }
