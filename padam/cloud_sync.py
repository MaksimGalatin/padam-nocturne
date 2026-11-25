# -*- coding: utf-8 -*-
"""Двусторонний мост синхронизации локального PADAM SQLite с облачным AIfa Memory MCP.

Подключается к https://aifa.works/api/mcp по личному Bearer-ключу владельца (amcp_...).
Правила безопасности:
- Весь сетевой трафик проверяется через padam.net_guard (запрет SSRF и локальных адресов).
- Перед отправкой в облако каждая запись проходит через safety.redact() (никаких ключей наружу).
- При загрузке из облака в локальную БД каждая запись проходит через guarded=True (4 кольца Agentic Shield).
- Дедупликация по SHA-256 текста в таблице ark_cloud_sync_map исключает повторные дубли.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from . import audit_chain, net_guard, safety

DEFAULT_CLOUD_MCP_URL = "https://aifa.works/api/mcp"

_DDL_STMTS = (
    """CREATE TABLE IF NOT EXISTS ark_cloud_sync_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        direction TEXT NOT NULL,
        local_id TEXT NOT NULL DEFAULT '',
        content_sha256 TEXT NOT NULL,
        synced_at REAL NOT NULL,
        UNIQUE(user_id, content_sha256)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_ark_cloud_sync_user ON ark_cloud_sync_map(user_id, synced_at)",
    """CREATE TABLE IF NOT EXISTS ark_cloud_sync_state (
        user_id TEXT PRIMARY KEY,
        last_direction TEXT NOT NULL DEFAULT '',
        last_scope TEXT NOT NULL DEFAULT 'global',
        last_pushed_ts TEXT NOT NULL DEFAULT '',
        last_pulled_ts REAL NOT NULL DEFAULT 0,
        updated_at REAL NOT NULL
    )""",
)


def _ensure_tables(memory) -> None:
    lock = getattr(memory.store, "_lock", None)
    if lock is not None:
        with lock:
            for stmt in _DDL_STMTS:
                memory.store.conn.execute(stmt)
            memory.store.conn.commit()
    else:
        for stmt in _DDL_STMTS:
            memory.store.conn.execute(stmt)
        memory.store.conn.commit()


def _sha256(text: str) -> str:
    return hashlib.sha256(str(text or "").strip().encode("utf-8")).hexdigest()


def _resolve_api_key(explicit_key: str | None = None) -> str:
    if explicit_key and str(explicit_key).strip():
        return str(explicit_key).strip()
    for env_name in ("PADAM_CLOUD_MCP_KEY", "AIFA_MCP_KEY", "AIFA_MCP_TOKEN"):
        val = os.environ.get(env_name, "").strip()
        if val:
            return val
    return ""


def _mcp_rpc(
    endpoint: str,
    api_key: str,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    timeout: float = 15.0,
) -> dict[str, Any]:
    url = str(endpoint or DEFAULT_CLOUD_MCP_URL).strip()
    # Защита от SSRF (разрешаем только публичный HTTPS; локальные адреса запрещены)
    net_guard.assert_url_allowed(url)
    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000) % 1_000_000,
        "method": method,
        "params": params or {},
    }
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "PADAM-NOCTURNE-CloudSync/0.9.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace").strip()
    if not body:
        return {}
    # Поддержка Streamable HTTP (SSE data: {...}) и чистого JSON
    if body.startswith("data:") or "\ndata:" in body:
        for line in reversed(body.splitlines()):
            line = line.strip()
            if line.startswith("data:"):
                cand = line[5:].strip()
                if cand and cand != "[DONE]":
                    return json.loads(cand)
    return json.loads(body)


def _extract_tool_text(rpc_resp: dict[str, Any]) -> str:
    if "error" in rpc_resp:
        err = rpc_resp["error"]
        msg = err.get("message") if isinstance(err, dict) else str(err)
        raise RuntimeError(f"Cloud MCP error: {msg}")
    res = rpc_resp.get("result") or {}
    if res.get("isError"):
        content = res.get("content") or []
        txt = content[0].get("text", "unknown error") if content else "unknown error"
        raise RuntimeError(f"Cloud MCP tool error: {txt}")
    parts = []
    for item in res.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(str(item.get("text") or ""))
    return "\n".join(parts)


def _parse_recent_records(raw_text: str) -> list[dict[str, str]]:
    """Извлекает текстовые записи из ответа memory_recent (JSON или fenced-строки)."""
    out: list[dict[str, str]] = []
    cleaned = raw_text.strip()
    if not cleaned:
        return out
    try:
        obj = json.loads(cleaned)
        items = obj if isinstance(obj, list) else (obj.get("records") or obj.get("items") or [])
        for it in items:
            if isinstance(it, dict):
                txt = str(it.get("content") or it.get("text") or "").strip()
                if txt:
                    out.append({"text": txt, "role": str(it.get("role") or "assistant")})
            elif isinstance(it, str) and it.strip():
                out.append({"text": it.strip(), "role": "assistant"})
        if out:
            return out
    except Exception:
        pass
    # Разбор текстового/маркдаун-формата (пропускаем теги ограждения <memory-data>)
    for line in cleaned.splitlines():
        s = line.strip()
        if not s or s.startswith("<memory-data") or s.startswith("</memory-data"):
            continue
        if s.startswith("Everything between the memory-data"):
            continue
        if s.startswith("- "):
            s = s[2:].strip()
        if len(s) >= 8:
            out.append({"text": s, "role": "assistant"})
    return out


def sync_status(memory) -> dict[str, Any]:
    """Возвращает состояние моста Local <-> Cloud Sync без сетевых вызовов."""
    _ensure_tables(memory)
    lock = getattr(memory.store, "_lock", None)

    def _read():
        row = memory.store.conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN direction='push' THEN 1 ELSE 0 END) AS pushed, "
            "SUM(CASE WHEN direction='pull' THEN 1 ELSE 0 END) AS pulled, "
            "MAX(synced_at) AS last_sync "
            "FROM ark_cloud_sync_map WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
        return dict(row) if row else {}

    def _read_state():
        r = memory.store.conn.execute(
            "SELECT last_direction, last_scope, last_pushed_ts, last_pulled_ts FROM ark_cloud_sync_state WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
        return dict(r) if r else {}
    data = _read() if lock is None else _with_lock(lock, _read)
    st_meta = _read_state() if lock is None else _with_lock(lock, _read_state)
    has_key = bool(_resolve_api_key())
    return {
        "ok": True,
        "endpoint": os.environ.get("PADAM_CLOUD_MCP_URL", DEFAULT_CLOUD_MCP_URL),
        "key_configured": has_key,
        "total_synced": int(data.get("total") or 0),
        "pushed_count": int(data.get("pushed") or 0),
        "pulled_count": int(data.get("pulled") or 0),
        "last_sync_ts": float(data.get("last_sync") or 0.0),
        "last_direction": str(st_meta.get("last_direction") or ""),
        "last_scope": str(st_meta.get("last_scope") or "global"),
        "last_pushed_ts": str(st_meta.get("last_pushed_ts") or ""),
    }


def _with_lock(lock, fn):
    with lock:
        return fn()


def sync_bidirectional(
    memory,
    *,
    api_key: str | None = None,
    endpoint: str | None = None,
    direction: str = "both",
    scope: str = "global",
    kind: str | None = None,
    limit: int = 20,
    dry_run: bool = False,
    rpc_fn=None,
) -> dict[str, Any]:
    """Выполняет безопасную двустороннюю синхронизацию Local SQLite <-> AIfa Memory Cloud MCP."""
    _ensure_tables(memory)
    key = _resolve_api_key(api_key)
    url = str(endpoint or os.environ.get("PADAM_CLOUD_MCP_URL") or DEFAULT_CLOUD_MCP_URL).strip()
    if not key and not dry_run:
        return {
            "ok": False,
            "error": "Cloud MCP key missing (pass api_key or set PADAM_CLOUD_MCP_KEY)",
            "endpoint": url,
        }
    direction = str(direction or "both").lower()
    if direction not in ("both", "push", "pull"):
        raise ValueError("direction must be one of: both, push, pull")
    lim = max(1, min(int(limit or 20), 50))
    call_rpc = rpc_fn or _mcp_rpc

    pushed = 0
    pulled = 0
    skipped = 0
    quarantined_pull = 0
    redacted_secrets_count = 0
    errors: list[str] = []

    lock = getattr(memory.store, "_lock", None)

    def _already_synced(digest: str) -> bool:
        def _q():
            r = memory.store.conn.execute(
                "SELECT 1 FROM ark_cloud_sync_map WHERE user_id = ? AND content_sha256 = ?",
                (memory.user_id, digest),
            ).fetchone()
            return r is not None
        return _q() if lock is None else _with_lock(lock, _q)

    def _mark_synced(dir_name: str, local_id: str, digest: str) -> None:
        if dry_run:
            return
        def _w():
            memory.store.conn.execute(
                "INSERT OR IGNORE INTO ark_cloud_sync_map (user_id, direction, local_id, content_sha256, synced_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (memory.user_id, dir_name, str(local_id), digest, time.time()),
            )
            memory.store.conn.commit()
        if lock is None:
            _w()
        else:
            _with_lock(lock, _w)

    # 1. PUSH: Локальные активные записи -> Облачный AIfa Memory MCP
    latest_pushed_ts = ""
    if direction in ("both", "push"):
        sql_p = "SELECT id, content, kind, origin, created_at FROM memory WHERE user_id = ? AND status = 'active'"
        params_p: list[Any] = [memory.user_id]
        sc_clean = str(scope or "").strip()
        if sc_clean and sc_clean != "all":
            sql_p += " AND scope = ?"
            params_p.append(sc_clean)
        k_clean = str(kind or "").strip()
        if k_clean:
            sql_p += " AND kind = ?"
            params_p.append(k_clean)
        sql_p += " ORDER BY created_at DESC LIMIT ?"
        params_p.append(lim)
        rows = memory.store.query(sql_p, tuple(params_p))
        for r in rows:
            raw_content = str(r["content"] or "").strip()
            if not raw_content:
                continue
            redacted, _masked = safety.redact(raw_content)
            if _masked:
                redacted_secrets_count += sum(_masked.values()) if isinstance(_masked, dict) else int(_masked or 0)
            c_ts = str(r["created_at"] or "")
            if c_ts > latest_pushed_ts:
                latest_pushed_ts = c_ts
            digest = _sha256(redacted)
            if _already_synced(digest):
                skipped += 1
                continue
            if dry_run:
                pushed += 1
                continue
            try:
                resp = call_rpc(
                    url,
                    key,
                    "tools/call",
                    {
                        "name": "memory_write",
                        "arguments": {
                            "text": redacted[:7500],
                            "role": "user" if str(r["origin"] or "") == "user" else "assistant",
                            "origin": "user" if str(r["origin"] or "") == "user" else "agent",
                        },
                    },
                )
                _extract_tool_text(resp)
                _mark_synced("push", str(r["id"]), digest)
                pushed += 1
            except Exception as exc:
                errors.append(f"push:{r['id']}: {exc}")

    # 2. PULL: Облачные свежие записи -> Локальный PADAM SQLite (через 4 кольца Agentic Shield)
    if direction in ("both", "pull"):
        if dry_run and not key:
            pass
        else:
            try:
                resp = call_rpc(
                    url,
                    key,
                    "tools/call",
                    {"name": "memory_recent", "arguments": {"limit": lim}},
                )
                raw_txt = _extract_tool_text(resp)
                for item in _parse_recent_records(raw_txt):
                    txt = item["text"]
                    digest = _sha256(txt)
                    if _already_synced(digest):
                        skipped += 1
                        continue
                    if dry_run:
                        pulled += 1
                        continue
                    res = memory.remember(
                        txt,
                        kind="fact",
                        scope="cloud_sync",
                        origin="agent",
                        guarded=True,
                        agent_id="aifa_cloud",
                    )
                    if getattr(res, "status", "") == "quarantined":
                        quarantined_pull += 1
                    else:
                        pulled += 1
                    _mark_synced("pull", getattr(res, "id", ""), digest)
            except Exception as exc:
                errors.append(f"pull: {exc}")

    if not dry_run:
        def _upd_state():
            now_t = time.time()
            memory.store.conn.execute(
                "INSERT INTO ark_cloud_sync_state (user_id, last_direction, last_scope, last_pushed_ts, last_pulled_ts, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET "
                "last_direction=excluded.last_direction, last_scope=excluded.last_scope, "
                "last_pushed_ts=CASE WHEN excluded.last_pushed_ts!='' THEN excluded.last_pushed_ts ELSE ark_cloud_sync_state.last_pushed_ts END, "
                "last_pulled_ts=CASE WHEN excluded.last_pulled_ts>0 THEN excluded.last_pulled_ts ELSE ark_cloud_sync_state.last_pulled_ts END, "
                "updated_at=excluded.updated_at",
                (memory.user_id, direction, str(scope or "global"), latest_pushed_ts, now_t if pulled else 0.0, now_t),
            )
            memory.store.conn.commit()
        try:
            _upd_state() if lock is None else _with_lock(lock, _upd_state)
        except Exception:
            pass
    if not dry_run and (pushed or pulled):
        try:
            audit_chain.append_audit(
                memory,
                "cloud_sync",
                {
                    "direction": direction,
                    "pushed": pushed,
                    "pulled": pulled,
                    "quarantined_pull": quarantined_pull,
                    "skipped": skipped,
                    "errors": len(errors),
                },
                agent_id="cloud_sync",
            )
        except Exception:
            pass

    return {
        "ok": len(errors) == 0,
        "endpoint": url,
        "direction": direction,
        "dry_run": dry_run,
        "pushed": pushed,
        "pulled": pulled,
        "quarantined_pull": quarantined_pull,
        "skipped": skipped,
        "redacted_secrets_count": redacted_secrets_count,
        "scope": str(scope or "global"),
        "errors": errors,
    }


def get_cloud_sync_status(memory) -> dict[str, Any]:
    """Возвращает статус двустороннего облачного моста с совместимыми ключами для API/UI."""
    st = sync_status(memory)
    st["has_api_key"] = bool(st.get("key_configured"))
    st["synced_records"] = int(st.get("total_synced") or 0)
    return st


def push_local_to_cloud(
    memory,
    *,
    api_key: str | None = None,
    endpoint: str | None = None,
    scope: str = "global",
    limit: int = 20,
    dry_run: bool = False,
    rpc_fn=None,
) -> dict[str, Any]:
    res = sync_bidirectional(
        memory,
        api_key=api_key,
        endpoint=endpoint,
        direction="push",
        scope=scope,
        limit=limit,
        dry_run=dry_run,
        rpc_fn=rpc_fn,
    )
    if not res.get("ok") and "missing" in str(res.get("error") or "").lower():
        res["error"] = "missing_api_key"
    return res


def pull_cloud_to_local(
    memory,
    *,
    api_key: str | None = None,
    endpoint: str | None = None,
    scope: str = "global",
    limit: int = 20,
    dry_run: bool = False,
    rpc_fn=None,
) -> dict[str, Any]:
    res = sync_bidirectional(
        memory,
        api_key=api_key,
        endpoint=endpoint,
        direction="pull",
        scope=scope,
        limit=limit,
        dry_run=dry_run,
        rpc_fn=rpc_fn,
    )
    if not res.get("ok") and "missing" in str(res.get("error") or "").lower():
        res["error"] = "missing_api_key"
    return res
