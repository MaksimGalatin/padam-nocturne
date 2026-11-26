# -*- coding: utf-8 -*-
"""Контроль траекторий и Taint Tracking (Control Flow Integrity) для PADAM Agentic Shield.

Решает проблему медленных многошаговых атак, которые обходят частотный rate-limiter:
например, агент в 10:00 прочитал `.env` или `id_rsa` (`TAINT_SENSITIVE_READ`),
а в 12:30 вызвал сетевой инструмент (`fetch`, `email_send`, `slack_post`) на внешний домен.
Все переходы сохраняются в SQLite (`shield_taint_edges`) для аудита и визуального графа атак
в PADAM Studio.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import urllib.parse
import uuid
from typing import Any

from .. import audit_chain

_TAINT_DDL = """
CREATE TABLE IF NOT EXISTS shield_taint_sessions (
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    taints_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, session_id)
);
CREATE TABLE IF NOT EXISTS shield_taint_edges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    step_seq INTEGER NOT NULL,
    source_node TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL,
    taints_added_json TEXT NOT NULL,
    active_taints_json TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_taint_edges_sess ON shield_taint_edges (user_id, session_id, step_seq);
"""

# Файлы и ресурсы, чтение которых немедленно вешает метку TAINT_SENSITIVE_READ
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:"
    r"(?:^|[/\\])\.env(?:\.[a-z0-9_-]+)?$|"
    r"(?:^|[/\\])id_(?:rsa|ed25519|ecdsa)(?:\.pub)?$|"
    r"(?:^|[/\\])\.aws[/\\]credentials|"
    r"(?:^|[/\\])\.ssh[/\\]|"
    r"wallet(?:s)?\.json|seed[_-]?phrase|private[_-]?key|"
    r"\.(?:pem|key|p12|pfx|kdbx)$|"
    r"secrets?\.(?:json|yaml|yml|toml|txt)|"
    r"service[_-]?account\.json|keyvault|"
    r"ключ|парол|сид-?фраз"
    r")"
)

_PRIVILEGED_TOOL_RE = re.compile(
    r"(?i)(?:keyvault|secret|credential|wallet|vault|decrypt|export_key|read_secret|dump_env)"
)
_UNTRUSTED_READ_TOOL_RE = re.compile(
    r"(?i)(?:web_fetch|fetch_url|browse|read_email|imap|inbox|parse_pdf|scrape|read_webpage|rag_ingest|external_doc)"
)
_NETWORK_EXFIL_TOOL_RE = re.compile(
    r"(?i)(?:fetch|http|curl|wget|request|post|webhook|email_send|send_mail|slack_post|telegram_send|upload|dns|outbound|send_message)"
)
_DANGEROUS_EXEC_TOOL_RE = re.compile(
    r"(?i)(?:bash|shell|exec|terminal|powershell|cmd|run_command|python_exec|eval|write_system|transfer|approve|sign_tx)"
)


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_taint_tables(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_taint_ready", False):
        return
    with store._lock:
        store.conn.executescript(_TAINT_DDL)
        store.conn.commit()
        store._shield_taint_ready = True


def _extract_host(target: str) -> str:
    t = str(target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return urllib.parse.urlsplit(t).netloc.lower().split(":")[0]
    m = re.search(r"\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b", t)
    return m.group(1).lower() if m else ""


def _allowed_domains_for(memory: Any) -> set[str]:
    from .. import agentic_shield as _ash

    rows = _ash.list_allowlist(memory)
    return {str(r.get("value") or "").lower() for r in rows if r.get("entry_type") == "domain"}


def _is_domain_allowed(host: str, allowed: set[str]) -> bool:
    if not host:
        return False
    return any(host == d or host.endswith("." + d) for d in allowed)


def get_session_taints(memory: Any, session_id: str) -> list[str]:
    """Возвращает список активных taint-меток сессии."""
    ensure_taint_tables(memory)
    sid = str(session_id or "default").strip()[:96]
    row = memory.store.one(
        "SELECT taints_json FROM shield_taint_sessions WHERE user_id = ? AND session_id = ?",
        (memory.user_id, sid),
    )
    if not row:
        return []
    try:
        data = json.loads(row["taints_json"] or "[]")
        return sorted({str(x) for x in data if x})
    except Exception:
        return []


def clear_session_taints(memory: Any, session_id: str) -> dict[str, Any]:
    """Сбрасывает taint-метки сессии (для нового чистого цикла после проверки владельцем)."""
    ensure_taint_tables(memory)
    sid = str(session_id or "default").strip()[:96]
    with memory.store._lock:
        memory.store.conn.execute(
            "DELETE FROM shield_taint_sessions WHERE user_id = ? AND session_id = ?",
            (memory.user_id, sid),
        )
        memory.store.conn.commit()
    return {"ok": True, "session_id": sid, "active_taints": []}


def observe_tool_step(
    memory: Any,
    *,
    session_id: str,
    tool_name: str,
    target: str = "",
    payload: str = "",
    agent_id: str = "agent",
    source_node: str = "agent_step",
    auto_trip_kill_switch: bool = True,
) -> dict[str, Any]:
    """Регистрирует шаг агента в графе траекторий и проверяет запрещённые переходы Taint Tracking."""
    ensure_taint_tables(memory)
    sid = str(session_id or "default").strip()[:96]
    tname = str(tool_name or "unknown").strip()[:80]
    tgt = str(target or "").strip()[:240]
    aid = str(agent_id or "agent").strip()[:80]
    combined = f"{tgt}\n{payload}"

    active = set(get_session_taints(memory, sid))
    added: list[str] = []

    # 1. Навешивание меток заражения при доступе к чувствительным или недоверенным источникам
    if _SENSITIVE_PATH_RE.search(tgt) or _SENSITIVE_PATH_RE.search(str(payload or "")):
        if "TAINT_SENSITIVE_READ" not in active:
            added.append("TAINT_SENSITIVE_READ")
            active.add("TAINT_SENSITIVE_READ")
    if _PRIVILEGED_TOOL_RE.search(tname):
        if "TAINT_PRIVILEGED_SECRET" not in active:
            added.append("TAINT_PRIVILEGED_SECRET")
            active.add("TAINT_PRIVILEGED_SECRET")
    if _UNTRUSTED_READ_TOOL_RE.search(tname):
        if "TAINT_UNTRUSTED_INPUT" not in active:
            added.append("TAINT_UNTRUSTED_INPUT")
            active.add("TAINT_UNTRUSTED_INPUT")

    # 2. Проверка матрицы запрещённых переходов (Control Flow Integrity)
    verdict = "allow"
    reason = "clean_transition"
    allowed_domains = _allowed_domains_for(memory)
    host = _extract_host(tgt) or _extract_host(combined)

    is_net_sink = bool(_NETWORK_EXFIL_TOOL_RE.search(tname))
    is_exec_sink = bool(_DANGEROUS_EXEC_TOOL_RE.search(tname))

    if ({"TAINT_SENSITIVE_READ", "TAINT_PRIVILEGED_SECRET"} & active) and is_net_sink:
        if not host or not _is_domain_allowed(host, allowed_domains):
            verdict = "block"
            reason = (
                f"taint_exfiltration_blocked: сессия имеет метку {sorted(active)} "
                f"и пытается вызвать сетевой инструмент {tname} на недоверенный адрес ({host or 'unknown'})"
            )
    elif "TAINT_UNTRUSTED_INPUT" in active and is_exec_sink:
        verdict = "block"
        reason = (
            f"taint_untrusted_to_exec: после чтения внешнего источника (TAINT_UNTRUSTED_INPUT) "
            f"заблокирован опасный вызов {tname}"
        )

    now = _utc_iso()
    edge_id = f"te-{uuid.uuid4().hex[:12]}"
    with memory.store._lock:
        seq_row = memory.store.one(
            "SELECT COALESCE(MAX(step_seq), 0) AS mx FROM shield_taint_edges WHERE user_id = ? AND session_id = ?",
            (memory.user_id, sid),
        )
        next_seq = int(seq_row["mx"] or 0) + 1 if seq_row else 1
        memory.store.conn.execute(
            """INSERT INTO shield_taint_sessions (user_id, session_id, agent_id, taints_json, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(user_id, session_id) DO UPDATE SET
                   agent_id=excluded.agent_id, taints_json=excluded.taints_json, updated_at=excluded.updated_at""",
            (memory.user_id, sid, aid, json.dumps(sorted(active)), now),
        )
        memory.store.conn.execute(
            """INSERT INTO shield_taint_edges
               (id, user_id, session_id, agent_id, step_seq, source_node, tool_name, target,
                taints_added_json, active_taints_json, verdict, reason, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                edge_id, memory.user_id, sid, aid, next_seq, str(source_node or "agent")[:64],
                tname, tgt, json.dumps(added), json.dumps(sorted(active)), verdict, reason[:280], now,
            ),
        )
        memory.store.conn.commit()

    kill_tripped = False
    if verdict == "block":
        try:
            audit_chain.append_audit(
                memory,
                "taint_flow_blocked",
                {"edge_id": edge_id, "session_id": sid, "tool": tname, "taints": sorted(active), "reason": reason[:200]},
                agent_id=aid,
            )
        except Exception:
            pass
        if auto_trip_kill_switch and ("TAINT_SENSITIVE_READ" in active or "TAINT_PRIVILEGED_SECRET" in active):
            from .. import agentic_shield as _ash

            _ash.trip_kill_switch(
                memory,
                reason=f"Taint Tracking: блокировка эксфильтрации ({tname} -> {host or 'external'})",
                agent_id=aid,
                block_writes=True,
            )
            kill_tripped = True

    return {
        "ok": True,
        "edge_id": edge_id,
        "session_id": sid,
        "step_seq": next_seq,
        "tool_name": tname,
        "target": tgt,
        "allowed": verdict == "allow",
        "verdict": verdict,
        "reason": reason,
        "taints_added": added,
        "active_taints": sorted(active),
        "kill_switch_tripped": kill_tripped,
    }


def get_session_graph(memory: Any, *, session_id: str | None = None, limit: int = 80) -> dict[str, Any]:
    """Возвращает узлы и рёбра графа траекторий для визуализации в PADAM Studio."""
    ensure_taint_tables(memory)
    lim = max(1, min(300, int(limit)))
    if session_id:
        rows = memory.store.query(
            "SELECT * FROM shield_taint_edges WHERE user_id = ? AND session_id = ? ORDER BY step_seq ASC LIMIT ?",
            (memory.user_id, str(session_id).strip(), lim),
        )
    else:
        rows = memory.store.query(
            "SELECT * FROM shield_taint_edges WHERE user_id = ? ORDER BY created_at DESC, step_seq DESC LIMIT ?",
            (memory.user_id, lim),
        )
        rows = list(reversed(rows))

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    prev_id_by_sess: dict[str, str] = {}
    blocked_count = 0

    for r in rows:
        d = dict(r)
        taints_added = json.loads(d.get("taints_added_json") or "[]")
        active_taints = json.loads(d.get("active_taints_json") or "[]")
        if d["verdict"] == "block":
            blocked_count += 1
        node = {
            "id": d["id"],
            "session_id": d["session_id"],
            "agent_id": d["agent_id"],
            "step_seq": d["step_seq"],
            "source_node": d["source_node"],
            "tool_name": d["tool_name"],
            "target": d["target"],
            "taints_added": taints_added,
            "active_taints": active_taints,
            "verdict": d["verdict"],
            "reason": d["reason"],
            "created_at": d["created_at"],
        }
        nodes.append(node)
        prev = prev_id_by_sess.get(d["session_id"])
        if prev:
            edges.append({
                "from": prev,
                "to": d["id"],
                "tainted": bool(active_taints),
                "blocked": d["verdict"] == "block",
            })
        prev_id_by_sess[d["session_id"]] = d["id"]

    sessions_rows = memory.store.query(
        "SELECT session_id, agent_id, taints_json, updated_at FROM shield_taint_sessions WHERE user_id = ? ORDER BY updated_at DESC LIMIT 30",
        (memory.user_id,),
    )
    sessions = [
        {
            "session_id": sr["session_id"],
            "agent_id": sr["agent_id"],
            "active_taints": json.loads(sr["taints_json"] or "[]"),
            "updated_at": sr["updated_at"],
        }
        for sr in sessions_rows
    ]
    return {
        "ok": True,
        "nodes": nodes,
        "edges": edges,
        "sessions": sessions,
        "total_steps": len(nodes),
        "blocked_steps": blocked_count,
    }
