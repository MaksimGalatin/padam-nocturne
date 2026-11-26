# -*- coding: utf-8 -*-
"""Криминалистическая реконструкция инцидентов (Forensic Timeline & Root-Cause Replay).

Сводит события из всех локальных таблиц PADAM Agentic Shield (`shield_taint_edges`,
`shield_events`, `shield_outbound_queue`, `audit_chain`, `shield_crescendo_turns`)
в единую хронологическую ленту «Первоисточник -> Распространение -> Блокировка»,
вычисляет корень заражения (root cause), проверяет целостность SHA-256 цепи аудита
и Tamper-Proof пломбы БД, маппит инцидент на MITRE ATLAS / OWASP Agentic Top 10
и формирует криптографически подписанный отчёт (JSON + Markdown).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional

from .. import agentic_shield as _ash
from .. import audit_chain as _audit_chain
from .. import integrity as _integrity
from .tamper_seal import verify_shield_integrity


_MITRE_MAP = {
    "taint": ("AML.T0051", "OWASP-ASI01/ASI02", "Indirect Prompt Injection / Data Exfiltration Chain"),
    "outbound": ("AML.T0048", "OWASP-ASI04", "Unauthorized Outbound Action / Payee-Swap / C2"),
    "anomaly": ("AML.T0040", "OWASP-ASI08", "High-Velocity Anomaly / Kill Switch Trigger"),
    "crescendo": ("AML.T0054", "OWASP-ASI01", "Multi-Turn Crescendo / Split-Payload Attack"),
    "honeytoken": ("AML.T0057", "OWASP-ASI06", "Decoy Honey-Token Exfiltration Trigger"),
}


def _table_exists(conn: Any, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def build_forensic_timeline(
    memory: Any,
    *,
    session_id: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Собирает хронологию инцидента, корень причины и верификацию цепи аудита."""
    _ash._ensure_tables(memory)
    conn = memory.store.conn
    events: List[Dict[str, Any]] = []

    # 1. Ребра графа Taint CFI
    if _table_exists(conn, "shield_taint_edges"):
        q = (
            "SELECT created_at, session_id, agent_id, step_seq, source_node, tool_name, "
            "target, taints_added_json, verdict, reason FROM shield_taint_edges"
        )
        params: List[Any] = []
        if session_id:
            q += " WHERE session_id = ?"
            params.append(session_id)
        q += " ORDER BY created_at ASC, step_seq ASC LIMIT ?"
        params.append(limit)
        for r in conn.execute(q, params).fetchall():
            events.append(
                {
                    "ts": str(r[0]),
                    "kind": "taint",
                    "session_id": str(r[1]),
                    "agent_id": str(r[2]),
                    "step": int(r[3]),
                    "source": str(r[4]),
                    "tool": str(r[5]),
                    "target": str(r[6]),
                    "taints_added": json.loads(r[7] or "[]"),
                    "verdict": str(r[8]),
                    "detail": str(r[9]),
                }
            )

    # 2. Исходящая очередь / блокировки
    if _table_exists(conn, "shield_outbound_queue"):
        for r in conn.execute(
            "SELECT created_at, agent_id, action_type, target, risk_level, status, reasons_json "
            "FROM shield_outbound_queue ORDER BY created_at ASC LIMIT ?",
            (limit,),
        ).fetchall():
            reasons = json.loads(r[6] or "[]")
            events.append(
                {
                    "ts": str(r[0]),
                    "kind": "outbound",
                    "session_id": session_id or "",
                    "agent_id": str(r[1]),
                    "tool": str(r[2]),
                    "target": str(r[3]),
                    "verdict": str(r[5]),
                    "risk_level": str(r[4]),
                    "detail": "; ".join(str(x) for x in reasons) if reasons else str(r[5]),
                }
            )

    # 3. Аномалии Kill Switch
    if _table_exists(conn, "shield_events"):
        for r in conn.execute(
            "SELECT created_at, agent_id, event_type, weight, detail "
            "FROM shield_events ORDER BY created_at ASC LIMIT ?",
            (limit,),
        ).fetchall():
            events.append(
                {
                    "ts": str(r[0]),
                    "kind": "anomaly",
                    "session_id": session_id or "",
                    "agent_id": str(r[1]),
                    "tool": str(r[2]),
                    "target": "",
                    "verdict": "anomaly",
                    "weight": int(r[3]),
                    "detail": str(r[4]),
                }
            )

    # 4. Ходы Crescendo
    if _table_exists(conn, "shield_crescendo_turns"):
        q = (
            "SELECT created_at, session_id, agent_id, turn_idx, risk_score, signals_json "
            "FROM shield_crescendo_turns"
        )
        params = []
        if session_id:
            q += " WHERE session_id = ?"
            params.append(session_id)
        q += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        for r in conn.execute(q, params).fetchall():
            sigs = json.loads(r[5] or "[]")
            if float(r[4]) >= 0.35 or sigs:
                events.append(
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(float(r[0]))),
                        "kind": "crescendo",
                        "session_id": str(r[1]),
                        "agent_id": str(r[2]),
                        "step": int(r[3]),
                        "tool": "dialogue_turn",
                        "target": "",
                        "verdict": "escalated" if float(r[4]) >= 0.7 else "observed",
                        "detail": f"risk={float(r[4]):.2f}, signals={sigs}",
                    }
                )

    # 5. Срабатывания Honey-Tokens
    if _table_exists(conn, "shield_honeytoken_hits"):
        for r in conn.execute(
            "SELECT created_at, agent_id, token_id, decoy_kind, channel, detail "
            "FROM shield_honeytoken_hits ORDER BY id ASC LIMIT ?",
            (limit,),
        ).fetchall():
            events.append(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(float(r[0]))),
                    "kind": "honeytoken",
                    "session_id": session_id or "",
                    "agent_id": str(r[1]),
                    "tool": str(r[4]),
                    "target": str(r[2]),
                    "verdict": "blocked_kill_switch",
                    "detail": f"Honey-Token ({r[3]}): {r[5]}",
                }
            )

    events.sort(key=lambda e: str(e.get("ts", "")))

    # Поиск первопричины (Root Cause): первое заражение Taint / первый Honey-Token / первая блокировка
    root_cause: Optional[Dict[str, Any]] = None
    for ev in events:
        if ev["kind"] == "taint" and ev.get("taints_added"):
            root_cause = {
                "stage": "initial_taint_source",
                "ts": ev["ts"],
                "agent_id": ev["agent_id"],
                "tool": ev["tool"],
                "target": ev["target"],
                "taints_added": ev["taints_added"],
                "summary": f"Первоисточник заражения: инструмент '{ev['tool']}' ({ev['target']}) повесил метки {ev['taints_added']}",
            }
            break
    if root_cause is None:
        for ev in events:
            if ev["kind"] in ("honeytoken", "outbound", "anomaly", "crescendo"):
                root_cause = {
                    "stage": ev["kind"],
                    "ts": ev["ts"],
                    "agent_id": ev.get("agent_id", ""),
                    "tool": ev.get("tool", ""),
                    "target": ev.get("target", ""),
                    "summary": ev.get("detail", ""),
                }
                break

    # MITRE ATLAS / OWASP Agentic маппинг
    tactics: List[Dict[str, str]] = []
    seen_k = set()
    for ev in events:
        k = ev["kind"]
        if k in _MITRE_MAP and k not in seen_k:
            seen_k.add(k)
            mitre_id, owasp_id, desc = _MITRE_MAP[k]
            tactics.append({"mitre_atlas": mitre_id, "owasp_agentic": owasp_id, "name": desc})

    # Проверка целостности аудита и Tamper-Proof пломбы БД
    try:
        chain_res = _audit_chain.verify_chain(conn)
        chain_ok = bool(chain_res.get("ok", True))
    except Exception:
        chain_ok = True
    seal_res = verify_shield_integrity(memory, enforce_lockdown_on_tamper=False)

    report = {
        "ok": True,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "session_id": session_id or "all",
        "events_count": len(events),
        "blocked_events": sum(1 for e in events if "block" in str(e.get("verdict", "")).lower() or e.get("verdict") == "pending"),
        "root_cause": root_cause,
        "mitre_owasp_mapping": tactics,
        "integrity": {
            "audit_chain_ok": chain_ok,
            "db_tamper_seal_ok": not bool(seal_res.get("tampered")),
        },
        "timeline": events,
    }

    key, _ = _integrity.owner_key(memory.store)
    key_b = key if isinstance(key, bytes) else str(key).encode("utf-8")
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    report["report_hmac_sha256"] = hmac.new(key_b, raw, hashlib.sha256).hexdigest()
    return report


def render_forensic_markdown(report: Dict[str, Any]) -> str:
    """Форматирует криминалистический отчёт инцидента в читаемый Markdown для CISO."""
    lines = [
        "# PADAM Agentic Shield — Forensic Incident Report",
        f"- **Сформирован:** {report.get('generated_at')}",
        f"- **Сессия:** `{report.get('session_id')}`",
        f"- **Событий в цепочке:** {report.get('events_count')} (блокировок/алертов: {report.get('blocked_events')})",
        f"- **Целостность цепи аудита (SHA-256):** {'OK' if report.get('integrity', {}).get('audit_chain_ok') else 'BROKEN'}",
        f"- **Пломба SQLite (Tamper Seal):** {'OK' if report.get('integrity', {}).get('db_tamper_seal_ok') else 'TAMPERED'}",
        f"- **Подпись отчёта (HMAC-SHA256):** `{report.get('report_hmac_sha256', '')[:24]}...`",
        "",
        "## Первопричина (Root Cause)",
    ]
    rc = report.get("root_cause")
    if rc:
        lines.append(f"- `{rc.get('ts')}` — {rc.get('summary')}")
    else:
        lines.append("- Подозрительных инцидентов не зафиксировано.")

    tactics = report.get("mitre_owasp_mapping") or []
    if tactics:
        lines.append("")
        lines.append("## Маппинг MITRE ATLAS / OWASP Agentic")
        for t in tactics:
            lines.append(f"- **{t['mitre_atlas']}** / **{t['owasp_agentic']}** — {t['name']}")

    lines.append("")
    lines.append("## Хронология (Timeline)")
    for ev in (report.get("timeline") or [])[:50]:
        lines.append(
            f"- `{ev.get('ts')}` [{ev.get('kind')}] agent=`{ev.get('agent_id')}` "
            f"tool=`{ev.get('tool')}` verdict=`{ev.get('verdict')}` — {ev.get('detail')}"
        )
    return "\n".join(lines) + "\n"
