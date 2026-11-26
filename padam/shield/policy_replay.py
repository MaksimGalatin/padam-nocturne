# -*- coding: utf-8 -*-
"""Симулятор политик и Replay исторических инцидентов (`padam shield replay` / «Что было бы, если…»).

Позволяет DevSecOps-инженеру или владельцу прогнать новую Rego-политику по реальной истории
событий в локальной SQLite (`shield_outbound_queue` + `shield_shadow_events` + `shield_taint_edges`)
без изменения состояния БД и точно увидеть, сколько легитимных вызовов она затронет и сколько
атак дополнительно перехватит.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from .learn_ueba import ensure_learn_ueba_tables
from .policy_dsl import POLICY_TEMPLATES, evaluate_rego_policy
from .taint import ensure_taint_tables


def replay_policy_on_history(
    memory: Any,
    *,
    rego_source: str | None = None,
    template_id: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Сухой прогон Rego-политики по историческим событиям Щита в SQLite."""
    from .. import agentic_shield as _ash

    _ash._ensure_tables(memory)
    ensure_learn_ueba_tables(memory)
    ensure_taint_tables(memory)

    src = str(rego_source or "").strip()
    if not src and template_id:
        tpl = POLICY_TEMPLATES.get(template_id)
        if tpl is None:
            raise KeyError(f"Unknown template_id: {template_id!r}")
        src = tpl["rego"]
    if not src:
        raise ValueError("rego_source or template_id is required")

    lim = max(1, min(1000, int(limit)))
    events: list[dict[str, Any]] = []

    for r in memory.store.query(
        "SELECT id, agent_id, action_type, target, preview, risk_level, status, created_at "
        "FROM shield_outbound_queue WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (memory.user_id, lim),
    ):
        tgt = str(r["target"] or "")
        host = urllib.parse.urlsplit(tgt).netloc.lower().split(":")[0] if "://" in tgt else tgt.split("/")[0].lower()
        events.append({
            "source": "outbound_queue",
            "id": r["id"],
            "actual_status": r["status"],
            "input": {
                "agent_id": r["agent_id"],
                "action": r["action_type"],
                "tool": r["action_type"],
                "target": tgt,
                "url": tgt,
                "host": host,
                "path": tgt,
                "command": str(r["preview"] or ""),
                "sql": str(r["preview"] or ""),
                "payload_bytes": len(str(r["preview"] or "").encode("utf-8")),
                "risk_level": r["risk_level"],
            },
        })

    for r in memory.store.query(
        "SELECT id, agent_id, tool_name, target, active_taints_json, verdict, created_at "
        "FROM shield_taint_edges WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (memory.user_id, lim),
    ):
        taints = json.loads(r["active_taints_json"] or "[]")
        tgt = str(r["target"] or "")
        events.append({
            "source": "taint_edges",
            "id": r["id"],
            "actual_status": "blocked" if r["verdict"] == "block" else "allowed",
            "input": {
                "agent_id": r["agent_id"],
                "action": r["tool_name"],
                "tool": r["tool_name"],
                "target": tgt,
                "path": tgt,
                "url": tgt,
                "tainted_untrusted": "TAINT_UNTRUSTED_INPUT" in taints,
                "tainted_sensitive": "TAINT_SENSITIVE_READ" in taints,
            },
        })

    would_block = 0
    would_allow = 0
    newly_caught = 0
    newly_allowed = 0
    samples: list[dict[str, Any]] = []

    for ev in events:
        res = evaluate_rego_policy(src, ev["input"])
        sim_allowed = bool(res.get("allowed", True))
        act_allowed = ev["actual_status"] in ("allowed", "approved", "shadow_logged")
        if sim_allowed:
            would_allow += 1
            if not act_allowed:
                newly_allowed += 1
        else:
            would_block += 1
            if act_allowed:
                newly_caught += 1
                if len(samples) < 20:
                    samples.append({
                        "event_id": ev["id"],
                        "source": ev["source"],
                        "actual_status": ev["actual_status"],
                        "simulated_verdict": "deny",
                        "deny_reasons": res.get("deny_reasons") or [],
                    })

    return {
        "ok": True,
        "events_replayed": len(events),
        "would_block": would_block,
        "would_allow": would_allow,
        "delta_newly_caught": newly_caught,
        "delta_newly_allowed": newly_allowed,
        "newly_caught_samples": samples,
        "dry_run": True,
    }
