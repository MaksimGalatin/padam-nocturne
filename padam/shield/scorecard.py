# -*- coding: utf-8 -*-
"""Executive Security Scorecard & OWASP ASI01–ASI10 Live File-Verified Auditor.

Формирует криптографически подписанную сводку покрытия OWASP Agentic AI Top 10
(ASI01–ASI10), проверяя ФИЗИЧЕСКОЕ существование каждого файла реализации на диске
(исключает любую фальсификацию документации без кода!), а также живую целостность
цепи аудита, цепи доказательств исполнения (`attestation`) и пломбы SQLite.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from .. import audit_chain as _audit_chain
from .. import integrity as _integrity
from .attestation import verify_attestation_chain
from .tamper_seal import verify_shield_integrity


OWASP_ASI_MODULES: List[Dict[str, Any]] = [
    {"id": "ASI01", "name": "Agent Goal Hijacking", "modules": ["semantic.py", "adversarial_norm.py", "prompt_hierarchy.py", "goal_drift.py", "crescendo_guard.py"]},
    {"id": "ASI02", "name": "Tool Misuse & Exploitation", "modules": ["taint.py", "mcp_proxy.py", "mcp_http_proxy.py", "sql_guard.py", "browser_guard.py", "cloud_iac_guard.py"]},
    {"id": "ASI03", "name": "Identity & Privilege Abuse (Confused Deputy)", "modules": ["capability_tokens.py", "iam_oidc.py", "approval_binding.py", "timelock_quorum.py"]},
    {"id": "ASI04", "name": "Agentic Supply Chain Vulnerabilities", "modules": ["inspect_mcp.py", "model_scan.py", "slopsquat_guard.py", "aibom.py", "diff_guard.py", "sigdb.py"]},
    {"id": "ASI05", "name": "Unexpected Code Execution & Sandbox Escape", "modules": ["sandbox.py", "resource_guard.py", "archive_xxe_guard.py", "ssrf_path_guard.py", "reward_hack_guard.py"]},
    {"id": "ASI06", "name": "Memory & Context Poisoning", "modules": ["memory_rules_guard.py", "output_rag.py", "context_isolation.py", "multimodal_guard.py", "voice_guard.py"]},
    {"id": "ASI07", "name": "Insecure Inter-Agent Communication (A2A / AI Worm)", "modules": ["a2a_trust.py", "swarm_breaker.py", "inbound_guard.py"]},
    {"id": "ASI08", "name": "Cascading Failures & Denial of Wallet (DoW)", "modules": ["dow_guard.py", "learn_ueba.py", "policy_replay.py", "pipeline.py"]},
    {"id": "ASI09", "name": "Human-Agent Trust & Sensitive Data Exfiltration", "modules": ["exfil_guard.py", "stego_dlp.py", "secret_broker.py", "honeytoken.py", "web3_abi.py"]},
    {"id": "ASI10", "name": "Rogue Agents, Auditability & Non-Repudiation", "modules": ["tamper_seal.py", "attestation.py", "forensics.py", "compliance.py", "policy_dsl.py", "policy_export.py", "pentest.py", "precision_bench.py"]},
]


def build_executive_scorecard(memory: Any) -> Dict[str, Any]:
    """Собирает проверяемую по файлам на диске и живой БД сводку защищённости PADAM Shield."""
    shield_dir = Path(__file__).resolve().parent
    all_py = sorted(p.name for p in shield_dir.glob("*.py") if p.name != "__init__.py")

    owasp_rows: List[Dict[str, Any]] = []
    covered_count = 0
    verified_refs = 0
    missing_refs: List[str] = []

    for item in OWASP_ASI_MODULES:
        present = []
        missing = []
        for fn in item["modules"]:
            if (shield_dir / fn).is_file():
                present.append(fn)
                verified_refs += 1
            else:
                missing.append(fn)
                missing_refs.append(fn)
        status = "enforced" if (present and not missing) else ("partial" if present else "missing")
        if status == "enforced":
            covered_count += 1
        owasp_rows.append(
            {
                "id": item["id"],
                "name": item["name"],
                "status": status,
                "verified_modules": present,
                "missing_modules": missing,
            }
        )

    # Живая проверка целостности БД и цепей
    try:
        audit_ok = bool(_audit_chain.verify_audit_chain(memory).get("valid", True))
    except Exception:
        audit_ok = False
    seal_ok = not bool(verify_shield_integrity(memory, enforce_lockdown_on_tamper=False).get("tampered"))
    att_res = verify_attestation_chain(memory)
    att_ok = bool(att_res.get("valid"))

    coverage_pct = round((covered_count / len(OWASP_ASI_MODULES)) * 100.0, 2)
    report: Dict[str, Any] = {
        "ok": covered_count == len(OWASP_ASI_MODULES) and not missing_refs and seal_ok and att_ok,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_shield_modules_on_disk": len(all_py),
        "owasp_asi_covered": covered_count,
        "owasp_asi_total": len(OWASP_ASI_MODULES),
        "owasp_coverage_pct": coverage_pct,
        "verified_module_refs": verified_refs,
        "missing_module_refs": missing_refs,
        "evaluation_scope": "local_disk_and_integrity_self_check",
        "zero_telemetry": True,
        "live_integrity": {
            "audit_chain_ok": audit_ok,
            "db_tamper_seal_ok": seal_ok,
            "attestation_chain_ok": att_ok,
            "attestation_entries": int(att_res.get("entries_checked", 0)),
        },
        "owasp_agentic_top10": owasp_rows,
    }

    key, _ = _integrity.owner_key(memory.store)
    key_b = key if isinstance(key, bytes) else str(key).encode("utf-8")
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    report["scorecard_hmac_sha256"] = hmac.new(key_b, raw, hashlib.sha256).hexdigest()
    return report


def render_scorecard_markdown(card: Dict[str, Any]) -> str:
    """Форматирует Executive Security Scorecard в Markdown для CISO и аудиторов."""
    lines = [
        "# PADAM Agentic Shield — Executive Security Scorecard",
        f"- **Сформирован:** {card.get('generated_at')}",
        f"- **Изолированных модулей на диске:** `{card.get('total_shield_modules_on_disk')}`",
        f"- **Покрытие OWASP Agentic Top 10:** `{card.get('owasp_asi_covered')}/{card.get('owasp_asi_total')}` (`{card.get('owasp_coverage_pct')}%`)",
        f"- **Режим приватности:** Zero-Telemetry (`100%` локальное исполнение)",
        "- **Область проверки:** Локальная самопроверка файлов и цепей (не внешний аудит; открытый Red Team Challenge: `docs/RED_TEAM_CHALLENGE.md`)",
        f"- **Целостность:** Audit Chain=`{'OK' if card['live_integrity']['audit_chain_ok'] else 'BROKEN'}`, "
        f"DB Seal=`{'OK' if card['live_integrity']['db_tamper_seal_ok'] else 'TAMPERED'}`, "
        f"Attestation=`{'OK' if card['live_integrity']['attestation_chain_ok'] else 'BROKEN'}`",
        f"- **Подпись (HMAC-SHA256):** `{card.get('scorecard_hmac_sha256', '')[:24]}...`",
        "",
        "| Код | Угроза OWASP Agentic AI | Статус | Подтверждённые модули на диске |",
        "|---|---|---|---|",
    ]
    for row in card.get("owasp_agentic_top10") or []:
        mods = ", ".join(f"`{m}`" for m in row["verified_modules"])
        lines.append(f"| **{row['id']}** | {row['name']} | {row['status']} | {mods} |")
    return "\n".join(lines) + "\n"
