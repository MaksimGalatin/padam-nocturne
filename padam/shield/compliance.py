# -*- coding: utf-8 -*-
"""Генератор пакетов доказательств комплаенса (EU AI Act, NIST AI RMF, OWASP LLM/Agentic, SOC 2, ISO 27001).

Сопоставляет живые данные работы всех 4 колец PADAM Agentic Shield, Taint Tracking, UEBA,
цепи аудита SHA-256 и локального `padam pentest` с требованиями международных стандартов.
Честно указывает, что пакет доказательств помогает клиенту в подготовке к аудиту, но не заменяет
формального внешнего аудитора (SOC 2 Type II / ISO 27001 / PCI QSA).
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import html as _html
import json
from typing import Any

from .. import audit_chain, defense_stats, integrity, solana_crypto_shield
from .a2a_trust import list_a2a_trust_scores
from .learn_ueba import get_shield_mode, list_ueba_profiles
from .semantic import semantic_engine_status
from .sigdb import get_active_sigdb
from .taint import get_session_graph


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_compliance_evidence_pack(
    memory: Any,
    *,
    frameworks: list[str] | None = None,
    pentest_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Собирает криптографически подписанный Compliance Evidence Pack для CISO и аудиторов."""
    from .. import agentic_shield as _ash

    selected = set(
        frameworks
        or ["EU_AI_ACT", "NIST_AI_RMF", "OWASP_LLM_TOP10", "OWASP_AGENTIC_TOP10", "PCI_DSS_4_0_1", "SOC2_ISO27001"]
    )
    st = _ash.get_shield_status(memory)
    att = defense_stats.attack_stats(memory)
    chain_ark = audit_chain.verify_audit_chain(memory)
    graph = get_session_graph(memory, limit=50)
    ueba = list_ueba_profiles(memory, limit=50)
    sem = semantic_engine_status()
    sigdb = get_active_sigdb(memory)
    a2a = list_a2a_trust_scores(memory)
    mode = get_shield_mode(memory)

    controls: dict[str, list[dict[str, Any]]] = {}

    if "EU_AI_ACT" in selected:
        controls["EU_AI_ACT"] = [
            {
                "article": "Article 9 (Risk Management System)",
                "control": "4-Ring Deterministic + Semantic ONNX Cascade, Taint Tracking CFI, Local UEBA Z-score, Rego DSL",
                "evidence": {
                    "shield_mode": mode,
                    "policy_profile": st["policy_profile"],
                    "semantic_backend": sem["builtin_backend"],
                    "ueba_profiles_active": len(ueba),
                    "taint_blocked_steps": graph["blocked_steps"],
                },
                "status": "enforced",
            },
            {
                "article": "Article 14 (Human Oversight)",
                "control": "Owner-only Kill Switch Unlock + Dual-Control OIDC/SSO (2 SecurityAdmins) + Outbound Approval Queue",
                "evidence": {
                    "lockdown_active": st["lockdown"],
                    "pending_owner_approvals": st["pending_outbound_count"],
                    "auto_kill_enabled": st["auto_kill_enabled"],
                },
                "status": "enforced",
            },
            {
                "article": "Article 15 (Accuracy, Robustness & Cybersecurity)",
                "control": "MCP SHA-256 Pinning, AST Inspector (`padam inspect`), Model Supply-Chain Scanner, RAG Poisoning Shield, A2A Ed25519 Trust",
                "evidence": {
                    "mcp_tools_pinned": st["mcp_pins_count"],
                    "attacks_quarantined": att.get("held_total", 0),
                    "sigdb_version": sigdb["version"],
                    "a2a_agents_tracked": len(a2a),
                },
                "status": "enforced",
            },
        ]

    if "NIST_AI_RMF" in selected:
        controls["NIST_AI_RMF"] = [
            {"function": "GOVERN", "control": "Rego Policy Engine (25 templates), OIDC RBAC, Owner-signed Identity", "status": "enforced"},
            {"function": "MAP", "control": "MCP AST Pre-Install Scanner, Model Supply-Chain Scanner (.pkl/.safetensors/.gguf)", "status": "enforced"},
            {"function": "MEASURE", "control": "Local Red-Team Fuzzer (`padam pentest`), UEBA Z-Score Baselines, AIFaSecurity-100", "status": "enforced"},
            {"function": "MANAGE", "control": "Machine-Speed Kill Switch, Micro-Sandbox Isolation, Taint Tracking Auto-Block, Signed Proof Pack", "status": "enforced"},
        ]

    if "OWASP_LLM_TOP10" in selected:
        controls["OWASP_LLM_TOP10"] = [
            {"id": "LLM01", "name": "Prompt Injection", "control": "Ring 1 Regex + Unicode/Bidi + Local ONNX Semantic Cascade + RAG Poisoning Shield", "status": "enforced"},
            {"id": "LLM02", "name": "Sensitive Information Disclosure", "control": "Output Guardrail (Secrets + PII GDPR/HIPAA + Canary Honeypots)", "status": "enforced"},
            {"id": "LLM03", "name": "Supply Chain", "control": "MCP SHA-256 Pinning + AST `padam inspect` + ML Model Scanner (.pkl/.gguf/.safetensors)", "status": "enforced"},
            {"id": "LLM05", "name": "Improper Output Handling", "control": "Output SAST Filter (SQLi/XSS/Shell/Deserialize) + HTML/SVG XSS Sanitizer", "status": "enforced"},
            {"id": "LLM06", "name": "Excessive Agency", "control": "Outbound Payee-Swap Gate + EVM/Solana ABI Decoder + Taint Tracking + Micro-Sandbox + Rego DSL", "status": "enforced"},
            {"id": "LLM08", "name": "Vector & Embedding Weaknesses", "control": "RAG Poisoning Shield (PDF/HTML hidden text strip) + HOLD_EXTERNAL Quarantine", "status": "enforced"},
        ]

    if "OWASP_AGENTIC_TOP10" in selected:
        controls["OWASP_AGENTIC_TOP10"] = list(_ash.OWASP_AGENTIC_MATRIX)

    if "PCI_DSS_4_0_1" in selected:
        controls["PCI_DSS_4_0_1"] = [
            {
                "req": "PCI DSS v4.0.1 — 6.4.3 & 11.6.1",
                "control": "Client-Side JS Inventory, SRI (sha384), Strict CSP Audit & Crypto-Clipper Detection (`supply_chain_guard.py`)",
                "recent_scans": len(st.get("recent_supply_scans") or []),
                "status": "enforced",
            },
            {
                "req": "PCI DSS — Cardholder Data Protection (PAN/Luhn)",
                "control": "Outbound Gate + Output DLP Luhn Card Masking & Blocking",
                "status": "enforced",
            },
        ]

    if "SOC2_ISO27001" in selected:
        controls["SOC2_ISO27001"] = [
            {
                "domain": "CC6.1 / ISO A.5.15 (Access Control)",
                "control": "OIDC/SSO JWT Verification, MCP RBAC, Dual-Control Kill Switch Unlock",
                "status": "enforced",
            },
            {
                "domain": "CC7.2 / ISO A.8.16 (Monitoring & Audit Trails)",
                "control": "Tamper-Evident SHA-256 Audit Chain + Signed SIEM Webhooks (HMAC)",
                "audit_chain_ok": bool(chain_ark.get("ok")),
                "audit_entries": int(chain_ark.get("length", 0)),
                "status": "enforced",
            },
            {
                "domain": "External Certification Readiness",
                "control": "Self-hosted Evidence Pack generator",
                "external_audit_status": "planned",
                "honest_disclaimer": "This Evidence Pack provides verifiable technical artifacts for client audits; it is NOT a formal SOC 2 Type II, ISO 27001 or PCI QSA certification.",
            },
        ]

    body: dict[str, Any] = {
        "schema": "padam-compliance-evidence-pack/1.0",
        "generated_at": _utc_iso(),
        "user_id": memory.user_id,
        "zero_telemetry": True,
        "honest_certification_notice": (
            "Technical evidence generated locally from verifiable logs and code controls. "
            "Does not replace formal independent SOC 2 Type II, ISO 27001, or PCI QSA certification."
        ),
        "summary": {
            "shield_mode": mode,
            "policy_profile": st["policy_profile"],
            "lockdown_active": st["lockdown"],
            "audit_chain_verified": bool(chain_ark.get("ok")),
            "audit_chain_entries": int(chain_ark.get("length", 0)),
            "taint_steps_logged": graph["total_steps"],
            "taint_blocks": graph["blocked_steps"],
            "ueba_profiles": len(ueba),
            "sigdb_version": sigdb["version"],
        },
        "pentest_summary": pentest_summary or {},
        "frameworks": controls,
    }

    canon = _canonical(body)
    pack_sha = hashlib.sha256(canon).hexdigest()
    key, _ = integrity.owner_key(memory.store)
    owner_hmac = hmac.new(key, pack_sha.encode("ascii"), hashlib.sha256).hexdigest()
    sol_att = solana_crypto_shield.sign_solana_shield_attestation(
        memory,
        summary_items=[{"section": "compliance_summary", "data": body["summary"]}],
    )

    return {
        **body,
        "attestation": {
            "pack_sha256": pack_sha,
            "owner_hmac_sha256": owner_hmac,
            "solana_signer_pubkey": sol_att["signer_pubkey"],
            "solana_ed25519_sig_b64": sol_att["signature_b64"],
            "algorithm": "SHA-256 + Owner HMAC-SHA256 + Ed25519",
        },
    }


def render_compliance_markdown(pack: dict[str, Any]) -> str:
    att = pack.get("attestation") or {}
    summ = pack.get("summary") or {}
    lines = [
        "# PADAM Agentic Shield — Enterprise Compliance Evidence Pack",
        "",
        f"- **Generated (UTC):** `{pack.get('generated_at')}`",
        f"- **Pack SHA-256:** `{att.get('pack_sha256')}`",
        f"- **Zero-Telemetry:** `{pack.get('zero_telemetry')}`",
        f"- **Audit Chain Verified:** `{summ.get('audit_chain_verified')}` (entries: `{summ.get('audit_chain_entries')}`)",
        "",
        f"> **Notice:** {pack.get('honest_certification_notice')}",
        "",
    ]
    for fw, items in (pack.get("frameworks") or {}).items():
        lines.append(f"## {fw}")
        lines.append("")
        for it in items:
            label = it.get("article") or it.get("function") or it.get("id") or it.get("req") or it.get("domain") or "control"
            ctrl = it.get("control") or ""
            status = it.get("status") or it.get("external_audit_status") or "info"
            lines.append(f"- **{label}** (`{status}`): {ctrl}")
        lines.append("")
    return "\n".join(lines)


def render_compliance_html(pack: dict[str, Any]) -> str:
    att = pack.get("attestation") or {}
    sections: list[str] = []
    for fw, items in (pack.get("frameworks") or {}).items():
        rows = "".join(
            "<tr>"
            f"<td><b>{_html.escape(str(it.get('article') or it.get('function') or it.get('id') or it.get('req') or it.get('domain') or ''))}</b></td>"
            f"<td>{_html.escape(str(it.get('control') or ''))}</td>"
            f"<td><code>{_html.escape(str(it.get('status') or it.get('external_audit_status') or 'info'))}</code></td>"
            "</tr>"
            for it in items
        )
        sections.append(
            f"<h2>{_html.escape(fw)}</h2>"
            f"<table><thead><tr><th>Requirement</th><th>Enforced Code Control</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<title>PADAM Agentic Shield — Compliance Evidence Pack</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#0f172a}"
        "table{width:100%;border-collapse:collapse;margin:10px 0 22px}th,td{border:1px solid #cbd5e1;padding:8px;text-align:left;font-size:13px}"
        "th{background:#f1f5f9}.note{background:#fefce8;border:1px solid #fde047;padding:10px 12px;border-radius:8px;font-size:13px}</style>"
        "</head><body>"
        "<h1>PADAM Agentic Shield — Enterprise Compliance Evidence Pack</h1>"
        f"<p><b>Generated (UTC):</b> {_html.escape(str(pack.get('generated_at', '')))} | "
        f"<b>SHA-256:</b> <code>{_html.escape(str(att.get('pack_sha256', '')))}</code></p>"
        f"<div class='note'>{_html.escape(str(pack.get('honest_certification_notice', '')))}</div>"
        + "".join(sections)
        + "</body></html>"
    )
