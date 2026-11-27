# -*- coding: utf-8 -*-
"""Пакет расширенных модулей PADAM Agentic Shield (локальный 4-кольцевой + Enterprise контур).

Объединяет:
- `semantic`: локальный ONNX / TF-IDF семантический классификатор (Zero-Telemetry)
- `taint`: контроль траекторий и Taint Tracking (Control Flow Integrity)
- `inspect_mcp`: статический AST-сканер исходного кода MCP-серверов (`padam inspect`)
- `learn_ueba`: режим Shadow-аудита (`padam learn`) и локальный UEBA (Z-score)
- `web3_abi`: декодер EVM ABI и инструкций Solana
- `output_rag`: двусторонний Output DLP/SAST и RAG Poisoning Shield (HTML/PDF)
- `policy_dsl`: программируемый Rego-совместимый движок политик + 25 шаблонов
- `sandbox`: эфемерная микро-песочница исполнения команд
- `model_scan`: сканер файлов локальных моделей (`.pkl`/`.pt`/`.safetensors`/`.gguf`)
- `iam_oidc`: корпоративный OIDC/SSO, RBAC и «Два ключа» для Kill Switch
- `sigdb`: одностороннее обновление подписанных Ed25519 баз сигнатур (`padam update-db`)
- `a2a_trust`: взаимная Ed25519 A2A-аутентификация и Trust Score роя агентов
- `compliance`: генератор Evidence Packs (EU AI Act, NIST AI RMF, OWASP, PCI 4.0.1, SOC 2)
- `pentest`: встроенный локальный фаззер атак (самопроверка на своих шаблонах, не независимая оценка) (`padam pentest`)
- `middleware`: обёртки в 1 клик для LangChain, LlamaIndex, CrewAI, AutoGen
"""
from .a2a_trust import (
    adjust_agent_trust,
    generate_agent_ed25519_keypair,
    list_a2a_trust_scores,
    register_a2a_agent,
    sign_a2a_message,
    verify_a2a_message,
)
from .compliance import build_compliance_evidence_pack, render_compliance_html, render_compliance_markdown
from .iam_oidc import (
    check_tool_rbac,
    issue_test_oidc_jwt,
    register_oidc_provider,
    request_or_approve_dual_unlock,
    verify_oidc_jwt,
)
from .inspect_mcp import inspect_mcp_package, inspect_report_to_sarif
from .learn_ueba import (
    apply_policy_yaml,
    generate_policy_yaml,
    get_shield_mode,
    list_ueba_profiles,
    observe_ueba_metric,
    record_shadow_event,
    set_shield_mode,
)
from .middleware import (
    AutoGenShieldHook,
    CrewAIShieldGuard,
    LangChainShieldCallback,
    LlamaIndexShieldHandler,
    ShieldBlockedError,
    ShieldMiddleware,
)
from .model_scan import scan_model_file
from .output_rag import inspect_output_guardrails, sanitize_rag_document
from .pentest import run_local_pentest
from .policy_dsl import POLICY_TEMPLATES, evaluate_rego_policy, evaluate_template_by_id, list_policy_templates
from .sandbox import MicroSandbox, build_container_command, detect_container_runtime, resolve_confined_path, sanitize_env
from .semantic import BuiltinSemanticClassifier, classify_semantic_threat, get_semantic_classifier, semantic_engine_status
from .sigdb import (
    apply_signature_bundle,
    generate_publisher_keypair,
    get_active_sigdb,
    sign_signature_bundle,
    update_sigdb_from_source,
    verify_signature_bundle,
)
from .taint import clear_session_taints, get_session_graph, get_session_taints, observe_tool_step
from .adversarial_norm import canonicalize_adversarial_text
from .context_isolation import bind_session_tenant, check_cross_tenant_leak, register_tenant_marker
from .dow_guard import check_dow_and_loop
from .exfil_guard import inspect_exfil_channels
from .mcp_proxy import McpStdioShieldProxy
from .policy_replay import replay_policy_on_history
from .slopsquat_guard import check_package_name, scan_dependencies_file, scan_dependencies_text
from .tamper_seal import seal_allowlist_entry, seal_shield_state, verify_shield_integrity
from .timelock_quorum import (
    approve_timelock_operation,
    execute_timelock_operation,
    propose_timelock_operation,
    veto_timelock_operation,
)
from .aibom import generate_aibom, verify_aibom_signature
from .browser_guard import inspect_browser_action, inspect_dom_html
from .capability_tokens import (
    attenuate_capability_token,
    issue_capability_token,
    list_capability_tokens,
    revoke_capability_token,
    verify_and_consume_capability,
)
from .crescendo_guard import evaluate_conversation_turn, reset_crescendo_session
from .forensics import build_forensic_timeline, render_forensic_markdown
from .honeytoken import list_honeytokens, plant_honeytoken, scan_for_honeytokens
from .mcp_http_proxy import (
    McpHttpShieldGateway,
    inspect_http_mcp_request,
    inspect_http_mcp_response_payload,
)
from .memory_rules_guard import inspect_memory_or_rule_text, scan_rules_directory
from .multimodal_guard import inspect_media_bytes, inspect_media_file
from .ssrf_path_guard import inspect_file_path_access, inspect_url_ssrf
from .approval_binding import compute_action_binding_hash, issue_approval_receipt, verify_and_consume_approval
from .diff_guard import scan_diff_file, scan_unified_diff
from .inbound_guard import inspect_inbound_event, verify_inbound_webhook
from .pipeline import ShieldPipeline
from .policy_export import export_policy_bundle
from .precision_bench import run_precision_recall_benchmark
from .prompt_hierarchy import (
    compute_system_prompt_fingerprint,
    detect_system_prompt_leak,
    fence_untrusted_content,
    inspect_role_delimiters,
)
from .resource_guard import inspect_os_command
from .secret_broker import (
    list_broker_secrets,
    register_broker_secret,
    resolve_outbound_headers,
    scrub_response_secrets,
)
from .sql_guard import inspect_graphql_query, inspect_nosql_filter, inspect_sql_query
from .archive_xxe_guard import inspect_archive_file, inspect_tar_bytes, inspect_xml_or_yaml, inspect_zip_bytes
from .attestation import record_execution_attestation, verify_attestation_chain, verify_attestation_receipt
from .cloud_iac_guard import inspect_cloud_or_iac, scan_iac_path
from .goal_drift import anchor_session_goal, evaluate_goal_drift
from .reward_hack_guard import inspect_test_diff_for_reward_hacking
from .scorecard import build_executive_scorecard, render_scorecard_markdown
from .stego_dlp import inspect_stego_dlp
from .swarm_breaker import get_swarm_health, record_swarm_interaction, release_from_quarantine, trigger_swarm_containment
from .voice_guard import inspect_audio_bytes, inspect_voice_transcript
from .web3_abi import decode_evm_calldata, inspect_solana_instruction, scan_text_for_web3_tx

__all__ = [
    "AutoGenShieldHook",
    "BuiltinSemanticClassifier",
    "CrewAIShieldGuard",
    "LangChainShieldCallback",
    "LlamaIndexShieldHandler",
    "MicroSandbox",
    "POLICY_TEMPLATES",
    "ShieldBlockedError",
    "ShieldMiddleware",
    "adjust_agent_trust",
    "apply_policy_yaml",
    "apply_signature_bundle",
    "build_compliance_evidence_pack",
    "build_container_command",
    "check_tool_rbac",
    "classify_semantic_threat",
    "clear_session_taints",
    "decode_evm_calldata",
    "detect_container_runtime",
    "evaluate_rego_policy",
    "evaluate_template_by_id",
    "generate_agent_ed25519_keypair",
    "generate_policy_yaml",
    "generate_publisher_keypair",
    "get_active_sigdb",
    "get_semantic_classifier",
    "get_session_graph",
    "get_session_taints",
    "get_shield_mode",
    "inspect_mcp_package",
    "inspect_output_guardrails",
    "inspect_report_to_sarif",
    "inspect_solana_instruction",
    "issue_test_oidc_jwt",
    "list_a2a_trust_scores",
    "list_policy_templates",
    "list_ueba_profiles",
    "observe_tool_step",
    "observe_ueba_metric",
    "record_shadow_event",
    "register_a2a_agent",
    "register_oidc_provider",
    "render_compliance_html",
    "render_compliance_markdown",
    "request_or_approve_dual_unlock",
    "resolve_confined_path",
    "run_local_pentest",
    "sanitize_env",
    "sanitize_rag_document",
    "scan_model_file",
    "scan_text_for_web3_tx",
    "semantic_engine_status",
    "set_shield_mode",
    "sign_a2a_message",
    "sign_signature_bundle",
    "update_sigdb_from_source",
    "verify_a2a_message",
    "verify_oidc_jwt",
    "McpStdioShieldProxy",
    "approve_timelock_operation",
    "bind_session_tenant",
    "canonicalize_adversarial_text",
    "check_cross_tenant_leak",
    "check_dow_and_loop",
    "check_package_name",
    "execute_timelock_operation",
    "inspect_exfil_channels",
    "propose_timelock_operation",
    "register_tenant_marker",
    "replay_policy_on_history",
    "scan_dependencies_file",
    "scan_dependencies_text",
    "seal_allowlist_entry",
    "seal_shield_state",
    "verify_shield_integrity",
    "verify_signature_bundle",
    "veto_timelock_operation",
    "McpHttpShieldGateway",
    "attenuate_capability_token",
    "build_forensic_timeline",
    "evaluate_conversation_turn",
    "generate_aibom",
    "inspect_browser_action",
    "inspect_dom_html",
    "inspect_file_path_access",
    "inspect_http_mcp_request",
    "inspect_http_mcp_response_payload",
    "inspect_media_bytes",
    "inspect_media_file",
    "inspect_memory_or_rule_text",
    "inspect_url_ssrf",
    "issue_capability_token",
    "list_capability_tokens",
    "list_honeytokens",
    "plant_honeytoken",
    "render_forensic_markdown",
    "reset_crescendo_session",
    "revoke_capability_token",
    "scan_for_honeytokens",
    "scan_rules_directory",
    "verify_aibom_signature",
    "verify_and_consume_capability",
    "ShieldPipeline",
    "compute_action_binding_hash",
    "compute_system_prompt_fingerprint",
    "detect_system_prompt_leak",
    "export_policy_bundle",
    "fence_untrusted_content",
    "inspect_graphql_query",
    "inspect_inbound_event",
    "inspect_nosql_filter",
    "inspect_os_command",
    "inspect_role_delimiters",
    "inspect_sql_query",
    "issue_approval_receipt",
    "list_broker_secrets",
    "register_broker_secret",
    "resolve_outbound_headers",
    "run_precision_recall_benchmark",
    "scan_diff_file",
    "scan_unified_diff",
    "scrub_response_secrets",
    "verify_and_consume_approval",
    "verify_inbound_webhook",
    "anchor_session_goal",
    "build_executive_scorecard",
    "evaluate_goal_drift",
    "get_swarm_health",
    "inspect_archive_file",
    "inspect_audio_bytes",
    "inspect_cloud_or_iac",
    "inspect_stego_dlp",
    "inspect_tar_bytes",
    "inspect_test_diff_for_reward_hacking",
    "inspect_voice_transcript",
    "inspect_xml_or_yaml",
    "inspect_zip_bytes",
    "record_execution_attestation",
    "record_swarm_interaction",
    "release_from_quarantine",
    "render_scorecard_markdown",
    "scan_iac_path",
    "trigger_swarm_containment",
    "verify_attestation_chain",
    "verify_attestation_receipt",
]
