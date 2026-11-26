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
- `pentest`: встроенный локальный фаззер на 520 векторов атак (`padam pentest`)
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
    "verify_signature_bundle",
]
