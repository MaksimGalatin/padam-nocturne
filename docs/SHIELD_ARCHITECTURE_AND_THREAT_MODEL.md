# PADAM Agentic Shield — Architecture Registry, Threat Model & Licensing Matrix

> **Positioning:** *PADAM — Local-First Security and Governance Infrastructure for Autonomous AI Agents.*
>
> **Evaluation honesty notice:** All counts below are **auto-generated directly from files on disk** in `padam/shield/`. OWASP Agentic AI Top 10 (`ASI01–ASI10`) coverage is an **internal engineering mapping**, not a third-party certification. See [`docs/RED_TEAM_CHALLENGE.md`](./RED_TEAM_CHALLENGE.md) for independent verification instructions.

---

## 1. Exact Metric Definitions (No Ambiguity)

- **Isolated Shield modules on disk (`padam/shield/*.py`, excluding `__init__.py`):** **`56`**
- **Total lines of Python code inside `padam/shield/*.py`:** **`15,450`** lines (does *not* count tests, `padam/api.py`, `padam/cli.py`, `padam/studio.py`, `packages/padam-shield-js/`, Helm charts, or generated `docs/site/`).
- **Test suites vs. built-in benchmark:**
  - `pytest` unit & integration suites (`tests/test_agentic_shield_*.py` + `tests/test_memory_rules_guard_outside_set_2611.py` + `packages/padam-shield-js/test.mjs`) verify API contracts, Fail-Closed enforcement, SQLite concurrency, OS Key Vault (DPAPI), Helm IaC, Ed25519 ONNX verification, and 20-agent stress behavior.
  - `padam shield benchmark` is a **built-in deterministic self-check** (1,200 attacks + 250 benign developer tasks). External researchers can audit every vector via `--export-corpus` and run their own unseen datasets via `--custom-attacks` / `--custom-benign`.

---

## 2. Threat Model of PADAM Agentic Shield Itself

A security platform is itself a high-value target. Below are the concrete attacks against PADAM and how each is mitigated in code:

| Attack Vector Against PADAM | Mitigation in Codebase | Module(s) |
|---|---|---|
| **1. Direct SQLite DB tampering** (attacker edits allowlist / kills audit log via `sqlite3`) | Cryptographic HMAC-SHA256 seal across security tables; auto-lockdown on mismatch | `tamper_seal.py`, `attestation.py`, `forensics.py` |
| **2. Root signing key theft from plaintext file/env** | OS/Hardware-bound key sealing: native Windows DPAPI (`CryptProtectData`), macOS Keychain, Linux Keyring, Enterprise KMS adapter | `key_vault.py` |
| **3. Malicious rule/model update supply-chain attack** | Mandatory Ed25519 signature + SHA-256 verification before loading signature DBs or `.onnx` weights; anti-rollback version check for fleet `.rego` bundles | `sigdb.py`, `semantic.py`, `control_plane.py` |
| **4. Shield module crash / timeout -> Fail-Open bypass** | `ShieldPipeline(fail_closed=True)` + `execute_guarded()`: any stage exception triggers `SHIELD-STAGE-FAIL-CLOSED` and physically prevents tool execution | `pipeline.py` |
| **5. TOCTOU parameter swap / capability fan-out escalation** | Single-use SHA-256 `approval_binding` receipts bound to exact `(agent, action, target, args, amount)` + atomic parent-chain budget deduction to `root_id` | `approval_binding.py`, `capability_tokens.py`, `agent_registry.py` |
| **6. Parser differential evasions** (`DR/**/OP`, double URL encoding `%252f`, UNC paths, spontaneous MCP `tools/list`) | Dual comment-stripping in SQL guard, iterative 4-round URL decoding in path guard, UNC/flag-path checks in sandbox, unconditional `tools` inspection in MCP proxy | `sql_guard.py`, `ssrf_path_guard.py`, `sandbox.py`, `mcp_proxy.py` |
| **7. Telemetry / covert vendor data leak** | 100% local execution (`zero_telemetry: true`), zero outbound calls in shield core, Kubernetes Zero-Egress `NetworkPolicy` | `deploy/helm/padam-shield/`, `scorecard.py` |

---

## 3. Licensing Matrix (Clarity for Buyers & Auditors)

| Component | License | Commercial Use |
|---|---|---|
| Core PADAM Memory & Shield runtime (`padam/`, `padam/shield/`) | **PADAM License 1.0** (source-available, converts to Apache-2.0 after 24 months per release; see `COMMERCIAL-LICENSE.md`) | Free for individuals, open-source, & local audit; paid Pro/Team/Enterprise license (`PADAMLIC1`) for commercial SaaS/fleet governance |
| GitHub Action, CI runners, `padam-shield-mcp` wrapper & Helm chart (`deploy/helm/padam-shield/`) | **Apache-2.0** | Unrestricted commercial & CI/CD use |
| Node.js SDK (`packages/padam-shield-js/`) | **Apache-2.0** | Unrestricted embedding in JS/TS agents |

---

## 4. Machine-Generated Module Registry (`padam/shield/`, 56 files, 15,450 lines)

| # | Module File | Lines | Purpose |
|---|---|---|---|
| 1 | `padam/shield/a2a_trust.py` | 246 | Защита мультиагентных роев: взаимная Ed25519 A2A-аутентификация и Trust Score агентов. |
| 2 | `padam/shield/adversarial_norm.py` | 115 | Адверсариальная нормализация текста перед семантической и детерминированной проверкой. |
| 3 | `padam/shield/agent_registry.py` | 498 | Agent Discovery & Cryptographic Agent Identity Registry (PADAM Shield). |
| 4 | `padam/shield/aibom.py` | 228 | Генератор AI-BOM (Software & Model Bill of Materials) в формате CycloneDX 1.6 JSON. |
| 5 | `padam/shield/approval_binding.py` | 276 | Криптографическая привязка согласия человека к действию (Anti-TOCTOU Approval Binding). |
| 6 | `padam/shield/archive_xxe_guard.py` | 151 | Защита от атак на архивы и парсеры (Zip-Slip, Zip-Bomb, Tar-Symlink, XXE, YAML RCE). |
| 7 | `padam/shield/attestation.py` | 281 | Криптографическая цепь доказательств исполнения (Signed Proof-of-Execution Attestation). |
| 8 | `padam/shield/browser_guard.py` | 311 | Файрвол браузерного / Computer-Use агента (DOM & UI-Redressing Guard). |
| 9 | `padam/shield/capability_tokens.py` | 651 | Криптографические гранулярные мандаты возможностей (Attenuated Capability Tokens). |
| 10 | `padam/shield/cloud_iac_guard.py` | 112 | Файрвол облачных и инфраструктурных агентов (Cloud IAM / Kubernetes / Terraform Guard). |
| 11 | `padam/shield/compliance.py` | 254 | Генератор пакетов доказательств комплаенса (EU AI Act, NIST AI RMF, OWASP LLM/Agentic, SOC 2, ISO 27001). |
| 12 | `padam/shield/context_isolation.py` | 156 | Защита от смешения контекстов и Cross-Tenant утечек (`Context Isolation Guard`). |
| 13 | `padam/shield/control_plane.py` | 282 | On-Premise Control Plane для централизованного управления флотом узлов PADAM Shield. |
| 14 | `padam/shield/crescendo_guard.py` | 241 | Детектор многоходовых атак Crescendo и склейки разбитой нагрузки (Split-Payload Guard). |
| 15 | `padam/shield/diff_guard.py` | 142 | AI Code-Review & Git Diff Security Gate (`padam shield scan-diff`). |
| 16 | `padam/shield/dow_guard.py` | 153 | Защита от экономических атак (Denial of Wallet / DoW) и детектор зацикливания агентов. |
| 17 | `padam/shield/exfil_guard.py` | 122 | Детектор скрытых каналов эксфильтрации (Markdown Image Exfil, DNS-туннели, Stego-пробелы). |
| 18 | `padam/shield/forensics.py` | 302 | Криминалистическая реконструкция инцидентов (Forensic Timeline & Root-Cause Replay). |
| 19 | `padam/shield/goal_drift.py` | 185 | Детектор дрейфа цели и угона личности агента (Agent Goal Drift Guard — OWASP ASI01). |
| 20 | `padam/shield/honeytoken.py` | 224 | Предиктивные Honey-Tokens (разнотипные приманки-ловушки для 0-day атак). |
| 21 | `padam/shield/iam_oidc.py` | 371 | Корпоративная авторизация OIDC / SSO, RBAC для MCP и «Два ключа» (Dual-Control) для Kill Switch. |
| 22 | `padam/shield/inbound_guard.py` | 225 | Защита входящих триггеров: Webhook, Email и Calendar Invite Injection Guard. |
| 23 | `padam/shield/inspect_mcp.py` | 337 | Статический AST-сканер исходного кода MCP-серверов до установки (`padam inspect`). |
| 24 | `padam/shield/key_vault.py` | 261 | Кроссплатформенная ОС- и аппаратная привязка корневых ключей (Key Vault / DPAPI / Keychain / KMS). |
| 25 | `padam/shield/learn_ueba.py` | 383 | Режим Shadow-аудита (`padam learn`) и локальный поведенческий движок UEBA (Z-score). |
| 26 | `padam/shield/mcp_http_proxy.py` | 392 | Прозрачный шлюз-перехватчик MCP Streamable HTTP / SSE (MCP HTTP Gateway). |
| 27 | `padam/shield/mcp_proxy.py` | 251 | Прозрачный локальный MCP STDIO JSON-RPC прокси (`padam shield proxy -- <cmd>`). |
| 28 | `padam/shield/memory_rules_guard.py` | 290 | Броня памяти и файлов правил агента (Rules File Backdoor & Sleeper Memory Poisoning Guard). |
| 29 | `padam/shield/middleware.py` | 243 | Middleware-обёртки в один клик для LangChain, LlamaIndex, CrewAI, AutoGen и любых Python-агентов. |
| 30 | `padam/shield/model_scan.py` | 265 | Статический сканер файлов локальных моделей на закладки (ML Supply Chain Security). |
| 31 | `padam/shield/multimodal_guard.py` | 326 | Защита от мультимодальных атак в изображениях и метаданных (PNG / JPEG / SVG / Polyglot Guard). |
| 32 | `padam/shield/output_rag.py` | 344 | Двусторонний Output Guardrail (PII GDPR/HIPAA + SAST кода) и RAG Poisoning Shield. |
| 33 | `padam/shield/pentest.py` | 777 | Встроенный локальный Red-Teaming и фаззер (`padam pentest`, 1200 реальных векторов по 40 категориям). |
| 34 | `padam/shield/pipeline.py` | 606 | Единый оркестратор PADAM Agentic Shield («Одно окно защиты» — ShieldPipeline). |
| 35 | `padam/shield/policy_dsl.py` | 444 | Программируемый движок политик безопасности (Rego-совместимый DSL + 25 шаблонов). |
| 36 | `padam/shield/policy_export.py` | 194 | Policy Compiler — экспорт политик PADAM в промышленные форматы инфраструктуры. |
| 37 | `padam/shield/policy_replay.py` | 131 | Симулятор политик и Replay исторических инцидентов (`padam shield replay` / «Что было бы, если…»). |
| 38 | `padam/shield/precision_bench.py` | 478 | Двусторонний бенчмарк точности (Precision / Recall / FPR / F1 Score). |
| 39 | `padam/shield/prompt_hierarchy.py` | 124 | Защита системного промпта и иерархии инструкций (Instruction Hierarchy Enforcer). |
| 40 | `padam/shield/resource_guard.py` | 122 | Защита локальных ресурсов ОС: криптомайнеры, fork-бомбы, персистенс и обратные туннели. |
| 41 | `padam/shield/reward_hack_guard.py` | 133 | Защита от подделки тестов и Reward Hacking автономными ИИ-кодерами. |
| 42 | `padam/shield/sandbox.py` | 187 | Эфемерная микро-песочница (Micro-Sandbox) для изолированного запуска инструментов агента. |
| 43 | `padam/shield/scorecard.py` | 128 | Executive Security Scorecard & OWASP ASI01–ASI10 Live File-Verified Auditor. |
| 44 | `padam/shield/secret_broker.py` | 278 | Zero-Exposure Secret Broker (брокер секретов по псевдонимам без утечки в LLM). |
| 45 | `padam/shield/semantic.py` | 569 | Локальный каскадный семантический классификатор атак (ONNX + встроенный TF-IDF/Logistic). |
| 46 | `padam/shield/sigdb.py` | 234 | Одностороннее обновление подписанных баз сигнатур угроз без телеметрии (`padam update-db`). |
| 47 | `padam/shield/slopsquat_guard.py` | 169 | Детектор Slopsquatting и подмены зависимостей (Supply-Chain Dependency Guard). |
| 48 | `padam/shield/sql_guard.py` | 350 | Файрвол баз данных и запросов SQL / NoSQL / GraphQL (Database & Query Guard). |
| 49 | `padam/shield/ssrf_path_guard.py` | 295 | Защита от Cloud Metadata SSRF и побега из файловой системы (Path Traversal / Symlink Escape). |
| 50 | `padam/shield/stego_dlp.py` | 189 | Продвинутый детектор закодированной и стеганографической утечки секретов (Stego DLP). |
| 51 | `padam/shield/swarm_breaker.py` | 197 | Кросс-агентный «Стоп-кран» и сдерживание AI-червей (Swarm Circuit-Breaker). |
| 52 | `padam/shield/taint.py` | 340 | Контроль траекторий и Taint Tracking (Control Flow Integrity) для PADAM Agentic Shield. |
| 53 | `padam/shield/tamper_seal.py` | 163 | Самозащита Щита от подмены SQLite (Tamper-Proof HMAC Seal для allowlist и shield_state). |
| 54 | `padam/shield/timelock_quorum.py` | 206 | Time-Lock (задержка охлаждения) и M-of-N кворум для критических операций агентов. |
| 55 | `padam/shield/voice_guard.py` | 175 | Защита голосовых и аудио-агентов (Voice / Audio & Transcript Injection Guard). |
| 56 | `padam/shield/web3_abi.py` | 343 | Локальный декодер смарт-контрактов EVM ABI и инструкций Solana для Кольца 3 (Payee-Swap). |
