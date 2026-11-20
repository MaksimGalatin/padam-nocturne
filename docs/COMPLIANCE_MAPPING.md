# Standards & Compliance Mapping — PADAM Agentic Shield

This document maps each implemented module in PADAM Agentic Shield directly to industry frameworks so legal, security, and GRC teams can verify coverage line by line.

---

## 1. OWASP Top 10 for Agentic Applications (ASI01–ASI10)

| OWASP ID | Threat Category | Implemented Enforced Controls in Code |
|---|---|---|
| `ASI01` | **Agent Goal Hijacking & Instruction Override** | `padam/safety.py` (`looks_like_instruction`, 13-language patterns, `fence()` 128-bit random nonce), `padam/agentic_shield.py` (`inspect_unicode_and_encoding`: Unicode Tags `U+E0020..U+E007E`, Bidi overrides, multi-layer Base64/Hex/URL), `padam/guard.py` (local ONNX classifier), `PADAM_STRICT=1` |
| `ASI02` | **Tool Misuse at Machine Speed** | `padam/agentic_shield.py` (`observe_tool_call_rate`, `record_anomaly`, `trip_kill_switch` automatic lockdown, owner-only `unlock_kill_switch`) |
| `ASI03` | **Identity & Privilege Abuse** | `padam/roles.py` (owner vs maintainer/contributor/auditor/guest RBAC), `padam/api.py` (`OWNER_GET` / `OWNER_POST` bearer token checks), `padam/integrity.py` (HMAC-signed protected owner records) |
| `ASI04` | **Agentic & Web Supply-Chain Compromise** | `padam/agentic_shield.py` (`audit_mcp_tools`: tool poisoning `<IMPORTANT>`, shadowing, `~/.ssh`/`.env` access, SHA-256 rug-pull pinning in `shield_mcp_tool_pins`); `padam/supply_chain_guard.py` (SRI, CSP, CDN SHA-256 baseline pinning, DOM/skimmer/clipper rules, `.github/actions/padam-agentic-shield/`) |
| `ASI05` | **Unexpected Code Execution & SSRF** | `padam/net_guard.py` (`validate_outbound_url`: blocks RFC1918/loopback/link-local/metadata IPs, unsafe schemes), `padam/agentic_shield.py` (`_DANGEROUS_SHELL_RE`: blocks `curl\|sh`, encoded PowerShell, reverse shells) |
| `ASI06` | **Memory & Context Poisoning** | `padam/memory.py` (`quarantine` for untrusted instructions and protected-kind edits, `contradiction` detection via `факт_ключ`, `Quarantine Council`) |
| `ASI07` | **Insecure Inter-Agent Communication** | `padam/memory.py` (`agent_id` attribution, `list_agents`, `intersections_matrix`), `padam/phoenix_beacon.py` (Ed25519 identity handshake), `padam/siem_webhook.py` (`X-PADAM-Signature-256` HMAC webhook signing) |
| `ASI08` | **Cascading Failures & Uncontrolled Autonomy** | `padam/agentic_shield.py` (`shield_state.block_writes`, policy profiles `balanced`/`strict_fin`/`paranoid_airgap`, automatic lockdown), `padam/memory.py` (`cognitive_snapshot` rollback) |
| `ASI09` | **Human-Agent Trust Exploitation / Payee-Swap** | `padam/agentic_shield.py` (`inspect_outbound_action`: owner-only approval queue for EVM/BTC/TRON/Solana wallets, IBAN mod-97, Luhn cards, domain typosquatting Levenshtein `<= 2`) |
| `ASI10` | **Rogue Agents & Audit Tampering** | `padam/audit_chain.py` (append-only SHA-256 hash chain + HMAC head anchor), `padam/agentic_shield.py` (`build_proof_pack`, `verify_proof_pack`) |

---

## 2. PCI DSS v4.0.1 (Client-Side Script & Payment Page Integrity)

| Requirement | Summary | Implemented PADAM Control |
|---|---|---|
| **Req 6.4.3** | All payment page scripts executed in consumer browsers must be authorized, verified for integrity, and inventoried. | `padam/supply_chain_guard.py`: full `<script>` inventory, W3C Subresource Integrity (`sha256`/`sha384`/`sha512`) verification + `crossorigin` validation, HTML SRI patch generation, `shield_js_baselines` cryptographic pinning, DOM skimmer (`cardnumber`/`cvv` + `fetch`/`sendBeacon`/`WebSocket`) & `form.action` hijack detection. |
| **Req 11.6.1** | Change- and tamper-detection mechanism on HTTP headers and payment page scripts as received by consumer browsers. | `padam/supply_chain_guard.py`: `shield_header_baselines` tracks drift on `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; flags any change or removal as `http_header_tamper_drift`; compares fetched JS bytes SHA-256 against baseline and emits SARIF 2.1.0 + HTML reports. |

---

## 3. Evidence Artifacts Generated Locally ($0)

- **Signed Proof Pack:** `padam shield proof-pack --out-json ... --out-html ... --out-md ...`
- **Supply-Chain Checkup & SARIF:** `padam shield scan-site <url> --out-html ... --out-sarif ...`
- **MCP Tool Integrity Audit:** `padam shield scan-mcp <mcp_config.json> [--pin]`
- **SIEM / Slack / Teams Payload Preview:** `padam shield webhook-test --format <slack|microsoft_teams|cef|splunk_hec|elastic_ecs>`
