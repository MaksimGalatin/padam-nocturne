# PADAM Agentic Shield

Local-first active defense against machine-speed AI agent exploitation, memory poisoning, MCP tool poisoning/rug-pulls, Unicode steganography, payee-swap attacks, and frontend JS supply-chain compromises (`$0`, zero external cloud telemetry by default).

- **Licensing:** Core under the PADAM License 1.0 (source-available; 15%/20% commission on Earning), GitHub CI Action (`.github/actions/padam-agentic-shield/`) under `Apache-2.0`, Enterprise Commercial License from **CODE Eternal LLC** — see [`COMMERCIAL-LICENSE.md`](../COMMERCIAL-LICENSE.md) &amp; [`LICENSING.md`](LICENSING.md).
- **Standards &amp; Competitors:** [`COMPLIANCE_MAPPING.md`](COMPLIANCE_MAPPING.md) (OWASP ASI01–ASI10 &amp; PCI DSS v4.0.1) and [`COMPETITIVE_COMPARISON.md`](COMPETITIVE_COMPARISON.md).

## Threat Boundaries (Honest Scope)

| Threat Surface | What PADAM Agentic Shield Defends | Code Module |
|---|---|---|
| **Machine-Speed Autonomous Attacks** (Google GTIG / ARTEX pattern) | Sliding-window anomaly detector &amp; tool-call burst limiter automatically trip strict quarantine (`PADAM_STRICT=1`), block external/outbound MCP tools and pause agent writes until manual owner unlock in Studio or CLI | [`padam/agentic_shield.py`](../padam/agentic_shield.py) |
| **Unicode Stealth &amp; Multi-Layer Obfuscation** | Decodes hidden Unicode Tag (`U+E0020..U+E007E`) instructions, Bidi Trojan overrides, mixed-script homoglyphs and nested Base64/Hex/URL payloads | [`padam/agentic_shield.py`](../padam/agentic_shield.py) |
| **MCP Tool Poisoning, Shadowing &amp; Rug-Pulls** | Scans MCP schemas/configs for hidden directives (`<IMPORTANT>`, `~/.ssh`, `.env`, tool shadowing) and pins canonical SHA-256 hashes in `shield_mcp_tool_pins` to catch post-install rug-pulls | [`padam/agentic_shield.py`](../padam/agentic_shield.py) |
| **Memory Poisoning &amp; Prompt Injection** | 128-bit CSPRNG data fence (`FENCING_SPEC.md`), 13-language heuristics (`safety.py`), optional local ONNX guard (`guard.py`), per-agent graphs &amp; intersections, owner-signed identity records | [`padam/safety.py`](../padam/safety.py), [`padam/memory.py`](../padam/memory.py), [`padam/guard.py`](../padam/guard.py) |
| **Outbound Action &amp; Payee-Swap / Typosquatting** | Pre-execution gate inspects EVM/BTC/Solana/TRON wallets, mod-97 IBANs, Luhn card numbers, domain typosquatting (`Levenshtein <= 2`), high-entropy unknown tokens, punycode (`xn--`), SSRF targets &amp; shell commands (`balanced`, `strict_fin`, `paranoid_airgap` profiles) | [`padam/agentic_shield.py`](../padam/agentic_shield.py), [`padam/net_guard.py`](../padam/net_guard.py) |
| **Web JS Supply-Chain &amp; PCI DSS v4.0.1** (Optimizely CDN pattern) | Audits third-party `<script>` tags for SRI (`sha384`), strict CSP, CDN SHA-256 baseline drift (`shield_js_baselines`), HTTP header tamper drift (`shield_header_baselines`, Req `11.6.1`), Req `6.4.3`, hidden iframes, DOM `form.action`/`WebSocket` skimmers, crypto-clippers &amp; outputs **SARIF 2.1.0** + HTML checkups | [`padam/supply_chain_guard.py`](../padam/supply_chain_guard.py), [`.github/actions/padam-agentic-shield/`](../.github/actions/padam-agentic-shield/action.yml) |
| **SIEM / Slack / Teams &amp; Signed Proof Pack** | Zero-secret alert webhooks (Slack Block Kit, MS Teams, ArcSight CEF, Splunk HEC, Elastic ECS, HMAC-SHA256 JSON) + SHA-256/HMAC CISO Proof Pack | [`padam/siem_webhook.py`](../padam/siem_webhook.py), [`padam/audit_chain.py`](../padam/audit_chain.py) |

## Quick Start

```bash
# Inspect Shield state, scan a site with SARIF output, or audit an MCP config with hash pinning
padam shield status
padam shield scan-site https://example.com --out-html checkup.html --out-sarif shield.sarif
padam shield scan-mcp ~/.claude.json --server claude --pin
padam shield webhook-test --format slack

# Per-agent clean chat log (no raw code blocks) & timeline graph sync
padam chats import-history
padam chats list

# Signed Compliance & Threat Proof Pack (JSON, HTML, Markdown)
padam shield proof-pack --out-json proof.json --out-html proof.html --out-md proof.md
```
