# Honest Technical Comparison: PADAM Agentic Shield vs. Commercial & Open Alternatives

> **Methodology:** Every PADAM capability below corresponds strictly to implemented modules in `padam/` (`agentic_shield.py`, `supply_chain_guard.py`, `siem_webhook.py`, `safety.py`, `audit_chain.py`, `chats.py`, `memory.py`). External vendor capabilities are summarized strictly from their public documentation as of November 2026.

---

## Capability Matrix (4 Rings of Defense)

| Defense Capability | PADAM Agentic Shield (`0.6.5`) | Lakera Guard | Palo Alto Prisma AIRS | Snyk / Invariant `agent-scan` | Cloudflare Page Shield / Feroot |
|---|---|---|---|---|---|
| **Zero-Cloud / Air-Gapped $0 Runtime** | Yes (SQLite + CPU + HMAC/SHA-256 local) | Cloud SaaS / Enterprise container | Enterprise cloud / hybrid | CLI / Cloud telemetry | SaaS Edge / Browser script |
| **Persistent AI Memory Defense & 128-bit Nonce Fencing** | Yes (`memory.py`, `safety.py`, `guard.py`) | No memory engine (stateless prompt guard) | Limited to session inspection | No memory store | N/A |
| **Machine-Speed Anomaly Lock / Kill Switch** | Yes (`shield_state`, `observe_tool_call_rate`, owner-only unlock) | Policy blocking | Runtime alert / block | Static / dynamic scan | N/A |
| **Outbound Payee-Swap & Wallet/IBAN/Card Gate** | Yes (`0x`/`bc1`/`TRC20`/`SOL`, IBAN mod-97, Luhn, typosquatting, entropy) | Partial PII/secret checks | DLP rules | Secret regexes | Client-side form monitor |
| **Unicode Tag (`U+E00xx`), Bidi & Multi-Layer Base64/Hex** | Yes (`inspect_unicode_and_encoding`) | Yes | Yes | Partial | N/A |
| **MCP Tool Poisoning, Shadowing & Rug-Pull SHA-256 Pinning** | Yes (`audit_mcp_tools` + `shield_mcp_tool_pins`) | No native MCP schema pin DB | Partial tool scan | Yes (`mcp-scan`) | N/A |
| **Web JS Supply-Chain: SRI, CSP, CDN SHA-256 Drift & Crypto-Clippers** | Yes (`supply_chain_guard.py`, offline + Playwright) | N/A | N/A | N/A | Yes |
| **PCI DSS v4.0.1 Req 6.4.3 & 11.6.1 Header Drift** | Yes (`shield_header_baselines` + `compliance`) | N/A | N/A | N/A | Yes (primary focus) |
| **Signed CISO Proof Pack (SHA-256 + Owner HMAC + SARIF 2.1.0)** | Yes (`build_proof_pack` + `supply_chain_to_sarif`) | Compliance exports | Enterprise reports | SARIF CLI | PCI DSS reports |
| **SIEM / Slack / Teams Zero-Secret Webhooks** | Yes (`siem_webhook.py`: Slack, Teams, CEF, Splunk HEC, Elastic ECS) | Enterprise SaaS | Enterprise SaaS | SaaS | Enterprise |
| **Multi-Agent Memory Graphs & Cross-Agent Intersections** | Yes (`memory.graph(agent_id, mode)` + Studio 3D + Clean Chats tab) | N/A | N/A | N/A | N/A |

---

## Where PADAM Agentic Shield Stands Alone

No single competing vendor combines all four layers into a local-first, cryptographically verifiable single-binary/package architecture:
1. **Before & inside the agent:** persistent memory protection + Unicode steganography decoding + MCP tool poisoning/rug-pull pinning (`Snyk agent-scan` + `Lakera Guard` scope).
2. **At machine-speed runtime:** autonomous burst anomaly lock (blocking `ARTEX`/`exploit_agent`-like loops) with hardware/owner-only unlock.
3. **At execution boundary:** Outbound Gate stopping payee-swaps, typosquatting domains, high-entropy keys, and unapproved bank/crypto destinations.
4. **At the web perimeter:** client-side JS supply-chain guard (stopping `Optimizely`-class CDN compromises, skimmers, crypto-clippers, and PCI DSS 4.0.1 header drift) + ready Apache-2.0 GitHub Action.
