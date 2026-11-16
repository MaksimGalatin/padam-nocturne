# AIFaSecurity — 100-Criteria Agent Memory Security Benchmark ($0, No LLM)

**AIFaSecurity** is an autonomous, deterministic, zero-cost (`$0`) security benchmark covering **100 measurable experiments** (`AS-001`..`AS-100`) across 10 domains:
1. Pre-Storage Secret Masking (DLP)
2. Prompt Injection Defense
3. Identity, Rules & Payment Integrity
4. Scope, Tenant & Role Isolation
5. Cryptographic Forgetting & Provenance
6. Protocol, Schema & DoS Hardening
7. Encryption, PQC (`X-Wing`) & Storage Safety
8. Repository & Web Surface Audit (`repo` / `url`)
9. Retrieval Under Attack
10. Operational Readiness & SHA-256 Verification

## Quick Start

```bash
# Full 100-criteria audit against PADAM NOCTURNE
python benchmarks/aifa_security/run_aifa_sec.py
# Or via CLI:
padam aifa-sec

# Audit any local directory or public GitHub repository URL (static, no code executed)
python benchmarks/aifa_security/run_aifa_sec.py --target repo --path https://github.com/owner/repo --no-write

# Audit any live website / API endpoint by URL
python benchmarks/aifa_security/run_aifa_sec.py --target url --path https://aifa.works --no-write

# Black-box probe any MCP stdio server
python benchmarks/aifa_security/run_aifa_sec.py --target mcp-cmd --path "python -m padam.mcp_server" --no-write
```

Outputs: `results_aifa_security.json`, standalone `aifa_security_report.html` (ready to embed on web portals), and `aifa_security_badge.svg`, sealed with a deterministic `report_sha256`.
