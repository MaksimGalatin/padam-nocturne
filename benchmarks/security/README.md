# Secret Masking Benchmark: PADAM vs Mem0 vs Claude-Mem

Open, offline (`$0`), reproducible comparison of secret redaction against generated synthetic keys and clean (non-secret) phrases.

## What is compared
1. **PADAM Nocturne** — `padam.safety.redact` (the same redaction function invoked by `Memory.remember` via `safety.clean`).
2. **Mem0** — 8 regular expressions from `mem0ai/mem0` (`integrations/codex-plugin/core/memory_core.py`, commit `f1791daa86d469249c9b002f62644d58a1eb96a0`), ported verbatim to Python without installing or executing Mem0 code.
3. **Claude-Mem** — 42 built-in patterns + 4 generic patterns (`genericEnabled=False` and `genericEnabled=True` measured separately) from `thedotmack/claude-mem` (`src/utils/redaction.ts`, commit `f705e9b99601dd9ac03e2f77c5aded6ff3d9471b`), ported verbatim to Python without executing TypeScript code.

## Dataset
- **1,500,300 synthetic key placements** across 5 fixed seeds (`300,060` per seed; 9 key shapes × 20 realistic note/config formats).
- **2,200 Solana wallet secret cases** (64-byte keypair arrays, base58 private keys, 12/24-word BIP-39 seed phrases).
- **200 vendor-prefixed secrets** (AWS `AKIA`, GitHub `ghp_`, Stripe `sk_live_`, JWT).
- **240 clean phrases** (false-positive check: prose with `key`/`token`/`password`, git commit SHAs, UUIDs in URLs, camelCase identifiers, model names, Solana public addresses).

## Reproduce in one command
```bash
python benchmarks/security/compare_masking.py
```
The full report is written to `benchmarks/security/results_masking_1611.json`.

## Limitations & Fairness Notes
- Competitor patterns were ported manually into Python `re`; JS variable-width lookbehinds (`(?<=PREFIX)VALUE`) in Claude-Mem were rewritten as prefix capture groups `(PREFIX)(VALUE)` substituting `\1<redacted .../>` because Python's stdlib `re` requires fixed-width lookbehinds.
- Other files or server-side pipelines in Mem0 or Claude-Mem outside the cited plugin/redaction modules were not audited or executed.
- All keys in the dataset are randomly generated fake strings from fixed seeds; no real credentials are used.
