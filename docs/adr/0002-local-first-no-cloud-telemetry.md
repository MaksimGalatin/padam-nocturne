# ADR-0002: Local-first — no cloud telemetry, no outbound data by default
- Status: accepted · Date: 2026-11-19
## Context
The roadmap proposed Sentry and an OpenTelemetry collector. Both send traces off the machine; traces can carry
fragments of memory.
## Decision
Observability is local: JSON-lines log per day in `PADAM_HOME/logs/mcp-YYYY-MM-DD.jsonl` with trace_id, tool,
duration, result — never arguments. `padam latency` gives p50/p95 (target p95 < 200 ms). Off switch `PADAM_OBS_LOG=0`.
Arweave mirroring stays opt-in (`ARWEAVE_MIRROR=1`) and only ciphertext leaves.
## Consequences
+ Nothing leaves the computer. − No hosted alerting; an operator who wants it can ship the JSON log themselves.
## Where in the code
`padam/observability.py`, hook in `padam/mcp_server.py` after `_audit_mcp_call`.
