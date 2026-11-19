# Roadmap — PADAM NOCTURNE

Public, honest, updated with each release. Decisions already taken are in [docs/adr](docs/adr/README.md).
Last update: 2026-11-19.

## Now (done in 0.6.5, verified)
- AIFaSecurity-100 benchmark in Studio, 4 languages, every button described; seal Ed25519 verified in its own line.
- Swarm of agents writing to one memory: 20 and 40 processes, 1000 records, 0 lost.
- Search: 10 000 records p95 47.5 ms, 20 000 — 54 ms (ordinary PC, no GPU).
- Hash-chained audit log with owner HMAC anchor (ADR-0006); connection under lock (ADR-0004).
- Local observability: per-call JSON log with trace_id, `padam latency` p50/p95 (ADR-0002).
- Restore drill: `padam restore-drill` — backup → restore to a temp file → verify fingerprint.
- Personal data inventory: `padam privacy-inventory`.
- Plugin SDK v1: `padam plugin list|approve|revoke|run` — loads only owner-approved code (ADR-0007).

## Next
- Answer accuracy with a local model on LOCOMO (published only after a cold, reproducible run).
- Fair comparison with Mem0 on 400 held-out questions.
- ANN index for > 100 000 records.
- Restore drill on a monthly schedule in CI.

## Later
- Plugin SDK v2: more capabilities and a shared registry (v1 shipped: owner-approved plugins pinned by code fingerprint, read-only memory facade, ADR-0007).
- Mobile companion (PWA) for one-tap owner approvals.

## Not planned (on purpose)
- Cloud telemetry (Sentry or hosted tracing) — memory stays with its owner (ADR-0002).
- Paid bug bounty — responsible disclosure via [SECURITY.md](SECURITY.md).

Ideas and votes: open an issue with the label `roadmap`.
