# Architecture Decision Records — PADAM NOCTURNE

Each file records one decision that is already in the code: context, decision, consequences, and where it lives.
New decisions use `0000-template.md`. Added 2026-11-19 (roadmap item N10).

| ADR | Decision | Code |
|---|---|---|
| [0001](0001-sqlite-wal-single-file.md) | One local SQLite file in WAL mode is the memory store | `padam/store.py` |
| [0002](0002-local-first-no-cloud-telemetry.md) | Local-first: no cloud telemetry, no outbound data by default | `padam/observability.py` |
| [0003](0003-owner-only-money-tools.md) | Money and outreach actions are owner-only, never callable by agents over MCP | `padam/mcp_server.py` |
| [0004](0004-connection-under-lock.md) | Every use of the shared SQLite connection goes through the store lock | `padam/store.py` `_ConnUnderLock` |
| [0005](0005-per-record-keys-crypto-shredding.md) | Forgetting = destroying a per-record key, with a receipt | `padam/memory.py`, `padam/audit_chain.py` |
| [0006](0006-hash-chained-audit-log.md) | The audit log is hash-chained and anchored with an owner HMAC | `padam/audit_chain.py` |
| [0007](0007-plugins-owner-approved-by-fingerprint.md) | Community plugins load only after owner approval of this exact code | `padam/plugins.py` |
