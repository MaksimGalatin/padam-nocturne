# ADR-0001: One local SQLite file in WAL mode is the memory store
- Status: accepted · Date: 2026-10 (recorded 2026-11-19)
## Context
Memory must live with its owner, work offline, move on a USB stick and survive several agents writing at once.
## Decision
A single SQLite file, `journal_mode=WAL`, `synchronous` left at the SQLite default (FULL; `padam doctor` reports it), `busy_timeout=30000`, transactions `BEGIN IMMEDIATE`
(writers queue instead of failing on lock upgrade — measured 2026-11-18: 4–6 % "database is locked" before, 0 after).
The whole schema is created in one IMMEDIATE transaction so parallel first starts do not collide.
## Consequences
+ No server, $0, portable, one file to back up. − Above ~100 000 records search needs an ANN index (planned).
## Where in the code
`padam/store.py` (`Store.__init__`, `_дополнить_схему`), measurement `benchmarks/scale/concurrent_writers.py`.
