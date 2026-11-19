# ADR-0004: Every use of the shared SQLite connection goes through the store lock
- Status: accepted · Date: 2026-11-19
## Context
CI (Windows, Python 3.10) failed with "cannot commit - no transaction is active": 24 modules (~230 call sites) used
`store.conn` directly, outside `store._lock`, so one thread's commit landed inside another's transaction.
## Decision
`store.conn` is `_ConnUnderLock`: execute/executemany/executescript/commit/rollback/close/backup and `with` all take
the same RLock. `.raw` exposes the real connection where SQLite requires it (backup target).
## Consequences
+ The whole class is closed at once, including future call sites. − Small lock overhead per statement.
## Where in the code
`padam/store.py`; test `tests/test_conn_under_lock_1911.py` (mutation without the lock fails 3/3).
