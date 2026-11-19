# ADR-0006: The audit log is hash-chained and anchored with an owner HMAC
- Status: accepted · Date: 2026-11-18 (MEM-02, work of the Antigravity agent)
## Context
An audit log that can be edited silently proves nothing.
## Decision
Each `audit_log` row stores `seq`, `prev_hash`, `entry_hash`; the head is signed with HMAC by the owner key
(`audit_log_anchor`). Rows written before the chain existed (seq IS NULL) are history and are not verified.
## Where in the code
`padam/audit_chain.py` (`verify_audit_log_chain`), `tests/test_phase2_net_wh_audit_ci_1811.py`.
