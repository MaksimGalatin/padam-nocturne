# ADR-0003: Money and outreach are owner-only — never callable by agents over MCP
- Status: accepted · Date: 2026-11-18
## Context
MCP clients are agents. An agent that can send mail, release payouts or record earnings can be prompt-injected
into doing it.
## Decision
`send_outreach, connect_mail, run_outreach_batch, run_follow_up, autopilot_tick, release_payouts, record_earning,
dispute_payout` are refused over MCP; they run only from the owner UI. Changing MCP calls are written to the audit chain.
## Where in the code
`padam/mcp_server.py` (owner gate, `_audit_mcp_call`), tests `test_glm3_owner_gate_1811.py`, `test_top20_mcp_audit_1811.py`.
