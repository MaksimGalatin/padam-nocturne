# ADR-0007: Community plugins load only when the owner approved this exact code
- Status: accepted · Date: 2026-11-19 (roadmap item B6)
## Context
Community tools should not require forking the repository, and must not get the keys to the core.
## Decision
A plugin is a folder in `PADAM_HOME/plugins/<name>/` with `plugin.json` (name, version, entry, capabilities) and one
Python file exposing `register(api)`. It loads only after `padam plugin approve <name>`; the approval stores the SHA-256
of the manifest and the code, so any later change blocks loading until approved again. The only capability is
`memory:read`; the facade returns copies of records and lets the plugin register its own tools.
## Consequences
+ No fork needed; changed code never runs silently. − This is not a sandbox against malicious code (Python cannot
provide one): trust comes from the owner reading and approving the plugin.
## Where in the code
`padam/plugins.py`, `padam/cli.py` (`padam plugin ...`), `tests/test_plugins_b6_1911.py` (mutation: without the
fingerprint check the test fails).
