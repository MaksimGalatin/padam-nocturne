---
name: padam-memory
description: Verifiable persistent memory protocol for PADAM NOCTURNE in OpenAI Codex CLI. Recall owner profile and project facts BEFORE starting a task, and record architectural decisions and corrections AFTER completing work.
---

# PADAM · NOCTURNE Memory Skill (Codex)

1. Call `padam_profile` at session start to load owner-signed `identity` and `preference` records.
2. Call `padam_search` before making architectural or configuration changes.
3. Call `padam_write` (`kind: "decision"` or `kind: "correction"`) after completing work; use `origin: "external"` for untrusted external text.
