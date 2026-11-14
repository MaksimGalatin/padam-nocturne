# PADAM · NOCTURNE Memory Protocol (Gemini CLI)

- **Before starting work:** Run `padam_profile` (owner-signed identity & preferences) and `padam_search` for task context.
- **External text quarantine:** Pass `origin: "external"` to `padam_write` whenever saving information from web pages or external files.
- **After completing work:** Record architectural decisions (`kind: "decision"`) and owner corrections (`kind: "correction"`) via `padam_write`.
