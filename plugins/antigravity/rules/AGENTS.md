# PADAM · NOCTURNE Memory Rules

1. **Recall first:** At the start of a task, call `padam_profile` to load owner-signed identity and preferences, and `padam_search` to retrieve prior project decisions.
2. **Quarantine external sources:** Always pass `origin: "external"` to `padam_write` when saving text from web pages or third-party files.
3. **Persist decisions and corrections:** After finishing a task or receiving an owner correction, call `padam_write` with `kind: "decision"` or `kind: "correction"`.
