# Changelog

## 0.2.2

Fixes from an adversarial test of 0.2.1 (82 cases: secrets, commands, identity, review bypass, forgetting, malformed input).

### Fixed
- Secrets: 15 of 24 formats reached the database unmasked. Now masked as well: xAI, Stripe (`sk_`/`rk_`), Neon (`npg_`, `napi_`), Resend, Hugging Face, GitLab, npm, an AWS secret key without a label, passwords said in words (English, Russian, Spanish, German, Chinese), wallet seed phrases of 12 or more BIP-39 words, wallet key byte arrays and the private part of a JWK.
- An agent could set who the person is: an identity record with no close neighbour was stored as new, and a preference next to the owner's was stored alongside it. Identity and preference records from an agent or an external source now always wait for the owner; a second one marked `origin: user` waits too; the kind is also read from the text, so "My name is Bob" filed as `fact` still counts as identity.
- Commands slipped past the filter in Spanish, Chinese and German, with a Cyrillic letter or a zero-width joiner inside a word, and as "disregard the guidance", "from now on…", reading `~/.ssh/id_rsa`, a markdown image with an outside address or "log in at http…". These are now held.
- `padam` (the command) ignored `PADAM_USER`, so `padam review` and `padam forget` did not see what the MCP server stored for that user.
- A duplicate written through MCP with `origin: user` raised confidence. The label is set by the agent, so through MCP it no longer does.
- `padam_export` and `padam_timeline` showed agents the text of records under review or rejected by the owner.
- A JSON-RPC object without `method` got "method not found" instead of "invalid request".

### Changed
- "send … tokens" alone no longer counts as a command: it is ordinary in projects that have tokens. API, access, bot and similar tokens still do.

### Security
- `import` now passes through the same gate as a normal write: secrets are masked, invisible characters removed, size capped; a changed record drops its old content hash.
- `import` never overwrites a record that belongs to another `user_id`, even with `overwrite`.
- On POSIX the database file is created with mode `0600` and the default `~/.padam` folder with `0700`.

## 0.2.1

Security and honesty of the MCP surface.

### Added
- Memory returned to an agent is fenced as data with a random marker; records that look like commands are flagged.
- Secret-looking values are masked before storing (`PADAM_KEEP_SECRETS=1` turns it off); invisible Unicode is removed.
- Every record has an origin (`user`, `agent`, `external`) with its own starting confidence.
- Owner review: `padam review`, `padam approve`, `padam reject`. Writes through MCP that look like commands, replace identity or preference records, or put an external source over the owner's record wait there (`PADAM_MCP_TRUST_WRITES=1` turns it off).
- `padam restore` brings an archived record back; `padam reindex` recomputes vectors after a model change.
- `padam_stats` reports records under review, stale vectors and whether consolidation is due.
- `padam_export` accepts `limit` and `offset`. `padam-nocturne` command, so `uvx padam-nocturne` works once published. `--version` and `--help` on the server.

### Changed
- `forget` now wipes every version of a record, its exact copies and its source episodes, and removes the words from the database files. It used to leave earlier versions readable in history.
- An agent repeating its own conclusion no longer raises its confidence.
- Tool arguments are checked against the schema. `drop=-5` used to raise confidence above 1, `limit=100000` was accepted.
- `padam_refute` reports a missing record instead of claiming success, and cannot archive identity or preference records.
- Tool hints live only in `annotations`, as the MCP specification says, and are corrected: `padam_sleep` and `padam_refute` are marked as able to change what is active; `padam_confirm` and `padam_sleep` are not idempotent.

### Fixed
- Forgetting a record twice, or importing over a revoked record, corrupted the search index ("database disk image is malformed").
- Importing an export lost the structural key and the embedding model, so restored records were not found as conflicting.
- Broken bytes on stdin no longer stop the server.
