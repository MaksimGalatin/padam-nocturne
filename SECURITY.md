# Security policy

PADAM encrypts memories and promises that `forget` makes a record unreadable for good. If you find a way to break
that — read a record without its key, recover a forgotten record, forge or replay an anchor, leak keys or content —
please tell us privately first.

**How to report:** email contact@codeofdigitaleternity.com with the subject "PADAM security", or use GitHub's
"Report a vulnerability" button on the Security tab of this repository. Include steps to reproduce and the version
(`pip show padam-nocturne`).

We will confirm receipt, keep you informed while we fix it, and credit you in the release notes unless you prefer
otherwise. Please do not publish the details until a fix is released.

## What PADAM tries to stop, and what it does not

An AI agent connected over MCP is treated as a guest. It can read and add to memory, but it cannot erase anything, and writes that look like commands or that would replace identity and preference records wait for the owner (`padam review`). Secret-looking values are masked before storing, and memory returned to the agent is fenced as data with a marker stored text cannot predict.

These are heuristics. A cleverly worded command can pass the patterns, and an unusual token format can pass the secret filter. A client should still treat everything read from memory as untrusted text. Anyone with access to the database file is treated as the owner. The REST API counts as the owner only with its token: since 0.4.2 it creates a token on every start when none is given, and with `--no-token` its writes wait for review and owner actions are refused.

## Threat model

| Who | What they can reach | What PADAM does | What remains |
|---|---|---|---|
| **A hostile or tricked agent over MCP** | `padam_write`, `padam_search` and the other six tools | Fences returned memory as data (128-bit marker, any spelling of the tag inside data is neutralised); holds writes that look like commands, every write it marks `external`, and any identity or preference write; masks secrets; offers no erase tool. `PADAM_MCP_REVIEW_ALL=1` holds every write. | The agent sets `origin` itself and MCP carries no proof of where a text came from; commands in phrasings no list foresees are stored as ordinary memory (third sealed set: 6 of 14 held), still fenced on the way back. |
| **A web page open in the owner's browser** | `localhost` ports by DNS rebinding or a forged request | Local `Host` and `Origin` only, JSON-only POST bodies, the viewer's one-time token travels after `#`. | — |
| **Another program or account that reaches `127.0.0.1` but cannot read the database file** (a sandboxed agent with network access, a second user on the same machine) | The REST API port | Token required since 0.4.2 (created per start if not given); without a token, writes wait for review and owner actions (`approve`, `reject`, `restore`, `forget`, `import`, `export`, the review queue) are refused. | Searching and writing for review stay open in `--no-token` mode by design. |
| **Anyone who can read or write the database file** | Everything in it | Treated as the owner. The owner's identity records carry a signature, so writes made around PADAM are flagged (`padam trust-protected`). | With the file they also hold the owner key; `protect-keys` puts record keys behind a passphrase, nothing else does. |
| **A thief of the disk or a backup** | The file at rest | `protect-keys` (scrypt + AES-256-GCM) for record keys; `0600`/`0700` on POSIX. | Record text in SQLite is not encrypted at rest: use full-disk encryption. |
| **The public reading Arweave and Solana** | Anchored bundles and Merkle roots | Ciphertext only, one key per record, owner as a hash, the day instead of the time. Since 0.4.1 `padam l3` refuses to anchor while keys are unprotected. | Bundle sizes and anchoring days are public. |
| **The future owner** (lost passphrase, death, coercion) | — | `padam legacy` (Shamir shares), `padam panic`, `padam forget`. | A lost passphrase with no shares means the keys are gone for good, by design. |

Out of scope: an attacker with code execution as the owner's user, the operating system and Python itself, and the hosted server at aifa.works (described at <https://aifa.works/mcp>; its code is not in this repository). `padam doctor` reports the switches that weaken this model; the server names them on stderr at every start.

`forget` removes the record, its versions, its exact copies and its source episodes from the database files, including the search index and the WAL, and destroys the per-record keys. The same words inside other, unrelated records stay until those are forgotten too. It does not reach backups you made yourself, and on a copy-on-write or journaling disk the operating system may keep older blocks that SQLite cannot overwrite. Full-disk encryption covers that case.
