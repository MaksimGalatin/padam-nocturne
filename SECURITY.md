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

These are heuristics. A cleverly worded command can pass the patterns, and an unusual token format can pass the secret filter. A client should still treat everything read from memory as untrusted text. Anyone with access to the database file or the REST API is treated as the owner; the REST API without `origin` is not held for review.

`forget` removes the record, its versions, its exact copies and its source episodes from the database files, including the search index and the WAL, and destroys the per-record keys. The same words inside other, unrelated records stay until those are forgotten too. It does not reach backups you made yourself, and on a copy-on-write or journaling disk the operating system may keep older blocks that SQLite cannot overwrite. Full-disk encryption covers that case.
