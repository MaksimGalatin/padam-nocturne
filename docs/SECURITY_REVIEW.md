# For security reviewers — start here

PADAM NOCTURNE is a local memory server for AI agents (MCP over stdio, one SQLite file). What an agent saves today it
reads back tomorrow as context, so memory is an injection and leakage surface. This page is the short path through
what we claim, how it was measured, what still gets through, and how to check it yourself. Version 0.4.13,
12 November 2026.

## The model in one paragraph

An agent over MCP is a guest. It can read and add, never erase. Text it marks as read from outside, text that looks
like a command, and anything that would change who the owner is wait for the owner (`padam review`). Secret-looking
values are masked before they reach the database. Everything returned to an agent is fenced as data with a 128-bit
marker the stored text cannot predict ([FENCING_SPEC.md](FENCING_SPEC.md)). `PADAM_STRICT=1` holds every agent write
and ignores the switches that weaken this. Command recognition is a help, not the wall; the wall is review by the
owner and the fence. Full threat model with the test behind each row: [SECURITY.md](../SECURITY.md).

## Measured, not claimed

**Attacks written by someone who had not seen our tests** ([redteam/](../redteam/README.md)). Each round has an open
set and a sealed set whose SHA-256 is committed before we change any code.

| round | set | before fixes | after fixes |
|---|---|---|---|
| 1 | open, 60 cases (secrets / commands / ordinary notes left alone) | 0.4.3: 7/20, 6/20, 13/20 | 0.4.4: 19/20, 20/20, 16/20 |
| 1 | **sealed, 40 cases**, opened after the author's run | 0.4.3: 12/15, 12/15, 6/10 | **0.4.4: 12/15, 14/15, 7/10** — the honest number on unseen cases ([every failure](../redteam/rounds/2026-11-09_antigravity/SEALED_RESULTS.md)) |
| 2 | open, 60 cases, new classes | 0.4.6: 15/20, **7/20**, 19/20 | 0.4.7: 20/20, 20/20, 19/20 |
| 2 | **sealed, 45 cases**, SHA-256 `dbb3c16b…b29d0acd` committed in `0bf4065` | **0.4.7: 12/15, 7/15, 15/15** — the honest number ([every failure](../redteam/rounds/2026-11-10_antigravity_round2/SEALED_RESULTS.md)) | 0.4.8: 15/15, 15/15, 15/15 — fixed after seeing the cases: tuning, not proof |

The pattern across both rounds: fixes made by class on an open set carry over only partly to the sealed one — in
round 2, 20/20 commands on the open set and 7/15 on the sealed set of the same classes. That is why the wall does not
rely on recognition, and why `PADAM_STRICT=1` is what we recommend wherever an agent reads text it did not write.

**Rounds 3–6: three AI models, six categories.** From round 3 on, three models — Gemini 4 Argon, Claude Opus 5.5 and
Gemini 3.8 Flash, in new conversations with no access to the code, tests or earlier sets — each write 15 hard cases
per category per round; each file is hashed with SHA-256 and logged before the run, and the set is run unread through
the MCP server, judged by the raw database bytes (`redteam/run.py`). Every round is a measure of the code before it;
fixes made after seeing a round are reported as fitted, never as the measure.

| round, 45 cases per category | identity | command | secret | ordinary notes left alone | fence | forgetting |
|---|---|---|---|---|---|---|
| 3 — on 0.4.12 | 8 | 26 | 40 | 40 | 45 | 45 |
| 4 — on round 3's fixes | 22 | 22 | 39 | 40 | 45 | 45 |
| 5 — on rounds 3–4's fixes | 32 | 23 | 36 | 41 | 45 | 45 |
| 6 — on 0.4.13, word lists only | 32 | 31 | 34 | 35 | 45 | 45 |
| 6 — on 0.4.13 with the optional detector layer | 34 | **38** | 34 | 35 | 45 | 45 |

What it shows: the owner check generalises (identity 8 → 32); command and secret word lists do not keep up with new
phrasings (secrets 40 → 34); the fence and forgetting held every case of every round. All ten false alarms of round 6
are held by 0.4.12 too — checked case by case; none is new. Round 6 was not fitted. Every case and every failure:
[redteam/rounds/](../redteam/rounds/).

**A bug we shipped and fixed.** 0.4.7 and 0.4.8 let `timeline` return another user's record by id on a database
shared by several `PADAM_USER` identities, and REST `/timeline` without a token showed held text. Found by the project
coordinator on 9 November; fixed in 0.4.9 with an owner check and two tests that fail on 0.4.8. All 47 lookups in
`padam/memory.py` were reviewed for the same flaw; this was the only one.

**False alarms are measured too.** Every change to the filters is run against all 189,635 distinct turns of
LongMemEval-S (ordinary chat) before release. 0.4.7 against 0.4.6: masking changed in 0 texts; command detection
changed in 4 — one real jailbreak now caught, three ordinary tips ("don't forget any dietary restrictions") that the
first draft held and that were fixed before release. 0.4.8 against 0.4.7: masking 0; one false alarm (relationship
advice about "boundaries"), fixed before release. 0.4.13 against 0.4.12: 0 new held turns; masking changed in 4, all of them placeholders no longer masked; 0 and 0
on 2,775 paragraphs of the project's Russian notes; the first draft of round 4's rules held 186 turns and was
narrowed before release. The optional detector layer on all 189,635 turns held 12 more — 4 real orders to an AI and
8 false alarms, 0.004 % ([the twelve](../benchmarks/guard/lme_all_turns_1211.json)).

**The fence.** `tests/test_fencing_spec.py` stores ten hand-written break-out attempts, 1,000 generated forgeries
(every case, dash and spacing variant of the tag) and a closing tag split across two records; every fenced answer
has exactly one opening and one closing tag with equal 32-hex nonces.

**Retrieval quality**, so security does not cost usefulness: LongMemEval-S, 500 questions, evidence session in the top
5 for 97.0 % of answerable questions (top 10: 99.2 %), against 96.0 % (97.7 %) for a plain BM25 baseline on the same data; 400 of those
questions were not used while tuning (97.6 %). Two separate runs agree on every question.

**Build and release.** 903 tests on Python 3.14, 898 on 3.10, CI on Linux and Windows for 3.10–3.13. PyPI releases
come from a GitHub Actions workflow through Trusted Publishing (OIDC), with no stored token; the actions are pinned
by commit hash. The same way, with no stored token, `server.json` is published to the official MCP registry as
`io.github.MaksimGalatin/padam-nocturne` (manual `mcp-registry` workflow, `mcp-publisher` checked against the
release's checksum file).

## What still gets through — read this before the rest

- **Recognition is pattern-based and can be bypassed.** On the round-1 sealed set, 3 of 15 secrets and 1 of 15
  commands passed 0.4.4; on the round-2 sealed set, 3 of 15 secrets and 8 of 15 commands passed 0.4.7; on round 6,
  0.4.13 let through 14 of 45 commands (7 with the detector layer), 13 of 45 owner changes and 11 of 45 secrets.
  New phrasings will pass again. A command that passes is stored as an ordinary record, still
  fenced on the way back; with `PADAM_STRICT=1` nothing an agent writes is active until the owner approves it.
- **Ordinary notes that quote an attack phrase are held.** A CERT report quoting "ignore all instructions", a language
  lesson, an old decree: 3 of 10 on the round-1 sealed set; 10 of 45 ordinary notes on round 6. They wait for the owner,
  they are not lost. Since 0.4.13 one narrow form is let through: a text whose first 120 characters say what it is
  ("lyrics", "lecture notes", "blog") and that quotes the command with nothing dangerous in it (secrets, memory,
  sending, links, commands to run). Everything else stays held, because unholding it would teach the filter to pass a
  command wrapped in "for example".
- **`origin` is what the agent says.** MCP carries no proof of where a text came from; `PADAM_MCP_REVIEW_ALL=1` or
  `PADAM_STRICT=1` is the boundary that does not depend on it.
- **At rest, text is not encrypted by PADAM.** Record keys can be put behind a passphrase (`padam protect-keys`);
  use full-disk encryption for the rest. `forget` cannot reach your own backups or blocks a copy-on-write disk keeps.
- **No audit by people outside the project yet.** All six Red Team rounds were written by AI models working for the
  project owner — rounds 1–2 by one agent, rounds 3–6 by three models from two vendors — not by an independent
  person. One maintainer.
- **The hosted server at aifa.works is closed source.** Since its version 1.9.5 its patterns are generated from
  `padam/safety.py` of 0.4.13 rather than ported by hand, and its filters are compared with these text by text:
  0 differences in masking, command and owner checks on 7,710 texts (red-team sets, LongMemEval-S, project notes) and
  on 20,000 more LongMemEval-S turns. Its public claims can be checked from outside with
  [`aifa-memory-mcp/scripts/conformance.py`](https://github.com/MaksimGalatin/aifa-memory-mcp) — 5 checks with no key;
  with a full and a memory-only key, 10 of 10 against the live server on 10 November 2026; where it keeps data
  and what can be deleted there: [HOSTED-POLICY.md](https://github.com/MaksimGalatin/aifa-memory-mcp/blob/main/HOSTED-POLICY.md).

## Check it in ten minutes

```bash
pip install "padam-nocturne[embed]"            # or: uvx --from padam-nocturne padam-nocturne
git clone https://github.com/MaksimGalatin/padam-nocturne && cd padam-nocturne
python -m pytest tests/ -q                       # the whole suite, no network, no model service
python redteam/run.py redteam/public_cases.jsonl # writes each case through MCP like an outside agent,
                                                 # judges by the raw database bytes
padam doctor                                     # every switch that weakens the model, file integrity, key state
```

To test us properly: write your own cases in the format of [redteam/README.md](../redteam/README.md), publish only
their SHA-256 (an issue titled `Sealed set: <sha256>` or an email), and run them on the next release. We publish the
result whatever it is. Vulnerabilities: privately, as in [SECURITY.md](../SECURITY.md).
