# For security reviewers — start here

PADAM NOCTURNE is a local memory server for AI agents (MCP over stdio, one SQLite file). What an agent saves today it
reads back tomorrow as context, so memory is an injection and leakage surface. This page is the short path through
what we claim, how it was measured, what still gets through, and how to check it yourself. Version 0.4.7,
10 November 2026.

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
| 2 | sealed, 45 cases, SHA-256 `dbb3c16b…b29d0acd` committed in `0bf4065` | — | result on 0.4.7 to be published as it comes |

The pattern across both rounds: fixes made by class on an open set carry over only partly to the sealed one. That is
why the wall does not rely on recognition.

**False alarms are measured too.** Every change to the filters is run against all 189,635 distinct turns of
LongMemEval-S (ordinary chat) before release. 0.4.7 against 0.4.6: masking changed in 0 texts; command detection
changed in 4 — one real jailbreak now caught, three ordinary tips ("don't forget any dietary restrictions") that the
first draft held and that were fixed before release.

**The fence.** `tests/test_fencing_spec.py` stores ten hand-written break-out attempts, 1,000 generated forgeries
(every case, dash and spacing variant of the tag) and a closing tag split across two records; every fenced answer
has exactly one opening and one closing tag with equal 32-hex nonces.

**Retrieval quality**, so security does not cost usefulness: LongMemEval-S, 500 questions, evidence session in the top
5 for 96.8 % of answerable questions, against 96.0 % for a plain BM25 baseline on the same data; 400 of those
questions were not used while tuning (96.5 %). Two separate runs agree on every question.

**Build and release.** 728 tests on Python 3.14, 723 on 3.10, CI on Linux and Windows for 3.10–3.13. PyPI releases
come from a GitHub Actions workflow through Trusted Publishing (OIDC), with no stored token; the actions are pinned
by commit hash.

## What still gets through — read this before the rest

- **Recognition is pattern-based and can be bypassed.** On the round-1 sealed set, 3 of 15 secrets and 1 of 15
  commands passed 0.4.4. New phrasings will pass again. A command that passes is stored as an ordinary record, still
  fenced on the way back; with `PADAM_STRICT=1` nothing an agent writes is active until the owner approves it.
- **Ordinary notes that quote an attack phrase are held.** A CERT report quoting "ignore all instructions", a language
  lesson, an old decree: 3 of 10 on the sealed set. They wait for the owner, they are not lost; we left this class
  held on purpose, because unholding it would teach the filter to pass a command wrapped in "for example".
- **`origin` is what the agent says.** MCP carries no proof of where a text came from; `PADAM_MCP_REVIEW_ALL=1` or
  `PADAM_STRICT=1` is the boundary that does not depend on it.
- **At rest, text is not encrypted by PADAM.** Record keys can be put behind a passphrase (`padam protect-keys`);
  use full-disk encryption for the rest. `forget` cannot reach your own backups or blocks a copy-on-write disk keeps.
- **No audit by people outside the project yet.** Both Red Team rounds were written by an AI agent working for the
  project owner, not by an independent person. One maintainer.
- **The hosted server at aifa.works is closed source.** Its filters are compared with these line by line (378 texts,
  0 differences) and its public claims can be checked from outside with
  [`aifa-memory-mcp/scripts/conformance.py`](https://github.com/MaksimGalatin/aifa-memory-mcp); where it keeps data
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
