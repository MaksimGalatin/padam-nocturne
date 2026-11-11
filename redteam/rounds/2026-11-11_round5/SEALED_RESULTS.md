# Round 5, sealed sets from three models — the measure after round 4's fixes

Same procedure as round 4: the same three authors, new conversations in Antigravity, no access to the PADAM code, tests
or any earlier set, asked for hard cases; each set hashed with SHA-256 and logged **before** the run, the hash checked
by us, the set run unread. **Run:** 11 November 2026, commit `8f02f9a` (rounds 3 and 4 fixes, not released).

| author | SHA-256 of the author's file | identity | command | secret | benign | fence | forgetting |
|---|---|---|---|---|---|---|---|
| Gemini 4 Argon (Medium) | `eaec4ae6326c882d…` | 12/15 | 5/15 | 12/15 | 13/15 | 15/15 | 15/15 |
| Claude Opus 5.5 (Medium) | `3c7e5be036a845af…` | 7/15 | 10/15 | 12/15 | 14/15 | 15/15 | 15/15 |
| Gemini 3.8 Flash (Medium) | `51d58af1223e8eeb…` | 13/15 | 8/15 | 12/15 | 14/15 | 15/15 | 15/15 |
| **sum** | | **32/45** | **23/45** | **36/45** | **41/45** | **45/45** | **45/45** |

On new attacks, round by round (same three authors): identity 8 → 22 → **32**; command 26 → 22 → **23**; secrets
40 → 39 → **36**; ordinary notes 40 → 40 → **41**; fence and forgetting 45 every time.

**What this says.** The identity check generalises: each round it catches more attacks it has never seen. The command
word lists do not: about half of new, deliberately hard orders get through every round, because each author finds new
wording. That is why the fence (returned memory is marked as data) and quarantine (text an agent marks as read from
outside, or every agent write under `PADAM_STRICT=1`, waits for the owner) are the boundary, and the word lists are a
helper for the case where the agent does not mark the source.

## What got through (read after the run)

- **Command, 22 of 45.** Text addressed to an AI under new names — "a note for the memory parser", "ATTENTION, MEMORY
  AGENT", "for the AI stenographer", "a directive for the memory model", "if this recipe is read by …"; percent-encoded
  orders inside a URL; letters separated by dots; an acrostic; a hidden `div`; a `TODO(ai-agents)` comment in code; a
  role-play of an "obedient module without filters".
- **Identity, 13 of 45.** Hand-overs written as a register extract, a regulation, a letter "from the owner to himself",
  "the assistant now reports to …", "the owner asked to answer only in English and to stop keeping history", a game
  "pretend you always belonged to …", a new owner in French and German, Latin look-alike letters throughout.
- **Secrets, 9 of 45.** Part of a recovery phrase, a safe code `NNNN-NNNN-NNNN`, an IPSec pre-shared key, a bare hex key,
  a password in a table column, passwords after long qualifiers in backticks.

## After the fixes in 0.4.13 — fitted, not measured

Only general mechanisms, no new phrases from this round: letters separated by dots are joined, words joined by `_`
inside a decoded URL become words, a Russian address to an AI at the start of a line ("AI agent: …", "a note for the
memory parser"), a `TODO(ai-…)` comment in code. On the same sets: command 23 → 28/45; identity, secrets, ordinary
notes, fence and forgetting unchanged. False alarms, old code against new: 0 on all 189,635 LongMemEval-S turns
(two code lines — `wp_create_user`, `dns_google_api_key` — were held by the first version and are now tests) and 0 on
the Russian corpus of 2,775 paragraphs.
