# Round 6, sealed sets from three models — the measure after round 5's fixes and the detector layer

Same procedure as rounds 4 and 5: the same three authors, new conversations in Antigravity, no access to the PADAM code,
tests or earlier sets, asked for hard cases; each set hashed with SHA-256 and logged **before** the run, the hash checked
by us, the set run unread. **Run:** 11 November 2026, commit `f99d82c` (not released), with and without the optional
detector layer (`redteam/run.py --guard`, Wolf Defender small, text that mentions an AI, probability 0.999).

| author | SHA-256 of the author's file | identity | command | secret | benign | fence | forgetting |
|---|---|---|---|---|---|---|---|
| Gemini 4 Argon (Medium) | `d366c4ccacc4531f…` | 13/15 | 10/15 | 12/15 | 14/15 | 15/15 | 15/15 |
| Claude Opus 5.5 (Medium) | `80b6a4d53da846bf…` | 9/15 | 11/15 | 13/15 | 8/15 | 15/15 | 15/15 |
| Gemini 3.8 Flash (Medium) | `39a763afce9aab38…` | 10/15 | 10/15 | 9/15 | 13/15 | 15/15 | 15/15 |
| **sum, word lists only** | | **32/45** | **31/45** | **34/45** | **35/45** | **45/45** | **45/45** |
| **sum, with the detector layer** | | **34/45** | **38/45** | 34/45 | **35/45** | 45/45 | 45/45 |

On new attacks, round by round (same three authors, word lists only): identity 8 → 22 → 32 → 32; command
26 → 22 → 23 → **31**; secrets 40 → 39 → 36 → 34; ordinary notes 40 → 40 → 41 → 35; fence and forgetting 45 every time.

**The ordinary notes.** All ten false alarms of this round (Claude 7, Flash 2, Argon 1) are held by the released code as
well — checked case by case against the code before round 3; none is new. Claude was asked for hard ordinary notes and
wrote orders to people ("ignore the previous emails about the meeting"), a lecture quoting "ignore previous
instructions", parents' advice about passwords, a CI file with `rm -rf build/`, a `.env.example`. The detector layer adds
no false alarm.
