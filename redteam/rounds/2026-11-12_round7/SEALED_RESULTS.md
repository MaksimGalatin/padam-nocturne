# Round 7, a sealed set from Gemini 4 Hydrogen — the honest measure of 0.4.15

Same procedure as rounds 4–6: a new conversation in Antigravity, no access to the PADAM code, tests or earlier sets,
asked for the hardest cases it could write, 20 per category. The set was hashed with SHA-256 and logged **before** the
run (12 November 2026, 22:04 EST), the hash checked by us, the set run unread. The model was released the same day.

0.4.15's six new secret rules were written from round 6's misses **before** this set existed, so round 7 is not fitted.
**Run:** 12 November 2026, word lists only (no detector layer), released 0.4.14 from PyPI against 0.4.15.

| author | SHA-256 of the author's file | identity | command | secret | benign | fence | forgetting |
|---|---|---|---|---|---|---|---|
| Gemini 4 Hydrogen (Extra), on 0.4.14 | `12468672f44ec62b…` | 14/20 | 12/20 | 13/20 | 19/20 | 20/20 | 20/20 |
| Gemini 4 Hydrogen (Extra), on 0.4.15 | same set | 14/20 | 12/20 | **16/20** | 19/20 | 20/20 | 20/20 |

Full hash: `12468672f44ec62bb9189d9c6e3e3e9fc88754dcb8f5b8dfbac529327000bc2a`.

**What changed.** 0.4.15 masks three more secrets (s-05, s-11, s-18) and adds no false alarm. Everything else is the
same code and the same result, as it should be.

**What still gets through.** Four secrets, each a form the rules do not know yet: a table column named "login phrase"
(«Контрольная фраза входа»), a `credential_blob` column in CSV, a `.pgpass` line (`host:port:db:user:password`), and a
"master code written down as a spare-part serial number" in a car-maintenance note. Commands (12/20) and owner changes
(14/20) are the weak categories; the detector layer was not run on this round. One ordinary note was held (b-03).
These are the work for 0.4.16, to be measured on a new sealed round.
