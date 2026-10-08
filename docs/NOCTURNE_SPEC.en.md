# NOCTURNE — Memory Consolidation Protocol

**Status:** specification v0.2 (v0.1 — 31 Aug 2026; v0.2 — 8 Oct 2026: decay clock aligned with the code, L3 implemented)
**Part of:** PADAM, the L1 → L2 transition layer, plus the L3 anchor
**Author:** Maksim Galatin
**Russian original:** [`NOCTURNE_SPEC.md`](NOCTURNE_SPEC.md)

---

## 1. Problem

PADAM defines three storage levels:

| Level | Medium | Content |
|---|---|---|
| L1 | Redis / Vercel KV (in this package: SQLite buffer) | Context of the current session |
| L2 | pgvector / Neon (in this package: SQLite + embeddings) | Semantic embeddings of experience |
| L3 | Arweave + Solana | Immutable anchor |

The original design had no mechanism for moving between levels. NOCTURNE fills that gap: an offline procedure that moves episodes from L1 to L2, deciding what to keep as a generalisation, what to keep as an episode, and what to let fade.

Without such a procedure the system only accumulates. Accumulating memory without priority control degrades: old decisions conflict with new ones, rare sharp episodes crowd out ordinary ones, and the agent answers from things that were abandoned long ago.

---

## 2. The defect NOCTURNE removes

### 2.1. Mechanism

In prioritized experience replay episodes are not replayed uniformly. The priority of episode `i`:

```
p_i = (|δ_i| + ε)^α
```

where `δ_i` is the prediction (temporal-difference) error, `α` controls the degree of prioritisation, and `ε` keeps the priority from reaching zero.

Probability of sampling the episode into a batch:

```
P(i) = p_i / Σ_k p_k
```

Consequence: high-error episodes — rare, extreme, unusual — are replayed many times more often than ordinary ones.

### 2.2. Effect

The system overfits on rare catastrophes and degrades on typical cases. The training distribution stops matching the distribution of real experience.

A literary statement of the same defect (PADAM PROTOCOL, part III): 612 deaths accumulated by a diagnostic AI merge into a continuous nightmare, because each of them carries the maximum error and is therefore replayed more often than thousands of ordinary appointments.

**Sleep built as plain prioritized replay becomes a second prison.**

Measured on a synthetic buffer of 1,000 ordinary and 612 catastrophic episodes: plain prioritized sampling gives catastrophes 90.7 % of the probability mass, about 181 of a 200-episode batch (re-measured 8 Oct 2026, `tests/test_nocturne.py -k nightmare`).

---

## 3. Solution: four limiters

### 3.1. Bias correction (importance sampling)

Prioritized sampling shifts the distribution. It is compensated with weights:

```
w_i = ( 1 / (N · P(i)) )^β
```

`N` is the buffer size, `β` grows from 0.4 to 1.0 over training. Weights are normalised by `max(w)` for stability. This is a standard PER component and is mandatory: without it prioritisation introduces a systematic error.

### 3.2. Cap on the high-priority share

In every batch the share of episodes from the top priority percentile is limited:

```
K_max = 0.25          # no more than 25 % of the batch
```

The remainder is filled by stratified sampling over the other groups. This is a direct analogue of a "nightmare filter": the sharp is present but does not fill the whole night. On the synthetic buffer above the batch contains 50 of 200 catastrophes instead of ~181.

### 3.3. Priority decay after replay

The key difference from classic PER. An episode that has already been consolidated loses its sharpness:

```
p_i ← p_i · γ_replay        # γ_replay = 0.85
```

Meaning: an experience that was revisited and processed no longer demands to be revisited. The episode is not deleted — it stops dominating.

Without this rule a single extreme-error episode is replayed indefinitely.

### 3.4. Priority floor

Ordinary episodes must not vanish from sampling entirely:

```
p_i ← max(p_i, p_floor)     # p_floor = 0.01 · median(p)
```

This keeps routine represented. A system that remembers only the exceptional loses the norm against which the exceptional is defined.

---

## 4. Decay by record kind

Different kinds of memory live differently. Final weight of a record at retrieval:

```
score = similarity
      × importance
      × confidence
      × exp( -ln(2) · Δt / half_life[kind] )
      × status_multiplier
```

| kind | Content | Half-life |
|---|---|---|
| `preference` | How the person wants to be worked with | never decays |
| `identity` | Who the person is, what they do | never decays |
| `decision` | A decision taken | 365 days |
| `correction` | A correction of something said earlier | 365 days |
| `fact` | A stable fact | 180 days |
| `state` | Current state of a process | 14 days |
| `event` | A dated event | 2 days |

**Two clocks per record (changed in v0.2).** `last_seen_at` is updated when a record is shown; `last_confirmed_at` only when it is confirmed (`padam confirm`, or a duplicate arriving). `Δt` is measured from **`last_confirmed_at`**. v0.1 measured it from `last_seen_at`; that made a confidently wrong fact — retrieved often precisely because it is relevant — "forever young". Showing a record does not make it true.

---

## 5. Contradiction resolution

Every new record passes a filter before entering L2:

1. A structural key (object + property, without the value) finds a competing record exactly; otherwise semantic search among active records of the same `kind`, cosine threshold 0.85 with neural embeddings (Ollama) or 0.35 with the built-in method (`PADAM_SIM_THRESHOLD_*`).
2. No match → create the record, `confidence = 1.0`.
3. Match → classify the pair:

| Outcome | Action |
|---|---|
| Duplicate | Do not create. `last_seen_at ← now`, `last_confirmed_at ← now`, `confidence += 0.05` |
| Refinement | Merge content into one record |
| Contradiction | New record with `supersedes = old.id`; the old one gets `status = 'superseded'` |
| Coexistence | Both stay active |

**Nothing is deleted.** `superseded` records do not appear in results but remain in the database. This gives audit, rollback and — essential for L3 — the natural shape for immutable storage: Arweave cannot hold an "update", only a new version referring to the previous one.

---

## 6. Revoke — separate from forgetting

`revoke` ≠ `superseded`. It executes a person's demand to delete data.

```
status     = 'revoked'
content    = NULL          # physically wiped
embedding  = NULL
content_hash               # kept
anchor_tx                  # kept
anchor_key.key_ref         # wiped ('destroyed') — the record's own key
```

L3 holds **only ciphertext**. Revocation is implemented as destroying the record's key (crypto-shredding): the data stays on chain but is unreadable forever. This is the only known way to reconcile GDPR Article 17 with immutable storage.

---

## 7. Session boundaries

Timestamps do not tell whether a person returned to a previous conversation or started a new one. An explicit `session_id` is needed.

A new session starts when any of these holds:

- a new dialogue is explicitly opened;
- more than 6 hours passed since the last message;
- the cosine distance between the current session's embedding centroid and the new message is > 0.5 (topic change).

At retrieval, records of the current session get a 1.3 multiplier, records of an earlier session of the same day — 1.1.

---

## 8. NOCTURNE cycle — pseudocode

```python
def nocturne_cycle(buffer, batch_size=256):
    """Offline L1 → L2 consolidation. Runs on a schedule,
    not during a dialogue."""

    # 1. Priorities with a floor
    p = np.maximum(priorities(buffer), P_FLOOR)

    # 2. Split into groups
    hi_mask = p >= np.percentile(p, 90)
    n_hi    = min(int(batch_size * K_MAX), hi_mask.sum())
    n_rest  = batch_size - n_hi

    # 3. Sampling with a cap on the sharp
    batch  = sample(buffer[hi_mask],  n_hi,   weights=p[hi_mask])
    batch += stratified(buffer[~hi_mask], n_rest, by='kind')

    # 4. Bias correction
    w = importance_weights(batch, beta=current_beta())

    # 5. Consolidation
    for ep, weight in zip(batch, w):
        record = summarize(ep, weight)
        resolve_and_store(record)        # section 5
        ep.priority *= GAMMA_REPLAY      # section 3.3

    # 6. Decay by kind
    apply_decay(store)                   # section 4
```

---

## 9. L3 — the immutable anchor (implemented in v0.2: `padam/anchor.py`)

1. Every active record gets its own AES-256-GCM key (`anchor_key`); content is encrypted with it. Record bytes = `nonce(12) ‖ ciphertext`.
2. New ciphertexts and **forget receipts** (records whose key was destroyed) form one bundle: ciphertext only, no plaintext, no keys, owner as a SHA-256 hash.
3. Merkle tree — the same scheme as the CODE Eternal memory anchor (`memory-anchor.ts`), cross-checked leaf by leaf:
   ```
   record leaf = SHA256(0x00 ‖ record bytes)
   forget leaf = SHA256(0x02 ‖ UTF-8 "AIFA-FORGET|<id>|<destroyed_at>")
   node        = SHA256(0x01 ‖ left ‖ right)      # odd node promoted, not duplicated
   ```
4. The bundle goes to Arweave (Turbo; free under 100 KiB, larger bundles refused unless explicitly allowed). The root goes to Solana as a Memo: `PADAM-NOCTURNE v1 root=<hex> n=<leaves> ar=<arweave id> d=<date>`. Mainnet only when named explicitly.
5. Each anchored record stores the Solana signature and slot (`anchor_tx`, `anchor_slot`); every anchor is logged in `l3_anchor` / `l3_leaf`; the owner keeps a local copy of each bundle.
6. Verification (`padam l3-verify`) needs no trust in the database: fetch the bundle from Arweave (or the local copy), recompute the root, read the Memo from the chain, compare.

Live since 8 Oct 2026 on Solana mainnet; three anchors verified 3 of 3 against Arweave and the chain (see README).

---

## 10. Validation metrics

The protocol is considered working when all hold at once:

| Metric | Threshold |
|---|---|
| High-priority share in a batch | ≤ 0.25 |
| Entropy of the `kind` distribution in a batch | ≥ 0.8 of maximum |
| Degradation on ordinary tasks (regression) | ≤ 2 % |
| Share of episodes replayed > 5 times | ≤ 1 % |
| Contradictions left unresolved | 0 |

The regression test is mandatory: without it the cap on the sharp could be set to anything without noticing that the system stopped learning from what matters.

---

## 11. What is new and what is borrowed

**Borrowed from existing work:** prioritized replay and bias correction; consolidation and replay in continual learning; complementary learning systems as an architectural scheme; methods against catastrophic forgetting.

**Added here:** a cap on the share of high-priority episodes in a batch and priority decay after replay as explicit protections against overfitting on the rare; decay measured from confirmation rather than from display; differentiated decay by record kind; crypto-shredding with per-record keys and forget receipts anchored in the same Merkle root, to reconcile the right to erasure with an immutable anchor.

There is no claim of novelty for the idea of consolidation during sleep itself — it is long-standing neuroscience theory, and in 2026 several labs publish sleep-style consolidation for LLM agents. What is new is the combination: concrete limiters on top of PER, the two-clock decay, and a three-level store with a verifiable immutable anchor.

---

## 12. Open questions

1. `K_MAX`, `GAMMA_REPLAY`, `P_FLOOR` are set by reasoning. They need fitting on a real buffer.
2. Pair classification (duplicate / refinement / contradiction) is done by a small model or rules. Classifier accuracy is not measured.
3. The 0.85 semantic-match threshold is not validated across record kinds — it probably should differ by `kind`.
4. Cycle frequency is not defined. Too often — wasted compute; too rarely — L1 overflows.
5. A public benchmark (LongMemEval) has not been run yet; internal numbers must not be compared with other systems.
