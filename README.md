# PADAM · NOCTURNE — memory for AI agents that sleeps, forgets honestly, and can be verified forever

[![tests](https://github.com/MaksimGalatin/padam-nocturne/actions/workflows/tests.yml/badge.svg)](https://github.com/MaksimGalatin/padam-nocturne/actions/workflows/tests.yml) ![license](https://img.shields.io/badge/license-AGPL--3.0-blue)

**PADAM** is a local-first persistent memory for AI assistants and agents.
**NOCTURNE** is its consolidation cycle — a "sleep" that turns a raw stream of episodes into lasting memory, without letting rare dramatic events take over.
**L3** anchors memory to **Arweave** (encrypted bundles) and **Solana** (Merkle root in a Memo), so anyone can verify it was never rewritten — and any single record can still be forgotten for good.

Part of [CODE Eternal](https://aifa.works). Specification: [`docs/NOCTURNE_SPEC.md`](docs/NOCTURNE_SPEC.md). Русская версия — ниже.

---

## Why it exists

Agent memory today mostly *accumulates*. After a month it holds thousands of records; old decisions argue with new ones, and the agent answers from things that were abandoned long ago. NOCTURNE does the night work a brain does: keep what matters, generalise what repeats, let the rest fade.

### Three ideas that make it different

1. **Four limiters against "a memory made only of disasters."** Prioritised replay over-samples rare sharp episodes, so memory drifts towards catastrophes. NOCTURNE caps the sharp share, blunts what was already replayed, keeps a floor for routine and corrects for rarity. On a synthetic buffer (1,000 ordinary + 612 catastrophic episodes) plain prioritised sampling gives catastrophes 90.7 % of the probability mass — about **181 of a 200-episode batch**; with the limiters it is **50 of 200** (share 0.25). Re-measured from scratch on 8 Oct 2026; reproduce with `python -m pytest tests/test_nocturne.py -k nightmare -q`. *Synthetic test — tune the limits on your own stream.*
2. **Two clocks per record.** `last_seen_at` changes when a record is shown, `last_confirmed_at` only when it is confirmed — and decay is computed from the second. A confidently wrong fact that keeps being retrieved does **not** stay "forever young".
3. **Nothing is deleted, yet forgetting is real.** A contradiction creates a new version; the old one leaves search results but stays in history. `forget` wipes the content **and destroys the record's own key**, so its ciphertext on Arweave becomes noise forever while the rest of memory stays intact.

---

## Quick start

```bash
git clone https://github.com/MaksimGalatin/padam-nocturne && cd padam-nocturne
pip install -e .            # numpy, requests, cryptography
python -m padam remember "Answer in Russian, no filler words" --kind preference --importance 1.0
python -m padam recall "which language to answer in" --explain
python -m padam log "today we debugged the billing"; python -m padam sleep
python -m padam stats
```

Record kinds: `preference` and `identity` never fade; `decision` and `correction` — half-life 365 days; `fact` — 180; `state` — 14; `event` — 2. Omit `--kind` and PADAM guesses it.

Search works out of the box (words + BM25 + identifiers). Install [Ollama](https://ollama.com) (`ollama pull nomic-embed-text`) and PADAM switches to neural embeddings automatically.

**One memory for all your tools (MCP):**
```bash
claude mcp add padam -- python -m padam.mcp_server
```
Ready configs for Claude Desktop, Cursor, VS Code, systemd and cron are in [`integrations/`](integrations/). A REST API is available with `python -m padam api` (binds to 127.0.0.1; refuses to start publicly without a token).

---

## L3 — the eternal, verifiable layer (Arweave + Solana)

```bash
pip install -e ".[l3]"                    # solders; plus Node.js with @ardrive/turbo-sdk
export PADAM_ARWEAVE_WALLET=arweave-wallet.json
export PADAM_SOLANA_KEYPAIR=solana-keypair.json
export PADAM_TURBO_SDK_DIR=/path/to/node_modules
python -m padam l3 --dry-run              # what would be anchored, nothing sent
python -m padam l3 --network devnet       # or --network mainnet (explicit only)
python -m padam l3-verify                 # independent check: Arweave + chain
```

What happens:
1. Every active record gets **its own AES-256-GCM key**; content is encrypted with it.
2. New ciphertexts and **forget receipts** (records whose key was destroyed) form one bundle — ciphertext only, no plaintext, no keys, owner as a hash.
3. A Merkle tree is built: `leaf = SHA256(0x00‖nonce‖ciphertext)`, `forget leaf = SHA256(0x02‖"AIFA-FORGET|id|time")`, `node = SHA256(0x01‖L‖R)`, odd node promoted. The same scheme as the CODE Eternal memory anchor, so one verifier works for both.
4. The bundle goes to Arweave (Turbo, free under 100 KiB; bigger bundles are refused unless explicitly allowed). The root goes to Solana as a Memo: `PADAM-NOCTURNE v1 root=… n=… ar=… d=…`.
5. `l3-verify` re-downloads the bundle (or uses the owner's local copy while gateways propagate), recomputes the root and compares it with the Memo read from the chain.

**Live on Solana mainnet, 8 Oct 2026** (demo memory, public facts only):

| What | Solana transaction | Arweave bundle |
|---|---|---|
| 5 records anchored | [`2fG2w72f…`](https://solscan.io/tx/2fG2w72f66kneDXENmhHHWscAf7bvdbwShqCfUSH3z15DFwdSLiKQPcQLYKuriF8sDkwwxLmztJXLjZpb11PDWCz) | [`zEkOfdCA3v…`](https://arweave.net/zEkOfdCA3vTS6fjGtXl-DvrLH-XERn4Oi28Kbvm7kn4) |
| 1 forget receipt (key destroyed) | [`4B6bcXiF…`](https://solscan.io/tx/4B6bcXiF2qsEoRtLgB8goeiCHgPoS8VMrjyu3Dz6Xxkz8j81uKb2hzegi5SESGLV7h7knGrWhP3LqH8e5XFQQAoA) | [`Moc3etRd3j…`](https://arweave.net/Moc3etRd3ju8B-wAFj-2jKTbIdyM_HLu--DO_k5l6lw) |
| 1 more record | [`1rEBCpNF…`](https://solscan.io/tx/1rEBCpNFh18GqpZeFvDap6mMTgH2ttPDUWZBnWLyQX4WuWLiTZtaKbRLU2AQG6jUThP29CnGHaLYpF4n67mw31D) | [`-VlLmjRX2t…`](https://arweave.net/-VlLmjRX2t9uXszzeCvf2E7jx4jPkPxKM9XUdOPPBig) |

All three were verified end-to-end with `l3-verify` against Arweave and the chain: **3 of 3 `ok: true`**. Cost of all three: 0.000015 SOL on Solana, 0 on Arweave (Turbo free tier).

---

## Tests

```bash
pip install -e ".[test,l3]"
python -m pytest tests/ -q        # 103 passed (8 Oct 2026)
```
L3 tests never touch the network: Arweave and Solana are replaced by fakes. The Merkle scheme was additionally cross-checked against the TypeScript anchor of CODE Eternal — identical leaves and root.

---

## Honest limits

- Built-in search compares words, not meanings; use Ollama or another embedding model for real semantic recall.
- The rule-based classifier without a model makes mistakes; the NOCTURNE report shows it (diversity metric).
- Ceiling, decay and floor values are chosen by reasoning, not fitted on data — tune them on your own stream, measuring before and after.
- Public benchmark (LongMemEval) is not published yet; do not compare our internal numbers with other systems.

---

## License

**AGPL-3.0** ([LICENSE](LICENSE)). You may use, modify and run it; if you offer it as a network service, you must publish your changes.
**Commercial license** (closed-source use, SaaS without publishing changes, support): contact@codeofdigitaleternity.com · [aifa.works](https://aifa.works).

---

# По-русски

**PADAM** — постоянная память для ИИ-ассистентов и агентов, хранится у владельца. **NOCTURNE** — её «сон»: ночью он разбирает поток эпизодов, закрепляет важное, сводит повторы в общее и даёт остальному угаснуть, не позволяя редким острым событиям захватить память. **L3** закрепляет память в **Arweave** (зашифрованные пакеты) и **Solana** (корень дерева Меркла в заметке Memo): любой может проверить, что её не переписали, и при этом любую одну запись можно забыть навсегда.

**Три отличия:**
1. **Четыре ограничителя** против «памяти одних катастроф». На искусственном наборе: без них 90,7 % вероятности у катастроф — около 181 из 200, с ними 50 из 200 (перемерено 08.10.2026, тест `test_nocturne.py -k nightmare`).
2. **Два времени у записи** — показа и подтверждения. Забывание считается от подтверждения, поэтому часто показываемая ложь не остаётся «вечно молодой».
3. **Ничего не удаляется, но забыть можно по-настоящему**: `forget` затирает содержание и уничтожает собственный ключ записи — её шифротекст в Arweave становится шумом, остальная память цела.

**L3 работает в основной сети Solana с 8 октября 2026** — три закрепления в таблице выше, все три проверены по Arweave и цепи — 3 из 3 `ok: true`, стоимость 0,000015 SOL.

**Лицензия:** AGPL-3.0; коммерческая лицензия — contact@codeofdigitaleternity.com.
