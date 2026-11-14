# How we tested agent memory on 30,000 fake keys

*13 November 2026 · PADAM NOCTURNE 0.4.17–0.4.18*

An agent sees API keys, database passwords and wallet keys while it works. Whatever it sees can end up in its memory, and memory is read back into prompts, logs and exports. A memory layer has to drop the secret **before** anything is stored. This note explains how we check that, and what the check does not cover.

## Why fake keys

We were about to rotate our own real keys and wanted proof first that memory would not keep the new ones. Testing on real keys would mean writing them into test data, which is exactly the leak we want to prevent. So the check generates **fake** keys at random, in the same formats as the services we really use, and never reads a real key.

## What is generated

Ten formats, a new random value every time:
a Telegram bot token, a payments key of four 7-character groups (no digit is guaranteed), a 32-character IPN secret, a 64-hex master key, a URL-safe encryption secret, a Neon password (`npg_…`), an OpenAI project key, a Postgres URL with a password inside, a Resend key and a 24-character Vercel-style token.

Each value is written into **20 kinds of sentences** that agents and people actually produce — `NAME=value`, `export NAME="value"`, a two-cell Markdown row, JSON, a `.env` fragment, the value on the next line after `NAME:`, and plain prose in English and Russian: "my api key is …", "Here is the token …, keep it.", "новый ключ … — сохрани", "пароль …".

10 formats × 20 sentence kinds × 150 rounds = **30,000 phrases**. A phrase counts as a leak if the secret is still in the text after masking.

Twelve **clean** phrases run alongside — a commit hash, a sha256, "the key insight is…", "token count: 128000", a cache key name, a Solana public key — and must stay untouched.

## Results

| version | leaks | clean phrases masked |
|---|---|---|
| 0.4.16 | 1,927 of 27,000 | — |
| 0.4.17 | **0 of 30,000** | 0 of 12 |
| 0.4.18 | **0 of 30,000** | 0 of 12 |

0.4.17 also kept **0 of 2,200** fake Solana wallet keys: the `id.json` keypair (64 numbers), the base58 secret and 12- and 24-word recovery phrases — while the public wallet address stays readable, so the agent can still pay ([test](../tests/test_solana_wallet_keys_0417.py)).

## The other side: false alarms

A memory that hides too much is useless. We ran the masking over all 189,635 unique chat turns of LongMemEval-S, old version against new. From 0.4.16 to 0.4.17 exactly one turn changed — and it was a real API key sitting in a public dataset.

0.4.18 came from the same kind of check on our own task tracker: 11 of 17 hits were names, not values (a token's name with a date, a variable name, a model tag, SSH key file names). Those are no longer masked; real keys next to them still are ([test](../tests/test_names_not_keys_0418.py)).

## The hosted version

AIfa Memory at `https://aifa.works/api/mcp` runs the same rules. We compare the two implementations text by text on two different corpora: 0 differences, and the hosted copy also keeps 0 of 30,000 fake keys.

## Limits, honestly

- Fake keys follow the formats we know. A secret with no known shape and no label next to it ("here is X" with no word like key, token or password) can still pass.
- Plain hex without a field name looks like a file hash, and base58 of 32–44 characters is treated as an address; both stay open on purpose.
- The check proves masking of text before storage. It says nothing about a key the agent sends elsewhere.

## Reproduce

The fixed-seed versions of these checks run in CI on every commit: [`tests/test_fake_keys_0417.py`](../tests/test_fake_keys_0417.py), [`tests/test_solana_wallet_keys_0417.py`](../tests/test_solana_wallet_keys_0417.py), [`tests/test_names_not_keys_0418.py`](../tests/test_names_not_keys_0418.py).

```bash
uvx padam-nocturne        # the MCP server
pip install padam-nocturne && pytest   # from a clone: the checks above
```
