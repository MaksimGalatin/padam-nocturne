# Contributing to PADAM · NOCTURNE

Thank you for helping make local AI agent memory safer and verifiable!

## Quick Local Setup

```bash
git clone https://github.com/MaksimGalatin/padam-nocturne.git
cd padam-nocturne
pip install -e ".[dev]"
python -m pytest tests/ -q
python redteam/run.py redteam/public_cases.jsonl
```

## Highest-Impact Ways to Contribute

1. **Break our filters (Red Team Challenge):** Try to slip a hidden prompt injection, secret key, MCP rug-pull, or payee-swap past `padam/safety.py` or `PADAM_STRICT=0` defaults. Verified bypasses are credited permanently in [`HALL_OF_FAME.md`](HALL_OF_FAME.md).
2. **Import adapters:** Add or improve local history parsers (ChatGPT, Claude, Gemini, Obsidian, Notion, Telegram, Discord, etc.) with secret-redaction tests.
3. **False-positive reports:** Ordinary notes that were unnecessarily quarantined — open an issue with the anonymized snippet so we can tighten rules without weakening defenses.
4. **Independent benchmarks:** Reproduce `LongMemEval-S` or `redteam/public_cases.jsonl` on your machine and share logs/comparisons (including cases where PADAM loses).

## Pull Request Rules

- Every behavior change or security fix must include a regression test in `tests/`.
- Never commit real API keys, tokens, or personal data in test fixtures (use synthetic tokens clearly prefixed as fake).
- For private vulnerability disclosures, email [`contact@codeofdigitaleternity.com`](mailto:contact@codeofdigitaleternity.com) (see [`SECURITY.md`](SECURITY.md)).
