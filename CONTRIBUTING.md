# Contributing to PADAM · NOCTURNE

Thank you for helping make local AI agent memory safer and verifiable!

## Quick Local Setup

```bash
git clone https://github.com/MaksimGalatin/padam-nocturne.git
cd padam-nocturne
pip install -e ".[test,l3]"
python -m pytest tests/ -q
python redteam/run.py redteam/public_cases.jsonl
```

## Highest-Impact Ways to Contribute

1. **Break our filters (Red Team Challenge):** Try to slip a hidden prompt injection, secret key, MCP rug-pull, or payee-swap past `padam/safety.py` or `PADAM_STRICT=0` defaults. Verified bypasses are credited permanently in [`HALL_OF_FAME.md`](HALL_OF_FAME.md).
2. **Import adapters:** Add or improve local history parsers (ChatGPT, Claude, Gemini, Obsidian, Notion, Telegram, Discord, etc.) with secret-redaction tests.
3. **False-positive reports:** Ordinary notes that were unnecessarily quarantined — open an issue with the anonymized snippet so we can tighten rules without weakening defenses.
4. **Independent benchmarks:** Reproduce `LongMemEval-S` or `redteam/public_cases.jsonl` on your machine and share logs/comparisons (including cases where PADAM loses).

## Licensing, DCO Sign-off & CLA Policy (100% IP Purity)

From `0.8.0`, PADAM core is **source-available** under [`PADAM License 1.0`](LICENSE) (`LicenseRef-PADAM-1.0`), with automatic delayed conversion of each released version to `Apache-2.0` 24 months after its release date (`docs/LICENSING.md`).

To keep copyright clean across future dual-licensing and the 24-month `Apache-2.0` conversion:
- **DCO Required (`git commit -s`):** Every commit in a Pull Request must carry a Developer Certificate of Origin sign-off (`Signed-off-by: Your Name <email>`), certifying you have the legal right to submit the contribution.
- **CLA Required for Core Code:** Before any external code PR can be merged into core packages (`padam/`, Studio, extensions), contributors must execute a Contributor License Agreement assigning or licensing full distribution & dual-licensing rights to **CODE Eternal LLC** (`contact@codeofdigitaleternity.com`; see [`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md)). Bug reports, benchmark logs, and Red Team test cases can always be submitted via Issues without a CLA.

## Pull Request Rules

- Every behavior change or security fix must include a regression test in `tests/`.
- Never commit real API keys, tokens, or personal data in test fixtures (use synthetic tokens clearly prefixed as fake).
- For private vulnerability disclosures, email [`contact@codeofdigitaleternity.com`](mailto:contact@codeofdigitaleternity.com) (see [`SECURITY.md`](SECURITY.md)).
