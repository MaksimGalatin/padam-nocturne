# Contributing to PADAM · NOCTURNE

Thank you for looking. The most useful contributions are real-world reports: where the memory helped your agent,
where it got in the way, and where NOCTURNE kept or dropped the wrong thing.

## 1. Tell us how it behaves in your agent

Open an issue with the **Integration report** template: which client (Claude Code, Claude Desktop, Cursor, VS Code,
your own agent), how long you used it, what it remembered well and what it got wrong. Logs from
`python -m padam stats` and `python -m padam recall "<query>" --explain` help a lot. Share only what you are
comfortable sharing — never paste private memories.

## 2. Report a bug

Use the **Bug report** template with the exact command, the full output and your OS / Python version.
Before opening a pull request, run the tests:

```bash
pip install -e ".[test,l3]"
python -m pytest tests/ -q
```

## 3. Security

Weaknesses in encryption, key handling, forgetting or the Arweave / Solana layer must **not** go into public issues —
see [SECURITY.md](SECURITY.md).

## 4. Pull requests

Bug fixes, new integrations (configs in `integrations/`), tests and documentation are welcome. Keep the honest
limits in README up to date if your change affects them.

Licence: AGPL-3.0. By opening a pull request you agree that your contribution is licensed under the same terms.

Questions: contact@codeofdigitaleternity.com · https://aifa.works/nocturne
