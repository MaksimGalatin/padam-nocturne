# Installing PADAM NOCTURNE (for AI agents)

PADAM NOCTURNE is a local MCP memory server. It needs no API key and no account.

## Requirements
- Python 3.10 or newer is pulled in by `uv`; install `uv` first if `uvx` is missing: https://docs.astral.sh/uv/getting-started/installation/

## MCP configuration (stdio)

```json
{
  "mcpServers": {
    "padam": {
      "command": "uvx",
      "args": ["padam-nocturne"]
    }
  }
}
```

Claude Code: `claude mcp add padam -- uvx padam-nocturne`

## Check that it works
After the client restarts, the server exposes 8 tools whose names start with `padam_`. They are padam_search, padam_write, padam_confirm, padam_refute, padam_timeline, padam_export, padam_stats and padam_sleep. Call `padam_stats` to see that the memory answers.

## Where the data lives
One SQLite file, `~/.padam/memory.db` by default; set `PADAM_DB` to use another path. Secrets (API keys, passwords, wallet keys) are masked before they are stored.

## Optional
- `PADAM_LANG=en` or `PADAM_LANG=ru` sets the CLI language.
- Anchoring to Arweave and Solana is optional and off by default; see the README section "L3".
