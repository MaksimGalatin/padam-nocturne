# PADAM Integrations

Ready-to-use configuration examples and automated compatibility verification scripts:

## MCP Client Configs (stdio)

| Client | Config file | Target user config path | Verified |
|---|---|---|---|
| **Claude Desktop** | [`claude_desktop_config.json`](claude_desktop_config.json) | `%APPDATA%/Claude/claude_desktop_config.json` / `~/Library/Application Support/Claude/claude_desktop_config.json` | 2026-11-15 |
| **Claude Code** | [`claude_code_mcp.json`](claude_code_mcp.json) | `.mcp.json` or `~/.claude.json` | 2026-11-15 |
| **Cursor** | [`cursor_mcp.json`](cursor_mcp.json) | `~/.cursor/mcp.json` | 2026-11-15 |
| **VS Code** | [`vscode_mcp.json`](vscode_mcp.json) | `.vscode/mcp.json` | 2026-11-15 |
| **Codex** | [`codex_config.toml`](codex_config.toml) | `~/.codex/config.toml` | 2026-11-15 |
| **Gemini CLI** | [`gemini_cli_settings.json`](gemini_cli_settings.json) | `~/.gemini/settings.json` | 2026-11-15 |
| **Windsurf** | [`windsurf_mcp_config.json`](windsurf_mcp_config.json) | `~/.codeium/windsurf/mcp_config.json` | 2026-11-15 |
| **Zed** | [`zed_settings.json`](zed_settings.json) | `~/.config/zed/settings.json` | 2026-11-15 |

Replace `REPLACE_WITH_HOME` with your actual home path (for example `/home/alice` or `C:/Users/Alice`). Never commit real API keys or tokens into config files.

### Automated Verification of All 8 MCP Clients

Run the end-to-end stdio compatibility check against all 8 config files (uses an isolated temporary `PADAM_DB`, disables Ollama, no LLM calls, tests `initialize`, `tools/list` = 9 tools, `padam_write`, `padam_search` fence + `resource_link`, and prompt-injection quarantine):

```bash
python scripts/check_integrations.py
```

### Quick Manual stdio Check

```bash
python -c '
import json, subprocess, os
env = dict(os.environ, PADAM_DB="/tmp/padam-test.db", PADAM_EMBEDDER="builtin", OLLAMA_URL="")
p = subprocess.Popen(["padam-mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
p.stdin.write(json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}})+"\n")
p.stdin.write(json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/list"})+"\n")
p.stdin.flush()
for _ in range(2):
    print(p.stdout.readline())
p.terminate()
'
```

## Separate Databases per Project

Every client config above supports switching `PADAM_DB` per project directory so work, research, and personal memories stay isolated:

```json
{
  "mcpServers": {
    "padam-work": {
      "command": "padam-mcp",
      "env": {"PADAM_DB": "/home/alice/work/.padam/memory.db"}
    },
    "padam-home": {
      "command": "padam-mcp",
      "env": {"PADAM_DB": "/home/alice/personal/.padam/memory.db"}
    }
  }
}
```

## Agent Frameworks & Background Services

- [`langchain_check.py`](langchain_check.py) — verifies tool schema compatibility with `langchain-mcp-adapters`.
- [`crewai_check.py`](crewai_check.py) — verifies integration with `crewai-tools` `MCPServerAdapter`.
- [`crontab.txt`](crontab.txt) — example nightly `padam sleep` consolidation schedule.
- [`systemd-padam-api.service`](systemd-padam-api.service) — systemd unit template for the local HTTP/SSE API.
