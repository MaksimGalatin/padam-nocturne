# Migrate from Official MCP Memory (`@modelcontextprotocol/server-memory`) to PADAM in 2 Minutes

Any tutorial, prompt, or agent built for `@modelcontextprotocol/server-memory` runs on PADAM Nocturne **without modifying a single tool call**, while gaining DLP secret masking, prompt-injection quarantine, and cryptographic forgetting receipts.

## 1. Install and auto-configure PADAM

```bash
pip install padam-nocturne
padam setup --all
```

## 2. Enable compatibility mode in your MCP client config

Add `PADAM_MCP_COMPAT=official-memory` (or pass `--compat official-memory`):

```json
{
  "mcpServers": {
    "memory": {
      "command": "padam-mcp",
      "args": ["--compat", "official-memory"],
      "env": {
        "PADAM_MCP_COMPAT": "official-memory"
      }
    }
  }
}
```

All 9 official tools (`create_entities`, `create_relations`, `add_observations`, `delete_entities`, `delete_observations`, `delete_relations`, `read_graph`, `search_nodes`, `open_nodes`) are exposed 1:1 alongside PADAM's 9 core tools.

## 3. Import your existing `memory.jsonl`

```bash
padam migrate --from official_mcp memory.jsonl
```

Or open PADAM Studio → **Move in** tab → select **MCP Memory (memory.jsonl)**.
Every entity observation and relation is scanned for leaked secrets and prompt injections before entering active memory, and deletions issue verifiable revocation receipts (`Memory.revoke`).
