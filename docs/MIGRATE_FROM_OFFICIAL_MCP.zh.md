# 2 分钟从官方 MCP 记忆（`@modelcontextprotocol/server-memory`）迁移到 PADAM

任何面向 `@modelcontextprotocol/server-memory` 编写的教程或智能体，都可**零修改**在 PADAM Nocturne 上运行，同时自动获得密钥遮蔽（DLP）、提示词注入隔离以及可验证的加密遗忘回执。

## 1. 安装并自动配置 PADAM

```bash
pip install padam-nocturne
padam setup --all
```

## 2. 在 MCP 客户端配置中启用兼容模式

添加 `PADAM_MCP_COMPAT=official-memory`（或 `--compat official-memory`）：

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

## 3. 导入现有的 `memory.jsonl`

```bash
padam migrate --from official_mcp memory.jsonl
```

或者打开 PADAM Studio → **迁入** 标签页 → 选择 **MCP Memory (memory.jsonl)**。
