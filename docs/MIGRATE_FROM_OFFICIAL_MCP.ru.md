# Переезд с официальной памяти MCP (`@modelcontextprotocol/server-memory`) на PADAM за 2 минуты

Любой учебник, промпт или агент, написанный под официальный `@modelcontextprotocol/server-memory`, работает на PADAM Nocturne **без единой правки вызовов** — и сразу получает маскировку ключей, карантин prompt-инъекций и квитанции криптографического забвения.

## 1. Установка и авто-настройка PADAM

```bash
pip install padam-nocturne
padam setup --all
```

## 2. Включение режима совместимости в конфигурации клиента

Добавьте `PADAM_MCP_COMPAT=official-memory` (или флаг `--compat official-memory`):

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

Все 9 официальных инструментов (`create_entities`, `create_relations`, `add_observations`, `delete_entities`, `delete_observations`, `delete_relations`, `read_graph`, `search_nodes`, `open_nodes`) работают 1:1 вместе с 9 базовыми инструментами PADAM.

## 3. Перенос существующего файла `memory.jsonl`

```bash
padam migrate --from official_mcp memory.jsonl
```

Либо откройте PADAM Studio → вкладка **Переезд** → выберите **MCP Memory (memory.jsonl)**.
Все наблюдения и связи проходят через маскировку секретов и фаервол внедрений, а `delete_*` выполняется через мягкий отзыв с криптографической квитанцией (`Memory.revoke`).
