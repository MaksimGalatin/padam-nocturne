# Подключение PADAM к клиентам

Память общая для всех перечисленных: записал в одном, нашёл в другом.

## Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
`%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "padam": {
      "command": "python",
      "args": ["-m", "padam.mcp_server"],
      "env": {
        "PADAM_DB": "/home/USER/.padam/memory.db",
        "PADAM_USER": "default",
        "OLLAMA_URL": "http://localhost:11434"
      }
    }
  }
}
```

Если пакет не установлен глобально, укажи полный путь:

```json
"command": "/usr/bin/python3",
"args": ["-m", "padam.mcp_server"],
"env": {"PYTHONPATH": "/path/to/padam"}
```

Перезапусти Claude Desktop. В интерфейсе появится значок инструментов.

## Claude Code

```bash
claude mcp add padam -- python -m padam.mcp_server
```

Или вручную в `~/.claude/settings.json` — блок `mcpServers` того же вида.

Проверка: `claude mcp list` должен показать `padam`.

## Cursor

`~/.cursor/mcp.json` — тот же блок `mcpServers`.

## VS Code (расширения с поддержкой MCP)

`.vscode/mcp.json` в корне проекта:

```json
{
  "servers": {
    "padam": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "padam.mcp_server"]
    }
  }
}
```

## Проверка вручную

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | python -m padam.mcp_server
```

Должны прийти два ответа: сведения о сервере и список из восьми
инструментов.

## Разные области памяти под разные проекты

Один и тот же сервер, разные базы:

```json
{
  "mcpServers": {
    "padam-code": {
      "command": "python", "args": ["-m", "padam.mcp_server"],
      "env": {"PADAM_DB": "/home/USER/.padam/code.db"}
    },
    "padam-personal": {
      "command": "python", "args": ["-m", "padam.mcp_server"],
      "env": {"PADAM_DB": "/home/USER/.padam/personal.db"}
    }
  }
}
```

Либо одна база и поле `scope` при записи — тогда история общая, а выдача
разделена.
