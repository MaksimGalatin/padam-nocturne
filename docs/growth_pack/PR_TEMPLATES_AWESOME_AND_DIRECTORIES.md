# PADAM NOCTURNE — Готовые PR-шаблоны и заявки в ТОП-20 площадок MCP

Все файлы и сниппеты готовы к прямой подаче на GitHub / каталоги без ручного сочинения текста. Внешние PR открываются исключительно после подтверждения Архитектора.

---

## 1. Дожим открытых PR

- **Glama-бейдж в `punkpeye/awesome-mcp-servers#19462`:** PR уже имеет статус `CLEAN` и `check-submission = SUCCESS`. Для ускорения мерджа: войти через GitHub на `https://glama.ai/mcp/servers/MaksimGalatin/padam-nocturne`, нажать **Claim**, проверить появление score-бейджа и ответить в PR #19462:
  > Claimed on Glama and updated README with the score badge (`glama.json` already present at repo root). Ready for review.
- **`punkpeye/awesome-remote-mcp-servers#4682` (`aifa-memory`):** статус `CLEAN` (`check-submission = SUCCESS`), пояснение по маркеру 🔑 уже оставлено в комментариях.
- **`docker/mcp-registry#7095` (`aifa-memory`):** уже открыт. Рядом готов пакет для `padam-nocturne` в [`docker_mcp_registry_padam-nocturne/`](./docker_mcp_registry_padam-nocturne/).

---

## 2. Готовые строки для Pull Request в awesome-списки и маркетплейсы

### A. `modelcontextprotocol/servers` (Third-Party Servers — Security / Memory)
```markdown
- **[PADAM NOCTURNE](https://github.com/MaksimGalatin/padam-nocturne)** — Local-first SQLite memory server with 4 deterministic defense rings (MCP tool poisoning / Rug-Pull SHA-256 pinning, Unicode Tag/Bidi decoder, outbound payee-swap/DLP gate, per-record crypto-shredding, and `AIFaSecurity-100` Grade S benchmark).
- **[AIfa Memory](https://github.com/MaksimGalatin/aifa-memory-mcp)** — Hosted Streamable HTTP cross-client MCP server (`https://aifa.works/api/mcp`, 15 tools) that shares masked verbatim memory across Claude Code, Cursor, VS Code, Codex, and Antigravity.
```

### B. `wong2/awesome-mcp-servers` и `appcypher/awesome-mcp-servers`
```markdown
- [MaksimGalatin/padam-nocturne](https://github.com/MaksimGalatin/padam-nocturne) - Local SQLite agent memory with prompt-injection quarantine, secret redaction before disk writes, and 4-ring Agentic Shield (`pip install padam-nocturne`).
- [MaksimGalatin/aifa-memory-mcp](https://github.com/MaksimGalatin/aifa-memory-mcp) - Hosted cross-client MCP memory over Streamable HTTP with Bearer-key isolation and secret masking (`https://aifa.works/api/mcp`).
```

### C. `cline/mcp-marketplace` / `LobeHub MCP` / `Cursor Directory` / `OpenTools`
- **Локальный сервер (`padam-nocturne`):** `githubUrl = https://github.com/MaksimGalatin/padam-nocturne`, команда `padam-mcp` (или `uvx padam-nocturne`), категория `Security & Memory`, конфиг в корне `smithery.yaml` + `glama.json` + `server.json`.
- **Облачный сервер (`aifa-memory`):** `url = https://aifa.works/api/mcp`, transport `streamable-http`, категория `Memory`, Bearer auth (`https://aifa.works/mcp`), реестр `works.aifa/aifa-memory`.

---

## 3. Ссылки прямого Claim для каталогов (без регистрации с нуля)

1. Glama (`padam-nocturne` & `aifa-memory`): `https://glama.ai/mcp/servers/MaksimGalatin/padam-nocturne`
2. PulseMCP: `https://www.pulsemcp.com/servers` (обновить описание до `0.6.5` + добавить `aifa-memory`)
3. MCP.so: `https://mcp.so` (обновить `padam-nocturne` + подать `aifa-memory`)
4. Smithery.ai: `https://smithery.ai/new` (указать репозиторий `MaksimGalatin/padam-nocturne`, `smithery.yaml` уже готов)
5. Serverdex / MCPServers.org / MCPMarket: `https://mcpservers.org`, `https://mcpmarket.com` (кнопка `Claim` / GitHub auth)
