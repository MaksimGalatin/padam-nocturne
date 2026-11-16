# Migrar desde la Memoria MCP Oficial (`@modelcontextprotocol/server-memory`) a PADAM en 2 Minutos

Cualquier tutorial o agente creado para `@modelcontextprotocol/server-memory` funciona en PADAM Nocturne **sin cambiar una sola llamada**, sumando enmascarado DLP de secretos, cuarentena contra inyecciones de prompt y recibos de borrado criptográfico.

## 1. Instala y configura PADAM

```bash
pip install padam-nocturne
padam setup --all
```

## 2. Activa el modo de compatibilidad en tu cliente MCP

Agrega `PADAM_MCP_COMPAT=official-memory` (o `--compat official-memory`):

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

## 3. Importa tu archivo `memory.jsonl`

```bash
padam migrate --from official_mcp memory.jsonl
```

O abre PADAM Studio → pestaña **Mudanza** → selecciona **MCP Memory (memory.jsonl)**.
