# `padam-client` — TypeScript & JavaScript SDK for PADAM NOCTURNE

Zero-dependency TypeScript/ESM client for:
1. **Local PADAM REST API** (`padam.api` / `padam studio`, `http://127.0.0.1:8077`) — supports Bearer token authentication, `X-Agent-ID` tagging, hybrid search with score breakdown (`explain`), owner-signed `profile()`, review queue (`approve` / `reject`), cryptographic `forget()` receipts, `audit()` log, and SSE `/events`.
2. **AIfa Memory Cloud MCP** (`https://aifa.works/api/mcp`) — JSON-RPC 2.0 client for `padam_write`, `padam_search`, `padam_profile`, and `padam_forget`.
3. **Framework adapters** — `createVercelAiTools(client)` for **Vercel AI SDK** and `createMastraMemoryTools(client)` for **Mastra**.

## Usage (Local REST API)

```ts
import { PadamRestClient } from "padam-client";

const padam = new PadamRestClient({
  baseUrl: "http://127.0.0.1:8077",
  token: process.env.PADAM_API_TOKEN,
  agentId: "cursor-agent",
});

// 1. Fetch owner-signed identity & preferences
const profile = await padam.profile();

// 2. Hybrid search with temporal decay & prompt-injection fencing
const { results } = await padam.search({ query: "PostgreSQL port", limit: 5 });

// 3. Write a decision (external texts with origin="external" are automatically held for review)
await padam.write({
  content: "Primary PostgreSQL runs on port 5432 with WAL archiving.",
  kind: "decision",
  origin: "agent",
});
```

## Usage (Cloud MCP — `aifa.works/api/mcp`)

```ts
import { PadamCloudMcpClient } from "padam-client";

const cloud = new PadamCloudMcpClient({
  apiKey: process.env.AIFA_MCP_KEY!,
  agentId: "claude-code",
});

const prof = await cloud.profile("global");
const hits = await cloud.search({ query: "deployment checklist" });
```

## License

- **PADAM NOCTURNE & Client SDK (`v0.8.0+`):** [`PADAM License 1.0`](LICENSE) (`LicenseRef-PADAM-1.0`) — source-available with 24-month delayed conversion to `Apache-2.0`; copyright © 2026 **CODE Eternal LLC** (New Mexico, USA · Entity ID `0008138873`). Commercial MSA: [`COMMERCIAL-LICENSE.md`](../../COMMERCIAL-LICENSE.md).
