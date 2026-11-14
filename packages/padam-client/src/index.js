/**
 * PADAM · NOCTURNE TypeScript/JavaScript Client (Б5)
 * Клиент для локального REST API (`padam.api` / `padam studio`) и облачного MCP (`aifa.works/api/mcp`),
 * включая адаптеры инструментов для Vercel AI SDK и Mastra.
 */

export class PadamRestClient {
  constructor(options = {}) {
    this.baseUrl = String(options.baseUrl || "http://127.0.0.1:8077").replace(/\/+$/, "");
    this.token = options.token || undefined;
    this.agentId = options.agentId || undefined;
    this._fetch = options.fetchImpl || globalThis.fetch.bind(globalThis);
  }

  _headers(extra = {}) {
    const h = { "Content-Type": "application/json", ...extra };
    if (this.token) h["Authorization"] = `Bearer ${this.token}`;
    if (this.agentId && !h["X-Agent-ID"]) h["X-Agent-ID"] = this.agentId;
    return h;
  }

  async _request(method, path, body, extraHeaders = {}) {
    const res = await this._fetch(`${this.baseUrl}${path}`, {
      method,
      headers: this._headers(extraHeaders),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || `PADAM HTTP ${res.status}`);
      err.status = res.status;
      err.payload = data;
      throw err;
    }
    return data;
  }

  async health() {
    return this._request("GET", "/health");
  }

  async write(input) {
    const payload = {
      content: input.content,
      kind: input.kind,
      importance: input.importance ?? 0.5,
      scope: input.scope ?? "global",
      origin: input.origin ?? "agent",
      agent_id: input.agent_id ?? this.agentId,
    };
    const headers = payload.agent_id ? { "X-Agent-ID": String(payload.agent_id) } : {};
    return this._request("POST", "/write", payload, headers);
  }

  async search(input) {
    const payload = {
      query: input.query,
      scope: input.scope ?? "global",
      kind: input.kind,
      limit: input.limit ?? 5,
      as_of: input.as_of,
      agent_id: input.agent_id,
    };
    return this._request("POST", "/search", payload);
  }

  async profile(scope = "global") {
    return this._request("GET", `/profile?scope=${encodeURIComponent(scope)}`);
  }

  async records(params = {}) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
    }
    const qs = q.toString();
    return this._request("GET", `/records${qs ? `?${qs}` : ""}`);
  }

  async approve(id) {
    return this._request("POST", "/approve", { id });
  }

  async reject(id) {
    return this._request("POST", "/reject", { id });
  }

  async forget(id, withDerived = false) {
    return this._request("POST", "/forget", { id, with_derived: Boolean(withDerived) });
  }

  async audit(params = {}) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
    }
    const qs = q.toString();
    return this._request("GET", `/audit${qs ? `?${qs}` : ""}`);
  }

  async eventsSnapshot(replay = 10) {
    const res = await this._fetch(
      `${this.baseUrl}/events?once=1&replay=${encodeURIComponent(String(replay))}`,
      { method: "GET", headers: this._headers() }
    );
    if (!res.ok) throw new Error(`PADAM SSE HTTP ${res.status}`);
    const text = await res.text();
    const out = [];
    for (const block of text.split("\n\n")) {
      const lines = block.trim().split("\n");
      const evLine = lines.find((l) => l.startsWith("event:"));
      const dataLine = lines.find((l) => l.startsWith("data:"));
      if (!dataLine) continue;
      const evName = evLine ? evLine.slice(6).trim() : "message";
      if (evName === "ready") continue;
      try {
        out.push(JSON.parse(dataLine.slice(5).trim()));
      } catch {}
    }
    return out;
  }
}

export class PadamCloudMcpClient {
  constructor(options) {
    if (!options || !options.apiKey) {
      throw new Error("PadamCloudMcpClient requires options.apiKey");
    }
    this.endpoint = String(options.endpoint || "https://aifa.works/api/mcp");
    this.apiKey = options.apiKey;
    this.agentId = options.agentId || undefined;
    this._fetch = options.fetchImpl || globalThis.fetch.bind(globalThis);
    this._rpcId = 1;
  }

  async _rpc(method, params = {}) {
    const id = this._rpcId++;
    const headers = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.apiKey}`,
    };
    if (this.agentId) headers["X-Agent-ID"] = this.agentId;
    const res = await this._fetch(this.endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.error) {
      throw new Error((data.error && data.error.message) || `MCP HTTP ${res.status}`);
    }
    return data.result;
  }

  async listTools() {
    return this._rpc("tools/list", {});
  }

  async callTool(name, args = {}) {
    const result = await this._rpc("tools/call", { name, arguments: args });
    const content = Array.isArray(result?.content) ? result.content : [];
    const text = content
      .filter((c) => c && c.type === "text")
      .map((c) => c.text)
      .join("\n");
    return { text, isError: Boolean(result?.isError), raw: result };
  }

  async write(input) {
    return this.callTool("padam_write", {
      content: input.content,
      kind: input.kind,
      importance: input.importance ?? 0.5,
      scope: input.scope ?? "global",
      origin: input.origin ?? "agent",
      agent_id: input.agent_id ?? this.agentId,
    });
  }

  async search(input) {
    return this.callTool("padam_search", {
      query: input.query,
      scope: input.scope ?? "global",
      kind: input.kind,
      limit: input.limit ?? 5,
      as_of: input.as_of,
      agent_id: input.agent_id,
    });
  }

  async profile(scope = "global") {
    return this.callTool("padam_profile", { scope });
  }

  async forget(id, withDerived = false) {
    return this.callTool("padam_forget", { id, with_derived: Boolean(withDerived) });
  }
}

export function createVercelAiTools(client) {
  return {
    padam_profile: {
      description: "Read the owner-signed identity and preferences profile from PADAM memory before starting a task.",
      parameters: {
        type: "object",
        properties: {
          scope: { type: "string", description: "Project or domain scope (default: global)" },
        },
      },
      execute: async (args = {}) => client.profile(args.scope || "global"),
    },
    padam_search: {
      description: "Search PADAM hybrid memory (vectors + FTS5 + graph + temporal decay) with prompt-injection fencing.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query" },
          kind: { type: "string", description: "Optional memory kind filter" },
          scope: { type: "string", description: "Scope (default: global)" },
          limit: { type: "number", description: "Max results (default: 5)" },
          as_of: { type: "string", description: "Optional ISO date YYYY-MM-DD for Time Machine lookup" },
        },
        required: ["query"],
      },
      execute: async (args) => client.search(args),
    },
    padam_write: {
      description: "Store a fact, decision, or correction into PADAM memory (secrets are masked, untrusted commands are held).",
      parameters: {
        type: "object",
        properties: {
          content: { type: "string", description: "Fact or decision to remember" },
          kind: { type: "string", description: "fact | decision | correction | state | event" },
          importance: { type: "number", description: "Importance 0.0..1.0" },
          scope: { type: "string", description: "Scope (default: global)" },
          origin: { type: "string", description: "agent | external (use external for web/file content)" },
        },
        required: ["content"],
      },
      execute: async (args) => client.write(args),
    },
  };
}

export function createMastraMemoryTools(client) {
  const v = createVercelAiTools(client);
  return Object.entries(v).map(([id, def]) => ({
    id,
    description: def.description,
    inputSchema: def.parameters,
    execute: async ({ context }) => def.execute(context || {}),
  }));
}
