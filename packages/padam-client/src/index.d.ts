export type PadamKind =
  | "preference"
  | "identity"
  | "decision"
  | "correction"
  | "fact"
  | "state"
  | "event"
  | "episode";

export type PadamOrigin = "user" | "agent" | "external";

export interface PadamClientOptions {
  /** Base URL of local PADAM API (default: http://127.0.0.1:8077) */
  baseUrl?: string;
  /** Bearer API token (PADAM_API_TOKEN) */
  token?: string;
  /** Optional default X-Agent-ID header sent with writes and searches */
  agentId?: string;
  /** Custom fetch implementation for testing or custom runtimes */
  fetchImpl?: typeof fetch;
}

export interface PadamWriteInput {
  content: string;
  kind?: PadamKind;
  importance?: number;
  scope?: string;
  origin?: PadamOrigin;
  agent_id?: string;
}

export interface PadamWriteResult {
  outcome: "created" | "merged" | "superseded" | "quarantined" | "episode";
  id: string;
  agent_id?: string | null;
}

export interface PadamSearchInput {
  query: string;
  scope?: string;
  kind?: PadamKind;
  limit?: number;
  as_of?: string;
  agent_id?: string;
}

export interface PadamRecordHit {
  id: string;
  kind: PadamKind;
  content: string;
  score: number;
  rrf: number;
  decay: number;
  importance: number;
  confidence: number;
  origin: PadamOrigin;
  agent_id?: string | null;
  created_at: string;
  last_confirmed_at: string;
  expired: boolean;
  status: string;
  scope: string;
  signed: boolean;
  conflict: boolean;
  suspicious: boolean;
  found_by: string[];
  explain: string;
}

export interface PadamProfileResult {
  user_id: string;
  scope: string;
  identity: Array<{
    id: string;
    kind: "identity";
    scope: string;
    content: string;
    confidence: number;
    importance: number;
    created_at: string;
    signed: true;
  }>;
  preferences: Array<{
    id: string;
    kind: "preference";
    scope: string;
    content: string;
    confidence: number;
    importance: number;
    created_at: string;
    signed: true;
  }>;
  unsigned_skipped: number;
  summary: string;
}

export interface PadamForgetReceipt {
  receipt_id: string;
  user_id: string;
  memory_id: string;
  forgotten_at: string;
  content_hash_sha256: string;
  wiped_count: number;
  wiped_ids: string[];
  with_derived: boolean;
  key_destroyed: boolean;
  leaf_forget_hex: string;
}

export interface PadamAuditEntry {
  id: string;
  user_id: string;
  created_at: string;
  action: "write" | "approve" | "reject" | "restore" | "forget";
  memory_id: string | null;
  actor: string;
  agent_id: string | null;
  scope: string;
  kind: string | null;
  outcome: string | null;
  detail: string | null;
}

export declare class PadamRestClient {
  readonly baseUrl: string;
  readonly token?: string;
  readonly agentId?: string;
  constructor(options?: PadamClientOptions);
  health(): Promise<{ status: string; version: string }>;
  write(input: PadamWriteInput): Promise<PadamWriteResult>;
  search(input: PadamSearchInput): Promise<{ results: PadamRecordHit[] }>;
  profile(scope?: string): Promise<PadamProfileResult>;
  records(params?: {
    view?: "active" | "review" | "history";
    q?: string;
    kind?: PadamKind;
    scope?: string;
    agent_id?: string;
    as_of?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ records: Record<string, unknown>[]; total: number }>;
  approve(id: string): Promise<{ ok: boolean }>;
  reject(id: string): Promise<{ ok: boolean }>;
  forget(id: string, withDerived?: boolean): Promise<{ ok: boolean; receipt: PadamForgetReceipt | null }>;
  audit(params?: { limit?: number; action?: string; agent_id?: string }): Promise<{ entries: PadamAuditEntry[] }>;
  eventsSnapshot(replay?: number): Promise<PadamAuditEntry[]>;
}

export interface PadamCloudMcpOptions {
  /** Cloud MCP endpoint (default: https://aifa.works/api/mcp) */
  endpoint?: string;
  /** Personal MCP API key (Bearer token) */
  apiKey: string;
  /** Default agent identifier */
  agentId?: string;
  fetchImpl?: typeof fetch;
}

export declare class PadamCloudMcpClient {
  readonly endpoint: string;
  readonly apiKey: string;
  readonly agentId?: string;
  constructor(options: PadamCloudMcpOptions);
  listTools(): Promise<unknown>;
  callTool(name: string, args?: Record<string, unknown>): Promise<{ text: string; isError: boolean; raw: unknown }>;
  write(input: PadamWriteInput): Promise<{ text: string; isError: boolean; raw: unknown }>;
  search(input: PadamSearchInput): Promise<{ text: string; isError: boolean; raw: unknown }>;
  profile(scope?: string): Promise<{ text: string; isError: boolean; raw: unknown }>;
  forget(id: string, withDerived?: boolean): Promise<{ text: string; isError: boolean; raw: unknown }>;
}

export declare function createVercelAiTools(client: PadamRestClient | PadamCloudMcpClient): Record<string, {
  description: string;
  parameters: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}>;

export declare function createMastraMemoryTools(client: PadamRestClient | PadamCloudMcpClient): Array<{
  id: string;
  description: string;
  inputSchema: Record<string, unknown>;
  execute: (context: { context: Record<string, unknown> }) => Promise<unknown>;
}>;
