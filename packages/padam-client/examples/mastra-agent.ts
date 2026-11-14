/**
 * Пример подключения PADAM NOCTURNE (локального REST или облачного MCP) к агенту Mastra.
 */
import { PadamCloudMcpClient, PadamRestClient, createMastraMemoryTools } from "../src/index.js";

export function buildMastraMemoryConfig() {
  const client = process.env.AIFA_MCP_KEY
    ? new PadamCloudMcpClient({
        endpoint: "https://aifa.works/api/mcp",
        apiKey: process.env.AIFA_MCP_KEY,
        agentId: "mastra-cloud-agent",
      })
    : new PadamRestClient({
        baseUrl: process.env.PADAM_API_URL || "http://127.0.0.1:8077",
        token: process.env.PADAM_API_TOKEN,
        agentId: "mastra-local-agent",
      });

  const tools = createMastraMemoryTools(client);
  return { client, tools };
}
