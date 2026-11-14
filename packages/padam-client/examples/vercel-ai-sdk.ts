/**
 * Пример подключения PADAM NOCTURNE к Vercel AI SDK (`generateText` / `streamText`).
 * Зависимости: нулевые внутри `padam-client`; передаётся готовый словарь инструментов.
 */
import { PadamRestClient, createVercelAiTools } from "../src/index.js";

export async function runWithVercelAiSdk(generateTextFn: Function, model: unknown) {
  const padam = new PadamRestClient({
    baseUrl: process.env.PADAM_API_URL || "http://127.0.0.1:8077",
    token: process.env.PADAM_API_TOKEN,
    agentId: "vercel-ai-agent",
  });

  // 1. В начале работы читаем подписанный владельцем профиль (identity + preferences)
  const ownerProfile = await padam.profile("global");

  // 2. Передаём инструменты памяти в Vercel AI SDK
  const tools = createVercelAiTools(padam);

  return generateTextFn({
    model,
    system: `Owner profile (verified signature):\n${ownerProfile.summary}`,
    tools,
    prompt: "Check our database port in memory and record the backup decision.",
  });
}
