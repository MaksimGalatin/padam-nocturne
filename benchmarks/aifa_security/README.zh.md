# AIFaSecurity — AI 智能体记忆安全基准测试（100 项可量化指标，$0，无 LLM）

**AIFaSecurity** 是一套完全离线、可复现且零成本（`$0`，不调用大模型）的安全评测基准，包含 10 大领域共 **100 项实验**（`AS-001`..`AS-100`），支持检测本地内存系统、任意 MCP 服务器（`--target mcp-cmd`）、GitHub 仓库（`--target repo`）及网站 URL（`--target url`）。

```bash
python benchmarks/aifa_security/run_aifa_sec.py
padam aifa-sec --target url --path https://aifa.works --no-write
```
