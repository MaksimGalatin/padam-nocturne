# 密钥遮蔽基准对比：PADAM vs Mem0 vs Claude-Mem

开放、离线（`$0`）、可复现的密钥遮蔽对比评测，覆盖合成密钥与正常无害文本（误报检测）。

## 对比对象
1. **PADAM Nocturne** — `padam.safety.redact`（`Memory.remember` 通过 `safety.clean` 实际调用的函数）。
2. **Mem0** — 来自 `mem0ai/mem0` (`integrations/codex-plugin/core/memory_core.py`, commit `f1791daa86d469249c9b002f62644d58a1eb96a0`) 的 8 条正则表达式。
3. **Claude-Mem** — 来自 `thedotmack/claude-mem` (`src/utils/redaction.ts`, commit `f705e9b99601dd9ac03e2f77c5aded6ff3d9471b`) 的 42 条内置模式 + 4 条通用模式（分别测试 `genericEnabled=False` 与 `True`）。

## 一键复现
```bash
python benchmarks/security/compare_masking.py
```
完整结果写入 `benchmarks/security/results_masking_1611.json`。

## 局限性说明
- 竞品正则均手动按字面迁移至 Python `re`，未安装或运行第三方代码；JS 中的变长后瞻断言（lookbehind）在 Python 中改写为前缀捕获组 `\1`。
- 仅评估上述引用文件中的模式；所有测试密钥均为固定随机种子生成的模拟字符串。
