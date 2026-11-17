# 诚实问答基准测试：LongMemEval-S + LoCoMo-10（$0，无付费 API / 无 LLM）

日期：`2026-11-17T01:10:12Z` | PADAM 版本：`0.6.2` | 费用：`$0.0` | 嵌入器：`builtin` | 耗时：`128.18 秒`  
脚本：[`qa_honest_bench.py`](qa_honest_bench.py) | 原始结果：[`results_qa_honest_1611.json`](results_qa_honest_1611.json)

## 汇总结果

由于本地 Ollama 暂无已安装模型且遵循 `$0` 原则，**PADAM** 与 **Plain BM25** 均使用同一确定性离线答案提取器（`offline_extractive_0usd`）。

| 数据集 | 系统 | N | Evidence R@5 | Evidence R@10 | Token F1 | Token Recall | Short Fact Match | 延迟 p50 / p95 (ms) | Abstention Acc |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| LongMemEval-S (`stride=5`) | **PADAM** | 94 | 0.9362 | **0.9787** | 0.0707 | 0.2914 | **0.2771** | 64.17 / 80.71 | 0.0 (n=6) |
| LongMemEval-S (`stride=5`) | Plain BM25 | 94 | **0.9574** | **0.9787** | **0.0750** | **0.2956** | **0.2771** | 1.76 / 2.43 | 0.0 (n=6) |
| LoCoMo-10 (`stride=4`) | **PADAM** | 388 | 0.8325 | 0.8737 | **0.0817** | 0.2560 | 0.1102 | 4.00 / 5.38 | 0.0 (n=112) |
| LoCoMo-10 (`stride=4`) | Plain BM25 | 388 | **0.8814** | **0.9253** | 0.0809 | **0.2667** | **0.1237** | 0.61 / 0.88 | 0.0 (n=112) |

在 LoCoMo 的 `multi-hop`（`ev@10 = 0.8507`、`token_f1 = 0.0601`）和 `temporal`（`token_f1 = 0.0969`、`short_fact_match = 0.1163`）类别中，PADAM 均优于 BM25 基线。
