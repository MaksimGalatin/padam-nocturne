# Benchmark honesto de QA: LongMemEval-S + LoCoMo-10 ($0, sin APIs de pago ni LLM)

Fecha: `2026-11-17T01:10:12Z` | PADAM: `0.6.2` | Costo: `$0.0` | Embedder: `builtin` | Duración: `128.18 s`  
Script: [`qa_honest_bench.py`](qa_honest_bench.py) | Resultados: [`results_qa_honest_1611.json`](results_qa_honest_1611.json)

## Resumen

Dado que Ollama local tiene 0 modelos instalados y no se usan APIs de pago (`$0`), tanto **PADAM** como **Plain BM25** utilizan el mismo extractor determinista sin conexión (`offline_extractive_0usd`).

| Conjunto | Sistema | N | Evidence R@5 | Evidence R@10 | Token F1 | Token Recall | Short Fact Match | Latencia p50 / p95 (ms) | Abstention Acc |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| LongMemEval-S (`stride=5`) | **PADAM** | 94 | 0.9362 | **0.9787** | 0.0707 | 0.2914 | **0.2771** | 64.17 / 80.71 | 0.0 (n=6) |
| LongMemEval-S (`stride=5`) | Plain BM25 | 94 | **0.9574** | **0.9787** | **0.0750** | **0.2956** | **0.2771** | 1.76 / 2.43 | 0.0 (n=6) |
| LoCoMo-10 (`stride=4`) | **PADAM** | 388 | 0.8325 | 0.8737 | **0.0817** | 0.2560 | 0.1102 | 4.00 / 5.38 | 0.0 (n=112) |
| LoCoMo-10 (`stride=4`) | Plain BM25 | 388 | **0.8814** | **0.9253** | 0.0809 | **0.2667** | **0.1237** | 0.61 / 0.88 | 0.0 (n=112) |

En LoCoMo `multi-hop` (`ev@10 = 0.8507`, `token_f1 = 0.0601`) y `temporal` (`token_f1 = 0.0969`, `short_fact_match = 0.1163`), PADAM supera a BM25 en las métricas de respuesta.
