# Honest QA Benchmark: LongMemEval-S + LoCoMo-10 ($0, No Paid APIs / No LLM)

Run date: `2026-11-17T01:10:12Z` | PADAM version: `0.6.2` | Cost: `$0.0` | Embedder: `builtin` | Runtime: `128.18 s`  
Script: [`qa_honest_bench.py`](qa_honest_bench.py) | Raw results: [`results_qa_honest_1611.json`](results_qa_honest_1611.json)

## Setup & Fairness

Since local Ollama has 0 installed models (`ollama list` is empty) and paid external APIs are forbidden (`$0` policy), both **PADAM** (`Memory.remember` with session `valid_from` -> `Memory.recall` + `smart_qa_excerpt` + `check_qa_sufficiency`) and **Plain BM25** (Okapi BM25) use the **exact same deterministic offline answer extractor** (`mode = offline_extractive_0usd`). Local Ollama is supported via `--ollama-model`.

## Summary

| Dataset | System | N (main) | Evidence R@5 | Evidence R@10 | Token F1 | Token Recall | Short Fact Match | Latency p50 / p95 (ms) | Abstention Acc |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| LongMemEval-S (`stride=5`) | **PADAM** | 94 | 0.9362 | **0.9787** | 0.0707 | 0.2914 | **0.2771** | 64.17 / 80.71 | 0.0 (n=6) |
| LongMemEval-S (`stride=5`) | Plain BM25 | 94 | **0.9574** | **0.9787** | **0.0750** | **0.2956** | **0.2771** | 1.76 / 2.43 | 0.0 (n=6) |
| LoCoMo-10 (`stride=4`) | **PADAM** | 388 | 0.8325 | 0.8737 | **0.0817** | 0.2560 | 0.1102 | 4.00 / 5.38 | 0.0 (n=112) |
| LoCoMo-10 (`stride=4`) | Plain BM25 | 388 | **0.8814** | **0.9253** | 0.0809 | **0.2667** | **0.1237** | 0.61 / 0.88 | 0.0 (n=112) |

### Key Category Breakdown

- **LongMemEval `knowledge-update` (n=14):** PADAM `ev@5 = 1.0`, `ev@10 = 1.0`, `short_fact_match = 0.3571`.
- **LongMemEval `temporal-reasoning` (n=25):** PADAM `ev@5 = 0.92`, `ev@10 = 0.96`, `token_f1 = 0.0743` (above BM25 `0.0734`).
- **LoCoMo `multi-hop` (n=67):** PADAM `ev@10 = 0.8507` (above BM25 `0.8358`), `token_f1 = 0.0601` (above BM25 `0.0421`).
- **LoCoMo `temporal` (n=86):** PADAM `token_f1 = 0.0969`, `token_recall = 0.4680`, `short_fact_match = 0.1163` (beating BM25 on all three answer metrics: `0.0939`, `0.4554`, `0.1047`).
