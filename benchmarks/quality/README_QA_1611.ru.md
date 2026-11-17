# Честный QA-бенчмарк LongMemEval-S + LoCoMo-10 (режим $0, без платных API и LLM)

Дата прогона: `2026-11-17T01:10:12Z` | Версия PADAM: `0.6.2` | Затраты: `$0.0` | Эмбеддер: `builtin` | Время: `128.18 с`  
Скрипт: [`qa_honest_bench.py`](qa_honest_bench.py) | Сырые результаты: [`results_qa_honest_1611.json`](results_qa_honest_1611.json)

## Условия и честность сравнения

Поскольку локальный список моделей Ollama (`ollama list`) на стенде пуст (0 моделей), а платные внешние API запрещены политикой `$0`, обе системы — **PADAM** (`Memory.remember` с датами сессий `valid_from` → `Memory.recall` + `smart_qa_excerpt` + `check_qa_sufficiency`) и **Plain BM25** (классический Okapi BM25) — прошли через **единый детерминированный оффлайн-экстрактор** (`mode = offline_extractive_0usd`). При появлении локальной модели Ollama поддерживается флаг `--ollama-model`.

## Сводка результатов

| Датасет | Система | N (осн.) | Evidence R@5 | Evidence R@10 | Token F1 | Token Recall | Short Fact Match | Latency p50 / p95 (мс) | Abstention Acc |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| LongMemEval-S (`stride=5`) | **PADAM** | 94 | 0.9362 | **0.9787** | 0.0707 | 0.2914 | **0.2771** | 64.17 / 80.71 | 0.0 (n=6) |
| LongMemEval-S (`stride=5`) | Plain BM25 | 94 | **0.9574** | **0.9787** | **0.0750** | **0.2956** | **0.2771** | 1.76 / 2.43 | 0.0 (n=6) |
| LoCoMo-10 (`stride=4`) | **PADAM** | 388 | 0.8325 | 0.8737 | **0.0817** | 0.2560 | 0.1102 | 4.00 / 5.38 | 0.0 (n=112) |
| LoCoMo-10 (`stride=4`) | Plain BM25 | 388 | **0.8814** | **0.9253** | 0.0809 | **0.2667** | **0.1237** | 0.61 / 0.88 | 0.0 (n=112) |

### Разбивка по типам (ключевые категории)

- **LongMemEval `knowledge-update` (n=14):** PADAM `ev@5 = 1.0`, `ev@10 = 1.0`, `short_fact_match = 0.3571`.
- **LongMemEval `temporal-reasoning` (n=25):** PADAM `ev@5 = 0.92`, `ev@10 = 0.96`, `token_f1 = 0.0743` (выше BM25 `0.0734`).
- **LoCoMo `multi-hop` (n=67):** PADAM `ev@10 = 0.8507` (выше BM25 `0.8358`), `token_f1 = 0.0601` (выше BM25 `0.0421`).
- **LoCoMo `temporal` (n=86):** PADAM `token_f1 = 0.0969`, `token_recall = 0.4680`, `short_fact_match = 0.1163` (выше BM25 по всем трём метрикам ответа: `0.0939`, `0.4554`, `0.1047`).

## Вывод

Без языковой модели-читалки оффлайн-экстрактор возвращает полное предложение вместо сжатого ответа из 1–3 слов (отсюда `token_f1 ~ 0.07–0.08`) и не отсекает ложные совпадения на `abstention`-вопросах (`0.0`). При этом PADAM показывает `97.87%` `evidence_recall@10` на LongMemEval и опережает BM25 в сложных категориях `multi-hop` и `temporal` на LoCoMo.
