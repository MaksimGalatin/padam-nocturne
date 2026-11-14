# Тест поиска PADAM на датасете LoCoMo (`locomo10.json`, Б16)

Замер этапа извлечения (`retrieval recall`) без языковых моделей, платных API или внешнего Ollama — только встроенный детерминированный эмбеддер `builtin` ($0, `PADAM 0.4.18`).

- **Датасет:** `locomo10.json` ([snap-research/locomo](https://github.com/snap-research/locomo)), **10** длинных диалогов, **5 882** реплик, **1 982** вопроса с указанным `evidence` (плюс 4 вопроса категории 3 с пустым `evidence` исключены при расчёте).
- **Единица записи:** каждая реплика с отметкой времени сессии `[session_date_time] speaker: text` (+ `[image: blip_caption]`, если есть) записывается через `Memory.remember(..., kind="event", origin="user")`.
- **Замер:** `Memory.recall(question, limit=50)` в одном потоке на Mac/Windows без LLM-переформулирования; метрики считаются на двух уровнях — точной реплики (`turn`, `dia_id` вида `D1:3`) и сессии (`sess`, вида `D1`).

## Сводка результатов (категории 1–4, `n = 1 536` вопросов)

| Режим | Время (10 диалогов) | `turn_any@5` | `turn_any@10` | `sess_any@5` | `sess_any@10` | `sess_all@5` | `sess_all@10` |
|---|---|---|---|---|---|---|---|
| Встроенный поиск (`PADAM_RERANK=0`, по умолч.) | 64.5 с | **56.1 %** (0.5612) | **64.0 %** (0.6400) | **90.1 %** (0.9010) | **95.5 %** (0.9551) | **78.3 %** (0.7832) | **85.6 %** (0.8561) |
| С переранжированием (`PADAM_RERANK=1`, top-30) | 56.9 с | **57.7 %** (0.5768) | **65.3 %** (0.6530) | **91.1 %** (0.9108) | **95.8 %** (0.9577) | **78.4 %** (0.7839) | **86.3 %** (0.8626) |

На категории 5 (`adversarial`, `n = 446` вопросов с `evidence`): без rerank `sess_any@5 = 95.1 %` (`0.9507`), `sess_any@10 = 97.5 %` (`0.9753`); с `PADAM_RERANK=1` — `sess_any@5 = 95.1 %` (`0.9507`), `sess_any@10 = 98.2 %` (`0.9821`).

## Разбивка по категориям (без rerank → с `PADAM_RERANK=1`)

| Категория | Вопросы | `turn_any@5` | `turn_any@10` | `sess_any@5` | `sess_any@10` |
|---|---|---|---|---|---|
| `multi-hop` (1) | 282 | 0.4326 → **0.4610** | 0.5709 → **0.6099** | 0.8404 → **0.8794** | 0.9539 → 0.9504 |
| `temporal` (2) | 321 | 0.6698 → **0.6916** | 0.7227 → **0.7321** | 0.8879 → **0.8941** | 0.9408 → **0.9470** |
| `open-domain` (3) | 92 | 0.3152 → 0.3043 | 0.3804 → **0.4130** | 0.6413 → **0.6522** | 0.7826 → **0.8043** |
| `single-hop` (4) | 841 | 0.5898 → **0.6017** | 0.6599 → **0.6635** | 0.9548 → **0.9560** | 0.9798 → **0.9810** |
| `adversarial` (5) | 446 | 0.6099 → 0.6009 | 0.6794 → 0.6682 | 0.9507 → 0.9507 | 0.9753 → **0.9821** |

## Как воспроизвести

```bash
python -I -X utf8 benchmarks/locomo/retrieval_recall.py <path/to/locomo10.json> benchmarks/locomo/results_builtin
python -I -X utf8 benchmarks/locomo/retrieval_recall.py <path/to/locomo10.json> benchmarks/locomo/results_rerank --rerank
```

Файлы итогов лежат рядом: [`results_builtin/summary.json`](results_builtin/summary.json) и [`results_rerank/summary.json`](results_rerank/summary.json).
