# PADAM NOCTURNE and mem0 on the same retrieval benchmark

Same data, same embedding model, same scoring, run on one machine on 11–12 November 2026.

- **Data:** LongMemEval-S, every fifth question (100 questions, 94 with an answer), each with its own haystack of past chats.
- **Embedding model for both:** `BAAI/bge-small-en-v1.5` through fastembed, local, no service.
- **Records:** one record per round ("user: … / assistant: …"), the same `rounds()` function as `../retrieval_recall.py`; the question is the query; 50 records are returned and reduced to sessions in order.
- **Scoring:** `any@k` — at least one evidence session in the top k; `all@k` — every evidence session in the top k (`answer_session_ids`). Abstention questions are left out.
- **mem0:** 2.2.1, `add(..., infer=False)` — stored as is, no language model (mem0's default mode calls a model on every write); qdrant on disk; telemetry off. Script: `mem0_recall.py`.
- **PADAM:** 0.4.13, `Memory.remember` per round, `Memory.recall(question, limit=50)`, no language model. Script: `../retrieval_recall.py --stride 5 --embedder fastembed:BAAI/bge-small-en-v1.5`.

| | any evidence session in top 5 | in top 10 | all evidence sessions in top 5 | in top 10 |
|---|---|---|---|---|
| PADAM 0.4.13 | 94.7 % | 97.9 % | 86.2 % | 93.6 % |
| mem0 2.2.1 | 96.8 % | 98.9 % | 85.1 % | 91.5 % |
| questions where PADAM wins / loses | 0 / 2 | 0 / 1 | 3 / 2 | 3 / 1 |

**Reading it.** The two are level: every difference is one to three questions out of 94. mem0 puts the first evidence session in the top 5 slightly more often; PADAM brings all of them slightly more often.

**A caveat that favours PADAM.** These 100 questions (every fifth) are the ones used while tuning PADAM's second search pass in 0.4.13; the other 400 were held out. mem0 was not tuned on them. PADAM's small lead on `all@k` here may come from that tuning. A run on the 400 held-out questions is the fair measure and has not been done yet.

**Speed is not compared.** The two runs shared the machine with different other jobs, so their times say nothing about the systems.

## Reproduce

```bash
# mem0
uv run --no-project --with mem0ai==2.2.1 --with fastembed --with ollama python -I -X utf8 mem0_recall.py longmemeval_s.json out_mem0 --stride 5
# PADAM, from a checkout at tag v0.4.13 (the script imports the checkout, not an installed package)
git clone --branch v0.4.13 https://github.com/MaksimGalatin/padam-nocturne && cd padam-nocturne
pip install fastembed
python -I -X utf8 benchmarks/longmemeval/retrieval_recall.py longmemeval_s.json out_padam --stride 5 --embedder fastembed:BAAI/bge-small-en-v1.5
```

Results as they came: `mem0_summary.json`, `mem0_per_question.json`, `padam_0.4.13_summary.json`, `padam_0.4.13_per_question.json`. The question lists are identical, in the same order.
