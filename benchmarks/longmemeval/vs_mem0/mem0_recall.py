# -*- coding: utf-8 -*-
"""Общий стенд поиска (план Архитектора 11.11.2026): mem0 на LongMemEval-S тем же подсчётом, что у PADAM.

Как у benchmarks/longmemeval/retrieval_recall.py: на вопрос — свой «стог» бесед, одна запись на раунд
(«user: … / assistant: …», та же функция rounds), поиск вопросом на 50 записей, записи сводятся к беседам,
меры any/all@5/10 по answer_session_ids. Отличие только в системе памяти:
  mem0 2.2.1, add(..., infer=False) — сохраняет как есть, без языковой модели (обычный режим mem0 зовёт модель
  на каждую запись — на LongMemEval это ~250 тыс. вызовов); векторы — fastembed BAAI/bge-small-en-v1.5 локально;
  хранилище — qdrant на диске. Языковая модель mem0 направлена на закрытый порт: если бы mem0 её вызвал, прогон упал бы.
Запуск: uv run --no-project --with mem0ai --with fastembed --with ollama python -I -X utf8 mem0_recall.py
        <longmemeval_s.json> <папка> [--stride 5]
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.pop("OPENAI_API_KEY", None)
# mem0 по умолчанию шлёт телеметрию в PostHog (mem0/memory/telemetry.py: MEM0_TELEMETRY = "True") — выключено.
os.environ["MEM0_TELEMETRY"] = "False"
sys.stdout.reconfigure(encoding="utf-8")
from mem0 import Memory  # noqa: E402

DATA, OUT = sys.argv[1], Path(sys.argv[2])
STRIDE = int(sys.argv[sys.argv.index("--stride") + 1]) if "--stride" in sys.argv else 1
MAX_CONTENT_CHARS = 20000            # как padam.config.MAX_CONTENT_CHARS — те же тексты записей
OUT.mkdir(parents=True, exist_ok=True)
questions = json.load(open(DATA, encoding="utf-8"))[::STRIDE]


def rounds(session):
    """Дословно как в retrieval_recall.py."""
    out, i = [], 0
    while i < len(session):
        turn = session[i]
        text = f"{turn['role']}: {turn['content']}"
        if turn["role"] == "user" and i + 1 < len(session) and session[i + 1]["role"] == "assistant":
            text += f"\nassistant: {session[i + 1]['content']}"
            i += 1
        out.append(text[:MAX_CONTENT_CHARS])
        i += 1
    return out


tmp = tempfile.mkdtemp(prefix="mem0-lme-")
m = Memory.from_config({
    "embedder": {"provider": "fastembed", "config": {"model": "BAAI/bge-small-en-v1.5"}},
    "vector_store": {"provider": "qdrant", "config": {"path": tmp + "/q", "collection_name": "lme",
                                                       "embedding_model_dims": 384, "on_disk": True}},
    "llm": {"provider": "ollama", "config": {"model": "none", "ollama_base_url": "http://127.0.0.1:9"}},
    "history_db_path": tmp + "/h.db"})

строки, начало = [], time.time()
for n, q in enumerate(questions, 1):
    user = "q" + q["question_id"]                     # свой «стог» на вопрос — фильтр по user_id
    for sid, session in zip(q["haystack_session_ids"], q["haystack_sessions"]):
        m.add([{"role": "user", "content": t} for t in rounds(session)], user_id=user, infer=False,
              metadata={"sid": sid})
    r = m.search(q["question"], filters={"user_id": user}, top_k=50, threshold=0.0)
    found = r.get("results", r) if isinstance(r, dict) else r
    ranked = []
    for rec in found:
        sid = (rec.get("metadata") or {}).get("sid")
        if sid and sid not in ranked:
            ranked.append(sid)
    gold = set(q["answer_session_ids"])
    row = {"question_id": q["question_id"], "type": q["question_type"], "abstention": q["question_id"].endswith("_abs"),
           "records_found": len(found), "gold": sorted(gold)}
    for k in (5, 10):
        row[f"any@{k}"] = bool(gold & set(ranked[:k]))
        row[f"all@{k}"] = gold <= set(ranked[:k])
    строки.append(row)
    if n % 5 == 0 or n == len(questions):
        print(f"{n}/{len(questions)}, {(time.time() - начало) / n:.1f} с на вопрос, any@5 {sum(r['any@5'] for r in строки) / n:.3f}",
              flush=True)
        json.dump(строки, open(OUT / "per_question.json", "w", encoding="utf-8"), ensure_ascii=False, indent=0)

отв = [r for r in строки if not r["abstention"]]
итог = {"system": "mem0 2.2.1, add(infer=False), fastembed BAAI/bge-small-en-v1.5, qdrant local, search top_k=50",
        "questions": len(строки), "scored_without_abstention": len(отв),
        "overall": {k: round(sum(r[k] for r in отв) / len(отв), 4) for k in ("any@5", "any@10", "all@5", "all@10")},
        "seconds": round(time.time() - начало)}
json.dump(итог, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(json.dumps(итог, ensure_ascii=False))
os._exit(0)                                           # qdrant на Windows падает при закрытии интерпретатора
