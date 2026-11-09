# -*- coding: utf-8 -*-
"""LongMemEval-S, retrieval stage only: does PADAM find the sessions that hold the answer?

No language model is used anywhere: no reader, no judge, no paid API, no local Ollama (the built-in
embedding is forced). For each of the 500 questions a fresh memory file is filled with the question's
haystack through the ordinary write path (`Memory.remember`, one record per round "user: … / assistant: …",
as in the 13.10.2026 experiment), then `Memory.recall(question)` is asked for 50 records. Records are mapped
back to their sessions; the ranked list of distinct sessions is scored against `answer_session_ids`.

Metrics (session level): recall_any@k — at least one evidence session in the top k;
recall_all@k — every evidence session in the top k. k = 5, 10. Abstention questions (`_abs`) are reported
separately: they still name evidence sessions, but their answer is "not mentioned".

Run: python -I -X utf8 retrieval_recall.py <longmemeval_s.json> <output folder> [--limit N] [--stride N]
     [--embedder model2vec:<model> | fastembed:<model>]

Results kept in this folder: results_0.3.1 — all 500 questions, built-in embedding; results_stride5_<model> —
every fifth question (100, of them 94 with an answer) with a model2vec model. The built-in numbers for the same
100 questions are results_0.3.1/per_question.json[::5] (the built-in embedding is deterministic).
Dataset: https://huggingface.co/datasets/xiaowu0162/longmemeval (MIT). Wu et al., LongMemEval, ICLR 2025.
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"      # built-in embedding only: no local model is started
# --embedder fastembed:<model> | model2vec:<model> — a small local embedding model in-process (no service). Neural
# vectors are closer to each other than the built-in ones, so the merge threshold of the Ollama path (0.85) is used.
EMBEDDER = sys.argv[sys.argv.index("--embedder") + 1] if "--embedder" in sys.argv else "builtin"
if EMBEDDER != "builtin":
    os.environ["PADAM_SIM_THRESHOLD_BUILTIN"] = os.environ.get("PADAM_SIM_THRESHOLD_OLLAMA", "0.85")
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from padam import config, embeddings  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402

config.OLLAMA_URL = "http://127.0.0.1:9"
embeddings._check_ollama = lambda: False
sys.stdout.reconfigure(encoding="utf-8")

if EMBEDDER != "builtin":
    import numpy as np
    kind, model_name = EMBEDDER.split(":", 1)
    if kind == "fastembed":
        from fastembed import TextEmbedding
        _model = TextEmbedding(model_name)
        def _vec(text: str):
            return next(iter(_model.embed([text])))
    elif kind == "model2vec":
        from model2vec import StaticModel
        _model = StaticModel.from_pretrained(model_name)
        def _vec(text: str):
            return _model.encode([text])[0]
    else:
        sys.exit("unknown embedder " + EMBEDDER)
    _builtin = embeddings._builtin_embed
    def _embed(text: str):
        if not text or not text.strip():
            return _builtin(text)
        v = np.asarray(_vec(text[:8000]), dtype=np.float32)
        n = float(np.linalg.norm(v))
        return v / n if n > 0 else v
    embeddings.embed = _embed
    embeddings.метка_модели = lambda: EMBEDDER

data_path, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
limit = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else None
out_dir.mkdir(parents=True, exist_ok=True)
questions = json.load(open(data_path, encoding="utf-8"))
if "--stride" in sys.argv:          # every n-th question: a sample with all question types (the file is grouped by type)
    questions = questions[::int(sys.argv[sys.argv.index("--stride") + 1])]
if limit:
    questions = questions[:limit]
KS = (5, 10)
RETRIEVE = 50


def rounds(session: list[dict]) -> list[str]:
    """One record per round: a user turn with the assistant turn that follows it."""
    out, i = [], 0
    while i < len(session):
        turn = session[i]
        text = f"{turn['role']}: {turn['content']}"
        if turn["role"] == "user" and i + 1 < len(session) and session[i + 1]["role"] == "assistant":
            text += f"\nassistant: {session[i + 1]['content']}"
            i += 1
        out.append(text[: config.MAX_CONTENT_CHARS])
        i += 1
    return out


per_question = []
started = time.time()
for n, q in enumerate(questions, 1):
    with tempfile.TemporaryDirectory() as tmp:
        mem = Memory(user_id="lme", store=Store(Path(tmp) / "m.db"))
        record_sessions: dict[str, set[str]] = {}
        written = 0
        for sid, session in zip(q["haystack_session_ids"], q["haystack_sessions"]):
            for text in rounds(session):
                outcome, mid = mem.remember(text, kind="event", origin="user")
                record_sessions.setdefault(mid, set()).add(sid)
                written += 1
        found = mem.recall(q["question"], limit=RETRIEVE)
        mem.close()
    ranked: list[str] = []
    for rec in found:
        for sid in sorted(record_sessions.get(rec.id, ())):
            if sid not in ranked:
                ranked.append(sid)
    gold = set(q["answer_session_ids"])
    row = {"question_id": q["question_id"], "type": q["question_type"], "abstention": q["question_id"].endswith("_abs"),
           "rounds_written": written, "records_found": len(found), "gold": sorted(gold)}
    for k in KS:
        top = set(ranked[:k])
        row[f"any@{k}"] = bool(gold & top)
        row[f"all@{k}"] = gold <= top
    per_question.append(row)
    if n % 10 == 0 or n == len(questions):
        done = time.time() - started
        print(f"{n}/{len(questions)} questions, {done / n:.1f} s each, any@5 so far "
              f"{sum(r['any@5'] for r in per_question) / n:.3f}", flush=True)
        json.dump(per_question, open(out_dir / "per_question.json", "w", encoding="utf-8"), ensure_ascii=False, indent=0)


def share(rows, key):
    return round(sum(r[key] for r in rows) / len(rows), 4) if rows else None


main = [r for r in per_question if not r["abstention"]]
summary = {
    "dataset": "LongMemEval-S", "questions": len(per_question), "scored_without_abstention": len(main),
    "method": "PADAM Memory.remember per round, Memory.recall(question, limit=50), embedding: " + EMBEDDER + ", no LLM",
    "padam_version": __import__("padam").__version__,
    "overall": {f"{m}@{k}": share(main, f"{m}@{k}") for m in ("any", "all") for k in KS},
    "abstention": {f"{m}@{k}": share([r for r in per_question if r["abstention"]], f"{m}@{k}") for m in ("any", "all") for k in KS},
    "by_type": {t: {"n": len(rs), **{f"{m}@{k}": share(rs, f"{m}@{k}") for m in ("any", "all") for k in KS}}
                for t in sorted({r["type"] for r in main}) for rs in [[r for r in main if r["type"] == t]]},
    "seconds": round(time.time() - started, 1),
}
json.dump(summary, open(out_dir / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(json.dumps(summary, ensure_ascii=False, indent=2))
