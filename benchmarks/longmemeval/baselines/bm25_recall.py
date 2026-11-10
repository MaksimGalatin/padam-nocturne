# -*- coding: utf-8 -*-
"""LongMemEval-S, retrieval only — a plain BM25 baseline with no PADAM at all.

Same unit and same scoring as ../retrieval_recall.py, so the two tables can be read side by side:
one document per round ("user: … / assistant: …", cut at the same 20,000 characters), the question is the
query, documents are ranked by Okapi BM25 (k1 = 1.2, b = 0.75, the Lucene defaults), mapped back to their
sessions, and the ranked list of distinct sessions is scored against `answer_session_ids`:
recall_any@k — at least one evidence session in the top k; recall_all@k — every evidence session in the top k.
Abstention questions (`_abs`) are reported separately.

Tokens: lower-cased `\\w+` of two characters and more, no stemming, no stop list — the same tokenizer PADAM's own
lexical strategy uses, so the difference between the two tables is the method, not the tokenizer.
Ties keep the order in which rounds appear in the haystack (deterministic). No model, no network.

Run: python -I -X utf8 bm25_recall.py <longmemeval_s.json> <output folder> [--stride N]
"""
import json
import math
import re
import sys
import time
from collections import Counter
from pathlib import Path

MAX_CHARS = 20000          # padam.config.MAX_CONTENT_CHARS
K1, B = 1.2, 0.75
KS = (5, 10)
TOKEN = re.compile(r"\w+")


def tokens(text: str) -> list[str]:
    return [t for t in TOKEN.findall(text.lower()) if len(t) > 1]


def rounds(session: list[dict]) -> list[str]:
    """One document per round: a user turn with the assistant turn that follows it (as in retrieval_recall.py)."""
    out, i = [], 0
    while i < len(session):
        turn = session[i]
        text = f"{turn['role']}: {turn['content']}"
        if turn["role"] == "user" and i + 1 < len(session) and session[i + 1]["role"] == "assistant":
            text += f"\nassistant: {session[i + 1]['content']}"
            i += 1
        out.append(text[:MAX_CHARS])
        i += 1
    return out


def bm25_rank(query: str, docs: list[list[str]]) -> list[int]:
    n = len(docs)
    avgdl = sum(len(d) for d in docs) / n if n else 0.0
    df = Counter()
    for d in docs:
        df.update(set(d))
    q = set(tokens(query))
    scores = []
    for i, d in enumerate(docs):
        tf = Counter(t for t in d if t in q)
        s = 0.0
        for t, f in tf.items():
            idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
            s += idf * f * (K1 + 1) / (f + K1 * (1 - B + B * len(d) / avgdl))
        scores.append((s, i))
    scores.sort(key=lambda x: x[0], reverse=True)          # stable: ties keep haystack order
    return [i for s, i in scores if s > 0]


def main() -> None:
    data_path, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    questions = json.load(open(data_path, encoding="utf-8"))
    if "--stride" in sys.argv:
        questions = questions[::int(sys.argv[sys.argv.index("--stride") + 1])]
    per_question, started = [], time.time()
    for n, q in enumerate(questions, 1):
        docs, doc_session = [], []
        for sid, session in zip(q["haystack_session_ids"], q["haystack_sessions"]):
            for text in rounds(session):
                docs.append(tokens(text))
                doc_session.append(sid)
        ranked: list[str] = []
        for i in bm25_rank(q["question"], docs):
            if doc_session[i] not in ranked:
                ranked.append(doc_session[i])
        gold = set(q["answer_session_ids"])
        row = {"question_id": q["question_id"], "type": q["question_type"],
               "abstention": q["question_id"].endswith("_abs"), "documents": len(docs), "gold": sorted(gold)}
        for k in KS:
            top = set(ranked[:k])
            row[f"any@{k}"] = bool(gold & top)
            row[f"all@{k}"] = gold <= top
        per_question.append(row)
        if n % 50 == 0 or n == len(questions):
            print(f"{n}/{len(questions)}, any@5 so far {sum(r['any@5'] for r in per_question) / n:.3f}", flush=True)

    def share(rows, key):
        return round(sum(r[key] for r in rows) / len(rows), 4) if rows else None

    main_rows = [r for r in per_question if not r["abstention"]]
    summary = {
        "dataset": "LongMemEval-S", "questions": len(per_question), "scored_without_abstention": len(main_rows),
        "method": f"Okapi BM25 (k1={K1}, b={B}) over rounds, tokens \\w+ len>=2 lower-cased, no PADAM, no model",
        "overall": {f"{m}@{k}": share(main_rows, f"{m}@{k}") for m in ("any", "all") for k in KS},
        "abstention": {f"{m}@{k}": share([r for r in per_question if r["abstention"]], f"{m}@{k}")
                       for m in ("any", "all") for k in KS},
        "by_type": {t: {"n": len(rs), **{f"{m}@{k}": share(rs, f"{m}@{k}") for m in ("any", "all") for k in KS}}
                    for t in sorted({r["type"] for r in main_rows}) for rs in [[r for r in main_rows if r["type"] == t]]},
        "seconds": round(time.time() - started, 1),
    }
    json.dump(per_question, open(out_dir / "per_question.json", "w", encoding="utf-8"), ensure_ascii=False, indent=0)
    json.dump(summary, open(out_dir / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(json.dumps(summary["overall"]))


if __name__ == "__main__":
    main()
