# -*- coding: utf-8 -*-
"""Честный прогон НА 400 ОТЛОЖЕННЫХ ВОПРОСАХ LongMemEval-S (индексы i % 5 != 0): PADAM 0.8.0 против mem0 2.2.1.

Совет Кота Лумо + Архитектора (24.11.2026): первые 100 вопросов (i % 5 == 0) участвовали при подборе
второго прохода в 0.4.13; остальные 400 вопросов НИКОГДА не использовались при настройке.
Обе системы используют ОДИН компьютер, ОДНУ модель эмбеддингов `BAAI/bge-small-en-v1.5` через `fastembed`,
ОДИНАКОВУЮ функцию разбиения раундов `rounds()`, без LLM и без телеметрии ($0.00).
"""
import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.pop("OPENAI_API_KEY", None)
os.environ["MEM0_TELEMETRY"] = "False"
os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"
os.environ["PADAM_EMBEDDER"] = "builtin"
sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(r"E:\CODE\_wt_top20_v2_2211\padam-nocturne")
sys.path.insert(0, str(ROOT))

MAX_CONTENT_CHARS = 20000
KS = (5, 10)
RETRIEVE = 50


def rounds(session: list[dict]) -> list[str]:
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


def share(rows: list[dict], key: str) -> float | None:
    return round(sum(r[key] for r in rows) / len(rows), 4) if rows else None


def run_padam(heldout: list[dict], out_dir: Path, embed_fn) -> dict:
    from padam import config, embeddings
    from padam.memory import Memory
    from padam.store import Store

    os.environ["PADAM_SIM_THRESHOLD_BUILTIN"] = os.environ.get("PADAM_SIM_THRESHOLD_OLLAMA", "0.85")
    config.OLLAMA_URL = "http://127.0.0.1:9"
    embeddings._check_ollama = lambda: False
    builtin_backup = embeddings._builtin_embed

    def _padam_embed(text: str):
        if not text or not text.strip():
            return builtin_backup(text)
        return embed_fn(text)

    def _padam_embed_with_model(text: str):
        if not text or not text.strip():
            return builtin_backup(text), f"builtin:{config.EMBED_DIM}"
        return embed_fn(text), "fastembed:BAAI/bge-small-en-v1.5"

    embeddings.embed = _padam_embed
    embeddings.embed_with_model = _padam_embed_with_model
    embeddings.метка_модели = lambda: "fastembed:BAAI/bge-small-en-v1.5"

    out_dir.mkdir(parents=True, exist_ok=True)
    pq_file = out_dir / "padam_0.8.0_per_question.json"
    done_rows: list[dict] = json.loads(pq_file.read_text(encoding="utf-8")) if pq_file.exists() else []
    done_ids = {r["question_id"] for r in done_rows}

    t0 = time.time()
    for idx, q in enumerate(heldout, 1):
        if q["question_id"] in done_ids:
            continue
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            mem = Memory(user_id="lme", store=Store(Path(tmp) / "m.db"))
            rec_sess: dict[str, set[str]] = {}
            written = 0
            for sid, sess in zip(q["haystack_session_ids"], q["haystack_sessions"]):
                for text in rounds(sess):
                    _, mid = mem.remember(text, kind="event", origin="user")
                    rec_sess.setdefault(mid, set()).add(sid)
                    written += 1
            found = mem.recall(q["question"], limit=RETRIEVE)
            mem.close()
        ranked: list[str] = []
        for rec in found:
            for sid in sorted(rec_sess.get(rec.id, ())):
                if sid not in ranked:
                    ranked.append(sid)
        gold = set(q["answer_session_ids"])
        row = {
            "question_id": q["question_id"],
            "type": q["question_type"],
            "abstention": q["question_id"].endswith("_abs"),
            "rounds_written": written,
            "records_found": len(found),
            "gold": sorted(gold),
        }
        for k in KS:
            top = set(ranked[:k])
            row[f"any@{k}"] = bool(gold & top)
            row[f"all@{k}"] = gold <= top
        done_rows.append(row)
        done_ids.add(q["question_id"])
        if len(done_rows) % 1 == 0 or idx == len(heldout):
            dt = time.time() - t0
            non_abs = [r for r in done_rows if not r["abstention"]]
            a5 = share(non_abs, "any@5") or 0.0
            print(f"[PADAM 0.8.0] {len(done_rows)}/{len(heldout)} ({dt:.1f}s), any@5={a5:.4f}", flush=True)
            pq_file.write_text(json.dumps(done_rows, ensure_ascii=False, indent=0), encoding="utf-8")

    main = [r for r in done_rows if not r["abstention"]]
    summary = {
        "system": "PADAM NOCTURNE 0.8.0, Memory.remember per round, Memory.recall(question, limit=50), fastembed BAAI/bge-small-en-v1.5, no LLM",
        "split": "heldout_400 (indices i % 5 != 0)",
        "questions": len(done_rows),
        "scored_without_abstention": len(main),
        "overall": {f"{m}@{k}": share(main, f"{m}@{k}") for m in ("any", "all") for k in KS},
        "abstention": {f"{m}@{k}": share([r for r in done_rows if r["abstention"]], f"{m}@{k}") for m in ("any", "all") for k in KS},
        "by_type": {
            tp: {"n": len(rs), **{f"{m}@{k}": share(rs, f"{m}@{k}") for m in ("any", "all") for k in KS}}
            for tp in sorted({r["type"] for r in main})
            for rs in [[r for r in main if r["type"] == tp]]
        },
        "seconds": round(time.time() - t0),
    }
    (out_dir / "padam_0.8.0_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def run_mem0(heldout: list[dict], out_dir: Path) -> dict:
    from mem0 import Memory as Mem0Memory

    out_dir.mkdir(parents=True, exist_ok=True)
    pq_file = out_dir / "mem0_per_question.json"
    done_rows: list[dict] = json.loads(pq_file.read_text(encoding="utf-8")) if pq_file.exists() else []
    done_ids = {r["question_id"] for r in done_rows}

    tmp_q = tempfile.mkdtemp(prefix="mem0-lme400-")
    m = Mem0Memory.from_config({
        "embedder": {"provider": "fastembed", "config": {"model": "BAAI/bge-small-en-v1.5"}},
        "vector_store": {"provider": "qdrant", "config": {"path": tmp_q + "/q", "collection_name": "lme", "embedding_model_dims": 384, "on_disk": True}},
        "llm": {"provider": "ollama", "config": {"model": "none", "ollama_base_url": "http://127.0.0.1:9"}},
        "history_db_path": tmp_q + "/h.db",
    })

    t0 = time.time()
    for idx, q in enumerate(heldout, 1):
        if q["question_id"] in done_ids:
            continue
        user = "q" + q["question_id"]
        for sid, sess in zip(q["haystack_session_ids"], q["haystack_sessions"]):
            m.add([{"role": "user", "content": t} for t in rounds(sess)], user_id=user, infer=False, metadata={"sid": sid})
        r = m.search(q["question"], filters={"user_id": user}, top_k=50, threshold=0.0)
        found = r.get("results", r) if isinstance(r, dict) else r
        ranked = []
        for rec in found:
            sid = (rec.get("metadata") or {}).get("sid")
            if sid and sid not in ranked:
                ranked.append(sid)
        gold = set(q["answer_session_ids"])
        row = {
            "question_id": q["question_id"],
            "type": q["question_type"],
            "abstention": q["question_id"].endswith("_abs"),
            "records_found": len(found),
            "gold": sorted(gold),
        }
        for k in KS:
            row[f"any@{k}"] = bool(gold & set(ranked[:k]))
            row[f"all@{k}"] = gold <= set(ranked[:k])
        done_rows.append(row)
        done_ids.add(q["question_id"])
        if len(done_rows) % 1 == 0 or idx == len(heldout):
            dt = time.time() - t0
            non_abs = [r for r in done_rows if not r["abstention"]]
            a5 = share(non_abs, "any@5") or 0.0
            print(f"[mem0 2.2.1] {len(done_rows)}/{len(heldout)} ({dt:.1f}s), any@5={a5:.4f}", flush=True)
            pq_file.write_text(json.dumps(done_rows, ensure_ascii=False, indent=0), encoding="utf-8")

    main = [r for r in done_rows if not r["abstention"]]
    summary = {
        "system": "mem0 2.2.1, add(infer=False), fastembed BAAI/bge-small-en-v1.5, qdrant local, search top_k=50",
        "split": "heldout_400 (indices i % 5 != 0)",
        "questions": len(done_rows),
        "scored_without_abstention": len(main),
        "overall": {f"{m}@{k}": share(main, f"{m}@{k}") for m in ("any", "all") for k in KS},
        "by_type": {
            tp: {"n": len(rs), **{f"{m}@{k}": share(rs, f"{m}@{k}") for m in ("any", "all") for k in KS}}
            for tp in sorted({r["type"] for r in main})
            for rs in [[r for r in main if r["type"] == tp]]
        },
        "seconds": round(time.time() - t0),
    }
    (out_dir / "mem0_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=r"E:\Aifa\_benchmarks_data\longmemeval_s.json")
    parser.add_argument("--out", default=str(ROOT / "benchmarks" / "longmemeval" / "vs_mem0" / "heldout_400"))
    parser.add_argument("--mode", choices=["padam", "mem0", "both"], default="both")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    all_q = json.load(open(args.data, encoding="utf-8"))
    heldout = [q for i, q in enumerate(all_q) if i % 5 != 0]
    if args.limit > 0:
        heldout = heldout[:args.limit]
    print(f"Loaded {len(all_q)} total questions -> selected {len(heldout)} held-out questions (i % 5 != 0).")

    out_dir = Path(args.out)
    if args.mode in ("padam", "both"):
        import numpy as np
        from fastembed import TextEmbedding

        _model = TextEmbedding("BAAI/bge-small-en-v1.5")

        def _vec(text: str):
            v = np.asarray(next(iter(_model.embed([text[:8000]]))), dtype=np.float32)
            n = float(np.linalg.norm(v))
            return v / n if n > 0 else v

        s_padam = run_padam(heldout, out_dir, _vec)
        print("PADAM SUMMARY:", json.dumps(s_padam["overall"], ensure_ascii=False))
    if args.mode in ("mem0", "both"):
        s_mem0 = run_mem0(heldout, out_dir)
        print("MEM0 SUMMARY:", json.dumps(s_mem0["overall"], ensure_ascii=False))
        os._exit(0)
