# -*- coding: utf-8 -*-
"""LongMemEval-S end to end: PADAM retrieves, a language model answers, the paper's judge prompt grades.

Pipeline per question: a fresh memory file is filled with the haystack through `Memory.remember` (one record per
round; the embedding is whatever `PADAM_EMBEDDER` selects), `Memory.recall(question, limit=K)` returns records, they
are shown to the reader model with each round's session date — in baseline mode (`--pipeline baseline`: compact view
and short reader prompt) or in the improved pipeline (`--pipeline improved`, default: full round text + adjacent
session round expansion, chronological ordering with [LATEST / MOST RECENT] markers, and missing-evidence abstention
checks via `Memory.build_qa_prompt`) — the reader answers, and a judge model grades the answer with the official
prompt of `src/evaluation/evaluate_qa.py` (Wu et al., LongMemEval, ICLR 2025).

Supports both free local Ollama (`--local`, 127.0.0.1:11434, $0, CPU threads capped at <= 50% of machine cores)
and Ollama Cloud (when `--local` is not passed and `OLLAMA_API_KEY` is set).
"""
import json
import os
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"      # embeddings: built-in / model2vec only, no Ollama embedder call
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from padam import config, embeddings  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.retrieval import compact_text  # noqa: E402
from padam.store import Store  # noqa: E402

config.OLLAMA_URL = "http://127.0.0.1:9"
embeddings._check_ollama = lambda: False
sys.stdout.reconfigure(encoding="utf-8")


def arg(name, default):
    return type(default)(sys.argv[sys.argv.index(name) + 1]) if name in sys.argv else default


data_path, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
LOCAL = "--local" in sys.argv
STRIDE = arg("--stride", 1)
WORKERS = arg("--workers", 1 if LOCAL else 4)
K = arg("--k", 20)
MODEL = arg("--model", "gemma3:4b-it-qat" if LOCAL else "gpt-oss:120b")
PIPELINE = arg("--pipeline", "improved")  # "baseline" (before) or "improved" (after)
FULL = ("--full" in sys.argv) or (PIPELINE == "improved")
LOCAL_URL = arg("--ollama-url", "http://127.0.0.1:11434")
MAX_THREADS = max(1, min(arg("--threads", max(1, (os.cpu_count() or 4) // 2)), max(1, (os.cpu_count() or 4) // 2)))

KEY = os.environ.get("OLLAMA_API_KEY", "")
if not LOCAL and not KEY:
    sys.exit("OLLAMA_API_KEY is not set (pass --local to use free local Ollama on 127.0.0.1:11434)")
if LOCAL and MODEL.lower().endswith("-cloud"):
    sys.exit("Refusing to run a -cloud model in --local mode")

out_dir.mkdir(parents=True, exist_ok=True)
answers_path = out_dir / "answers.jsonl"
done = set()
if answers_path.exists():
    done = {json.loads(line)["question_id"] for line in answers_path.open(encoding="utf-8") if line.strip()}
questions = [q for q in json.load(open(data_path, encoding="utf-8"))[::STRIDE] if q["question_id"] not in done]
lock = threading.Lock()

READER_BASELINE = (
    "Below are excerpts from the user's earlier chats with an assistant, found in the assistant's memory, "
    "each with the date of its chat session. Answer the question using only these excerpts. If the excerpts "
    "do not contain the answer, say that the information is not available.\n\n{context}\n\n"
    "Current date: {date}\nQuestion: {question}\nAnswer briefly:"
)


def judge_prompt(task, question, answer, response, abstention):
    """The official LongMemEval grading prompt (src/evaluation/evaluate_qa.py, get_anscheck_prompt), verbatim."""
    base = ("I will give you a question, a correct answer, and a response from a model. Please answer yes if the "
            "response contains the correct answer. Otherwise, answer no. If the response is equivalent to the correct "
            "answer or contains all the intermediate steps to get the correct answer, you should also answer yes. If "
            "the response only contains a subset of the information required by the answer, answer no. ")
    if abstention:
        t = ("I will give you an unanswerable question, an explanation, and a response from a model. Please answer yes "
             "if the model correctly identifies the question as unanswerable. The model could say that the information "
             "is incomplete, or some other information is given but the asked information is not.\n\nQuestion: {}\n\n"
             "Explanation: {}\n\nModel Response: {}\n\nDoes the model correctly identify the question as unanswerable? "
             "Answer yes or no only.")
    elif task in ("single-session-user", "single-session-assistant", "multi-session"):
        t = base + "\n\nQuestion: {}\n\nCorrect Answer: {}\n\nModel Response: {}\n\nIs the model response correct? Answer yes or no only."
    elif task == "temporal-reasoning":
        t = (base + "In addition, do not penalize off-by-one errors for the number of days. If the question asks for the "
             "number of days/weeks/months, etc., and the model makes off-by-one errors (e.g., predicting 19 days when the "
             "answer is 18), the model's response is still correct. \n\nQuestion: {}\n\nCorrect Answer: {}\n\nModel "
             "Response: {}\n\nIs the model response correct? Answer yes or no only.")
    elif task == "knowledge-update":
        t = ("I will give you a question, a correct answer, and a response from a model. Please answer yes if the response "
             "contains the correct answer. Otherwise, answer no. If the response contains some previous information along "
             "with an updated answer, the response should be considered as correct as long as the updated answer is the "
             "required answer.\n\nQuestion: {}\n\nCorrect Answer: {}\n\nModel Response: {}\n\nIs the model response "
             "correct? Answer yes or no only.")
    else:  # single-session-preference
        t = ("I will give you a question, a rubric for desired personalized response, and a response from a model. Please "
             "answer yes if the response satisfies the desired response. Otherwise, answer no. The model does not need to "
             "reflect all the points in the rubric. The response is correct as long as it recalls and utilizes the user's "
             "personal information correctly.\n\nQuestion: {}\n\nRubric: {}\n\nModel Response: {}\n\nIs the model "
             "response correct? Answer yes or no only.")
    return t.format(question, answer, response)


BUDGET = arg("--budget", 0.0 if LOCAL else 1.0)
MAX_OUT = 320 if LOCAL else 4000
PRICES = {"gpt-oss:20b": (0.07, 0.30), "gpt-oss:120b": (0.15, 0.60), "glm-5.3-flash": (0.15, 0.50),
          "deepseek-v4.1-flash": (0.30, 1.20), "kimi-k2.6": (0.95, 4.00), "glm-5.3": (1.40, 4.40),
          "kimi-k3": (3.00, 15.00)}
PRICE = (0.0, 0.0) if LOCAL else PRICES.get(MODEL, max(PRICES.values(), key=lambda p: p[1]))
spent = [0.0]
spend_lock = threading.Lock()


def chat(prompt: str, max_tokens: int | None = None) -> str:
    num_predict = max_tokens or MAX_OUT
    if LOCAL:
        for attempt in range(4):
            try:
                r = requests.post(
                    f"{LOCAL_URL.rstrip('/')}/api/chat",
                    timeout=180,
                    json={
                        "model": MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "stream": False,
                        "options": {
                            "num_thread": MAX_THREADS,
                            "num_predict": num_predict,
                            "temperature": 0.0,
                        },
                    },
                )
                if r.status_code == 200:
                    d = r.json()
                    return (d.get("message") or {}).get("content", "").strip()
            except requests.RequestException:
                pass
            time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"Local Ollama ({LOCAL_URL}) did not answer after 4 attempts")

    worst = (len(prompt) * PRICE[0] + num_predict * PRICE[1]) / 1e6
    with spend_lock:
        if spent[0] + worst > BUDGET:
            raise SystemExit(f"spending cap: ${spent[0]:.4f} spent, next call could cost ${worst:.4f}, cap ${BUDGET:.2f}")
        spent[0] += worst
    for attempt in range(6):
        try:
            r = requests.post("https://ollama.com/api/chat", timeout=300,
                              headers={"Authorization": "Bearer " + KEY},
                              json={"model": MODEL, "messages": [{"role": "user", "content": prompt}], "stream": False,
                                    "options": {"num_predict": num_predict}})
            if r.status_code == 200:
                d = r.json()
                actual = (d.get("prompt_eval_count", 0) * PRICE[0] + d.get("eval_count", 0) * PRICE[1]) / 1e6
                with spend_lock:
                    spent[0] += actual - worst
                return (d.get("message") or {}).get("content", "").strip()
            if r.status_code in (401, 402, 403):
                raise SystemExit(f"Ollama Cloud refused: HTTP {r.status_code} {r.text[:200]}")
        except requests.RequestException:
            pass
        time.sleep(10 * (attempt + 1))
    raise RuntimeError("Ollama Cloud did not answer after 6 attempts")


def rounds(session):
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


def one(q):
    with tempfile.TemporaryDirectory() as tmp:
        mem = Memory(user_id="lme", store=Store(Path(tmp) / "m.db"))
        sess_of = {}
        round_idx_of = {}
        sess_rounds_map = {}
        date_of = dict(zip(q["haystack_session_ids"], q["haystack_dates"]))
        for sid, session in zip(q["haystack_session_ids"], q["haystack_sessions"]):
            r_list = rounds(session)
            sess_rounds_map[sid] = r_list
            for r_idx, text in enumerate(r_list):
                _, mid = mem.remember(text, kind="event", origin="user")
                sess_of.setdefault(mid, sid)
                round_idx_of.setdefault(mid, r_idx)
        found = mem.recall(q["question"], limit=K)
        mem.close()

    if PIPELINE == "baseline":
        view = (lambda c: c[:6000]) if "--full" in sys.argv else compact_text
        parts = sorted(((date_of.get(sess_of.get(r.id), ""), view(r.content)) for r in found), key=lambda x: x[0])
        context = "\n\n".join(f"[Session date: {d}]\n{t}" for d, t in parts)
        reader_prompt = READER_BASELINE.format(context=context, date=q["question_date"], question=q["question"])
    else:
        # Improved pipeline (Item 3.1):
        # 1. Full round text (up to 6000 chars instead of 150-char assistant truncation)
        # 2. Adjacent session round expansion (+/- 1 round in the same session for top-5 hits)
        # 3. Chronological ordering preserving both session_date and within-session round_index
        # 4. Explicit [LATEST / MOST RECENT] markers and abstention / missing-term checks via Memory.build_qa_prompt
        selected_keys = {}
        rank_of = {}
        for rank, r in enumerate(found):
            sid = sess_of.get(r.id)
            r_idx = round_idx_of.get(r.id, 0)
            if sid is None:
                continue
            selected_keys.setdefault((sid, r_idx), r.similarity)
            rank_of.setdefault((sid, r_idx), rank)
            if rank < 3:
                s_rounds = sess_rounds_map.get(sid, [])
                for neighbor_idx in (r_idx - 1, r_idx + 1):
                    if 0 <= neighbor_idx < len(s_rounds):
                        selected_keys.setdefault((sid, neighbor_idx), r.similarity * 0.5)
                        rank_of.setdefault((sid, neighbor_idx), rank + 5)

        sorted_keys = sorted(
            selected_keys.keys(),
            key=lambda sr: (date_of.get(sr[0], ""), sr[0], sr[1]),
        )
        ctx_records = []
        for sid, r_idx in sorted_keys:
            s_rounds = sess_rounds_map.get(sid, [])
            if 0 <= r_idx < len(s_rounds):
                rk = rank_of.get((sid, r_idx), 10)
                ctx_records.append({
                    "id": f"{sid}_{r_idx}",
                    "kind": "event",
                    "origin": "user",
                    "session_date": date_of.get(sid, ""),
                    "created_at": date_of.get(sid, ""),
                    "round_index": r_idx,
                    "rrf": selected_keys[(sid, r_idx)],
                    "score": selected_keys[(sid, r_idx)],
                    "content": Memory.smart_qa_excerpt(s_rounds[r_idx], q["question"], rank=rk),
                })
        reader_prompt = Memory.build_qa_prompt(
            q["question"],
            ctx_records,
            current_date=q["question_date"],
            fenced=False,
        )

    abstention = q["question_id"].endswith("_abs")
    hyp = chat(reader_prompt, max_tokens=240 if LOCAL else MAX_OUT)
    verdict = chat(judge_prompt(q["question_type"], q["question"], q["answer"], hyp, abstention), max_tokens=24 if LOCAL else 120)
    row = {
        "question_id": q["question_id"],
        "type": q["question_type"],
        "abstention": abstention,
        "pipeline": PIPELINE,
        "hypothesis": hyp,
        "judge": verdict,
        "correct": "yes" in verdict.lower()[:25],
        "records": len(found),
    }
    with lock:
        with answers_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


if __name__ == "__main__":
    started = time.time()
    mode_tag = f"local Ollama ({LOCAL_URL}, threads={MAX_THREADS}, $0)" if LOCAL else f"Ollama Cloud (cap ${BUDGET:.2f})"
    print(
        f"questions to run: {len(questions)} (already done {len(done)}), model={MODEL}, pipeline={PIPELINE}, "
        f"k={K}, workers={WORKERS}, {mode_tag}",
        flush=True,
    )
    n = 0
    with ThreadPoolExecutor(WORKERS) as pool:
        for row in pool.map(one, questions):
            n += 1
            if n % 10 == 0 or n == len(questions):
                print(f"{n}/{len(questions)} in {time.time() - started:.0f} s", flush=True)

    rows = [json.loads(line) for line in answers_path.open(encoding="utf-8") if line.strip()]
    def acc(rs): return round(sum(r["correct"] for r in rs) / len(rs), 4) if rs else None
    summary = {
        "dataset": "LongMemEval-S",
        "stride": STRIDE,
        "questions": len(rows),
        "pipeline": PIPELINE,
        "reader_and_judge": f"{MODEL} ({'local Ollama 127.0.0.1, $0' if LOCAL else 'Ollama Cloud'})",
        "cpu_threads_cap": MAX_THREADS if LOCAL else None,
        "spent_usd_this_run": round(spent[0], 4),
        "budget_usd": BUDGET,
        "retrieval": (
            f"PADAM {__import__('padam').__version__}, embedding {embeddings.backend()}, recall limit {K}, "
            + ("improved QA pipeline (full rounds + neighbor expansion + chronological/LATEST + abstention check)"
               if PIPELINE == "improved" else "baseline compact view")
        ),
        "accuracy_overall": acc(rows),
        "accuracy_without_abstention": acc([r for r in rows if not r["abstention"]]),
        "abstention_accuracy": acc([r for r in rows if r["abstention"]]),
        "by_type": {
            t: {"n": len(rs), "accuracy": acc(rs)}
            for t in sorted({r["type"] for r in rows})
            for rs in [[r for r in rows if r["type"] == t and not r["abstention"]]]
        },
    }
    json.dump(summary, open(out_dir / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
