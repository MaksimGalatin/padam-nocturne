# -*- coding: utf-8 -*-
"""LongMemEval-S end to end: PADAM retrieves, a language model answers, the paper's judge prompt grades.

Pipeline per question: a fresh memory file is filled with the haystack through `Memory.remember` (one record per
round; the embedding is whatever `PADAM_EMBEDDER` selects), `Memory.recall(question, limit=K)` returns records, they
are shown to the reader model with each round's session date — whole (`--full`, as `padam_search` serves them by
default) or in the compact view (the default of this script) — the reader answers, and a judge model grades the
answer with the official prompt of `src/evaluation/evaluate_qa.py` (Wu et al., LongMemEval, ICLR 2025).

Results kept in this folder: results_qa_0.3.1 — compact view, K=20, built-in embedding (the first run, which showed
that the compact view cuts the assistant's replies to 150 characters); results_qa_full_builtin and
results_qa_full_model2vec — whole records, K=10; results_qa_full20_model2vec — whole records, K=20;
results_qa_full20_builtin_STOPPED_174_of_500 — the same with the built-in embedding, stopped when the free
Ollama Cloud quota ran out (HTTP 429, 9 Nov 2026); its 174 questions are of three types only and are not a result.

Differences from the paper, stated plainly: reader and judge are gpt-oss:120b on Ollama Cloud (the paper's judge
is GPT-4o), and the reader prompt is ours. Numbers are therefore not directly comparable with tables that use
GPT-4o as the judge.

Run: python -I -X utf8 qa_end_to_end.py <longmemeval_s.json> <out folder> [--stride N] [--workers 4] [--k 20]
     [--budget 1.00]  (USD, hard cap: the run stops before a call that could pass it)
The API key is read from the environment variable OLLAMA_API_KEY and never printed. Results are appended to
answers.jsonl after every question; a rerun skips questions already done.
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

os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"      # embeddings: built-in only, no local model
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
STRIDE, WORKERS, K = arg("--stride", 1), arg("--workers", 4), arg("--k", 20)
MODEL = arg("--model", "gpt-oss:120b")
FULL = "--full" in sys.argv          # records as padam_search serves them by default (whole text), not the compact view
KEY = os.environ.get("OLLAMA_API_KEY", "")
if not KEY:
    sys.exit("OLLAMA_API_KEY is not set")
out_dir.mkdir(parents=True, exist_ok=True)
answers_path = out_dir / "answers.jsonl"
done = set()
if answers_path.exists():
    done = {json.loads(line)["question_id"] for line in answers_path.open(encoding="utf-8") if line.strip()}
questions = [q for q in json.load(open(data_path, encoding="utf-8"))[::STRIDE] if q["question_id"] not in done]
lock = threading.Lock()

READER = ("Below are excerpts from the user's earlier chats with an assistant, found in the assistant's memory, "
          "each with the date of its chat session. Answer the question using only these excerpts. If the excerpts "
          "do not contain the answer, say that the information is not available.\n\n{context}\n\n"
          "Current date: {date}\nQuestion: {question}\nAnswer briefly:")


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


# Spending cap (11 Nov 2026). On a paid Ollama plan, usage past the monthly pool is billed per token and we found no
# way to stop it on the Pro plan, so the cap lives here: every reply's token counts are priced, and before each call
# the worst case (input + MAX_OUT output) must fit in what is left of --budget (USD, default 1.00), or the run stops.
# Prices per million tokens (input, output), ollama.com/pricing, read 11 Nov 2026; an unknown model is priced at the
# most expensive rate in the table.
BUDGET = arg("--budget", 1.0)
MAX_OUT = 4000
PRICES = {"gpt-oss:20b": (0.07, 0.30), "gpt-oss:120b": (0.15, 0.60), "glm-5.3-flash": (0.15, 0.50),
          "deepseek-v4.1-flash": (0.30, 1.20), "kimi-k2.6": (0.95, 4.00), "glm-5.3": (1.40, 4.40),
          "kimi-k3": (3.00, 15.00)}
PRICE = PRICES.get(MODEL, max(PRICES.values(), key=lambda p: p[1]))
spent = [0.0]
spend_lock = threading.Lock()


def chat(prompt: str) -> str:
    worst = (len(prompt) * PRICE[0] + MAX_OUT * PRICE[1]) / 1e6      # characters >= tokens, so this over-estimates
    with spend_lock:
        if spent[0] + worst > BUDGET:
            raise SystemExit(f"spending cap: ${spent[0]:.4f} spent, next call could cost ${worst:.4f}, cap ${BUDGET:.2f}")
        spent[0] += worst                                             # reserved; corrected when the reply arrives
    for attempt in range(6):
        try:
            r = requests.post("https://ollama.com/api/chat", timeout=300,
                              headers={"Authorization": "Bearer " + KEY},
                              json={"model": MODEL, "messages": [{"role": "user", "content": prompt}], "stream": False,
                                    "options": {"num_predict": MAX_OUT}})
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
        sess_of, date_of = {}, dict(zip(q["haystack_session_ids"], q["haystack_dates"]))
        for sid, session in zip(q["haystack_session_ids"], q["haystack_sessions"]):
            for text in rounds(session):
                _, mid = mem.remember(text, kind="event", origin="user")
                sess_of.setdefault(mid, sid)
        found = mem.recall(q["question"], limit=K)
        mem.close()
    view = (lambda c: c[:6000]) if FULL else compact_text
    parts = sorted(((date_of.get(sess_of.get(r.id), ""), view(r.content)) for r in found), key=lambda x: x[0])
    context = "\n\n".join(f"[Session date: {d}]\n{t}" for d, t in parts)
    abstention = q["question_id"].endswith("_abs")
    hyp = chat(READER.format(context=context, date=q["question_date"], question=q["question"]))
    verdict = chat(judge_prompt(q["question_type"], q["question"], q["answer"], hyp, abstention))
    row = {"question_id": q["question_id"], "type": q["question_type"], "abstention": abstention,
           "hypothesis": hyp, "judge": verdict, "correct": "yes" in verdict.lower()[:20], "records": len(found)}
    with lock:
        with answers_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


started = time.time()
print(f"questions to run: {len(questions)} (already done {len(done)}), model {MODEL}, k={K}, workers={WORKERS}, "
      f"spending cap ${BUDGET:.2f}", flush=True)
n = 0
with ThreadPoolExecutor(WORKERS) as pool:
    for row in pool.map(one, questions):
        n += 1
        if n % 10 == 0:
            print(f"{n}/{len(questions)} in {time.time() - started:.0f} s", flush=True)

rows = [json.loads(line) for line in answers_path.open(encoding="utf-8") if line.strip()]
def acc(rs): return round(sum(r["correct"] for r in rs) / len(rs), 4) if rs else None
summary = {"dataset": "LongMemEval-S", "questions": len(rows), "reader_and_judge": MODEL + " (Ollama Cloud)",
           "spent_usd_this_run": round(spent[0], 4), "budget_usd": BUDGET,
           "retrieval": f"PADAM {__import__('padam').__version__}, embedding {embeddings.backend()}, recall limit {K}, "
                        + ("whole records (padam_search default)" if FULL else "compact view"),
           "accuracy_overall": acc(rows), "accuracy_without_abstention": acc([r for r in rows if not r["abstention"]]),
           "abstention_accuracy": acc([r for r in rows if r["abstention"]]),
           "by_type": {t: {"n": len(rs), "accuracy": acc(rs)} for t in sorted({r["type"] for r in rows})
                       for rs in [[r for r in rows if r["type"] == t and not r["abstention"]]]}}
json.dump(summary, open(out_dir / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(json.dumps(summary, ensure_ascii=False, indent=2))
