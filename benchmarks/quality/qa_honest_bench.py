#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Честный оффлайн-бенчмарк ответов (QA) LongMemEval-S + LoCoMo без платных API ($0).

Проводит воспроизводимое сравнение «вопрос -> поиск -> ответ» между:
  1) PADAM (`Memory.remember` с датами сессий `valid_from` -> `Memory.recall` +
     `smart_qa_excerpt` + `classify_qa_intent` + `check_qa_sufficiency`);
  2) Plain BM25 (классический Okapi BM25 без графа, битемпоральности и RRF).

По умолчанию при пустом Ollama работает в детерминированном режиме `offline_extractive_0usd`
с единым для обеих систем экстрактором ответа (без LLM, $0). Если указан `--ollama-model`,
использует локальный Ollama (`$0`) и `Memory.build_qa_prompt`.

Запуск:
  python benchmarks/quality/qa_honest_bench.py --out benchmarks/quality/results_qa_honest_1611.json
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"
os.environ["PADAM_EMBEDDER"] = "builtin"

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from padam import config, embeddings  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402

config.OLLAMA_URL = "http://127.0.0.1:9"
embeddings._check_ollama = lambda: False

DEFAULT_LME = Path(r"E:\CODE\_данные_longmemeval\longmemeval_s_cleaned.json")
DEFAULT_LOCOMO = Path(r"E:\CODE\_данные_locomo\locomo10.json")

LOCOMO_CATEGORIES = {
    1: "multi-hop",
    2: "temporal",
    3: "open-domain",
    4: "single-hop",
    5: "adversarial",
}

_STOPWORDS = {
    "a", "an", "the", "and", "or", "but", "if", "in", "on", "at", "to", "for", "of", "with",
    "by", "from", "as", "is", "was", "are", "were", "be", "been", "being", "have", "has", "had",
    "do", "does", "did", "will", "would", "could", "should", "can", "may", "might", "what",
    "when", "where", "which", "who", "whom", "whose", "why", "how", "many", "much", "this",
    "that", "these", "those", "it", "its", "i", "me", "my", "you", "your", "he", "she", "they",
    "we", "his", "her", "their", "our", "user", "assistant", "not", "no", "yes", "about",
}

_MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8, "sep": 9,
    "oct": 10, "nov": 11, "dec": 12,
}


def _tokenize(text: str, drop_stop: bool = False) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", str(text or "").lower())
    if drop_stop:
        return [t for t in tokens if t not in _STOPWORDS]
    return tokens


def _parse_iso_date(raw: str) -> str | None:
    """Преобразует даты LongMemEval (`2023/05/20 (Sat) 02:21`) и LoCoMo (`1:56 pm on 8 May, 2023`) в ISO."""
    s = str(raw or "").strip()
    if not s:
        return None
    m = re.match(r"(\d{4})/(\d{2})/(\d{2})(?:\s*\([^)]+\)\s*(\d{2}):(\d{2}))?", s)
    if m:
        y, mo, d = m.group(1), m.group(2), m.group(3)
        hh, mm = m.group(4) or "12", m.group(5) or "00"
        return f"{y}-{mo}-{d}T{hh}:{mm}:00+00:00"
    m2 = re.search(r"(\d{1,2})\s+([A-Za-z]+),?\s+(\d{4})", s)
    if m2:
        day = int(m2.group(1))
        mo = _MONTHS.get(m2.group(2).lower())
        year = int(m2.group(3))
        if mo:
            try:
                dt = datetime(year, mo, day)
                return dt.strftime("%Y-%m-%dT12:00:00+00:00")
            except ValueError:
                return None
    return None


class PlainBM25Index:
    """Классический Okapi BM25 по тем же текстам для честного базового сравнения."""

    def __init__(self, docs: list[dict], k1: float = 1.5, b: float = 0.75) -> None:
        self.docs = docs
        self.k1 = k1
        self.b = b
        self.doc_tokens = [_tokenize(d["text"], drop_stop=False) for d in docs]
        self.doc_freqs: list[Counter[str]] = [Counter(toks) for toks in self.doc_tokens]
        self.doc_lens = [len(toks) for toks in self.doc_tokens]
        self.avg_dl = (sum(self.doc_lens) / len(self.doc_lens)) if self.doc_lens else 1.0
        df: Counter[str] = Counter()
        for freq in self.doc_freqs:
            for tok in freq:
                df[tok] += 1
        n_docs = len(docs)
        self.idf = {
            tok: math.log((n_docs - count + 0.5) / (count + 0.5) + 1.0)
            for tok, count in df.items()
        }

    def search(self, query: str, limit: int = 10) -> list[dict]:
        q_toks = _tokenize(query, drop_stop=True) or _tokenize(query, drop_stop=False)
        if not q_toks or not self.docs:
            return []
        scored: list[tuple[float, int]] = []
        for idx, freq in enumerate(self.doc_freqs):
            dl = self.doc_lens[idx] or 1
            score = 0.0
            for tok in q_toks:
                tf = freq.get(tok, 0)
                if not tf:
                    continue
                idf = self.idf.get(tok, 0.0)
                denom = tf + self.k1 * (1.0 - self.b + self.b * (dl / self.avg_dl))
                score += idf * ((tf * (self.k1 + 1.0)) / max(denom, 1e-9))
            if score > 0.0:
                scored.append((score, idx))
        scored.sort(key=lambda item: item[0], reverse=True)
        out = []
        for score, idx in scored[:limit]:
            doc = self.docs[idx]
            out.append({
                "content": doc["text"],
                "session_id": doc["session_id"],
                "turn_id": doc.get("turn_id"),
                "session_date": doc.get("session_date") or "",
                "order_idx": doc.get("order_idx", idx),
                "score": round(score, 4),
            })
        return out


def _detect_intent(question: str) -> dict[str, bool]:
    """Определение типа вопроса (совместимо с логикой `Memory.classify_qa_intent`)."""
    return Memory.classify_qa_intent(question)


def _offline_extract_answer(question: str, items: list[dict], sufficiency: dict | None = None) -> str:
    """Единый детерминированный оффлайн-экстрактор ответа ($0, без LLM) для PADAM и BM25."""
    if not items:
        return "Information not available in the provided conversations."
    if sufficiency is not None and not sufficiency.get("sufficient", True):
        return "Information not available in the provided conversations."

    q_terms = _tokenize(question, drop_stop=True)
    if sufficiency is None and q_terms:
        joined = " ".join(str(x.get("content") or "").lower() for x in items)
        matched = sum(1 for t in q_terms if t in joined or (len(t) > 4 and t[:-1] in joined))
        if matched == 0:
            return "Information not available in the provided conversations."

    intent = _detect_intent(question)
    q_low = question.lower()
    asks_number = any(w in q_low for w in ("how many", "how much", "how long", "age", "times", "days", "months", "years"))
    asks_when = any(w in q_low for w in ("when ", "what date", "what year", "what month", "which month"))
    q_bigrams = {f"{q_terms[i]} {q_terms[i + 1]}" for i in range(len(q_terms) - 1)}

    candidates: list[tuple[float, str]] = []
    max_order = max((int(x.get("order_idx") or 0) for x in items), default=1) or 1

    for rank, item in enumerate(items[:8]):
        raw = str(item.get("content") or "")
        sdate = str(item.get("session_date") or "").strip()
        order_ratio = float(item.get("order_idx") or 0) / max_order
        rank_bonus = 1.0 / (rank + 1)

        # Разбиваем на реплики/предложения, сохраняя контекст даты сессии
        clean_raw = re.sub(r"\b(user|assistant)\s*:\s*", " ", raw, flags=re.IGNORECASE)
        sents = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", clean_raw) if len(s.strip()) >= 8]
        if not sents:
            sents = [clean_raw.strip()]

        for sent in sents[:16]:
            s_toks = set(_tokenize(sent, drop_stop=True))
            overlap = sum(1 for t in q_terms if t in s_toks or (len(t) > 4 and t[:-1] in sent.lower()))
            if not overlap and rank > 1:
                continue
            sent_low = sent.lower()
            bg_hits = sum(1 for bg in q_bigrams if bg in sent_low)
            score = overlap * 1.5 + bg_hits * 2.0 + rank_bonus * 1.4

            if asks_when or intent["temporal"]:
                if re.search(r"\b(19|20)\d{2}\b|\b(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)\b|\b\d{1,2}/\d{1,2}\b|\b(ago|last|yesterday|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b", sent_low):
                    score += 1.6
            if asks_number and re.search(r"\b\d+\b", sent_low):
                score += 1.4
            if intent["knowledge_update"]:
                score += order_ratio * 2.2

            line = f"[{sdate}] {sent}" if (sdate and (asks_when or intent["temporal"]) and sdate not in sent) else sent
            candidates.append((score, line[:260]))

    if not candidates:
        best_raw = re.sub(r"\b(user|assistant)\s*:\s*", " ", str(items[0].get("content") or ""), flags=re.IGNORECASE).strip()
        return best_raw[:240]

    candidates.sort(key=lambda pair: pair[0], reverse=True)
    best_text = candidates[0][1]
    if len(candidates) > 1 and (intent["temporal"] or "order" in q_low or "both" in q_low):
        second = candidates[1][1]
        if second != best_text and len(best_text) + len(second) < 320:
            return f"{best_text} {second}"
    return best_text


def _ollama_answer(model: str, question: str, items: list[dict], current_date: str | None) -> str:
    prompt = Memory.build_qa_prompt(question, items, current_date=current_date, fenced=True)
    body = json.dumps({"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.0}}).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:11434/api/generate", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    return str(data.get("response") or "").strip()


def _token_f1_and_recall(pred: str, gold: str) -> tuple[float, float]:
    p_toks = _tokenize(pred, drop_stop=True) or _tokenize(pred, drop_stop=False)
    g_toks = _tokenize(gold, drop_stop=True) or _tokenize(gold, drop_stop=False)
    if not p_toks or not g_toks:
        return (1.0, 1.0) if p_toks == g_toks else (0.0, 0.0)
    common = Counter(p_toks) & Counter(g_toks)
    num_same = sum(common.values())
    if num_same == 0:
        return 0.0, 0.0
    prec = num_same / len(p_toks)
    rec = num_same / len(g_toks)
    f1 = (2 * prec * rec) / (prec + rec)
    return round(f1, 4), round(rec, 4)


def _contains_fact(pred: str, gold: str) -> bool:
    p_norm = " ".join(_tokenize(pred, drop_stop=False))
    g_norm = " ".join(_tokenize(gold, drop_stop=False))
    if not g_norm:
        return False
    return g_norm in p_norm


def _is_abstention_answer(pred: str) -> bool:
    low = pred.lower()
    return any(p in low for p in ("not available", "not mentioned", "cannot answer", "no information", "unknown"))


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int((len(s) - 1) * q + 0.5)))
    return round(float(s[idx]), 2)


def _summarize_rows(rows: list[dict], abstention_rows: list[dict] | None = None) -> dict:
    def _agg(sub: list[dict]) -> dict:
        if not sub:
            return {"n": 0}
        lats = [r["latency_ms"] for r in sub]
        fact_rows = [r for r in sub if r["short_fact"]]
        return {
            "n": len(sub),
            "evidence_recall@5": round(sum(r["ev@5"] for r in sub) / len(sub), 4),
            "evidence_recall@10": round(sum(r["ev@10"] for r in sub) / len(sub), 4),
            "token_f1": round(statistics.mean(r["f1"] for r in sub), 4),
            "token_recall": round(statistics.mean(r["recall"] for r in sub), 4),
            "short_fact_match": round(sum(r["fact_hit"] for r in fact_rows) / len(fact_rows), 4) if fact_rows else None,
            "latency_p50_ms": _percentile(lats, 0.50),
            "latency_p95_ms": _percentile(lats, 0.95),
        }

    out = {"overall": _agg(rows), "by_type": {}}
    for qtype in sorted({r["type"] for r in rows}):
        out["by_type"][qtype] = _agg([r for r in rows if r["type"] == qtype])
    if abstention_rows is not None:
        out["abstention"] = {
            "n": len(abstention_rows),
            "accuracy": round(sum(r["abs_ok"] for r in abstention_rows) / len(abstention_rows), 4) if abstention_rows else None,
        }
    return out


def _lme_rounds(session: list[dict]) -> list[str]:
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


def run_longmemeval(data_path: Path, stride: int = 5, limit: int | None = None, ollama_model: str | None = None) -> dict:
    questions = json.load(open(data_path, encoding="utf-8"))
    if stride > 1:
        questions = questions[::stride]
    if limit:
        questions = questions[:limit]

    padam_rows, padam_abs = [], []
    bm25_rows, bm25_abs = [], []

    for idx_q, q in enumerate(questions, 1):
        docs: list[dict] = []
        record_meta: dict[str, dict] = {}
        mem = Memory(user_id="lme_qa", store=Store(":memory:"))
        order_idx = 0
        for sid, sdate_raw, session in zip(q["haystack_session_ids"], q["haystack_dates"], q["haystack_sessions"]):
            iso_dt = _parse_iso_date(sdate_raw)
            for text in _lme_rounds(session):
                order_idx += 1
                tagged_text = f"[{sdate_raw}] {text}" if sdate_raw else text
                _, mid = mem.remember(tagged_text, kind="event", origin="user", valid_from=iso_dt)
                meta = {"session_id": sid, "session_date": sdate_raw, "order_idx": order_idx}
                record_meta[mid] = meta
                docs.append({"text": tagged_text, **meta})

        # 1. PADAM
        t0 = time.perf_counter()
        found = mem.recall(q["question"], limit=15)
        padam_items = []
        for rank, rec in enumerate(found[:10]):
            meta = record_meta.get(rec.id, {})
            padam_items.append({
                "content": Memory.smart_qa_excerpt(rec.content, q["question"], rank=rank),
                "session_id": meta.get("session_id", ""),
                "session_date": meta.get("session_date", ""),
                "order_idx": meta.get("order_idx", 0),
                "rrf": rec.similarity,
                "score": rec.score,
            })
        suff = Memory.check_qa_sufficiency(q["question"], padam_items)
        if ollama_model:
            padam_ans = _ollama_answer(ollama_model, q["question"], padam_items, q.get("question_date"))
        else:
            padam_ans = _offline_extract_answer(q["question"], padam_items, sufficiency=suff)
        padam_ms = (time.perf_counter() - t0) * 1000.0
        mem.close()
        if idx_q % 20 == 0 or idx_q == len(questions):
            print(f"[LME] {idx_q}/{len(questions)}", flush=True)

        # 2. Plain BM25
        bm25 = PlainBM25Index(docs)
        t1 = time.perf_counter()
        bm25_items = bm25.search(q["question"], limit=10)
        if ollama_model:
            bm25_ans = _ollama_answer(ollama_model, q["question"], bm25_items, q.get("question_date"))
        else:
            bm25_ans = _offline_extract_answer(q["question"], bm25_items, sufficiency=None)
        bm25_ms = (time.perf_counter() - t1) * 1000.0

        gold_sids = set(q["answer_session_ids"])
        gold_ans = str(q["answer"])
        is_abs = q["question_id"].endswith("_abs")
        short_fact = (not is_abs) and (len(gold_ans) <= 80)

        for ans, items, ms, rows_dst, abs_dst in (
            (padam_ans, padam_items, padam_ms, padam_rows, padam_abs),
            (bm25_ans, bm25_items, bm25_ms, bm25_rows, bm25_abs),
        ):
            if is_abs:
                abs_dst.append({"question_id": q["question_id"], "abs_ok": _is_abstention_answer(ans)})
            else:
                top5 = {it.get("session_id") for it in items[:5]}
                top10 = {it.get("session_id") for it in items[:10]}
                f1, rec_tok = _token_f1_and_recall(ans, gold_ans)
                rows_dst.append({
                    "question_id": q["question_id"],
                    "type": q["question_type"],
                    "ev@5": bool(gold_sids & top5),
                    "ev@10": bool(gold_sids & top10),
                    "f1": f1,
                    "recall": rec_tok,
                    "short_fact": short_fact,
                    "fact_hit": _contains_fact(ans, gold_ans) if short_fact else False,
                    "latency_ms": ms,
                })

    return {
        "dataset": "LongMemEval-S",
        "questions_total": len(questions),
        "stride": stride,
        "padam": _summarize_rows(padam_rows, padam_abs),
        "bm25": _summarize_rows(bm25_rows, bm25_abs),
    }


def _locomo_sessions(conv: dict) -> list[tuple[int, str, list[dict]]]:
    nums = sorted(int(k.split("_", 1)[1]) for k, v in conv.items() if re.match(r"^session_\d+$", k) and isinstance(v, list))
    return [(n, str(conv.get(f"session_{n}_date_time") or "").strip(), conv[f"session_{n}"]) for n in nums]


def run_locomo(data_path: Path, qa_stride: int = 5, limit_convs: int | None = None, ollama_model: str | None = None) -> dict:
    convs = json.load(open(data_path, encoding="utf-8"))
    if limit_convs:
        convs = convs[:limit_convs]

    padam_rows, padam_abs = [], []
    bm25_rows, bm25_abs = [], []
    total_qa = 0

    for conv_idx, item in enumerate(convs, 1):
        conv = item["conversation"]
        docs: list[dict] = []
        record_meta: dict[str, dict] = {}
        mem = Memory(user_id="locomo_qa", store=Store(":memory:"))
        order_idx = 0
        for snum, sdate_raw, turns in _locomo_sessions(conv):
            sid = f"D{snum}"
            iso_dt = _parse_iso_date(sdate_raw)
            for turn in turns:
                order_idx += 1
                speaker = str(turn.get("speaker") or "speaker").strip()
                text = str(turn.get("text") or "").strip()
                caption = str(turn.get("blip_caption") or "").strip()
                body = f"[{sdate_raw}] {speaker}: {text}" if sdate_raw else f"{speaker}: {text}"
                if caption:
                    body = f"{body} [image: {caption}]"
                body = body[: config.MAX_CONTENT_CHARS]
                _, mid = mem.remember(body, kind="event", origin="user", valid_from=iso_dt)
                did = str(turn.get("dia_id") or "")
                meta = {"session_id": sid, "turn_id": did, "session_date": sdate_raw, "order_idx": order_idx}
                record_meta[mid] = meta
                docs.append({"text": body, **meta})

        bm25 = PlainBM25Index(docs)
        qa_list = item["qa"][::qa_stride] if qa_stride > 1 else item["qa"]
        total_qa += len(qa_list)

        for q in qa_list:
            qtext = str(q["question"])
            cat_id = int(q.get("category") or 0)
            qtype = LOCOMO_CATEGORIES.get(cat_id, f"cat_{cat_id}")
            gold_dids = set(q.get("evidence") or [])
            gold_sids = {d.split(":", 1)[0] for d in gold_dids if ":" in d} or gold_dids
            gold_ans = str(q.get("answer") or q.get("adversarial_answer") or "")
            is_abs = cat_id == 5
            short_fact = (not is_abs) and (len(gold_ans) <= 80)

            t0 = time.perf_counter()
            found = mem.recall(qtext, limit=15)
            padam_items = []
            for rank, rec in enumerate(found[:10]):
                meta = record_meta.get(rec.id, {})
                padam_items.append({
                    "content": Memory.smart_qa_excerpt(rec.content, qtext, rank=rank),
                    "session_id": meta.get("session_id", ""),
                    "turn_id": meta.get("turn_id", ""),
                    "session_date": meta.get("session_date", ""),
                    "order_idx": meta.get("order_idx", 0),
                    "rrf": rec.similarity,
                    "score": rec.score,
                })
            suff = Memory.check_qa_sufficiency(qtext, padam_items)
            if ollama_model:
                padam_ans = _ollama_answer(ollama_model, qtext, padam_items, None)
            else:
                padam_ans = _offline_extract_answer(qtext, padam_items, sufficiency=suff)
            padam_ms = (time.perf_counter() - t0) * 1000.0

            t1 = time.perf_counter()
            bm25_items = bm25.search(qtext, limit=10)
            if ollama_model:
                bm25_ans = _ollama_answer(ollama_model, qtext, bm25_items, None)
            else:
                bm25_ans = _offline_extract_answer(qtext, bm25_items, sufficiency=None)
            bm25_ms = (time.perf_counter() - t1) * 1000.0

            for ans, items, ms, rows_dst, abs_dst in (
                (padam_ans, padam_items, padam_ms, padam_rows, padam_abs),
                (bm25_ans, bm25_items, bm25_ms, bm25_rows, bm25_abs),
            ):
                if is_abs:
                    abs_dst.append({"question": qtext, "abs_ok": _is_abstention_answer(ans)})
                else:
                    top5_s = {it.get("session_id") for it in items[:5]}
                    top10_s = {it.get("session_id") for it in items[:10]}
                    top5_t = {it.get("turn_id") for it in items[:5]}
                    top10_t = {it.get("turn_id") for it in items[:10]}
                    f1, rec_tok = _token_f1_and_recall(ans, gold_ans)
                    rows_dst.append({
                        "type": qtype,
                        "ev@5": bool((gold_dids & top5_t) or (gold_sids & top5_s)),
                        "ev@10": bool((gold_dids & top10_t) or (gold_sids & top10_s)),
                        "f1": f1,
                        "recall": rec_tok,
                        "short_fact": short_fact,
                        "fact_hit": _contains_fact(ans, gold_ans) if short_fact else False,
                        "latency_ms": ms,
                    })
        mem.close()
        print(f"[LoCoMo] conv {conv_idx}/{len(convs)}", flush=True)

    return {
        "dataset": "LoCoMo-10",
        "conversations": len(convs),
        "questions_total": total_qa,
        "qa_stride": qa_stride,
        "padam": _summarize_rows(padam_rows, padam_abs),
        "bm25": _summarize_rows(bm25_rows, bm25_abs),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Честный QA-бенчмарк LongMemEval + LoCoMo ($0)")
    parser.add_argument("--lme", type=Path, default=DEFAULT_LME)
    parser.add_argument("--locomo", type=Path, default=DEFAULT_LOCOMO)
    parser.add_argument("--lme-stride", type=int, default=5)
    parser.add_argument("--locomo-stride", type=int, default=4)
    parser.add_argument("--limit-lme", type=int, default=None)
    parser.add_argument("--limit-convs", type=int, default=None)
    parser.add_argument("--ollama-model", type=str, default=None)
    parser.add_argument("--out", type=Path, default=Path("benchmarks/quality/results_qa_honest_1611.json"))
    args = parser.parse_args(argv)

    started = time.time()
    mode = f"ollama:{args.ollama_model}" if args.ollama_model else "offline_extractive_0usd"
    report = {
        "benchmark": "PADAM Honest QA Bench (LongMemEval-S + LoCoMo-10)",
        "padam_version": __import__("padam").__version__,
        "mode": mode,
        "embedder": "builtin",
        "paid_api_cost_usd": 0.0,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if args.lme.exists():
        report["longmemeval"] = run_longmemeval(
            args.lme, stride=args.lme_stride, limit=args.limit_lme, ollama_model=args.ollama_model
        )
    if args.locomo.exists():
        report["locomo"] = run_locomo(
            args.locomo, qa_stride=args.locomo_stride, limit_convs=args.limit_convs, ollama_model=args.ollama_model
        )

    report["total_seconds"] = round(time.time() - started, 2)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
