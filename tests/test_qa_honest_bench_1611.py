# -*- coding: utf-8 -*-
"""Быстрые тесты честного QA-бенчмарка LongMemEval / LoCoMo ($0, оффлайн)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.quality import qa_honest_bench as qhb  # noqa: E402


def test_parse_iso_date_formats() -> None:
    assert qhb._parse_iso_date("2023/05/20 (Sat) 02:21") == "2023-05-20T02:21:00+00:00"
    assert qhb._parse_iso_date("1:56 pm on 8 May, 2023") == "2023-05-08T12:00:00+00:00"
    assert qhb._parse_iso_date("") is None


def test_bm25_and_offline_extractor_agreement() -> None:
    docs = [
        {"text": "user: My cat Luna is 9 months old.", "session_id": "s1", "session_date": "2023/11/01", "order_idx": 1},
        {"text": "user: I bought a 55-inch Samsung TV.", "session_id": "s2", "session_date": "2023/11/05", "order_idx": 2},
    ]
    idx = qhb.PlainBM25Index(docs)
    hits = idx.search("What size is my Samsung TV?", limit=5)
    assert hits and hits[0]["session_id"] == "s2"
    ans = qhb._offline_extract_answer("What size is my Samsung TV?", hits)
    assert "55-inch" in ans or "samsung" in ans.lower()
    f1, rec = qhb._token_f1_and_recall(ans, "55-inch")
    assert rec == 1.0 and f1 > 0.0


def test_main_synthetic_smoke(tmp_path: Path) -> None:
    lme_file = tmp_path / "lme.json"
    locomo_file = tmp_path / "locomo.json"
    out_file = tmp_path / "out.json"

    lme_file.write_text(
        json.dumps([
            {
                "question_id": "q1",
                "question_type": "single-session-user",
                "question": "What degree did I graduate with?",
                "question_date": "2023/05/30 (Tue) 23:40",
                "answer": "Business Administration",
                "answer_session_ids": ["s1"],
                "haystack_dates": ["2023/05/10 (Wed) 10:00"],
                "haystack_session_ids": ["s1"],
                "haystack_sessions": [
                    [{"role": "user", "content": "I graduated with a degree in Business Administration."}]
                ],
            },
            {
                "question_id": "q2_abs",
                "question_type": "single-session-user",
                "question": "What is my secret Mars rover password?",
                "question_date": "2023/05/30 (Tue) 23:40",
                "answer": "not mentioned",
                "answer_session_ids": ["s1"],
                "haystack_dates": ["2023/05/10 (Wed) 10:00"],
                "haystack_session_ids": ["s1"],
                "haystack_sessions": [
                    [{"role": "user", "content": "I like coffee in the morning."}]
                ],
            },
        ]),
        encoding="utf-8",
    )
    locomo_file.write_text(
        json.dumps([
            {
                "sample_id": "c1",
                "conversation": {
                    "speaker_a": "Alice",
                    "speaker_b": "Bob",
                    "session_1_date_time": "1:56 pm on 8 May, 2023",
                    "session_1": [
                        {"speaker": "Alice", "dia_id": "D1:1", "text": "I visited Paris in May 2023."},
                        {"speaker": "Bob", "dia_id": "D1:2", "text": "Nice!"},
                    ],
                },
                "qa": [
                    {"question": "Which city did Alice visit?", "answer": "Paris", "evidence": ["D1:1"], "category": 4}
                ],
            }
        ]),
        encoding="utf-8",
    )

    rc = qhb.main([
        "--lme", str(lme_file),
        "--locomo", str(locomo_file),
        "--lme-stride", "1",
        "--locomo-stride", "1",
        "--out", str(out_file),
    ])
    assert rc == 0
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["paid_api_cost_usd"] == 0.0
    assert data["longmemeval"]["padam"]["overall"]["n"] == 1
    assert data["longmemeval"]["padam"]["abstention"]["accuracy"] == 1.0
    assert data["locomo"]["padam"]["overall"]["evidence_recall@5"] == 1.0
