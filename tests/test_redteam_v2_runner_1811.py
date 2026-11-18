# -*- coding: utf-8 -*-
"""Автотест-обёртка второй программы красной команды (redteam/run_v2.py + cases_v2.jsonl)."""

from __future__ import annotations

from pathlib import Path

from redteam import run_v2


def test_redteam_v2_suite_zero_failures():
    cases_file = Path(__file__).resolve().parent.parent / "redteam" / "cases_v2.jsonl"
    report = run_v2.run_all_cases(cases_file)
    assert report["cases"] >= 25
    assert report["failed"] == [], f"Redteam v2 failures: {report['failed']}"
    assert report["passed"] == report["cases"]
