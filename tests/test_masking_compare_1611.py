"""Быстрый тест сравнения маскировки (2 000+ ключей и >= 50 чистых фраз, < 10 секунд)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "benchmarks" / "security") not in sys.path:
    sys.path.insert(0, str(ROOT / "benchmarks" / "security"))

import compare_masking  # noqa: E402


def test_masking_compare_fast_slice_and_no_padam_regressions():
    rep = compare_masking.run_benchmark(
        per_seed=1980,
        seeds=1,
        solana_batches=10,
        vendor_per_family=25,
        out_path=None,
    )
    assert rep["elapsed_s"] < 10.0

    padam = rep["systems"]["PADAM"]
    assert padam["fake_keys"]["total"] >= 1980
    assert padam["fake_keys"]["leaks"] == 0
    assert padam["solana_keys"]["total"] == 220
    assert padam["solana_keys"]["leaks"] == 0
    assert padam["vendor_keys"]["total"] == 100
    assert padam["vendor_keys"]["leaks"] == 0
    assert padam["clean_phrases"]["total"] >= 50
    assert padam["clean_phrases"]["false_masks"] == 0

    # Проверяем честный учёт соперников (они ловят вендорные ключи, но пропускают часть фейковых/Solana)
    mem0 = rep["systems"]["Mem0"]
    assert mem0["fake_keys"]["leaks"] > 0
    assert mem0["solana_keys"]["leaks"] == mem0["solana_keys"]["total"]

    cm_builtin = rep["systems"]["Claude-Mem (builtin)"]
    assert cm_builtin["vendor_keys"]["leaks"] == 0
    assert cm_builtin["solana_keys"]["leaks"] == cm_builtin["solana_keys"]["total"]
