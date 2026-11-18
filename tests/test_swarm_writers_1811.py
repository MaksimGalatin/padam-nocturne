# -*- coding: utf-8 -*-
"""18.11.2026: рой агентов пишет в один файл памяти. До починки: «trigger memory_fts_delete already exists» при
одновременном открытии и 4–16 % записей с «database is locked». Замер: benchmarks/scale/concurrent_writers.py."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_рой_12_процессов_без_потерь():
    r = subprocess.run([sys.executable, "-I", "-X", "utf8", str(ROOT / "benchmarks" / "scale" / "concurrent_writers.py"), "12", "25"],
                       capture_output=True, text=True, encoding="utf-8", timeout=600)
    итог = json.loads(r.stdout.strip().splitlines()[-1])
    assert итог["errors"] == 0, итог
    assert итог["rows_in_db"] == итог["writes_attempted"] == 300
