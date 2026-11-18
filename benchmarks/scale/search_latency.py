# -*- coding: utf-8 -*-
"""Замер задержки поиска PADAM на растущем объёме: p50/p95 recall() на N записях (встроенный эмбеддер, $0, без сети).
    python -I -X utf8 benchmarks/scale/search_latency.py 1000 10000 50000"""
import json
import os
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
os.environ["PADAM_EMBEDDER"] = "builtin"
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402

СЛОВА = ("deploy server berlin moscow invoice client python sqlite memory agent payment report scanner site "
         "ollama model graph bug fix release token budget family council quarantine lesson checkpoint").split()


def main():
    random.seed(7)
    for n in [int(x) for x in sys.argv[1:]] or [1000, 10000]:
        m = Memory(user_id="u", store=Store(os.path.join(tempfile.mkdtemp(prefix="padam_scale_"), "s.db")))
        t0 = time.perf_counter()
        for i in range(n):
            m.remember(f"note {i}: " + " ".join(random.choice(СЛОВА) for _ in range(12)) + f" id{i}", kind="fact")
        write_s = time.perf_counter() - t0
        lat = []
        for q in range(40):
            t1 = time.perf_counter()
            m.recall(" ".join(random.choice(СЛОВА) for _ in range(4)), limit=10)
            lat.append((time.perf_counter() - t1) * 1000)
        lat.sort()
        print(json.dumps({"records": n, "write_s": round(write_s, 1), "search_ms_p50": round(statistics.median(lat), 1),
                          "search_ms_p95": round(lat[int(len(lat) * 0.95) - 1], 1)}))


if __name__ == "__main__":
    main()
