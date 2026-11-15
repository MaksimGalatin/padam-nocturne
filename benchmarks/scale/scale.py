# -*- coding: utf-8 -*-
"""How PADAM scales: write time, search time and database size at 1k, 10k and 100k records.

Run: python -I -X utf8 benchmarks/scale/scale.py <output.json> [--embedder builtin|model2vec] [--sizes 1000,10000,100000]
Texts are turns from LongMemEval-S if a path is given with --data, otherwise synthetic notes built from a fixed
word list (seeded, so every run writes the same text). Each size gets a fresh database. Search time is the median
of 200 queries; the first query is not counted (it warms the index). Ollama is pointed at a closed port.
"""
import json
import os
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


def _memory_mb():
    """Return (current_rss_mb, peak_rss_mb) for the current process."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class _PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        pmc = _PMC()
        pmc.cb = ctypes.sizeof(_PMC)
        h = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
            return round(pmc.WorkingSetSize / 1e6, 2), round(pmc.PeakWorkingSetSize / 1e6, 2)
    if psutil is not None:
        mi = psutil.Process().memory_info()
        peak = getattr(mi, "peak_wset", mi.rss)
        return round(mi.rss / 1e6, 2), round(peak / 1e6, 2)
    import resource  # type: ignore

    ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_mb = round((ru / 1e6) if sys.platform == "darwin" else (ru / 1e3), 2)
    return peak_mb, peak_mb

os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from padam import __version__, config, embeddings  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402


def arg(name, default):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


config.OLLAMA_URL = "http://127.0.0.1:9"
embeddings._check_ollama = lambda: False
config.EMBEDDER = arg("--embedder", "builtin")
SIZES = [int(x) for x in arg("--sizes", "1000,10000,100000").split(",")]
WORDS = ("billing deploy invoice postgres sprint release tea garden lisbon sister meeting budget server memory "
         "backup report contract design album song radio map audit school river city train ticket doctor "
         "recipe holiday laptop phone password review customer partner office printer hosting domain").split()


def texts(n, rnd):
    data = arg("--data", None)
    if data:
        out = []
        for q in json.load(open(data, encoding="utf-8")):
            for s in q["haystack_sessions"]:
                for turn in s:
                    if turn["role"] == "user":
                        out.append(turn["content"][:2000])
                        if len(out) == n:
                            return out
        return out
    return [f"Note {i}: " + " ".join(rnd.choice(WORDS) for _ in range(rnd.randint(8, 40))) for i in range(n)]


def main():
    rnd = random.Random(20261109)
    pool = texts(max(SIZES), rnd)
    queries = [" ".join(rnd.choice(WORDS) for _ in range(3)) for _ in range(201)]
    rows = []
    for n in SIZES:
        rss_before, _ = _memory_mb()
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "m.db"
            m = Memory(user_id="scale", store=Store(db))
            t0 = time.perf_counter()
            for text in pool[:n]:
                m.remember(text, kind="event")
            write_s = time.perf_counter() - t0
            t_cold = time.perf_counter()
            m.recall(queries[0], limit=10)
            cold_ms = (time.perf_counter() - t_cold) * 1000
            times = []
            for q in queries[1:]:
                t1 = time.perf_counter()
                m.recall(q, limit=10)
                times.append((time.perf_counter() - t1) * 1000)
            rss_after, peak_rss = _memory_mb()
            m.close()
            size = sum(f.stat().st_size for f in Path(tmp).iterdir() if f.name.startswith("m.db"))
        times.sort()
        row = {"records": n, "write_seconds": round(write_s, 1), "write_ms_per_record": round(write_s * 1000 / n, 2),
               "cold_search_ms": round(cold_ms, 1),
               "search_ms_median": round(statistics.median(times), 1), "search_ms_p95": round(times[int(len(times) * 0.95)], 1),
               "db_mb": round(size / 1e6, 1),
               "rss_mb_before": rss_before, "rss_mb_after": rss_after, "peak_rss_mb": peak_rss}
        rows.append(row)
        print(json.dumps(row), flush=True)
    out = {"padam_version": __version__, "embedding": embeddings.backend(), "python": sys.version.split()[0],
           "texts": "LongMemEval-S user turns" if arg("--data", None) else "synthetic notes, 8–40 words",
           "rows": rows}
    Path(sys.argv[1]).write_text(json.dumps(out, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
