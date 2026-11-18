# -*- coding: utf-8 -*-
"""Замер: N процессов одновременно пишут в ОДИН файл памяти PADAM (как рой агентов на одной машине).

Отвечает на вопрос «ловит ли SQLite `database is locked` при 10–20 агентах». Печатает число ошибок, записей, p50/p95.
    python -I -X utf8 benchmarks/scale/concurrent_writers.py [процессов=20] [записей_на_процесс=50]
$0, без сети, встроенный эмбеддер."""
import json
import multiprocessing as mp
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _writer(args):
    db, wid, n = args
    os.environ["PADAM_EMBEDDER"] = "builtin"
    from padam.memory import Memory
    from padam.store import Store
    lat, errors = [], []
    try:
        m = Memory(user_id="swarm", store=Store(db))
    except Exception as e:
        import traceback
        tb = [f"{fr.filename.split(chr(92))[-1]}:{fr.lineno}:{fr.name}" for fr in traceback.extract_tb(e.__traceback__)][-3:]
        return [], [f"OPEN {type(e).__name__}: {str(e)[:60]} @ " + " > ".join(tb)] * n
    for i in range(n):
        t0 = time.perf_counter()
        try:
            m.remember(f"agent {wid} note {i}: the deploy of service {wid}-{i} finished at step {i}", kind="fact", origin="agent", agent_id=f"agent-{wid}")
        except Exception as e:  # считаем любую ошибку, включая database is locked
            import traceback
            tb = [f"{fr.filename.split(chr(92))[-1]}:{fr.lineno}:{fr.name}" for fr in traceback.extract_tb(e.__traceback__)][-3:]
            errors.append(type(e).__name__ + ": " + str(e)[:60] + " @ " + " > ".join(tb))
        lat.append((time.perf_counter() - t0) * 1000)
    return lat, errors


def main():
    procs = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    per = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    d = tempfile.mkdtemp(prefix="padam_swarm_")
    db = os.path.join(d, "swarm.db")
    os.environ["PADAM_EMBEDDER"] = "builtin"
    from padam.memory import Memory
    from padam.store import Store
    Memory(user_id="swarm", store=Store(db))  # схема до старта роя
    t0 = time.perf_counter()
    with mp.Pool(procs) as pool:
        res = pool.map(_writer, [(db, w, per) for w in range(procs)])
    wall = time.perf_counter() - t0
    lat = sorted(x for r in res for x in r[0])
    errs = [e for r in res for e in r[1]]
    m = Memory(user_id="swarm", store=Store(db))
    n = m.store.one("SELECT COUNT(*) FROM memory WHERE user_id = 'swarm'")[0]
    out = {"processes": procs, "writes_attempted": procs * per, "rows_in_db": n, "errors": len(errs),
           "error_kinds": sorted(set(errs))[:4], "wall_s": round(wall, 2),
           "writes_per_s": round(procs * per / wall, 1),
           "write_ms_p50": round(statistics.median(lat), 1) if lat else None, "write_ms_p95": round(lat[int(len(lat) * 0.95) - 1], 1) if lat else None}
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
