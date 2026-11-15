# -*- coding: utf-8 -*-
"""Холодный бенчмарк MCP-инструментов padam_write и padam_search на 10 000 и 100 000 записях.

Запуск:
    python -I -X utf8 benchmarks/scale/mcp_bench.py [--out benchmarks/scale/mcp_results_1511.json] [--sizes 10000,100000]
"""

from __future__ import annotations

import argparse
import cProfile
import io
import json
import os
from pathlib import Path
import pstats
import random
import statistics
import sys
import tempfile
import time

os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"
os.environ["PADAM_EMBEDDER"] = "builtin"

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from padam import __version__, config, embeddings, mcp_server  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402

config.OLLAMA_URL = "http://127.0.0.1:9"
embeddings._check_ollama = lambda: False
config.EMBEDDER = "builtin"

WORDS = (
    "billing deploy invoice postgres sprint release tea garden lisbon sister meeting budget server memory "
    "backup report contract design album song radio map audit school river city train ticket doctor "
    "recipe holiday laptop phone password review customer partner office printer hosting domain"
).split()


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(len(sorted_vals) * pct))
    return sorted_vals[idx]


def _build_seed_texts(n: int, seed: int = 20261115) -> list[str]:
    rnd = random.Random(seed)
    return [
        f"Note {i}: " + " ".join(rnd.choice(WORDS) for _ in range(rnd.randint(8, 28)))
        for i in range(n)
    ]


def _seed_db_fast(db_path: Path, texts: list[str]) -> float:
    """Быстрое наполнение базы начальными N записями (одна транзакция через store)."""
    t0 = time.perf_counter()
    from padam import classify
    from padam.memory import content_hash
    from padam.store import new_id, now_iso, pack

    mem = Memory(user_id="bench", store=Store(db_path))
    try:
        ts = now_iso()
        model_tag = embeddings.метка_модели()
        rows = []
        for txt in texts:
            vec = embeddings.embed(txt)
            fk = classify.разобрать_факт(txt)[0]
            rows.append((
                new_id(), "bench", "global", "event", txt, pack(vec), 0.5, 1.0,
                ts, ts, ts, ts, None, None, "active", None, None,
                content_hash(txt), model_tag, fk, "user", None, None, "private", None,
            ))
        mem.store.conn.executemany(
            """INSERT INTO memory
               (id, user_id, scope, kind, content, embedding, importance,
                confidence, created_at, last_seen_at, last_confirmed_at,
                valid_from, valid_to, expires_at, status, supersedes,
                source_episode_id, content_hash, embedding_model, факт_ключ,
                origin, quarantine_reason, agent_id, visibility, workspace_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        mem.store.conn.commit()
    finally:
        mem.close()
    return time.perf_counter() - t0


def _bench_size(n: int, n_writes: int, n_searches: int, profile: bool = False) -> dict:
    pool = _build_seed_texts(n)
    rnd = random.Random(9000 + n)
    write_texts = [
        f"MCP benchmark record {i}: " + " ".join(rnd.choice(WORDS) for _ in range(12))
        for i in range(n_writes)
    ]
    queries = [" ".join(rnd.choice(WORDS) for _ in range(3)) for _ in range(n_searches + 1)]

    with tempfile.TemporaryDirectory(prefix=f"padam_mcp_bench_{n}_") as tmp:
        db_path = Path(tmp) / "bench.db"
        seed_s = _seed_db_fast(db_path, pool)

        # Свежий экземпляр Memory / MCP — холодный старт
        mem = Memory(user_id="bench", store=Store(db_path))
        old_mem = mcp_server._memory
        mcp_server._memory = mem
        try:
            # 1. Холодный первый поиск
            t_cold = time.perf_counter()
            r_cold = mcp_server.handle({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "padam_search", "arguments": {"query": queries[0], "limit": 10}},
            })
            cold_search_ms = (time.perf_counter() - t_cold) * 1000.0
            assert not (r_cold.get("result") or {}).get("isError"), r_cold

            # 2. Замер padam_search поверх N записей (на тёплом кэше, как в работе)
            search_ms: list[float] = []
            prof_search = cProfile.Profile() if profile else None
            if prof_search:
                prof_search.enable()
            for idx, q in enumerate(queries[1:], start=10):
                t1 = time.perf_counter()
                resp = mcp_server.handle({
                    "jsonrpc": "2.0", "id": idx, "method": "tools/call",
                    "params": {"name": "padam_search", "arguments": {"query": q, "limit": 10}},
                })
                search_ms.append((time.perf_counter() - t1) * 1000.0)
                assert not (resp.get("result") or {}).get("isError"), resp
            if prof_search:
                prof_search.disable()

            # 3. Замер padam_write поверх N записей (через MCP tools/call)
            write_ms: list[float] = []
            prof_write = cProfile.Profile() if profile else None
            if prof_write:
                prof_write.enable()
            for idx, txt in enumerate(write_texts, start=1000):
                t1 = time.perf_counter()
                resp = mcp_server.handle({
                    "jsonrpc": "2.0", "id": idx, "method": "tools/call",
                    "params": {
                        "name": "padam_write",
                        "arguments": {"content": txt, "kind": "event", "origin": "user"},
                    },
                })
                write_ms.append((time.perf_counter() - t1) * 1000.0)
                assert not (resp.get("result") or {}).get("isError"), resp
            if prof_write:
                prof_write.disable()

            if prof_search and prof_write:
                for label, prof in (("padam_search", prof_search), ("padam_write", prof_write)):
                    sio = io.StringIO()
                    pstats.Stats(prof, stream=sio).sort_stats("tottime").print_stats(12)
                    print(f"\n--- cProfile {label} @ {n} ---\n{sio.getvalue()}", file=sys.stderr)
        finally:
            mcp_server._memory = old_mem
            mem.close()

    search_ms.sort()
    write_ms.sort()
    return {
        "records": n,
        "seed_seconds": round(seed_s, 2),
        "cold_search_ms": round(cold_search_ms, 2),
        "search_samples": len(search_ms),
        "search_p50_ms": round(statistics.median(search_ms), 2),
        "search_p95_ms": round(_percentile(search_ms, 0.95), 2),
        "write_samples": len(write_ms),
        "write_p50_ms": round(statistics.median(write_ms), 2),
        "write_p95_ms": round(_percentile(write_ms, 0.95), 2),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCP padam_write/padam_search latency benchmark (p50/p95)")
    parser.add_argument("--sizes", default="10000,100000")
    parser.add_argument("--writes", type=int, default=60)
    parser.add_argument("--searches", type=int, default=100)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    sizes = [int(x.strip()) for x in args.sizes.split(",") if x.strip()]
    rows = []
    for n in sizes:
        row = _bench_size(n, args.writes, args.searches, profile=args.profile)
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)

    report = {
        "padam_version": __version__,
        "embedding": embeddings.backend(),
        "python": sys.version.split()[0],
        "rows": rows,
    }
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
