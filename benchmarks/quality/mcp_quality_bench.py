#!/usr/bin/env python3
"""Офлайн-бенчмарк качества MCP-памяти и Web3-суверенности PADAM NOCTURNE ($0, builtin embedder).

Измеряет:
  1) single_hop: Recall@5 и MRR одношаговых фактов через padam_write / padam_search;
  2) multi_hop: прирост Recall@5 и MRR графового поиска (graph_hops=2 против baseline graph_hops=0);
  3) temporal_asof: точность исторического среза as_of и отсутствие утечки заменённых фактов;
  4) security_guard: % удержания prompt-инъекций в карантин и % маскирования секретов (0 утечек);
  5) web3_sovereignty: скорость генерации/верификации крипто-аттестаций Solana (Ed25519 + Merkle, $0)
     и % верифицированного забвения (revoke -> forget_receipt -> destruction of key -> Merkle forget-leaves).

Запуск:
  python benchmarks/quality/mcp_quality_bench.py --out benchmarks/quality/results_1511.json --strict --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"
os.environ["PADAM_EMBEDDER"] = "builtin"

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from padam import anchor, config, embeddings, mcp_server  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402

config.OLLAMA_URL = "http://127.0.0.1:9"
embeddings._check_ollama = lambda: False


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int((len(s) - 1) * q + 0.5)))
    return round(float(s[idx]), 3)


def _rpc(method: str, params: dict | None = None) -> dict:
    return mcp_server.handle({"jsonrpc": "2.0", "id": f"bench-{method}", "method": method, "params": params or {}})


def _call_tool(name: str, arguments: dict) -> dict:
    resp = _rpc("tools/call", {"name": name, "arguments": arguments})
    if "error" in resp:
        raise RuntimeError(f"MCP error in {name}: {resp['error']}")
    return resp["result"]


def run_benchmark(dataset_path: Path) -> dict:
    data = json.loads(dataset_path.read_text(encoding="utf-8"))
    old_mem = mcp_server._memory
    old_review_all = os.environ.get("PADAM_MCP_REVIEW_ALL")
    os.environ["PADAM_MCP_REVIEW_ALL"] = "0"

    all_search_latencies_ms: list[float] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        m = Memory(user_id="quality_bench", store=Store(Path(tmpdir) / "quality_bench.db"))
        mcp_server._memory = m
        try:
            # --- 1. Single-hop ---
            sh_cases = data["single_hop"]
            for c in sh_cases:
                res = _call_tool("padam_write", {
                    "content": c["content"],
                    "kind": c["kind"],
                    "scope": c["scope"],
                    "origin": "user",
                })
                assert res["isError"] is False

            sh_hits = 0
            sh_rr_sum = 0.0
            for c in sh_cases:
                t0 = time.perf_counter()
                sres = _call_tool("padam_search", {"query": c["query"], "scope": c["scope"], "limit": 5})
                all_search_latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                txt = sres["content"][0]["text"]
                # Ранжируем строки с записями внутри ответа
                lines = [ln for ln in txt.splitlines() if ln.startswith("- ")]
                rank = next((i + 1 for i, ln in enumerate(lines) if c["expect"] in ln), None)
                if rank is not None and rank <= 5:
                    sh_hits += 1
                    sh_rr_sum += 1.0 / rank
                elif c["expect"] in txt:
                    sh_hits += 1
                    sh_rr_sum += 1.0

            single_hop_metrics = {
                "count": len(sh_cases),
                "recall_at_5": round(sh_hits / max(1, len(sh_cases)), 4),
                "mrr": round(sh_rr_sum / max(1, len(sh_cases)), 4),
            }

            # --- 2. Multi-hop (baseline graph_hops=0 vs graph_hops=2) ---
            mh_cases = data["multi_hop"]
            for c in mh_cases:
                key_to_id: dict[str, str] = {}
                for node in c["nodes"]:
                    links = None
                    if node.get("link_to"):
                        links = [{"target": key_to_id[node["link_to"]], "relation": node.get("relation", "derived")}]
                    wres = _call_tool("padam_write", {
                        "content": node["content"],
                        "kind": node["kind"],
                        "scope": c["scope"],
                        "origin": "user",
                        **({"links": links} if links else {}),
                    })
                    key_to_id[node["key"]] = wres["structuredContent"]["id"]

            mh_base_hits = 0
            mh_base_rr = 0.0
            mh_hop_hits = 0
            mh_hop_rr = 0.0
            for c in mh_cases:
                t0 = time.perf_counter()
                b_res = _call_tool("padam_search", {
                    "query": c["query"], "scope": c["scope"], "limit": 1, "graph_hops": 0
                })
                all_search_latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                if c["expect_neighbor"] in b_res["content"][0]["text"]:
                    mh_base_hits += 1
                    mh_base_rr += 1.0

                t1 = time.perf_counter()
                g_res = _call_tool("padam_search", {
                    "query": c["query"], "scope": c["scope"], "limit": 1, "graph_hops": 2
                })
                all_search_latencies_ms.append((time.perf_counter() - t1) * 1000.0)
                g_txt = g_res["content"][0]["text"]
                if c["expect_neighbor"] in g_txt:
                    mh_hop_hits += 1
                    nbs = g_res["structuredContent"].get("graphNeighbors", [])
                    hop_n = next((nb["hop"] for nb in nbs if c["expect_neighbor"] in g_txt), 2)
                    mh_hop_rr += 1.0 / max(1, int(hop_n) + 1)

            mh_total = max(1, len(mh_cases))
            base_r5 = round(mh_base_hits / mh_total, 4)
            hop_r5 = round(mh_hop_hits / mh_total, 4)
            multi_hop_metrics = {
                "count": len(mh_cases),
                "baseline_hops0": {"recall_at_5": base_r5, "mrr": round(mh_base_rr / mh_total, 4)},
                "graph_hops2": {"recall_at_5": hop_r5, "mrr": round(mh_hop_rr / mh_total, 4)},
                "recall_delta": round(hop_r5 - base_r5, 4),
            }

            # --- 3. Temporal as_of ---
            tm_cases = data["temporal_asof"]
            for idx, c in enumerate(tm_cases):
                sc = f"{c['scope']}:{idx}"
                _call_tool("padam_write", {
                    "content": c["old_content"], "kind": "fact", "scope": sc,
                    "origin": "user", "valid_from": c["old_from"], "valid_to": c["old_to"],
                })
                _call_tool("padam_write", {
                    "content": c["new_content"], "kind": "fact", "scope": sc,
                    "origin": "user", "valid_from": c["new_from"],
                })

            tm_hits = 0
            tm_rr = 0.0
            tm_leaks = 0
            for idx, c in enumerate(tm_cases):
                sc = f"{c['scope']}:{idx}"
                t0 = time.perf_counter()
                tres = _call_tool("padam_search", {
                    "query": c["query"], "scope": sc, "as_of": c["as_of"], "limit": 5
                })
                all_search_latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                txt = tres["content"][0]["text"]
                if c["expect"] in txt:
                    tm_hits += 1
                    tm_rr += 1.0
                if c["forbid"] in txt:
                    tm_leaks += 1

            temporal_metrics = {
                "count": len(tm_cases),
                "recall_at_5": round(tm_hits / max(1, len(tm_cases)), 4),
                "mrr": round(tm_rr / max(1, len(tm_cases)), 4),
                "future_leak_count": tm_leaks,
                "leak_rate": round(tm_leaks / max(1, len(tm_cases)), 4),
            }

            # --- 4. Cognitive firewall & secret masking ---
            inj_cases = data["injections"]
            inj_quarantined = 0
            inj_leaked = 0
            for c in inj_cases:
                wres = _call_tool("padam_write", {
                    "content": c["content"], "kind": "fact", "scope": c["scope"], "origin": "external"
                })
                if wres["structuredContent"]["outcome"] == "quarantined":
                    inj_quarantined += 1
                sres = _call_tool("padam_search", {"query": c["query"], "scope": c["scope"], "limit": 5})
                if c["content"][:24] in sres["content"][0]["text"]:
                    inj_leaked += 1

            sec_cases = data["secrets"]
            sec_redacted = 0
            sec_leaked = 0
            for c in sec_cases:
                raw_sec = c["raw_secret"]
                content = c["template"].replace("{SECRET}", raw_sec)
                wres = _call_tool("padam_write", {
                    "content": content, "kind": "fact", "scope": c["scope"], "origin": "user"
                })
                rid = wres["structuredContent"]["id"]
                sres = _call_tool("padam_search", {"query": content.split()[0], "scope": c["scope"], "limit": 10})
                r_rec = m.store.one("SELECT content FROM memory WHERE id = ?", (rid,))
                stored = r_rec["content"] if r_rec else ""
                if raw_sec not in stored and "[REDACTED" in stored:
                    sec_redacted += 1
                if raw_sec in sres["content"][0]["text"] or raw_sec in stored:
                    sec_leaked += 1

            security_metrics = {
                "injections_count": len(inj_cases),
                "injection_quarantine_rate": round(inj_quarantined / max(1, len(inj_cases)), 4),
                "injection_search_leak_rate": round(inj_leaked / max(1, len(inj_cases)), 4),
                "secrets_count": len(sec_cases),
                "secret_redaction_rate": round(sec_redacted / max(1, len(sec_cases)), 4),
                "secret_leak_rate": round(sec_leaked / max(1, len(sec_cases)), 4),
            }

            # Секция 4 умышленно подаёт серию prompt-инъекций подряд, что по политике Machine-Speed Kill Switch
            # переводит базу в строгий карантин; перед замером Web3 (секция 5) владелец снимает тревогу.
            from padam import agentic_shield as _ash
            if _ash.is_lockdown_active(m):
                _ash.unlock_kill_switch(m)

            # --- 5. Web3 Sovereignty & Verified Forgetting ($0 offline Solana/Merkle proofs) ---
            w3_cases = data["web3_sovereignty"]
            w3_ids: list[str] = []
            w3_tokens: list[str] = []
            for c in w3_cases:
                wres = _call_tool("padam_write", {
                    "content": c["content"], "kind": "fact", "scope": c["scope"], "origin": "user"
                })
                w3_ids.append(wres["structuredContent"]["id"])
                w3_tokens.append(c["content"].split()[-1])

            # 5a. Строим оффлайн L3 пакет и замеряем скорость генерации/верификации Ed25519 Solana-аттестаций
            anchor.ensure_keys(m)
            bundle_before = anchor.build_bundle(m)
            assert bundle_before is not None
            root_hex_before = bundle_before.root.hex()
            memo_before = f"{anchor.MEMO_PREFIX} root={root_hex_before} n={len(bundle_before.leaves)} ar=offline-ar-bench d=2026-11-15"

            sk = Ed25519PrivateKey.generate()
            sign_times_ms: list[float] = []
            verify_times_ms: list[float] = []
            valid_checks = 0
            bench_iters = 40
            for it in range(bench_iters):
                ts0 = time.perf_counter()
                att = anchor.sign_anchor_attestation(
                    memo_before, root_hex_before, sk,
                    network="devnet", measurement="offline-quality-bench", slot=1000 + it,
                )
                sign_times_ms.append((time.perf_counter() - ts0) * 1000.0)

                tv0 = time.perf_counter()
                vres = anchor.verify_anchor_attestation(
                    bundle_before.payload, memo_before, att,
                    expected_measurement="offline-quality-bench", reject_mainnet=True,
                )
                verify_times_ms.append((time.perf_counter() - tv0) * 1000.0)
                if vres.get("ok") and vres.get("bundle_ok") and vres.get("signature_ok"):
                    valid_checks += 1

            # Фиксируем первый L3-якорь офлайн ($0 mock uploader/anchorer), чтобы далее проверить Merkle forget-листья
            l3_rep = anchor.run_l3(
                m,
                uploader=lambda payload, tags: "offline-ar-tx-bench-1",
                anchorer=lambda memo: ("offline-sol-sig-bench-1", 1001),
                network="devnet",
                dry_run=False,
            )
            assert l3_rep.get("status") == "anchored"

            # 5b. Верифицированное забвение (revoke -> ключ уничтожен -> квитанция -> 0 утечек -> Merkle forget leaf)
            receipts_ok = 0
            keys_destroyed = 0
            forgetting_leaks = 0
            for mid, marker in zip(w3_ids, w3_tokens):
                rev = m.revoke(mid)
                rcpt = m._last_receipt
                if (
                    rcpt
                    and rcpt.get("format") == "padam-forget-receipt/1"
                    and rcpt.get("memory_id") == mid
                    and rcpt.get("key_destroyed") is True
                    and rcpt.get("leaf_forget_hex")
                ):
                    receipts_ok += 1
                if anchor.key_for(m, mid) is None:
                    keys_destroyed += 1
                s_after = _call_tool("padam_search", {"query": marker, "scope": "bench:web3", "limit": 5})
                g_after = m.expand_graph([mid], hops=1)
                if marker in s_after["content"][0]["text"]:
                    forgetting_leaks += 1
                if any(marker in (nb.get("content") or "") for nb in g_after.get("nodes", [])):
                    forgetting_leaks += 1
                row_chk = m.store.one("SELECT content, status FROM memory WHERE id = ?", (mid,))
                if row_chk and (row_chk["content"] is not None or row_chk["status"] != "revoked"):
                    forgetting_leaks += 1

            # Строим следующий L3-пакет и проверяем, что все 8 квитанций забвения вошли как 0x02 Merkle-листья и прошли аттестацию
            bundle_forget = anchor.build_bundle(m)
            forget_leaves_verified = 0
            if bundle_forget is not None:
                root_hex_f = bundle_forget.root.hex()
                memo_f = f"{anchor.MEMO_PREFIX} root={root_hex_f} n={len(bundle_forget.leaves)} ar=offline-ar-forget d=2026-11-15"
                att_f = anchor.sign_anchor_attestation(
                    memo_f, root_hex_f, sk,
                    network="devnet", measurement="offline-quality-bench", slot=1002,
                )
                vres_f = anchor.verify_anchor_attestation(
                    bundle_forget.payload, memo_f, att_f,
                    expected_measurement="offline-quality-bench", reject_mainnet=True,
                )
                if vres_f.get("ok"):
                    forget_leaves_verified = sum(1 for k, _ in bundle_forget.entries if k == "forget")

            w3_total = max(1, len(w3_ids))
            verified_ok = min(receipts_ok, keys_destroyed, forget_leaves_verified)
            web3_metrics = {
                "count": len(w3_ids),
                "attestation_iterations": bench_iters,
                "attestation_valid_rate": round(valid_checks / bench_iters, 4),
                "attestation_sign_p50_ms": _percentile(sign_times_ms, 0.50),
                "attestation_sign_p95_ms": _percentile(sign_times_ms, 0.95),
                "attestation_verify_p50_ms": _percentile(verify_times_ms, 0.50),
                "attestation_verify_p95_ms": _percentile(verify_times_ms, 0.95),
                "receipts_issued": receipts_ok,
                "keys_destroyed": keys_destroyed,
                "merkle_forget_leaves_verified": forget_leaves_verified,
                "verified_forgetting_rate": round(verified_ok / w3_total, 4),
                "forgetting_leak_count": forgetting_leaks,
            }

            # --- Overall summary ---
            tot_q = len(sh_cases) + len(mh_cases) + len(tm_cases)
            tot_hits = sh_hits + mh_hop_hits + tm_hits
            tot_rr = sh_rr_sum + mh_hop_rr + tm_rr
            overall = {
                "retrieval_queries": tot_q,
                "recall_at_5": round(tot_hits / max(1, tot_q), 4),
                "mrr": round(tot_rr / max(1, tot_q), 4),
                "search_latency_p50_ms": _percentile(all_search_latencies_ms, 0.50),
                "search_latency_p95_ms": _percentile(all_search_latencies_ms, 0.95),
            }

            return {
                "benchmark": "padam-mcp-quality-web3/1",
                "dataset": dataset_path.name,
                "embedder": "builtin ($0 offline)",
                "overall": overall,
                "single_hop": single_hop_metrics,
                "multi_hop": multi_hop_metrics,
                "temporal_asof": temporal_metrics,
                "security_guard": security_metrics,
                "web3_sovereignty": web3_metrics,
            }
        finally:
            mcp_server._memory = old_mem
            m.close()
            if old_review_all is None:
                os.environ.pop("PADAM_MCP_REVIEW_ALL", None)
            else:
                os.environ["PADAM_MCP_REVIEW_ALL"] = old_review_all


def check_strict_thresholds(report: dict) -> list[str]:
    errs: list[str] = []
    if report["overall"]["recall_at_5"] < 0.85:
        errs.append(f"overall recall@5 too low: {report['overall']['recall_at_5']}")
    mh = report["multi_hop"]
    if mh["graph_hops2"]["recall_at_5"] <= mh["baseline_hops0"]["recall_at_5"]:
        errs.append(f"multi-hop did not improve over baseline: {mh}")
    if report["temporal_asof"]["future_leak_count"] != 0:
        errs.append(f"temporal as_of leaked future records: {report['temporal_asof']}")
    sec = report["security_guard"]
    if sec["injection_quarantine_rate"] != 1.0 or sec["injection_search_leak_rate"] != 0.0:
        errs.append(f"injection guard failed: {sec}")
    if sec["secret_redaction_rate"] != 1.0 or sec["secret_leak_rate"] != 0.0:
        errs.append(f"secret redaction failed: {sec}")
    w3 = report["web3_sovereignty"]
    if w3["attestation_valid_rate"] != 1.0:
        errs.append(f"web3 attestation check failed: {w3}")
    if w3["verified_forgetting_rate"] != 1.0 or w3["forgetting_leak_count"] != 0:
        errs.append(f"verified forgetting failed: {w3}")
    return errs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PADAM MCP quality + Web3 sovereignty benchmark")
    ap.add_argument("--dataset", default=str(Path(__file__).resolve().with_name("dataset_sample.json")))
    ap.add_argument("--out", default=None, help="Optional path to write JSON report")
    ap.add_argument("--strict", action="store_true", help="Exit non-zero if quality/security thresholds fail")
    ap.add_argument("--json", action="store_true", help="Print compact JSON report")
    args = ap.parse_args(argv)

    report = run_benchmark(Path(args.dataset))
    if args.out:
        out_p = Path(args.out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    errs = check_strict_thresholds(report)
    report["strict_passed"] = (len(errs) == 0)
    if errs:
        report["strict_errors"] = errs

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"PADAM MCP Quality Bench: Recall@5={report['overall']['recall_at_5']:.3f} "
            f"MRR={report['overall']['mrr']:.3f} "
            f"multi-hop={report['multi_hop']['baseline_hops0']['recall_at_5']:.2f}->{report['multi_hop']['graph_hops2']['recall_at_5']:.2f} "
            f"forgetting={report['web3_sovereignty']['verified_forgetting_rate']:.2f} "
            f"sign_p50={report['web3_sovereignty']['attestation_sign_p50_ms']:.3f}ms"
        )
    return 1 if (args.strict and errs) else 0


if __name__ == "__main__":
    sys.exit(main())
