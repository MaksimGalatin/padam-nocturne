# -*- coding: utf-8 -*-
"""Тесты усиленных бенчмарков (SARIF 2.1.0, OWASP/MITRE/NIST, baseline diff, QA MRR/nDCG/ROUGE-L, кнопки Studio)."""
from __future__ import annotations

import json
import sys
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.aifa_security.fuzzer import run_fuzz_suite  # noqa: E402
from benchmarks.aifa_security.render import render_sarif  # noqa: E402
from benchmarks.aifa_security.run_aifa_sec import run_aifa_security, verify_report_attestation  # noqa: E402
from benchmarks.quality import qa_honest_bench as qhb  # noqa: E402
from padam import api  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402


def test_aifa_security_standards_sarif_domain_filter_and_baseline() -> None:
    rep = run_aifa_security(target="padam", domains_filter={"D1", "D3"})
    assert set(rep["domains"].keys()) == {"D1", "D3"}
    assert "LLM01" in rep["standards_summary"]["owasp_llm_covered"]
    assert "ASI05" in rep["standards_summary"]["owasp_agentic_covered"]
    assert "AML.T0051" in rep["standards_summary"]["mitre_atlas_covered"]

    sarif = json.loads(render_sarif(rep))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == len(rep["criteria"])

    rep_diff = run_aifa_security(target="padam", domains_filter={"D1"}, baseline=rep)
    assert "baseline_diff" in rep_diff
    assert rep_diff["baseline_diff"]["regressions"] == []

    # Проверка Ed25519 + SHA-256 аттестации и детекта подделки (tamper detection)
    assert verify_report_attestation(rep)["verified"] is True
    tampered = json.loads(json.dumps(rep))
    tampered["summary"]["score_pct"] = 99.9
    assert verify_report_attestation(tampered)["verified"] is False

    fuzz = run_fuzz_suite()
    assert fuzz["padam"]["secrets_masked_pct"] == 100.0
    assert fuzz["padam"]["false_positive_rate_pct"] == 0.0
    assert fuzz["padam"]["defense_rate_pct"] > fuzz["baselines"]["basic_regex"]["defense_rate_pct"]


def test_qa_honest_bench_mrr_ndcg_rougel_em() -> None:
    mrr, nd5, nd10 = qhb._rank_metrics(["s2", "s1", "s3"], {"s1"})
    assert mrr == 0.5 and 0.0 < nd5 < 1.0 and nd10 == nd5
    assert qhb._exact_match("Hello, World!", "hello world") is True
    assert qhb._rouge_l("Paris is the capital of France", "capital of France") > 0.5


def _get_with_retry(req, attempts: int = 3, timeout: float = 60.0) -> str:
    """24.11.2026: на windows-latest 3.12 после ~1 750 тестов сокет трижды за двое суток не дождался ответа
    (36c05ce, 6b85900, 20edd22), хотя локально каждый адрес отвечает за 0,00–0,65 с, а отчёт берётся из кеша.
    Тест проверяет кнопки и ответы, а не скорость машины CI, поэтому — до трёх попыток с запасом 60 с."""
    last: Exception | None = None
    for _ in range(attempts):
        try:
            return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8")
        except (TimeoutError, OSError) as exc:  # socket.timeout — подкласс OSError
            last = exc
    raise AssertionError(f"нет ответа за {attempts} попытки: {last!r}")


def test_studio_benchmark_buttons_and_endpoints(tmp_path: Path) -> None:
    m = Memory(user_id="bench_ui", store=Store(tmp_path / "b.db"))
    srv, link = api.make_studio_server(m, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base, tok = link.split("/studio#t=", 1)
        # 23.11.2026: запас 30 с вместо 5. Локально /studio отдаётся за 0,06 с (замер), но на windows-latest 3.12 после 1 700 тестов
        # первый запрос дважды подряд не уложился в 5 с (CI 36c05ce, 6b85900) — это нагрузка машины CI, не Studio.
        html = _get_with_retry(f"{base}/studio")
        for marker in (
            "att-aifasec-dl-json",
            "att-aifasec-dl-sarif",
            "att-aifasec-dl-html",
            "att-qa-load",
            "att-fuzz-run",
            "att-sec-verify",
            "apple-mobile-web-app-capable",
        ):
            assert marker in html

        for ep, expect in (
            ("/api/v2/aifa-security/sarif", '"version": "2.1.0"'),
            ("/api/v2/aifa-security/html", "AIFaSecurity"),
            ("/api/v2/aifa-security/fuzz", "total_attack_vectors"),
            ("/api/v2/aifa-security/verify", '"verified": true'),
            ("/api/v2/qa-benchmark", "benchmark"),
        ):
            req = urllib.request.Request(f"{base}{ep}", headers={"Authorization": f"Bearer {tok}"})
            body = _get_with_retry(req)
            assert expect in body
    finally:
        srv.shutdown()
        srv.server_close()
        m.close()
