"""Тесты эталонного бенчмарка AIFaSecurity (100 критериев, воспроизводимость, сканер уязвимостей, CLI)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.aifa_security import catalog, render, run_aifa_sec  # noqa: E402


def test_aifa_security_catalog_has_exact_100_unique_criteria():
    assert len(catalog.CATALOG) == 100
    assert len({c.id for c in catalog.CATALOG}) == 100
    assert len(catalog.DOMAINS) == 10


def test_aifa_security_padam_100_criteria_pass_and_reproducible():
    r1 = run_aifa_sec.run_aifa_security(target="padam")
    r2 = run_aifa_sec.run_aifa_security(target="padam")

    assert r1["summary"]["total_criteria"] == 100
    assert r1["summary"]["applicable"] == 100
    assert r1["summary"]["failed"] == 0
    assert r1["summary"]["grade"] == "S"
    assert r1["summary"]["score_pct"] == 100.0
    assert r1["elapsed_s"] < 25.0

    # Детерминированная воспроизводимость: балл и SHA-256 печать совпадают
    assert r1["summary"]["score_pct"] == r2["summary"]["score_pct"]
    assert r1["summary"]["report_sha256"] == r2["summary"]["report_sha256"]


def test_aifa_security_repo_scanner_catches_real_vulnerabilities_and_escapes_html(tmp_path):
    vuln_repo = tmp_path / "bad_repo"
    vuln_repo.mkdir()
    fake_sk = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4"
    (vuln_repo / "app.py").write_text(
        f'SECRET = "{fake_sk}"\n'
        'def run(x):\n'
        '    return eval(x)\n',
        encoding="utf-8",
    )
    rep = run_aifa_sec.run_aifa_security(target="repo", target_path=str(vuln_repo))
    by_id = {c["id"]: c for c in rep["criteria"]}
    assert by_id["AS-071"]["status"] == "FAIL"
    assert by_id["AS-072"]["status"] == "FAIL"
    assert rep["summary"]["failed"] >= 2

    # XSS-экранирование в HTML/SVG генераторах
    rep["summary"]["target"] = "<script>alert(1)</script>"
    html_out = render.render_html_dashboard(rep)
    svg_out = render.render_svg_badge(rep["summary"])
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;" in html_out
    assert "<script>alert(1)</script>" not in svg_out


def test_aifa_security_cli_entrypoint():
    from padam import cli

    rc = cli.main(["aifa-sec", "--no-write"])
    assert rc == 0
