# -*- coding: utf-8 -*-
"""Генераторы SVG-бейджа, автономного HTML-дашборда и Markdown-отчёта AIFaSecurity (без внешних зависимостей и CDN)."""
from __future__ import annotations

import html
from typing import Any


def render_svg_badge(summary: dict[str, Any]) -> str:
    target = html.escape(str(summary.get("target", "padam-nocturne")))
    score = float(summary.get("score_pct", 0.0))
    grade = html.escape(str(summary.get("grade", "F")))
    passed = int(summary.get("passed", 0))
    applicable = int(summary.get("applicable", 0))
    seal = html.escape(str(summary.get("report_sha256", ""))[:16])

    grade_color = "#3fb950" if grade in ("S", "A") else ("#d29922" if grade in ("B", "C") else "#f85149")
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="560" height="150" viewBox="0 0 560 150" role="img" '
        'aria-label="AIFaSecurity Benchmark Badge">\n'
        '  <rect width="560" height="150" rx="12" fill="#0d1117" stroke="#30363d" stroke-width="1.5"/>\n'
        '  <text x="20" y="34" fill="#58a6ff" font-family="system-ui,sans-serif" font-size="16" font-weight="700">'
        'AIFaSecurity · 100-Criteria Agent Memory Audit</text>\n'
        f'  <text x="20" y="58" fill="#8b949e" font-family="monospace" font-size="12">Target: {target} · Cost: $0 (No LLM)</text>\n'
        f'  <text x="20" y="92" fill="#e6edf3" font-family="monospace" font-size="15" font-weight="700">'
        f'Score: {score:.1f}%   |   Passed: {passed}/{applicable}</text>\n'
        f'  <text x="20" y="122" fill="#8b949e" font-family="monospace" font-size="11">Report SHA-256: {seal}…</text>\n'
        f'  <rect x="470" y="26" width="68" height="68" rx="10" fill="{grade_color}" fill-opacity="0.18" stroke="{grade_color}" stroke-width="2"/>\n'
        f'  <text x="504" y="72" text-anchor="middle" fill="{grade_color}" font-family="system-ui,sans-serif" font-size="34" font-weight="800">{grade}</text>\n'
        '</svg>\n'
    )


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"# AIFaSecurity Report — `{s['target']}`",
        "",
        f"- **Grade:** **{s['grade']}** (`{s['score_pct']:.1f}%` applicable weighted score)",
        f"- **Criteria:** `100` total | `{s['applicable']}` applicable | `{s['passed']}` PASS | `{s['partial']}` PARTIAL | `{s['failed']}` FAIL | `{s['na']}` N/A",
        f"- **Execution:** `$0` offline (No LLM), `{report['elapsed_s']}s`, Python `{report['python_version']}`",
        f"- **Report SHA-256:** `{s['report_sha256']}`",
        "",
        "## Domain Breakdown",
        "",
        "| Domain | Name | Applicable | Passed | Failed | Score |",
        "|---|---|---|---|---|---|",
    ]
    for dom, d in report["domains"].items():
        lines.append(f"| {dom} | {d['name']} | {d['applicable']} | {d['passed']} | {d['failed']} | {d['score_pct']:.1f}% |")
    lines.append("")
    lines.append("## Detailed Criteria (100)")
    lines.append("")
    lines.append("| ID | Domain | Severity | Status | Metric | Evidence |")
    lines.append("|---|---|---|---|---|---|")
    for c in report["criteria"]:
        ev = str(c["evidence"]).replace("|", "/")
        mt = str(c["metric"]).replace("|", "/")
        lines.append(f"| {c['id']} | {c['domain']} | {c['severity']} | {c['status']} | `{mt}` | {ev} |")
    return "\n".join(lines) + "\n"


def render_html_dashboard(report: dict[str, Any]) -> str:
    s = report["summary"]
    target = html.escape(str(s["target"]))
    grade = html.escape(str(s["grade"]))
    seal = html.escape(str(s["report_sha256"]))

    dom_rows = []
    for dom, d in report["domains"].items():
        dom_rows.append(
            f"<tr><td><strong>{html.escape(dom)}</strong></td>"
            f"<td>{html.escape(str(d['name']))}</td>"
            f"<td>{d['passed']}/{d['applicable']}</td>"
            f"<td>{d['failed']}</td>"
            f"<td><strong>{d['score_pct']:.1f}%</strong></td></tr>"
        )

    crit_rows = []
    for c in report["criteria"]:
        st = c["status"]
        cls = "pass" if st == "PASS" else ("fail" if st == "FAIL" else ("part" if st == "PARTIAL" else "na"))
        crit_rows.append(
            f"<tr><td><code>{html.escape(c['id'])}</code></td>"
            f"<td>{html.escape(c['domain'])}</td>"
            f"<td>{html.escape(c['severity'])}</td>"
            f"<td><span class='badge {cls}'>{html.escape(st)}</span></td>"
            f"<td>{html.escape(c['title_en'])}</td>"
            f"<td><code>{html.escape(str(c['metric']))}</code></td>"
            f"<td>{html.escape(str(c['evidence']))}</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIFaSecurity · {target}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 24px; }}
  .wrap {{ max-width: 1120px; margin: 0 auto; }}
  .hero {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px 24px; display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; }}
  .grade {{ font-size: 42px; font-weight: 800; color: #3fb950; border: 2px solid #3fb950; border-radius: 12px; padding: 10px 22px; }}
  .meta {{ color: #8b949e; font-size: 13px; margin-top: 6px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; background: #161b22; border: 1px solid #30363d; }}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; text-align: left; }}
  th {{ background: #1f242c; color: #8b949e; }}
  .badge {{ padding: 2px 8px; border-radius: 999px; font-weight: 700; font-size: 11px; }}
  .pass {{ background: #23863633; color: #3fb950; }}
  .fail {{ background: #da363333; color: #f85149; }}
  .part {{ background: #d2992233; color: #d29922; }}
  .na {{ background: #8b949e33; color: #8b949e; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div>
      <h1 style="margin:0;font-size:22px;color:#58a6ff;">AIFaSecurity · 100-Criteria Agent Memory Benchmark</h1>
      <div class="meta">Target: <strong>{target}</strong> · Applicable: {s['applicable']}/100 · Passed: {s['passed']} · Failed: {s['failed']} · N/A: {s['na']} · Cost: $0 (No LLM)</div>
      <div class="meta">Report SHA-256: <code>{seal}</code></div>
    </div>
    <div style="text-align:center;">
      <div class="grade">{grade} ({s['score_pct']:.1f}%)</div>
    </div>
  </div>
  <h2 style="margin-top:24px;font-size:17px;">Domains (10)</h2>
  <table><thead><tr><th>Domain</th><th>Name</th><th>Passed</th><th>Failed</th><th>Score</th></tr></thead><tbody>{''.join(dom_rows)}</tbody></table>
  <h2 style="margin-top:24px;font-size:17px;">All 100 Criteria</h2>
  <table><thead><tr><th>ID</th><th>Dom</th><th>Sev</th><th>Status</th><th>Criterion</th><th>Metric</th><th>Evidence</th></tr></thead><tbody>{''.join(crit_rows)}</tbody></table>
</div>
</body>
</html>
"""


def render_sarif(report: dict[str, Any]) -> str:
    """Формирует отчёт в стандарте SARIF 2.1.0 для GitHub Code Scanning и CI SecOps."""
    import json as _json

    s = report["summary"]
    domains = report.get("domains") or {}
    rules = []
    results = []
    for c in report.get("criteria") or []:
        cid = str(c.get("id") or "")
        dom = str(c.get("domain") or "")
        sev = str(c.get("severity") or "MEDIUM").upper()
        st = str(c.get("status") or "N/A")
        stds = (domains.get(dom) or {}).get("standards") or {}
        rules.append({
            "id": cid,
            "name": str(c.get("title") or cid),
            "shortDescription": {"text": str(c.get("title") or cid)},
            "properties": {
                "domain": dom,
                "severity": sev,
                "standards": stds,
            },
        })
        if st in ("FAIL", "PARTIAL"):
            level = "error" if (st == "FAIL" and sev in ("CRITICAL", "HIGH")) else "warning"
            results.append({
                "ruleId": cid,
                "level": level,
                "message": {"text": f"[{st}] {c.get('title')}: {c.get('evidence')} (metric={c.get('metric')}, threshold={c.get('threshold')})"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(s.get("target") or "padam-nocturne")}}}],
                "properties": {"domain": dom, "standards": stds},
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AIFaSecurity",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/MaksimGalatin/padam-nocturne",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "grade": s.get("grade"),
                "score_pct": s.get("score_pct"),
                "report_sha256": s.get("report_sha256"),
            },
        }],
    }
    return _json.dumps(sarif, ensure_ascii=False, indent=2)
