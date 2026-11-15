"""ТОП-10 v4 Пункт 9: Виральная карточка суверенности PADAM (SVG + Markdown по реальным метрикам, без приватных данных)."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _default_report_path() -> Path:
    return Path(__file__).resolve().parents[1] / "benchmarks" / "quality" / "results_1511.json"


def load_benchmark_metrics(report_path: Path | None = None) -> dict[str, Any]:
    """Загружает агрегированные метрики бенчмарка качества (без персональных данных)."""
    path = Path(report_path) if report_path else _default_report_path()
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def generate_sovereignty_badge(
    metrics: dict[str, Any] | None = None,
    *,
    report_path: Path | None = None,
    out_svg: Path | None = None,
) -> dict[str, Any]:
    """Генерирует самодостаточный SVG-бейдж и Markdown-карточку суверенности PADAM Nocturne."""
    data = metrics if metrics is not None else load_benchmark_metrics(report_path)
    overall = data.get("overall", {})
    sec = data.get("security_guard", {})
    web3 = data.get("web3_sovereignty", {})

    recall5 = float(overall.get("recall_at_5", 0.0)) * 100.0
    p50_ms = float(overall.get("search_latency_p50_ms", 0.0))
    quarantine_pct = float(sec.get("injection_quarantine_rate", 0.0)) * 100.0
    redaction_pct = float(sec.get("secret_redaction_rate", 0.0)) * 100.0
    forget_pct = float(web3.get("verified_forgetting_rate", 0.0)) * 100.0
    dataset_name = html.escape(str(data.get("dataset", "offline-bench")))

    summary = {
        "dataset": dataset_name,
        "recall_at_5_pct": round(recall5, 1),
        "p50_ms": round(p50_ms, 2),
        "injection_quarantine_pct": round(quarantine_pct, 1),
        "secret_redaction_pct": round(redaction_pct, 1),
        "verified_forgetting_pct": round(forget_pct, 1),
    }

    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="540" height="170" viewBox="0 0 540 170" role="img" '
        'aria-label="PADAM Nocturne Sovereignty Card">\n'
        '  <defs>\n'
        '    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">\n'
        '      <stop offset="0%" stop-color="#0d1117"/>\n'
        '      <stop offset="100%" stop-color="#161b22"/>\n'
        '    </linearGradient>\n'
        '  </defs>\n'
        '  <rect width="540" height="170" rx="12" fill="url(#bg)" stroke="#30363d" stroke-width="1.5"/>\n'
        '  <text x="20" y="34" fill="#58a6ff" font-family="system-ui,sans-serif" font-size="16" font-weight="700">'
        'PADAM NOCTURNE · SOVEREIGN AI MEMORY</text>\n'
        f'  <text x="20" y="56" fill="#8b949e" font-family="monospace" font-size="11">'
        f'Local-First · Zero-Cloud ($0) · Dataset: {dataset_name}</text>\n'
        f'  <text x="20" y="92" fill="#e6edf3" font-family="monospace" font-size="13">'
        f'Recall@5: {summary["recall_at_5_pct"]}%   |   p50 Latency: {summary["p50_ms"]} ms</text>\n'
        f'  <text x="20" y="118" fill="#3fb950" font-family="monospace" font-size="13">'
        f'Injection Guard: {summary["injection_quarantine_pct"]}%   |   DLP Redaction: {summary["secret_redaction_pct"]}%</text>\n'
        f'  <text x="20" y="144" fill="#d2a8ff" font-family="monospace" font-size="13">'
        f'Cryptographic Forgetting (Merkle): {summary["verified_forgetting_pct"]}%</text>\n'
        '</svg>\n'
    )

    if out_svg is not None:
        out_path = Path(out_svg)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(svg, encoding="utf-8")

    markdown = (
        "### PADAM Nocturne — Sovereign Memory Card\n"
        f"- **Recall@5:** `{summary['recall_at_5_pct']}%` (`p50`: `{summary['p50_ms']} ms`)\n"
        f"- **Injection Quarantine:** `{summary['injection_quarantine_pct']}%` | **DLP Redaction:** `{summary['secret_redaction_pct']}%`\n"
        f"- **Verified Cryptographic Forgetting:** `{summary['verified_forgetting_pct']}%`\n"
        f"- **Mode:** `Local-First ($0)` (`{dataset_name}`)\n"
    )

    return {
        "status": "ok",
        "metrics": summary,
        "svg": svg,
        "markdown": markdown,
        "svg_path": str(out_svg) if out_svg is not None else None,
    }
