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


def _show(value: Any, unit: str) -> str:
    """Число — с единицей, «n/a» — без неё."""
    return f"{value}{unit}" if isinstance(value, (int, float)) else str(value)


def generate_sovereignty_badge(
    metrics: dict[str, Any] | None = None,
    *,
    report_path: Path | None = None,
    out_svg: Path | None = None,
) -> dict[str, Any]:
    """Генерирует самодостаточный SVG-бейдж и Markdown-карточку суверенности PADAM Nocturne."""
    data = metrics if metrics is not None else load_benchmark_metrics(report_path)
    if not data:
        # 15.11.2026: в пакете с PyPI нет папки benchmarks/, и раньше карточка рисовала «Recall 0 %, защита 0 %» —
        # число, которого никто не мерил. Нет замера — нет карточки: честный отказ вместо выдуманных нулей.
        return {
            "status": "no_report",
            "error": "benchmark report not found",
            "hint": ("run: python benchmarks/quality/mcp_quality_bench.py --out report.json "
                     "(from the GitHub repository), then: padam badge --report report.json"),
            "svg": None,
            "markdown": None,
            "svg_path": None,
        }
    overall = data.get("overall", {})
    sec = data.get("security_guard", {})
    web3 = data.get("web3_sovereignty", {})

    def _pct(block: dict[str, Any], key: str) -> float | str:
        # Отсутствующая метрика — «n/a», а не 0: ноль читается как «защита не работает».
        return round(float(block[key]) * 100.0, 1) if key in block else "n/a"

    recall5 = _pct(overall, "recall_at_5")
    p50_ms = round(float(overall["search_latency_p50_ms"]), 2) if "search_latency_p50_ms" in overall else "n/a"
    quarantine_pct = _pct(sec, "injection_quarantine_rate")
    redaction_pct = _pct(sec, "secret_redaction_rate")
    forget_pct = _pct(web3, "verified_forgetting_rate")
    dataset_name = html.escape(str(data.get("dataset", "offline-bench")))

    summary = {
        "dataset": dataset_name,
        "recall_at_5_pct": recall5,
        "p50_ms": p50_ms,
        "injection_quarantine_pct": quarantine_pct,
        "secret_redaction_pct": redaction_pct,
        "verified_forgetting_pct": forget_pct,
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
        f'Recall@5: {_show(summary["recall_at_5_pct"], "%")}   |   p50 Latency: {_show(summary["p50_ms"], " ms")}</text>\n'
        f'  <text x="20" y="118" fill="#3fb950" font-family="monospace" font-size="13">'
        f'Injection Guard: {_show(summary["injection_quarantine_pct"], "%")}   |   DLP Redaction: {_show(summary["secret_redaction_pct"], "%")}</text>\n'
        f'  <text x="20" y="144" fill="#d2a8ff" font-family="monospace" font-size="13">'
        f'Cryptographic Forgetting (Merkle): {_show(summary["verified_forgetting_pct"], "%")}</text>\n'
        '</svg>\n'
    )

    if out_svg is not None:
        out_path = Path(out_svg)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(svg, encoding="utf-8")

    markdown = (
        "### PADAM Nocturne — Sovereign Memory Card\n"
        f"- **Recall@5:** `{_show(summary['recall_at_5_pct'], '%')}` (`p50`: `{_show(summary['p50_ms'], ' ms')}`)\n"
        f"- **Injection Quarantine:** `{_show(summary['injection_quarantine_pct'], '%')}` | **DLP Redaction:** `{_show(summary['secret_redaction_pct'], '%')}`\n"
        f"- **Verified Cryptographic Forgetting:** `{_show(summary['verified_forgetting_pct'], '%')}`\n"
        f"- **Mode:** `Local-First ($0)` (`{dataset_name}`)\n"
    )

    return {
        "status": "ok",
        "metrics": summary,
        "svg": svg,
        "markdown": markdown,
        "svg_path": str(out_svg) if out_svg is not None else None,
    }
