"""Локальная телеметрия в формате OpenTelemetry (OTLP JSONL, $0, без сети).

Собирает спаны вызовов MCP-инструментов, гистограммы задержки (p50/p95/p99),
счётчики безопасности (dlp_hits, acl_denies, quarantine_hits, tokens_saved)
и экспортирует их через ресурс `padam://metrics` и опциональный локальный JSONL.

По умолчанию выключено (PADAM_OTEL_METRICS=0).
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import config


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 3)
    idx = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    val = sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac
    return round(val, 3)


class LocalTelemetry:
    """Потокобезопасный локальный сборщик метрик и OTLP-спанов."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._latencies: dict[str, list[float]] = defaultdict(list)
        self._counters: dict[str, int] = defaultdict(int)
        self._spans: list[dict[str, Any]] = []

    def reset(self) -> None:
        with self._lock:
            self._latencies.clear()
            self._counters.clear()
            self._spans.clear()

    def incr(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] += int(value)

    def record_span(
        self,
        tool_name: str,
        duration_ms: float,
        *,
        status: str = "ok",
        attributes: dict[str, Any] | None = None,
        force: bool = False,
    ) -> dict[str, Any] | None:
        if not force and not config.mcp_otel_enabled():
            return None

        now_ns = time.time_ns()
        dur_ns = max(0, int(round(duration_ms * 1_000_000)))
        span = {
            "traceId": secrets.token_hex(16),
            "spanId": secrets.token_hex(8),
            "name": f"mcp.tool.{tool_name}",
            "kind": 1,
            "startTimeUnixNano": str(max(0, now_ns - dur_ns)),
            "endTimeUnixNano": str(now_ns),
            "attributes": [
                {"key": str(k), "value": {"stringValue": str(v)}}
                for k, v in (attributes or {"tool": tool_name}).items()
            ],
            "status": {"code": 1 if status == "ok" else 2},
        }
        otlp_record = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "padam-nocturne"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "padam.mcp"},
                            "spans": [span],
                        }
                    ],
                }
            ]
        }

        with self._lock:
            self._counters["tool_calls_total"] += 1
            self._counters[f"tool_calls.{tool_name}"] += 1
            if status != "ok":
                self._counters["tool_errors_total"] += 1
            arr = self._latencies[tool_name]
            arr.append(float(duration_ms))
            if len(arr) > 2000:
                del arr[: len(arr) - 2000]
            self._spans.append(span)
            if len(self._spans) > 200:
                del self._spans[: len(self._spans) - 200]

        out_path = config.mcp_otel_path()
        if out_path:
            p = Path(out_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps(otlp_record, ensure_ascii=False) + "\n")

        return otlp_record

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            latency_summary: dict[str, dict[str, Any]] = {}
            all_vals: list[float] = []
            for tool, vals in self._latencies.items():
                s = sorted(vals)
                all_vals.extend(s)
                latency_summary[tool] = {
                    "count": len(s),
                    "p50_ms": _percentile(s, 50),
                    "p95_ms": _percentile(s, 95),
                    "p99_ms": _percentile(s, 99),
                }
            all_sorted = sorted(all_vals)
            return {
                "enabled": config.mcp_otel_enabled(),
                "counters": dict(self._counters),
                "latency_ms": {
                    "overall": {
                        "count": len(all_sorted),
                        "p50_ms": _percentile(all_sorted, 50),
                        "p95_ms": _percentile(all_sorted, 95),
                        "p99_ms": _percentile(all_sorted, 99),
                    },
                    "by_tool": latency_summary,
                },
                "otlp_recent_spans": len(self._spans),
            }


_GLOBAL_TELEMETRY = LocalTelemetry()


def get_telemetry() -> LocalTelemetry:
    return _GLOBAL_TELEMETRY
