# -*- coding: utf-8 -*-
"""Инспектор Бюджета Токенов и Телеметрии MCP (MCP Telemetry Inspector, ТОП-8).

Измеряет реальный размер JSON-схем инструментов (`schema_tokens`), время отклика (p50/p95)
и выдаёт рекомендации по экономии контекстного окна агента без платных вызовов.
"""
from __future__ import annotations

import json
from typing import Any

from . import telemetry


def inspect_mcp_telemetry(tools_list: list[dict[str, Any]], *, memory_stats: dict[str, Any] | None = None) -> dict[str, Any]:
    """Рассчитывает вес схем MCP в токенах, статистику вызовов и подсказки оптимизации."""
    per_tool_schema: list[dict[str, Any]] = []
    total_chars = 0
    for t in tools_list:
        raw_len = len(json.dumps(t, ensure_ascii=False))
        total_chars += raw_len
        per_tool_schema.append({
            "name": str(t.get("name") or ""),
            "schema_chars": raw_len,
            "approx_tokens": max(1, round(raw_len / 4.0, 1)),
        })

    per_tool_schema.sort(key=lambda x: -x["schema_chars"])
    snap = telemetry.get_telemetry().snapshot()

    recommendations: list[str] = []
    if len(tools_list) > 12:
        recommendations.append("Keep compact default tools (9) when spawning lightweight siblings; enable PADAM_MCP_ARK_TOOLS=1 only for coordinators.")
    if any(item["approx_tokens"] > 350 for item in per_tool_schema):
        recommendations.append("Use compact=true or max_tokens in padam_search / padam_session_pack to keep context slim.")

    return {
        "ok": True,
        "tools_count": len(tools_list),
        "total_schema_chars": total_chars,
        "total_schema_approx_tokens": max(1, round(total_chars / 4.0, 1)),
        "heaviest_tools": per_tool_schema[:5],
        "runtime_telemetry": {
            "tool_calls_total": snap.get("counters", {}).get("tool_calls_total", 0),
            "tool_errors_total": snap.get("counters", {}).get("tool_errors_total", 0),
            "latencies": snap.get("latencies", {}),
        },
        "memory_stats": memory_stats or {},
        "recommendations": recommendations,
    }
