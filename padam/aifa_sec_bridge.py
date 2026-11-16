"""Мост между PADAM Studio / API / MCP и автономным бенчмарком AIFaSecurity (100 критериев, $0)."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def get_aifa_security_report(*, run_fresh: bool = False, target: str = "padam", target_path: str | None = None) -> dict[str, Any]:
    """Возвращает отчёт AIFaSecurity (из кеша или живого прогона 100 критериев за $0)."""
    root = _repo_root()
    cache_file = root / "benchmarks" / "aifa_security" / "results_aifa_security.json"
    if not run_fresh and target == "padam" and not target_path and cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            data["cached"] = True
            return data
        except Exception:
            pass

    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from benchmarks.aifa_security import run_aifa_sec
    except ImportError:
        return {
            "benchmark": "AIFaSecurity/1.0",
            "status": "unavailable",
            "error": "benchmarks/aifa_security package not found in this distribution",
        }

    rep = run_aifa_sec.run_aifa_security(target=target, target_path=target_path)
    rep["cached"] = False
    return rep
