"""Мост между PADAM Studio / API / MCP и автономным бенчмарком AIFaSecurity (100 критериев, $0)."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


HONEST_NOTE = ("All 100 criteria are deterministic checks without an LLM judge; 100% on PADAM's own code is expected "
               "by design — compare products with --target / --target-path.")


def _honest(rep: dict[str, Any], *, cached: bool, generated_ts: float) -> dict[str, Any]:
    """Grok-аудит 18.11, пп. 5/12/15: свежесть и честная пометка в КАЖДОМ ответе — из кеша и из живого прогона."""
    rep["cached"] = cached
    rep["generated_at"] = datetime.fromtimestamp(generated_ts, tz=timezone.utc).isoformat(timespec="seconds")
    age_h = max(0.0, (time.time() - generated_ts) / 3600.0)
    rep["cache_age_hours"] = round(age_h, 1) if cached else 0.0
    rep["stale"] = bool(cached and age_h > 24)
    rep["honest_note"] = HONEST_NOTE
    return rep


def get_aifa_security_report(*, run_fresh: bool = False, target: str = "padam", target_path: str | None = None) -> dict[str, Any]:
    """Возвращает отчёт AIFaSecurity (из кеша или живого прогона 100 критериев за $0)."""
    root = _repo_root()
    cache_file = root / "benchmarks" / "aifa_security" / "results_aifa_security.json"
    if not run_fresh and target == "padam" and not target_path and cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            return _honest(data, cached=True, generated_ts=cache_file.stat().st_mtime)
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

    saved_api_state = None
    _api_mod = sys.modules.get("padam.api")
    if _api_mod is not None and hasattr(_api_mod, "_state"):
        saved_api_state = dict(_api_mod._state)
    try:
        rep = run_aifa_sec.run_aifa_security(target=target, target_path=target_path)
    finally:
        if _api_mod is not None and saved_api_state is not None:
            _api_mod._state.clear()
            _api_mod._state.update(saved_api_state)
    return _honest(rep, cached=False, generated_ts=time.time())
