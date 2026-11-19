"""Мост между PADAM Studio / API / MCP и автономным бенчмарком AIFaSecurity (100 критериев, $0)."""
from __future__ import annotations
import threading
import os

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


_RUN_LOCK = threading.Lock()


def _run_in_subprocess(root) -> dict[str, Any]:
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory(prefix="padam_bench_") as td:
        out = os.path.join(td, "r.json")
        env = dict(os.environ, PYTHONPATH=str(root) + os.pathsep + os.environ.get("PYTHONPATH", ""), PYTHONIOENCODING="utf-8")
        cmd = [sys.executable, "-X", "utf8", "-m", "benchmarks.aifa_security.run_aifa_sec", "--out-json", out,
               "--out-html", os.path.join(td, "r.html"), "--out-svg", os.path.join(td, "r.svg")]
        kw = {"creationflags": 0x08000000} if os.name == "nt" else {}   # без окна консоли в приложении
        r = subprocess.run(cmd, cwd=str(root), env=env, capture_output=True, timeout=300, **kw)
        if r.returncode not in (0, 1) or not os.path.exists(out):
            return {"benchmark": "AIFaSecurity/1.0", "status": "error",
                    "error": (r.stderr or r.stdout or b"").decode("utf-8", "replace")[-600:]}
        with open(out, encoding="utf-8") as fh:
            return json.loads(fh.read())


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

    # 19.11.2026: проверщик «как человек» ловил пустой ответ сервера на «Скачать SARIF» сразу после «Запустить»:
    # прогон внутри процесса сервера временно подменял padam.api._state, и параллельный запрос падал на проверке
    # владельца. Свежий прогон своей памяти теперь идёт в ОТДЕЛЬНОМ процессе и строго по одному (замок).
    if target == "padam" and not target_path and os.environ.get("PADAM_BENCH_INPROC") != "1":
        with _RUN_LOCK:
            return _honest(_run_in_subprocess(root), cached=False, generated_ts=time.time())

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
