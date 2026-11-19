"""B1 дорожной карты Сестры (19.11.2026): наблюдаемость без облака.

Каждый вызов MCP-инструмента — строка JSON в журнале дня: trace_id, инструмент, длительность, итог, процесс.
Аргументы и текст памяти НЕ пишутся (в них бывают секреты). Sentry и внешние сборщики сознательно не подключены:
память PADAM живёт у владельца, отправка трасс в чужое облако нарушила бы это. Сводка latency_summary() даёт
p50/p95 по дню — цель Сестры: p95 < 200 мс. Выключить: PADAM_OBS_LOG=0."""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

_ЗАМОК = threading.Lock()
_ПРЕДЕЛ_БАЙТ = 20 * 1024 * 1024   # журнал дня не растёт бесконечно: после 20 МБ записи за день прекращаются


def _папка() -> Path:
    base = os.environ.get("PADAM_HOME") or os.path.join(os.path.expanduser("~"), ".padam")
    p = Path(base) / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _файл_дня(day: str | None = None) -> Path:
    day = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _папка() / f"mcp-{day}.jsonl"


def new_trace_id() -> str:
    return uuid.uuid4().hex[:16]


def log_call(tool: str, *, ok: bool, duration_ms: float, trace_id: str | None = None, action: str = "") -> str | None:
    if os.environ.get("PADAM_OBS_LOG", "1") == "0":
        return None
    tid = trace_id or new_trace_id()
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "trace_id": tid, "tool": str(tool),
           "action": str(action or "")[:64], "ok": bool(ok), "duration_ms": round(float(duration_ms), 2),
           "pid": os.getpid(), "agent": os.environ.get("PADAM_AGENT_ID") or ""}
    try:
        f = _файл_дня()
        with _ЗАМОК:
            if f.exists() and f.stat().st_size > _ПРЕДЕЛ_БАЙТ:
                return tid
            with f.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass   # журнал не должен ломать вызов
    return tid


def _перцентиль(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round(q * (len(xs) - 1)))))
    return xs[k]


def latency_summary(day: str | None = None) -> dict:
    f = _файл_дня(day)
    рядов, ошибок, по_инстр = 0, 0, {}
    if f.exists():
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            рядов += 1
            ошибок += 0 if r.get("ok") else 1
            по_инстр.setdefault(r.get("tool", "?"), []).append(float(r.get("duration_ms") or 0))
    все = [x for v in по_инстр.values() for x in v]
    return {"day": day or datetime.now(timezone.utc).strftime("%Y-%m-%d"), "calls": рядов, "errors": ошибок,
            "p50_ms": round(_перцентиль(все, 0.5), 2), "p95_ms": round(_перцентиль(все, 0.95), 2),
            "target_p95_ms": 200, "p95_ok": _перцентиль(все, 0.95) < 200,
            "by_tool": {k: {"calls": len(v), "p95_ms": round(_перцентиль(v, 0.95), 2)}
                        for k, v in sorted(по_инстр.items(), key=lambda kv: -len(kv[1]))[:20]},
            "file": str(f)}
