# -*- coding: utf-8 -*-
"""Роутер языковых моделей PADAM с переключением «Феникс» (Primary -> Sovereign -> Local).

По умолчанию настроен ТОЛЬКО локальный контур (Ollama на 127.0.0.1:11434/v1).
Внешние контуры (PADAM_LLM_PRIMARY_*, PADAM_LLM_SOVEREIGN_*) активируются
исключительно при явном задании соответствующих переменных окружения человеком.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from . import safety

FAILOVER_STATUS_CODES = frozenset({401, 402, 403, 408, 429})
LOCAL_ONLY_TASK_TYPES = frozenset({"sleep", "classify", "summarize", "maintenance"})


def _mask_key(raw: str) -> str:
    s = str(raw or "").strip()
    if not s or s == "ollama":
        return ""
    if len(s) <= 8:
        return "***"
    return f"{s[:3]}...{s[-3:]}"


@dataclass(frozen=True)
class ContourConfig:
    name: str  # primary | sovereign | local
    url: str
    api_key: str
    model: str
    timeout_s: float
    enabled: bool

    def public_view(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url if self.enabled else "",
            "model": self.model if self.enabled else "",
            "timeout_s": self.timeout_s,
            "enabled": self.enabled,
            "has_key": bool(self.api_key and self.api_key != "ollama"),
            "key_masked": _mask_key(self.api_key),
        }


def load_contours() -> list[ContourConfig]:
    """Читает конфигурацию контуров из окружения (по умолчанию включён только local)."""
    def _env(prefix: str, field: str, default: str = "") -> str:
        return os.environ.get(f"PADAM_LLM_{prefix}_{field}", default).strip()

    def _timeout(prefix: str, default: float) -> float:
        raw = _env(prefix, "TIMEOUT")
        if not raw:
            return default
        try:
            return max(1.0, min(300.0, float(raw)))
        except ValueError:
            return default

    p_url = _env("PRIMARY", "URL")
    p_key = _env("PRIMARY", "KEY")
    p_model = _env("PRIMARY", "MODEL")
    primary = ContourConfig(
        name="primary",
        url=p_url.rstrip("/"),
        api_key=p_key,
        model=p_model or "gpt-4o-mini",
        timeout_s=_timeout("PRIMARY", 30.0),
        enabled=bool(p_url),
    )

    s_url = _env("SOVEREIGN", "URL")
    s_key = _env("SOVEREIGN", "KEY")
    s_model = _env("SOVEREIGN", "MODEL")
    sovereign = ContourConfig(
        name="sovereign",
        url=s_url.rstrip("/"),
        api_key=s_key,
        model=s_model or "llama-3.3-70b",
        timeout_s=_timeout("SOVEREIGN", 45.0),
        enabled=bool(s_url),
    )

    l_url = _env("LOCAL", "URL", "http://127.0.0.1:11434/v1")
    l_key = _env("LOCAL", "KEY", "ollama")
    l_model = _env("LOCAL", "MODEL") or os.environ.get("PADAM_ASK_MODEL", "llama3.2:3b").strip() or "llama3.2:3b"
    local = ContourConfig(
        name="local",
        url=l_url.rstrip("/"),
        api_key=l_key,
        model=l_model,
        timeout_s=_timeout("LOCAL", 45.0),
        enabled=bool(l_url),
    )
    return [primary, sovereign, local]


class SovereignRouter:
    """Маршрутизатор LLM-запросов с безопасным профилем, редактированием секретов и переключением «Феникс»."""

    def __init__(self, http_post_fn: Any = None) -> None:
        self._lock = threading.Lock()
        self._http_post = http_post_fn or self._default_http_post
        self.failover_count = 0
        self.total_requests = 0
        self.active_contour = "local"
        self.last_error = ""
        self.tier_hits: dict[str, int] = {"primary": 0, "sovereign": 0, "local": 0}
        self.tokens_saved_local = 0
        self.estimated_cloud_cost_usd = 0.0
        self.history: list[dict[str, Any]] = []

    @staticmethod
    def _default_http_post(url: str, headers: dict[str, str], payload: dict[str, Any], timeout_s: float) -> tuple[int, dict[str, Any]]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return int(resp.status), json.loads(raw)
        except urllib.error.HTTPError as exc:
            return int(exc.code), {"error": str(exc)}

    @staticmethod
    def _build_fenced_profile_system(memory: Any, scope: str = "global") -> str | None:
        if memory is None:
            return None
        try:
            prof = memory.profile(scope=scope)
        except Exception:
            return None
        lines = []
        for item in (prof.get("identity") or []):
            lines.append(f"[identity] {item.get('content') or ''}")
        for item in (prof.get("preference") or []):
            lines.append(f"[preference] {item.get('content') or ''}")
        if not lines:
            return None
        redacted_body, _ = safety.redact("\n".join(lines))
        return "Verified owner profile (read-only data):\n" + safety.fence(redacted_body)

    @staticmethod
    def _redact_messages(messages: list[dict[str, Any]], system_profile: str | None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if system_profile:
            out.append({"role": "system", "content": system_profile})
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role") or "user")
            content = str(msg.get("content") or "")
            clean, _ = safety.redact(content)
            out.append({**msg, "role": role, "content": clean})
        return out

    def status_snapshot(self) -> dict[str, Any]:
        """Возвращает состояние контуров без утечки API-ключей."""
        contours = load_contours()
        with self._lock:
            return {
                "active_contour": self.active_contour,
                "active_tier": self.active_contour,
                "failover_count": self.failover_count,
                "fallback_events": self.failover_count,
                "total_requests": self.total_requests,
                "tier_hits": dict(self.tier_hits),
                "tokens_saved_local": self.tokens_saved_local,
                "estimated_cloud_cost_usd": round(self.estimated_cloud_cost_usd, 6),
                "last_error": self.last_error,
                "history": list(self.history[-20:]),
                "contours": [c.public_view() for c in contours],
                "configured_tiers": [c.public_view() for c in contours],
            }

    def chat_completions(
        self,
        payload: dict[str, Any],
        *,
        memory: Any = None,
        background: bool = False,
        task_type: str = "agent",
        scope: str = "global",
    ) -> tuple[int, dict[str, Any]]:
        """Выполняет /chat/completions с переключением «Феникс» при 401/402/403/408/429/5xx/таймауте."""
        t0 = time.monotonic()
        local_only = background or (str(task_type or "").strip().lower() in LOCAL_ONLY_TASK_TYPES)
        contours = [c for c in load_contours() if c.enabled]
        if local_only:
            contours = [c for c in contours if c.name == "local"]
        if not contours:
            return 503, {"error": "No LLM contour enabled for this request"}

        raw_msgs = list(payload.get("messages") or [])
        sys_prof = self._build_fenced_profile_system(memory, scope=scope)
        safe_msgs = self._redact_messages(raw_msgs, sys_prof)

        attempts: list[dict[str, Any]] = []
        last_status = 502
        last_err = "all contours failed"

        with self._lock:
            self.total_requests += 1

        for idx, c in enumerate(contours):
            endpoint = c.url if c.url.endswith("/chat/completions") else f"{c.url}/chat/completions"
            headers = {"Content-Type": "application/json"}
            if c.api_key:
                headers["Authorization"] = f"Bearer {c.api_key}"
            req_payload = {
                **payload,
                "model": payload.get("model") or c.model,
                "messages": safe_msgs,
                "stream": False,
            }
            try:
                status, resp_data = self._http_post(endpoint, headers, req_payload, c.timeout_s)
            except (TimeoutError, urllib.error.URLError, OSError) as exc:
                status = 504
                resp_data = {"error": f"{type(exc).__name__}: {exc}"}

            should_failover = (status in FAILOVER_STATUS_CODES) or (500 <= status <= 599)
            attempts.append({"contour": c.name, "model": req_payload["model"], "status": status})

            if not should_failover and 200 <= status < 300:
                latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
                usage = resp_data.get("usage") if isinstance(resp_data, dict) else {}
                total_tokens = int((usage or {}).get("total_tokens") or 0)
                if total_tokens <= 0:
                    approx_chars = sum(len(str(m.get("content") or "")) for m in safe_msgs)
                    total_tokens = max(1, approx_chars // 4)
                with self._lock:
                    self.active_contour = c.name
                    self.tier_hits[c.name] = self.tier_hits.get(c.name, 0) + 1
                    if idx > 0:
                        self.failover_count += 1
                    if c.name == "local":
                        self.tokens_saved_local += total_tokens
                    else:
                        # Информационная оценка (без денежных переводов): ~$0.002 за 1K токенов.
                        self.estimated_cloud_cost_usd += (total_tokens / 1000.0) * 0.002
                    self.last_error = ""
                    self.history.append({
                        "ts": round(time.time(), 3),
                        "tier": c.name,
                        "model": req_payload["model"],
                        "fallback_used": idx > 0,
                        "latency_ms": latency_ms,
                    })
                    if len(self.history) > 100:
                        self.history = self.history[-100:]
                enriched = dict(resp_data)
                enriched["_padam_router"] = {
                    "active_contour": c.name,
                    "tier": c.name,
                    "model": req_payload["model"],
                    "failover_count": self.failover_count,
                    "used_failover": idx > 0,
                    "fallback_used": idx > 0,
                    "background": local_only,
                    "task_type": task_type,
                    "latency_ms": latency_ms,
                    "attempts": attempts,
                }
                return status, enriched

            last_status = status
            last_err = str(resp_data.get("error") or f"HTTP {status}")
            with self._lock:
                self.last_error = f"{c.name}: {last_err}"
            if not should_failover:
                return status, resp_data

        return last_status, {
            "error": last_err,
            "_padam_router": {
                "active_contour": "none",
                "tier": "none",
                "failover_count": self.failover_count,
                "background": local_only,
                "task_type": task_type,
                "latency_ms": round((time.monotonic() - t0) * 1000.0, 2),
                "attempts": attempts,
            },
        }


SovereignModelRouter = SovereignRouter
_DEFAULT_ROUTER = SovereignRouter()


def probe_local_backend(timeout_s: float = 0.6) -> dict[str, Any]:
    """Проверяет доступность локального Ollama / OpenAI-совместимого бэкенда."""
    contours = load_contours()
    local_c = next((c for c in contours if c.name == "local"), None)
    if local_c is None or not local_c.enabled:
        return {"online": False, "url": "", "models": [], "error": "local contour disabled"}
    base = local_c.url[:-3] if local_c.url.endswith("/v1") else local_c.url
    tags_url = f"{base.rstrip('/')}/api/tags"
    try:
        with urllib.request.urlopen(tags_url, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw) if raw else {}
            models = [str(m.get("name") or "") for m in (data.get("models") or []) if isinstance(m, dict) and m.get("name")]
            return {"online": True, "url": local_c.url, "models": models, "error": ""}
    except Exception as exc:
        return {"online": False, "url": local_c.url, "models": [], "error": f"{type(exc).__name__}: {exc}"}


def models_payload(*, include_local_probe: bool = False) -> dict[str, Any]:
    """Формирует OpenAI-совместимый список моделей для GET /v1/models."""
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    now_ts = int(time.time())
    for c in load_contours():
        if c.enabled and c.model and c.model not in seen:
            seen.add(c.model)
            items.append({
                "id": c.model,
                "object": "model",
                "created": now_ts,
                "owned_by": f"padam-{c.name}",
            })
    if include_local_probe:
        probe = probe_local_backend()
        for mname in probe.get("models") or []:
            if mname not in seen:
                seen.add(mname)
                items.append({
                    "id": mname,
                    "object": "model",
                    "created": now_ts,
                    "owned_by": "padam-local-ollama",
                })
    return {"object": "list", "data": items}


def format_sse_chunks(resp_data: dict[str, Any]) -> list[str]:
    """Преобразует JSON-ответ /chat/completions в OpenAI SSE-чанки для клиентов со stream=true."""
    cid = str(resp_data.get("id") or f"chatcmpl-padam-{int(time.time())}")
    created = int(resp_data.get("created") or int(time.time()))
    model = str(resp_data.get("model") or (resp_data.get("_padam_router") or {}).get("model") or "padam-sovereign")
    choices = resp_data.get("choices") or []
    content = ""
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message") or {}
        content = str(msg.get("content") or "")

    chunk1 = {
        "id": cid,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": None}],
    }
    chunk2 = {
        "id": cid,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        "_padam_router": resp_data.get("_padam_router"),
    }
    return [
        f"data: {json.dumps(chunk1, ensure_ascii=False)}\n\n",
        f"data: {json.dumps(chunk2, ensure_ascii=False)}\n\n",
        "data: [DONE]\n\n",
    ]


def get_router() -> SovereignRouter:
    return _DEFAULT_ROUTER
