# -*- coding: utf-8 -*-
"""Роутер языковых моделей PADAM с переключением «Феникс» (Primary -> Sovereign -> Local).

По умолчанию настроен ТОЛЬКО локальный контур (Ollama на 127.0.0.1:11434/v1).
Внешние контуры (PADAM_LLM_PRIMARY_*, PADAM_LLM_SOVEREIGN_*) активируются
исключительно при явном задании соответствующих переменных окружения человеком.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
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

    def __init__(self, http_post_fn: Any = None, http_stream_fn: Any = None, *, cooldown_s: float | None = None) -> None:
        self._lock = threading.Lock()
        self._http_post = http_post_fn or self._default_http_post
        self._http_stream = http_stream_fn
        self._cooldown_s = float(os.environ.get("PADAM_ROUTER_COOLDOWN_S", "60.0") or "60.0") if cooldown_s is None else float(cooldown_s)
        self.mode = "auto"  # auto | local_only
        self.failover_count = 0
        self.total_requests = 0
        self.cache_hits = 0
        self.semantic_cache_hits = 0
        self.active_contour = "local"
        self.last_error = ""
        self.tier_hits: dict[str, int] = {"primary": 0, "sovereign": 0, "local": 0}
        self.tokens_saved_local = 0
        self.cloud_tokens_used = 0
        self.estimated_cloud_cost_usd = 0.0
        self.history: list[dict[str, Any]] = []
        self._cooldown_until: dict[str, float] = {}
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._semantic_cache: list[tuple[float, str, set[str], dict[str, Any]]] = []
        self._recent_req_hashes: list[tuple[float, str]] = []

    def set_mode(self, mode: str) -> str:
        norm = str(mode or "").strip().lower()
        if norm not in ("auto", "local_only"):
            raise ValueError(f"Unsupported router mode: {mode}")
        with self._lock:
            self.mode = norm
        return norm

    @staticmethod
    def _trigrams(text: str) -> set[str]:
        s = " ".join(text.lower().split())
        if len(s) < 3:
            return {s} if s else set()
        return {s[i:i + 3] for i in range(len(s) - 2)}

    @classmethod
    def _dice_similarity(cls, a: set[str], b: set[str]) -> float:
        if not a or not b:
            return 0.0
        return (2.0 * len(a & b)) / (len(a) + len(b))

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
    def _build_fenced_profile_system(memory: Any, scope: str = "global", *, max_chars: int = 4000) -> str | None:
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
        if len(redacted_body) > max_chars:
            redacted_body = redacted_body[: max(100, max_chars - 3)] + "..."
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
        now_m = time.monotonic()
        with self._lock:
            breakers = {
                name: max(0.0, round(until - now_m, 2))
                for name, until in self._cooldown_until.items()
                if until > now_m
            }
            return {
                "mode": self.mode,
                "active_contour": self.active_contour,
                "active_tier": self.active_contour,
                "failover_count": self.failover_count,
                "fallback_events": self.failover_count,
                "total_requests": self.total_requests,
                "cache_hits": self.cache_hits,
                "semantic_cache_hits": self.semantic_cache_hits,
                "tier_hits": dict(self.tier_hits),
                "tokens_saved_local": self.tokens_saved_local,
                "cloud_tokens_used": self.cloud_tokens_used,
                "estimated_cloud_cost_usd": round(self.estimated_cloud_cost_usd, 6),
                "circuit_breakers": breakers,
                "last_error": self.last_error,
                "history": list(self.history[-20:]),
                "contours": [c.public_view() for c in contours],
                "configured_tiers": [c.public_view() for c in contours],
            }

    def _budget_exhausted(self) -> bool:
        usd_cap_raw = os.environ.get("PADAM_LLM_DAILY_USD_CAP", "").strip()
        tok_cap_raw = os.environ.get("PADAM_LLM_DAILY_TOKEN_CAP", "").strip()
        with self._lock:
            if usd_cap_raw:
                try:
                    if self.estimated_cloud_cost_usd >= float(usd_cap_raw):
                        return True
                except ValueError:
                    pass
            if tok_cap_raw:
                try:
                    if self.cloud_tokens_used >= int(tok_cap_raw):
                        return True
                except ValueError:
                    pass
        return False

    def chat_completions(
        self,
        payload: dict[str, Any],
        *,
        memory: Any = None,
        background: bool = False,
        task_type: str = "agent",
        scope: str = "global",
    ) -> tuple[int, dict[str, Any]]:
        """Выполняет /chat/completions с переключением «Феникс», Circuit Breaker и Budget Guard."""
        t0 = time.monotonic()
        local_only = (
            background
            or (self.mode == "local_only")
            or (str(task_type or "").strip().lower() in LOCAL_ONLY_TASK_TYPES)
        )
        budget_blocked = self._budget_exhausted()
        contours = [c for c in load_contours() if c.enabled]
        if local_only or budget_blocked:
            contours = [c for c in contours if c.name == "local"]
        if not contours:
            if os.environ.get("PADAM_LLM_CPU_FALLBACK", "0").strip() == "1" or bool(payload.get("allow_cpu_fallback", False)):
                from . import cpu_engine
                return 200, cpu_engine.run_cpu_completion(payload, memory=memory, task_type=task_type, scope=scope)
            return 503, {"error": "No LLM contour enabled for this request"}

        # Circuit breaker: пропускаем контуры в cooldown, если есть хотя бы один живой кандидат
        now_m = time.monotonic()
        with self._lock:
            healthy = [c for c in contours if self._cooldown_until.get(c.name, 0.0) <= now_m]
        if healthy:
            contours = healthy

        raw_msgs = list(payload.get("messages") or [])
        budget_chars = 1200 if (local_only or budget_blocked or (contours and contours[0].name == "local")) else 4000
        sys_prof = self._build_fenced_profile_system(memory, scope=scope, max_chars=budget_chars)
        safe_msgs = self._redact_messages(raw_msgs, sys_prof)

        # Loop & Runaway Guard: отлавливает зацикливание одинаковых запросов за 30с
        loop_limit = int(os.environ.get("PADAM_ROUTER_LOOP_LIMIT", "5") or "5")
        if loop_limit > 0 and not (local_only and float(payload.get("temperature") or 0.0) == 0.0):
            req_h = hashlib.sha256(json.dumps(raw_msgs, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
            with self._lock:
                self._recent_req_hashes = [(ts, h) for ts, h in self._recent_req_hashes if (now_m - ts) < 30.0]
                same_cnt = sum(1 for _, h in self._recent_req_hashes if h == req_h)
                if same_cnt >= loop_limit:
                    return 429, {
                        "error": "Loop guard triggered: identical request repeated",
                        "_padam_router": {"loop_guard_triggered": True, "repeat_count": same_cnt + 1},
                    }
                self._recent_req_hashes.append((now_m, req_h))

        # Лёгкий локальный + семантический кэш для детерминированных фоновых запросов (temperature == 0)
        cache_key = ""
        sem_prompt = ""
        sem_grams: set[str] = set()
        if local_only and float(payload.get("temperature") or 0.0) == 0.0:
            raw_key = json.dumps({"msgs": safe_msgs, "task_type": task_type}, ensure_ascii=False, sort_keys=True)
            cache_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
            sem_prompt = "\n".join(f"{m.get('role')}:{m.get('content')}" for m in safe_msgs)
            sem_grams = self._trigrams(sem_prompt)
            with self._lock:
                cached = self._cache.get(cache_key)
                if cached and (now_m - cached[0]) < 300.0:
                    self.total_requests += 1
                    self.cache_hits += 1
                    hit_data = dict(cached[1])
                    hit_data["_padam_router"] = {
                        **dict(hit_data.get("_padam_router") or {}),
                        "cache_hit": True,
                        "cache_type": "exact",
                        "latency_ms": round((time.monotonic() - t0) * 1000.0, 2),
                    }
                    return 200, hit_data
                for ts_c, c_task, c_grams, c_resp in reversed(self._semantic_cache):
                    if (now_m - ts_c) < 300.0 and c_task == task_type and self._dice_similarity(sem_grams, c_grams) >= 0.85:
                        self.total_requests += 1
                        self.cache_hits += 1
                        self.semantic_cache_hits += 1
                        hit_data = dict(c_resp)
                        hit_data["_padam_router"] = {
                            **dict(hit_data.get("_padam_router") or {}),
                            "cache_hit": True,
                            "cache_type": "semantic",
                            "latency_ms": round((time.monotonic() - t0) * 1000.0, 2),
                        }
                        return 200, hit_data

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
                    self._cooldown_until.pop(c.name, None)
                    self.active_contour = c.name
                    self.tier_hits[c.name] = self.tier_hits.get(c.name, 0) + 1
                    if idx > 0 or budget_blocked:
                        self.failover_count += 1
                    if c.name == "local":
                        self.tokens_saved_local += total_tokens
                    else:
                        self.cloud_tokens_used += total_tokens
                        # Информационная оценка (без денежных переводов): ~$0.002 за 1K токенов.
                        self.estimated_cloud_cost_usd += (total_tokens / 1000.0) * 0.002
                    self.last_error = ""
                    self.history.append({
                        "ts": round(time.time(), 3),
                        "tier": c.name,
                        "model": req_payload["model"],
                        "fallback_used": idx > 0 or budget_blocked,
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
                    "used_failover": idx > 0 or budget_blocked,
                    "fallback_used": idx > 0 or budget_blocked,
                    "budget_guard_triggered": budget_blocked,
                    "cache_hit": False,
                    "background": local_only,
                    "task_type": task_type,
                    "latency_ms": latency_ms,
                    "attempts": attempts,
                }
                if cache_key:
                    with self._lock:
                        if len(self._cache) >= 128:
                            self._cache.pop(next(iter(self._cache)))
                        self._cache[cache_key] = (time.monotonic(), enriched)
                        if sem_grams:
                            if len(self._semantic_cache) >= 128:
                                self._semantic_cache.pop(0)
                            self._semantic_cache.append((time.monotonic(), task_type, sem_grams, enriched))
                return status, enriched

            last_status = status
            last_err = str(resp_data.get("error") or f"HTTP {status}")
            with self._lock:
                self.last_error = f"{c.name}: {last_err}"
                if should_failover and self._cooldown_s > 0:
                    self._cooldown_until[c.name] = time.monotonic() + self._cooldown_s
            if not should_failover:
                return status, resp_data

        if os.environ.get("PADAM_LLM_CPU_FALLBACK", "0").strip() == "1" or bool(payload.get("allow_cpu_fallback", False)):
            from . import cpu_engine
            return 200, cpu_engine.run_cpu_completion(payload, memory=memory, task_type=task_type, scope=scope)
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

    @staticmethod
    def _default_http_stream(url: str, headers: dict[str, str], payload: dict[str, Any], timeout_s: float):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            for raw_line in resp:
                yield raw_line.decode("utf-8", errors="replace")

    def stream_chat_completions(
        self,
        payload: dict[str, Any],
        *,
        memory: Any = None,
        background: bool = False,
        task_type: str = "agent",
        scope: str = "global",
    ):
        """Сквозной потоковый SSE-стриминг с переключением «Феникс» до первого чанка."""
        if self._http_stream is None and self._http_post != self._default_http_post:
            st, resp_data = self.chat_completions(payload, memory=memory, background=background, task_type=task_type, scope=scope)
            if not (200 <= st < 300):
                yield f"data: {json.dumps(resp_data, ensure_ascii=False)}\n\n"
                yield "data: [DONE]\n\n"
                return
            for chunk in format_sse_chunks(resp_data):
                yield chunk
            return

        stream_fn = self._http_stream or self._default_http_stream
        local_only = background or (self.mode == "local_only") or (str(task_type or "").strip().lower() in LOCAL_ONLY_TASK_TYPES)
        contours = [c for c in load_contours() if c.enabled]
        if local_only or self._budget_exhausted():
            contours = [c for c in contours if c.name == "local"]

        sys_prof = self._build_fenced_profile_system(memory, scope=scope)
        safe_msgs = self._redact_messages(list(payload.get("messages") or []), sys_prof)

        for idx, c in enumerate(contours):
            endpoint = c.url if c.url.endswith("/chat/completions") else f"{c.url}/chat/completions"
            headers = {"Content-Type": "application/json"}
            if c.api_key:
                headers["Authorization"] = f"Bearer {c.api_key}"
            req_payload = {**payload, "model": payload.get("model") or c.model, "messages": safe_msgs, "stream": True}
            emitted_any = False
            try:
                for line in stream_fn(endpoint, headers, req_payload, c.timeout_s):
                    s = line.rstrip("\r\n")
                    if not s:
                        continue
                    emitted_any = True
                    yield s + "\n\n"
                if emitted_any:
                    with self._lock:
                        self.total_requests += 1
                        self.active_contour = c.name
                        self.tier_hits[c.name] = self.tier_hits.get(c.name, 0) + 1
                        if idx > 0:
                            self.failover_count += 1
                    return
            except Exception as exc:
                if emitted_any:
                    yield f"data: {json.dumps({'error': str(exc)})}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                with self._lock:
                    self.last_error = f"{c.name}: {exc}"
                continue

        yield f"data: {json.dumps({'error': 'All streaming contours failed'})}\n\n"
        yield "data: [DONE]\n\n"


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


def recommend_local_model() -> dict[str, Any]:
    """Подбирает оптимальную локальную модель Ollama по доступной VRAM и проверяет установленные."""
    probe = probe_local_backend(timeout_s=0.6)
    free_mib = 0
    gpu_name = None
    smi = shutil.which("nvidia-smi")
    if smi:
        try:
            out = subprocess.check_output(
                [smi, "--query-gpu=name,memory.free", "--format=csv,noheader,nounits"],
                text=True, encoding="utf-8", errors="replace",
                timeout=3,
            ).strip()
            if out:
                parts = out.splitlines()[0].split(",")
                gpu_name = parts[0].strip()
                free_mib = int(float(parts[1].strip()))
        except Exception:
            pass
    if free_mib >= 16000:
        recommended = "qwen2.5-coder:14b"
    elif free_mib >= 8000:
        recommended = "qwen2.5-coder:7b"
    elif free_mib >= 3500:
        recommended = "qwen2.5-coder:3b"
    else:
        recommended = "llama3.2:1b"
    installed = list(probe.get("models") or [])
    return {
        "ollama_online": bool(probe.get("online")),
        "installed_models": installed,
        "gpu_name": gpu_name,
        "free_vram_mib": free_mib,
        "recommended_model": installed[0] if installed else recommended,
        "pull_command": f"ollama pull {recommended}",
    }


def warmup_local_model(*, timeout_s: float = 5.0) -> dict[str, Any]:
    """Безопасный прогрев уже установленной локальной модели Ollama (ничего не скачивает)."""
    rec = recommend_local_model()
    if not rec["ollama_online"]:
        return {"ok": False, "reason": "ollama_offline", **rec}
    installed = rec["installed_models"]
    if not installed:
        return {"ok": False, "reason": "no_models_installed", **rec}
    target = installed[0]
    local_c = next((c for c in load_contours() if c.name == "local"), None)
    base = (local_c.url[:-3] if local_c and local_c.url.endswith("/v1") else (local_c.url if local_c else "http://127.0.0.1:11434")).rstrip("/")
    gen_url = f"{base}/api/generate"
    body = json.dumps({"model": target, "prompt": "", "keep_alive": "10m"}).encode("utf-8")
    req = urllib.request.Request(gen_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return {"ok": 200 <= int(resp.status) < 300, "model": target, "keep_alive": "10m"}
    except Exception as exc:
        return {"ok": False, "model": target, "reason": f"{type(exc).__name__}: {exc}"}


def get_router() -> SovereignRouter:
    return _DEFAULT_ROUTER
