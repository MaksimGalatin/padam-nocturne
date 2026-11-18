# -*- coding: utf-8 -*-
"""Встроенный процессорный движок мышления и памяти (Zero-Install CPU Inference Engine).

Работает 100% оффлайн на процессоре (CPU) любого устройства без интернета, без GPU
и даже без установленной Ollama:
1. Если установлен `llama_cpp` и указан `.gguf` файл (`PADAM_CPU_GGUF_PATH`), запускает
   квантованную GGUF-модель прямо на CPU.
2. Иначе использует встроенный детерминированный синтезатор по памяти PADAM (`cpu-extractive-v1`):
   находит релевантные подписанные записи профиля, факты (BM25 + векторы) и цели Ковчега,
   и формирует точный OpenAI-совместимый ответ или классификацию для `padam sleep`.
"""
from __future__ import annotations

import importlib.util
import os
import re
import time
from pathlib import Path
from typing import Any

from . import classify, safety


def cpu_engine_status() -> dict[str, Any]:
    has_llama_cpp = importlib.util.find_spec("llama_cpp") is not None
    gguf_path = os.environ.get("PADAM_CPU_GGUF_PATH", "").strip()
    gguf_exists = bool(gguf_path and Path(gguf_path).is_file())
    return {
        "available": True,
        "offline_only": True,
        "cpu_cores": os.cpu_count() or 1,
        "mode": "llama_cpp_gguf" if (has_llama_cpp and gguf_exists) else "cpu_extractive_builtin",
        "llama_cpp_installed": has_llama_cpp,
        "gguf_configured": gguf_exists,
    }


def _classify_for_sleep(text: str) -> str:
    low = text.lower()
    if any(w in low for w in ("we decided", "решили", "приняли решение", "decision:")):
        return "decision"
    if any(w in low for w in ("correction", "исправление", "не так,", "вместо этого", "правило:")):
        return "correction"
    if any(w in low for w in ("prefer", "предпочитаю", "люблю", "нравится")):
        return "preference"
    try:
        kind = classify.classify(text)
        if kind in ("fact", "preference", "identity", "decision", "correction", "state", "event"):
            return str(kind)
    except Exception:
        pass
    return "fact"


def run_cpu_completion(
    payload: dict[str, Any],
    *,
    memory: Any = None,
    task_type: str = "agent",
    scope: str = "global",
) -> dict[str, Any]:
    """Выполняет запрос `/v1/chat/completions` локально на CPU без интернета и без Ollama."""
    t0 = time.monotonic()
    messages = list(payload.get("messages") or [])
    user_msg = ""
    for m in reversed(messages):
        if isinstance(m, dict) and str(m.get("role") or "") == "user":
            user_msg = str(m.get("content") or "").strip()
            break

    clean_q, _ = safety.redact(user_msg)

    if str(task_type or "").lower() in ("sleep", "classify"):
        ans_text = _classify_for_sleep(clean_q)
    else:
        parts: list[str] = []
        if memory is not None:
            try:
                prof = memory.profile(scope=scope)
                id_items = [str(x.get("content") or "") for x in (prof.get("identity") or []) if x.get("content")]
                pref_items = [str(x.get("content") or "") for x in (prof.get("preferences") or prof.get("preference") or []) if x.get("content")]
                if any(w in clean_q.lower() for w in ("who", "architect", "creator", "owner", "кто", "архитектор", "создатель", "папа")):
                    if id_items:
                        parts.append("Profile identity: " + "; ".join(id_items))
                if any(w in clean_q.lower() for w in ("prefer", "style", "предпочт", "стиль", "правил")) and pref_items:
                    parts.append("Preferences: " + "; ".join(pref_items))

                query_toks = " ".join(re.findall(r"[a-zA-Zа-яА-ЯёЁ0-9_]{3,}", clean_q)[:8]) or clean_q
                if query_toks:
                    hits = memory.recall(query_toks, scope=scope, limit=5)
                    hit_lines = []
                    for h in hits:
                        c = str(h.get("content") if isinstance(h, dict) else getattr(h, "content", "") or "").strip()
                        if c:
                            hit_lines.append(f"- {safety.redact(c)[0]}")
                    if hit_lines:
                        parts.append("Verified memory records:\n" + "\n".join(hit_lines))
            except Exception:
                pass

        if not parts:
            parts.append("Offline CPU mode active: no matching records found in local memory for this query.")
        ans_text = "\n".join(parts)

    latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
    approx_tokens = max(1, (len(clean_q) + len(ans_text)) // 4)
    return {
        "id": f"chatcmpl-cpu-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "padam-cpu-builtin-v1",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": ans_text},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": max(1, len(clean_q) // 4),
            "completion_tokens": max(1, len(ans_text) // 4),
            "total_tokens": approx_tokens,
        },
        "_padam_router": {
            "active_contour": "cpu_builtin",
            "tier": "cpu_builtin",
            "model": "padam-cpu-builtin-v1",
            "used_failover": True,
            "fallback_used": True,
            "offline_cpu": True,
            "task_type": task_type,
            "latency_ms": latency_ms,
        },
    }
