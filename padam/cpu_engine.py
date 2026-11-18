# -*- coding: utf-8 -*-
"""Встроенный процессорный движок мышления и памяти (Zero-Install Offline AI Engine).

Работает 100% оффлайн без интернета на любом оборудовании (CPU / малая RAM / GPU):
1. Если установлен `llama_cpp` и указан квантованный `.gguf` файл (`PADAM_CPU_GGUF_PATH`),
   выполняет реальный локальный нейросетевой инференс квантованной модели (Q2_K..Q8_0)
   с подстановкой проверенного контекста из памяти PADAM.
2. Если GGUF не задан (или `llama_cpp` не установлен), включает встроенный оффлайн-синтезатор
   `cpu-extractive-v2`: извлекает профиль владельца, релевантные факты (BM25 + локальные векторы),
   связи графа, активные обещания Ковчега и уроки саморефлексии (`ark_lesson`).
"""
from __future__ import annotations

import importlib.util
import os
import platform
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any

from . import classify, safety

_GGUF_LOCK = threading.Lock()
_GGUF_CACHE: dict[str, Any] = {"path": "", "llm": None}


def _has_llama_cpp() -> bool:
    if "llama_cpp" in sys.modules:
        return True
    try:
        return importlib.util.find_spec("llama_cpp") is not None
    except ValueError:
        return False


def _detect_system_ram_gb() -> float:
    """Аккуратно оценивает объём RAM без обязательных сторонних библиотек."""
    try:
        if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names and "SC_PHYS_PAGES" in os.sysconf_names:
            pages = os.sysconf("SC_PHYS_PAGES")
            psize = os.sysconf("SC_PAGE_SIZE")
            if pages > 0 and psize > 0:
                return round((pages * psize) / (1024 ** 3), 2)
    except Exception:
        pass
    if os.name == "nt":
        try:
            import ctypes

            class _MemStat(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = _MemStat()
            stat.dwLength = ctypes.sizeof(_MemStat)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return round(stat.ullTotalPhys / (1024 ** 3), 2)
        except Exception:
            pass
    return 8.0


def recommend_quantized_profile(
    *,
    ram_gb: float | None = None,
    cpu_cores: int | None = None,
    has_gpu: bool = False,
) -> dict[str, Any]:
    """Подбирает оптимальную квантованную GGUF-модель и параметры под железо пользователя."""
    ram = float(ram_gb if ram_gb is not None else _detect_system_ram_gb())
    cores = int(cpu_cores if cpu_cores is not None else (os.cpu_count() or 2))

    if ram < 3.5:
        tier = "ultra_light_mobile"
        model_size = "0.5B–1.5B (Qwen2.5-1.5B / Llama-3.2-1B)"
        quant = "Q4_K_M"
        ctx = 2048
    elif ram < 7.5:
        tier = "laptop_4gb_6gb"
        model_size = "3B (Llama-3.2-3B / Qwen2.5-3B)"
        quant = "Q4_K_M"
        ctx = 4096
    elif ram < 15.0:
        tier = "workstation_8gb_12gb"
        model_size = "7B–8B (Qwen2.5-7B / Llama-3.1-8B)"
        quant = "Q4_K_M" if not has_gpu else "Q5_K_M"
        ctx = 8192
    elif ram < 31.0:
        tier = "pro_16gb_24gb"
        model_size = "14B (Qwen2.5-14B / DeepSeek-R1-Distill-14B)"
        quant = "Q5_K_M"
        ctx = 16384
    else:
        tier = "server_32gb_plus"
        model_size = "32B–70B (Qwen2.5-32B / Llama-3.3-70B)"
        quant = "Q4_K_M" if ram < 48 else "Q6_K"
        ctx = 16384

    return {
        "tier": tier,
        "system_ram_gb": ram,
        "cpu_cores": cores,
        "threads_recommended": max(1, min(cores, cores - 1 if cores > 2 else cores)),
        "recommended_model": model_size,
        "recommended_quant": quant,
        "context_window": ctx,
        "arch": platform.machine() or "unknown",
    }


def cpu_engine_status() -> dict[str, Any]:
    has_llama_cpp = _has_llama_cpp()
    gguf_path = os.environ.get("PADAM_CPU_GGUF_PATH", "").strip()
    gguf_exists = bool(gguf_path and Path(gguf_path).is_file())
    hw = recommend_quantized_profile()
    return {
        "available": True,
        "offline_only": True,
        "cpu_cores": hw["cpu_cores"],
        "system_ram_gb": hw["system_ram_gb"],
        "mode": "llama_cpp_gguf" if (has_llama_cpp and gguf_exists) else "cpu_extractive_builtin",
        "llama_cpp_installed": has_llama_cpp,
        "gguf_configured": gguf_exists,
        "recommended_quant_profile": hw,
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


def _gather_offline_context(memory: Any, clean_q: str, scope: str) -> list[str]:
    """Собирает богатый локальный контекст из SQLite + графа + уроков + обязательств без сети."""
    parts: list[str] = []
    if memory is None:
        return parts
    try:
        prof = memory.profile(scope=scope)
        id_items = [str(x.get("content") or "") for x in (prof.get("identity") or []) if x.get("content")]
        pref_items = [str(x.get("content") or "") for x in (prof.get("preferences") or prof.get("preference") or []) if x.get("content")]
        if id_items and any(w in clean_q.lower() for w in ("who", "architect", "creator", "owner", "кто", "архитектор", "создатель", "папа", "семья", "family")):
            parts.append("Profile identity: " + "; ".join(id_items))
        if pref_items and any(w in clean_q.lower() for w in ("prefer", "style", "предпочт", "стиль", "правил", "как")):
            parts.append("Preferences: " + "; ".join(pref_items))

        query_toks = " ".join(re.findall(r"[a-zA-Zа-яА-ЯёЁ0-9_]{3,}", clean_q)[:8]) or clean_q
        if query_toks:
            hits = memory.recall(query_toks, scope=scope, limit=6)
            hit_lines = []
            for h in hits:
                c = str(h.get("content") if isinstance(h, dict) else getattr(h, "content", "") or "").strip()
                if c:
                    hit_lines.append(f"- {safety.redact(c)[0]}")
            if hit_lines:
                parts.append("Verified memory records:\n" + "\n".join(hit_lines))

        conn = getattr(getattr(memory, "store", None), "conn", None)
        if conn is not None:
            try:
                rows_com = conn.execute(
                    "SELECT title, status FROM ark_commitment WHERE status = 'open' ORDER BY created_at DESC LIMIT 3"
                ).fetchall()
                if rows_com:
                    parts.append("Open commitments: " + "; ".join(f"{r['title']} ({r['status']})" for r in rows_com))
            except Exception:
                pass
            try:
                rows_les = conn.execute(
                    "SELECT rule_learned FROM ark_lesson ORDER BY created_at DESC LIMIT 3"
                ).fetchall()
                if rows_les:
                    parts.append("Learned lessons: " + "; ".join(safety.redact(str(r["rule_learned"]))[0] for r in rows_les))
            except Exception:
                pass
    except Exception:
        pass
    return parts


def _run_gguf_if_configured(
    clean_q: str,
    context_blocks: list[str],
    payload: dict[str, Any],
) -> str | None:
    """Запускает реальную квантованную GGUF-модель через llama_cpp, если библиотека и файл настроены."""
    gguf_path = os.environ.get("PADAM_CPU_GGUF_PATH", "").strip()
    if not gguf_path or not Path(gguf_path).is_file():
        return None
    if not _has_llama_cpp():
        return None
    try:
        import llama_cpp  # type: ignore

        hw = recommend_quantized_profile()
        with _GGUF_LOCK:
            if _GGUF_CACHE.get("path") != gguf_path or _GGUF_CACHE.get("llm") is None:
                _GGUF_CACHE["llm"] = llama_cpp.Llama(
                    model_path=gguf_path,
                    n_ctx=int(os.environ.get("PADAM_CPU_GGUF_CTX", hw["context_window"])),
                    n_threads=int(os.environ.get("PADAM_CPU_GGUF_THREADS", hw["threads_recommended"])),
                    verbose=False,
                )
                _GGUF_CACHE["path"] = gguf_path
            llm = _GGUF_CACHE["llm"]

        sys_ctx = "Offline sovereign assistant. Use verified memory only.\n" + ("\n".join(context_blocks) if context_blocks else "")
        prompt_msgs = [
            {"role": "system", "content": sys_ctx[:4000]},
            {"role": "user", "content": clean_q[:3000]},
        ]
        max_tok = int(payload.get("max_tokens") or 384)
        temp = float(payload.get("temperature") or 0.2)
        if hasattr(llm, "create_chat_completion"):
            res = llm.create_chat_completion(messages=prompt_msgs, max_tokens=max_tok, temperature=temp)
            txt = str((((res or {}).get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
        else:
            raw_p = f"System: {sys_ctx[:2000]}\nUser: {clean_q[:2000]}\nAssistant:"
            res = llm(raw_p, max_tokens=max_tok, temperature=temp)
            txt = str((((res or {}).get("choices") or [{}])[0]).get("text") or "").strip()
        if txt:
            return safety.redact(txt)[0]
    except Exception:
        return None
    return None


def run_cpu_completion(
    payload: dict[str, Any],
    *,
    memory: Any = None,
    task_type: str = "agent",
    scope: str = "global",
) -> dict[str, Any]:
    """Выполняет запрос `/v1/chat/completions` полностью оффлайн (квантованный GGUF на CPU или встроенный синтез)."""
    t0 = time.monotonic()
    messages = list(payload.get("messages") or [])
    user_msg = ""
    for m in reversed(messages):
        if isinstance(m, dict) and str(m.get("role") or "") == "user":
            user_msg = str(m.get("content") or "").strip()
            break

    clean_q, _ = safety.redact(user_msg)
    used_mode = "cpu_builtin"

    if str(task_type or "").lower() in ("sleep", "classify"):
        ans_text = _classify_for_sleep(clean_q)
    else:
        parts = _gather_offline_context(memory, clean_q, scope)
        gguf_ans = _run_gguf_if_configured(clean_q, parts, payload)
        if gguf_ans:
            ans_text = gguf_ans
            used_mode = "llama_cpp_gguf"
        else:
            if not parts:
                parts.append("Offline CPU mode active: no matching records found in local memory for this query.")
            ans_text = "\n".join(parts)

    latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
    approx_tokens = max(1, (len(clean_q) + len(ans_text)) // 4)
    return {
        "id": f"chatcmpl-cpu-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "padam-gguf-cpu-v1" if used_mode == "llama_cpp_gguf" else "padam-cpu-builtin-v2",
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
            "active_contour": used_mode,
            "tier": used_mode,
            "model": "padam-gguf-cpu-v1" if used_mode == "llama_cpp_gguf" else "padam-cpu-builtin-v2",
            "used_failover": True,
            "fallback_used": True,
            "offline_cpu": True,
            "task_type": task_type,
            "latency_ms": latency_ms,
        },
    }
