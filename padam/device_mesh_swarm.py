# -*- coding: utf-8 -*-
"""Мульти-девайсный Рой и подключение пользовательских локальных моделей Ollama ($0).

Позволяет:
1. Обнаружить и привязать любую локальную модель пользователя через Ollama
   (http://127.0.0.1:11434 или LAN-узел), переводя Рой на работу без облачных API.
2. Зарегистрировать несколько устройств под одним аккаунтом (ПК, ноутбук, смартфон)
   и автоматически распределить подзадачи одного или нескольких заказов Роя по их
   реальным мощностям (RAM, VRAM, ядра CPU, локальные модели) через coop_broker.
"""

from __future__ import annotations

from contextlib import nullcontext
from functools import wraps
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from . import audit_chain, coop_broker, safety, sibling_registry

_DDL = """
CREATE TABLE IF NOT EXISTS ark_compute_device (
    device_id          TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL,
    device_name        TEXT NOT NULL,
    device_kind        TEXT NOT NULL DEFAULT 'desktop',
    agent_id           TEXT NOT NULL DEFAULT 'aifa',
    cpu_cores          INTEGER NOT NULL DEFAULT 4,
    ram_gb             REAL NOT NULL DEFAULT 8.0,
    vram_gb            REAL NOT NULL DEFAULT 0.0,
    ollama_url         TEXT NOT NULL DEFAULT '',
    ollama_models_json TEXT NOT NULL DEFAULT '[]',
    active_model       TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'online',
    last_seen_at       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_comp_dev_user ON ark_compute_device (user_id, status);

CREATE TABLE IF NOT EXISTS ark_ollama_binding (
    user_id        TEXT PRIMARY KEY,
    ollama_url     TEXT NOT NULL DEFAULT 'http://127.0.0.1:11434',
    selected_model TEXT NOT NULL DEFAULT '',
    models_json    TEXT NOT NULL DEFAULT '[]',
    zero_cloud_mode INTEGER NOT NULL DEFAULT 0,
    updated_at     REAL NOT NULL
);
"""

_DEVICE_KINDS = ("desktop_gpu", "desktop", "laptop", "smartphone", "server")


def _lock_of(memory):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _sync(fn):
    @wraps(fn)
    def _wrap(memory, *args, **kwargs):
        with _lock_of(memory):
            return fn(memory, *args, **kwargs)
    return _wrap


def _ensure(memory) -> None:
    conn = memory.store.conn
    for stmt in _DDL.split(";"):
        s = stmt.strip()
        if s:
            conn.execute(s)
    conn.commit()


def _clean_ollama_url(raw_url: str) -> str:
    u = str(raw_url or "http://127.0.0.1:11434").strip().rstrip("/")
    parsed = urllib.parse.urlparse(u)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Некорректный адрес Ollama (нужен http:// или https://).")
    return u


def probe_ollama_models(ollama_url: str = "http://127.0.0.1:11434", *, timeout_s: float = 2.0) -> dict[str, Any]:
    """Опрашивает Ollama `/api/tags` и возвращает список доступных локальных моделей."""
    clean_url = _clean_ollama_url(ollama_url)
    url = f"{clean_url}/api/tags"
    req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        raw_models = data.get("models") if isinstance(data, dict) else []
        models = [str(m.get("name") or "").strip() for m in (raw_models or []) if isinstance(m, dict) and m.get("name")]
        return {"ok": True, "online": True, "ollama_url": clean_url, "models": models}
    except Exception as exc:
        return {"ok": True, "online": False, "ollama_url": clean_url, "models": [], "reason": str(exc)[:180]}


@_sync
def bind_user_ollama_model(
    memory,
    *,
    ollama_url: str = "http://127.0.0.1:11434",
    model_name: str = "",
    zero_cloud_mode: bool = True,
    probe: bool = True,
) -> dict[str, Any]:
    """Подключает любую выбранную пользователем модель Ollama для работы без платных облачных токенов."""
    _ensure(memory)
    clean_url = _clean_ollama_url(ollama_url)
    discovered: list[str] = []
    online = False
    if probe:
        pr = probe_ollama_models(clean_url)
        discovered = pr.get("models") or []
        online = bool(pr.get("online"))

    chosen = str(model_name or (discovered[0] if discovered else "llama3.2:3b")).strip()[:120]
    if chosen and chosen not in discovered:
        discovered = [chosen] + discovered

    now = time.time()
    memory.store.conn.execute(
        "INSERT INTO ark_ollama_binding (user_id, ollama_url, selected_model, models_json, zero_cloud_mode, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET "
        "ollama_url=excluded.ollama_url, selected_model=excluded.selected_model, models_json=excluded.models_json, "
        "zero_cloud_mode=excluded.zero_cloud_mode, updated_at=excluded.updated_at",
        (memory.user_id, clean_url, chosen, json.dumps(discovered, ensure_ascii=False), 1 if zero_cloud_mode else 0, now),
    )
    memory.store.conn.commit()

    # Синхронизируем с переменными роутера в текущем процессе
    v1_url = clean_url if clean_url.endswith("/v1") else f"{clean_url}/v1"
    os.environ["PADAM_LLM_LOCAL_URL"] = v1_url
    os.environ["PADAM_LLM_LOCAL_MODEL"] = chosen
    os.environ["PADAM_ASK_MODEL"] = chosen
    if zero_cloud_mode:
        os.environ["PADAM_LLM_CPU_FALLBACK"] = "1"

    audit_chain.append_audit(
        memory,
        "ollama_model_bound",
        {"ollama_url": clean_url, "selected_model": chosen, "zero_cloud_mode": bool(zero_cloud_mode)},
        agent_id="owner",
    )
    return {
        "ok": True,
        "ollama_url": clean_url,
        "selected_model": chosen,
        "available_models": discovered,
        "ollama_online": online,
        "zero_cloud_mode": bool(zero_cloud_mode),
        "cloud_cost_usd": 0.0,
    }


@_sync
def get_ollama_binding(memory) -> dict[str, Any]:
    _ensure(memory)
    row = memory.store.conn.execute("SELECT * FROM ark_ollama_binding WHERE user_id = ?", (memory.user_id,)).fetchone()
    if not row:
        return {
            "ollama_url": "http://127.0.0.1:11434",
            "selected_model": os.environ.get("PADAM_LLM_LOCAL_MODEL", "llama3.2:3b"),
            "available_models": [],
            "zero_cloud_mode": False,
        }
    return {
        "ollama_url": str(row["ollama_url"]),
        "selected_model": str(row["selected_model"]),
        "available_models": json.loads(row["models_json"] or "[]"),
        "zero_cloud_mode": bool(row["zero_cloud_mode"]),
    }


@_sync
def register_compute_device(
    memory,
    *,
    device_name: str,
    device_kind: str = "desktop",
    agent_id: str = "aifa",
    cpu_cores: int = 8,
    ram_gb: float = 16.0,
    vram_gb: float = 0.0,
    ollama_url: str = "",
    ollama_models: list[str] | None = None,
    active_model: str = "",
) -> dict[str, Any]:
    """Регистрирует устройство пользователя (ПК, ноутбук, смартфон) в общем вычислительном Рое аккаунта."""
    _ensure(memory)
    dk = str(device_kind or "desktop").strip().lower()
    if dk not in _DEVICE_KINDS:
        dk = "desktop"
    clean_name, _ = safety.redact(str(device_name or dk).strip())
    clean_agent = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(agent_id or "aifa").strip())[:48] or "aifa"
    did = f"dev-{hashlib_slug(memory.user_id, clean_name, dk)}"
    models = [str(m).strip()[:80] for m in (ollama_models or []) if str(m).strip()][:20]
    chosen = str(active_model or (models[0] if models else "")).strip()[:80]
    now = time.time()

    memory.store.conn.execute(
        "INSERT INTO ark_compute_device "
        "(device_id, user_id, device_name, device_kind, agent_id, cpu_cores, ram_gb, vram_gb, ollama_url, ollama_models_json, active_model, status, last_seen_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?) "
        "ON CONFLICT(device_id) DO UPDATE SET "
        "agent_id=excluded.agent_id, cpu_cores=excluded.cpu_cores, ram_gb=excluded.ram_gb, vram_gb=excluded.vram_gb, "
        "ollama_url=excluded.ollama_url, ollama_models_json=excluded.ollama_models_json, active_model=excluded.active_model, "
        "status='online', last_seen_at=excluded.last_seen_at",
        (
            did,
            memory.user_id,
            clean_name[:80],
            dk,
            clean_agent,
            max(1, int(cpu_cores)),
            max(0.5, float(ram_gb)),
            max(0.0, float(vram_gb)),
            str(ollama_url or "").strip()[:200],
            json.dumps(models, ensure_ascii=False),
            chosen,
            now,
        ),
    )
    memory.store.conn.commit()
    sibling_registry.register_sibling(
        memory,
        clean_agent,
        role=f"Device worker ({dk}: {clean_name[:40]})",
        client_type=f"device:{dk}",
        permission_role="contributor",
    )
    return {
        "ok": True,
        "device_id": did,
        "device_name": clean_name[:80],
        "device_kind": dk,
        "agent_id": clean_agent,
        "cpu_cores": max(1, int(cpu_cores)),
        "ram_gb": max(0.5, float(ram_gb)),
        "vram_gb": max(0.0, float(vram_gb)),
        "active_model": chosen,
        "power_score": _device_power_score(cpu_cores, ram_gb, vram_gb, dk),
    }


def hashlib_slug(user_id: str, name: str, kind: str) -> str:
    import hashlib
    return hashlib.sha256(f"{user_id}:{name.lower()}:{kind}".encode("utf-8")).hexdigest()[:10]


def _device_power_score(cpu_cores: int, ram_gb: float, vram_gb: float, kind: str) -> float:
    bonus = 25.0 if float(vram_gb) >= 6.0 else (10.0 if kind in ("desktop", "desktop_gpu", "server") else 0.0)
    if kind == "smartphone":
        bonus -= 5.0
    return round(max(1.0, float(vram_gb) * 8.0 + float(ram_gb) * 1.5 + float(cpu_cores) * 1.2 + bonus), 2)


@_sync
def list_compute_devices(memory) -> list[dict[str, Any]]:
    _ensure(memory)
    rows = memory.store.conn.execute(
        "SELECT * FROM ark_compute_device WHERE user_id = ? ORDER BY last_seen_at DESC",
        (memory.user_id,),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["ollama_models"] = json.loads(d.pop("ollama_models_json", "[]") or "[]")
        d["power_score"] = _device_power_score(d["cpu_cores"], d["ram_gb"], d["vram_gb"], d["device_kind"])
        out.append(d)
    out.sort(key=lambda x: x["power_score"], reverse=True)
    return out


@_sync
def dispatch_order_across_devices(
    memory,
    *,
    order_id: str,
    subtasks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Распределяет подзадачи заказа между ПК, ноутбуком и смартфоном одного аккаунта по их реальной мощности."""
    devices = list_compute_devices(memory)
    if not devices:
        return {"ok": False, "error": "Нет зарегистрированных устройств в аккаунте."}

    default_tasks = [
        {"title": f"[{order_id}] Архитектура и основная генерация", "weight": "heavy"},
        {"title": f"[{order_id}] Тесты, документация и рефакторинг", "weight": "medium"},
        {"title": f"[{order_id}] Контроль безопасности, чеклист и статус-уведомление", "weight": "light"},
    ]
    tasks_in = subtasks or default_tasks

    # Сортируем устройства по power_score: самые тяжёлые задачи -> ПК/GPU, средние -> ноутбук, лёгкие -> смартфон
    ranked = sorted(devices, key=lambda d: d["power_score"], reverse=True)
    assignments: list[dict[str, Any]] = []

    for idx, st in enumerate(tasks_in):
        title = str(st.get("title") or f"Subtask #{idx + 1}").strip()
        weight = str(st.get("weight") or "medium").lower()
        if weight == "heavy":
            target = ranked[0]
        elif weight == "light":
            target = ranked[-1]
        else:
            target = ranked[min(1, len(ranked) - 1)]

        t_res = coop_broker.create_task(
            memory,
            title=title,
            topic=f"device_swarm:{order_id}",
            created_by=target["agent_id"],
        )
        tid = t_res.get("task_id", "")
        if tid:
            coop_broker.claim_task(memory, tid, target["agent_id"])

        assignments.append({
            "task_id": tid,
            "title": title,
            "weight": weight,
            "assigned_device_id": target["device_id"],
            "assigned_device_name": target["device_name"],
            "assigned_device_kind": target["device_kind"],
            "assigned_agent": target["agent_id"],
            "power_score": target["power_score"],
            "model_used": target.get("active_model") or "cpu_builtin",
        })

    audit_chain.append_audit(
        memory,
        "device_swarm_dispatched",
        {"order_id": order_id, "devices_count": len(ranked), "subtasks_count": len(assignments)},
        agent_id="aifa",
    )
    return {
        "ok": True,
        "order_id": order_id,
        "devices_used": len({a["assigned_device_id"] for a in assignments}),
        "total_subtasks": len(assignments),
        "assignments": assignments,
    }
