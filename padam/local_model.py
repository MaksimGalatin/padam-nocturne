# -*- coding: utf-8 -*-
"""Настройки локальной модели: мощность, файл GGUF, найденные модели Ollama (18.11.2026).

Слово Архитектора 18.11.2026: «тяжёлые модели в пол мощности у нас, а в приложении и МСР — подумай как это также
оптимизировать в настройках для пользователей, чтобы они могли всё включить и настроить в пару кликов».

Почему отдельный файл, а не переменные окружения: человек в Studio нажимает кнопку, и выбор должен пережить
перезапуск. Переменные окружения (PADAM_CPU_POWER, PADAM_CPU_GGUF_PATH, PADAM_CPU_GGUF_THREADS) по-прежнему
сильнее файла — так их могут задать опытные пользователи и клиенты MCP.

Мощность:
- eco  — четверть ядер, модель на две ступени меньше: тихо и прохладно;
- half — половина ядер, модель на ступень меньше (по умолчанию): компьютер остаётся отзывчивым;
- full — все ядра минус одно, полная модель: только по явному выбору человека.

Расход: $0. Модель работает на процессоре этого компьютера, ничего не отправляется наружу. Скачивание модели —
отдельное действие человека (файл GGUF или `ollama pull`); этот модуль ничего не скачивает.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

POWER_MODES = ("eco", "half", "full")
DEFAULT_POWER = "half"
_RAM_SHARE = {"eco": 0.25, "half": 0.5, "full": 1.0}


def settings_path() -> Path:
    base = Path(os.environ.get("PADAM_HOME") or (Path.home() / ".padam"))
    return base / "local_model.json"


def load() -> dict[str, Any]:
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    power = data.get("power") if data.get("power") in POWER_MODES else DEFAULT_POWER
    return {"power": power, "gguf_path": str(data.get("gguf_path") or "")}


def save(*, power: str | None = None, gguf_path: str | None = None) -> dict[str, Any]:
    cur = load()
    if power is not None:
        if power not in POWER_MODES:
            raise ValueError(f"power must be one of {', '.join(POWER_MODES)}")
        cur["power"] = power
    if gguf_path is not None:
        p = str(gguf_path).strip()
        if p:
            path = Path(p).expanduser()
            if not path.is_absolute() or not path.is_file():
                raise ValueError("gguf_path must be an existing absolute file path")
            with open(path, "rb") as fh:
                if fh.read(4) != b"GGUF":
                    raise ValueError("the file is not a GGUF model")
            p = str(path.resolve())
        cur["gguf_path"] = p
    sp = settings_path()
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(json.dumps(cur, ensure_ascii=False, indent=2), encoding="utf-8")
    return cur


def effective() -> dict[str, Any]:
    """Итоговые настройки: переменные окружения сильнее файла."""
    s = load()
    env_power = os.environ.get("PADAM_CPU_POWER", "").strip().lower()
    env_path = os.environ.get("PADAM_CPU_GGUF_PATH", "").strip()
    return {
        "power": env_power if env_power in POWER_MODES else s["power"],
        "gguf_path": env_path or s["gguf_path"],
        "power_from": "env" if env_power in POWER_MODES else "settings",
        "gguf_from": "env" if env_path else ("settings" if s["gguf_path"] else "none"),
    }


def threads_for(cores: int, power: str) -> int:
    cores = max(1, int(cores))
    if power == "eco":
        return max(1, cores // 4)
    if power == "full":
        return max(1, cores - 1 if cores > 2 else cores)
    return max(1, cores // 2)


def ram_budget(ram_gb: float, power: str) -> float:
    """Сколько памяти «отдаём» модели при выборе её размера: в режиме half модель на ступень меньше."""
    return float(ram_gb) * _RAM_SHARE.get(power, 0.5)


def capped_threads(requested: int | None, cores: int, power: str) -> int:
    """Ручное число потоков (PADAM_CPU_GGUF_THREADS) не может превысить «все ядра минус одно»."""
    ceiling = max(1, cores - 1 if cores > 2 else cores)
    if requested is None:
        return threads_for(cores, power)
    return max(1, min(int(requested), ceiling))


def ollama_models_dir() -> Path:
    env = os.environ.get("OLLAMA_MODELS", "").strip()
    return Path(env) if env else Path.home() / ".ollama" / "models"


def list_ollama_models(models_dir: str | Path | None = None) -> list[dict[str, Any]]:
    """Модели Ollama, уже скачанные на диск: их слой модели — это обычный файл GGUF без расширения."""
    root = Path(models_dir) if models_dir else ollama_models_dir()
    lib = root / "manifests" / "registry.ollama.ai" / "library"
    found: list[dict[str, Any]] = []
    if not lib.is_dir():
        return found
    for manifest in sorted(p for p in lib.glob("*/*") if p.is_file()):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        layer = next((x for x in data.get("layers", []) if str(x.get("mediaType", "")).endswith("image.model")), None)
        if not layer:
            continue  # облачные модели (например *-cloud) не хранят веса на диске
        blob = root / "blobs" / str(layer.get("digest", "")).replace(":", "-")
        if not blob.is_file():
            continue
        try:
            with open(blob, "rb") as fh:
                if fh.read(4) != b"GGUF":
                    continue
        except OSError:
            continue
        name = f"{manifest.parent.name}:{manifest.name}"
        is_embed = any(w in name for w in ("embed", "bge-", "nomic"))
        # resolve() даёт настоящий регистр пути на диске — тот же, что сохраняет save(); иначе в списке дубль
        found.append({"name": name, "path": str(blob.resolve()), "size_gb": round(blob.stat().st_size / 1e9, 2),
                      "kind": "embedding" if is_embed else "chat", "source": "ollama"})
    return found


def list_gguf_files(extra_dirs: list[str | Path] | None = None) -> list[dict[str, Any]]:
    dirs = [Path(os.environ.get("PADAM_HOME") or (Path.home() / ".padam")) / "models", *(Path(d) for d in (extra_dirs or []))]
    out: list[dict[str, Any]] = []
    for d in dirs:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.gguf")):
            out.append({"name": f.name, "path": str(f.resolve()), "size_gb": round(f.stat().st_size / 1e9, 2), "kind": "chat", "source": "gguf"})
    return out


def overview(extra_dirs: list[str | Path] | None = None) -> dict[str, Any]:
    """Всё для экрана Studio: что выбрано, что найдено, что делать дальше."""
    from . import cpu_engine

    eff = effective()
    status = cpu_engine.cpu_engine_status()
    models = [m for m in list_ollama_models() if m["kind"] == "chat"] + list_gguf_files(extra_dirs)
    cores = status["cpu_cores"]
    return {
        "power": eff["power"],
        "power_modes": [{"id": p, "threads": threads_for(cores, p)} for p in POWER_MODES],
        "gguf_path": eff["gguf_path"],
        "llama_cpp_installed": status["llama_cpp_installed"],
        "mode": status["mode"],
        "cpu_cores": cores,
        "system_ram_gb": status["system_ram_gb"],
        "recommended": status["recommended_quant_profile"],
        "models_found": models,
        "last_error": status.get("last_error", ""),
        "next_step": (
            "install" if not status["llama_cpp_installed"]
            else "choose_model" if not eff["gguf_path"]
            else "ready"
        ),
        "cost_usd": 0.0,
    }
