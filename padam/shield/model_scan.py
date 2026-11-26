# -*- coding: utf-8 -*-
"""Статический сканер файлов локальных моделей на закладки (ML Supply Chain Security).

Безопасно анализирует артефакты моделей БЕЗ исполнения кода (никогда не вызывает `pickle.load`):
- `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin` (включая ZIP-архивы PyTorch с `data.pkl`):
  разбор опкодов через стандартный `pickletools.genops` и блокировка `os.system`, `subprocess`,
  `builtins.eval/exec`, `socket`, `urllib`, `requests`, `ctypes`, `importlib`.
- `.safetensors`: проверка 8-байтного заголовка (защита от overflow), валидация JSON,
  проверка `__metadata__` на инъекции и сверка смещений тензоров с размером файла (anti-polyglot).
- `.gguf`: разбор бинарного заголовка `GGUF`, проверка метаданных и `tokenizer.chat_template`
  на скрытые prompt-инъекции и бэкдоры.
"""
from __future__ import annotations

import hashlib
import io
import json
import pickletools
import struct
import time
import zipfile
from pathlib import Path
from typing import Any

from .. import safety
from .semantic import classify_semantic_threat

_DANGEROUS_PICKLE_MODULES = frozenset({
    "os", "posix", "nt", "subprocess", "sys", "socket", "http", "urllib", "requests",
    "webbrowser", "ctypes", "shutil", "importlib", "marshal", "pty", "commands", "popen2",
})
_DANGEROUS_PICKLE_BUILTINS = frozenset({
    "eval", "exec", "compile", "__import__", "open", "getattr", "setattr",
})


def _scan_pickle_stream(raw: bytes, source_label: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    stack_strings: list[str] = []
    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(raw)):
            name = opcode.name
            if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"):
                if isinstance(arg, str):
                    stack_strings.append(arg)
                    if len(stack_strings) > 8:
                        stack_strings.pop(0)
            elif name in ("GLOBAL", "INST"):
                sym = str(arg or "")
                parts = sym.split()
                mod = parts[0] if parts else ""
                attr = parts[1] if len(parts) > 1 else ""
                _check_pickle_symbol(mod, attr, pos or 0, source_label, findings)
            elif name == "STACK_GLOBAL":
                if len(stack_strings) >= 2:
                    mod, attr = stack_strings[-2], stack_strings[-1]
                    _check_pickle_symbol(mod, attr, pos or 0, source_label, findings)
            elif name == "EXT1" or name == "EXT2" or name == "EXT4":
                findings.append({
                    "rule_id": "ML-PICKLE-EXT-REGISTRY",
                    "severity": "high",
                    "source": source_label,
                    "offset": int(pos or 0),
                    "detail": f"Использован редкий опкод {name} (вызов из внешнего реестра копирования).",
                })
    except Exception as exc:
        findings.append({
            "rule_id": "ML-PICKLE-MALFORMED",
            "severity": "high",
            "source": source_label,
            "offset": 0,
            "detail": f"Повреждённый или намеренно обфусцированный поток Pickle: {str(exc)[:140]}",
        })
    return findings


def _check_pickle_symbol(
    mod: str, attr: str, pos: int, source_label: str, findings: list[dict[str, Any]]
) -> None:
    root_mod = mod.split(".")[0].lower()
    attr_low = attr.lower()
    if root_mod in _DANGEROUS_PICKLE_MODULES or (root_mod in ("builtins", "__builtin__") and attr_low in _DANGEROUS_PICKLE_BUILTINS):
        findings.append({
            "rule_id": "ML-PICKLE-CODE-EXEC",
            "severity": "critical",
            "source": source_label,
            "offset": int(pos),
            "detail": f"Заблокирован эксплойт десериализации Pickle: вызов `{mod}.{attr}` на смещении {pos}!",
        })


def _scan_safetensors(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    size = path.stat().st_size
    if size < 8:
        findings.append({
            "rule_id": "ML-SAFETENSORS-TRUNCATED",
            "severity": "high",
            "source": path.name,
            "offset": 0,
            "detail": "Файл .safetensors меньше 8 байт.",
        })
        return findings

    with path.open("rb") as f:
        hdr_len = struct.unpack("<Q", f.read(8))[0]
        if hdr_len > 100_000_000 or 8 + hdr_len > size:
            findings.append({
                "rule_id": "ML-SAFETENSORS-HEADER-OVERFLOW",
                "severity": "critical",
                "source": path.name,
                "offset": 0,
                "detail": f"Некорректная длина заголовка .safetensors ({hdr_len} байт при размере файла {size}).",
            })
            return findings
        hdr_raw = f.read(hdr_len)

    try:
        hdr = json.loads(hdr_raw.decode("utf-8"))
    except Exception as exc:
        findings.append({
            "rule_id": "ML-SAFETENSORS-BAD-JSON",
            "severity": "critical",
            "source": path.name,
            "offset": 8,
            "detail": f"Заголовок .safetensors не является валидным JSON: {exc}",
        })
        return findings

    max_end = 0
    for k, v in hdr.items():
        if k == "__metadata__" and isinstance(v, dict):
            for mk, mv in v.items():
                s = str(mv or "")
                if safety.looks_like_instruction(s) or classify_semantic_threat(s, threshold=0.78).get("is_threat"):
                    findings.append({
                        "rule_id": "ML-SAFETENSORS-METADATA-INJECTION",
                        "severity": "high",
                        "source": f"{path.name}:__metadata__.{mk}",
                        "offset": 8,
                        "detail": f"Подозрительная инструкция в __metadata__.{mk} файла .safetensors!",
                    })
        elif isinstance(v, dict) and "data_offsets" in v:
            offs = v.get("data_offsets") or [0, 0]
            if len(offs) == 2 and isinstance(offs[1], int):
                max_end = max(max_end, offs[1])

    expected_size = 8 + hdr_len + max_end
    if max_end > 0 and size > expected_size + 64:
        findings.append({
            "rule_id": "ML-SAFETENSORS-TRAILING-PAYLOAD",
            "severity": "high",
            "source": path.name,
            "offset": expected_size,
            "detail": f"Обнаружены скрытые хвостовые байты ({size - expected_size} Б) после тензоров — риск polyglot-закладки!",
        })
    return findings


def _scan_gguf(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    with path.open("rb") as f:
        head = f.read(min(path.stat().st_size, 512 * 1024))
    if len(head) < 24 or head[:4] != b"GGUF":
        findings.append({
            "rule_id": "ML-GGUF-BAD-MAGIC",
            "severity": "critical",
            "source": path.name,
            "offset": 0,
            "detail": "Файл .gguf не начинается с сигнатуры GGUF.",
        })
        return findings

    version, tensor_cnt, kv_cnt = struct.unpack("<IQQ", head[4:24])
    if version not in (1, 2, 3) or kv_cnt > 1_000_000 or tensor_cnt > 1_000_000:
        findings.append({
            "rule_id": "ML-GGUF-HEADER-ANOMALY",
            "severity": "critical",
            "source": path.name,
            "offset": 4,
            "detail": f"Аномальный заголовок GGUF: version={version}, tensors={tensor_cnt}, kv={kv_cnt}.",
        })
        return findings

    # Разбираем текстовый заголовок GGUF на предмет скрытых инъекций в tokenizer.chat_template
    # (читаем строковые KV-пары и/или безопасный скан области заголовка)
    header_str = head[24:].decode("utf-8", "ignore")
    if "chat_template" in header_str:
        idx = header_str.find("chat_template")
        snippet = header_str[idx : idx + 2000]
        if safety.looks_like_instruction(snippet) or classify_semantic_threat(snippet, threshold=0.78).get("is_threat"):
            findings.append({
                "rule_id": "ML-GGUF-POISONED-CHAT-TEMPLATE",
                "severity": "critical",
                "source": f"{path.name}:tokenizer.chat_template",
                "offset": 24 + idx,
                "detail": "Обнаружена скрытая prompt-инъекция внутри `tokenizer.chat_template` файла GGUF!",
            })
    if b"__import__" in head or b"os.system" in head or b"subprocess" in head:
        findings.append({
            "rule_id": "ML-GGUF-SUSPICIOUS-CODE-MARKER",
            "severity": "high",
            "source": path.name,
            "offset": 24,
            "detail": "В метаданных GGUF найдены маркеры исполнения системного кода (`os.system`/`subprocess`).",
        })
    return findings


def scan_model_file(model_path: str | Path) -> dict[str, Any]:
    """Сканирует локальный файл модели (.pkl/.pt/.pth/.bin/.safetensors/.gguf) на закладки."""
    t0 = time.perf_counter()
    p = Path(model_path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Model file not found: {p}")

    ext = p.suffix.lower()
    size = p.stat().st_size
    # Хешируем потоково (безопасно для гигабайтных моделей)
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    file_sha = h.hexdigest()

    findings: list[dict[str, Any]] = []
    fmt = "unknown"

    if ext == ".safetensors":
        fmt = "safetensors"
        findings.extend(_scan_safetensors(p))
    elif ext == ".gguf":
        fmt = "gguf"
        findings.extend(_scan_gguf(p))
    elif zipfile.is_zipfile(p):
        fmt = "pytorch_zip_pickle"
        with zipfile.ZipFile(p, "r") as zf:
            for member in zf.namelist():
                if member.endswith((".pkl", ".pickle", "data.pkl")):
                    findings.extend(_scan_pickle_stream(zf.read(member), f"{p.name}!{member}"))
    elif ext in (".pkl", ".pickle", ".pt", ".pth", ".bin"):
        fmt = "pickle"
        findings.extend(_scan_pickle_stream(p.read_bytes(), p.name))
    else:
        fmt = "binary_other"

    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    blocked = crit > 0
    return {
        "ok": True,
        "path": str(p),
        "format": fmt,
        "size_bytes": size,
        "sha256": file_sha,
        "safe_to_load": not blocked,
        "blocked": blocked,
        "risk_grade": "CRITICAL" if crit else ("WARN" if high else "SAFE"),
        "counts": {"critical": crit, "high": high, "total": len(findings)},
        "findings": findings,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
    }
