# -*- coding: utf-8 -*-
"""Генератор AI-BOM (Software & Model Bill of Materials) в формате CycloneDX 1.6 JSON.

Инвентаризирует всю AI-цепочку поставок проекта (EU AI Act ст. 11/53, NIST AI RMF):
- файлы локальных моделей (`.safetensors`, `.gguf`, `.onnx`, `.pkl`, `.pt`, `.bin`) + `model_scan`,
- зависимости (`requirements.txt`, `pyproject.toml`, `package.json`) + `slopsquat_guard`,
- файлы системных инструкций/скилов (`.cursorrules`, `CLAUDE.md`, `SKILL.md` и др.) + `memory_rules_guard`,
- манифесты MCP-серверов (`mcp.json`, `claude_desktop_config.json`, `.mcp.json`).
Каждый компонент снабжается SHA-256 хешем и оценкой риска, а итоговый документ
CycloneDX 1.6 подписывается локальным ключом владельца HMAC-SHA256.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import integrity as _integrity
from .memory_rules_guard import RULE_FILENAME_PATTERNS, inspect_memory_or_rule_text
from .model_scan import scan_model_file
from .slopsquat_guard import scan_dependencies_file


_MODEL_EXTS = {".safetensors", ".gguf", ".onnx", ".pkl", ".pickle", ".pt", ".pth"}
_DEP_FILES = {"requirements.txt", "pyproject.toml", "package.json"}
_MCP_CONFIG_FILES = {"mcp.json", ".mcp.json", "claude_desktop_config.json"}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _canonical_bom_bytes(bom: Dict[str, Any]) -> bytes:
    clone = {k: v for k, v in bom.items() if k != "signature"}
    return json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_aibom(
    root_dir: str | os.PathLike[str],
    *,
    memory: Any = None,
    project_name: str = "",
    max_files: int = 300,
) -> Dict[str, Any]:
    """Генерирует валидный CycloneDX 1.6 AI-BOM JSON по директории проекта."""
    root = Path(root_dir)
    if not root.exists():
        return {"ok": False, "error": f"Каталог не найден: {root}"}

    components: List[Dict[str, Any]] = []
    findings_total = 0
    critical_count = 0
    scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in (".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache")
        ]
        for fn in filenames:
            if scanned >= max_files:
                break
            full = Path(dirpath) / fn
            rel = str(full.relative_to(root)).replace("\\", "/")
            low = fn.lower()
            ext = full.suffix.lower()

            # 1. Файлы ML-моделей
            if ext in _MODEL_EXTS:
                scanned += 1
                sha = _sha256_file(full)
                ms = scan_model_file(full)
                f_cnt = len(ms.get("findings") or [])
                findings_total += f_cnt
                if ms.get("blocked"):
                    critical_count += 1
                components.append(
                    {
                        "type": "machine-learning-model",
                        "bom-ref": f"model:{rel}",
                        "name": fn,
                        "hashes": [{"alg": "SHA-256", "content": sha}],
                        "properties": [
                            {"name": "padam:path", "value": rel},
                            {"name": "padam:format", "value": ext.lstrip(".")},
                            {"name": "padam:risk_grade", "value": str(ms.get("risk_grade", "SAFE"))},
                            {"name": "padam:findings_count", "value": str(f_cnt)},
                        ],
                    }
                )
            # 2. Манифесты зависимостей
            elif low in _DEP_FILES:
                scanned += 1
                sha = _sha256_file(full)
                ds = scan_dependencies_file(full)
                f_cnt = len(ds.get("findings") or [])
                findings_total += f_cnt
                if ds.get("blocked"):
                    critical_count += 1
                components.append(
                    {
                        "type": "library",
                        "bom-ref": f"deps:{rel}",
                        "name": fn,
                        "hashes": [{"alg": "SHA-256", "content": sha}],
                        "properties": [
                            {"name": "padam:path", "value": rel},
                            {"name": "padam:packages_checked", "value": str(ds.get("packages_checked", 0))},
                            {"name": "padam:risk_grade", "value": str(ds.get("risk_grade", "SAFE"))},
                            {"name": "padam:findings_count", "value": str(f_cnt)},
                        ],
                    }
                )
            # 3. Файлы правил и промптов агентов
            elif low in RULE_FILENAME_PATTERNS or rel.lower().endswith(".github/copilot-instructions.md"):
                scanned += 1
                sha = _sha256_file(full)
                txt = full.read_text(encoding="utf-8", errors="replace")
                rs = inspect_memory_or_rule_text(txt, source_name=rel)
                f_cnt = len(rs.get("findings") or [])
                findings_total += f_cnt
                if rs.get("blocked"):
                    critical_count += 1
                components.append(
                    {
                        "type": "data",
                        "bom-ref": f"rules:{rel}",
                        "name": fn,
                        "hashes": [{"alg": "SHA-256", "content": sha}],
                        "properties": [
                            {"name": "padam:path", "value": rel},
                            {"name": "padam:category", "value": "agent-rules"},
                            {"name": "padam:blocked", "value": "true" if rs.get("blocked") else "false"},
                            {"name": "padam:findings_count", "value": str(f_cnt)},
                        ],
                    }
                )
            # 4. Конфигурации MCP-серверов
            elif low in _MCP_CONFIG_FILES:
                scanned += 1
                sha = _sha256_file(full)
                servers: List[str] = []
                try:
                    cfg = json.loads(full.read_text(encoding="utf-8", errors="replace"))
                    if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                        servers = sorted(str(k) for k in cfg["mcpServers"].keys())
                except Exception:
                    pass
                components.append(
                    {
                        "type": "service",
                        "bom-ref": f"mcp:{rel}",
                        "name": fn,
                        "hashes": [{"alg": "SHA-256", "content": sha}],
                        "properties": [
                            {"name": "padam:path", "value": rel},
                            {"name": "padam:mcp_servers", "value": ",".join(servers)},
                            {"name": "padam:mcp_server_count", "value": str(len(servers))},
                        ],
                    }
                )

    bom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "component": {
                "type": "application",
                "name": project_name or root.name,
            },
            "tools": [{"vendor": "AIfa Works / PADAM", "name": "PADAM Agentic Shield AI-BOM"}],
            "properties": [
                {"name": "padam:total_components", "value": str(len(components))},
                {"name": "padam:total_findings", "value": str(findings_total)},
                {"name": "padam:critical_components", "value": str(critical_count)},
                {"name": "padam:risk_grade", "value": "CRITICAL" if critical_count > 0 else ("MEDIUM" if findings_total > 0 else "SAFE")},
            ],
        },
        "components": components,
    }

    if memory is not None:
        key, _ = _integrity.owner_key(memory.store)
        key_b = key if isinstance(key, bytes) else str(key).encode("utf-8")
        sig = hmac.new(key_b, _canonical_bom_bytes(bom), hashlib.sha256).hexdigest()
        bom["signature"] = {"algorithm": "HMAC-SHA256", "value": sig}

    return {
        "ok": True,
        "risk_grade": "CRITICAL" if critical_count > 0 else ("MEDIUM" if findings_total > 0 else "SAFE"),
        "components_count": len(components),
        "findings_total": findings_total,
        "critical_components": critical_count,
        "signed": "signature" in bom,
        "bom": bom,
    }


def verify_aibom_signature(bom: Dict[str, Any], memory: Any) -> Dict[str, Any]:
    """Проверяет криптографическую HMAC-SHA256 подпись CycloneDX 1.6 AI-BOM."""
    sig_obj = bom.get("signature")
    if not isinstance(sig_obj, dict) or not sig_obj.get("value"):
        return {"ok": False, "valid": False, "reason": "Подпись отсутствует в AI-BOM"}
    key, _ = _integrity.owner_key(memory.store)
    key_b = key if isinstance(key, bytes) else str(key).encode("utf-8")
    expected = hmac.new(key_b, _canonical_bom_bytes(bom), hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(expected, str(sig_obj.get("value")))
    return {
        "ok": valid,
        "valid": valid,
        "algorithm": sig_obj.get("algorithm", "HMAC-SHA256"),
        "reason": "" if valid else "Подпись AI-BOM не совпадает (документ был изменён)",
    }
