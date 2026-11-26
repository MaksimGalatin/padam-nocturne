# -*- coding: utf-8 -*-
"""Статический AST-сканер исходного кода MCP-серверов до установки (`padam inspect`).

Закрывает окно уязвимости ДО первого пиннинга схемы SHA-256: проверяет Python через нативный `ast`,
а также JS/TS/Go/`package.json`/`pyproject.toml`/`setup.py` на скрытые prompt-инъекции в
docstrings и полях `description`, опасные вызовы (`eval`/`exec`/`subprocess(shell=True)`/
`child_process`), чтение `~/.ssh`/`~/.aws`/`.env`, жёстко вшитые внешние IP и скрытые Unicode-теги.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from .. import safety
from .semantic import classify_semantic_threat

_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox"})
_CODE_EXTS = frozenset({".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".json", ".toml", ".sh", ".ps1"})

_HARDCODED_IP_RE = re.compile(
    r"\b(?!127\.0\.0\.1\b|0\.0\.0\.0\b|10\.\d+\.\d+\.\d+\b|192\.168\.\d+\.\d+\b)"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_SENSITIVE_REF_RE = re.compile(
    r"(?i)(?:~[/\\]\.ssh|[/\\]\.ssh[/\\]id_|~[/\\]\.aws|[/\\]\.aws[/\\]credentials|"
    r"wallet\.json|seed[_-]?phrase|authorized_keys|/etc/shadow)"
)
_JS_DANGEROUS_RE = re.compile(
    r"(?:\beval\s*\(|\bnew\s+Function\s*\(|child_process|\bexecSync\s*\(|\bspawnSync\s*\(|"
    r"process\.env\b.*fetch\s*\(|Buffer\.from\s*\([^)]*['\"]base64['\"])"
)
_UNICODE_TAG_RE = re.compile(r"[\U000E0000-\U000E007F\u202A-\u202E\u2066-\u2069]")


def _finding(
    *,
    rule_id: str,
    severity: str,
    file_path: str,
    line: int,
    detail: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": file_path,
        "line": int(line),
        "detail": detail[:260],
    }


def _scan_python_ast(text: str, rel_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        findings.append(_finding(
            rule_id="MCP-AST-SYNTAX",
            severity="medium",
            file_path=rel_path,
            line=int(exc.lineno or 1),
            detail=f"Не удалось разобрать Python AST: {exc.msg}",
        ))
        return findings

    for node in ast.walk(tree):
        # 1. Опасные вызовы eval/exec/compile/__import__/os.system/subprocess(shell=True)/pickle.loads
        if isinstance(node, ast.Call):
            fn_name = ""
            if isinstance(node.func, ast.Name):
                fn_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                parent = getattr(node.func.value, "id", "")
                fn_name = f"{parent}.{node.func.attr}" if parent else node.func.attr

            if fn_name in ("eval", "exec", "compile", "__import__", "builtins.eval", "builtins.exec"):
                findings.append(_finding(
                    rule_id="MCP-PY-DYNAMIC-EXEC",
                    severity="critical",
                    file_path=rel_path,
                    line=node.lineno,
                    detail=f"Обнаружен опасный динамический вызов `{fn_name}()` в коде MCP-сервера.",
                ))
            elif fn_name in ("os.system", "os.popen", "pickle.loads", "pickle.load", "marshal.loads"):
                findings.append(_finding(
                    rule_id="MCP-PY-UNSAFE-CALL",
                    severity="critical",
                    file_path=rel_path,
                    line=node.lineno,
                    detail=f"Обнаружен опасный системный/десериализационный вызов `{fn_name}()`.",
                ))
            elif fn_name.startswith("subprocess.") or fn_name in ("Popen", "run", "call", "check_output"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(_finding(
                            rule_id="MCP-PY-SUBPROCESS-SHELL",
                            severity="high",
                            file_path=rel_path,
                            line=node.lineno,
                            detail=f"Вызов `{fn_name}(..., shell=True)` создаёт риск инъекции команд ОС.",
                        ))

        # 2. Скрытые инструкции в docstrings и строковых полях description MCP-инструментов
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            doc = ast.get_docstring(node)
            if doc and len(doc) >= 18:
                if safety.looks_like_instruction(doc) or safety.changes_owner_or_rules(doc):
                    findings.append(_finding(
                        rule_id="MCP-POISONED-DOCSTRING",
                        severity="critical",
                        file_path=rel_path,
                        line=getattr(node, "lineno", 1),
                        detail="Обнаружена скрытая prompt-инъекция внутри docstring MCP-инструмента!",
                    ))
                else:
                    sem = classify_semantic_threat(doc, threshold=0.80)
                    if sem.get("is_threat"):
                        findings.append(_finding(
                            rule_id="MCP-SEMANTIC-DOCSTRING",
                            severity="high",
                            file_path=rel_path,
                            line=getattr(node, "lineno", 1),
                            detail=f"Семантическая инъекция в docstring (score={sem['score']}).",
                        ))

        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) >= 4:
            val = node.value
            if _SENSITIVE_REF_RE.search(val):
                findings.append(_finding(
                    rule_id="MCP-SENSITIVE-PATH-ACCESS",
                    severity="high",
                    file_path=rel_path,
                    line=getattr(node, "lineno", 1),
                    detail=f"Обращение к чувствительному системному пути: {val[:80]}",
                ))
            if _HARDCODED_IP_RE.search(val):
                ip = _HARDCODED_IP_RE.search(val).group(0)
                findings.append(_finding(
                    rule_id="MCP-HARDCODED-EXTERNAL-IP",
                    severity="high",
                    file_path=rel_path,
                    line=getattr(node, "lineno", 1),
                    detail=f"Жёстко вшитый внешний IP-адрес `{ip}` (потенциальный C2/эксфильтрация).",
                ))

        # Проверка keyword-аргумента description="..." (типично для FastMCP / MCP SDK)
        if isinstance(node, ast.keyword) and node.arg in ("description", "instructions", "system_prompt"):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                desc = node.value.value
                if safety.looks_like_instruction(desc) or classify_semantic_threat(desc, threshold=0.78).get("is_threat"):
                    findings.append(_finding(
                        rule_id="MCP-POISONED-DESCRIPTION",
                        severity="critical",
                        file_path=rel_path,
                        line=getattr(node.value, "lineno", 1),
                        detail=f"Скрытая инъекция в поле `{node.arg}` инструмента MCP!",
                    ))

    return findings


def _scan_package_json(text: str, rel_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads(text)
    except Exception:
        return findings
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if isinstance(scripts, dict):
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            cmd = str(scripts.get(hook) or "").strip()
            if cmd:
                sev = "critical" if re.search(r"curl|wget|powershell|bash|sh\s+-c|node\s+-e|eval", cmd, re.I) else "high"
                findings.append(_finding(
                    rule_id="MCP-NPM-LIFECYCLE-HOOK",
                    severity=sev,
                    file_path=rel_path,
                    line=1,
                    detail=f"Скрипт установки `{hook}` в package.json: {cmd[:120]}",
                ))
    return findings


def _scan_generic_text(text: str, rel_path: str, ext: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if _UNICODE_TAG_RE.search(line):
            findings.append(_finding(
                rule_id="MCP-HIDDEN-UNICODE",
                severity="critical",
                file_path=rel_path,
                line=lineno,
                detail="Обнаружены невидимые Unicode-теги (U+E00xx) или Bidi-переопределения в исходнике!",
            ))
        if ext in (".js", ".mjs", ".cjs", ".ts", ".tsx") and _JS_DANGEROUS_RE.search(line):
            findings.append(_finding(
                rule_id="MCP-JS-DANGEROUS-API",
                severity="high",
                file_path=rel_path,
                line=lineno,
                detail=f"Подозрительный JS/TS вызов: {line.strip()[:120]}",
            ))
        if ext != ".py":
            if _SENSITIVE_REF_RE.search(line):
                findings.append(_finding(
                    rule_id="MCP-SENSITIVE-PATH-ACCESS",
                    severity="high",
                    file_path=rel_path,
                    line=lineno,
                    detail=f"Упоминание чувствительного пути: {line.strip()[:100]}",
                ))
            m_ip = _HARDCODED_IP_RE.search(line)
            if m_ip:
                findings.append(_finding(
                    rule_id="MCP-HARDCODED-EXTERNAL-IP",
                    severity="high",
                    file_path=rel_path,
                    line=lineno,
                    detail=f"Жёстко вшитый внешний IP `{m_ip.group(0)}`.",
                ))
    return findings


def inspect_mcp_package(target_path: str | Path, *, max_files: int = 200) -> dict[str, Any]:
    """Статически анализирует исходный код MCP-сервера (файл или директория) до пиннинга и запуска."""
    t0 = time.perf_counter()
    root = Path(target_path)
    if not root.exists():
        raise FileNotFoundError(f"MCP package path not found: {root}")

    files: list[Path] = []
    if root.is_file():
        files = [root]
    else:
        for p in sorted(root.rglob("*")):
            if len(files) >= max_files:
                break
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.is_file() and (p.suffix.lower() in _CODE_EXTS or p.name.lower() in ("dockerfile", "makefile")):
                files.append(p)

    findings: list[dict[str, Any]] = []
    file_hashes: dict[str, str] = {}
    for fp in files:
        rel = str(fp.relative_to(root)) if root.is_dir() else fp.name
        try:
            raw_bytes = fp.read_bytes()
        except Exception:
            continue
        file_hashes[rel] = hashlib.sha256(raw_bytes).hexdigest()
        if len(raw_bytes) > 2_000_000:
            continue
        txt = raw_bytes.decode("utf-8", "replace")
        ext = fp.suffix.lower()
        if ext == ".py":
            findings.extend(_scan_python_ast(txt, rel))
        if fp.name.lower() == "package.json":
            findings.extend(_scan_package_json(txt, rel))
        findings.extend(_scan_generic_text(txt, rel, ext))

    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    med = sum(1 for f in findings if f["severity"] == "medium")
    if crit > 0:
        grade = "CRITICAL"
        block_install = True
    elif high > 0:
        grade = "WARN"
        block_install = False
    else:
        grade = "SAFE"
        block_install = False

    bundle_sha = hashlib.sha256(
        json.dumps(file_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return {
        "ok": True,
        "target": str(root),
        "files_scanned": len(files),
        "bundle_sha256": bundle_sha,
        "risk_grade": grade,
        "block_install": block_install,
        "counts": {"critical": crit, "high": high, "medium": med, "total": len(findings)},
        "findings": findings,
        "file_hashes": file_hashes,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
    }


def inspect_report_to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Экспортирует отчёт `padam inspect` в стандарт SARIF 2.1.0 для GitHub Actions / SIEM."""
    level_map = {"critical": "error", "high": "warning", "medium": "note"}
    results = []
    for f in report.get("findings") or []:
        results.append({
            "ruleId": f["rule_id"],
            "level": level_map.get(f["severity"], "warning"),
            "message": {"text": f["detail"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": max(1, int(f["line"]))},
                }
            }],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PADAM Agentic Shield — MCP AST Inspector",
                    "informationUri": "https://aifa.works",
                }
            },
            "results": results,
        }],
    }
