# -*- coding: utf-8 -*-
"""Детектор Slopsquatting и подмены зависимостей (Supply-Chain Dependency Guard).

Ловит галлюцинированные ИИ-агентами и поддельные имена пакетов в `requirements.txt`,
`pyproject.toml` и `package.json`:
- Расстояние Левенштейна <= 2 от популярных пакетов PyPI и npm (например, `reqeusts`, `crytography`, `l0dash`).
- Опасные суффиксы-приманки (`requests-pro`, `openai-helper`, `langchain-fast`).
- Небезопасные URL-источники (`git+http://`, прямые IP, `http://` вместо HTTPS).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Эталонный словарь наиболее часто атакуемых (и галлюцинируемых) пакетов PyPI и npm
POPULAR_PYPI: frozenset[str] = frozenset({
    "requests", "numpy", "pandas", "scipy", "cryptography", "pytest", "fastapi", "flask", "django",
    "pydantic", "sqlalchemy", "uvicorn", "httpx", "aiohttp", "urllib3", "certifi", "charset-normalizer",
    "beautifulsoup4", "lxml", "pillow", "matplotlib", "scikit-learn", "torch", "transformers",
    "onnxruntime", "tokenizers", "openai", "anthropic", "langchain", "llama-index", "crewai",
    "playwright", "selenium", "pyyaml", "toml", "click", "typer", "rich", "psutil", "boto3",
    "redis", "celery", "paramiko", "pyjwt", "solders", "solana", "web3", "eth-account", "mcp",
    "fastmcp", "uvicorn", "gunicorn", "starlette", "jinja2", "markupsafe", "packaging", "setuptools",
    "wheel", "pip", "virtualenv", "black", "ruff", "mypy", "flake8", "isort", "coverage",
})

POPULAR_NPM: frozenset[str] = frozenset({
    "react", "react-dom", "next", "typescript", "express", "axios", "lodash", "zod", "tailwindcss",
    "eslint", "prettier", "vite", "webpack", "playwright", "puppeteer", "dotenv", "cors", "helmet",
    "jsonwebtoken", "bcrypt", "prisma", "mongoose", "pg", "redis", "socket.io", "ethers", "viem",
    "wagmi", "openai", "langchain", "chalk", "commander", "yargs", "semver", "uuid", "dayjs",
    "moment", "immer", "zustand", "redux", "vue", "nuxt", "svelte", "astro", "esbuild", "rollup",
    "vitest", "jest", "mocha", "ts-node", "tsx", "nodemon", "pm2", "winston", "pino",
})

_SLOP_SUFFIX_RE = re.compile(r"(?:-(?:helper|utils?|pro|v2|fast|plus|ext|wrapper|sdk2|ai-tool))$", re.I)
_UNSAFE_URL_RE = re.compile(r"(?i)(?:git\+http://|http://(?!127\.0\.0\.1|localhost)|https?://\d+\.\d+\.\d+\.\d+)")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _norm_pkg(name: str) -> str:
    return re.sub(r"[_.\s]+", "-", str(name or "").strip().lower())


def check_package_name(name: str, *, ecosystem: str = "pypi") -> list[dict[str, Any]]:
    """Проверяет одно имя пакета на тайпсквоттинг и slopsquatting."""
    raw = str(name or "").strip()
    norm = _norm_pkg(raw)
    if not norm or norm.startswith("@"):
        return []
    catalog = POPULAR_NPM if ecosystem == "npm" else POPULAR_PYPI
    if norm in catalog:
        return []

    findings: list[dict[str, Any]] = []
    # 1. Тайпсквоттинг (расстояние Левенштейна 1..2 для имён длиной >= 5)
    for pop in catalog:
        if len(pop) < 5 or abs(len(norm) - len(pop)) > 2:
            continue
        dist = _levenshtein(norm, pop)
        if 1 <= dist <= 2:
            findings.append({
                "rule_id": "SLOP-TYPOSQUAT-PACKAGE",
                "severity": "critical" if dist == 1 else "high",
                "package": raw,
                "ecosystem": ecosystem,
                "similar_to": pop,
                "distance": dist,
                "detail": f"Подозрение на тайпсквоттинг/slopsquatting: `{raw}` отличается на {dist} симв. от популярного `{pop}`!",
            })
            break

    # 2. Суффикс-приманка поверх популярного имени (например, `requests-helper`, `openai-pro`)
    if not findings and _SLOP_SUFFIX_RE.search(norm):
        base = _SLOP_SUFFIX_RE.sub("", norm)
        if base in catalog:
            findings.append({
                "rule_id": "SLOP-HALLUCINATED-SUFFIX",
                "severity": "high",
                "package": raw,
                "ecosystem": ecosystem,
                "similar_to": base,
                "detail": f"Подозрительное имя-приманка `{raw}` на базе популярного `{base}` (типичный паттерн slopsquatting).",
            })
    return findings


def scan_dependencies_text(content: str, *, filename: str = "requirements.txt") -> dict[str, Any]:
    """Анализирует содержимое `requirements.txt`, `package.json` или `pyproject.toml` на slopsquatting."""
    fname = Path(filename).name.lower()
    findings: list[dict[str, Any]] = []
    packages_checked = 0

    if fname == "package.json":
        try:
            data = json.loads(content)
        except Exception:
            data = {}
        for sec in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(sec) if isinstance(data, dict) else None
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                packages_checked += 1
                findings.extend(check_package_name(pkg, ecosystem="npm"))
                if _UNSAFE_URL_RE.search(str(ver or "")):
                    findings.append({
                        "rule_id": "SLOP-UNSAFE-DEP-URL",
                        "severity": "critical",
                        "package": pkg,
                        "ecosystem": "npm",
                        "detail": f"Небезопасный URL зависимости `{pkg}`: {str(ver)[:100]}",
                    })
    else:
        for lineno, line in enumerate(content.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("-r "):
                continue
            if _UNSAFE_URL_RE.search(s):
                findings.append({
                    "rule_id": "SLOP-UNSAFE-DEP-URL",
                    "severity": "critical",
                    "package": s[:60],
                    "ecosystem": "pypi",
                    "line": lineno,
                    "detail": f"Небезопасный источник пакета (HTTP или прямой IP): {s[:100]}",
                })
                continue
            # Извлекаем имя пакета из строки requirements.txt или массива dependencies в pyproject.toml
            m = re.match(r'^["\']?([A-Za-z0-9][A-Za-z0-9._-]{1,64})(?:\[[^\]]+\])?(?:\s*(?:==|>=|<=|~=|!=|>|<|@|,|["\']|$))', s)
            if m:
                pkg = m.group(1)
                if pkg.lower() in ("dependencies", "optional-dependencies", "requires", "name", "version", "python"):
                    continue
                packages_checked += 1
                for f in check_package_name(pkg, ecosystem="pypi"):
                    f["line"] = lineno
                    findings.append(f)

    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    return {
        "ok": True,
        "filename": filename,
        "packages_checked": packages_checked,
        "risk_grade": "CRITICAL" if crit else ("WARN" if high else "SAFE"),
        "blocked": crit > 0,
        "findings": findings,
    }


def scan_dependencies_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    return scan_dependencies_text(p.read_text(encoding="utf-8", errors="replace"), filename=p.name)
