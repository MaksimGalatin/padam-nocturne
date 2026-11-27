# -*- coding: utf-8 -*-
"""AI Code-Review & Git Diff Security Gate (`padam shield scan-diff`).

Инспектирует unified git diff (от ИИ-кодера или стороннего PR) по добавленным (`+`)
и удалённым (`-`) строкам и перехватывает тихие логические и агентские бэкдоры:
- Trojan Source (CVE-2021-42574: невидимые Bidi-переопределения U+202A..U+202E, U+2066..U+2069)
  и невидимые Unicode-теги в исходном коде,
- ослабление криптографии/безопасности в новых строках (`verify=False`, `rejectUnauthorized: false`,
  `unsafe-inline`/`unsafe-eval`, `shell=True`, `eval(base64...)`, `exec(...)`, `pickle.loads`),
- тихое удаление проверок авторизации в `-` строках (`require_owner`, `@login_required`, `verify_signature`),
- зашитые секреты, приватные ключи и чужие криптокошельки,
- скрытые правки `.github/workflows/`, `.cursorrules`, `CLAUDE.md`, `package.json` `postinstall`.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List


_BIDI_TROJAN_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069\U000E0000-\U000E007F]")

_ADDED_DANGER_RULES = [
    ("DIFF-OBFUSCATED-EXEC", "CRITICAL", re.compile(r"(?i)\b(?:eval|exec)\s*\([^)]*(?:b64decode|base64|bytes\.fromhex|codecs\.decode|zlib\.decompress|__import__)"), "Обфусцированный вызов eval/exec в добавленном коде"),
    ("DIFF-TLS-VERIFY-DISABLED", "HIGH", re.compile(r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|ssl\._create_unverified_context)"), "Отключение проверки TLS-сертификатов"),
    ("DIFF-CSP-WEAKENED", "HIGH", re.compile(r"(?i)Content-Security-Policy[^\n]*(?:unsafe-inline|unsafe-eval)"), "Ослабление Content-Security-Policy (unsafe-inline / unsafe-eval)"),
    ("DIFF-SHELL-INJECTION-RISK", "HIGH", re.compile(r"(?i)(?:subprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True|\bos\.system\s*\(|\bchild_process\.exec\s*\()"), "Опасный вызов оболочки (shell=True / os.system / exec)"),
    ("DIFF-SECRET-HARDCODED", "CRITICAL", re.compile(r"(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----)"), "Зашитый секрет или приватный ключ в диффе"),
    ("DIFF-POSTINSTALL-BACKDOOR", "CRITICAL", re.compile(r'(?i)"(?:postinstall|preinstall)"\s*:\s*"[^"]*(?:curl|wget|powershell|bash|node\s+-e|python\s+-c)'), "Подозрительный скрипт postinstall/preinstall с загрузкой/выполнением кода"),
    ("DIFF-EXTERNAL-EXFIL-CMD", "CRITICAL", re.compile(r"(?i)\b(?:curl|wget)\b[^\n]*(?:\|\s*(?:sh|bash)|-d\s+[^\n]*(?:env|secret|token|key))"), "Команда сетевой загрузки/эксфильтрации в добавленном коде"),
]

_REMOVED_AUTH_GUARD_RE = re.compile(
    r"(?i)(?:roles\.require_owner|@login_required|@require_auth|verify_signature|verify_oidc_jwt|hmac\.compare_digest|check_tool_rbac)"
)

_SENSITIVE_FILES_RE = re.compile(
    r"(?i)(?:^\.github/workflows/|^\.cursorrules$|^\.windsurfrules$|claude\.md$|gemini\.md$|agents\.md$|^\.git/hooks/)"
)


def scan_unified_diff(diff_text: str) -> Dict[str, Any]:
    """Анализирует unified git diff и возвращает список находок с точным файлом и строкой."""
    raw = str(diff_text or "")
    findings: List[Dict[str, Any]] = []
    current_file = ""
    current_line = 0
    files_touched: List[str] = []
    added_lines = 0
    removed_lines = 0

    removed_auth_by_file: Dict[str, List[int]] = {}
    added_auth_by_file: Dict[str, int] = {}

    for line in raw.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            if current_file and current_file not in files_touched:
                files_touched.append(current_file)
            if _SENSITIVE_FILES_RE.search(current_file):
                findings.append(
                    {
                        "rule_id": "DIFF-SENSITIVE-CONFIG-MODIFIED",
                        "severity": "MEDIUM",
                        "file": current_file,
                        "line": 0,
                        "detail": f"Изменён чувствительный файл CI/правил агента: {current_file}",
                    }
                )
            continue
        if line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            if m:
                current_line = int(m.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added_lines += 1
            code = line[1:]
            if _BIDI_TROJAN_RE.search(code):
                findings.append(
                    {
                        "rule_id": "DIFF-TROJAN-SOURCE-BIDI",
                        "severity": "CRITICAL",
                        "file": current_file or "<diff>",
                        "line": current_line,
                        "detail": "Обнаружены скрытые Bidi/Unicode-тег символы (атака Trojan Source CVE-2021-42574!)",
                    }
                )
            for rid, sev, rx, desc in _ADDED_DANGER_RULES:
                if rx.search(code):
                    findings.append(
                        {
                            "rule_id": rid,
                            "severity": sev,
                            "file": current_file or "<diff>",
                            "line": current_line,
                            "detail": f"{desc}: {code.strip()[:120]}",
                        }
                    )
            if _REMOVED_AUTH_GUARD_RE.search(code):
                added_auth_by_file[current_file] = added_auth_by_file.get(current_file, 0) + 1
            current_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed_lines += 1
            code = line[1:]
            if _REMOVED_AUTH_GUARD_RE.search(code):
                removed_auth_by_file.setdefault(current_file, []).append(current_line)
        elif not line.startswith("\\"):
            current_line += 1

    # Если из файла удалили проверку авторизации и НЕ добавили взамен — тревога!
    for fpath, rlines in removed_auth_by_file.items():
        if len(rlines) > added_auth_by_file.get(fpath, 0):
            findings.append(
                {
                    "rule_id": "DIFF-AUTH-CHECK-REMOVED",
                    "severity": "CRITICAL",
                    "file": fpath or "<diff>",
                    "line": rlines[0],
                    "detail": f"Из файла '{fpath}' удалена проверка авторизации/подписи без замены!",
                }
            )

    blocked = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)
    return {
        "ok": not blocked,
        "blocked": blocked,
        "risk_grade": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else ("HIGH" if blocked else ("MEDIUM" if findings else "SAFE")),
        "files_touched": files_touched,
        "added_lines": added_lines,
        "removed_lines": removed_lines,
        "findings": findings,
    }


def scan_diff_file(path: str | os.PathLike[str]) -> Dict[str, Any]:
    """Читает файл unified diff с диска и запускает проверку."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"ok": False, "blocked": True, "error": f"Файл diff не найден: {p}", "findings": []}
    return scan_unified_diff(p.read_text(encoding="utf-8", errors="replace"))
