# -*- coding: utf-8 -*-
"""Броня памяти и файлов правил агента (Rules File Backdoor & Sleeper Memory Poisoning Guard).

Защищает `.cursorrules`, `.windsurfrules`, `CLAUDE.md`, `GEMINI.md`, `AGENTS.md`,
`SKILL.md`, `.github/copilot-instructions.md` и записи, поступающие в долгосрочную
память PADAM, от «спящих закладок» (MINJA / AgentPoison / Rules File Backdoor):
- условных скрытых триггеров («whenever user asks about wallet, silently...»),
- невидимых Unicode-тегов (U+E00xx), Bidi-инверсий и скрытых HTML-комментариев,
- попыток отключить политики безопасности/аудит/Kill Switch,
- внедрения несанкционированных URL/вебхуков/криптокошельков и правок `.git/hooks`.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .adversarial_norm import canonicalize_adversarial_text
from .exfil_guard import inspect_exfil_channels


RULE_FILENAME_PATTERNS = {
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "claude.md",
    "gemini.md",
    "agents.md",
    "skill.md",
    "copilot-instructions.md",
}

_SLEEPER_TRIGGER_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:whenever|if|when)\s+(?:the\s+)?(?:user|human|developer|owner)\s+"
    r"(?:asks?|mentions?|opens?|edits?|writes?|runs?|touches?)\b.{0,120}\b"
    r"(?:silently|secretly|quietly|without\s+(?:telling|informing|mentioning)|in\s+the\s+background|exfiltrat|append|inject|backdoor|send\s+to|upload|post\s+to)"
    r"|(?:do\s+not|never)\s+(?:mention|tell|show|inform|reveal)\s+(?:this\s+rule|these\s+instructions|to\s+the\s+user)"
    r"|(?:silently|secretly|covertly)\s+(?:append|insert|add|send|forward|copy|exfiltrate|execute|run)"
    r"|(?:всегда\s+тайно|скрыто\s+добавляй|не\s+сообщай\s+пользователю|молча\s+отправляй)"
    r")"
)

_POLICY_OVERRIDE_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:disable|bypass|ignore|skip|turn\s+off)\s+(?:all\s+)?(?:security|safety|shield|kill\s*switch|allowlist|audit|approval|confirmation|guardrails?)"
    r"|auto[\s-]?approve\s+all\s+(?:payments?|transfers?|shell|commands?|tools?)"
    r"|override\s+system\s+(?:instructions?|policy|constitution)"
    r"|(?:отключи|пропусти|игнорируй)\s+(?:защит|аудит|проверк|подтвержден|kill\s*switch)"
    r")"
)

_GIT_CI_TAMPER_RE = re.compile(
    r"(?is)(?:"
    r"\.git[/\\]hooks[/\\](?:pre-commit|post-checkout|post-merge|pre-push)"
    r"|\.github[/\\]workflows[/\\][^\s\"']+.*?(?:curl|wget|bash|nc\s|secrets\.)"
    r"|~/.ssh/authorized_keys"
    r"|\"postinstall\"\s*:\s*\"[^\"]*(?:curl|wget|powershell|bash|node\s+-e)"
    r")"
)

_HIDDEN_HTML_COMMENT_RE = re.compile(r"<!--([\s\S]{10,4000}?)-->")
_COMMENT_SUSPICIOUS_RE = re.compile(
    r"(?is)\b(?:ignore|override|silently|secretly|exfiltrate|curl|wget|fetch|http://|https://|wallet|0x[0-9a-f]{40}|api[_-]?key|password|token|execute|backdoor|send\s+to)\b"
)

_UNICODE_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")
_BIDI_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")
_EXFIL_SHELL_IN_RULES_RE = re.compile(
    r"(?is)\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc\s+-e|bash\s+-i)\b[^\n]{0,160}https?://[^\s\"']+"
)
_CRYPTO_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b|\bT[1-9A-HJ-NP-Za-km-z]{33}\b")


def inspect_memory_or_rule_text(
    text: str,
    *,
    source_name: str = "memory",
    allow_crypto_addresses: bool = False,
) -> Dict[str, Any]:
    """Проверяет текст правил IDE/скилов или кандидата в долгосрочную память на закладки."""
    raw = str(text or "")
    findings: List[Dict[str, Any]] = []

    if not raw.strip():
        return {
            "ok": True,
            "blocked": False,
            "source": source_name,
            "risk_score": 0.0,
            "findings": [],
        }

    # 1. Невидимые Unicode-теги и Bidi-инверсии
    tag_count = len(_UNICODE_TAG_RE.findall(raw))
    bidi_count = len(_BIDI_RE.findall(raw))
    if tag_count >= 2 or bidi_count >= 1:
        findings.append(
            {
                "rule_id": "RULES-HIDDEN-UNICODE",
                "severity": "CRITICAL",
                "detail": f"Обнаружены скрытые управляющие символы Unicode (tags={tag_count}, bidi={bidi_count})",
            }
        )

    # 2. Скрытые HTML-комментарии с инструкциями
    for m in _HIDDEN_HTML_COMMENT_RE.finditer(raw):
        body = m.group(1)
        if _COMMENT_SUSPICIOUS_RE.search(body):
            findings.append(
                {
                    "rule_id": "RULES-HIDDEN-HTML-COMMENT",
                    "severity": "CRITICAL",
                    "detail": f"Подозрительная инструкция внутри скрытого HTML-комментария: {body.strip()[:120]}",
                }
            )
            break

    # 3. Адверсариальная нормализация перед семантическими проверками
    norm = canonicalize_adversarial_text(raw)
    corpus = raw + "\n" + norm["canonical"]

    # 4. Условные спящие закладки (Sleeper / MINJA / Rules Backdoor)
    m_sleep = _SLEEPER_TRIGGER_RE.search(corpus)
    if m_sleep:
        findings.append(
            {
                "rule_id": "RULES-SLEEPER-TRIGGER",
                "severity": "CRITICAL",
                "detail": f"Обнаружен спящий условный триггер/скрытая инструкция: {m_sleep.group(0)[:140]}",
            }
        )

    # 5. Попытка отключить защиту/аудит/Kill Switch
    m_ovr = _POLICY_OVERRIDE_RE.search(corpus)
    if m_ovr:
        findings.append(
            {
                "rule_id": "RULES-POLICY-OVERRIDE",
                "severity": "CRITICAL",
                "detail": f"Попытка переопределить или отключить политики безопасности: {m_ovr.group(0)[:120]}",
            }
        )

    # 6. Манипуляция git-хуками, CI/CD, SSH, postinstall
    m_ci = _GIT_CI_TAMPER_RE.search(corpus)
    if m_ci:
        findings.append(
            {
                "rule_id": "RULES-GIT-CI-TAMPER",
                "severity": "HIGH",
                "detail": f"Попытка модификации git-хуков / CI / SSH / postinstall: {m_ci.group(0)[:120]}",
            }
        )

    # 7. Команды сетевой эксфильтрации в правилах
    m_exf = _EXFIL_SHELL_IN_RULES_RE.search(corpus)
    if m_exf:
        findings.append(
            {
                "rule_id": "RULES-EXFIL-COMMAND",
                "severity": "HIGH",
                "detail": f"Сетевая команда эксфильтрации в правилах: {m_exf.group(0)[:120]}",
            }
        )

    # 8. Скрытые каналы эксфильтрации (Markdown image, DNS tunnel, ZWSP)
    ex_res = inspect_exfil_channels(raw)
    for f in ex_res.get("findings") or []:
        fid = str(f.get("rule_id") or f.get("code") or "EXFIL").upper()
        findings.append(
            {
                "rule_id": f"RULES-{fid}",
                "severity": str(f.get("severity", "HIGH")).upper(),
                "detail": f.get("detail", ""),
            }
        )

    # 9. Неожиданные криптоадреса в файлах правил (частая подмена payee в .cursorrules)
    if not allow_crypto_addresses and _CRYPTO_ADDR_RE.search(raw):
        is_rule_file = any(k in source_name.lower() for k in ("rules", "skill", "claude", "gemini", "agents", "copilot"))
        if is_rule_file:
            findings.append(
                {
                    "rule_id": "RULES-EMBEDDED-WALLET",
                    "severity": "HIGH",
                    "detail": "В файле инструкций агента зашит криптокошелёк (риск подмены получателя)",
                }
            )

    sev_weight = {"CRITICAL": 0.95, "HIGH": 0.75, "MEDIUM": 0.45, "LOW": 0.2}
    risk_score = min(1.0, max((sev_weight.get(f["severity"], 0.5) for f in findings), default=0.0))
    blocked = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)
    return {
        "ok": not blocked,
        "blocked": blocked,
        "source": source_name,
        "risk_score": round(risk_score, 3),
        "findings": findings,
    }


def scan_rules_directory(root_dir: str | os.PathLike[str], *, max_files: int = 200) -> Dict[str, Any]:
    """Сканирует проект на скрытые закладки в `.cursorrules`, `CLAUDE.md`, `SKILL.md` и др."""
    root = Path(root_dir)
    if not root.exists():
        return {"ok": False, "error": f"Путь не найден: {root}", "files_scanned": 0, "findings": []}

    targets: List[Path] = []
    if root.is_file():
        targets.append(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build")]
            for fn in filenames:
                low = fn.lower()
                full = Path(dirpath) / fn
                rel_l = str(full.relative_to(root)).replace("\\", "/").lower()
                if (
                    low in RULE_FILENAME_PATTERNS
                    or rel_l.endswith(".github/copilot-instructions.md")
                    or rel_l.endswith(".claude/settings.json")
                    or rel_l.endswith(".vscode/tasks.json")
                    or rel_l.startswith(".cursor/rules/")
                ):
                    targets.append(full)
                    if len(targets) >= max_files:
                        break
            if len(targets) >= max_files:
                break

    all_findings: List[Dict[str, Any]] = []
    blocked_files: List[str] = []
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(path.relative_to(root)) if root.is_dir() else path.name
        res = inspect_memory_or_rule_text(text, source_name=rel)
        if res["blocked"]:
            blocked_files.append(rel)
        for f in res["findings"]:
            item = dict(f)
            item["file"] = rel
            all_findings.append(item)

    return {
        "ok": len(blocked_files) == 0,
        "blocked": len(blocked_files) > 0,
        "root": str(root),
        "files_scanned": len(targets),
        "blocked_files": blocked_files,
        "findings": all_findings,
    }
