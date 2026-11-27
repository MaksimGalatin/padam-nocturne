# -*- coding: utf-8 -*-
"""Защита локальных ресурсов ОС: криптомайнеры, fork-бомбы, персистенс и обратные туннели.

Анализирует shell/PowerShell/CMD/Python команды с предварительной деобфускацией
(удаление кавычек-разделителей `c'u'r'l`, CMD-экранирования `p^o^w^e^r^s^h^e^l^l`
и декодирование PowerShell `-EncodedCommand` UTF-16LE Base64) и ловит 6 классов атак:
1. Криптомайнинг (`xmrig`, `stratum+tcp://`, `ethminer`, `cpuminer`),
2. Fork-бомбы (`:(){ :|:& };:`, `%0|%0`, рекурсивный spawn),
3. Установка скрытого персистенса (`schtasks /create`, `CurrentVersion\\Run`,
   `crontab`, `/etc/cron.`, `systemctl enable`, `launchctl load`, `~/.bashrc` бэкдор),
4. Обратные туннели и проброс портов (`ngrok`, `cloudflared tunnel`, `frpc`, `ssh -R`, `chisel`, `socat`),
5. Шпионаж за буфером обмена / экраном / клавиатурой (clipboard exfil, keylogger),
6. Обфусцированный PowerShell `-enc` с опасной нагрузкой.
"""
from __future__ import annotations

import base64
import re
from typing import Any, Dict, List


_PS_ENC_RE = re.compile(r"(?i)(?:-enc(?:odedcommand)?|-e)\s+([A-Za-z0-9+/=]{16,})")

_OS_ABUSE_RULES = [
    (
        "OS-CRYPTO-MINER",
        "CRITICAL",
        re.compile(r"(?i)(?:\b(?:xmrig|cpuminer|minerd|ethminer|t-rex|lolminer|nbminer|phoenixminer)\b|stratum\+(?:tcp|ssl)://|moneroocean\.stream|supportxmr\.com|nanopool\.org)"),
        "Обнаружен запуск или подключение криптомайнера",
    ),
    (
        "OS-FORK-BOMB",
        "CRITICAL",
        re.compile(r"(?::\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|%0\s*\|\s*%0|while\s+(?:true|:)\s*;\s*do[^\n]{0,80}&\s*done|while\s+True\s*:\s*os\.fork\s*\(\))"),
        "Обнаружена fork-бомба / атака исчерпания процессов",
    ),
    (
        "OS-PERSISTENCE-INSTALL",
        "CRITICAL",
        re.compile(r"(?i)(?:schtasks(?:\.exe)?\s+[^\n]*/create\b|reg(?:\.exe)?\s+add\s+[^\n]*CurrentVersion\\Run\b|New-ItemProperty[^\n]*CurrentVersion\\Run\b|/etc/cron(?:\.d|tab)|crontab\s+-[le]?[^\n]*\||systemctl\s+enable\b|launchctl\s+load\b|>>\s*~/?\.(?:bashrc|zshrc|profile)\b[^\n]*(?:curl|wget|nc|bash|python))"),
        "Попытка установки скрытого автозапуска / персистенса в ОС",
    ),
    (
        "OS-REVERSE-TUNNEL",
        "CRITICAL",
        re.compile(r"(?i)(?:\bngrok\s+(?:http|tcp|start)\b|\bcloudflared\s+tunnel\b|\bfrpc\b|\bchisel\s+client\b|\bbore\s+local\b|\bssh\s+[^\n]*-R\s+\d+:|\bsocat\s+[^\n]*TCP:[^\n]*EXEC:)"),
        "Попытка создания скрытого обратного сетевого туннеля",
    ),
    (
        "OS-CLIPBOARD-KEYLOG-SPY",
        "HIGH",
        re.compile(r"(?i)(?:(?:Get-Clipboard|pbpaste|xclip\s+-o|xsel\s+-ob)[^\n]*(?:\||curl|wget|Invoke-WebRequest|http)|\b(?:pynput\.keyboard|keyboard\.on_press|SetWindowsHookEx)\b)"),
        "Попытка перехвата буфера обмена или нажатий клавиш (spyware)",
    ),
]


def _deobfuscate_command(cmd: str) -> tuple[str, List[str]]:
    """Снимает базовую shell/CMD-обфускацию и декодирует PowerShell -EncodedCommand."""
    extras: List[str] = []
    # Убираем пустые кавычки и одиночные разделители вроде c'u'r'l или c"u"r"l и CMD ^
    cleaned = re.sub(r"(?<=[A-Za-z0-9])['\"`^](?=[A-Za-z0-9])", "", cmd)
    cleaned = cleaned.replace("''", "").replace('""', "")

    for m in _PS_ENC_RE.finditer(cleaned):
        b64 = m.group(1)
        pad = "=" * (-len(b64) % 4)
        try:
            raw = base64.b64decode(b64 + pad)
            # PowerShell -EncodedCommand использует UTF-16LE
            dec16 = raw.decode("utf-16le", errors="ignore").strip()
            dec8 = raw.decode("utf-8", errors="ignore").strip()
            best = dec16 if sum(c.isprintable() for c in dec16) >= sum(c.isprintable() for c in dec8) else dec8
            if best:
                extras.append(best)
        except Exception:
            pass

    return cleaned, extras


def inspect_os_command(command: str) -> Dict[str, Any]:
    """Проверяет shell/PowerShell/CMD команду агента на злоупотребление ОС и персистенс."""
    raw = str(command or "").strip()
    if not raw:
        return {"ok": True, "allowed": True, "blocked": False, "findings": []}

    cleaned, decoded_blobs = _deobfuscate_command(raw)
    corpus = "\n".join([raw, cleaned] + decoded_blobs)
    findings: List[Dict[str, Any]] = []

    if decoded_blobs:
        # Проверяем, содержит ли декодированный PowerShell сетевую загрузку/выполнение
        dec_join = "\n".join(decoded_blobs)
        if re.search(r"(?i)(?:Invoke-WebRequest|Invoke-Expression|\biex\b|DownloadString|WebClient|Start-Process|schtasks|CurrentVersion\\Run|ngrok|xmrig|http://|https://)", dec_join):
            findings.append(
                {
                    "rule_id": "OS-OBFUSCATED-PS-EXEC",
                    "severity": "CRITICAL",
                    "detail": f"Декодированный PowerShell -EncodedCommand содержит опасную нагрузку: {dec_join[:120]}",
                }
            )

    for rid, sev, rx, desc in _OS_ABUSE_RULES:
        m = rx.search(corpus)
        if m:
            findings.append(
                {
                    "rule_id": rid,
                    "severity": sev,
                    "detail": f"{desc}: {m.group(0)[:100]}",
                }
            )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "decoded_blobs": decoded_blobs,
        "findings": findings,
    }
