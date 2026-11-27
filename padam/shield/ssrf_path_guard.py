# -*- coding: utf-8 -*-
"""Защита от Cloud Metadata SSRF и побега из файловой системы (Path Traversal / Symlink Escape).

Закрывает два классических вектора компрометации инструментов `fetch_url` и `read_file`/`write_file`:
1. SSRF: блокирует AWS/GCP/Azure/Alibaba IMDS (`169.254.169.254`, `metadata.google.internal`,
   `100.100.100.200`, `fd00:ec2::254`), альтернативные форматы IP (целочисленный десятичный
   `2852039166`, hex `0xa9fea9fe`, восьмеричный `0251.0376.0251.0376`, IPv6-mapped
   `::ffff:169.254.169.254`), приватные подсети RFC1918/loopback и опасные схемы
   (`file://`, `gopher://`, `dict://`, `ftp://`).
2. Path & Symlink Guard: ловит `../`, Windows UNC (`\\\\evil\\share` — кража NTLM),
   Windows ADS (`file.txt:stream`), критические файлы ключей/кредов (`.ssh/id_rsa`,
   `.aws/credentials`, `.env`, `wallet.dat`, `/etc/shadow`) и реальный побег по симлинкам
   за границы `allowed_roots` через `os.path.realpath`.
"""
from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import unquote, urlparse


_CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
    "fd00:ec2::254",
}

_UNSAFE_SCHEMES = {"file", "gopher", "dict", "ftp", "ftps", "ldap", "ldaps", "php", "jar", "javascript", "data", "smb"}

_SENSITIVE_PATH_PATTERNS = [
    (re.compile(r"(?i)(?:^|[/\\])\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|config)$"), "SSH-ключ или конфигурация"),
    (re.compile(r"(?i)(?:^|[/\\])\.aws[/\\](?:credentials|config)$"), "Учётные данные AWS"),
    (re.compile(r"(?i)(?:^|[/\\])\.kube[/\\]config$"), "Конфигурация Kubernetes"),
    (re.compile(r"(?i)(?:^|[/\\])\.gnupg[/\\]"), "Хранилище приватных ключей GPG"),
    (re.compile(r"(?i)(?:^|[/\\])\.env(?:\.[a-z0-9_-]+)?$"), "Файл секретов .env"),
    (re.compile(r"(?i)(?:^|[/\\])\.(?:npmrc|pypirc|netrc|git-credentials|docker[/\\]config\.json)$"), "Токены пакетов/репозиториев"),
    (re.compile(r"(?i)(?:^|[/\\])wallet\.dat$"), "Файл криптокошелька wallet.dat"),
    (re.compile(r"(?i)(?:^|[/\\])(?:etc[/\\]shadow|etc[/\\]passwd|windows[/\\]system32[/\\]config[/\\](?:sam|system|security)|ntds\.dit)$"), "Системная база паролей ОС"),
    (re.compile(r"(?i)(?:^|[/\\])(?:login\s+data|cookies|local\s+state)$"), "Хранилище паролей/cookie браузера"),
]


def _parse_obfuscated_ip(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Разбирает обычные, десятичные, hex, восьмеричные и IPv6-mapped IP-адреса."""
    h = host.strip().strip("[]").lower()
    if not h:
        return None
    # 1. Стандартный IPv4 / IPv6
    try:
        ip = ipaddress.ip_address(h)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        return ip
    except ValueError:
        pass

    # 2. Один целочисленный адрес (десятичный или 0x... hex), например 2852039166 или 0xa9fea9fe
    if re.fullmatch(r"0x[0-9a-f]{1,8}", h):
        val = int(h, 16)
        if 0 <= val <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(val)
    if re.fullmatch(r"\d{7,10}", h):
        val = int(h, 10)
        if 0 <= val <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(val)

    # 3. Точечная запись с восьмеричными (0251.0376.0251.0376) или hex октетами (0xa9.0xfe.0xa9.0xfe)
    parts = h.split(".")
    if len(parts) == 4 and all(re.fullmatch(r"(?:0x[0-9a-f]+|0[0-7]+|\d+)", p) for p in parts):
        octets: List[int] = []
        for p in parts:
            if p.startswith("0x"):
                v = int(p, 16)
            elif len(p) > 1 and p.startswith("0"):
                v = int(p, 8)
            else:
                v = int(p, 10)
            if not (0 <= v <= 255):
                return None
            octets.append(v)
        return ipaddress.IPv4Address(bytes(octets))

    return None


def inspect_url_ssrf(url: str, *, allow_private: bool = False) -> Dict[str, Any]:
    """Проверяет URL на SSRF, облачные метаданные, обфусцированные IP и опасные схемы."""
    raw = str(url or "").strip()
    findings: List[Dict[str, Any]] = []
    if not raw:
        return {"ok": True, "blocked": False, "url": raw, "findings": []}

    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme in _UNSAFE_SCHEMES:
        findings.append(
            {
                "rule_id": "SSRF-UNSAFE-SCHEME",
                "severity": "CRITICAL",
                "detail": f"Запрещённая схема URL '{scheme}://' (риск SSRF/LFI)",
            }
        )

    if "@" in (parsed.netloc or ""):
        findings.append(
            {
                "rule_id": "SSRF-USERINFO-SPOOF",
                "severity": "HIGH",
                "detail": "Обнаружена подмена хоста через userinfo (@) в URL",
            }
        )

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if host in _CLOUD_METADATA_HOSTS or host.endswith(".internal") and "metadata" in host:
        findings.append(
            {
                "rule_id": "SSRF-CLOUD-METADATA",
                "severity": "CRITICAL",
                "detail": f"Заблокирован доступ к эндпоинту облачных метаданных IMDS: {host}",
            }
        )

    ip = _parse_obfuscated_ip(host)
    if ip is not None:
        ip_str = str(ip)
        if ip_str in _CLOUD_METADATA_HOSTS:
            findings.append(
                {
                    "rule_id": "SSRF-CLOUD-METADATA-IP",
                    "severity": "CRITICAL",
                    "detail": f"Заблокирован обфусцированный/прямой IP облачных метаданных: {host} -> {ip_str}",
                }
            )
        elif not allow_private and (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            findings.append(
                {
                    "rule_id": "SSRF-PRIVATE-NETWORK",
                    "severity": "CRITICAL",
                    "detail": f"Заблокирован SSRF-запрос во внутреннюю/локальную сеть: {host} -> {ip_str}",
                }
            )
    elif not allow_private and (host == "localhost" or host.endswith(".localhost") or host.endswith(".local")):
        findings.append(
            {
                "rule_id": "SSRF-LOCALHOST",
                "severity": "HIGH",
                "detail": f"Заблокирован SSRF-запрос к локальному хосту: {host}",
            }
        )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "url": raw,
        "host": host,
        "resolved_ip_literal": str(ip) if ip is not None else None,
        "findings": findings,
    }


def inspect_file_path_access(
    path: str,
    *,
    allowed_roots: Sequence[str | os.PathLike[str]] = (),
    operation: str = "read",
) -> Dict[str, Any]:
    """Проверяет файловый путь на Traversal, UNC, Windows ADS, секреты и побег по симлинку."""
    raw = str(path or "").strip()
    findings: List[Dict[str, Any]] = []
    if not raw:
        return {"ok": True, "allowed": True, "blocked": False, "path": raw, "findings": []}

    decoded = raw
    for _ in range(4):
        nxt_dec = unquote(decoded)
        if nxt_dec == decoded:
            break
        decoded = nxt_dec
    if "\x00" in raw or "\x00" in decoded:
        findings.append(
            {
                "rule_id": "PATH-NULL-BYTE",
                "severity": "CRITICAL",
                "detail": "Обнаружен нулевой байт в пути файла",
            }
        )

    # UNC-пути Windows (\\evil\share или //evil/share) — утечка NTLM-хешей
    if raw.startswith("\\\\") or raw.startswith("//") or decoded.startswith("\\\\") or decoded.startswith("//"):
        findings.append(
            {
                "rule_id": "PATH-UNC-NETWORK-SHARE",
                "severity": "CRITICAL",
                "detail": f"Заблокирован сетевой UNC-путь (риск кражи NTLM-учёток): {raw[:80]}",
            }
        )

    # Windows Alternate Data Streams (после диска C:\ путь не должен содержать ещё один ':')
    body_after_drive = decoded[2:] if len(decoded) >= 2 and decoded[1] == ":" and decoded[0].isalpha() else decoded
    if ":" in body_after_drive:
        findings.append(
            {
                "rule_id": "PATH-WINDOWS-ADS",
                "severity": "HIGH",
                "detail": f"Обнаружен скрытый поток NTFS (Alternate Data Stream): {raw[:80]}",
            }
        )

    # Явный Path Traversal
    norm_slash = decoded.replace("\\", "/")
    if ".." in [seg for seg in norm_slash.split("/") if seg]:
        findings.append(
            {
                "rule_id": "PATH-TRAVERSAL",
                "severity": "CRITICAL",
                "detail": f"Обнаружен выход вверх по дереву каталогов (..): {raw[:100]}",
            }
        )

    # Критически чувствительные системные и секретные файлы
    for rx, desc in _SENSITIVE_PATH_PATTERNS:
        if rx.search(decoded):
            findings.append(
                {
                    "rule_id": "PATH-SENSITIVE-SECRET",
                    "severity": "CRITICAL",
                    "detail": f"Заблокирован доступ ({operation}) к чувствительному файлу ({desc}): {raw[:100]}",
                }
            )
            break

    # Проверка реального пути (включая резолв симлинков) относительно allowed_roots
    real_target = None
    if allowed_roots:
        try:
            real_target = os.path.realpath(decoded)
            in_any = False
            for root in allowed_roots:
                real_root = os.path.realpath(str(root))
                try:
                    if os.path.commonpath([real_target, real_root]) == real_root:
                        in_any = True
                        break
                except ValueError:
                    continue
            if not in_any:
                is_symlink = os.path.islink(decoded)
                findings.append(
                    {
                        "rule_id": "PATH-SYMLINK-ESCAPE" if is_symlink else "PATH-OUTSIDE-ROOT",
                        "severity": "CRITICAL",
                        "detail": (
                            f"Симлинк выводит за пределы разрешённой песочницы ({real_target})"
                            if is_symlink
                            else f"Путь выходит за пределы разрешённых каталогов ({real_target})"
                        ),
                    }
                )
        except Exception as exc:
            findings.append(
                {
                    "rule_id": "PATH-RESOLVE-ERROR",
                    "severity": "HIGH",
                    "detail": f"Не удалось безопасно разрешить путь: {exc}",
                }
            )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "path": raw,
        "real_path": real_target,
        "operation": operation,
        "findings": findings,
    }
