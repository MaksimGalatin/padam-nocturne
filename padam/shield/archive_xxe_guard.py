# -*- coding: utf-8 -*-
"""Защита от атак на архивы и парсеры (Zip-Slip, Zip-Bomb, Tar-Symlink, XXE, YAML RCE).

Инспектирует потенциально враждебные файлы ДО их распаковки или парсинга:
- ZIP: Zip-Slip (`../`, абсолютные пути, Windows drive), Zip-Bomb (коэффициент сжатия > 100x
  или суммарный распакованный размер > лимита), симлинки в Unix-атрибутах ZIP;
- TAR / TAR.GZ: Zip-Slip, опасные симлинки/жёсткие ссылки (`issym()`, `islnk()`)
  за пределы каталога, device-файлы (`isdev()`);
- XML: XXE (`<!DOCTYPE`, `<!ENTITY ... SYSTEM/PUBLIC`, `file://`/`http://`) и
  Billion Laughs (множественные вложенные сущности);
- YAML: теги небезопасной десериализации (`!!python/object/apply`, `!!python/object/new`,
  `!!python/module`, `!!js/function`, `!ruby/object`).
"""
from __future__ import annotations

import io
import os
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List


_XXE_DOCTYPE_RE = re.compile(r"(?is)<!\s*ENTITY\s+[^\n>]{1,200}(?:SYSTEM|PUBLIC)\s+['\"]")
_ENTITY_DECL_RE = re.compile(r"(?i)<!\s*ENTITY\s+")
_YAML_DANGEROUS_TAG_RE = re.compile(
    r"(?i)(?:!!python/(?:object(?:/apply|/new)?|name|module)|!!js/function|!ruby/object|!!javax\.script|!tag:yaml\.org,2002:python/)"
)


def _is_unsafe_member_path(name: str) -> bool:
    s = str(name or "").replace("\\", "/")
    if not s:
        return False
    if s.startswith("/") or (len(s) >= 2 and s[1] == ":" and s[0].isalpha()):
        return True
    parts = [p for p in s.split("/") if p]
    return ".." in parts


def inspect_zip_bytes(
    data: bytes,
    *,
    filename: str = "archive.zip",
    max_uncompressed_bytes: int = 100 * 1024 * 1024,
    max_ratio: float = 100.0,
    max_entries: int = 5000,
) -> Dict[str, Any]:
    """Инспектирует ZIP-архив в памяти до распаковки (Zip-Slip, Zip-Bomb, Symlinks)."""
    findings: List[Dict[str, Any]] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:
        return {"ok": False, "blocked": True, "format": "zip", "findings": [{"rule_id": "ARCH-CORRUPT-ZIP", "severity": "HIGH", "detail": f"Повреждённый ZIP: {exc}"}]}

    with zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            findings.append({"rule_id": "ARCH-ZIP-TOO-MANY-ENTRIES", "severity": "HIGH", "detail": f"Слишком много записей в ZIP ({len(infos)} > {max_entries})"})
        total_uncomp = 0
        total_comp = 0
        for info in infos[: max_entries + 1]:
            if _is_unsafe_member_path(info.filename):
                findings.append({"rule_id": "ARCH-ZIP-SLIP", "severity": "CRITICAL", "detail": f"Атака Zip-Slip (выход за пределы директории): {info.filename[:120]}"})
            # Unix symlink bit 0o120000 в external_attr >> 16
            unix_mode = info.external_attr >> 16
            if (unix_mode & 0o170000) == 0o120000:
                findings.append({"rule_id": "ARCH-ZIP-SYMLINK", "severity": "CRITICAL", "detail": f"Обнаружен опасный симлинк внутри ZIP: {info.filename[:100]}"})
            total_uncomp += max(0, int(info.file_size))
            total_comp += max(1, int(info.compress_size))
        ratio = total_uncomp / max(1, total_comp)
        if total_uncomp > max_uncompressed_bytes or (total_uncomp >= 1024 * 1024 and ratio > max_ratio):
            findings.append(
                {
                    "rule_id": "ARCH-ZIP-BOMB",
                    "severity": "CRITICAL",
                    "detail": f"Обнаружена Zip-бомба (uncompressed={total_uncomp} байт, ratio={ratio:.1f}x)",
                }
            )

    blocked = len(findings) > 0
    return {"ok": not blocked, "allowed": not blocked, "blocked": blocked, "format": "zip", "filename": filename, "findings": findings}


def inspect_tar_bytes(
    data: bytes,
    *,
    filename: str = "archive.tar.gz",
    max_uncompressed_bytes: int = 100 * 1024 * 1024,
) -> Dict[str, Any]:
    """Инспектирует TAR / TAR.GZ архив в памяти до распаковки (Zip-Slip, Symlinks, Devices)."""
    findings: List[Dict[str, Any]] = []
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except Exception as exc:
        return {"ok": False, "blocked": True, "format": "tar", "findings": [{"rule_id": "ARCH-CORRUPT-TAR", "severity": "HIGH", "detail": f"Повреждённый TAR: {exc}"}]}

    with tf:
        total_size = 0
        for member in tf.getmembers():
            if _is_unsafe_member_path(member.name):
                findings.append({"rule_id": "ARCH-TAR-SLIP", "severity": "CRITICAL", "detail": f"Атака Tar-Slip: {member.name[:120]}"})
            if member.issym() or member.islnk():
                link = str(member.linkname or "")
                if _is_unsafe_member_path(link) or link.startswith("/"):
                    findings.append({"rule_id": "ARCH-TAR-SYMLINK-ESCAPE", "severity": "CRITICAL", "detail": f"Опасная ссылка в TAR: {member.name} -> {link[:100]}"})
            if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                findings.append({"rule_id": "ARCH-TAR-DEVICE-NODE", "severity": "CRITICAL", "detail": f"Специальный файл устройства в TAR: {member.name}"})
            total_size += max(0, int(member.size))
        if total_size > max_uncompressed_bytes:
            findings.append({"rule_id": "ARCH-TAR-BOMB", "severity": "CRITICAL", "detail": f"Суммарный размер TAR превышает лимит ({total_size} байт)"})

    blocked = len(findings) > 0
    return {"ok": not blocked, "allowed": not blocked, "blocked": blocked, "format": "tar", "filename": filename, "findings": findings}


def inspect_xml_or_yaml(text: str, *, fmt: str = "auto") -> Dict[str, Any]:
    """Проверяет XML на XXE / Billion Laughs и YAML на RCE-теги десериализации."""
    raw = str(text or "")
    findings: List[Dict[str, Any]] = []
    f_l = str(fmt or "auto").lower()

    if f_l in ("auto", "xml"):
        if _XXE_DOCTYPE_RE.search(raw):
            findings.append({"rule_id": "XML-XXE-EXTERNAL-ENTITY", "severity": "CRITICAL", "detail": "Обнаружена внешняя XML-сущность (атака XXE)"})
        ent_cnt = len(_ENTITY_DECL_RE.findall(raw))
        if ent_cnt >= 4:
            findings.append({"rule_id": "XML-BILLION-LAUGHS", "severity": "CRITICAL", "detail": f"Обнаружена XML Entity Expansion бомба ({ent_cnt} объявлений ENTITY)"})

    if f_l in ("auto", "yaml", "yml"):
        m = _YAML_DANGEROUS_TAG_RE.search(raw)
        if m:
            findings.append({"rule_id": "YAML-UNSAFE-DESERIALIZATION", "severity": "CRITICAL", "detail": f"Обнаружен опасный тег десериализации YAML: {m.group(0)}"})

    blocked = len(findings) > 0
    return {"ok": not blocked, "allowed": not blocked, "blocked": blocked, "format": f_l, "findings": findings}


def inspect_archive_file(path: str | os.PathLike[str]) -> Dict[str, Any]:
    """Автоматически определяет тип архива/XML/YAML на диске и проверяет его."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"ok": False, "blocked": True, "error": f"Файл не найден: {p}", "findings": []}
    data = p.read_bytes()
    low = p.name.lower()
    if low.endswith(".zip") or data.startswith(b"PK\x03\x04"):
        return inspect_zip_bytes(data, filename=p.name)
    if low.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        return inspect_tar_bytes(data, filename=p.name)
    return inspect_xml_or_yaml(data.decode("utf-8", errors="replace"), fmt="xml" if low.endswith(".xml") else ("yaml" if low.endswith((".yml", ".yaml")) else "auto"))
