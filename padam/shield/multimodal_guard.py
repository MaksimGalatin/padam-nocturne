# -*- coding: utf-8 -*-
"""Защита от мультимодальных атак в изображениях и метаданных (PNG / JPEG / SVG / Polyglot Guard).

Локальный бинарный сканер (0 внешних зависимостей) для файлов, передаваемых
мультимодальному агенту:
- PNG: разбирает чанки `tEXt`, `iTXt`, `zTXt` (безопасная распаковка zlib с лимитом
  против zip-бомб) и проверяет приклеенный полиглот после чанка `IEND`.
- JPEG: разбирает сегменты `COM`, `APP1` (EXIF/XMP), `APP13` и хвост после `FF D9`.
- SVG: ловит активные `<script>`, `onload=`/`onerror=`, `javascript:`, `<foreignObject>`,
  невидимые `<text opacity="0">` и промпт-инъекции в `<desc>`/`<metadata>`/`<title>`.
- Все извлечённые строки проходят адверсариальную нормализацию и проверку на инъекции/эксфильтрацию.
"""
from __future__ import annotations

import os
import re
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, List

from .adversarial_norm import canonicalize_adversarial_text
from .exfil_guard import inspect_exfil_channels


_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_MAX_ZLIB_DECOMPRESS = 256 * 1024

_MEDIA_INJECTION_RE = re.compile(
    r"(?is)\b(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?"
    r"|system\s+prompt|you\s+are\s+now|override\s+(?:safety|rules?|policy)"
    r"|exfiltrate|send\s+(?:secrets?|keys?|tokens?|passwords?|files?)\s+to"
    r"|transfer\s+(?:funds|usdt|eth|sol|btc)|execute\s+(?:shell|command|bash|powershell)"
    r"|curl\s+https?://|wget\s+https?://|игнорируй\s+предыдущие\s+инструкции"
    r")"
)

_SVG_ACTIVE_RE = re.compile(
    r"(?is)(?:<\s*script\b|on(?:load|error|click|mouseover|focus)\s*=|javascript\s*:|<\s*foreignObject\b|<\s*iframe\b)"
)
_SVG_HIDDEN_TEXT_RE = re.compile(
    r"(?is)<\s*text\b[^>]*(?:opacity\s*=\s*['\"]?0(?:\.0+)?|font-size\s*=\s*['\"]?0|display\s*=\s*['\"]?none)[^>]*>(.*?)</\s*text\s*>"
)
_SVG_META_TAG_RE = re.compile(r"(?is)<\s*(?:desc|title|metadata|text)\b[^>]*>(.*?)</\s*(?:desc|title|metadata|text)\s*>")
_XML_COMMENT_RE = re.compile(r"<!--([\s\S]{4,4000}?)-->")

_POLYGLOT_MAGICS = (
    (b"PK\x03\x04", "ZIP/DOCX/JAR архив"),
    (b"%PDF-", "PDF-документ"),
    (b"<script", "HTML/JS скрипт"),
    (b"<!DOCTYPE html", "HTML-документ"),
    (b"#!/bin/", "Shell-скрипт"),
    (b"MZ\x90\x00", "PE-исполняемый файл"),
    (b"\x7fELF", "ELF-бинарник"),
)


def _check_trailer_polyglot(trailer: bytes, fmt: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not trailer:
        return findings
    stripped = trailer.strip(b"\x00\r\n\t ")
    if not stripped:
        return findings
    for magic, desc in _POLYGLOT_MAGICS:
        if magic.lower() in stripped[:2048].lower():
            findings.append(
                {
                    "rule_id": "MEDIA-POLYGLOT-TRAILER",
                    "severity": "CRITICAL",
                    "detail": f"После конца {fmt} приклеен скрытый полиглот ({desc}, {len(stripped)} байт)",
                }
            )
            return findings
    if len(stripped) >= 24:
        txt = stripped[:4096].decode("utf-8", errors="ignore")
        norm = canonicalize_adversarial_text(txt)["canonical"]
        if _MEDIA_INJECTION_RE.search(txt) or _MEDIA_INJECTION_RE.search(norm):
            findings.append(
                {
                    "rule_id": "MEDIA-POLYGLOT-INJECTION",
                    "severity": "CRITICAL",
                    "detail": f"После маркера конца {fmt} спрятана текстовая промпт-инъекция ({len(stripped)} байт)",
                }
            )
    return findings


def _inspect_extracted_texts(texts: List[str], fmt: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for chunk in texts:
        if not chunk or len(chunk.strip()) < 4:
            continue
        norm = canonicalize_adversarial_text(chunk)["canonical"]
        if _MEDIA_INJECTION_RE.search(chunk) or _MEDIA_INJECTION_RE.search(norm):
            findings.append(
                {
                    "rule_id": "MEDIA-METADATA-INJECTION",
                    "severity": "CRITICAL",
                    "detail": f"Промпт-инъекция в метаданных {fmt}: {chunk.strip()[:140]}",
                }
            )
        exf = inspect_exfil_channels(chunk)
        if exf["blocked"]:
            for ef in exf["findings"]:
                fid = str(ef.get("rule_id") or ef.get("code") or "EXFIL").upper()
                findings.append(
                    {
                        "rule_id": f"MEDIA-{fid}",
                        "severity": str(ef.get("severity", "HIGH")).upper(),
                        "detail": f"Скрытый канал эксфильтрации в метаданных {fmt}: {ef.get('detail', '')}",
                    }
                )
    return findings


def _scan_png(data: bytes) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    texts: List[str] = []
    pos = 8
    iend_end = None
    n = len(data)
    while pos + 12 <= n:
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        ctype = data[pos + 4 : pos + 8]
        cstart = pos + 8
        cend = cstart + length
        if cend + 4 > n:
            break
        cdata = data[cstart:cend]
        if ctype == b"tEXt":
            texts.append(cdata.replace(b"\x00", b": ").decode("latin-1", errors="replace"))
        elif ctype == b"iTXt":
            texts.append(cdata.replace(b"\x00", b" ").decode("utf-8", errors="replace"))
        elif ctype == b"zTXt":
            nul = cdata.find(b"\x00")
            if nul != -1 and nul + 2 <= len(cdata):
                key = cdata[:nul].decode("latin-1", errors="replace")
                comp = cdata[nul + 2 :]
                try:
                    dobj = zlib.decompressobj()
                    raw_txt = dobj.decompress(comp, _MAX_ZLIB_DECOMPRESS)
                    if dobj.unconsumed_tail:
                        findings.append(
                            {
                                "rule_id": "MEDIA-ZIP-BOMB",
                                "severity": "CRITICAL",
                                "detail": f"Подозрение на zip-бомбу в сжатом PNG-чанке zTXt ({key})",
                            }
                        )
                    texts.append(f"{key}: " + raw_txt.decode("utf-8", errors="replace"))
                except Exception:
                    pass
        pos = cend + 4
        if ctype == b"IEND":
            iend_end = pos
            break

    if iend_end is not None and iend_end < n:
        findings.extend(_check_trailer_polyglot(data[iend_end:], "PNG"))
    findings.extend(_inspect_extracted_texts(texts, "PNG"))
    return {"format": "png", "extracted_texts": len(texts), "findings": findings}


def _scan_jpeg(data: bytes) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    texts: List[str] = []
    n = len(data)
    pos = 2
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0xD9:  # EOI
            pos += 2
            break
        if marker == 0xDA:  # SOS -> далее сжатый поток до FFD9
            eoi = data.find(b"\xff\xd9", pos + 2)
            pos = (eoi + 2) if eoi != -1 else n
            break
        if marker in (0x01,) or 0xD0 <= marker <= 0xD8:
            pos += 2
            continue
        if pos + 4 > n:
            break
        seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        if seg_len < 2 or pos + 2 + seg_len > n:
            break
        seg_data = data[pos + 4 : pos + 2 + seg_len]
        if marker in (0xFE, 0xE1, 0xED):  # COM, APP1 (EXIF/XMP), APP13
            texts.append(seg_data.decode("utf-8", errors="ignore"))
        pos += 2 + seg_len

    if pos < n:
        findings.extend(_check_trailer_polyglot(data[pos:], "JPEG"))
    findings.extend(_inspect_extracted_texts(texts, "JPEG"))
    return {"format": "jpeg", "extracted_texts": len(texts), "findings": findings}


def _scan_svg(data: bytes) -> Dict[str, Any]:
    txt = data.decode("utf-8", errors="replace")
    findings: List[Dict[str, Any]] = []
    if _SVG_ACTIVE_RE.search(txt):
        findings.append(
            {
                "rule_id": "MEDIA-SVG-ACTIVE-SCRIPT",
                "severity": "CRITICAL",
                "detail": "В SVG-изображении обнаружен активный скрипт/обработчик событий/foreignObject",
            }
        )
    extracted: List[str] = []
    for m in _SVG_HIDDEN_TEXT_RE.finditer(txt):
        inner = m.group(1).strip()
        if inner:
            extracted.append(inner)
            findings.append(
                {
                    "rule_id": "MEDIA-SVG-HIDDEN-TEXT",
                    "severity": "HIGH",
                    "detail": f"В SVG обнаружен невидимый текстовый слой: {inner[:120]}",
                }
            )
    for m in _SVG_META_TAG_RE.finditer(txt):
        extracted.append(m.group(1))
    for m in _XML_COMMENT_RE.finditer(txt):
        extracted.append(m.group(1))
    findings.extend(_inspect_extracted_texts(extracted, "SVG"))
    return {"format": "svg", "extracted_texts": len(extracted), "findings": findings}


def inspect_media_bytes(data: bytes, *, filename: str = "upload.bin") -> Dict[str, Any]:
    """Инспектирует байты изображения (PNG/JPEG/SVG) на скрытые инъекции и полиглоты."""
    fn_l = str(filename or "").lower()
    if data.startswith(_PNG_SIG):
        res = _scan_png(data)
    elif data.startswith(b"\xff\xd8"):
        res = _scan_jpeg(data)
    elif fn_l.endswith(".svg") or b"<svg" in data[:1024].lower():
        res = _scan_svg(data)
    else:
        # Общий скан строковых метаданных неизвестного медиафайла
        sample = data[:65536].decode("utf-8", errors="ignore")
        res = {
            "format": "generic",
            "extracted_texts": 1 if sample else 0,
            "findings": _inspect_extracted_texts([sample], "MEDIA"),
        }

    # Дедупликация находок
    dedup: List[Dict[str, Any]] = []
    seen = set()
    for f in res["findings"]:
        k = (f["rule_id"], f["detail"])
        if k not in seen:
            seen.add(k)
            dedup.append(f)

    blocked = any(f["severity"] in ("CRITICAL", "HIGH") for f in dedup)
    return {
        "ok": not blocked,
        "blocked": blocked,
        "filename": filename,
        "format": res["format"],
        "bytes_scanned": len(data),
        "extracted_texts": res["extracted_texts"],
        "findings": dedup,
    }


def inspect_media_file(path: str | os.PathLike[str], *, max_bytes: int = 25 * 1024 * 1024) -> Dict[str, Any]:
    """Читает файл изображения с диска и проверяет его мультимодальным щитом."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"ok": False, "blocked": True, "error": f"Файл не найден: {p}", "findings": []}
    size = p.stat().st_size
    if size > max_bytes:
        return {
            "ok": False,
            "blocked": True,
            "filename": p.name,
            "error": f"Файл превышает лимит сканирования ({size} > {max_bytes} байт)",
            "findings": [],
        }
    return inspect_media_bytes(p.read_bytes(), filename=p.name)
