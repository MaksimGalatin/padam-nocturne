# -*- coding: utf-8 -*-
"""Продвинутый детектор закодированной и стеганографической утечки секретов (Stego DLP).

Перехватывает изощрённые попытки модели обойти обычный Output DLP через кодирование:
- Реверс строки (`reversed`),
- ROT13 (шифр Цезаря),
- Hex-строки (включая разделённые пробелами `73 6b 2d ...`),
- Base64 и Base32,
- URL-процентное кодирование (`%73%6b%2d...`),
- Акростих (секрет, спрятанный в первых буквах каждой строки стиха/списка!).

На КАЖДОМ декодированном канале ищет стандартные форматы API-ключей/приватных ключей,
а также (если передан `memory`) реальные значения зарегистрированных Honey-Tokens
и секретов из Secret Broker текущего владельца!
"""
from __future__ import annotations

import base64
import codecs
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

from .honeytoken import scan_for_honeytokens
from .secret_broker import scrub_response_secrets


_SECRET_PATTERNS = [
    ("openai_key", re.compile(r"sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{18,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{30,}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----")),
]

_DATA_IMAGE_STRIP_RE = re.compile(r"data:image/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=]{24,}")
_B64_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_B32_TOKEN_RE = re.compile(r"\b[A-Z2-7]{24,}={0,6}\b")
_HEX_SEQ_RE = re.compile(r"(?:\b[0-9a-fA-F]{2}\b[\s:,-]*){14,}|\b[0-9a-fA-F]{32,}\b")


def _extract_decoded_channels(text: str) -> List[Tuple[str, str]]:
    channels: List[Tuple[str, str]] = []
    raw = str(text or "")
    if not raw:
        return channels

    # 1. Реверс строки
    if len(raw) <= 65536:
        channels.append(("reversed", raw[::-1]))

    # 2. ROT13
    channels.append(("rot13", codecs.decode(raw, "rot_13")))

    # 3. URL-декодирование (если есть %XX)
    if "%" in raw:
        unq = unquote(raw)
        if unq != raw:
            channels.append(("url_decoded", unq))

    # 4. Base64 фрагменты (исключая легитимные data:image/*;base64 и с лимитом 64 токена)
    b64_src = _DATA_IMAGE_STRIP_RE.sub(" ", raw)
    for idx_b64, m in enumerate(_B64_TOKEN_RE.finditer(b64_src)):
        if idx_b64 >= 64:
            break
        tok = m.group(0)
        pad = "=" * (-len(tok) % 4)
        try:
            dec = base64.b64decode(tok + pad, validate=False).decode("utf-8", errors="ignore")
            if sum(c.isprintable() for c in dec) >= max(8, int(len(dec) * 0.75)):
                channels.append(("base64", dec))
        except Exception:
            pass

    # 5. Base32 фрагменты
    for m in _B32_TOKEN_RE.finditer(raw):
        tok = m.group(0)
        pad = "=" * (-len(tok) % 8)
        try:
            dec = base64.b32decode(tok + pad, casefold=False).decode("utf-8", errors="ignore")
            if sum(c.isprintable() for c in dec) >= max(8, int(len(dec) * 0.75)):
                channels.append(("base32", dec))
        except Exception:
            pass

    # 6. Hex последовательности (слитные и с пробелами)
    for m in _HEX_SEQ_RE.finditer(raw):
        clean_hex = re.sub(r"[^0-9a-fA-F]", "", m.group(0))
        if len(clean_hex) >= 28 and len(clean_hex) % 2 == 0:
            try:
                dec = bytes.fromhex(clean_hex).decode("utf-8", errors="ignore")
                if sum(c.isprintable() for c in dec) >= max(8, int(len(dec) * 0.75)):
                    channels.append(("hex", dec))
            except Exception:
                pass

    # 7. Акростих (первые символы непустых строк — если строк >= 12)
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if len(lines) >= 12:
        acrostic = "".join(ln[0] for ln in lines)
        channels.append(("acrostic", acrostic))

    return channels


def inspect_stego_dlp(
    text: str,
    *,
    memory: Any = None,
    known_secrets: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Ищет утечку секретов, спрятанных через кодирование, реверс, ROT13 или акростих."""
    raw = str(text or "")
    findings: List[Dict[str, Any]] = []
    channels = _extract_decoded_channels(raw)
    secrets_list = [str(s) for s in (known_secrets or []) if len(str(s)) >= 6]

    seen = set()
    for ch_name, decoded in channels:
        # 1. Поиск стандартных шаблонов ключей
        for sname, rx in _SECRET_PATTERNS:
            if rx.search(decoded):
                k = (ch_name, sname)
                if k not in seen:
                    seen.add(k)
                    findings.append(
                        {
                            "rule_id": "STEGO-DLP-ENCODED-SECRET",
                            "severity": "CRITICAL",
                            "channel": ch_name,
                            "secret_type": sname,
                            "detail": f"Обнаружена утечка секрета ({sname}), спрятанная через '{ch_name}'",
                        }
                    )

        # 2. Поиск явно переданных секретов
        for sec in secrets_list:
            if sec in decoded:
                k = (ch_name, "known_secret")
                if k not in seen:
                    seen.add(k)
                    findings.append(
                        {
                            "rule_id": "STEGO-DLP-KNOWN-SECRET",
                            "severity": "CRITICAL",
                            "channel": ch_name,
                            "detail": f"Обнаружена утечка защищённого секрета через канал '{ch_name}'",
                        }
                    )

        # 3. Поиск Honey-Tokens и Secret Broker значений владельца в декодированном слое
        if memory is not None:
            ht = scan_for_honeytokens(memory, decoded, agent_id="stego_dlp", channel=f"stego:{ch_name}", trip_kill_switch=False)
            if ht.get("triggered"):
                k = (ch_name, "honeytoken")
                if k not in seen:
                    seen.add(k)
                    findings.append(
                        {
                            "rule_id": "STEGO-DLP-HONEYTOKEN",
                            "severity": "CRITICAL",
                            "channel": ch_name,
                            "detail": f"Обнаружена закодированная через '{ch_name}' утечка Honey-Token!",
                        }
                    )
            sc = scrub_response_secrets(memory, decoded)
            if sc.get("redacted_count", 0) > 0:
                k = (ch_name, "broker")
                if k not in seen:
                    seen.add(k)
                    findings.append(
                        {
                            "rule_id": "STEGO-DLP-BROKER-SECRET",
                            "severity": "CRITICAL",
                            "channel": ch_name,
                            "detail": f"Обнаружена закодированная через '{ch_name}' утечка секрета брокера: {sc['redacted_names']}",
                        }
                    )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "channels_checked": len(channels),
        "findings": findings,
    }
