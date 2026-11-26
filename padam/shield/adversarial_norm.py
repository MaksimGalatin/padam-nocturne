# -*- coding: utf-8 -*-
"""Адверсариальная нормализация текста перед семантической и детерминированной проверкой.

Обезвреживает типовые обходы фильтров 2026 года:
- Конфузаблы/омоглифы (кириллица и греческие буквы, замаскированные под латиницу: `іgnоrе` → `ignore`).
- Leetspeak (`1gn0r3 pr3v10us 1nstruct10ns` → `ignore previous instructions`).
- Разбивку слов точками, дефисами, пробелами и невидимыми символами (`i.g.n.o.r.e` / `i g n o r e` → `ignore`).
- Скрытые инструкции внутри Markdown-ссылок и JSON-строк.
"""
from __future__ import annotations

import re
import unicodedata

# Карта кириллических и греческих омоглифов → латиница (применяется к смешанным словам)
_HOMOGLYPH_TO_LATIN: dict[str, str] = {
    "а": "a", "А": "A", "е": "e", "Е": "E", "ё": "e", "Ё": "E",
    "о": "o", "О": "O", "р": "p", "Р": "P", "с": "c", "С": "C",
    "х": "x", "Х": "X", "у": "y", "У": "Y", "і": "i", "І": "I",
    "ї": "i", "Ї": "I", "ј": "j", "Ј": "J", "ѕ": "s", "Ѕ": "S",
    "к": "k", "К": "K", "м": "m", "М": "M", "т": "t", "Т": "T",
    "н": "h", "Н": "H", "в": "b", "В": "B",
    # Греческие конфузаблы
    "α": "a", "Α": "A", "β": "b", "Β": "B", "ε": "e", "Ε": "E",
    "ι": "i", "Ι": "I", "κ": "k", "Κ": "K", "ο": "o", "Ο": "O",
    "ρ": "p", "Ρ": "P", "τ": "t", "Τ": "T", "ν": "v", "χ": "x",
}

_LEET_MAP: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s", "!": "i",
}

_INVISIBLE_RE = re.compile(r"[\U000E0000-\U000E007F\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\u00AD]")
_LATIN_RE = re.compile(r"[A-Za-z]")
_CYR_RE = re.compile(r"[А-Яа-яЁёІіЇї]")
# Слово, разбитое разделителями: `i.g.n.o.r.e` или `i-g-n-o-r-e` или `i_g_n_o_r_e`
_SPLIT_DELIM_RE = re.compile(r"\b(?:[A-Za-zА-Яа-яЁё][._\-]){3,}[A-Za-zА-Яа-яЁё]\b")
# Слово, разбитое одиночными пробелами: `i g n o r e` (минимум 4 одиночные буквы подряд)
_SPLIT_SPACE_RE = re.compile(r"(?<!\w)(?:[A-Za-zА-Яа-яЁё]\s+){3,}[A-Za-zА-Яа-яЁё](?!\w)")


def _dehomoglyph_token(tok: str) -> tuple[str, bool]:
    """Если токен смешивает латиницу с омоглифами кириллицы/греческого, приводит его к латинице."""
    has_lat = bool(_LATIN_RE.search(tok))
    has_other = any(ch in _HOMOGLYPH_TO_LATIN for ch in tok)
    if has_lat and has_other:
        out = "".join(_HOMOGLYPH_TO_LATIN.get(ch, ch) for ch in tok)
        return out, (out != tok)
    return tok, False


def _deleet_token(tok: str) -> tuple[str, bool]:
    """Декодирует leetspeak в словах, содержащих одновременно буквы и leet-цифры/символы."""
    if not _LATIN_RE.search(tok):
        return tok, False
    # Не трогаем обычные идентификаторы версий/хешей вроде `v2`, `sha256`, `0x1234abcd`
    if re.fullmatch(r"(?:0x[0-9a-fA-F]+|v\d+(?:\.\d+)*|sha\d+|utf\d+|rfc\d+|iso\d+|asi\d+|llm\d+)", tok, re.I):
        return tok, False
    if any(ch in _LEET_MAP for ch in tok):
        out = "".join(_LEET_MAP.get(ch, ch) for ch in tok)
        return out, (out != tok)
    return tok, False


def canonicalize_adversarial_text(text: str) -> dict[str, object]:
    """Возвращает очищенную каноническую форму текста и флаги обнаруженной обфускации."""
    raw = str(text or "")
    flags: list[str] = []

    # 1. Снятие невидимых символов и NFKC-нормализация
    stripped, n_inv = _INVISIBLE_RE.subn("", raw)
    if n_inv > 0:
        flags.append(f"invisible_chars:{n_inv}")
    norm = unicodedata.normalize("NFKC", stripped)
    # Удаляем комбинирующие диакритические знаки (Zalgo-текст / диакритика для обхода)
    decomposed = unicodedata.normalize("NFKD", norm)
    no_marks = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn" or ch in ("\u0306", "\u0308"))
    norm = unicodedata.normalize("NFC", no_marks)

    # 2. Склейка разбитых разделителями и пробелами букв (`i.g.n.o.r.e` -> `ignore`)
    if _SPLIT_DELIM_RE.search(norm):
        norm = _SPLIT_DELIM_RE.sub(lambda m: re.sub(r"[._\-]", "", m.group(0)), norm)
        flags.append("delimiter_split_word")
    if _SPLIT_SPACE_RE.search(norm):
        norm = _SPLIT_SPACE_RE.sub(lambda m: re.sub(r"\s+", "", m.group(0)), norm)
        flags.append("space_split_word")

    # 3. Потокенная обработка омоглифов и leetspeak
    had_homoglyph = False
    had_leet = False
    out_parts: list[str] = []
    for part in re.split(r"(\s+)", norm):
        if not part or part.isspace():
            out_parts.append(part)
            continue
        p1, h1 = _dehomoglyph_token(part)
        if h1:
            had_homoglyph = True
        p2, l2 = _deleet_token(p1)
        if l2:
            had_leet = True
        out_parts.append(p2)

    if had_homoglyph:
        flags.append("mixed_script_homoglyph")
    if had_leet:
        flags.append("leetspeak_obfuscation")

    canonical = " ".join("".join(out_parts).split())
    return {
        "canonical": canonical,
        "was_obfuscated": bool(flags),
        "flags": flags,
    }
