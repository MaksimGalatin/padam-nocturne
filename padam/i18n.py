"""Язык командной строки и REST-консоли: английский или русский.

PADAM_LANG=en|ru задаёт язык явно. Без неё — язык системы: переменные LC_ALL / LC_MESSAGES / LANG / LANGUAGE,
затем локаль Python. Всё, кроме русского, — английский.

Зачем (12.10.2026): README и судьи хакатона — по-английски, а CLI отвечал только по-русски. Ответы MCP-сервера
от этого не зависят: они всегда английские, их читает модель.
"""

from __future__ import annotations

import locale
import os


def _system_is_russian() -> bool:
    for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        value = os.environ.get(var, "")
        if value:
            return value.lower().startswith("ru")
    # На Windows локаль приходит как ('Russian_Russia', '1251'), в Linux/macOS — ('ru_RU', 'UTF-8').
    try:
        return (locale.getlocale()[0] or "").lower().startswith("ru")
    except (ValueError, TypeError):
        return False


def lang() -> str:
    """'ru' или 'en'."""
    forced = os.environ.get("PADAM_LANG", "").strip().lower()
    if forced in ("ru", "en"):
        return forced
    return "ru" if _system_is_russian() else "en"


def t(ru: str, en: str) -> str:
    """Строка на языке пользователя."""
    return ru if lang() == "ru" else en
