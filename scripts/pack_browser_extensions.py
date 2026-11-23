# -*- coding: utf-8 -*-
"""Собирает архивы расширения для магазинов из текущих папок extensions/chromium и extensions/firefox.

17.11.2026 архивы в extensions/dist оказались версии 0.5.2 при папках 0.6.4: собирались руками и отстали.
Скрипт кладёт в архив всё, кроме README.md, проверяет версию внутри и печатает SHA-256.
Запуск: python scripts/pack_browser_extensions.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

КОРЕНЬ = Path(__file__).resolve().parents[1]
ВЕРСИЯ = __import__("re").search(r'^version = "([^"]+)"', (КОРЕНЬ / "pyproject.toml").read_text(encoding="utf-8"), __import__("re").M).group(1)


def собрать(папка: str, имя: str) -> None:
    src = КОРЕНЬ / "extensions" / папка
    манифест = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    if манифест.get("version") != ВЕРСИЯ:
        sys.exit(f"{папка}: версия в manifest.json {манифест.get('version')} ≠ {ВЕРСИЯ} в pyproject.toml")
    dst = КОРЕНЬ / "extensions" / "dist" / имя
    dst.parent.mkdir(parents=True, exist_ok=True)
    файлы = sorted(p for p in src.rglob("*") if p.is_file() and p.name != "README.md")
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for p in файлы:
            info = zipfile.ZipInfo(p.relative_to(src).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes())
        # 23.11.2026: Лицензия PADAM 1.0, пункт 2(c) — копии раздаются только вместе с текстом лицензии.
        # Магазин расширений — это раздача копий, поэтому LICENSE лежит в каждом архиве.
        info = zipfile.ZipInfo("LICENSE", date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, (КОРЕНЬ / "LICENSE").read_bytes())
    with zipfile.ZipFile(dst) as z:
        if z.read("LICENSE") != (КОРЕНЬ / "LICENSE").read_bytes():
            sys.exit(f"{имя}: LICENSE в архиве не совпадает с корневым")
        внутри = json.loads(z.read("manifest.json"))["version"]
    print(f"{имя}: файлов {len(файлы)}, версия внутри {внутри}, sha256 {hashlib.sha256(dst.read_bytes()).hexdigest()[:16]}")


if __name__ == "__main__":
    собрать("chromium", "padam-memory-guard-chromium.zip")
    собрать("firefox", "padam-memory-guard-firefox.zip")
