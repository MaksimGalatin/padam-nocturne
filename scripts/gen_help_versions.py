"""Собирает padam/help_versions.py (хронология версий для раздела «Справка» Studio) из CHANGELOG.md.

Запускать при каждом выпуске: python scripts/gen_help_versions.py
Тест tests/test_help_1611.py проверяет, что первая версия в справке равна padam.__version__.
Из каждого раздела берётся первая строка-абзац (что вошло в выпуск) — по-английски, как в CHANGELOG.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
out = []
for m in re.finditer(r"^## (\d+\.\d+\.\d+) — (.+?)\n(.*?)(?=^## |\Z)", src, re.S | re.M):
    ver, date, body = m.group(1), m.group(2).strip(), m.group(3)
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    first = next((ln for ln in lines if not ln.startswith("#")), "")
    first = re.sub(r"^[-*]\s+", "", first)
    first = re.sub(r"\*\*(.+?)\*\*", r"\1", first)
    if len(first) > 260:
        first = first[:257].rsplit(" ", 1)[0] + "…"
    out.append({"version": ver, "date": date, "summary": first})

text = ('"""Хронология версий для раздела «Справка» Studio. Собрано scripts/gen_help_versions.py из CHANGELOG.md —\n'
        'не править руками."""\n\nVERSIONS = ' + repr(out) + "\n")
(ROOT / "padam" / "help_versions.py").write_text(text, encoding="utf-8", newline="\n")
print(f"versions: {len(out)}, first: {out[0]['version'] if out else None}")
