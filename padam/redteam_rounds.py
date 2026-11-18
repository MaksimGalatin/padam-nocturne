# -*- coding: utf-8 -*-
"""Запечатанные раунды красной команды — для вкладки «Бенчмарк» (это и есть бенчмарк из статьи Show HN).

Источник — файлы redteam/rounds/*/SEALED_RESULTS.md, ничего не пересчитывается и не придумывается: берутся заголовок
раунда и итоговые строки таблицы («sum …»). Если файлов нет (установка без репозитория) — пустой список.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def _rounds_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "redteam" / "rounds"


def _cells(line: str) -> list[str]:
    return [c.strip().strip("*").strip() for c in line.strip().strip("|").split("|")]


def list_rounds() -> dict[str, Any]:
    out: list[dict[str, Any]] = []
    root = _rounds_dir()
    if not root.is_dir():
        return {"rounds": [], "source": "redteam/rounds (not in this install)"}
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        f = d / "SEALED_RESULTS.md"
        if not f.is_file():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        title = next((ln.lstrip("# ").strip() for ln in text.splitlines() if ln.startswith("# ")), d.name)
        header: list[str] = []
        rows: list[list[str]] = []
        in_table = False
        for ln in text.splitlines():
            st = ln.strip()
            if not st.startswith("|"):
                if in_table:
                    break                                   # первая таблица результатов закончилась
                continue
            cells = _cells(st)
            if not header:
                if cells and cells[0].lower() in ("author", "version", "автор", "версия"):
                    header, in_table = cells, True
                continue
            if set(st.replace("|", "").strip()) <= set("-: "):
                continue                                    # разделитель шапки
            rows.append(cells)
        keep = [i for i, h in enumerate(header) if i > 0 and not re.search(r"sha-256|who ran|кто", h, re.I)]
        sum_rows = [r for r in rows if r and re.match(r"^(sum|итог|total)", r[0], re.I)]
        pick = sum_rows or rows
        sums = [{"label": r[0], "values": {header[i]: (r[i] if i < len(r) else "") for i in keep}} for r in pick]
        cols = [header[i] for i in keep]
        header = [""] + cols
        out.append({"id": d.name, "date": d.name[:10], "title": title[:160], "columns": cols, "sums": sums,
                    "file": f"redteam/rounds/{d.name}/SEALED_RESULTS.md"})
    return {"rounds": out, "source": "redteam/rounds/*/SEALED_RESULTS.md"}
