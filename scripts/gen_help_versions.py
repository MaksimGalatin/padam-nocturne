"""Собирает padam/help_versions.py (хронология версий для раздела «Справка» Studio) из CHANGELOG.md.

Запускать при каждом выпуске: python scripts/gen_help_versions.py
Тест tests/test_help_1611.py проверяет, что первая версия в справке равна padam.__version__,
ни одна строка не содержит обратных кавычек (`) и не оканчивается двоеточием (:).
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _strip_markdown(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"\1", text)
    text = text.replace("`", "")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _pick_sentences(body: str, limit: int = 260) -> str:
    raw_lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not raw_lines:
        return ""
    cleaned_lines = [re.sub(r"^[-*]\s+", "", ln) for ln in raw_lines]
    # Если первая строка обрывается двоеточием (вводная перед списком), связываем её с первым пунктом через тире.
    parts = [cleaned_lines[0]]
    idx = 1
    if parts[-1].endswith(":") and idx < len(cleaned_lines):
        first_intro = parts[0].rstrip(":").strip()
        nxt = cleaned_lines[idx]
        nxt = nxt[0].lower() + nxt[1:] if len(nxt) > 1 and nxt[0].isupper() and nxt[1].islower() else nxt
        parts = [f"{first_intro} — {nxt}"]
        idx += 1
    merged = " ".join(parts)
    while len(merged) < 600 and idx < len(cleaned_lines):
        merged = merged + " " + cleaned_lines[idx]
        idx += 1
    text = _strip_markdown(merged)

    # Разбиваем на целые предложения (точка/!/? + пробел + заглавная/цифра)
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Za-zА-Яа-яЁё0-9\"«(])", text)
    chosen = ""
    picked = 0
    for sent in sentences:
        sent = sent.strip()
        if not sent or sent[-1] not in ".!?":
            continue
        cand = f"{chosen} {sent}".strip() if chosen else sent
        if len(cand) <= limit and picked < 2:
            chosen = cand
            picked += 1
        else:
            break
    if not chosen:
        chosen = text
    if len(chosen) > limit:
        chosen = chosen[: limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:-") + "…"
    chosen = chosen.rstrip(":")
    if chosen and chosen[-1] not in ".!?…":
        chosen += "."
    return chosen


def main() -> None:
    src = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    out = []
    for m in re.finditer(r"^## (\d+\.\d+\.\d+) — (.+?)\n(.*?)(?=^## |\Z)", src, re.S | re.M):
        ver, date, body = m.group(1), m.group(2).strip(), m.group(3)
        summary = _pick_sentences(body, limit=260)
        out.append({"version": ver, "date": date, "summary": summary})

    text = (
        '"""Хронология версий для раздела «Справка» Studio. Собрано scripts/gen_help_versions.py из CHANGELOG.md —\n'
        'не править руками."""\n\nVERSIONS = ' + repr(out) + "\n"
    )
    (ROOT / "padam" / "help_versions.py").write_text(text, encoding="utf-8", newline="\n")
    print(f"versions: {len(out)}, first: {out[0]['version'] if out else None}")


if __name__ == "__main__":
    main()
