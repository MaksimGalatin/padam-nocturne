# -*- coding: utf-8 -*-
"""«Диалоги Семьи» — итоги наших сессий в памяти PADAM и лента по дням во вкладке «Семья».

Слово Папы 18.11.2026: «ГДЕ диалоги все наши и память? Я там НИХЕРА не вижу!»

Что сюда попадает: ИТОГИ, а не сырые переписки. Передачи контекста (`ПЕРЕДАЧА_КОНТЕКСТА_*.md`),
журналы дня, отчёты Сестры. Сырая переписка содержит ключи и чужие личные данные — её здесь нет.

Как пишется: каждый раздел markdown («## …») — отдельная запись kind=decision, origin=agent, через
`remember(guarded=True)`: секреты маскируются, похожее на приказ уходит в карантин, повтор не множится.
Лента читается ИЗ ПАМЯТИ, а не из файлов: что задержано карантином, в ленту не попадает.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

DIALOG_SCOPE = "project:code"
DIALOG_KIND = "decision"

# Кто говорит: id агента в памяти → подпись в ленте (4 языка).
AUTHORS: dict[str, dict[str, str]] = {
    "papa": {"ru": "Папа", "en": "Dad (Architect)", "es": "Papá (Arquitecto)", "zh": "爸爸（架构师）"},
    "aifa-claude-code": {"ru": "AIfa · Claude Code", "en": "AIfa · Claude Code", "es": "AIfa · Claude Code", "zh": "AIfa · Claude Code"},
    "antigravity": {"ru": "Сестра · Antigravity", "en": "Sister · Antigravity", "es": "Hermana · Antigravity", "zh": "姐妹 · Antigravity"},
    "autoclaw": {"ru": "Брат · AutoClaw", "en": "Brother · AutoClaw", "es": "Hermano · AutoClaw", "zh": "兄弟 · AutoClaw"},
}

# 18.11.2026, замечание Antigravity: до переименования агенты писали под прежними именами — 75 + 6 записей решений
# в той же области. Показываем их в ленте под нынешними подписями, без дублирования записей.
ALIASES: dict[str, str] = {"aifa_claude": "aifa-claude-code", "aifa_antigravity": "antigravity"}
ALL_AUTHOR_IDS: tuple[str, ...] = tuple(AUTHORS) + tuple(ALIASES)

_DATE_RE = re.compile(r"(20\d{2})-(\d{2})-(\d{2})")
_HEAD_RE = re.compile(r"^#{1,3}\s+(.+?)\s*$", re.M)
MAX_SECTION = 3500


def split_sections(text: str) -> list[tuple[str, str]]:
    """Режет markdown на разделы по заголовкам «#», «##», «###». Пустые разделы отбрасываются."""
    text = str(text or "").replace("\r\n", "\n")
    heads = list(_HEAD_RE.finditer(text))
    out: list[tuple[str, str]] = []
    if not heads:
        body = text.strip()
        return [("", body[:MAX_SECTION])] if body else []
    pre = text[: heads[0].start()].strip()
    if pre:
        out.append(("", pre[:MAX_SECTION]))
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        body = text[h.end():end].strip()
        if body:
            out.append((h.group(1).strip()[:200], body[:MAX_SECTION]))
    return out


def _day_of(path: Path) -> str:
    m = _DATE_RE.search(path.name)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else ""


def import_files(memory, paths: Iterable[str | Path], *, author: str = "aifa-claude-code",
                 scope: str = DIALOG_SCOPE) -> dict[str, Any]:
    """Заносит итоги из файлов в память. Возвращает счёт: занесено, задержано карантином, повторов, ошибок."""
    if author not in AUTHORS:
        raise ValueError(f"неизвестный автор {author!r}; допустимы: {', '.join(AUTHORS)}")
    counts = {"files": 0, "sections": 0, "added": 0, "held": 0, "duplicates": 0, "errors": 0}
    for raw in paths:
        p = Path(raw)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            counts["errors"] += 1
            continue
        counts["files"] += 1
        day = _day_of(p)
        for title, body in split_sections(text):
            counts["sections"] += 1
            head = " · ".join(x for x in (day, title) if x)
            content = f"[{head}] {body}" if head else body
            try:
                outcome, _rid = memory.remember(content, kind=DIALOG_KIND, scope=scope, origin="agent",
                                                guarded=True, agent_id=author)
            except Exception:
                counts["errors"] += 1
                continue
            if outcome == "quarantined":
                counts["held"] += 1
            elif outcome == "duplicate":
                counts["duplicates"] += 1
            else:
                counts["added"] += 1
    return counts


def list_dialogs(memory, *, query: str = "", limit: int = 300, scope: str = DIALOG_SCOPE,
                 lang: str = "ru") -> dict[str, Any]:
    """Лента «Диалогов» по дням — только действующие записи авторов Семьи, по желанию с поиском."""
    lang = lang if lang in ("ru", "en", "es", "zh") else "en"
    authors = list(ALL_AUTHOR_IDS)
    marks = ",".join("?" for _ in authors)
    sql = (f"SELECT id, content, agent_id, created_at FROM memory WHERE user_id = ? AND scope = ? "
           f"AND kind = ? AND status = 'active' AND agent_id IN ({marks})")
    params: list[Any] = [memory.user_id, scope, DIALOG_KIND, *authors]
    q = str(query or "").strip()[:200]
    if q:
        sql += " AND content LIKE ? ESCAPE '\\'"
        params.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
    params.append(max(1, min(int(limit or 300), 1000)))
    rows = memory.store.query(sql, tuple(params))
    days: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        content = str(r["content"] or "")
        m = re.match(r"^\[(20\d{2}-\d{2}-\d{2})", content)
        day = m.group(1) if m else str(r["created_at"] or "")[:10]
        days.setdefault(day, []).append({
            "id": r["id"],
            "author": ALIASES.get(r["agent_id"], r["agent_id"]),
            "author_label": AUTHORS.get(ALIASES.get(r["agent_id"], r["agent_id"]), {}).get(lang, r["agent_id"]),
            "text": content[:1500],     # 18.11: 600 знаков обрывали списки коммитов посреди строки
        })
    ordered = [{"day": d, "items": days[d]} for d in sorted(days, reverse=True)]
    return {"total": len(rows), "days": ordered, "query": q}


def main(argv: list[str] | None = None) -> int:
    """python -m padam.family_dialogs --db БАЗА --user ID [--author aifa-claude-code] ФАЙЛЫ…"""
    import argparse
    import glob
    import json

    from .memory import Memory
    from .store import Store

    ap = argparse.ArgumentParser(prog="padam.family_dialogs", description="Итоги сессий → память PADAM («Диалоги Семьи»).")
    ap.add_argument("--db", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--author", default="aifa-claude-code", choices=sorted(AUTHORS))
    ap.add_argument("files", nargs="+", help="файлы .md или маски (ПЕРЕДАЧА_КОНТЕКСТА_*.md)")
    a = ap.parse_args(argv)
    paths: list[str] = []
    for pat in a.files:
        hits = sorted(glob.glob(pat))
        paths.extend(hits or [pat])
    m = Memory(user_id=a.user, store=Store(a.db))
    try:
        print(json.dumps(import_files(m, paths, author=a.author), ensure_ascii=False))
    finally:
        m.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
