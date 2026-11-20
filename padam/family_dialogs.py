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


def _parse_dialog_entry(content: str) -> tuple[str, str]:
    raw = str(content or "").strip()
    title = ""
    body = raw
    m = re.match(r"^\[(20\d{2}-\d{2}-\d{2})(?:\s*·\s*([^\]]+))?\]\s*(.*)$", raw, flags=re.S)
    if m:
        title = (m.group(2) or "").strip()
        body = (m.group(3) or "").strip()
    if not title:
        first_line = body.splitlines()[0].strip() if body else ""
        if len(first_line) <= 120:
            title = first_line
        else:
            title = first_line[:117] + "…"
    return title[:140], body


def list_dialogs(memory, *, query: str = "", limit: int = 300, scope: str = DIALOG_SCOPE,
                 lang: str = "ru", since: str = "all", day: str = "") -> dict[str, Any]:
    """Лента «Диалогов» по дням — чистые структурированные карточки, новые сверху, фильтры 24h/date/all."""
    from datetime import datetime, timedelta, timezone
    from . import family_admin

    lang = lang if lang in ("ru", "en", "es", "zh") else "en"
    role_matrix = family_admin.get_role_matrix(memory, lang=lang)
    roles_by_agent: dict[str, list[str]] = {}
    for rm in role_matrix:
        aid_r = str(rm.get("agent_id") or "")
        roles_by_agent.setdefault(aid_r, []).append(str(rm.get("code") or rm.get("role_key")))

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

    since_norm = str(since or "all").strip().lower()
    day_filter = str(day or "").strip()[:10]
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    days: dict[str, list[dict[str, Any]]] = {}
    total_filtered = 0
    for r in rows:
        content = str(r["content"] or "")
        m = re.match(r"^\[(20\d{2}-\d{2}-\d{2})", content)
        rec_day = m.group(1) if m else str(r["created_at"] or "")[:10]
        if since_norm == "24h" and str(r["created_at"] or "") < cutoff_iso:
            continue
        if day_filter and rec_day != day_filter:
            continue

        raw_agent = str(r["agent_id"] or "")
        canon_author = ALIASES.get(raw_agent, raw_agent)
        r_codes = list(dict.fromkeys((roles_by_agent.get(raw_agent) or []) + (roles_by_agent.get(canon_author) or [])))
        if canon_author == "aifa-claude-code" and not r_codes:
            r_codes = roles_by_agent.get("aifa_claude") or ["LANCE", "PIXEL"]
        elif canon_author == "antigravity" and not r_codes:
            r_codes = roles_by_agent.get("aifa_antigravity") or ["ARIA"]

        title, clean_body = _parse_dialog_entry(content)
        total_filtered += 1
        days.setdefault(rec_day, []).append({
            "id": r["id"],
            "day": rec_day,
            "created_at": r["created_at"],
            "author": canon_author,
            "raw_agent_id": raw_agent,
            "author_label": AUTHORS.get(canon_author, {}).get(lang, raw_agent),
            "council_roles": r_codes,
            "controlled_by": family_admin.describe_agent_controller(raw_agent, "", lang=lang),
            "title": title,
            "summary": clean_body[:420],
            "text": content[:2500],
        })
    ordered = [{"day": d, "items": days[d]} for d in sorted(days, reverse=True)]
    return {"total": total_filtered, "days": ordered, "query": q, "since": since_norm, "day": day_filter, "roles": role_matrix}

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
