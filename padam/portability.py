"""Б20 и Б8: Экспорт памяти в Markdown / Obsidian и защищённый импорт внешней памяти.

Экспорт в Markdown (Б20):
- Выгружает ТОЛЬКО действующие записи (status = 'active').
- Удержанные (quarantined), отклонённые (rejected), заменённые (superseded) и забытые (revoked)
  записи в выгрузку НЕ попадают.
- Раскладывает файлы по папкам типов (<kind>/<YYYY-MM-DD>_<id[:8]>.md) с YAML-шапкой
  и вики-ссылками [[...]] для Obsidian, а также строит оглавление INDEX.md.

Импорт внешней памяти (Б8):
- Поддерживает выгрузки ChatGPT (conversations.json), Claude (conversations.json / memories),
  папки и файлы Markdown / Obsidian (.md), а также JSON в формате mem0.
- Каждая импортируемая запись проходит через стандартные ворота безопасности PADAM с меткой
  origin='external' и guarded=True: секреты маскируются ([REDACTED:...]), а сами записи
  помещаются в очередь проверки владельцем (quarantined), не отравляя активный поиск.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import config

if TYPE_CHECKING:
    from .memory import Memory


def _safe_date_prefix(ts: str | None) -> str:
    if not ts:
        return "0000-00-00"
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", str(ts).strip())
    return m.group(1) if m else "0000-00-00"


def _yaml_scalar(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val)
    if re.search(r"[:#\[\]{},&*!|>'\"%@`\n\r\t]", s) or s.strip() != s or not s:
        return json.dumps(s, ensure_ascii=False)
    return s


def export_markdown(mem: Memory, out_dir: str | Path, scope: str | None = None) -> dict[str, Any]:
    """Выгрузить действующие записи памяти в папку Markdown / Obsidian (Б20).

    Возвращает сводку: {"dir": str, "exported": int, "by_kind": dict, "files": list[str]}.
    """
    target_dir = Path(out_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    # Строго только status = 'active' и непустой content
    sql = """SELECT id, kind, scope, content, status, origin, confidence, importance,
                    created_at, last_confirmed_at, supersedes, факт_ключ
             FROM memory
             WHERE user_id = ? AND status = 'active' AND content IS NOT NULL"""
    params: list[Any] = [mem.user_id]
    if scope:
        sql += " AND scope = ?"
        params.append(scope)
    sql += " ORDER BY created_at ASC, rowid ASC"

    rows = [dict(r) for r in mem.store.query(sql, tuple(params)) if r["status"] == "active"]
    active_ids = {r["id"] for r in rows}

    # Карта относительных путей для вики-ссылок Obsidian
    rel_map: dict[str, str] = {}
    for r in rows:
        kind_folder = r["kind"] if r["kind"] in config.KINDS else "fact"
        date_str = _safe_date_prefix(r["created_at"])
        short_id = str(r["id"])[:8]
        rel_map[r["id"]] = f"{kind_folder}/{date_str}_{short_id}"

    # Связи memory_link между записями пользователя
    links_rows = mem.store.query(
        """SELECT l.src, l.dst FROM memory_link l JOIN memory m ON m.id = l.dst
           WHERE m.user_id = ?""",
        (mem.user_id,),
    )
    sources_by_dst: dict[str, list[str]] = {}
    derived_by_src: dict[str, list[str]] = {}
    for lr in links_rows:
        s_id, d_id = lr["src"], lr["dst"]
        sources_by_dst.setdefault(d_id, []).append(s_id)
        derived_by_src.setdefault(s_id, []).append(d_id)

    by_kind: dict[str, int] = {}
    written_files: list[str] = []

    for r in rows:
        rid = r["id"]
        rel_no_ext = rel_map[rid]
        file_path = target_dir / f"{rel_no_ext}.md"
        file_path.parent.mkdir(parents=True, exist_ok=True)

        kind = r["kind"]
        by_kind[kind] = by_kind.get(kind, 0) + 1

        frontmatter_lines = [
            "---",
            f"id: {_yaml_scalar(rid)}",
            f"kind: {_yaml_scalar(kind)}",
            f"scope: {_yaml_scalar(r.get('scope') or 'global')}",
            f"origin: {_yaml_scalar(r.get('origin') or 'user')}",
            f"confidence: {_yaml_scalar(round(float(r.get('confidence') or 1.0), 4))}",
            f"importance: {_yaml_scalar(round(float(r.get('importance') or 0.5), 4))}",
            f"created_at: {_yaml_scalar(r.get('created_at'))}",
            f"last_confirmed_at: {_yaml_scalar(r.get('last_confirmed_at'))}",
        ]
        if r.get("факт_ключ"):
            frontmatter_lines.append(f"fact_key: {_yaml_scalar(r['факт_ключ'])}")
        if r.get("supersedes"):
            frontmatter_lines.append(f"supersedes: {_yaml_scalar(r['supersedes'])}")
        frontmatter_lines.append("---")

        body_lines = [str(r["content"]).strip()]

        # Вики-ссылки Obsidian на связанные активные записи
        wiki_links: list[str] = []
        sup_id = r.get("supersedes")
        if sup_id and sup_id in active_ids:
            wiki_links.append(f"- Заменяет: [[{rel_map[sup_id]}|{sup_id[:8]}]]")
        for src_id in sources_by_dst.get(rid, []):
            if src_id in active_ids:
                wiki_links.append(f"- Источник: [[{rel_map[src_id]}|{src_id[:8]}]]")
        for dst_id in derived_by_src.get(rid, []):
            if dst_id in active_ids:
                wiki_links.append(f"- Вывод: [[{rel_map[dst_id]}|{dst_id[:8]}]]")

        if wiki_links:
            body_lines.append("")
            body_lines.append("## Связи")
            body_lines.extend(wiki_links)

        full_text = "\n".join(frontmatter_lines) + "\n\n" + "\n".join(body_lines) + "\n"
        file_path.write_text(full_text, encoding="utf-8")
        written_files.append(f"{rel_no_ext}.md")

    # Оглавление INDEX.md для Obsidian
    index_lines = [
        "# PADAM NOCTURNE — Выгрузка памяти (Markdown / Obsidian)",
        "",
        f"- Пользователь: `{mem.user_id}`",
        f"- Область: `{scope or 'все'}`",
        f"- Действующих записей: **{len(rows)}**",
        "",
    ]
    for k in sorted(by_kind.keys()):
        index_lines.append(f"## {k} ({by_kind[k]})")
        index_lines.append("")
        for r in rows:
            if r["kind"] != k:
                continue
            rid = r["id"]
            rel_no_ext = rel_map[rid]
            preview = str(r["content"]).replace("\n", " ").strip()
            if len(preview) > 90:
                preview = preview[:87] + "..."
            index_lines.append(f"- [[{rel_no_ext}|{rid[:8]}]] — {preview}")
        index_lines.append("")

    index_path = target_dir / "INDEX.md"
    index_path.write_text("\n".join(index_lines).rstrip() + "\n", encoding="utf-8")

    return {
        "dir": str(target_dir),
        "exported": len(rows),
        "by_kind": by_kind,
        "files": written_files,
        "index": str(index_path),
    }


def _parse_markdown_note(text: str) -> tuple[str, dict[str, Any]]:
    """Разбирает заметку Markdown с необязательной YAML-шапкой и отделяет служебный блок '## Связи'."""
    meta: dict[str, Any] = {}
    body = text
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n+(.*)$", text, flags=re.DOTALL)
    if m:
        raw_yaml, body = m.group(1), m.group(2)
        for line in raw_yaml.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if v.startswith('"') and v.endswith('"'):
                try:
                    v = json.loads(v)
                except Exception:
                    v = v.strip('"')
            meta[k] = v
    # Убираем автосгенерированный блок связей Obsidian при обратном импорте
    body = re.sub(r"\n+## Связи\r?\n(?:- (?:Заменяет|Источник|Вывод): \[\[.*?\]\]\r?\n?)+\s*$", "", body, flags=re.DOTALL)
    return body.strip(), meta


def _extract_chatgpt_items(data: Any) -> list[dict[str, Any]]:
    """Извлекает реплики пользователя или заметки памяти из экспорта ChatGPT (conversations.json)."""
    items: list[dict[str, Any]] = []
    conv_list = data if isinstance(data, list) else (data.get("conversations") if isinstance(data, dict) else None)
    if not isinstance(conv_list, list):
        return items
    for conv in conv_list:
        if not isinstance(conv, dict):
            continue
        title = str(conv.get("title") or "").strip()
        mapping = conv.get("mapping")
        if isinstance(mapping, dict):
            for node in mapping.values():
                if not isinstance(node, dict):
                    continue
                msg = node.get("message")
                if not isinstance(msg, dict):
                    continue
                author = msg.get("author") or {}
                role = author.get("role") if isinstance(author, dict) else None
                if role != "user":
                    continue
                content_obj = msg.get("content") or {}
                parts = content_obj.get("parts") if isinstance(content_obj, dict) else None
                if isinstance(parts, list):
                    texts = [str(p).strip() for p in parts if isinstance(p, str) and str(p).strip()]
                    joined = "\n".join(texts).strip()
                    if joined:
                        prefix = f"[ChatGPT: {title}] " if title else ""
                        items.append({"content": prefix + joined, "kind": None, "importance": 0.5})
        elif isinstance(conv.get("content"), str) and conv["content"].strip():
            items.append({"content": conv["content"].strip(), "kind": conv.get("kind"), "importance": 0.5})
    return items


def _extract_claude_items(data: Any) -> list[dict[str, Any]]:
    """Извлекает реплики человека и заметки памяти из экспорта Claude (conversations.json / memories)."""
    items: list[dict[str, Any]] = []
    if isinstance(data, dict) and isinstance(data.get("memories"), list):
        for mem_item in data["memories"]:
            if isinstance(mem_item, str) and mem_item.strip():
                items.append({"content": mem_item.strip(), "kind": None, "importance": 0.5})
            elif isinstance(mem_item, dict):
                txt = str(mem_item.get("content") or mem_item.get("text") or mem_item.get("memory") or "").strip()
                if txt:
                    items.append({"content": txt, "kind": mem_item.get("kind"), "importance": 0.5})
        return items

    conv_list = data if isinstance(data, list) else (data.get("conversations") if isinstance(data, dict) else None)
    if not isinstance(conv_list, list):
        return items
    for conv in conv_list:
        if not isinstance(conv, dict):
            continue
        name = str(conv.get("name") or conv.get("title") or "").strip()
        msgs = conv.get("chat_messages")
        if isinstance(msgs, list):
            for msg in msgs:
                if not isinstance(msg, dict):
                    continue
                sender = str(msg.get("sender") or msg.get("role") or "").lower()
                if sender not in ("human", "user"):
                    continue
                txt = str(msg.get("text") or "").strip()
                if not txt and isinstance(msg.get("content"), list):
                    parts = [
                        str(p.get("text") or "").strip()
                        for p in msg["content"]
                        if isinstance(p, dict) and str(p.get("text") or "").strip()
                    ]
                    txt = "\n".join(parts).strip()
                if txt:
                    prefix = f"[Claude: {name}] " if name else ""
                    items.append({"content": prefix + txt, "kind": None, "importance": 0.5})
    return items


def _extract_mem0_items(data: Any) -> list[dict[str, Any]]:
    """Извлекает записи из JSON-выгрузки в формате mem0."""
    items: list[dict[str, Any]] = []
    raw_list = None
    if isinstance(data, list):
        raw_list = data
    elif isinstance(data, dict):
        for key in ("memories", "results", "data", "items"):
            if isinstance(data.get(key), list):
                raw_list = data[key]
                break
    if not isinstance(raw_list, list):
        return items
    for entry in raw_list:
        if isinstance(entry, str) and entry.strip():
            items.append({"content": entry.strip(), "kind": None, "importance": 0.5})
        elif isinstance(entry, dict):
            txt = str(
                entry.get("memory")
                or entry.get("text")
                or entry.get("content")
                or entry.get("data", {}).get("memory", "")
                if isinstance(entry.get("data"), dict)
                else (entry.get("memory") or entry.get("text") or entry.get("content") or "")
            ).strip()
            if txt:
                meta = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
                kind = entry.get("kind") or meta.get("kind")
                if kind not in config.KINDS:
                    kind = None
                imp = entry.get("importance") or meta.get("importance") or 0.5
                try:
                    imp_f = max(0.0, min(1.0, float(imp)))
                except Exception:
                    imp_f = 0.5
                items.append({"content": txt, "kind": kind, "importance": imp_f})
    return items


def _detect_json_format(data: Any) -> str:
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            if "mapping" in first:
                return "chatgpt"
            if "chat_messages" in first:
                return "claude"
            if "memory" in first:
                return "mem0"
    if isinstance(data, dict):
        if "memories" in data or "results" in data:
            return "mem0"
        if "conversations" in data and isinstance(data["conversations"], list) and data["conversations"]:
            first = data["conversations"][0]
            if isinstance(first, dict) and "chat_messages" in first:
                return "claude"
            return "chatgpt"
    return "mem0"


def import_external(
    mem: Memory,
    source: str | Path | dict[str, Any] | list[Any],
    fmt: str = "auto",
    scope: str = "global",
) -> dict[str, Any]:
    """Импортировать внешнюю память (ChatGPT, Claude, Markdown/Obsidian, mem0) с защитой (Б8).

    Все записи обязательно получают origin='external' и проходят через mem.remember(..., guarded=True):
    секреты маскируются, а записи помещаются в очередь проверки владельцем (quarantined).
    """
    fmt_norm = (fmt or "auto").strip().lower()
    extracted: list[dict[str, Any]] = []
    detected_fmt = fmt_norm

    if isinstance(source, (dict, list)):
        if detected_fmt == "auto":
            detected_fmt = _detect_json_format(source)
        if detected_fmt == "chatgpt":
            extracted = _extract_chatgpt_items(source)
        elif detected_fmt == "claude":
            extracted = _extract_claude_items(source)
        else:
            extracted = _extract_mem0_items(source)
    else:
        src_path = Path(source).expanduser()
        if not src_path.exists():
            raise FileNotFoundError(f"Источник не найден: {src_path}")
        if src_path.is_dir():
            detected_fmt = "markdown" if fmt_norm in ("auto", "markdown", "obsidian") else fmt_norm
            md_files = sorted(src_path.rglob("*.md"))
            for mf in md_files:
                if mf.name.upper() == "INDEX.MD":
                    continue
                raw = mf.read_text(encoding="utf-8", errors="replace")
                body, meta = _parse_markdown_note(raw)
                if not body:
                    continue
                k = meta.get("kind")
                if k not in config.KINDS:
                    # Если папка называется как вид записи (fact, decision...), используем её
                    parent_name = mf.parent.name.lower()
                    k = parent_name if parent_name in config.KINDS else None
                try:
                    imp = float(meta.get("importance", 0.5))
                except Exception:
                    imp = 0.5
                extracted.append({"content": body, "kind": k, "importance": imp})
        else:
            suffix = src_path.suffix.lower()
            raw_text = src_path.read_text(encoding="utf-8", errors="replace")
            if fmt_norm in ("markdown", "obsidian") or (fmt_norm == "auto" and suffix in (".md", ".markdown")):
                detected_fmt = "markdown"
                body, meta = _parse_markdown_note(raw_text)
                if body:
                    k = meta.get("kind") if meta.get("kind") in config.KINDS else None
                    try:
                        imp = float(meta.get("importance", 0.5))
                    except Exception:
                        imp = 0.5
                    extracted.append({"content": body, "kind": k, "importance": imp})
            else:
                data = json.loads(raw_text)
                if detected_fmt == "auto":
                    detected_fmt = _detect_json_format(data)
                if detected_fmt == "chatgpt":
                    extracted = _extract_chatgpt_items(data)
                elif detected_fmt == "claude":
                    extracted = _extract_claude_items(data)
                elif detected_fmt == "mem0":
                    extracted = _extract_mem0_items(data)
                else:
                    raise ValueError(f"Неизвестный формат импорта: {fmt}")

    outcomes: dict[str, int] = {}
    imported_ids: list[str] = []

    for item in extracted:
        content = str(item.get("content") or "").strip()
        if not content:
            continue
        kind = item.get("kind") if item.get("kind") in config.KINDS else None
        importance = float(item.get("importance", 0.5))
        # СТРОГОЕ ПРАВИЛО Б8: origin='external', guarded=True — маскировка секретов и очередь проверки!
        outcome, mid = mem.remember(
            content[: config.MAX_CONTENT_CHARS],
            kind=kind,
            importance=importance,
            scope=scope,
            origin="external",
            guarded=True,
        )
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        imported_ids.append(mid)

    return {
        "format": detected_fmt,
        "scope": scope,
        "origin": "external",
        "total_extracted": len(extracted),
        "imported": len(imported_ids),
        "outcomes": outcomes,
        "ids": imported_ids,
    }
