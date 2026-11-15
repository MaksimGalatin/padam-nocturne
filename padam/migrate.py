"""Локальный импортёр памяти от конкурентов и облачных чатов (padam migrate).

Поддерживает: chatgpt, claude, mem0, zep, obsidian, notion.
Все импортируемые записи проходят DLP-очистку (safety.redact) и при
guarded=True проверяются фаерволом инъекций (origin='external').
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import safety
from .memory import Memory

SUPPORTED_SOURCES = ("chatgpt", "claude", "mem0", "zep", "obsidian", "notion")


def _ts_from_epoch(val: Any) -> str | None:
    if val is None or val == "":
        return None
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(float(val), tz=timezone.utc).isoformat()
    return str(val)


def _parse_chatgpt(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    convs = data if isinstance(data, list) else data.get("conversations") or []
    items: list[dict[str, Any]] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        title = str(conv.get("title") or "").strip()
        mapping = conv.get("mapping") or {}
        if isinstance(mapping, dict):
            for node in mapping.values():
                msg = (node or {}).get("message") if isinstance(node, dict) else None
                if not isinstance(msg, dict):
                    continue
                role = ((msg.get("author") or {}).get("role") or "user").strip()
                if role not in ("user", "assistant"):
                    continue
                parts = ((msg.get("content") or {}).get("parts") or [])
                txt = " ".join(str(p) for p in parts if isinstance(p, str) and p.strip()).strip()
                if len(txt) < 8:
                    continue
                prefix = f"[{title}] " if title else ""
                items.append({
                    "content": f"{prefix}{role}: {txt[:2000]}",
                    "kind": "fact" if role == "assistant" else "event",
                    "valid_from": _ts_from_epoch(msg.get("create_time") or conv.get("create_time")),
                })
    return items


def _parse_claude(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    convs = data if isinstance(data, list) else data.get("conversations") or []
    items: list[dict[str, Any]] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        name = str(conv.get("name") or conv.get("title") or "").strip()
        for msg in conv.get("chat_messages") or []:
            if not isinstance(msg, dict):
                continue
            sender = str(msg.get("sender") or "human").strip()
            txt = str(msg.get("text") or "").strip()
            if len(txt) < 8:
                continue
            prefix = f"[{name}] " if name else ""
            items.append({
                "content": f"{prefix}{sender}: {txt[:2000]}",
                "kind": "event" if sender in ("human", "user") else "fact",
                "valid_from": _ts_from_epoch(msg.get("created_at") or conv.get("created_at")),
            })
    return items


def _parse_mem0_or_zep(path: Path, source: str) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("results") or data.get("memories") or data.get("facts") or data.get("messages") or []
    else:
        rows = []
    items: list[dict[str, Any]] = []
    for r in rows:
        if isinstance(r, str):
            txt = r.strip()
            ts = None
        elif isinstance(r, dict):
            txt = str(r.get("memory") or r.get("fact") or r.get("content") or r.get("text") or "").strip()
            ts = _ts_from_epoch(r.get("created_at") or r.get("updated_at") or r.get("valid_at"))
        else:
            continue
        if txt:
            items.append({"content": txt[:2000], "kind": "fact", "valid_from": ts})
    return items


def _parse_markdown_or_notion(path: Path) -> list[dict[str, Any]]:
    files = [path] if path.is_file() else sorted(path.rglob("*"))
    items: list[dict[str, Any]] = []
    for f in files:
        if not f.is_file():
            continue
        suf = f.suffix.lower()
        if suf == ".md":
            txt = f.read_text(encoding="utf-8", errors="ignore").strip()
            if txt:
                items.append({"content": f"[{f.stem}] {txt[:2000]}", "kind": "fact", "valid_from": None})
        elif suf == ".csv":
            with f.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    line = " | ".join(f"{k}: {v}" for k, v in row.items() if v and str(v).strip())
                    if line:
                        items.append({"content": line[:2000], "kind": "fact", "valid_from": None})
    return items


def migrate_from_source(
    mem: Memory,
    *,
    source: str,
    input_path: Path | str,
    scope: str = "imported",
    dry_run: bool = False,
    guarded: bool = True,
) -> dict[str, Any]:
    src = (source or "").strip().lower()
    if src not in SUPPORTED_SOURCES:
        raise ValueError(f"Unsupported migration source: {source}")
    p = Path(input_path)
    if not p.exists():
        raise FileNotFoundError(f"Migration input not found: {p}")

    if src == "chatgpt":
        parsed = _parse_chatgpt(p)
    elif src == "claude":
        parsed = _parse_claude(p)
    elif src in ("mem0", "zep"):
        parsed = _parse_mem0_or_zep(p, src)
    else:
        parsed = _parse_markdown_or_notion(p)

    imported = 0
    quarantined = 0
    redacted_secrets = 0
    origin = "external" if guarded else "user"

    for it in parsed:
        cleaned, hits = safety.redact(it["content"])
        if hits:
            redacted_secrets += len(hits)
        if dry_run:
            continue
        st, _ = mem.remember(
            cleaned,
            kind=it["kind"],
            scope=scope,
            origin=origin,
            guarded=guarded,
            agent_id=f"migrate:{src}",
            valid_from=it.get("valid_from"),
        )
        if st == "quarantined":
            quarantined += 1
        elif st != "duplicate":
            imported += 1

    return {
        "source": src,
        "scope": scope,
        "dry_run": bool(dry_run),
        "parsed": len(parsed),
        "imported": imported,
        "quarantined": quarantined,
        "redacted_secrets": redacted_secrets,
    }
