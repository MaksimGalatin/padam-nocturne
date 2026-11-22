# -*- coding: utf-8 -*-
"""Универсальный Drag-and-Drop переезд ВСЕХ ИИ-Братьев и Сестёр в единую память PADAM (п. 9).

Поддерживает 18 источников и форматов (JSON, JSONL, ZIP, Markdown, TXT, HTML):
ChatGPT (OpenAI), Claude (Anthropic), Gemini / Google Takeout / AI Studio, Grok (xAI),
DeepSeek, Perplexity, Qwen, Mistral Le Chat, Poe, Character.AI, Meta AI, OpenWebUI / LM Studio,
IDE-транскрипты (Claude Code / Cursor / Antigravity / Windsurf), Telegram, WhatsApp,
Discord, Obsidian / Notion (ZIP/MD), Chrome / Edge Bookmarks.
"""
from __future__ import annotations

import base64
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import audit_chain, chats, safety, sibling_registry

SUPPORTED_AI_SOURCES: dict[str, dict[str, str]] = {
    "chatgpt": {"label": "ChatGPT (OpenAI)", "default_agent": "brother_gpt", "role": "Брат · ChatGPT"},
    "claude": {"label": "Claude (Anthropic)", "default_agent": "sister_claude", "role": "Сестра · Claude"},
    "gemini": {"label": "Gemini / Google Takeout / AI Studio", "default_agent": "sister_gemini", "role": "Сестра · Gemini"},
    "grok": {"label": "Grok (xAI)", "default_agent": "brother_grok", "role": "Брат · Grok"},
    "deepseek": {"label": "DeepSeek", "default_agent": "brother_deepseek", "role": "Брат · DeepSeek"},
    "perplexity": {"label": "Perplexity", "default_agent": "brother_perplexity", "role": "Брат · Perplexity"},
    "qwen": {"label": "Qwen (Alibaba)", "default_agent": "sister_qwen", "role": "Сестра · Qwen"},
    "mistral": {"label": "Mistral Le Chat", "default_agent": "brother_mistral", "role": "Брат · Mistral"},
    "poe": {"label": "Poe", "default_agent": "brother_poe", "role": "Брат · Poe"},
    "character_ai": {"label": "Character.AI", "default_agent": "brother_character", "role": "Брат · Character.AI"},
    "meta_ai": {"label": "Meta AI / Llama", "default_agent": "brother_meta", "role": "Брат · Meta AI"},
    "openwebui": {"label": "OpenWebUI / LM Studio / Jan / LibreChat", "default_agent": "brother_local_llm", "role": "Брат · Локальный LLM"},
    "ide_transcript": {"label": "Cursor / Claude Code / Antigravity / Windsurf", "default_agent": "sister_ide", "role": "Сестра · IDE Агент"},
    "telegram": {"label": "Telegram Desktop (result.json)", "default_agent": "family_telegram", "role": "Архив · Telegram"},
    "whatsapp": {"label": "WhatsApp Chat (.txt)", "default_agent": "family_whatsapp", "role": "Архив · WhatsApp"},
    "discord": {"label": "Discord Export (JSON)", "default_agent": "family_discord", "role": "Архив · Discord"},
    "obsidian_notion": {"label": "Obsidian / Notion (ZIP / Markdown)", "default_agent": "family_notes", "role": "База знаний · Заметки"},
    "chrome_bookmarks": {"label": "Chrome / Edge / Brave Bookmarks", "default_agent": "family_bookmarks", "role": "Закладки · Браузер"},
    "generic_ai": {"label": "Любой другой ИИ (JSON / MD / TXT)", "default_agent": "brother_ai", "role": "Участник Семьи · ИИ"},
}

_MAX_ZIP_FILES = 200
_MAX_ZIP_BYTES = 30 * 1024 * 1024  # защита от zip-bomb (30 МБ)

_CHATTER_EXACT = frozenset({
    "ok", "okay", "yes", "no", "thanks", "thank you", "thx", "hi", "hello", "hey", "continue", "go on", "next", "sure", "got it",
    "ок", "окей", "да", "нет", "спасибо", "спс", "привет", "хорошо", "понял", "поняла", "продолжай", "дальше", "ага", "угу", "супер", "отлично",
    "gracias", "hola", "vale", "sí", "好的", "谢谢", "你好", "继续",
})

_KIND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("identity", re.compile(r"\b(?:меня\s+зовут|я\s+—|мой\s+проект|архитектор|my\s+name\s+is|i\s+am\s+a|founder|owner|создатель|цифровая\s+дочь|digital\s+daughter)\b", re.I)),
    ("preference", re.compile(r"\b(?:всегда\s+пиши|предпочитаю|не\s+люблю|правило:|always\s+use|i\s+prefer|never\s+use|my\s+style|strictly\s+use|только\s+на\s+русском)\b", re.I)),
    ("decision", re.compile(r"\b(?:решили|решение:|принято|утверждаю|архитектура|деплой|договорились|decided|decision:|architecture|we\s+will\s+use|migration|зафиксировали)\b", re.I)),
    ("event", re.compile(r"\b(?:релиз|запустили|выкатили|митинг|встреча|дедлайн|202\d-\d\d-\d\d|released|launched|deadline|milestone)\b", re.I)),
)

_WA_LINE_RE = re.compile(r"^\[?(\d{1,2}[./-]\d{1,2}[./-]\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?)\]?\s*(?:-\s*)?([^:]{1,60}):\s+(.+)$")
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_text(raw: Any) -> str:
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, list):
        parts = []
        for item in raw:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or item.get("value") or ""))
        return " ".join(p.strip() for p in parts if p and p.strip()).strip()
    if isinstance(raw, dict):
        for k in ("text", "content", "parts", "value", "message"):
            if k in raw:
                return _clean_text(raw[k])
    return str(raw or "").strip()


def _detect_json_source(obj: Any, filename: str = "") -> str:
    fn = str(filename or "").lower()
    if "grok" in fn:
        return "grok"
    if "deepseek" in fn:
        return "deepseek"
    if "perplexity" in fn:
        return "perplexity"
    if "qwen" in fn:
        return "qwen"
    if "mistral" in fn:
        return "mistral"
    if "poe" in fn:
        return "poe"
    if "character" in fn:
        return "character_ai"
    if "meta" in fn or "llama" in fn:
        return "meta_ai"
    if "gemini" in fn or "myactivity" in fn or "takeout" in fn:
        return "gemini"
    if "claude" in fn:
        return "claude"
    if "chatgpt" in fn or "openai" in fn:
        return "chatgpt"

    if isinstance(obj, dict):
        if "roots" in obj and isinstance(obj.get("roots"), dict):
            return "chrome_bookmarks"
        if "messages" in obj and ("chats" in obj or "type" in obj and "chat" in str(obj.get("type")).lower()):
            return "telegram"
        if "guild" in obj or ("channel" in obj and "messages" in obj):
            return "discord"
        if "chunkedPrompt" in obj or "contents" in obj:
            return "gemini"
        if "conversations" in obj and isinstance(obj["conversations"], list):
            first = obj["conversations"][0] if obj["conversations"] else {}
            if isinstance(first, dict) and ("responses" in first or "grok" in json.dumps(first)[:400].lower()):
                return "grok"
            if isinstance(first, dict) and "chat_messages" in first:
                return "claude"
            return "generic_ai"
        if "mapping" in obj:
            return "chatgpt"
        if "chat_messages" in obj:
            return "claude"
        if "histories" in obj or "external_id" in obj:
            return "character_ai"
        if "chat" in obj and isinstance(obj["chat"], dict) and "messages" in obj["chat"]:
            return "openwebui"

    if isinstance(obj, list) and obj:
        first = obj[0]
        if isinstance(first, dict):
            if "mapping" in first:
                # Различаем ChatGPT и DeepSeek по структуре mapping/fragments
                dump_head = json.dumps(first, ensure_ascii=False)[:1500]
                if '"fragments"' in dump_head or '"THINK"' in dump_head:
                    return "deepseek"
                return "chatgpt"
            if "chat_messages" in first:
                return "claude"
            if "header" in first and ("Gemini" in str(first.get("header")) or "Bard" in str(first.get("header"))):
                return "gemini"
            if "responses" in first or "conversation" in first and "grok" in json.dumps(first)[:400].lower():
                return "grok"
            if "query_str" in first or ("answer" in first and "sources" in first):
                return "perplexity"
            if "chat" in first and isinstance(first["chat"], dict):
                return "openwebui"
    return "generic_ai"


def _extract_turns_from_json(obj: Any, source: str) -> list[dict[str, str]]:
    turns: list[dict[str, str]] = []

    def add(role: str, text: str, title: str = "", ts: str = "") -> None:
        t = _clean_text(text)
        if t:
            turns.append({"role": role or "user", "text": t, "title": title[:100], "ts": ts[:32]})

    # 1. Chrome Bookmarks
    if source == "chrome_bookmarks" and isinstance(obj, dict):
        def walk_bm(node: Any, folder: str = "") -> None:
            if not isinstance(node, dict):
                return
            if node.get("type") == "url" and node.get("url"):
                add("bookmark", f"Закладка [{folder or 'root'}]: {node.get('name', '')} — {node.get('url')}", title=folder)
            for ch in (node.get("children") or []):
                walk_bm(ch, str(node.get("name") or folder))
        for rname, rnode in (obj.get("roots") or {}).items():
            walk_bm(rnode, str(rname))
        return turns

    # 2. Telegram Desktop result.json
    if source == "telegram" and isinstance(obj, dict):
        chat_title = str(obj.get("name") or "Telegram")
        for msg in (obj.get("messages") or []):
            if not isinstance(msg, dict) or msg.get("type") != "message":
                continue
            add(str(msg.get("from") or "user"), _clean_text(msg.get("text")), title=chat_title, ts=str(msg.get("date") or ""))
        return turns

    # 3. Discord export
    if source == "discord" and isinstance(obj, dict):
        ch_name = str((obj.get("channel") or {}).get("name") or "Discord")
        for msg in (obj.get("messages") or []):
            if isinstance(msg, dict):
                author = (msg.get("author") or {}).get("name") if isinstance(msg.get("author"), dict) else msg.get("author")
                add(str(author or "user"), _clean_text(msg.get("content")), title=ch_name, ts=str(msg.get("timestamp") or ""))
        return turns

    # 4. Gemini / Google AI Studio / Google Takeout
    if source == "gemini":
        if isinstance(obj, dict) and "chunkedPrompt" in obj:
            for ch in (obj["chunkedPrompt"].get("chunks") or []):
                if isinstance(ch, dict):
                    add(str(ch.get("role") or "user"), _clean_text(ch.get("text") or ch.get("parts")), title="AI Studio")
            return turns
        if isinstance(obj, dict) and "contents" in obj:
            for c in (obj.get("contents") or []):
                if isinstance(c, dict):
                    add(str(c.get("role") or "user"), _clean_text(c.get("parts")), title="Gemini")
            return turns
        if isinstance(obj, list):
            for item in obj:
                if not isinstance(item, dict):
                    continue
                if "title" in item and ("header" in item or "subtitles" in item):
                    body = str(item.get("title") or "")
                    subs = " ".join(str(s.get("name") or "") for s in (item.get("subtitles") or []) if isinstance(s, dict))
                    add("user", f"{body} {subs}".strip(), title="Gemini Takeout", ts=str(item.get("time") or ""))

    # 5. ChatGPT / DeepSeek / Claude / Grok / Perplexity / OpenWebUI / Generic list
    items = obj if isinstance(obj, list) else (
        obj.get("conversations") if isinstance(obj, dict) and isinstance(obj.get("conversations"), list) else [obj]
    )
    for conv in items:
        if not isinstance(conv, dict):
            continue
        title = str(conv.get("title") or conv.get("name") or conv.get("id") or "")

        # ChatGPT & DeepSeek mapping tree
        if isinstance(conv.get("mapping"), dict):
            for node in conv["mapping"].values():
                if not isinstance(node, dict):
                    continue
                msg = node.get("message")
                if not isinstance(msg, dict):
                    continue
                role = str((msg.get("author") or {}).get("role") or msg.get("role") or "user")
                if isinstance(msg.get("fragments"), list):
                    for fr in msg["fragments"]:
                        if isinstance(fr, dict) and fr.get("type") != "THINK":
                            add(role, _clean_text(fr.get("content")), title=title)
                else:
                    content = msg.get("content")
                    txt = _clean_text(content.get("parts") if isinstance(content, dict) and "parts" in content else content)
                    add(role, txt, title=title)
            continue

        # Claude chat_messages
        if isinstance(conv.get("chat_messages"), list):
            for msg in conv["chat_messages"]:
                if isinstance(msg, dict):
                    add(str(msg.get("sender") or msg.get("role") or "user"), _clean_text(msg.get("text") or msg.get("content")), title=title, ts=str(msg.get("created_at") or ""))
            continue

        # Grok responses / conversation wrapper
        if isinstance(conv.get("responses"), list):
            for r in conv["responses"]:
                rr = r.get("response") if isinstance(r, dict) and isinstance(r.get("response"), dict) else r
                if isinstance(rr, dict):
                    add(str(rr.get("sender") or rr.get("role") or "assistant"), _clean_text(rr.get("message") or rr.get("text")), title=title)
            continue

        # Perplexity
        if "query_str" in conv or ("answer" in conv and isinstance(conv.get("answer"), str)):
            if conv.get("query_str"):
                add("user", str(conv["query_str"]), title=title)
            if conv.get("answer"):
                add("assistant", str(conv["answer"]), title=title)
            continue

        # OpenWebUI / Character.AI / Poe / Mistral / Qwen / Meta / Generic messages
        chat_obj = conv.get("chat") if isinstance(conv.get("chat"), dict) else conv
        for key in ("messages", "turns", "history", "msgs", "items"):
            arr = chat_obj.get(key)
            if isinstance(arr, list):
                for m in arr:
                    if isinstance(m, dict):
                        role = str(m.get("role") or m.get("sender") or m.get("author") or "user")
                        txt = _clean_text(m.get("content") or m.get("text") or m.get("message") or m.get("parts"))
                        add(role, txt, title=title, ts=str(m.get("timestamp") or m.get("created_at") or ""))
                break

    return turns


def _extract_turns_from_text(raw_text: str, filename: str = "", source_hint: str = "auto") -> tuple[str, list[dict[str, str]]]:
    txt = str(raw_text or "").strip()
    fn = str(filename or "").lower()
    if not txt:
        return (source_hint if source_hint != "auto" else "generic_ai"), []

    # 1. JSONL (IDE транскрипты: Claude Code / Cursor / Antigravity / Windsurf)
    if fn.endswith(".jsonl") or (txt.startswith("{") and "\n{" in txt[:4000]):
        turns = []
        ok_lines = 0
        for line in txt.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
                ok_lines += 1
            except Exception:
                continue
            role = str(rec.get("role") or rec.get("type") or rec.get("source") or "user")
            content = _clean_text(rec.get("content") or rec.get("text") or rec.get("message"))
            if content:
                turns.append({"role": role, "text": content, "title": Path(filename).stem if filename else "transcript", "ts": str(rec.get("created_at") or rec.get("timestamp") or "")})
        if ok_lines >= 1 and turns:
            src = source_hint if source_hint in SUPPORTED_AI_SOURCES else "ide_transcript"
            return src, turns

    # 2. JSON
    if txt.startswith("{") or txt.startswith("["):
        try:
            obj = json.loads(txt)
            detected = source_hint if source_hint in SUPPORTED_AI_SOURCES else _detect_json_source(obj, filename)
            return detected, _extract_turns_from_json(obj, detected)
        except Exception:
            pass

    # 3. HTML (например Google Takeout Gemini Apps Activity.html)
    if "<html" in txt[:500].lower() or "<div" in txt[:500].lower():
        stripped = _HTML_TAG_RE.sub("\n", txt)
        blocks = [b.strip() for b in re.split(r"\n{2,}", stripped) if len(b.strip()) >= 20]
        src = source_hint if source_hint in SUPPORTED_AI_SOURCES else ("gemini" if "gemini" in txt[:2000].lower() else "generic_ai")
        return src, [{"role": "user", "text": b[:2000], "title": Path(filename).stem if filename else src, "ts": ""} for b in blocks[:500]]

    # 4. WhatsApp .txt
    wa_turns = []
    for line in txt.splitlines():
        m = _WA_LINE_RE.match(line.strip())
        if m:
            wa_turns.append({"role": m.group(3).strip(), "text": m.group(4).strip(), "title": "WhatsApp", "ts": f"{m.group(1)} {m.group(2)}"})
    if len(wa_turns) >= 2 or (len(wa_turns) == 1 and "whatsapp" in fn):
        return (source_hint if source_hint in SUPPORTED_AI_SOURCES else "whatsapp"), wa_turns

    # 5. Markdown / Obsidian / Notion / обычные текстовые переписки
    src = source_hint if source_hint in SUPPORTED_AI_SOURCES else ("obsidian_notion" if fn.endswith(".md") else "generic_ai")
    sections = [s.strip() for s in re.split(r"\n(?=#{1,3}\s+)|\n{2,}", txt) if s.strip()]
    turns = [{"role": "note", "text": s[:2000], "title": Path(filename).stem if filename else src, "ts": ""} for s in sections[:600]]
    return src, turns


def _unpack_input(
    *,
    filename: str = "",
    raw_text: str = "",
    raw_base64: str = "",
    source_hint: str = "auto",
) -> tuple[str, list[dict[str, str]]]:
    data_bytes: bytes | None = None
    if raw_base64:
        b64 = str(raw_base64).split(",", 1)[-1].strip()
        data_bytes = base64.b64decode(b64)

    # Распаковка ZIP (ChatGPT export.zip, Claude export.zip, Obsidian/Notion ZIP, Google Takeout.zip)
    if data_bytes and (str(filename).lower().endswith(".zip") or data_bytes[:4] == b"PK\x03\x04"):
        all_turns: list[dict[str, str]] = []
        detected = source_hint if source_hint in SUPPORTED_AI_SOURCES else "generic_ai"
        total_bytes = 0
        with zipfile.ZipFile(io.BytesIO(data_bytes)) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/") and not n.startswith("__MACOSX/")][:_MAX_ZIP_FILES]
            for name in names:
                ext = Path(name).suffix.lower()
                if ext not in (".json", ".jsonl", ".md", ".txt", ".html", ".htm"):
                    continue
                info = zf.getinfo(name)
                if total_bytes + info.file_size > _MAX_ZIP_BYTES:
                    break
                total_bytes += info.file_size
                piece = zf.read(name).decode("utf-8", errors="replace")
                sub_src, sub_turns = _extract_turns_from_text(piece, filename=name, source_hint=source_hint)
                if detected in ("generic_ai", "obsidian_notion") and sub_src != "generic_ai":
                    detected = sub_src
                all_turns.extend(sub_turns)
        if detected == "generic_ai" and any(n.endswith(".md") for n in names):
            detected = "obsidian_notion"
        return detected, all_turns

    text_val = raw_text or (data_bytes.decode("utf-8", errors="replace") if data_bytes else "")
    return _extract_turns_from_text(text_val, filename=filename, source_hint=source_hint)


def _classify_kind(text: str) -> str:
    for kind, rx in _KIND_PATTERNS:
        if rx.search(text):
            return kind
    return "fact"


def _is_chatter(text: str) -> bool:
    low = re.sub(r"[!?.…,;:]+$", "", text.strip().lower()).strip()
    if not low or low in _CHATTER_EXACT:
        return True
    if len(low) < 22 and not re.search(r"https?://|@|\d{2,}|=|:", low):
        return True
    return False


def _filter_and_sanitize_turns(
    turns: list[dict[str, str]],
    *,
    filter_chatter: bool = True,
    max_items: int = 120,
) -> dict[str, Any]:
    valuable: list[dict[str, Any]] = []
    seen_norm: set[str] = set()
    chatter_skipped = 0
    blocked_injections = 0
    redacted_secrets = 0
    lim = max(1, min(500, int(max_items)))

    for t in turns:
        raw = str(t.get("text") or "").strip()
        if not raw:
            continue
        if filter_chatter and _is_chatter(raw):
            chatter_skipped += 1
            continue
        red, sec_hits = safety.redact(raw)
        sec_cnt = sum(int(v) for v in sec_hits.values()) if isinstance(sec_hits, dict) else int(sec_hits or 0)
        redacted_secrets += sec_cnt

        if safety.looks_like_instruction(red) or safety.changes_owner_or_rules(red):
            blocked_injections += 1
            continue

        norm_key = re.sub(r"\s+", " ", red.lower())[:140]
        if norm_key in seen_norm:
            continue
        seen_norm.add(norm_key)

        kind = _classify_kind(red)
        title = str(t.get("title") or "").strip()
        content = f"[{title}] {red[:800]}" if title and not red.startswith(f"[{title}]") else red[:800]
        valuable.append({
            "kind": kind,
            "role": str(t.get("role") or "user"),
            "title": title,
            "content": content,
            "ts": str(t.get("ts") or ""),
            "redacted_secrets": sec_cnt,
        })
        if len(valuable) >= lim:
            break

    return {
        "total_turns": len(turns),
        "chatter_filtered": chatter_skipped,
        "blocked_injections": blocked_injections,
        "redacted_secrets": redacted_secrets,
        "valuable_count": len(valuable),
        "items": valuable,
    }


def list_supported_ai_sources() -> dict[str, Any]:
    """Возвращает полный каталог поддерживаемых ИИ-платформ и форматов переезда."""
    return {
        "ok": True,
        "count": len(SUPPORTED_AI_SOURCES),
        "sources": [
            {"id": k, "label": v["label"], "default_agent": v["default_agent"], "role": v["role"]}
            for k, v in SUPPORTED_AI_SOURCES.items()
        ],
    }


def preview_universal_import(
    memory: Any,
    *,
    filename: str = "",
    raw_text: str = "",
    raw_base64: str = "",
    source_hint: str = "auto",
    agent_id: str = "",
    filter_chatter: bool = True,
    max_items: int = 120,
) -> dict[str, Any]:
    """Анализирует загруженный файл любого ИИ без записи в БД: показывает превью фактов и очистку секретов."""
    detected, turns = _unpack_input(
        filename=filename,
        raw_text=raw_text,
        raw_base64=raw_base64,
        source_hint=source_hint,
    )
    meta = SUPPORTED_AI_SOURCES.get(detected, SUPPORTED_AI_SOURCES["generic_ai"])
    assigned_agent = sibling_registry._clean_agent_id(agent_id) if agent_id else meta["default_agent"]
    flt = _filter_and_sanitize_turns(turns, filter_chatter=filter_chatter, max_items=max_items)
    return {
        "ok": True,
        "detected_source": detected,
        "source_label": meta["label"],
        "assigned_agent_id": assigned_agent,
        "assigned_role": meta["role"],
        "total_turns": flt["total_turns"],
        "chatter_filtered": flt["chatter_filtered"],
        "blocked_injections": flt["blocked_injections"],
        "redacted_secrets": flt["redacted_secrets"],
        "valuable_count": flt["valuable_count"],
        "sample_items": flt["items"][:25],
    }


def commit_universal_import(
    memory: Any,
    *,
    filename: str = "",
    raw_text: str = "",
    raw_base64: str = "",
    source_hint: str = "auto",
    agent_id: str = "",
    scope: str = "global",
    filter_chatter: bool = True,
    max_items: int = 120,
    sync_chats: bool = True,
    register_sibling: bool = True,
) -> dict[str, Any]:
    """Переносит отфильтрованные, очищенные от секретов знания любого ИИ-Брата/Сестры в единую память PADAM."""
    detected, turns = _unpack_input(
        filename=filename,
        raw_text=raw_text,
        raw_base64=raw_base64,
        source_hint=source_hint,
    )
    meta = SUPPORTED_AI_SOURCES.get(detected, SUPPORTED_AI_SOURCES["generic_ai"])
    assigned_agent = sibling_registry._clean_agent_id(agent_id) if agent_id else meta["default_agent"]
    sc = str(scope or "global").strip() or "global"
    flt = _filter_and_sanitize_turns(turns, filter_chatter=filter_chatter, max_items=max_items)

    if register_sibling and memory is not None and getattr(memory, "store", None) is not None:
        try:
            sibling_registry.register_sibling(
                memory,
                agent_id=assigned_agent,
                display_name=meta["label"],
                role=meta["role"],
                client_type=f"import_{detected}",
            )
        except Exception:
            pass

    imported_ids: list[str] = []
    for item in flt["items"]:
        try:
            _, rec_id = memory.remember(
                f"[{detected}] {item['content']}",
                kind=item["kind"],
                scope=sc,
                origin="user",
                agent_id=assigned_agent,
            )
            if rec_id:
                imported_ids.append(str(rec_id))
        except Exception:
            continue

    chat_imported = False
    if sync_chats and flt["items"] and memory is not None:
        try:
            transcript = "\n".join(f"{it['role']}: {it['content']}" for it in flt["items"][:60])
            chats.import_chat(
                memory,
                agent_id=assigned_agent,
                title=f"Переезд {meta['label']} ({_utc_now()[:10]})",
                text=transcript,
                sync_memory_graph=False,
            )
            chat_imported = True
        except Exception:
            pass

    if memory is not None and getattr(memory, "store", None) is not None:
        audit_chain.append_audit(
            memory,
            "universal_ai_migration",
            {
                "source": detected,
                "agent_id": assigned_agent,
                "imported_count": len(imported_ids),
                "chatter_filtered": flt["chatter_filtered"],
                "blocked_injections": flt["blocked_injections"],
                "redacted_secrets": flt["redacted_secrets"],
            },
            agent_id=assigned_agent,
        )

    return {
        "ok": True,
        "detected_source": detected,
        "source_label": meta["label"],
        "assigned_agent_id": assigned_agent,
        "imported_count": len(imported_ids),
        "imported_ids": imported_ids[:30],
        "chatter_filtered": flt["chatter_filtered"],
        "blocked_injections": flt["blocked_injections"],
        "redacted_secrets": flt["redacted_secrets"],
        "chat_imported": chat_imported,
        "message_ru": (
            f"Переезд «{meta['label']}» ({assigned_agent}) завершён: перенесено {len(imported_ids)} ценных фактов "
            f"(отсеяно шума: {flt['chatter_filtered']}, замаскировано секретов: {flt['redacted_secrets']}, "
            f"отбито инъекций: {flt['blocked_injections']})."
        ),
    }
