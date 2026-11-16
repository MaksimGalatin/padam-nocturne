"""Локальный импортёр памяти из облачных чатов и других систем памяти (padam migrate).

Поддерживает: chatgpt, claude, gemini, grok, deepseek, copilot, perplexity, mem0, zep, obsidian, notion,
а также source="auto" — источник определяется по содержимому файла, папки или .zip-архива экспорта.

Форматы экспорта взяты из открытых импортёров и сверены минимум по двум независимым проектам
(16.11.2026): Gemini — Google Takeout «My Activity › Gemini Apps» в JSON (`MyActivity.json`, запись на
каждый запрос, ответ в `safeHtmlItem`); Grok — `prod-grok-backend.json` (`conversations[].responses[].response`);
DeepSeek — `conversations.json` с деревом `mapping` и фрагментами REQUEST/RESPONSE; Copilot — CSV
`Conversation,Time,Author,Message`; Perplexity — `conversations-*.json` (`entries[].query/answer`).

Все импортируемые записи проходят маскировку секретов (safety.redact) и при guarded=True проверяются
фаерволом внедрений (origin='external'). Архивы читаются в памяти, на диск ничего не распаковывается;
размер одного файла и общий объём ограничены, чтобы архив-бомба не уронила машину. Перед импортом
снимается снимок памяти этого scope, поэтому импорт можно отменить (undo_import) с квитанцией.
"""
from __future__ import annotations

import csv
import html as _html
import io
import json
import re
import zipfile
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable

from . import safety
from .memory import Memory

SUPPORTED_SOURCES = ("chatgpt", "claude", "gemini", "grok", "deepseek", "copilot", "perplexity",
                     "mem0", "zep", "obsidian", "notion", "official_mcp")
AUTO_SOURCES = ("chatgpt", "claude", "gemini", "grok", "deepseek", "copilot", "perplexity")

MAX_MEMBER_BYTES = 1024 * 1024 * 1024        # один файл внутри экспорта — не больше 1 ГиБ
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024     # всё прочитанное за один импорт — не больше 4 ГиБ
MAX_ZIP_MEMBERS = 200_000
CHUNK = 2000                                 # длинный ответ делится на записи по 2 000 знаков, а не обрезается

# Где человеку взять экспорт (по документации импортёров, сверено 16.11.2026).
EXPORT_HELP = {
    "chatgpt": {"url": "https://chatgpt.com/", "steps": "Settings › Data controls › Export data; the emailed link lasts 24 hours."},
    "claude": {"url": "https://claude.ai/settings", "steps": "Settings › Privacy › Export data; the emailed link lasts 24 hours."},
    "gemini": {"url": "https://takeout.google.com/", "steps": "Choose only My Activity › Gemini Apps and switch its format from HTML to JSON."},
    "grok": {"url": "https://accounts.x.ai/data", "steps": "Settings › Data Controls › Download account data; the link arrives by email."},
    "deepseek": {"url": "https://chat.deepseek.com/", "steps": "Settings › Data › Export data; the link lasts 7 days."},
    "copilot": {"url": "https://account.microsoft.com/privacy", "steps": "Copilot › Copilot apps › Export all activity history."},
    "perplexity": {"url": "https://www.perplexity.ai/", "steps": "All settings › Account › Export my data; the zip arrives by email."},
}


class _Member:
    """Один файл экспорта: обычный файл на диске или запись внутри .zip (в том числе .zip в .zip)."""

    def __init__(self, name: str, size: int, reader: Callable[[], bytes]) -> None:
        self.name = name.replace("\\", "/")
        self.size = size
        self._reader = reader

    @property
    def base(self) -> str:
        return self.name.rsplit("/", 1)[-1]

    def read(self) -> bytes:
        return self._reader()


class _Budget:
    def __init__(self) -> None:
        self.used = 0
        self.warnings: list[str] = []

    def take(self, member: _Member) -> bytes | None:
        if member.size > MAX_MEMBER_BYTES:
            self.warnings.append(f"{member.name}: larger than 1 GiB, skipped")
            return None
        if self.used + member.size > MAX_TOTAL_BYTES:
            self.warnings.append(f"{member.name}: import limit of 4 GiB reached, skipped")
            return None
        data = member.read()
        self.used += len(data)
        return data


def _zip_members(label: str, raw: bytes | None, path: Path | None, depth: int = 0) -> list[_Member]:
    zf = zipfile.ZipFile(io.BytesIO(raw)) if raw is not None else zipfile.ZipFile(path)  # type: ignore[arg-type]
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > MAX_ZIP_MEMBERS:
        raise ValueError(f"{label}: too many files in the archive ({len(infos)})")
    out: list[_Member] = []
    for info in infos:
        name = f"{label}/{info.filename}"
        if info.filename.lower().endswith(".zip") and depth < 1 and info.file_size <= MAX_MEMBER_BYTES:
            # ChatGPT иногда присылает «контейнер»: архив внутри архива.
            out.extend(_zip_members(name, zf.read(info), None, depth + 1))
            continue
        out.append(_Member(name, info.file_size, (lambda zf=zf, info=info: zf.read(info))))
    return out


def _collect(path: Path) -> list[_Member]:
    if path.is_dir():
        out: list[_Member] = []
        for f in sorted(path.rglob("*")):
            if f.is_file():
                if f.suffix.lower() == ".zip":
                    out.extend(_zip_members(str(f.relative_to(path)), None, f))
                else:
                    out.append(_Member(str(f.relative_to(path)), f.stat().st_size, f.read_bytes))
        return out
    if path.suffix.lower() == ".zip" or zipfile.is_zipfile(path):
        return _zip_members(path.name, None, path)
    return [_Member(path.name, path.stat().st_size, path.read_bytes)]


# ---------- время, текст ----------

_TIME_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                 "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
                 "%d/%m/%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S")


def _ts(val: Any) -> str | None:
    """Время в ISO 8601 UTC из чисел (секунды или миллисекунды), строк ISO, дат Copilot и дат Grok/Mongo."""
    if val is None or val == "":
        return None
    if isinstance(val, dict):  # Grok: {"$date": {"$numberLong": "…"}} или {"$date": "…"}
        inner = val.get("$date", val.get("$numberLong"))
        if isinstance(inner, dict):
            inner = inner.get("$numberLong")
        return _ts(int(inner) if isinstance(inner, str) and inner.isdigit() else inner)
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        sec = float(val) / 1000.0 if float(val) > 1e12 else float(val)
        try:
            return datetime.fromtimestamp(sec, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    s = str(val).strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        for fmt in _TIME_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


class _HtmlText(HTMLParser):
    _BREAK = {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self._BREAK:
            self.parts.append("\n")
        if tag == "li":
            self.parts.append("• ")

    def handle_endtag(self, tag):
        if tag in self._BREAK:
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def _html_to_text(s: str) -> str:
    if "<" not in s:
        return _html.unescape(s).strip()
    p = _HtmlText()
    p.feed(s)
    p.close()
    return re.sub(r"\n{3,}", "\n\n", "".join(p.parts)).strip()


def _chunks(text: str, size: int = CHUNK) -> list[str]:
    text = text.strip()
    if len(text) <= size:
        return [text]
    parts: list[str] = []
    while text:
        if len(text) <= size:
            parts.append(text)
            break
        cut = text.rfind("\n\n", 0, size)
        if cut < size // 2:
            cut = text.rfind(". ", 0, size)
            cut = cut + 1 if cut >= size // 2 else size
        parts.append(text[:cut].strip())
        text = text[cut:].strip()
    return [p for p in parts if p]


def _branch(parents: dict[str, str | None], times: dict[str, float | None], order: list[str],
            leaf: str | None = None) -> list[str]:
    """Нынешняя ветка дерева сообщений: от указанного (или самого нового) листа к корню."""
    children = {p for p in parents.values() if p}
    if not children:
        # Связей нет вовсе (плоский файл): это не дерево веток, а просто сообщения — берём все по времени.
        pos = {n: i for i, n in enumerate(order)}
        return sorted(order, key=lambda n: ((times.get(n) if times.get(n) is not None else float("inf")), pos[n]))
    leaves = [n for n in order if n not in children]
    if leaf not in parents:
        pos = {n: i for i, n in enumerate(order)}
        leaf = max(leaves or order, key=lambda n: ((times.get(n) or float("-inf")), pos[n])) if order else None
    out: list[str] = []
    seen: set[str] = set()
    while leaf and leaf not in seen and leaf in parents:
        seen.add(leaf)
        out.append(leaf)
        leaf = parents[leaf]
    return list(reversed(out))


# ---------- разговоры → записи ----------

def _conv(title: str, messages: list[tuple[str, str, str | None]]) -> dict[str, Any] | None:
    msgs = [(r, t.strip(), ts) for r, t, ts in messages if t and t.strip()]
    return {"title": (title or "").strip(), "messages": msgs} if msgs else None


def _items_from_conversations(convs: list[dict[str, Any]], *, user_label: str = "user") -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for c in convs:
        prefix = f"[{c['title']}] " if c["title"] else ""
        for role, text, ts in c["messages"]:
            label = user_label if role == "user" else role
            parts = _chunks(text)
            for i, part in enumerate(parts):
                mark = f" ({i + 1}/{len(parts)})" if len(parts) > 1 else ""
                if len(part) < 8:
                    continue
                items.append({"content": f"{prefix}{label}{mark}: {part}",
                              "kind": "event" if role == "user" else "fact",
                              "valid_from": ts,
                              # свои слова человека — его записи; ответы чат-бота — с доверием агента
                              "origin": "user" if role == "user" else "agent"})
    return items


def _json(data: bytes) -> Any:
    return json.loads(data.decode("utf-8-sig"))


def _parse_chatgpt_data(data: Any) -> list[dict[str, Any]]:
    convs = data if isinstance(data, list) else (data.get("conversations") or []) if isinstance(data, dict) else []
    out: list[dict[str, Any]] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        mapping = conv.get("mapping") or {}
        if not isinstance(mapping, dict):
            continue
        parents = {k: (v.get("parent") if isinstance(v, dict) else None) for k, v in mapping.items()}
        times: dict[str, float | None] = {}
        for k, v in mapping.items():
            msg = (v or {}).get("message") if isinstance(v, dict) else None
            ct = msg.get("create_time") if isinstance(msg, dict) else None
            times[k] = float(ct) if isinstance(ct, (int, float)) else None
        current = conv.get("current_node")
        ids = _branch(parents, times, list(mapping), current if isinstance(current, str) else None)
        msgs: list[tuple[str, str, str | None]] = []
        for k in ids:
            msg = (mapping.get(k) or {}).get("message")
            if not isinstance(msg, dict):
                continue
            role = ((msg.get("author") or {}).get("role") or "").strip()
            if role not in ("user", "assistant"):
                continue
            parts = ((msg.get("content") or {}).get("parts") or [])
            txt = "\n".join(str(p) for p in parts if isinstance(p, str) and p.strip())
            msgs.append((role, txt, _ts(msg.get("create_time") or conv.get("create_time"))))
        c = _conv(str(conv.get("title") or ""), msgs)
        if c:
            out.append(c)
    return out


def _parse_deepseek_data(data: Any) -> list[dict[str, Any]]:
    convs = data if isinstance(data, list) else (data.get("conversations") or []) if isinstance(data, dict) else []
    out: list[dict[str, Any]] = []
    for conv in convs:
        mapping = conv.get("mapping") if isinstance(conv, dict) else None
        if not isinstance(mapping, dict):
            continue
        parents: dict[str, str | None] = {}
        times: dict[str, float | None] = {}
        for k, v in mapping.items():
            v = v if isinstance(v, dict) else {}
            parents[k] = v.get("parent") if isinstance(v.get("parent"), str) else None
            stamp = _ts((v.get("message") or {}).get("inserted_at") if isinstance(v.get("message"), dict) else None)
            times[k] = datetime.fromisoformat(stamp).timestamp() if stamp else None
        for k, v in mapping.items():
            for ch in (v or {}).get("children") or [] if isinstance(v, dict) else []:
                if isinstance(ch, str) and ch in parents and parents[ch] is None and ch != k:
                    parents[ch] = k
        msgs: list[tuple[str, str, str | None]] = []
        for k in _branch(parents, times, list(mapping)):
            msg = (mapping.get(k) or {}).get("message")
            if not isinstance(msg, dict):
                continue
            role = None
            pieces: list[str] = []
            for fr in msg.get("fragments") or []:
                if not isinstance(fr, dict):
                    continue
                kind = str(fr.get("type") or "").upper()
                if kind == "REQUEST":
                    role = "user"
                    pieces.append(str(fr.get("content") or ""))
                elif kind == "RESPONSE":
                    role = role or "assistant"
                    pieces.append(str(fr.get("content") or ""))
                # THINK — рассуждения модели, в память не берём
            if role:
                msgs.append((role, "\n".join(p for p in pieces if p.strip()), _ts(msg.get("inserted_at"))))
        c = _conv(str(conv.get("title") or ""), msgs)
        if c:
            out.append(c)
    return out


def _parse_claude_data(data: Any) -> list[dict[str, Any]]:
    convs = data if isinstance(data, list) else (data.get("conversations") or []) if isinstance(data, dict) else []
    out: list[dict[str, Any]] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        msgs: list[tuple[str, str, str | None]] = []
        for msg in conv.get("chat_messages") or []:
            if not isinstance(msg, dict):
                continue
            sender = str(msg.get("sender") or "human").strip()
            txt = str(msg.get("text") or "")
            if not txt.strip() and isinstance(msg.get("content"), list):
                txt = "\n".join(str(b.get("text") or "") for b in msg["content"] if isinstance(b, dict))
            role = "user" if sender in ("human", "user") else "assistant"
            msgs.append((role, txt, _ts(msg.get("created_at") or conv.get("created_at"))))
        c = _conv(str(conv.get("name") or conv.get("title") or ""), msgs)
        if c:
            out.append(c)
    return out


_GEMINI_PROMPT = ("Prompted ", "Eingegebener Prompt: ", "Prompt eingegeben: ", "Prompt saisi : ", "Requête : ",
                  "Instrucción: ", "Prompt: ", "Prompt inserito: ", "Prompt enviado: ", "Запрос: ")
_GEMINI_OTHER = ("Created ", "Cleared ", "Gave feedback", "Used ", "Deleted ", "Selected ", "Shared ")
_GEMINI_CHAT = re.compile(r"gemini\.google\.com/(?:u/\d+/)?app/([0-9A-Za-z_-]+)")


def _is_gemini_record(r: Any) -> bool:
    if not isinstance(r, dict):
        return False
    labels = [str(r.get("header") or "")] + [str(x) for x in (r.get("products") or [])]
    return any("gemini" in s.lower() or "bard" in s.lower() for s in labels)


def _parse_gemini_data(data: Any) -> list[dict[str, Any]]:
    rows = data if isinstance(data, list) else []
    chats: dict[str, list[tuple[str, int, str, str]]] = {}
    for idx, r in enumerate(rows):
        if not _is_gemini_record(r):
            continue
        answer = "\n\n".join(_html_to_text(str((x or {}).get("html") or "")) for x in r.get("safeHtmlItem") or []
                             if isinstance(x, dict))
        title = str(r.get("title") or "").strip()
        prompt = None
        for pre in _GEMINI_PROMPT:
            if title.startswith(pre):
                prompt = title[len(pre):].strip()
                break
        if prompt is None:
            if title.startswith(_GEMINI_OTHER) or not answer:
                continue
            prompt = title
        chat = None
        for d in (r.get("details") or []) + (r.get("subtitles") or []):
            if isinstance(d, dict):
                m = _GEMINI_CHAT.search(str(d.get("url") or d.get("value") or ""))
                if m:
                    chat = m.group(1)
                    break
        if chat is None:
            m = _GEMINI_CHAT.search(str(r.get("titleUrl") or ""))
            chat = m.group(1) if m else f"single-{idx}"
        chats.setdefault(chat, []).append((_ts(r.get("time")) or "", -idx, prompt, answer))
    out: list[dict[str, Any]] = []
    for chat, turns in chats.items():
        turns.sort(key=lambda t: (t[0], t[1]))
        msgs: list[tuple[str, str, str | None]] = []
        for stamp, _, prompt, answer in turns:
            msgs.append(("user", prompt, stamp or None))
            if answer:
                msgs.append(("assistant", answer, stamp or None))
        day = (turns[0][0] or "")[:10]
        c = _conv(f"Gemini {day}".strip(), msgs)
        if c:
            out.append(c)
    return out


_GROK_RENDER = re.compile(r"<grok:render\b[^>]*?(?:/>|>.*?</grok:render>)", re.DOTALL)
_GROK_ARTIFACT = re.compile(r"</?xaiArtifact\b[^>]*>")


def _parse_grok_data(data: Any) -> list[dict[str, Any]]:
    items = (data.get("conversations") or []) if isinstance(data, dict) else data if isinstance(data, list) else []
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        head = item.get("conversation") if isinstance(item.get("conversation"), dict) else {}
        responses: dict[str, dict] = {}
        order: list[str] = []
        for i, w in enumerate(item.get("responses") or []):
            if not isinstance(w, dict):
                continue
            r = w.get("response") if isinstance(w.get("response"), dict) else w
            rid = str(r.get("_id") or r.get("id") or f"#{i}")
            responses[rid] = r
            order.append(rid)
        times: dict[str, float | None] = {}
        for rid, r in responses.items():
            s = _ts(r.get("create_time"))
            times[rid] = datetime.fromisoformat(s).timestamp() if s else None
        if any(r.get("parent_response_id") for r in responses.values()):
            parents = {rid: (str(r.get("parent_response_id")) if r.get("parent_response_id") else None)
                       for rid, r in responses.items()}
            leaf = head.get("leaf_response_id")
            chosen = _branch(parents, times, order, str(leaf) if leaf else None)
        else:
            pos = {rid: i for i, rid in enumerate(order)}
            chosen = sorted(order, key=lambda rid: (times[rid] if times[rid] is not None else float("inf"),
                                                    0 if str(responses[rid].get("sender")).lower() == "human" else 1,
                                                    pos[rid]))
        msgs: list[tuple[str, str, str | None]] = []
        for rid in chosen:
            r = responses[rid]
            role = {"human": "user", "user": "user", "assistant": "assistant"}.get(str(r.get("sender") or "").lower())
            text = _GROK_ARTIFACT.sub("", _GROK_RENDER.sub("", str(r.get("message") or ""))).strip()
            if role:
                msgs.append((role, text, _ts(r.get("create_time"))))
        c = _conv(str(head.get("title") or ""), msgs)
        if c:
            out.append(c)
    return out


_COPILOT_HEADER = ["Conversation", "Time", "Author", "Message"]


def _is_copilot_csv(head: bytes) -> bool:
    text = head.lstrip(b"\xef\xbb\xbf").decode("utf-8", "replace")
    first = text.splitlines()[0] if text else ""
    return [c.strip().strip('"') for c in first.split(",")] == _COPILOT_HEADER


def _parse_copilot_csv(data: bytes) -> list[dict[str, Any]]:
    rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig", "replace"))))
    if not rows or [c.strip() for c in rows[0]] != _COPILOT_HEADER:
        return []
    roles = {"human": "user", "user": "user", "ai": "assistant", "assistant": "assistant", "copilot": "assistant"}
    chats: list[tuple[str, list[tuple[str, str, str | None]]]] = []
    open_: dict[str, int] = {}
    last_dt: dict[int, datetime] = {}
    for row in reversed(rows[1:]):  # файл идёт от новых к старым; переворачиваем, а не сортируем
        if len(row) < 4:
            continue
        title, when, author, text = row[0], row[1], row[2], row[3]
        role = roles.get(author.strip().lower())
        if role is None or not text.strip():
            continue
        stamp = _ts(when)
        dt = datetime.fromisoformat(stamp) if stamp else None
        idx = open_.get(title)
        if idx is not None and dt and idx in last_dt and dt - last_dt[idx] > timedelta(hours=12):
            idx = None  # у Copilot нет id чатов: тот же заголовок спустя 12 часов — новый чат
        if idx is None:
            chats.append((title, []))
            idx = len(chats) - 1
            open_[title] = idx
        chats[idx][1].append((role, text, stamp))
        if dt:
            last_dt[idx] = dt
    return [c for c in (_conv(t, m) for t, m in chats) if c]


_PERPLEXITY_MARKS = re.compile(r"\s?\[\d{1,3}\](?:\[\d{1,3}\])*")


def _parse_perplexity_data(data: Any) -> list[dict[str, Any]]:
    convs = data if isinstance(data, list) else (data.get("conversations") or []) if isinstance(data, dict) else []
    out: list[dict[str, Any]] = []
    for conv in convs:
        if not isinstance(conv, dict):
            continue
        msgs: list[tuple[str, str, str | None]] = []
        for e in conv.get("entries") or []:
            if not isinstance(e, dict):
                continue
            stamp = _ts(e.get("created_at"))
            msgs.append(("user", str(e.get("query") or ""), stamp))
            msgs.append(("assistant", _PERPLEXITY_MARKS.sub("", str(e.get("answer") or "")), stamp))
        c = _conv(str(conv.get("context_title") or "")[:120], msgs)
        if c:
            out.append(c)
    return out


def _parse_mem0_or_zep_data(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("results") or data.get("memories") or data.get("facts") or data.get("messages") or []
    else:
        rows = []
    items: list[dict[str, Any]] = []
    for r in rows:
        if isinstance(r, str):
            txt, ts = r.strip(), None
        elif isinstance(r, dict):
            txt = str(r.get("memory") or r.get("fact") or r.get("content") or r.get("text") or "").strip()
            ts = _ts(r.get("created_at") or r.get("updated_at") or r.get("valid_at"))
        else:
            continue
        if txt:
            items.append({"content": txt[:CHUNK], "kind": "fact", "valid_from": ts})
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
            for i, part in enumerate(_chunks(txt) if txt else []):
                mark = f" ({i + 1})" if i else ""
                items.append({"content": f"[{f.stem}{mark}] {part}", "kind": "fact", "valid_from": None})
        elif suf == ".csv":
            with f.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
                for row in csv.DictReader(fh):
                    line = " | ".join(f"{k}: {v}" for k, v in row.items() if v and str(v).strip())
                    if line:
                        items.append({"content": line[:CHUNK], "kind": "fact", "valid_from": None})
    return items


# ---------- определение источника ----------

def _classify(member: _Member, head: bytes) -> str | None:
    base = member.base.lower()
    if base == "prod-grok-backend.json":
        return "grok"
    if base.endswith(".csv") and _is_copilot_csv(head):
        return "copilot"
    if base.startswith("conversations-") and base.endswith(".json"):
        return "perplexity"
    if base == "myactivity.json":
        return "gemini?"
    if base == "conversations.json":
        return "conversations?"
    return None


def _resolve(kind: str, data: Any) -> str | None:
    if kind == "gemini?":
        rows = data if isinstance(data, list) else []
        return "gemini" if any(_is_gemini_record(r) for r in rows[:200]) else None
    if kind == "conversations?":
        convs = data if isinstance(data, list) else (data.get("conversations") or []) if isinstance(data, dict) else []
        for conv in convs[:50]:
            if not isinstance(conv, dict):
                continue
            if "chat_messages" in conv:
                return "claude"
            if "entries" in conv and "context_uuid" in conv:
                return "perplexity"
            mapping = conv.get("mapping")
            if isinstance(mapping, dict):
                for node in mapping.values():
                    msg = (node or {}).get("message") if isinstance(node, dict) else None
                    if isinstance(msg, dict):
                        if "fragments" in msg:
                            return "deepseek"
                        if "author" in msg:
                            return "chatgpt"
        return None
    return kind


_PARSERS: dict[str, Callable[[Any], list[dict[str, Any]]]] = {
    "chatgpt": _parse_chatgpt_data, "claude": _parse_claude_data, "gemini": _parse_gemini_data,
    "grok": _parse_grok_data, "deepseek": _parse_deepseek_data, "perplexity": _parse_perplexity_data,
}


def _scan(path: Path, wanted: str) -> tuple[str, list[dict[str, Any]], list[str], list[str]]:
    """Возвращает (источник, разговоры, использованные файлы, предупреждения) для чатовых источников."""
    budget = _Budget()
    found: dict[str, list[dict[str, Any]]] = {}
    used: dict[str, list[str]] = {}
    for member in _collect(path):
        head_ok = member.base.lower().endswith((".json", ".csv"))
        if not head_ok:
            continue
        kind = None
        if wanted in ("auto",):
            kind = _classify(member, b"")
            if kind is None and member.base.lower().endswith(".csv"):
                data = budget.take(member)
                if data is not None and _is_copilot_csv(data[:4096]):
                    convs = _parse_copilot_csv(data)
                    found.setdefault("copilot", []).extend(convs)
                    used.setdefault("copilot", []).append(member.name)
                continue
        elif wanted == "copilot":
            kind = "copilot" if member.base.lower().endswith(".csv") else None
        else:
            kind = _classify(member, b"") or ("conversations?" if member.base.lower().endswith(".json") else None)
        if kind is None:
            continue
        data = budget.take(member)
        if data is None:
            continue
        if kind == "copilot":
            if _is_copilot_csv(data[:4096]):
                found.setdefault("copilot", []).extend(_parse_copilot_csv(data))
                used.setdefault("copilot", []).append(member.name)
            continue
        try:
            obj = _json(data)
        except (ValueError, UnicodeDecodeError):
            budget.warnings.append(f"{member.name}: not valid JSON, skipped")
            continue
        src = _resolve(kind, obj) if kind.endswith("?") else kind
        if wanted != "auto" and src is None and kind.endswith("?"):
            src = wanted  # явно выбранный источник: пробуем разобрать даже нестандартный файл
        if src is None or (wanted != "auto" and src != wanted):
            continue
        convs = _PARSERS[src](obj)
        found.setdefault(src, []).extend(convs)
        used.setdefault(src, []).append(member.name)
    if not found:
        return (wanted if wanted != "auto" else "unknown"), [], [], budget.warnings
    if wanted == "auto" and len(found) > 1:
        budget.warnings.append("several exports found: " + ", ".join(sorted(found)) + "; the largest one is used")
    src = wanted if wanted != "auto" else max(found, key=lambda s: sum(len(c["messages"]) for c in found[s]))
    return src, found[src], used[src], budget.warnings


def _parse_official_mcp_jsonl(p: Path) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Разбор файла memory.jsonl официального сервера @modelcontextprotocol/server-memory."""
    target = p
    if p.is_dir():
        cand = p / "memory.jsonl"
        if not cand.exists():
            jsonls = sorted(p.glob("*.jsonl"))
            if not jsonls:
                return [], [], [f"{p}: no memory.jsonl found"]
            cand = jsonls[0]
        target = cand
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    text = target.read_text(encoding="utf-8", errors="replace")
    for idx, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            warnings.append(f"{target.name}:{idx}: malformed JSON line skipped")
            continue
        if not isinstance(obj, dict):
            continue
        rtype = obj.get("type")
        if rtype == "entity":
            name = str(obj.get("name") or "").strip()
            etype = str(obj.get("entityType") or "entity").strip()
            if not name:
                continue
            obs_list = [str(o).strip() for o in (obj.get("observations") or []) if str(o).strip()]
            if not obs_list:
                items.append({"content": f"[entity:{name} type:{etype}]", "kind": "fact", "origin": "external"})
            else:
                for obs in obs_list:
                    items.append({"content": f"[entity:{name} type:{etype}] {obs}", "kind": "fact", "origin": "external"})
        elif rtype == "relation":
            src = str(obj.get("from") or "").strip()
            dst = str(obj.get("to") or "").strip()
            rel = str(obj.get("relationType") or "").strip()
            if src and dst and rel:
                items.append({"content": f"[relation:{src} --({rel})--> {dst}]", "kind": "fact", "origin": "external"})
    return items, [target.name], warnings


def _parse(src_req: str, p: Path) -> dict[str, Any]:
    """Разбор без записи: источник, разговоры, записи, файлы, предупреждения."""
    if src_req in ("mem0", "zep"):
        items = _parse_mem0_or_zep_data(_json(p.read_bytes()))
        return {"source": src_req, "conversations": [], "items": items, "files": [p.name], "warnings": []}
    if src_req in ("obsidian", "notion"):
        items = _parse_markdown_or_notion(p)
        return {"source": src_req, "conversations": [], "items": items, "files": [p.name], "warnings": []}
    if src_req == "official_mcp" or (src_req == "auto" and ((p.is_file() and p.suffix.lower() == ".jsonl") or (p.is_dir() and (p / "memory.jsonl").exists()))):
        items, files, warnings = _parse_official_mcp_jsonl(p)
        if items or src_req == "official_mcp":
            return {"source": "official_mcp", "conversations": [], "items": items, "files": files, "warnings": warnings}
    src, convs, files, warnings = _scan(p, src_req)
    label = "human" if src == "claude" else "user"   # прежний вид записей Claude сохранён
    return {"source": src, "conversations": convs, "items": _items_from_conversations(convs, user_label=label),
            "files": files, "warnings": warnings}


def _check(source: str, input_path: Path | str) -> tuple[str, Path]:
    src = (source or "auto").strip().lower()
    if src != "auto" and src not in SUPPORTED_SOURCES:
        raise ValueError(f"Unsupported migration source: {source}")
    p = Path(input_path)
    if not p.exists():
        raise FileNotFoundError(f"Migration input not found: {p}")
    return src, p


def preview(*, source: str = "auto", input_path: Path | str) -> dict[str, Any]:
    """Что будет импортировано — без записи в память: источник, разговоры, сообщения, период, скрытые ключи."""
    src, p = _check(source, input_path)
    r = _parse(src, p)
    stamps = sorted(it["valid_from"] for it in r["items"] if it.get("valid_from"))
    secrets = sum(len(safety.redact(it["content"])[1]) for it in r["items"])
    return {
        "source": r["source"], "files": r["files"][:20], "warnings": r["warnings"],
        "conversations": len(r["conversations"]),
        "messages": sum(len(c["messages"]) for c in r["conversations"]),
        "records": len(r["items"]), "secrets_to_mask": secrets,
        "date_from": stamps[0][:10] if stamps else None, "date_to": stamps[-1][:10] if stamps else None,
        "sample_titles": [c["title"] for c in r["conversations"][:5]],
        "how_to_export": EXPORT_HELP.get(r["source"]),
    }


def migrate_from_source(
    mem: Memory,
    *,
    source: str = "auto",
    input_path: Path | str,
    scope: str = "imported",
    dry_run: bool = False,
    guarded: bool = True,
    hold_all: bool = False,
) -> dict[str, Any]:
    """Импорт экспорта. Проверка «похоже на приказ» и маскировка ключей работают всегда (guarded=True);
    hold_all=True держит у владельца на проверке каждую запись, как прежде (origin='external')."""
    src, p = _check(source, input_path)
    r = _parse(src, p)
    src = r["source"]
    if src == "unknown":
        return {"source": "unknown", "scope": scope, "dry_run": bool(dry_run), "parsed": 0, "imported": 0,
                "quarantined": 0, "redacted_secrets": 0, "warnings": r["warnings"] + [
                    "no known export found: choose the source by hand or check the file"]}
    snapshot_id = None
    if not dry_run and r["items"]:
        snapshot_id = mem.snapshot(name=f"before-migrate-{src}", scope=scope,
                                   note=f"padam migrate from {src}").get("snapshot_id")

    imported = quarantined = redacted_secrets = 0
    for it in r["items"]:
        if not guarded:
            origin = "user"
        elif hold_all:
            origin = "external"
        else:
            origin = it.get("origin", "external")
        cleaned, hits = safety.redact(it["content"])
        if hits:
            redacted_secrets += len(hits)
        if dry_run:
            continue
        st, _ = mem.remember(cleaned, kind=it["kind"], scope=scope, origin=origin, guarded=guarded,
                             agent_id=f"migrate:{src}", valid_from=it.get("valid_from"))
        if st == "quarantined":
            quarantined += 1
        elif st != "duplicate":
            imported += 1

    return {
        "source": src,
        "scope": scope,
        "dry_run": bool(dry_run),
        "parsed": len(r["items"]),
        "conversations": len(r["conversations"]),
        "imported": imported,
        "quarantined": quarantined,
        "redacted_secrets": redacted_secrets,
        "snapshot_id": snapshot_id,
        "warnings": r["warnings"],
    }


def undo_import(mem: Memory, *, snapshot_id: str, scope: str = "imported") -> dict[str, Any]:
    """Отменяет импорт: откат scope к снимку, снятому перед импортом, с квитанциями забвения."""
    if not snapshot_id:
        raise ValueError("snapshot_id is required")
    return mem.rollback(snapshot_id=snapshot_id, scope=scope, reason="undo padam migrate")
