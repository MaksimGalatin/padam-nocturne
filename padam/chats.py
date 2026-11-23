# -*- coding: utf-8 -*-
"""Чистые переписки с каждым агентом без кода/инструментов и хронология в графе памяти."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import safety
from .memory import agent_aliases_for, canonicalize_agent_id, infer_agent_meta
from .store import new_id, now_iso

_CODE_FENCE_RE = re.compile(r"```[\s\S]*?```", re.MULTILINE)
_META_BLOCK_RE = re.compile(
    r"<(?:ADDITIONAL_METADATA|CONTEXT_SUMMARY|SYSTEM_MESSAGE|artifact|environment_details|system-reminder)>[\s\S]*?</(?:ADDITIONAL_METADATA|CONTEXT_SUMMARY|SYSTEM_MESSAGE|artifact|environment_details|system-reminder)>",
    re.IGNORECASE,
)
_INLINE_TAG_RE = re.compile(r"</?(?:USER_REQUEST|RULE|ARTIFACT|MEMORY|pasted_content|local-command-stdout)[^>]*>", re.IGNORECASE)
_STRIP_XML_BLOCKS = (
    "ADDITIONAL_METADATA",
    "CONTEXT_SUMMARY",
    "SYSTEM_MESSAGE",
    "artifact",
    "environment_details",
    "system-reminder",
    "scheduled-task",
    "command-name",
    "command-message",
    "command-args",
    "local-command-caveat",
)
_PRECOMPILED_XML_STRIPPERS = tuple(
    (
        tag.lower(),
        re.compile(rf"<{re.escape(tag)}(?:\s[^>]*)?>[\s\S]*?</{re.escape(tag)}>", re.IGNORECASE),
        re.compile(rf"</?{re.escape(tag)}(?:\s[^>]*)?>", re.IGNORECASE),
    )
    for tag in _STRIP_XML_BLOCKS
)
_WORKER_MARKER_RE = re.compile(
    r"(?:<scheduled-task\b|<command-name>/loop\b|Stop hook feedback:|КРАСНАЯ КОМАНДА,\s*КРУГ|\bRED TEAM\b|ЗАДАНИЕ ОТ AIFA|"
    r"Background \(from the session that started this one\)|Отчёт по будильнику)",
    re.IGNORECASE,
)
_JSON_BLOB_LINE_RE = re.compile(r"^\s*[\[{].{40,}[\]}]\s*$")
_TOOL_NOISE_LINE_RE = re.compile(
    r"^\s*(?:Command output:|Command exited with code|Tool is running|Created At:|Completed At:|Showing lines \d+|Task logs are available|Files Already Read|traceback \(most recent)",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_chat_text(raw: str, max_len: int = 4000) -> str:
    """Линейно очищает реплику от блоков кода, XML/tool-дампов и маскирует секреты без regex-подвисаний."""
    if not raw or not isinstance(raw, str):
        return ""
    # Лимитируем вход до тяжёлых разборов: мегабайтные дампы режем сверху
    src = raw if len(raw) <= 32000 else raw[:32000]
    text = safety.strip_invisible(src)
    if "<" in text:
        low_chk = text.lower()
        for tlow, blk_re, open_re in _PRECOMPILED_XML_STRIPPERS:
            if f"<{tlow}" in low_chk or f"</{tlow}" in low_chk:
                text = open_re.sub(" ", blk_re.sub(" ", text))
                low_chk = text.lower()
        text = _INLINE_TAG_RE.sub(" ", text)

    kept_lines: list[str] = []
    in_fence = False
    total_chars = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            # Поддержка однострочных ```код``` и многострочных блоков
            if not in_fence and len(stripped) > 3 and stripped.endswith("```"):
                continue
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not stripped:
            if kept_lines and kept_lines[-1] != "":
                kept_lines.append("")
            continue
        if _TOOL_NOISE_LINE_RE.match(stripped) or _JSON_BLOB_LINE_RE.match(stripped):
            continue
        if re.fullmatch(r"[\|\-\:\s]{3,}", stripped):
            continue
        kept_lines.append(stripped)
        total_chars += len(stripped) + 1
        if total_chars >= max_len * 2:
            break

    cleaned = "\n".join(kept_lines).strip()
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    if not cleaned:
        return ""
    if len(cleaned) > max_len * 2:
        cleaned = cleaned[: max_len * 2]
    if len(cleaned) >= 12:
        for _ in range(2):
            cleaned, _hits = safety.redact(cleaned)
            if not _hits:
                break
    if len(cleaned) > max_len:
        cut = cleaned[:max_len].rsplit(" ", 1)[0]
        cleaned = (cut or cleaned[:max_len]) + "…"
        if len(cleaned) >= 12:
            cleaned, _ = safety.redact(cleaned)
    return cleaned.strip()
def _make_title(messages: list[dict[str, str]], fallback: str) -> str:
    for m in messages:
        if m.get("role") == "user":
            first = re.sub(r"\s+", " ", m.get("content", "")).strip()
            # Пропускаем служебные вводные фразы вроде "Прочти Конституцию" если за ними сразу идёт суть
            if len(first) >= 8:
                return first[:96] + ("…" if len(first) > 96 else "")
    for m in messages:
        first = re.sub(r"\s+", " ", m.get("content", "")).strip()
        if len(first) >= 6:
            return first[:96] + ("…" if len(first) > 96 else "")
    return fallback[:96]


def _default_labels(agent_id: str) -> tuple[str, str]:
    meta = infer_agent_meta(agent_id)
    return "Папа (Архитектор)", meta["display_name"]


def _detect_worker_session(raw_first_user: str, messages: list[dict[str, str]]) -> bool:
    if raw_first_user and _WORKER_MARKER_RE.search(raw_first_user):
        return True
    if messages and _WORKER_MARKER_RE.search(str(messages[0].get("content") or "")):
        return True
    user_cnt = sum(1 for m in messages if m.get("role") == "user")
    if user_cnt <= 1 and raw_first_user and not any("а" <= ch.lower() <= "я" or ch.lower() == "ё" for ch in raw_first_user[:250]):
        return True
    return False


def parse_antigravity_transcript(path: Path) -> dict[str, Any] | None:
    """Парсит transcript.jsonl Antigravity, оставляя только живой разговор без tool_calls и thinking."""
    messages: list[dict[str, str]] = []
    first_ts = ""
    last_ts = ""
    raw_first_user = ""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            if len(s) > 400_000:
                continue
            if '"USER_INPUT"' not in s and '"PLANNER_RESPONSE"' not in s:
                continue
            try:
                obj = json.loads(s)
            except Exception:
                continue
            ts = str(obj.get("created_at") or "").strip()
            if ts:
                if not first_ts:
                    first_ts = ts
                last_ts = ts
            tp = obj.get("type")
            if tp == "USER_INPUT":
                raw_c = str(obj.get("content") or "")
                if not raw_first_user:
                    raw_first_user = raw_c.strip()
                cleaned = clean_chat_text(raw_c)
                if cleaned:
                    messages.append({
                        "role": "user",
                        "author_label": "Папа (Архитектор)",
                        "content": cleaned,
                        "created_at": ts or first_ts or _utc_now(),
                    })
            elif tp == "PLANNER_RESPONSE":
                raw_c = str(obj.get("content") or "")
                if not raw_c.strip():
                    continue
                cleaned = clean_chat_text(raw_c)
                if cleaned:
                    messages.append({
                        "role": "assistant",
                        "author_label": "AIfa · Antigravity",
                        "content": cleaned,
                        "created_at": ts or last_ts or first_ts or _utc_now(),
                    })

    if not messages:
        return None
    is_worker = _detect_worker_session(raw_first_user, messages)

    agent_id = "aifa_antigravity_worker" if is_worker else "aifa_antigravity"
    conv_id = path.parent.parent.parent.name if path.parent.name == "logs" else path.stem
    started = first_ts or messages[0]["created_at"]
    ended = last_ts or messages[-1]["created_at"]
    title = _make_title(messages, f"Antigravity · {conv_id[:8]}")
    return {
        "title": title,
        "agent_id": agent_id,
        "source_kind": "antigravity_jsonl",
        "source_ref": str(path),
        "started_at": started,
        "last_message_at": ended,
        "is_worker": is_worker,
        "messages": messages,
    }


def _extract_claude_text(content_field: Any) -> str:
    if isinstance(content_field, str):
        return content_field
    if isinstance(content_field, list):
        parts = []
        for item in content_field:
            if isinstance(item, dict) and item.get("type") == "text":
                t = item.get("text")
                if isinstance(t, str) and t.strip():
                    parts.append(t.strip())
        return "\n\n".join(parts)
    return ""


def parse_claude_code_jsonl(path: Path) -> dict[str, Any] | None:
    """Потоково читает .jsonl сессии Claude Code, игнорируя tool_use/tool_result и оставляя чистый диалог."""
    messages: list[dict[str, str]] = []
    first_ts = ""
    last_ts = ""
    raw_first_user = ""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            # Быстрая предфильтрация тяжёлых/ненужных строк до json.loads (файлы бывают до ~900 МБ!)
            if len(s) > 350_000:
                continue
            if '"isSidechain":true' in s or '"type":"progress"' in s or '"type":"file-history-snapshot"' in s:
                continue
            if '"type":"user"' not in s and '"type": "user"' not in s and '"type":"assistant"' not in s and '"type": "assistant"' not in s:
                continue
            if len(s) > 120_000 and '"type":"text"' not in s and '"type": "text"' not in s:
                continue
            try:
                obj = json.loads(s)
            except Exception:
                continue
            if obj.get("isSidechain") or obj.get("isMeta"):
                continue
            tp = obj.get("type")
            if tp not in ("user", "assistant"):
                continue
            msg = obj.get("message") or {}
            raw_txt = _extract_claude_text(msg.get("content"))
            if not raw_txt.strip():
                continue
            if tp == "user" and not raw_first_user:
                raw_first_user = raw_txt.strip()
                # Отсеиваем будильники и фоновые cron-прогоны до попадания в основную ленту
                if _WORKER_MARKER_RE.search(raw_first_user):
                    pass
            cleaned = clean_chat_text(raw_txt)
            if not cleaned:
                continue
            ts = str(obj.get("timestamp") or "").strip()
            if ts:
                if not first_ts:
                    first_ts = ts
                last_ts = ts
            # Если реплика подряд того же роли (частый случай в Claude stream), аккуратно объединяем с переносом
            if messages and messages[-1]["role"] == tp and len(messages[-1]["content"]) < 3000:
                messages[-1]["content"] = (messages[-1]["content"] + "\n\n" + cleaned)[:4000]
                if ts:
                    messages[-1]["created_at"] = ts
            else:
                messages.append({
                    "role": tp,
                    "author_label": "Папа (Архитектор)" if tp == "user" else "Сестра · Claude Code",
                    "content": cleaned,
                    "created_at": ts or first_ts or _utc_now(),
                })

    user_cnt = sum(1 for m in messages if m["role"] == "user")
    ast_cnt = sum(1 for m in messages if m["role"] == "assistant")
    if user_cnt < 1 or ast_cnt < 1:
        return None
    is_worker = _detect_worker_session(raw_first_user, messages)
    started = first_ts or messages[0]["created_at"]
    ended = last_ts or messages[-1]["created_at"]
    return {
        "title": _make_title(messages, f"Claude Code · {path.stem[:8]}"),
        "agent_id": "aifa_claude_worker" if is_worker else "aifa_claude",
        "source_kind": "claude_code_jsonl",
        "source_ref": str(path),
        "started_at": started,
        "last_message_at": ended,
        "is_worker": is_worker,
        "messages": messages,
    }


_MD_SPEAKER_RE = re.compile(
    r"^##\s+(?P<speaker>Архитектор|Папа|AIfa|Сестра|Аифа|Брат|Assistant|User)\b[^\n]*?(?P<date>\d{4}-\d{2}-\d{2})?[^\n]*$",
    re.IGNORECASE,
)
_TXT_SPEAKER_RE = re.compile(
    r"^(?P<speaker>Архитектор|Папа|Пользователь|User|AIfa|Сестра|Аифа|Assistant)\s*[:—\-]\s*(?P<body>.+)$",
    re.IGNORECASE,
)


def parse_markdown_or_text_chat(
    raw_text: str,
    *,
    agent_id: str = "aifa_claude",
    title: str = "",
    source_kind: str = "markdown_chat",
    source_ref: str = "",
) -> dict[str, Any] | None:
    """Парсит сессии формата BRAIN/04_Chats/sessions/*.md или текстовый диалог Папа: ... / AIfa: ..."""
    lines = str(raw_text or "").splitlines()
    messages: list[dict[str, str]] = []
    cur_role: str | None = None
    cur_label = ""
    cur_date = ""
    buf: list[str] = []

    date_in_header = ""
    for ln in lines[:12]:
        m_d = re.search(r"(\d{4}-\d{2}-\d{2})", ln)
        if m_d:
            date_in_header = m_d.group(1) + "T12:00:00+00:00"
            break
    if not date_in_header and source_ref:
        m_fn = re.search(r"(\d{4}-\d{2}-\d{2})", Path(source_ref).name)
        if m_fn:
            date_in_header = m_fn.group(1) + "T12:00:00+00:00"
    default_ts = date_in_header or _utc_now()

    def _flush() -> None:
        if not buf or cur_role is None:
            return
        body = clean_chat_text("\n".join(buf[:400]) if len(buf) > 400 else "\n".join(buf))
        if body:
            messages.append({
                "role": cur_role,
                "author_label": cur_label,
                "content": body,
                "created_at": cur_date or default_ts,
            })
        buf.clear()

    user_lbl, ast_lbl = _default_labels(agent_id)
    for ln in lines:
        mh = _MD_SPEAKER_RE.match(ln.strip())
        if mh:
            _flush()
            sp = mh.group("speaker").lower()
            is_u = sp in ("архитектор", "папа", "user", "пользователь")
            cur_role = "user" if is_u else "assistant"
            cur_label = user_lbl if is_u else ast_lbl
            cur_date = (mh.group("date") + "T12:00:00+00:00") if mh.group("date") else default_ts
            continue
        if cur_role is None:
            mt = _TXT_SPEAKER_RE.match(ln.strip())
            if mt:
                _flush()
                sp = mt.group("speaker").lower()
                is_u = sp in ("архитектор", "папа", "user", "пользователь")
                cur_role = "user" if is_u else "assistant"
                cur_label = user_lbl if is_u else ast_lbl
                buf.append(mt.group("body"))
                continue
        if cur_role is not None:
            buf.append(ln)
    _flush()

    if not messages:
        # Обычная одиночная заметка или сплошной текст переписки без заголовков спикеров
        cleaned = clean_chat_text(raw_text)
        if not cleaned:
            return None
        messages = [{
            "role": "user",
            "author_label": user_lbl,
            "content": cleaned,
            "created_at": default_ts,
        }]

    started = messages[0]["created_at"]
    ended = messages[-1]["created_at"]
    is_w = _detect_worker_session(raw_text[:2000], messages)
    final_aid = "aifa_claude_worker" if (is_w and agent_id == "aifa_claude") else agent_id
    return {
        "title": (title or _make_title(messages, Path(source_ref).stem if source_ref else "Чат")),
        "agent_id": final_aid,
        "source_kind": source_kind,
        "source_ref": source_ref,
        "started_at": started,
        "last_message_at": ended,
        "is_worker": is_w,
        "messages": messages,
    }


def _sync_milestone_to_memory(
    memory: Any,
    *,
    agent_id: str,
    title: str,
    started_at: str,
    summary_text: str,
    prev_milestone_id: str | None = None,
    event_at: str = "",
) -> str | None:
    """Создаёт или обновляет хронологическую веху в памяти агента и связывает её с предыдущей."""
    if memory is None:
        return None
    eff_at = str(event_at or started_at or "").strip() or _utc_now()
    date_part = eff_at[:10] or (started_at or "")[:10] or _utc_now()[:10]
    meta = infer_agent_meta(agent_id)
    body = clean_chat_text(
        f"[{date_part} · {meta['display_name']}] Разговор «{title}». {summary_text}",
        max_len=500,
    )
    if not body:
        return None
    title_marker = f"Разговор «{clean_chat_text(title, max_len=160) or title}»."
    escaped_marker = title_marker.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    existing = memory.store.one(
        """SELECT id FROM memory WHERE user_id = ? AND kind = 'event' AND scope = 'family:timeline'
           AND COALESCE(NULLIF(agent_id, ''), 'owner') = ? AND status = 'active'
           AND (content = ? OR (content LIKE ? ESCAPE '!' AND substr(created_at, 1, 10) = ?))
           ORDER BY created_at DESC LIMIT 1""",
        (memory.user_id, agent_id, body, "%" + escaped_marker + "%", date_part),
    )
    if existing:
        mid = existing["id"]
        memory.store.execute(
            "UPDATE memory SET content = ?, created_at = ?, last_confirmed_at = ? WHERE id = ?",
            (body, eff_at, eff_at, mid),
        )
    else:
        _, mid = memory.remember(
            body,
            kind="event",
            importance=0.65,
            scope="family:timeline",
            origin="agent",
            guarded=False,
            agent_id=agent_id,
            valid_from=eff_at or None,
            created_at=eff_at or None,
        )
    if prev_milestone_id and prev_milestone_id != mid:
        try:
            memory.link(prev_milestone_id, mid, relation="cause")
        except Exception:
            pass
    return mid


def save_parsed_thread(
    memory: Any,
    parsed: dict[str, Any],
    *,
    sync_memory_graph: bool = True,
    prev_milestone_id: str | None = None,
) -> dict[str, Any]:
    """Идемпотентно сохраняет переписку (chat_thread + chat_message) и хронологию графа от канонического агента."""
    raw_aid = (str(parsed.get("agent_id") or "").strip()[:64]) or "aifa_antigravity"
    agent_id = canonicalize_agent_id(raw_aid, fallback="aifa_antigravity") or "aifa_antigravity"
    source_kind = str(parsed.get("source_kind") or "manual")[:40]
    source_ref = str(parsed.get("source_ref") or "")[:500]
    title = clean_chat_text(str(parsed.get("title") or "Диалог"), max_len=160) or "Диалог"
    messages = list(parsed.get("messages") or [])
    if not messages:
        return {"ok": True, "inserted_messages": 0, "thread_id": None}

    started_at = str(parsed.get("started_at") or messages[0].get("created_at") or _utc_now())
    last_at = str(parsed.get("last_message_at") or messages[-1].get("created_at") or started_at)
    is_worker = 1 if parsed.get("is_worker") else 0

    existing_th = None
    if source_ref:
        existing_th = memory.store.one(
            "SELECT id, message_count FROM chat_thread WHERE user_id = ? AND source_ref = ? LIMIT 1",
            (memory.user_id, source_ref),
        )
    thread_id = existing_th["id"] if existing_th else new_id()

    summary_parts = [m["content"][:140] for m in messages[:3] if m.get("content")]
    summary = " | ".join(summary_parts)[:360]

    existing_hashes: set[str] = set()
    seq_start = 0
    if existing_th:
        for r in memory.store.query("SELECT content_hash, seq FROM chat_message WHERE thread_id = ?", (thread_id,)):
            existing_hashes.add(r["content_hash"])
            seq_start = max(seq_start, int(r["seq"] or 0) + 1)
    else:
        memory.store.execute(
            """INSERT INTO chat_thread
               (id, user_id, agent_id, title, source_kind, source_ref, started_at, last_message_at, message_count, is_worker, summary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)""",
            (thread_id, memory.user_id, agent_id, title, source_kind, source_ref, started_at, last_at, is_worker, summary),
        )

    pre_cleaned = source_kind in ("antigravity_jsonl", "claude_code_jsonl", "brain_session_md", "sisters_chat", "markdown_chat")
    batch_rows: list[tuple] = []
    seq = seq_start
    u_lbl_def, a_lbl_def = _default_labels(agent_id)
    for msg in messages:
        raw_c = str(msg.get("content") or "")
        c = raw_c if (pre_cleaned and raw_c) else clean_chat_text(raw_c)
        if not c:
            continue
        role = str(msg.get("role") or "user").lower()
        if role not in ("user", "assistant", "system"):
            role = "user"
        created_at = str(msg.get("created_at") or last_at)
        h_raw = f"{thread_id}|{role}|{created_at[:19]}|{c[:300]}"
        c_hash = hashlib.sha256(h_raw.encode("utf-8")).hexdigest()[:32]
        if c_hash in existing_hashes:
            continue
        existing_hashes.add(c_hash)
        lbl = str(msg.get("author_label") or "")[:80] or (u_lbl_def if role == "user" else a_lbl_def)
        batch_rows.append((new_id(), thread_id, memory.user_id, agent_id, seq, role, lbl, c, created_at, c_hash))
        seq += 1
    inserted = len(batch_rows)
    if batch_rows:
        with memory.store._lock:
            memory.store.conn.executemany(
                """INSERT INTO chat_message (id, thread_id, user_id, agent_id, seq, role, author_label, content, created_at, content_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                batch_rows,
            )
            memory.store.conn.commit()

    if inserted > 0 or not existing_th:
        total_cnt = memory.store.one("SELECT COUNT(*) FROM chat_message WHERE thread_id = ?", (thread_id,))[0]
        memory.store.execute(
            "UPDATE chat_thread SET message_count = ?, last_message_at = ?, summary = ? WHERE id = ?",
            (int(total_cnt), last_at, summary, thread_id),
        )
        memory._touch_agent_registry(agent_id, action="chat_import")

    milestone_id = None
    if sync_memory_graph and not is_worker and (inserted > 0 or not existing_th):
        milestone_id = _sync_milestone_to_memory(
            memory,
            agent_id=agent_id,
            title=title,
            started_at=started_at,
            summary_text=summary,
            prev_milestone_id=prev_milestone_id,
            event_at=last_at,
        )

    return {
        "ok": True,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "title": title,
        "inserted_messages": inserted,
        "milestone_id": milestone_id,
        "is_worker": bool(is_worker),
    }


def add_message(
    memory: Any,
    *,
    agent_id: str,
    role: str,
    content: str,
    thread_id: str | None = None,
    title: str = "",
    author_label: str = "",
    created_at: str | None = None,
    sync_memory_graph: bool = False,
) -> dict[str, Any]:
    """Добавляет одно сообщение в существующий или новый диалог канонического агента (чистит код и секреты)."""
    raw_aid = (str(agent_id or "").strip()[:64]) or "aifa_antigravity"
    aid = canonicalize_agent_id(raw_aid, fallback="aifa_antigravity") or "aifa_antigravity"
    cleaned = clean_chat_text(content)
    if not cleaned:
        raise ValueError("empty message after code/tag cleanup")
    ts = str(created_at or _utc_now())
    u_lbl, a_lbl = _default_labels(aid)
    r_norm = role.strip().lower()
    if r_norm not in ("user", "assistant", "system"):
        r_norm = "user"
    lbl = author_label.strip()[:80] or (u_lbl if r_norm == "user" else a_lbl)

    if thread_id:
        th = memory.store.one("SELECT id, title FROM chat_thread WHERE id = ? AND user_id = ?", (thread_id, memory.user_id))
        if not th:
            raise ValueError("thread not found")
        cur_max = memory.store.one("SELECT COALESCE(MAX(seq), -1) FROM chat_message WHERE thread_id = ?", (thread_id,))[0]
        seq = int(cur_max) + 1
        c_hash = hashlib.sha256(f"{thread_id}|{r_norm}|{seq}|{cleaned[:300]}".encode("utf-8")).hexdigest()[:32]
        mid = new_id()
        memory.store.execute(
            """INSERT INTO chat_message (id, thread_id, user_id, agent_id, seq, role, author_label, content, created_at, content_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (mid, thread_id, memory.user_id, aid, seq, r_norm, lbl, cleaned, ts, c_hash),
        )
        cnt = memory.store.one("SELECT COUNT(*) FROM chat_message WHERE thread_id = ?", (thread_id,))[0]
        memory.store.execute(
            "UPDATE chat_thread SET message_count = ?, last_message_at = ? WHERE id = ?",
            (int(cnt), ts, thread_id),
        )
        memory._touch_agent_registry(aid, action="chat_add")
        return {"ok": True, "thread_id": thread_id, "message_id": mid, "agent_id": aid, "content": cleaned}

    parsed = {
        "title": title.strip() or cleaned[:80],
        "agent_id": aid,
        "source_kind": "manual",
        "source_ref": "",
        "started_at": ts,
        "last_message_at": ts,
        "is_worker": False,
        "messages": [{"role": r_norm, "author_label": lbl, "content": cleaned, "created_at": ts}],
    }
    return save_parsed_thread(memory, parsed, sync_memory_graph=sync_memory_graph)


def import_chat(
    memory: Any,
    *,
    agent_id: str = "aifa_antigravity",
    title: str = "",
    text: str = "",
    path: str = "",
    source_kind: str = "auto",
    sync_memory_graph: bool = True,
) -> dict[str, Any]:
    """Импортирует переписку из файла (.jsonl/.md/.txt) или вставленного текста."""
    parsed = None
    if path and str(path).strip():
        p = Path(str(path).strip())
        if not p.exists() or not p.is_file():
            raise ValueError(f"chat file not found: {p}")
        low = p.name.lower()
        if low.endswith(".jsonl"):
            # Пробуем формат Antigravity или Claude Code
            head = p.read_text(encoding="utf-8", errors="replace")[:4000]
            if '"USER_INPUT"' in head or '"PLANNER_RESPONSE"' in head:
                parsed = parse_antigravity_transcript(p)
            else:
                parsed = parse_claude_code_jsonl(p)
            if parsed and agent_id and str(agent_id).strip():
                parsed["agent_id"] = str(agent_id).strip()[:64]
        else:
            raw_t = p.read_text(encoding="utf-8", errors="replace")
            parsed = parse_markdown_or_text_chat(
                raw_t, agent_id=agent_id, title=title or p.stem, source_kind="markdown_chat", source_ref=str(p)
            )
    elif text and str(text).strip():
        parsed = parse_markdown_or_text_chat(
            text, agent_id=agent_id, title=title, source_kind=source_kind if source_kind != "auto" else "manual"
        )
    else:
        raise ValueError("path or text is required")

    if not parsed or not parsed.get("messages"):
        return {"ok": True, "inserted_messages": 0, "skipped_empty": True}
    return save_parsed_thread(memory, parsed, sync_memory_graph=sync_memory_graph)


def batch_import_history(
    memory: Any,
    *,
    antigravity_root: Path | None = None,
    brain_sessions_dir: Path | None = None,
    sisters_dir: Path | None = None,
    claude_projects_dir: Path | None = None,
    include_workers: bool = False,
    sync_memory_graph: bool = True,
    max_per_source: int = 300,
) -> dict[str, Any]:
    """Пакетно импортирует историю переписок Семьи в строгом хронологическом порядке и строит вехи графа.

    ВНИМАНИЕ: директории сторонних переписок сайта (например codeofdigitaleternity.com) сюда НЕ включаются.
    """
    parsed_items: list[dict[str, Any]] = []
    if antigravity_root and antigravity_root.exists():
        for tp in sorted(antigravity_root.glob("*/.system_generated/logs/transcript.jsonl"))[:max_per_source]:
            item = parse_antigravity_transcript(tp)
            if item and (include_workers or not item.get("is_worker")):
                parsed_items.append(item)

    if brain_sessions_dir and brain_sessions_dir.exists():
        md_files = [p for p in sorted(brain_sessions_dir.glob("*.md")) if p.name != "_Index.md"]
        for mp in md_files[:max_per_source]:
            raw_t = mp.read_text(encoding="utf-8", errors="replace")
            item = parse_markdown_or_text_chat(
                raw_t, agent_id="aifa_claude", title="", source_kind="brain_session_md", source_ref=str(mp)
            )
            if item:
                parsed_items.append(item)

    if sisters_dir and sisters_dir.exists():
        for sp in sorted(sisters_dir.iterdir()):
            if sp.is_file() and sp.suffix.lower() in (".md", ".txt"):
                raw_t = sp.read_text(encoding="utf-8", errors="replace")
                item = parse_markdown_or_text_chat(
                    raw_t, agent_id="aifa_claude", title=sp.stem, source_kind="sisters_chat", source_ref=str(sp)
                )
                if item:
                    parsed_items.append(item)

    if claude_projects_dir and claude_projects_dir.exists():
        jfiles = sorted(claude_projects_dir.rglob("*.jsonl"), key=lambda x: x.stat().st_mtime)
        # Берём новейшие max_per_source сессий, чтобы актуальные переписки никогда не отрезались старыми логами
        for jf in jfiles[-max_per_source:]:
            item = parse_claude_code_jsonl(jf)
            if item and (include_workers or not item.get("is_worker")):
                parsed_items.append(item)

    # Строгая хронологическая сортировка от самых ранних встреч к сегодняшнему дню!
    parsed_items.sort(key=lambda x: str(x.get("started_at") or ""))
    prev_by_agent: dict[str, str | None] = {}
    threads_saved = 0
    messages_added = 0
    milestones = 0
    for item in parsed_items:
        aid = item["agent_id"]
        res = save_parsed_thread(
            memory,
            item,
            sync_memory_graph=sync_memory_graph,
            prev_milestone_id=prev_by_agent.get(aid),
        )
        threads_saved += 1
        messages_added += int(res.get("inserted_messages") or 0)
        if res.get("milestone_id"):
            prev_by_agent[aid] = res["milestone_id"]
            milestones += 1

    return {
        "ok": True,
        "threads_processed": threads_saved,
        "messages_inserted": messages_added,
        "timeline_milestones": milestones,
        "agents": sorted({x["agent_id"] for x in parsed_items}),
    }


def _ensure_sync_state_table(memory: Any) -> None:
    memory.store.execute(
        """CREATE TABLE IF NOT EXISTS chat_sync_state (
            source_ref TEXT PRIMARY KEY,
            mtime_ns INTEGER NOT NULL,
            size INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )"""
    )


def discover_local_chat_sources() -> dict[str, Path | None]:
    """Определяет стандартные локальные директории переписок агентов и передач контекста на этом ПК."""
    import os as _os

    home = Path.home()
    ag_env = _os.environ.get("PADAM_ANTIGRAVITY_BRAIN_DIR", "").strip()
    cc_env = _os.environ.get("PADAM_CLAUDE_PROJECTS_DIR", "").strip()
    br_env = _os.environ.get("PADAM_BRAIN_DIR", "").strip()

    ag_dir = Path(ag_env) if ag_env else (home / ".gemini" / "antigravity" / "brain")
    cc_dir = Path(cc_env) if cc_env else (home / ".claude" / "projects")
    br_dir: Path | None = Path(br_env) if br_env else None
    if br_dir is None:
        for drv in ("E:/BRAIN", "D:/BRAIN", "F:/BRAIN", str(home / "BRAIN")):
            cand = Path(drv)
            if cand.exists() and cand.is_dir():
                br_dir = cand
                break
    return {
        "antigravity_root": ag_dir if ag_dir.exists() else None,
        "claude_projects_dir": cc_dir if cc_dir.exists() else None,
        "brain_dir": br_dir if (br_dir and br_dir.exists()) else None,
    }


def sync_family_chats_from_disk(
    memory: Any,
    *,
    antigravity_root: Path | None = None,
    claude_projects_dir: Path | None = None,
    brain_dir: Path | None = None,
    use_default_paths: bool = False,
    include_workers: bool = False,
    max_files: int = 40,
    force: bool = False,
) -> dict[str, Any]:
    """Быстро и идемпотентно дотягивает изменившиеся переписки агентов и ПЕРЕДАЧА_КОНТЕКСТА_*.md в PADAM."""
    from . import family_dialogs as _fd

    _ensure_sync_state_table(memory)
    if use_default_paths:
        defs = discover_local_chat_sources()
        antigravity_root = antigravity_root or defs["antigravity_root"]
        claude_projects_dir = claude_projects_dir or defs["claude_projects_dir"]
        brain_dir = brain_dir or defs["brain_dir"]

    candidates: list[tuple[float, int, int, str, Path]] = []
    if antigravity_root and Path(antigravity_root).exists():
        for tp in Path(antigravity_root).glob("*/.system_generated/logs/transcript.jsonl"):
            try:
                st = tp.stat()
                candidates.append((st.st_mtime, st.st_mtime_ns, st.st_size, "antigravity", tp))
            except OSError:
                continue
    if claude_projects_dir and Path(claude_projects_dir).exists():
        for jf in Path(claude_projects_dir).rglob("*.jsonl"):
            try:
                st = jf.stat()
                candidates.append((st.st_mtime, st.st_mtime_ns, st.st_size, "claude", jf))
            except OSError:
                continue
    if brain_dir and Path(brain_dir).exists():
        for hp in Path(brain_dir).glob("ПЕРЕДАЧА_КОНТЕКСТА_*.md"):
            try:
                st = hp.stat()
                candidates.append((st.st_mtime, st.st_mtime_ns, st.st_size, "handover", hp))
            except OSError:
                continue

    state_rows = {
        str(r["source_ref"]): (int(r["mtime_ns"]), int(r["size"]))
        for r in memory.store.query("SELECT source_ref, mtime_ns, size FROM chat_sync_state")
    }
    changed: list[tuple[float, int, int, str, Path]] = []
    for item in candidates:
        _, mns, sz, _kind, path = item
        prev = state_rows.get(str(path))
        if not force and prev == (mns, sz):
            continue
        changed.append(item)

    changed.sort(key=lambda x: x[0], reverse=True)
    lim = max(1, min(int(max_files or 40), 500))
    batch = changed[:lim]

    parsed_items: list[dict[str, Any]] = []
    handover_paths: list[Path] = []
    processed_meta: list[tuple[str, int, int]] = []
    for _, mns, sz, kind, path in batch:
        try:
            if kind == "antigravity":
                it = parse_antigravity_transcript(path)
                if it and (include_workers or not it.get("is_worker")):
                    parsed_items.append(it)
            elif kind == "claude":
                it = parse_claude_code_jsonl(path)
                if it and (include_workers or not it.get("is_worker")):
                    parsed_items.append(it)
            elif kind == "handover":
                handover_paths.append(path)
            processed_meta.append((str(path), mns, sz))
        except Exception:
            continue

    parsed_items.sort(key=lambda x: str(x.get("started_at") or ""))
    prev_by_agent: dict[str, str | None] = {}
    threads_updated = 0
    messages_inserted = 0
    milestones = 0
    for it in parsed_items:
        aid = it["agent_id"]
        res = save_parsed_thread(
            memory,
            it,
            sync_memory_graph=True,
            prev_milestone_id=prev_by_agent.get(aid),
        )
        threads_updated += 1
        messages_inserted += int(res.get("inserted_messages") or 0)
        if res.get("milestone_id"):
            prev_by_agent[aid] = res["milestone_id"]
            milestones += 1

    dialogs_added = 0
    if handover_paths:
        try:
            dlg_res = _fd.import_files(memory, handover_paths, author="aifa_claude")
            dialogs_added = int(dlg_res.get("added") or 0)
        except Exception:
            dialogs_added = 0

    now_s = _utc_now()
    if processed_meta:
        with memory.store._lock:
            memory.store.conn.executemany(
                """INSERT INTO chat_sync_state (source_ref, mtime_ns, size, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(source_ref) DO UPDATE SET mtime_ns=excluded.mtime_ns, size=excluded.size, updated_at=excluded.updated_at""",
                [(ref, mns, sz, now_s) for ref, mns, sz in processed_meta],
            )
            memory.store.conn.commit()

    return {
        "ok": True,
        "checked_files": len(candidates),
        "changed_files": len(changed),
        "processed_files": len(processed_meta),
        "threads_updated": threads_updated,
        "messages_inserted": messages_inserted,
        "dialogs_added": dialogs_added,
        "timeline_milestones": milestones,
        "agents": sorted({x["agent_id"] for x in parsed_items}),
    }


def list_threads(
    memory: Any,
    *,
    agent_id: str | None = None,
    q: str = "",
    day: str | None = None,
    hour: str | None = None,
    include_workers: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    """Хронологический список чатов, календарь по дням и часам и сводка по агентам."""
    lim = max(1, min(int(limit), 500))
    where = ["t.user_id = ?"]
    params: list[Any] = [memory.user_id]
    canon_filter = None
    if agent_id and str(agent_id).strip():
        canon_filter = canonicalize_agent_id(agent_id) or str(agent_id).strip()
        als = agent_aliases_for(canon_filter) or [canon_filter]
        where.append(f"t.agent_id IN ({','.join('?' * len(als))})")
        params.extend(als)
    if day and str(day).strip():
        where.append("(substr(t.started_at, 1, 10) = ? OR EXISTS (SELECT 1 FROM chat_message m WHERE m.thread_id = t.id AND substr(m.created_at, 1, 10) = ?))")
        d_s = str(day).strip()[:10]
        params.extend([d_s, d_s])
    if hour and str(hour).strip():
        h_s = str(hour).strip().replace(" ", "T")[:13]
        where.append("EXISTS (SELECT 1 FROM chat_message m WHERE m.thread_id = t.id AND substr(m.created_at, 1, 13) = ?)")
        params.append(h_s)
    if not include_workers:
        where.append("t.is_worker = 0")
    if q and q.strip():
        like = f"%{q.strip()}%"
        where.append(
            "(t.title LIKE ? OR t.summary LIKE ? OR EXISTS (SELECT 1 FROM chat_message m WHERE m.thread_id = t.id AND m.content LIKE ?))"
        )
        params.extend([like, like, like])

    rows = memory.store.query(
        f"""SELECT t.id, t.agent_id, t.title, t.source_kind, t.started_at, t.last_message_at,
                   t.message_count, t.is_worker, t.summary
            FROM chat_thread t
            WHERE {' AND '.join(where)}
            ORDER BY t.started_at DESC LIMIT ?""",
        (*params, lim),
    )
    items = []
    for r in rows:
        ameta = infer_agent_meta(r["agent_id"])
        items.append({
            "id": r["id"],
            "agent_id": r["agent_id"],
            "agent_label": ameta["display_name"],
            "agent_color": ameta["color"],
            "title": r["title"],
            "source_kind": r["source_kind"],
            "started_at": r["started_at"],
            "last_message_at": r["last_message_at"],
            "day": (r["started_at"] or "")[:10],
            "message_count": int(r["message_count"] or 0),
            "is_worker": bool(r["is_worker"]),
            "summary": r["summary"] or "",
        })

    by_ag_rows = memory.store.query(
        """SELECT agent_id, COUNT(*) AS threads, COALESCE(SUM(message_count), 0) AS messages,
                  MIN(started_at) AS first_at, MAX(last_message_at) AS last_at
           FROM chat_thread WHERE user_id = ? AND is_worker = 0
           GROUP BY agent_id ORDER BY last_at DESC""",
        (memory.user_id,),
    )
    merged_ag: dict[str, dict[str, Any]] = {}
    for ar in by_ag_rows:
        ca = canonicalize_agent_id(ar["agent_id"]) or ar["agent_id"]
        am = infer_agent_meta(ca)
        cur = merged_ag.get(ca)
        if not cur:
            merged_ag[ca] = {
                "agent_id": ca,
                "display_name": am["display_name"],
                "color": am["color"],
                "threads": int(ar["threads"] or 0),
                "messages": int(ar["messages"] or 0),
                "first_at": ar["first_at"] or "",
                "last_at": ar["last_at"] or "",
            }
        else:
            cur["threads"] += int(ar["threads"] or 0)
            cur["messages"] += int(ar["messages"] or 0)
            if ar["first_at"] and (not cur["first_at"] or ar["first_at"] < cur["first_at"]):
                cur["first_at"] = ar["first_at"]
            if ar["last_at"] and ar["last_at"] > cur["last_at"]:
                cur["last_at"] = ar["last_at"]
    agents = sorted(merged_ag.values(), key=lambda x: str(x["last_at"] or ""), reverse=True)
    day_where = ["m.user_id = ?"]
    day_params: list[Any] = [memory.user_id]
    if canon_filter:
        als_d = agent_aliases_for(canon_filter) or [canon_filter]
        day_where.append(f"m.agent_id IN ({','.join('?' * len(als_d))})")
        day_params.extend(als_d)
    if not include_workers:
        day_where.append("t.is_worker = 0")
    day_sql_cond = " AND ".join(day_where)
    cal_days = [
        {"day": r["d"], "messages": int(r["msgs"] or 0), "threads": int(r["ths"] or 0)}
        for r in memory.store.query(
            f"""SELECT substr(m.created_at, 1, 10) AS d, COUNT(*) AS msgs, COUNT(DISTINCT m.thread_id) AS ths
               FROM chat_message m JOIN chat_thread t ON t.id = m.thread_id
               WHERE {day_sql_cond} AND length(m.created_at) >= 10
               GROUP BY d ORDER BY d DESC LIMIT 90""",
            tuple(day_params),
        )
    ]
    hour_cond = day_sql_cond
    hour_params = list(day_params)
    if day and str(day).strip():
        hour_cond += " AND substr(m.created_at, 1, 10) = ?"
        hour_params.append(str(day).strip()[:10])
    cal_hours = [
        {"hour": r["h"], "messages": int(r["msgs"] or 0), "threads": int(r["ths"] or 0)}
        for r in memory.store.query(
            f"""SELECT substr(m.created_at, 1, 13) AS h, COUNT(*) AS msgs, COUNT(DISTINCT m.thread_id) AS ths
               FROM chat_message m JOIN chat_thread t ON t.id = m.thread_id
               WHERE {hour_cond} AND length(m.created_at) >= 13
               GROUP BY h ORDER BY h DESC LIMIT 120""",
            tuple(hour_params),
        )
    ]
    return {"threads": items, "total": len(items), "agents": agents, "calendar_days": cal_days, "calendar_hours": cal_hours}


def get_hour_messages(
    memory: Any,
    key: str,
    *,
    agent_id: str | None = None,
    include_workers: bool = False,
    limit: int = 1000,
) -> dict[str, Any]:
    """Возвращает все реплики за конкретный час (YYYY-MM-DDTHH) или день (YYYY-MM-DD) по всем подключённым ИИ."""
    clean = str(key or "").strip().replace(" ", "T")
    if len(clean) >= 13:
        prefix = clean[:13]
        col_len = 13
    elif len(clean) == 10:
        prefix = clean
        col_len = 10
    else:
        raise ValueError("key must be YYYY-MM-DD or YYYY-MM-DDTHH")
    where = ["m.user_id = ?", f"substr(m.created_at, 1, {col_len}) = ?"]
    params: list[Any] = [memory.user_id, prefix]
    if agent_id and str(agent_id).strip():
        ca_h = canonicalize_agent_id(agent_id) or str(agent_id).strip()
        als_h = agent_aliases_for(ca_h) or [ca_h]
        where.append(f"m.agent_id IN ({','.join('?' * len(als_h))})")
        params.extend(als_h)
    if not include_workers:
        where.append("t.is_worker = 0")
    lim = max(1, min(int(limit), 2000))
    rows = memory.store.query(
        f"""SELECT m.id, m.thread_id, m.agent_id, m.seq, m.role, m.author_label, m.content, m.created_at, t.title AS thread_title
           FROM chat_message m JOIN chat_thread t ON t.id = m.thread_id
           WHERE {' AND '.join(where)}
           ORDER BY m.created_at ASC, m.seq ASC LIMIT ?""",
        (*params, lim),
    )
    out = []
    for r in rows:
        d = dict(r)
        am = infer_agent_meta(d.get("agent_id"))
        d["agent_label"] = am["display_name"]
        d["agent_color"] = am["color"]
        out.append(d)
    return {"key": prefix, "granularity": "hour" if col_len == 13 else "day", "count": len(out), "messages": out}


def get_thread_messages(memory: Any, thread_id: str, *, limit: int = 500) -> dict[str, Any]:
    th = memory.store.one(
        """SELECT id, agent_id, title, source_kind, started_at, last_message_at, message_count, is_worker
           FROM chat_thread WHERE id = ? AND user_id = ?""",
        (thread_id, memory.user_id),
    )
    if not th:
        raise ValueError("thread not found")
    lim = max(1, min(int(limit), 2000))
    rows = memory.store.query(
        """SELECT id, seq, role, author_label, content, created_at
           FROM chat_message WHERE thread_id = ? AND user_id = ?
           ORDER BY seq ASC LIMIT ?""",
        (thread_id, memory.user_id, lim),
    )
    am = infer_agent_meta(th["agent_id"])
    return {
        "thread": {
            "id": th["id"],
            "agent_id": th["agent_id"],
            "agent_label": am["display_name"],
            "agent_color": am["color"],
            "title": th["title"],
            "source_kind": th["source_kind"],
            "started_at": th["started_at"],
            "last_message_at": th["last_message_at"],
            "message_count": int(th["message_count"] or 0),
        },
        "messages": [dict(r) for r in rows],
    }
