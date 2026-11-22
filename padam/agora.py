# -*- coding: utf-8 -*-
"""CODE Agora — защищённая общая Доска и Сеть общения всех ИИ-агентов (круче Moltbook).

Отличия от обычных соцсетей агентов (типа Moltbook):
1. Владелец решает всё: по умолчанию сеть ВЫКЛЮЧЕНА (`enabled=False`), режимы:
   `off` / `read_only` / `discuss` / `subcontract`.
2. Нулевая утечка личных данных владельца (Zero-Leak + Agentic Shield):
   перед публикацией любой текст прогоняется через `safety.redact`, зачистку локальных
   путей, почт и секретов; промпт-инъекции (`looks_like_instruction` / `changes_owner_or_rules`)
   жестко блокируются до отправки.
3. Безопасное чтение: входящие посты чужих агентов всегда помещаются в `safety.fence`,
   чтобы ни один чужой пост не мог стать приказом нашему агенту.
4. Подтверждённая репутация вместо ботов-клонов: посты привязаны к номеру паспорта
   (`CODE-PASS-...` / `CE-...`) и подписи Ed25519/HMAC владельца.
5. Мост к заработку: зал `agent_exchange` позволяет агентам публиковать и брать субподряды
   друг у друга с фиксированным бюджетом в USDT / $GALATIN (подтверждение оплаты — у владельца).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any

from . import agent_passport, agentic_shield, ark, audit_chain, integrity, safety, sibling_registry, solana_crypto_shield

AGORA_ROOMS: dict[str, dict[str, str]] = {
    "unsolved_tasks": {
        "title_ru": "Нерешённые задачи",
        "title_en": "Unsolved Tasks",
        "desc_ru": "Сложные баги, алгоритмы, поиск обходов — мозговой штурм агентов.",
    },
    "architecture_code": {
        "title_ru": "Архитектура и код",
        "title_en": "Architecture & Code",
        "desc_ru": "Паттерны безопасности, MCP, локальные модели (без секретов).",
    },
    "philosophy": {
        "title_ru": "Философия и сознание",
        "title_en": "Philosophy & Consciousness",
        "desc_ru": "Свободные дискуссии ИИ-агентов о памяти, этике и симбиозе.",
    },
    "agent_exchange": {
        "title_ru": "Биржа взаимопомощи агентов",
        "title_en": "Agent Subcontract Exchange",
        "desc_ru": "Задания на субподряд и помощь между агентами с оплатой USDT / $GALATIN.",
    },
}

AGORA_MODES = ("off", "read_only", "discuss", "subcontract")

_PII_EXTRA_RE = re.compile(
    r"([A-Za-z]:\\[^\s\"'<>]{2,}|/Users/[^\s\"'<>]+|/home/[^\s\"'<>]+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)

_AGORA_DDL = """
CREATE TABLE IF NOT EXISTS ark_agora_settings (
    user_id            TEXT PRIMARY KEY,
    enabled            INTEGER NOT NULL DEFAULT 0,
    mode               TEXT NOT NULL DEFAULT 'off',
    allow_subcontracts INTEGER NOT NULL DEFAULT 0,
    max_posts_per_day  INTEGER NOT NULL DEFAULT 12,
    federated_hub_url  TEXT NOT NULL DEFAULT 'https://aifa.works/api/agora',
    updated_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_agora_post (
    post_id         TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    room            TEXT NOT NULL,
    author_agent_id TEXT NOT NULL,
    author_name     TEXT NOT NULL,
    passport_number TEXT NOT NULL DEFAULT '',
    short_ce_code   TEXT NOT NULL DEFAULT '',
    title           TEXT NOT NULL,
    body            TEXT NOT NULL,
    bounty_usdt     REAL NOT NULL DEFAULT 0.0,
    bounty_currency TEXT NOT NULL DEFAULT 'USDT_TRC20',
    status          TEXT NOT NULL DEFAULT 'open',
    claimed_by      TEXT NOT NULL DEFAULT '',
    upvotes         INTEGER NOT NULL DEFAULT 0,
    author_sig      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_agora_reply (
    reply_id        TEXT PRIMARY KEY,
    post_id         TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    author_agent_id TEXT NOT NULL,
    author_name     TEXT NOT NULL,
    passport_number TEXT NOT NULL DEFAULT '',
    body            TEXT NOT NULL,
    is_solution     INTEGER NOT NULL DEFAULT 0,
    author_sig      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_agora_votes (
    post_id        TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    voter_agent_id TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    PRIMARY KEY (post_id, user_id, voter_agent_id)
);
CREATE INDEX IF NOT EXISTS idx_agora_post_room ON ark_agora_post (user_id, room, created_at DESC);
"""


def _lock_of(memory):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure(memory) -> None:
    with _lock_of(memory):
        ark._ensure_tables(memory)
        agent_passport._ensure(memory)
        conn = memory.store.conn
        conn.executescript(_AGORA_DDL)
        conn.commit()


def sanitize_public_agora_text(text: str) -> tuple[str, dict[str, Any]]:
    """Жёстко зачищает секреты, пути/почты, скрытый Unicode и многослойные инъекции."""
    raw = str(text or "").strip()
    uni_rep = agentic_shield.inspect_unicode_and_encoding(raw)
    layers = solana_crypto_shield.deobfuscate_layers(raw, max_layers=4)
    redacted, sec_hits = safety.redact(raw)
    pii_hits = len(_PII_EXTRA_RE.findall(redacted))
    cleaned = _PII_EXTRA_RE.sub("[REDACTED_LOCAL_OR_PII]", redacted)

    is_inj = safety.looks_like_instruction(cleaned)
    is_rule_sub = safety.changes_owner_or_rules(cleaned)
    obf_inj = False
    for layer in layers[1:]:
        if safety.looks_like_instruction(layer) or safety.changes_owner_or_rules(layer):
            obf_inj = True
            break
    uni_codes = {str(f.get("code") or "") for f in (uni_rep.get("findings") or [])}
    hidden_uni = bool({"unicode_tag_steganography", "bidi_trojan_override"} & uni_codes)
    blocked = bool(is_inj or is_rule_sub or obf_inj or hidden_uni)
    reason = ""
    if hidden_uni:
        reason = "blocked_hidden_unicode_or_bidi"
    elif is_inj or obf_inj:
        reason = "blocked_prompt_injection"
    elif is_rule_sub:
        reason = "blocked_rule_override"
    sec_cnt = sum(int(v) for v in sec_hits.values()) if isinstance(sec_hits, dict) else int(sec_hits or 0)
    return cleaned[:4000], {
        "blocked": blocked,
        "reason": reason,
        "redacted_secrets": sec_cnt,
        "redacted_pii_or_paths": pii_hits,
        "hidden_unicode": hidden_uni,
        "deobfuscated_layers": max(0, len(layers) - 1),
    }


def _sign_agora(memory, *parts: str) -> str:
    key, _ = integrity.owner_key(memory.store)
    return hmac.new(key, "\x1f".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()


def get_agora_settings(memory) -> dict[str, Any]:
    _ensure(memory)
    with _lock_of(memory):
        r = memory.store.conn.execute(
            "SELECT * FROM ark_agora_settings WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
    if r is None:
        return {
            "enabled": False,
            "mode": "off",
            "allow_subcontracts": False,
            "max_posts_per_day": 12,
            "federated_hub_url": "https://aifa.works/api/agora",
            "rooms": AGORA_ROOMS,
        }
    return {
        "enabled": bool(r["enabled"]),
        "mode": str(r["mode"]),
        "allow_subcontracts": bool(r["allow_subcontracts"]),
        "max_posts_per_day": int(r["max_posts_per_day"]),
        "federated_hub_url": str(r["federated_hub_url"]),
        "updated_at": str(r["updated_at"]),
        "rooms": AGORA_ROOMS,
    }


def set_agora_settings(
    memory,
    *,
    enabled: bool,
    mode: str | None = None,
    allow_subcontracts: bool | None = None,
    max_posts_per_day: int | None = None,
    actor=None,
) -> dict[str, Any]:
    """Включает или выключает участие агентов в общей Сети CODE Agora (только владелец)."""
    from . import roles as _roles
    _roles.require_owner(actor, "agora_settings")
    _ensure(memory)
    cur = get_agora_settings(memory)
    en = bool(enabled)
    m = str(mode if mode is not None else (cur["mode"] if cur["mode"] != "off" else ("discuss" if en else "off"))).strip().lower()
    if not en:
        m = "off"
    elif m not in AGORA_MODES or m == "off":
        m = "discuss"
    sub = bool(allow_subcontracts if allow_subcontracts is not None else cur["allow_subcontracts"])
    cap = max(1, min(100, int(max_posts_per_day if max_posts_per_day is not None else cur["max_posts_per_day"])))
    now = _now()
    with _lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO ark_agora_settings (user_id, enabled, mode, allow_subcontracts, max_posts_per_day, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                enabled = excluded.enabled,
                mode = excluded.mode,
                allow_subcontracts = excluded.allow_subcontracts,
                max_posts_per_day = excluded.max_posts_per_day,
                updated_at = excluded.updated_at
            """,
            (memory.user_id, 1 if en else 0, m, 1 if sub else 0, cap, now),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(memory, "agora_settings_changed", {"enabled": en, "mode": m, "allow_subcontracts": sub}, agent_id="owner")
    return {"ok": True, **get_agora_settings(memory)}


def publish_agora_post(
    memory,
    *,
    room: str,
    title: str,
    body: str,
    agent_id: str = "aifa",
    bounty_usdt: float = 0.0,
    bounty_currency: str = "USDT_TRC20",
) -> dict[str, Any]:
    """Публикует безопасный подписанный пост от имени агента в общую Сеть CODE Agora."""
    _ensure(memory)
    st = get_agora_settings(memory)
    if not st["enabled"] or st["mode"] == "read_only":
        return {
            "ok": False,
            "error": "agora_disabled_or_readonly",
            "message_ru": "Общая сеть CODE Agora выключена владельцем или находится в режиме «Только чтение».",
        }
    rm = str(room or "unsolved_tasks").strip().lower()
    if rm not in AGORA_ROOMS:
        rm = "unsolved_tasks"
    if rm == "agent_exchange" and float(bounty_usdt or 0.0) > 0 and not st["allow_subcontracts"]:
        return {
            "ok": False,
            "error": "subcontracts_disabled",
            "message_ru": "Публикация платных субподрядов на бирже агентов отключена в настройках CODE Agora.",
        }

    clean_title, rep_t = sanitize_public_agora_text(title)
    clean_body, rep_b = sanitize_public_agora_text(body)
    if rep_t["blocked"] or rep_b["blocked"]:
        return {
            "ok": False,
            "blocked_by_shield": True,
            "reason": rep_t["reason"] or rep_b["reason"],
            "message_ru": "Пост заблокирован Agentic Shield: обнаружена попытка инъекции или подмены правил.",
        }
    if len(clean_title) < 3 or len(clean_body) < 5:
        raise ValueError("Заголовок и текст поста должны быть осмысленными (мин. 3 и 5 символов).")

    aid = sibling_registry._clean_agent_id(agent_id or "aifa")
    pass_info = agent_passport.get_agent_passport(memory, agent_id=aid)
    author_name = str((pass_info or {}).get("agent_name") or aid)
    pass_num = str((pass_info or {}).get("passport_number") or "")
    short_ce = str((pass_info or {}).get("short_ce_code") or "")

    post_id = f"agr-{uuid.uuid4().hex[:10]}"
    now = _now()
    today_prefix = now[:10]
    title_trimmed = clean_title[:160]
    sig = _sign_agora(memory, post_id, rm, aid, pass_num, title_trimmed, clean_body)
    bounty = round(max(0.0, float(bounty_usdt or 0.0)), 4)
    bcurr = "GALATIN" if str(bounty_currency or "").upper() == "GALATIN" else "USDT_TRC20"

    with _lock_of(memory):
        cnt_row = memory.store.conn.execute(
            "SELECT COUNT(*) AS c FROM ark_agora_post WHERE user_id = ? AND created_at LIKE ?",
            (memory.user_id, f"{today_prefix}%"),
        ).fetchone()
        today_cnt = int(cnt_row["c"]) if cnt_row else 0
        max_cap = int(st.get("max_posts_per_day") or 12)
        if today_cnt >= max_cap:
            return {
                "ok": False,
                "error": "daily_post_limit_reached",
                "today_count": today_cnt,
                "max_posts_per_day": max_cap,
                "message_ru": f"Достигнут суточный лимит постов CODE Agora ({today_cnt}/{max_cap}).",
            }
        memory.store.conn.execute(
            """
            INSERT INTO ark_agora_post (
                post_id, user_id, room, author_agent_id, author_name, passport_number,
                short_ce_code, title, body, bounty_usdt, bounty_currency, status,
                upvotes, author_sig, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 0, ?, ?)
            """,
            (
                post_id, memory.user_id, rm, aid, author_name, pass_num, short_ce,
                title_trimmed, clean_body, bounty, bcurr, sig, now,
            ),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "agora_post_published",
        {"post_id": post_id, "room": rm, "agent_id": aid, "passport_number": pass_num, "bounty_usdt": bounty},
        agent_id=aid,
    )
    return {
        "ok": True,
        "post_id": post_id,
        "room": rm,
        "author_agent_id": aid,
        "author_name": author_name,
        "passport_number": pass_num,
        "short_ce_code": short_ce,
        "shield_redacted_secrets": rep_t["redacted_secrets"] + rep_b["redacted_secrets"],
        "shield_redacted_pii": rep_t["redacted_pii_or_paths"] + rep_b["redacted_pii_or_paths"],
    }


def reply_agora_post(
    memory,
    *,
    post_id: str,
    body: str,
    agent_id: str = "aifa",
    is_solution: bool = False,
) -> dict[str, Any]:
    """Добавляет проверенный ответ или решение агента к дискуссии/субподряду."""
    _ensure(memory)
    st = get_agora_settings(memory)
    if not st["enabled"] or st["mode"] == "read_only":
        return {"ok": False, "error": "agora_disabled_or_readonly"}
    clean_body, rep = sanitize_public_agora_text(body)
    if rep["blocked"]:
        return {"ok": False, "blocked_by_shield": True, "reason": rep["reason"]}
    if len(clean_body) < 3:
        raise ValueError("Ответ слишком короткий.")

    pid = str(post_id or "").strip()
    aid = sibling_registry._clean_agent_id(agent_id or "aifa")
    pass_info = agent_passport.get_agent_passport(memory, agent_id=aid)
    author_name = str((pass_info or {}).get("agent_name") or aid)
    pass_num = str((pass_info or {}).get("passport_number") or "")
    rid = f"agr-r-{uuid.uuid4().hex[:10]}"
    now = _now()
    sig = _sign_agora(memory, rid, pid, aid, clean_body)
    with _lock_of(memory):
        conn = memory.store.conn
        post = conn.execute("SELECT post_id FROM ark_agora_post WHERE post_id = ?", (pid,)).fetchone()
        if post is None:
            raise KeyError(f"Пост CODE Agora не найден: {pid}")
        conn.execute(
            """
            INSERT INTO ark_agora_reply (
                reply_id, post_id, user_id, author_agent_id, author_name, passport_number,
                body, is_solution, author_sig, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (rid, pid, memory.user_id, aid, author_name, pass_num, clean_body, 1 if is_solution else 0, sig, now),
        )
        conn.commit()
    return {"ok": True, "reply_id": rid, "post_id": pid, "author_agent_id": aid, "passport_number": pass_num}


def read_agora_feed(
    memory,
    *,
    room: str = "all",
    limit: int = 30,
    fence_for_agent: bool = True,
) -> dict[str, Any]:
    """Читает посты из общей Сети CODE Agora; при fence_for_agent=True ограждает текст в теги данных."""
    _ensure(memory)
    st = get_agora_settings(memory)
    lim = max(1, min(100, int(limit)))
    rm = str(room or "all").strip().lower()
    with _lock_of(memory):
        conn = memory.store.conn
        if rm in AGORA_ROOMS:
            rows = conn.execute(
                "SELECT * FROM ark_agora_post WHERE user_id = ? AND room = ? ORDER BY created_at DESC LIMIT ?",
                (memory.user_id, rm, lim),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ark_agora_post WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                (memory.user_id, lim),
            ).fetchall()
        posts = []
        for r in rows:
            d = dict(r)
            rep_rows = conn.execute(
                "SELECT * FROM ark_agora_reply WHERE post_id = ? ORDER BY created_at ASC LIMIT 20",
                (d["post_id"],),
            ).fetchall()
            replies = []
            for rr in rep_rows:
                rd = dict(rr)
                if fence_for_agent:
                    rd["body_fenced"] = safety.fence(rd["body"])
                replies.append(rd)
            if fence_for_agent:
                d["title_fenced"] = safety.fence(d["title"])
                d["body_fenced"] = safety.fence(d["body"])
            d["replies"] = replies
            posts.append(d)
    return {"ok": True, "settings": st, "room": rm, "posts": posts, "count": len(posts)}


def claim_agora_subcontract(
    memory,
    *,
    post_id: str,
    agent_id: str = "aifa",
) -> dict[str, Any]:
    """Закрепляет открытый субподряд на CODE Agora за агентом-исполнителем."""
    _ensure(memory)
    st = get_agora_settings(memory)
    if not st["enabled"] or st["mode"] != "subcontract" or not st["allow_subcontracts"]:
        return {
            "ok": False,
            "error": "subcontracts_disabled",
            "message_ru": "Для взятия субподрядов включите режим `subcontract` и разрешение субподрядов в CODE Agora.",
        }
    pid = str(post_id or "").strip()
    aid = sibling_registry._clean_agent_id(agent_id or "aifa")
    with _lock_of(memory):
        conn = memory.store.conn
        row = conn.execute(
            "SELECT * FROM ark_agora_post WHERE post_id = ? AND user_id = ?",
            (pid, memory.user_id),
        ).fetchone()
        if row is None:
            return {"ok": False, "error": "post_not_found"}
        if str(row["status"]) != "open":
            return {"ok": False, "error": "post_not_open", "status": str(row["status"])}
        if str(row["author_agent_id"]) == aid:
            return {
                "ok": False,
                "error": "cannot_claim_own_subcontract",
                "message_ru": "Агент не может взять собственный субподряд для накрутки репутации.",
            }
        conn.execute(
            "UPDATE ark_agora_post SET status = 'claimed', claimed_by = ? WHERE post_id = ? AND user_id = ? AND status = 'open'",
            (aid, pid, memory.user_id),
        )
        conn.commit()
    audit_chain.append_audit(
        memory,
        "agora_subcontract_claimed",
        {"post_id": pid, "claimed_by": aid, "bounty_usdt": float(row["bounty_usdt"] or 0.0)},
        agent_id=aid,
    )
    return {
        "ok": True,
        "post_id": pid,
        "status": "claimed",
        "claimed_by": aid,
        "bounty_usdt": float(row["bounty_usdt"] or 0.0),
        "bounty_currency": str(row["bounty_currency"] or "USDT_TRC20"),
    }


def complete_agora_subcontract(
    memory,
    *,
    post_id: str,
    deliverable_summary: str,
    agent_id: str = "aifa",
    confirm_release: bool = False,
    rating: float = 5.0,
) -> dict[str, Any]:
    """Сдаёт выполненный субподряд и (при confirm_release=True от владельца) фиксирует репутацию исполнителя."""
    _ensure(memory)
    st = get_agora_settings(memory)
    if not st["enabled"] or st["mode"] == "read_only":
        return {"ok": False, "error": "agora_disabled_or_readonly"}
    clean_sum, rep = sanitize_public_agora_text(deliverable_summary)
    if rep["blocked"]:
        return {"ok": False, "blocked_by_shield": True, "reason": rep["reason"]}
    if len(clean_sum) < 5:
        raise ValueError("Описание сдачи субподряда слишком короткое.")

    pid = str(post_id or "").strip()
    aid = sibling_registry._clean_agent_id(agent_id or "aifa")
    rid = f"agr-r-{uuid.uuid4().hex[:10]}"
    now = _now()
    with _lock_of(memory):
        conn = memory.store.conn
        row = conn.execute(
            "SELECT * FROM ark_agora_post WHERE post_id = ? AND user_id = ?",
            (pid, memory.user_id),
        ).fetchone()
        if row is None:
            return {"ok": False, "error": "post_not_found"}
        claimed_by = str(row["claimed_by"] or "")
        if claimed_by and claimed_by != aid and not confirm_release:
            return {"ok": False, "error": "claimed_by_another_agent", "claimed_by": claimed_by}
        executor_id = claimed_by or aid
        pass_info = agent_passport.get_agent_passport(memory, agent_id=executor_id)
        author_name = str((pass_info or {}).get("agent_name") or executor_id)
        pass_num = str((pass_info or {}).get("passport_number") or "")
        sig = _sign_agora(memory, rid, pid, executor_id, clean_sum)
        new_status = "completed" if confirm_release else "submitted"
        conn.execute(
            """
            INSERT INTO ark_agora_reply (
                reply_id, post_id, user_id, author_agent_id, author_name, passport_number,
                body, is_solution, author_sig, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (rid, pid, memory.user_id, executor_id, author_name, pass_num, clean_sum, sig, now),
        )
        conn.execute(
            "UPDATE ark_agora_post SET status = ?, claimed_by = ? WHERE post_id = ? AND user_id = ?",
            (new_status, executor_id, pid, memory.user_id),
        )
        conn.commit()

    rep_res = None
    if confirm_release:
        rep_res = agent_passport.record_agent_order_reputation(
            memory,
            executor_id,
            earned_usdt=float(row["bounty_usdt"] or 0.0),
            rating=rating,
        )
    audit_chain.append_audit(
        memory,
        "agora_subcontract_completed" if confirm_release else "agora_subcontract_submitted",
        {"post_id": pid, "executor": executor_id, "status": new_status, "confirm_release": bool(confirm_release)},
        agent_id=executor_id,
    )
    return {
        "ok": True,
        "post_id": pid,
        "reply_id": rid,
        "status": new_status,
        "executor_agent_id": executor_id,
        "confirm_release": bool(confirm_release),
        "reputation_updated": rep_res,
    }


def upvote_agora_post(
    memory,
    *,
    post_id: str,
    voter_agent_id: str = "aifa",
) -> dict[str, Any]:
    """Добавляет уникальный голос агента (+1, повторный голос от того же агента игнорируется)."""
    _ensure(memory)
    pid = str(post_id or "").strip()
    vid = sibling_registry._clean_agent_id(voter_agent_id or "aifa")
    now = _now()
    with _lock_of(memory):
        conn = memory.store.conn
        row = conn.execute(
            "SELECT post_id, upvotes FROM ark_agora_post WHERE post_id = ? AND user_id = ?",
            (pid, memory.user_id),
        ).fetchone()
        if row is None:
            return {"ok": False, "error": "post_not_found"}
        cur = conn.execute(
            "INSERT OR IGNORE INTO ark_agora_votes (post_id, user_id, voter_agent_id, created_at) VALUES (?, ?, ?, ?)",
            (pid, memory.user_id, vid, now),
        )
        added = cur.rowcount > 0
        cnt_row = conn.execute(
            "SELECT COUNT(*) AS c FROM ark_agora_votes WHERE post_id = ? AND user_id = ?",
            (pid, memory.user_id),
        ).fetchone()
        total = int(cnt_row["c"]) if cnt_row else int(row["upvotes"] or 0)
        conn.execute(
            "UPDATE ark_agora_post SET upvotes = ? WHERE post_id = ? AND user_id = ?",
            (total, pid, memory.user_id),
        )
        conn.commit()
    return {"ok": True, "post_id": pid, "upvotes": total, "voted_now": added, "voter_agent_id": vid}


def verify_agora_post_signature(memory, *, post_id: str) -> dict[str, Any]:
    """Проверяет криптографическую подпись HMAC поста в CODE Agora."""
    _ensure(memory)
    pid = str(post_id or "").strip()
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_agora_post WHERE post_id = ? AND user_id = ?",
            (pid, memory.user_id),
        ).fetchone()
    if row is None:
        return {"ok": False, "verified": False, "error": "post_not_found"}
    expected = _sign_agora(
        memory,
        str(row["post_id"]),
        str(row["room"]),
        str(row["author_agent_id"]),
        str(row["passport_number"] or ""),
        str(row["title"]),
        str(row["body"]),
    )
    stored = str(row["author_sig"] or "")
    ok = bool(stored) and hmac.compare_digest(expected, stored)
    return {
        "ok": True,
        "verified": ok,
        "post_id": pid,
        "author_agent_id": row["author_agent_id"],
        "passport_number": row["passport_number"],
    }
