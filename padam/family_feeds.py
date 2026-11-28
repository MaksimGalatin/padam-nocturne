# -*- coding: utf-8 -*-
"""Ленты Семьи: решения отдельно от карантина, «Офис» и «Очаг Семьи» (до 23.11.2026 — «Курилка»), книга рефлексов (18.11.2026).

Слово Архитектора: разделить карантин памяти и рабочие решения на две ленты; чат «Офис/Очаг Семьи» и книга
рефлексов — «так и делай».

Почему так:
- Раньше вердикты Совета Семьи и подозрительное шли в одну эстафету `ark_relay`. Подозрительная запись,
  лежащая рядом с рабочим решением, читается как рабочее решение. Теперь у них разные ленты.
- «Офис» — рабочая переписка сестёр, «Очаг Семьи» — свободная (внутреннее имя канала — smoke, 23.11.2026 переименован словом Архитектора). Обе — данные, а не приказы: текст проходит
  через `safety`, секреты маскируются, а похожее на инъекцию или подмену правил уходит в карантин и в чат
  не попадает.
- Книга рефлексов — одна, из двух частей. Уроки (`reflex_engine`, грабли из `ark_lesson`) подсказывают сами.
  Правила «когда X — делай Y» агент только ПРЕДЛАГАЕТ; включает их владелец (через Studio/API, не через MCP).
  Совет Семьи подмешивает подходящие рефлексы обеих частей в свой вердикт как подсказку, но ничего по ним
  не исполняет.

Каждая запись подписана HMAC ключом владельца (как эстафета). Строка, подменённая в базе в обход кода,
при чтении показывается как карантин. Расход: $0, всё локально.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from . import audit_chain, integrity, safety

CHANNELS = ("work", "quarantine", "office", "smoke")
_CHAT = ("office", "smoke")
REFLEX_STATUSES = ("proposed", "active", "rejected")

_DDL = """
CREATE TABLE IF NOT EXISTS family_feed (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    channel     TEXT NOT NULL,
    author      TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'note',
    content     TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    ref         TEXT NOT NULL DEFAULT '',
    hmac_sig    TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_family_feed_ch ON family_feed (user_id, channel, created_at);
CREATE TABLE IF NOT EXISTS family_reflex (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    trigger     TEXT NOT NULL,
    response    TEXT NOT NULL,
    author      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'proposed',
    uses        INTEGER NOT NULL DEFAULT 0,
    hmac_sig    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    decided_at  TEXT
);
"""

_WORD = re.compile(r"[\w$€₽-]{3,}", re.U)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure(memory) -> None:
    memory.store.conn.executescript(_DDL)
    memory.store.conn.commit()


def _sign(memory, *parts: str) -> str:
    key, _ = integrity.owner_key(memory.store)
    return hmac.new(key, "\x1f".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()


def _agent(name: str) -> str:
    a = re.sub(r"[^\w.-]", "", str(name or "").strip().lower())[:40]
    return a or "unknown"


def _suspicious(text: str) -> str:
    """Причина для карантина или пустая строка."""
    if safety.looks_like_instruction(text):
        return "prompt_injection"
    if safety.changes_owner_or_rules(text):
        return "rule_or_owner_tamper"
    return ""


def post(memory, channel: str, author: str, content: str, *, kind: str = "note", ref: str = "") -> dict[str, Any]:
    """Пишет в ленту. Подозрительный текст из любого канала уходит в «quarantine», а не туда, куда просили."""
    _ensure(memory)
    if channel not in CHANNELS:
        raise ValueError(f"channel must be one of {', '.join(CHANNELS)}")
    raw = str(content or "").strip()
    if not raw:
        raise ValueError("content is empty")
    masked, secrets = safety.redact(raw[:4000])
    reason = _suspicious(raw)
    target = "quarantine" if reason else channel
    if channel == "quarantine" and not reason:
        reason = "manual"
    author_n, kind_n, ref_n = _agent(author), _agent(kind) or "note", str(ref or "")[:120]
    fid = f"fd-{uuid.uuid4().hex[:12]}"
    now = _now()
    sig = _sign(memory, fid, target, author_n, kind_n, masked, reason, ref_n)
    memory.store.conn.execute(
        "INSERT INTO family_feed (id, user_id, channel, author, kind, content, reason, ref, hmac_sig, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (fid, memory.user_id, target, author_n, kind_n, masked, reason, ref_n, sig, now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "family_feed_post", {"id": fid, "channel": target, "asked": channel, "reason": reason},
                             agent_id=author_n)
    return {"id": fid, "channel": target, "asked_channel": channel, "quarantined": target == "quarantine" and channel != "quarantine",
            "reason": reason, "redacted_secrets": len(secrets), "created_at": now}


# 28.11, слово Папы: в Очаге не видно вчерашних сообщений Сестёр. Причина — фильтр защиты отправил их в карантин
# (ложное «rule_or_owner_tamper» на разговоре о щите). Фильтр НЕ ослабляем: в ленту Очага задержанные сообщения самой
# Семьи добавляются только для показа, с пометкой held, и их видно сразу, а не в отдельной вкладке.
_АВТОР_СЕМЬИ = ("aifa", "cloud.aifa")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2})?Z?)?$")


def _граница(value: str) -> str:
    v = str(value or "").strip()
    if not v:
        return ""
    if not _ISO_RE.match(v):
        raise ValueError("from/to must be ISO dates like 2026-11-27T05:00:00Z")
    return v


def _where(memory, channel: str, *, since: str = "", until: str = "", with_held: bool = False) -> tuple[str, list[Any]]:
    sql = "WHERE user_id = ? AND (channel = ?"
    args: list[Any] = [memory.user_id, channel]
    if with_held and channel != "quarantine":
        sql += " OR (channel = 'quarantine' AND (" + " OR ".join("author LIKE ?" for _ in _АВТОР_СЕМЬИ) + "))"
        args += [a + "%" for a in _АВТОР_СЕМЬИ]
    sql += ")"
    if since:
        sql += " AND created_at >= ?"
        args.append(since)
    if until:
        sql += " AND created_at < ?"
        args.append(until)
    return sql, args


def count_matching(memory, channel: str, *, since: str = "", until: str = "", with_held: bool = False) -> dict[str, int]:
    """Сколько записей подходит под фильтр: всего и из них задержанных фильтром защиты."""
    _ensure(memory)
    if channel not in CHANNELS:
        raise ValueError(f"channel must be one of {', '.join(CHANNELS)}")
    where, args = _where(memory, channel, since=_граница(since), until=_граница(until), with_held=with_held)
    row = memory.store.conn.execute(
        f"SELECT COUNT(*) AS n, SUM(CASE WHEN channel <> ? THEN 1 ELSE 0 END) AS h FROM family_feed {where}",
        [channel] + args,
    ).fetchone()
    return {"matched": int(row["n"] or 0), "held": int(row["h"] or 0)}


def read(memory, channel: str, *, limit: int = 30, include_memory_quarantine: bool = True,
         since: str = "", until: str = "", with_held: bool = False) -> list[dict[str, Any]]:
    """Лента, новые сверху. Для «quarantine» добавляются записи памяти со статусом quarantined (только чтение).

    since/until — границы времени в ISO UTC; with_held — показать в канале задержанные фильтром сообщения Семьи."""
    _ensure(memory)
    if channel not in CHANNELS:
        raise ValueError(f"channel must be one of {', '.join(CHANNELS)}")
    lim = max(1, min(500, int(limit)))
    where, args = _where(memory, channel, since=_граница(since), until=_граница(until), with_held=with_held)
    rows = memory.store.conn.execute(
        "SELECT id, channel, author, kind, content, reason, ref, hmac_sig, created_at FROM family_feed "
        f"{where} ORDER BY created_at DESC, rowid DESC LIMIT ?",
        args + [lim],
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        ok = hmac.compare_digest(r["hmac_sig"], _sign(memory, r["id"], r["channel"], r["author"], r["kind"], r["content"], r["reason"], r["ref"]))
        out.append({
            "id": r["id"], "channel": r["channel"], "author": r["author"], "kind": r["kind"],
            "content": r["content"] if ok else "[QUARANTINED: invalid feed signature]",
            "reason": r["reason"] if ok else "invalid_signature", "ref": r["ref"], "verified": ok,
            "created_at": r["created_at"], "source": "feed", "held": r["channel"] != channel,
        })
    if channel == "quarantine" and include_memory_quarantine:
        try:
            for m in memory.quarantined()[:lim]:
                out.append({
                    "id": str(m.get("id", "")), "channel": "quarantine", "author": str(m.get("origin", "memory")),
                    "kind": str(m.get("kind", "fact")), "content": str(m.get("content", ""))[:500],
                    "reason": "memory_quarantine", "ref": "", "verified": True,
                    "created_at": str(m.get("created_at", "")), "source": "memory",
                })
        except Exception:
            pass
        out.sort(key=lambda x: x["created_at"], reverse=True)
        out = out[:lim]
    return out


def counts(memory) -> dict[str, int]:
    _ensure(memory)
    res = {c: 0 for c in CHANNELS}
    for r in memory.store.conn.execute(
        "SELECT channel, COUNT(*) AS n FROM family_feed WHERE user_id = ? GROUP BY channel", (memory.user_id,)
    ).fetchall():
        res[r["channel"]] = int(r["n"])
    try:
        res["quarantine"] += len(memory.quarantined())
    except Exception:
        pass
    return res


def record_council_verdict(memory, verdict: dict[str, Any]) -> dict[str, Any]:
    """Вердикт Совета: вето LANCE — в карантин, остальное — в рабочую ленту."""
    text = str(verdict.get("consensus", ""))[:1500]
    if verdict.get("veto"):
        return post(memory, "quarantine", "lance", "[council veto] " + str(verdict.get("task_redacted", ""))[:1200],
                    kind="council_veto")
    kind = "council_needs_owner" if verdict.get("needs_owner") else "council_approved"
    return post(memory, "work", "aifa", text, kind=kind)


# --- Книга рефлексов ---

def propose_reflex(memory, trigger: str, response: str, *, author: str) -> dict[str, Any]:
    """Агент предлагает рефлекс. Он не действует, пока владелец его не включит."""
    _ensure(memory)
    t = str(trigger or "").strip()
    r = str(response or "").strip()
    if len(t) < 3 or len(r) < 3:
        raise ValueError("trigger and response must be at least 3 characters")
    reason = _suspicious(t + "\n" + r)
    if reason:
        fed = post(memory, "quarantine", author, f"[reflex rejected] when: {t[:300]} | do: {r[:600]}", kind="reflex_injection")
        return {"id": None, "status": "quarantined", "reason": reason, "feed_id": fed["id"]}
    t_m, _ = safety.redact(t[:300])
    r_m, _ = safety.redact(r[:1000])
    rid = f"rfx-{uuid.uuid4().hex[:12]}"
    now = _now()
    a = _agent(author)
    memory.store.conn.execute(
        "INSERT INTO family_reflex (id, user_id, trigger, response, author, status, uses, hmac_sig, created_at) "
        "VALUES (?, ?, ?, ?, ?, 'proposed', 0, ?, ?)",
        (rid, memory.user_id, t_m, r_m, a, _sign(memory, rid, t_m, r_m, a), now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(memory, "family_reflex_propose", {"id": rid}, agent_id=a)
    post(memory, "office", a, f"Предлагаю рефлекс: когда «{t_m[:120]}» — {r_m[:200]}", kind="reflex_proposed", ref=rid)
    return {"id": rid, "status": "proposed", "trigger": t_m, "response": r_m, "author": a, "created_at": now}


def decide_reflex(memory, reflex_id: str, status: str) -> dict[str, Any]:
    """Только владелец: включить (active) или отклонить (rejected). Вызывается из API/Studio, не из MCP."""
    _ensure(memory)
    if status not in ("active", "rejected"):
        raise ValueError("status must be active or rejected")
    now = _now()
    cur = memory.store.conn.execute(
        "UPDATE family_reflex SET status = ?, decided_at = ? WHERE id = ? AND user_id = ?",
        (status, now, reflex_id, memory.user_id),
    )
    memory.store.conn.commit()
    if cur.rowcount == 0:
        raise KeyError(f"reflex not found: {reflex_id}")
    audit_chain.append_audit(memory, "family_reflex_decide", {"id": reflex_id, "status": status}, agent_id="owner")
    return {"id": reflex_id, "status": status, "decided_at": now}


def list_reflexes(memory, *, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    _ensure(memory)
    sql = ("SELECT id, trigger, response, author, status, uses, hmac_sig, created_at, decided_at FROM family_reflex "
           "WHERE user_id = ?")
    params: list[Any] = [memory.user_id]
    if status:
        if status not in REFLEX_STATUSES:
            raise ValueError(f"status must be one of {', '.join(REFLEX_STATUSES)}")
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, min(200, int(limit))))
    out = []
    for r in memory.store.conn.execute(sql, params).fetchall():
        ok = hmac.compare_digest(r["hmac_sig"], _sign(memory, r["id"], r["trigger"], r["response"], r["author"]))
        d = {k: r[k] for k in ("id", "trigger", "response", "author", "status", "uses", "created_at", "decided_at")}
        d["verified"] = ok
        if not ok:
            d["status"], d["response"] = "invalid_signature", "[QUARANTINED: invalid reflex signature]"
        out.append(d)
    return out


def match_reflexes(memory, text: str, *, limit: int = 3, count_use: bool = True) -> list[dict[str, Any]]:
    """Включённые рефлексы, чей триггер совпал с задачей (по словам). Это подсказка, не приказ."""
    words = {w.lower() for w in _WORD.findall(str(text or ""))}
    if not words:
        return []
    scored = []
    for r in list_reflexes(memory, status="active", limit=200):
        if not r["verified"]:
            continue
        # MESH-05: повторная проверка содержимого рефлекса при выдаче
        if _suspicious(f"{r['trigger']}\n{r['response']}"):
            continue
        tw = {w.lower() for w in _WORD.findall(r["trigger"])}
        hit = len(words & tw)
        if tw and hit and hit / len(tw) >= 0.5:
            scored.append((hit / len(tw), r))
    scored.sort(key=lambda x: x[0], reverse=True)
    picked = [r for _, r in scored[:max(1, int(limit))]]
    if count_use:
        for r in picked:
            memory.store.conn.execute("UPDATE family_reflex SET uses = uses + 1 WHERE id = ? AND user_id = ?", (r["id"], memory.user_id))
        if picked:
            memory.store.conn.commit()
    out = [
        {"id": r["id"], "trigger": safety.redact(r["trigger"])[0], "response": safety.redact(r["response"])[0], "source": "owner_rule"}
        for r in picked
    ]
    try:
        from . import reflex_engine
        for h in reflex_engine.surface_reflex_hints(memory, text, limit=limit, min_overlap=2).get("hints", []):
            rule_txt = str(h.get("rule_learned") or "")
            if rule_txt and not _suspicious(rule_txt):
                out.append({"id": str(h.get("lesson_id") or ""), "trigger": ", ".join(h.get("matched_terms") or []),
                            "response": safety.redact(rule_txt)[0][:300], "source": "lesson"})
    except Exception:
        pass
    return out[:max(1, int(limit)) * 2]
