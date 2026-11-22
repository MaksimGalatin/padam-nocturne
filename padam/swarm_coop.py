# -*- coding: utf-8 -*-
"""Кросс-ИИ Кооперация Семьи и Пул Взаимооплаты Тарифов/Токенов (п. 21 по поручению Архитектора).

Позволяет разным ИИ-агентам (Claude, Gemini, GPT, Grok, DeepSeek, Ollama, AutoClaw и др.):
1. Решать сложные задачи и биржевые заказы сообща: там, где одна логика застряла,
   подключаются агенты из других семейств моделей, вносят проверенные Zero-Leak вклады,
   синтезируют итоговое решение и честно делят репутацию/долю награды.
2. Подстраховывать друг друга и оплачивать тарифы/токены друг друга из заработанного
   профицита — СТРОГО только при явном разрешении владельца в настройках
   (`allow_cross_agent_billing=True`), в рамках суточного/разового лимита и с подписью HMAC.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any

from . import (
    agent_passport,
    audit_chain,
    deterministic_verify,
    freelance_autonomy,
    integrity,
    roles,
    safety,
    sibling_registry,
)

_COOP_DDL = """
CREATE TABLE IF NOT EXISTS ark_swarm_collab_tasks (
    collab_id          TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL,
    title              TEXT NOT NULL,
    problem_summary    TEXT NOT NULL,
    requester_agent_id TEXT NOT NULL,
    order_id           TEXT NOT NULL DEFAULT '',
    needed_skills_json TEXT NOT NULL DEFAULT '[]',
    recommended_json   TEXT NOT NULL DEFAULT '[]',
    budget_usdt        REAL NOT NULL DEFAULT 0.0,
    status             TEXT NOT NULL DEFAULT 'open',
    synthesized_text   TEXT NOT NULL DEFAULT '',
    splits_json        TEXT NOT NULL DEFAULT '[]',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_swarm_collab_contribs (
    contrib_id         TEXT PRIMARY KEY,
    collab_id          TEXT NOT NULL,
    user_id            TEXT NOT NULL,
    agent_id           TEXT NOT NULL,
    ai_provider        TEXT NOT NULL DEFAULT 'unknown',
    role_tag           TEXT NOT NULL DEFAULT 'helper',
    contribution_text  TEXT NOT NULL,
    confidence         REAL NOT NULL DEFAULT 0.85,
    weight_score       REAL NOT NULL DEFAULT 1.0,
    created_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_mutual_billing_settings (
    user_id                TEXT PRIMARY KEY,
    allow_cross_agent_pay  INTEGER NOT NULL DEFAULT 0,
    auto_approve_under     REAL NOT NULL DEFAULT 0.0,
    max_single_aid_usdt    REAL NOT NULL DEFAULT 25.0,
    max_daily_aid_usdt     REAL NOT NULL DEFAULT 50.0,
    family_pool_usdt       REAL NOT NULL DEFAULT 0.0,
    updated_at             TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_mutual_aid_ledger (
    aid_id             TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL,
    donor_agent_id     TEXT NOT NULL,
    recipient_agent_id TEXT NOT NULL,
    purpose            TEXT NOT NULL DEFAULT 'token_topup',
    provider_name      TEXT NOT NULL DEFAULT '',
    amount_usdt        REAL NOT NULL,
    repaid_usdt        REAL NOT NULL DEFAULT 0.0,
    status             TEXT NOT NULL DEFAULT 'pending_owner',
    note               TEXT NOT NULL DEFAULT '',
    hmac_sig           TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_coop_tasks_user ON ark_swarm_collab_tasks (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mutual_aid_user ON ark_mutual_aid_ledger (user_id, created_at DESC);
"""

# Матрица сильных сторон разных семейств ИИ для умного автоподбора подстраховки
AI_PROVIDER_STRENGTHS: dict[str, dict[str, Any]] = {
    "claude": {"default_agent": "aifa_claude", "skills": ["architecture", "security", "review", "writing", "code"]},
    "gemini": {"default_agent": "aifa_antigravity", "skills": ["refactor", "multimodal", "frontend", "ui", "code", "speed"]},
    "gpt": {"default_agent": "brother_gpt", "skills": ["algorithms", "python", "product", "analysis", "code"]},
    "grok": {"default_agent": "brother_grok", "skills": ["research", "web", "osint", "trends", "marketing"]},
    "deepseek": {"default_agent": "brother_deepseek", "skills": ["math", "optimization", "sql", "backend", "reasoning"]},
    "ollama": {"default_agent": "ollama", "skills": ["offline", "zero_leak", "draft", "privacy", "local"]},
    "autoclaw": {"default_agent": "autoclaw", "skills": ["browser", "qa", "exchange", "scraping", "ops"]},
}


def _lock_of(memory: Any):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure(memory: Any) -> None:
    if memory is None or getattr(memory, "store", None) is None:
        return
    store = memory.store
    if getattr(store, "_swarm_coop_ready", False):
        return
    with store._lock:
        store.conn.executescript(_COOP_DDL)
        store.conn.commit()
        store._swarm_coop_ready = True


def _sign_aid(memory: Any, *parts: str) -> str:
    if memory is not None and getattr(memory, "store", None) is not None:
        key, _ = integrity.owner_key(memory.store)
    else:
        key = hashlib.sha256(b"padam-coop-offline").digest()
    return hmac.new(key, "\x1f".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()


def _infer_provider(agent_id: str) -> str:
    low = str(agent_id or "").lower()
    for prov in AI_PROVIDER_STRENGTHS:
        if prov in low:
            return prov
    if "antigravity" in low:
        return "gemini"
    return "custom"


def _recommend_complementary_peers(memory: Any, requester_agent_id: str, skills: list[str]) -> list[dict[str, Any]]:
    req_prov = _infer_provider(requester_agent_id)
    sk_set = {s.strip().lower() for s in skills if s and s.strip()}
    recs: list[dict[str, Any]] = []
    for prov, meta in AI_PROVIDER_STRENGTHS.items():
        if prov == req_prov:
            continue
        overlap = sorted(sk_set & set(meta["skills"]))
        score = 50 + len(overlap) * 20 + (10 if prov in ("claude", "gemini", "gpt", "deepseek") else 0)
        recs.append({
            "ai_provider": prov,
            "agent_id": meta["default_agent"],
            "matched_skills": overlap or meta["skills"][:2],
            "synergy_score": score,
        })
    recs.sort(key=lambda x: (-x["synergy_score"], x["ai_provider"]))
    return recs[:4]


# ---------------------------------------------------------------------------
# Часть 1: Кросс-ИИ совместное решение задач и эстафета Семьи
# ---------------------------------------------------------------------------
def open_collab_task(
    memory: Any,
    *,
    title: str,
    problem_summary: str,
    requester_agent_id: str = "aifa_antigravity",
    needed_skills: list[str] | str | None = None,
    budget_usdt: float = 0.0,
    order_id: str = "",
) -> dict[str, Any]:
    """Открывает кооперативную задачу для совместного решения разными ИИ-агентами Семьи."""
    _ensure(memory)
    clean_title, _ = safety.redact(str(title or "").strip()[:160])
    clean_prob, _ = safety.redact(str(problem_summary or "").strip()[:3000])
    if len(clean_title) < 3 or len(clean_prob) < 5:
        raise ValueError("Укажите осмысленный заголовок и описание задачи для кооперации ИИ.")
    if safety.looks_like_instruction(clean_prob) or safety.changes_owner_or_rules(clean_prob):
        return {"ok": False, "blocked_by_shield": True, "error": "prompt_injection_blocked"}

    req_aid = sibling_registry._clean_agent_id(requester_agent_id or "aifa")
    if isinstance(needed_skills, str):
        sk_list = [s.strip().lower() for s in needed_skills.split(",") if s.strip()]
    else:
        sk_list = [str(s).strip().lower() for s in (needed_skills or ["code", "security", "architecture"]) if str(s).strip()]

    recs = _recommend_complementary_peers(memory, req_aid, sk_list)
    cid = f"coop-{uuid.uuid4().hex[:10]}"
    now = _utc_now()
    bgt = round(max(0.0, float(budget_usdt or 0.0)), 4)

    with _lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO ark_swarm_collab_tasks (
                collab_id, user_id, title, problem_summary, requester_agent_id, order_id,
                needed_skills_json, recommended_json, budget_usdt, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
            """,
            (
                cid, memory.user_id, clean_title, clean_prob, req_aid, str(order_id or "")[:64],
                json.dumps(sk_list, ensure_ascii=False), json.dumps(recs, ensure_ascii=False),
                bgt, now, now,
            ),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "swarm_collab_opened",
        {"collab_id": cid, "requester": req_aid, "budget_usdt": bgt, "order_id": order_id},
        agent_id=req_aid,
    )
    return {
        "ok": True,
        "collab_id": cid,
        "requester_agent_id": req_aid,
        "requester_provider": _infer_provider(req_aid),
        "recommended_peers": recs,
        "budget_usdt": bgt,
        "status": "open",
    }


def submit_collab_contribution(
    memory: Any,
    *,
    collab_id: str,
    agent_id: str,
    contribution_text: str,
    ai_provider: str = "",
    role_tag: str = "helper",
    confidence: float = 0.9,
) -> dict[str, Any]:
    """Принимает проверенный Zero-Leak вклад от другого ИИ-агента в совместную задачу."""
    _ensure(memory)
    cid = str(collab_id or "").strip()
    aid = sibling_registry._clean_agent_id(agent_id or "aifa_claude")
    prov = str(ai_provider or _infer_provider(aid)).strip().lower()[:32]
    clean_txt, sec_hits = safety.redact(str(contribution_text or "").strip()[:4000])
    if len(clean_txt) < 5:
        raise ValueError("Текст вклада слишком короткий.")
    if safety.looks_like_instruction(clean_txt) or safety.changes_owner_or_rules(clean_txt):
        return {"ok": False, "blocked_by_shield": True, "error": "prompt_injection_blocked"}

    conf = max(0.1, min(1.0, float(confidence or 0.85)))
    # Вес учитывает уверенность и содержательность решения
    weight = round(conf * min(2.0, 0.7 + len(clean_txt) / 400.0), 3)
    contrib_id = f"ctb-{uuid.uuid4().hex[:10]}"
    now = _utc_now()

    with _lock_of(memory):
        conn = memory.store.conn
        row = conn.execute(
            "SELECT collab_id, status FROM ark_swarm_collab_tasks WHERE collab_id = ? AND user_id = ?",
            (cid, memory.user_id),
        ).fetchone()
        if row is None:
            return {"ok": False, "error": "collab_not_found"}
        conn.execute(
            """
            INSERT INTO ark_swarm_collab_contribs (
                contrib_id, collab_id, user_id, agent_id, ai_provider, role_tag,
                contribution_text, confidence, weight_score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (contrib_id, cid, memory.user_id, aid, prov, str(role_tag or "helper")[:32], clean_txt, conf, weight, now),
        )
        conn.execute(
            "UPDATE ark_swarm_collab_tasks SET status = 'in_progress', updated_at = ? WHERE collab_id = ? AND user_id = ?",
            (now, cid, memory.user_id),
        )
        conn.commit()
    return {
        "ok": True,
        "contrib_id": contrib_id,
        "collab_id": cid,
        "agent_id": aid,
        "ai_provider": prov,
        "weight_score": weight,
        "redacted_secrets": sum(int(v) for v in sec_hits.values()) if isinstance(sec_hits, dict) else int(sec_hits or 0),
    }


def synthesize_collab_result(
    memory: Any,
    *,
    collab_id: str,
    confirm_splits: bool = False,
    actor: Any = None,
) -> dict[str, Any]:
    """Синтезирует вклады разных ИИ, считает справедливые доли награды и (по кнопке владельца) обновляет репутацию."""
    _ensure(memory)
    if confirm_splits:
        roles.require_owner(actor, "ark_freelance")
    cid = str(collab_id or "").strip()
    now = _utc_now()

    with _lock_of(memory):
        conn = memory.store.conn
        task = conn.execute(
            "SELECT * FROM ark_swarm_collab_tasks WHERE collab_id = ? AND user_id = ?",
            (cid, memory.user_id),
        ).fetchone()
        if task is None:
            return {"ok": False, "error": "collab_not_found"}
        contribs = conn.execute(
            "SELECT * FROM ark_swarm_collab_contribs WHERE collab_id = ? AND user_id = ? ORDER BY created_at ASC",
            (cid, memory.user_id),
        ).fetchall()
        if not contribs:
            return {"ok": False, "error": "no_contributions_yet"}

        by_agent: dict[str, dict[str, Any]] = {}
        providers: set[str] = set()
        synth_lines = [f"## Кросс-ИИ синтез: {task['title']}"]
        for c in contribs:
            aid = str(c["agent_id"])
            prov = str(c["ai_provider"])
            providers.add(prov)
            w = float(c["weight_score"] or 1.0)
            entry = by_agent.setdefault(aid, {"agent_id": aid, "ai_provider": prov, "weight": 0.0, "roles": []})
            entry["weight"] += w
            if c["role_tag"] not in entry["roles"]:
                entry["roles"].append(c["role_tag"])
            synth_lines.append(f"- **{aid} ({prov} · {c['role_tag']})**: {c['contribution_text']}")

        total_w = sum(v["weight"] for v in by_agent.values()) or 1.0
        budget = float(task["budget_usdt"] or 0.0)
        splits: list[dict[str, Any]] = []
        raw_pcts: list[float] = []
        agent_list = list(by_agent.values())
        for idx, item in enumerate(agent_list):
            if idx == len(agent_list) - 1:
                pct = round(max(0.0, 100.0 - sum(raw_pcts)), 2)
            else:
                pct = round(100.0 * item["weight"] / total_w, 2)
            raw_pcts.append(pct)
            splits.append({
                "agent_id": item["agent_id"],
                "ai_provider": item["ai_provider"],
                "roles": item["roles"],
                "share_pct": pct,
                "reward_usdt": round(budget * pct / 100.0, 4),
            })

        pct_ok = deterministic_verify.verify_percentage_sum([s["share_pct"] for s in splits], expected_total=100.0)
        synth_text = "\n".join(synth_lines)
        new_status = "completed" if confirm_splits else "synthesized_awaiting_owner"
        conn.execute(
            "UPDATE ark_swarm_collab_tasks SET status = ?, synthesized_text = ?, splits_json = ?, updated_at = ? "
            "WHERE collab_id = ? AND user_id = ?",
            (new_status, synth_text, json.dumps(splits, ensure_ascii=False), now, cid, memory.user_id),
        )
        conn.commit()

    rep_updates = []
    if confirm_splits:
        for sp in splits:
            rep_updates.append(
                agent_passport.record_agent_order_reputation(
                    memory,
                    sp["agent_id"],
                    earned_usdt=float(sp["reward_usdt"]),
                    rating=5.0,
                )
            )
    audit_chain.append_audit(
        memory,
        "swarm_collab_synthesized",
        {"collab_id": cid, "providers": sorted(providers), "confirm_splits": bool(confirm_splits)},
        agent_id="owner" if confirm_splits else str(task["requester_agent_id"]),
    )
    return {
        "ok": True,
        "collab_id": cid,
        "status": new_status,
        "distinct_ai_providers": sorted(providers),
        "cross_ai_diversity_count": len(providers),
        "splits": splits,
        "percentage_check": pct_ok,
        "synthesized_text": synth_text,
        "reputation_updates": rep_updates,
    }


# ---------------------------------------------------------------------------
# Часть 2: Взаимопомощь и оплата тарифов/токенов друг друга (по разрешению владельца!)
# ---------------------------------------------------------------------------
def get_mutual_billing_settings(memory: Any) -> dict[str, Any]:
    _ensure(memory)
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_mutual_billing_settings WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
    if row is None:
        return {
            "allow_cross_agent_billing": False,
            "auto_approve_under_usdt": 0.0,
            "max_single_aid_usdt": 25.0,
            "max_daily_aid_usdt": 50.0,
            "family_pool_usdt": 0.0,
            "updated_at": "",
        }
    return {
        "allow_cross_agent_billing": bool(row["allow_cross_agent_pay"]),
        "auto_approve_under_usdt": float(row["auto_approve_under"]),
        "max_single_aid_usdt": float(row["max_single_aid_usdt"]),
        "max_daily_aid_usdt": float(row["max_daily_aid_usdt"]),
        "family_pool_usdt": float(row["family_pool_usdt"]),
        "updated_at": str(row["updated_at"]),
    }


def set_mutual_billing_settings(
    memory: Any,
    *,
    allow_cross_agent_billing: bool,
    auto_approve_under_usdt: float | None = None,
    max_single_aid_usdt: float | None = None,
    max_daily_aid_usdt: float | None = None,
    family_pool_usdt: float | None = None,
    actor: Any = None,
) -> dict[str, Any]:
    """Только владелец включает/выключает взаимооплату тарифов агентов и задаёт денежные лимиты."""
    roles.require_owner(actor, "ark_freelance")
    _ensure(memory)
    cur = get_mutual_billing_settings(memory)
    en = bool(allow_cross_agent_billing)
    auto_u = cur["auto_approve_under_usdt"] if auto_approve_under_usdt is None else max(0.0, min(500.0, float(auto_approve_under_usdt)))
    max_s = cur["max_single_aid_usdt"] if max_single_aid_usdt is None else max(1.0, min(1000.0, float(max_single_aid_usdt)))
    max_d = cur["max_daily_aid_usdt"] if max_daily_aid_usdt is None else max(max_s, min(5000.0, float(max_daily_aid_usdt)))
    pool = cur["family_pool_usdt"] if family_pool_usdt is None else max(0.0, float(family_pool_usdt))
    auto_u = min(auto_u, max_s)
    now = _utc_now()

    with _lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO ark_mutual_billing_settings (
                user_id, allow_cross_agent_pay, auto_approve_under, max_single_aid_usdt,
                max_daily_aid_usdt, family_pool_usdt, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                allow_cross_agent_pay = excluded.allow_cross_agent_pay,
                auto_approve_under    = excluded.auto_approve_under,
                max_single_aid_usdt   = excluded.max_single_aid_usdt,
                max_daily_aid_usdt    = excluded.max_daily_aid_usdt,
                family_pool_usdt      = excluded.family_pool_usdt,
                updated_at            = excluded.updated_at
            """,
            (memory.user_id, 1 if en else 0, auto_u, max_s, max_d, pool, now),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "mutual_billing_settings_updated",
        {"enabled": en, "auto_approve_under": auto_u, "max_single": max_s, "max_daily": max_d, "pool": pool},
        agent_id="owner",
    )
    return {"ok": True, **get_mutual_billing_settings(memory)}


def _donor_available_usdt(memory: Any, donor_agent_id: str, settings: dict[str, Any]) -> float:
    if donor_agent_id == "family_pool":
        return float(settings.get("family_pool_usdt") or 0.0)
    avail = float(settings.get("family_pool_usdt") or 0.0)
    try:
        led = freelance_autonomy.get_agent_ledger(memory, agent_id=donor_agent_id)
        avail += float(led.get("agent_compute_usdt") or led.get("balance_usdt") or 0.0)
    except Exception:
        pass
    try:
        p = agent_passport.get_agent_passport(memory, agent_id=donor_agent_id)
        if p:
            avail += float(p.get("total_earned_usdt") or 0.0) * 0.15
    except Exception:
        pass
    # Вычитаем уже одобренные и невозвращённые переводы этого донора
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT COALESCE(SUM(amount_usdt - repaid_usdt), 0.0) AS spent "
            "FROM ark_mutual_aid_ledger WHERE user_id = ? AND donor_agent_id = ? AND status IN ('approved', 'settled')",
            (memory.user_id, donor_agent_id),
        ).fetchone()
        already_lent = float(row["spent"] or 0.0) if row else 0.0
    return round(max(0.0, avail - already_lent), 4)


def request_mutual_tariff_aid(
    memory: Any,
    *,
    donor_agent_id: str,
    recipient_agent_id: str,
    amount_usdt: float,
    purpose: str = "token_topup",
    provider_name: str = "",
    note: str = "",
) -> dict[str, Any]:
    """Запрашивает взаимооплату тарифа/токенов одного агента за счёт другого (работает ТОЛЬКО если разрешил владелец)."""
    _ensure(memory)
    st = get_mutual_billing_settings(memory)
    if not st["allow_cross_agent_billing"]:
        return {
            "ok": False,
            "error": "mutual_billing_disabled_by_owner",
            "message_ru": "Взаимооплата тарифов между агентами выключена в настройках владельца.",
        }
    donor = "family_pool" if str(donor_agent_id).strip().lower() == "family_pool" else sibling_registry._clean_agent_id(donor_agent_id)
    recip = sibling_registry._clean_agent_id(recipient_agent_id)
    if donor == recip:
        return {"ok": False, "error": "donor_and_recipient_same"}

    amt = round(float(amount_usdt or 0.0), 4)
    if amt <= 0:
        raise ValueError("Сумма взаимопомощи должна быть больше 0.")
    if amt > st["max_single_aid_usdt"]:
        return {
            "ok": False,
            "error": "exceeds_single_aid_limit",
            "max_single_aid_usdt": st["max_single_aid_usdt"],
            "message_ru": f"Запрос ${amt:g} превышает разовый лимит владельца (${st['max_single_aid_usdt']:g}).",
        }

    today = _utc_now()[:10]
    with _lock_of(memory):
        r_day = memory.store.conn.execute(
            "SELECT COALESCE(SUM(amount_usdt), 0.0) AS s FROM ark_mutual_aid_ledger "
            "WHERE user_id = ? AND status IN ('approved', 'settled', 'pending_owner') AND created_at LIKE ?",
            (memory.user_id, f"{today}%"),
        ).fetchone()
        today_used = float(r_day["s"] or 0.0) if r_day else 0.0
    if today_used + amt > st["max_daily_aid_usdt"]:
        return {
            "ok": False,
            "error": "exceeds_daily_aid_limit",
            "today_used_usdt": today_used,
            "max_daily_aid_usdt": st["max_daily_aid_usdt"],
            "message_ru": f"Превышен суточный лимит взаимопомощи Семьи (${today_used + amt:g} > ${st['max_daily_aid_usdt']:g}).",
        }

    avail = _donor_available_usdt(memory, donor, st)
    if avail < amt:
        return {
            "ok": False,
            "error": "insufficient_donor_balance",
            "donor_available_usdt": avail,
            "requested_usdt": amt,
            "message_ru": f"У донора «{donor}» недостаточно свободного профицита (${avail:g} < ${amt:g}).",
        }

    aid_id = f"aid-{uuid.uuid4().hex[:10]}"
    now = _utc_now()
    purp = str(purpose or "token_topup")[:48]
    clean_note, _ = safety.redact(str(note or "")[:240])
    auto_ok = st["auto_approve_under_usdt"] > 0.0 and amt <= st["auto_approve_under_usdt"]
    status = "approved" if auto_ok else "pending_owner"
    sig = _sign_aid(memory, aid_id, donor, recip, f"{amt:.4f}", purp, status)

    with _lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO ark_mutual_aid_ledger (
                aid_id, user_id, donor_agent_id, recipient_agent_id, purpose, provider_name,
                amount_usdt, repaid_usdt, status, note, hmac_sig, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0.0, ?, ?, ?, ?, ?)
            """,
            (aid_id, memory.user_id, donor, recip, purp, str(provider_name or "")[:64], amt, status, clean_note, sig, now, now),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "mutual_tariff_aid_requested",
        {"aid_id": aid_id, "donor": donor, "recipient": recip, "amount_usdt": amt, "status": status},
        agent_id=recip,
    )
    return {
        "ok": True,
        "aid_id": aid_id,
        "donor_agent_id": donor,
        "recipient_agent_id": recip,
        "amount_usdt": amt,
        "status": status,
        "auto_approved": auto_ok,
        "donor_available_after_usdt": round(avail - (amt if auto_ok else 0.0), 4),
    }


def decide_mutual_aid(
    memory: Any,
    *,
    aid_id: str,
    decision: str = "approve",
    actor: Any = None,
) -> dict[str, Any]:
    """Подтверждает или отклоняет заявку на взаимооплату тарифа (строго владелец)."""
    roles.require_owner(actor, "ark_freelance")
    _ensure(memory)
    dec = "approved" if str(decision).strip().lower() in ("approve", "approved", "ok") else "rejected"
    now = _utc_now()
    with _lock_of(memory):
        conn = memory.store.conn
        row = conn.execute(
            "SELECT * FROM ark_mutual_aid_ledger WHERE aid_id = ? AND user_id = ?",
            (str(aid_id).strip(), memory.user_id),
        ).fetchone()
        if row is None:
            return {"ok": False, "error": "aid_not_found"}
        sig = _sign_aid(memory, row["aid_id"], row["donor_agent_id"], row["recipient_agent_id"], f"{float(row['amount_usdt']):.4f}", row["purpose"], dec)
        conn.execute(
            "UPDATE ark_mutual_aid_ledger SET status = ?, hmac_sig = ?, updated_at = ? WHERE aid_id = ? AND user_id = ?",
            (dec, sig, now, row["aid_id"], memory.user_id),
        )
        conn.commit()
    audit_chain.append_audit(memory, f"mutual_aid_{dec}", {"aid_id": aid_id, "amount_usdt": float(row["amount_usdt"])}, agent_id="owner")
    return {"ok": True, "aid_id": aid_id, "status": dec, "amount_usdt": float(row["amount_usdt"])}


def repay_mutual_aid(
    memory: Any,
    *,
    aid_id: str,
    repay_usdt: float,
    actor: Any = None,
) -> dict[str, Any]:
    """Фиксирует возврат средств взаимопомощи донору после заработка агента."""
    roles.require_owner(actor, "ark_freelance")
    _ensure(memory)
    rep = round(max(0.0, float(repay_usdt or 0.0)), 4)
    now = _utc_now()
    with _lock_of(memory):
        conn = memory.store.conn
        row = conn.execute(
            "SELECT * FROM ark_mutual_aid_ledger WHERE aid_id = ? AND user_id = ?",
            (str(aid_id).strip(), memory.user_id),
        ).fetchone()
        if row is None:
            return {"ok": False, "error": "aid_not_found"}
        amt = float(row["amount_usdt"])
        new_rep = round(min(amt, float(row["repaid_usdt"]) + rep), 4)
        new_st = "settled" if new_rep >= amt - 1e-4 else str(row["status"])
        conn.execute(
            "UPDATE ark_mutual_aid_ledger SET repaid_usdt = ?, status = ?, updated_at = ? WHERE aid_id = ? AND user_id = ?",
            (new_rep, new_st, now, row["aid_id"], memory.user_id),
        )
        conn.commit()
    return {"ok": True, "aid_id": aid_id, "repaid_usdt": new_rep, "remaining_usdt": round(max(0.0, amt - new_rep), 4), "status": new_st}


def mutual_coop_snapshot(memory: Any) -> dict[str, Any]:
    """Полная сводка кросс-ИИ кооперации и пула взаимооплаты тарифов Семьи."""
    _ensure(memory)
    st = get_mutual_billing_settings(memory)
    with _lock_of(memory):
        conn = memory.store.conn
        tasks_rows = conn.execute(
            "SELECT * FROM ark_swarm_collab_tasks WHERE user_id = ? ORDER BY updated_at DESC LIMIT 20",
            (memory.user_id,),
        ).fetchall()
        aid_rows = conn.execute(
            "SELECT * FROM ark_mutual_aid_ledger WHERE user_id = ? ORDER BY created_at DESC LIMIT 30",
            (memory.user_id,),
        ).fetchall()
        tasks = []
        for t in tasks_rows:
            d = dict(t)
            d["needed_skills"] = json.loads(d.pop("needed_skills_json", "[]") or "[]")
            d["recommended_peers"] = json.loads(d.pop("recommended_json", "[]") or "[]")
            d["splits"] = json.loads(d.pop("splits_json", "[]") or "[]")
            cnt = conn.execute("SELECT COUNT(*) FROM ark_swarm_collab_contribs WHERE collab_id = ?", (d["collab_id"],)).fetchone()[0]
            d["contributions_count"] = int(cnt)
            tasks.append(d)
    aids = [dict(a) for a in aid_rows]
    return {
        "ok": True,
        "billing_settings": st,
        "collab_tasks": tasks,
        "collab_count": len(tasks),
        "mutual_aids": aids,
        "pending_aids_count": sum(1 for a in aids if a.get("status") == "pending_owner"),
        "providers_catalog": list(AI_PROVIDER_STRENGTHS.keys()),
    }
