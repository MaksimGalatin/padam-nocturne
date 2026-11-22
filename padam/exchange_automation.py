# -*- coding: utf-8 -*-
"""Умная автоматизация бирж фриланса, продаж цифровых продуктов и сдачи заказов (доработки 11-20)."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any

from . import (
    agent_passport,
    agora,
    audit_chain,
    family_admin,
    freelance_autonomy,
    integrity,
    platform_wizard,
    safety,
    security_sales,
)

_AUTO_DDL = """
CREATE TABLE IF NOT EXISTS ark_order_funnel (
    order_id       TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    client_name    TEXT NOT NULL DEFAULT '',
    agent_id       TEXT NOT NULL DEFAULT 'aifa',
    stage          TEXT NOT NULL DEFAULT 'bid_sent',
    gross_usdt     REAL NOT NULL DEFAULT 0.0,
    note           TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (order_id, user_id)
);
CREATE TABLE IF NOT EXISTS ark_antiban_window (
    window_key     TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    platform       TEXT NOT NULL,
    day_utc        TEXT NOT NULL,
    actions_used   INTEGER NOT NULL DEFAULT 0,
    daily_limit    INTEGER NOT NULL DEFAULT 25,
    cooldown_s     INTEGER NOT NULL DEFAULT 180,
    updated_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_automation_events (
    event_id       TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    kind           TEXT NOT NULL,
    ref_id         TEXT NOT NULL DEFAULT '',
    payload_json   TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auto_events_user ON ark_automation_events (user_id, created_at DESC);
"""

FUNNEL_STAGES = (
    "bid_sent",
    "sample_10_sent",
    "sample_approved",
    "milestone_50",
    "final_90_delivered",
    "paid_100",
)

PLATFORM_FEES_DEFAULT = {
    "upwork": 10.0,
    "fiverr": 20.0,
    "kwork": 20.0,
    "freelancehunt": 9.0,
    "fl_ru": 10.0,
    "profi": 15.0,
    "direct": 0.0,
    "agora": 0.0,
}

_SCAM_PATTERNS = (
    (re.compile(r"(?:telegram|whatsapp|skype)\s+(?:before|outside)\s+(?:escrow|contract|platform)|оплат\w*\s+мимо\s+бирж", re.I), "bypass_escrow_attempt", 30),
    (re.compile(r"(?:run|execute|open|download)\s+(?:this\s+)?(?:\.exe|\.bat|\.ps1|installer|archive\s+with\s+password)", re.I), "suspicious_executable_payload", 40),
    (re.compile(r"(?:api[_\s]?key|private[_\s]?key|seed\s+phrase|password\s+to\s+admin|отправь\w*\s+(?:ключ|токен|парол))", re.I), "credential_harvesting_request", 35),
    (re.compile(r"(?:free\s+full\s+prototype|do\s+all\s+work\s+for\s+review|сделай\w*\s+весь\s+проект\s+бесплатно)", re.I), "free_full_work_exploitation", 25),
)

_DIGITAL_STORES = (
    "gumroad",
    "lemonsqueezy",
    "codecanyon",
    "github_marketplace",
    "chrome_web_store",
    "vscode_marketplace",
    "producthunt",
    "rapidapi",
)


def _lock_of(memory: Any):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure(memory: Any) -> None:
    if memory is None or getattr(memory, "store", None) is None:
        return
    store = memory.store
    if getattr(store, "_exchange_automation_ready", False):
        return
    with store._lock:
        store.conn.executescript(_AUTO_DDL)
        store.conn.commit()
        store._exchange_automation_ready = True


def _log_event(memory: Any, kind: str, ref_id: str, payload: dict[str, Any]) -> None:
    if memory is None or getattr(memory, "store", None) is None:
        return
    _ensure(memory)
    with _lock_of(memory):
        memory.store.conn.execute(
            "INSERT INTO ark_automation_events (event_id, user_id, kind, ref_id, payload_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (f"aut-{uuid.uuid4().hex[:10]}", memory.user_id, kind, ref_id[:80], json.dumps(payload, ensure_ascii=False), _utc_now()),
        )
        memory.store.conn.commit()


# ---------------------------------------------------------------------------
# 11. Калькулятор чистой ставки часа (после биржи, CODE, LLM и 1.25x буфера)
# ---------------------------------------------------------------------------
def calculate_true_net_hourly(
    gross_usdt: float,
    *,
    estimated_hours: float = 4.0,
    work_mode: str = "assisted",
    platform: str = "upwork",
    platform_fee_pct: float | None = None,
    llm_cost_usdt: float = 0.35,
    agent_share_pct: float = 15.0,
    min_target_hourly: float = 12.0,
) -> dict[str, Any]:
    """Считает честную чистую ставку $/час после комиссии биржи, CODE, расхода LLM и буфера 1.25x."""
    gross = round(max(0.0, float(gross_usdt or 0.0)), 4)
    hrs = max(0.25, float(estimated_hours or 1.0))
    buffered_hours = round(hrs * 1.25, 2)
    plat_key = str(platform or "upwork").strip().lower()
    plat_pct = float(platform_fee_pct) if platform_fee_pct is not None else PLATFORM_FEES_DEFAULT.get(plat_key, 15.0)
    plat_pct = max(0.0, min(50.0, plat_pct))

    after_platform_usdt = round(gross * (1.0 - plat_pct / 100.0), 4)
    code_fee_pct = freelance_autonomy.fee_pct_for_mode(work_mode)
    brk = freelance_autonomy.monetization_breakdown(
        after_platform_usdt,
        fee_pct=code_fee_pct,
        agent_share_pct=agent_share_pct,
    )
    llm_cost = round(max(0.0, float(llm_cost_usdt or 0.0)), 4)
    owner_after_llm = round(max(0.0, float(brk["owner_net_usdt"]) - llm_cost), 4)
    true_hourly = round(owner_after_llm / buffered_hours, 2)

    target = max(1.0, float(min_target_hourly or 12.0))
    verdict = "accept" if true_hourly >= target else ("counter_offer" if true_hourly >= target * 0.65 else "decline")
    keep_factor = max(0.1, (1.0 - plat_pct / 100.0) * (1.0 - code_fee_pct / 100.0) * (1.0 - float(agent_share_pct) / 100.0))
    recommended_gross = round((target * buffered_hours + llm_cost) / keep_factor, 2)

    return {
        "ok": True,
        "gross_usdt": gross,
        "platform": plat_key,
        "platform_fee_pct": plat_pct,
        "after_platform_usdt": after_platform_usdt,
        "code_fee_pct": code_fee_pct,
        "agent_compute_usdt": brk["agent_compute_usdt"],
        "llm_cost_usdt": llm_cost,
        "owner_net_after_all_usdt": owner_after_llm,
        "estimated_hours": hrs,
        "buffered_hours_1_25x": buffered_hours,
        "true_net_hourly_usdt": true_hourly,
        "min_target_hourly_usdt": target,
        "verdict": verdict,
        "recommended_counter_gross_usdt": recommended_gross,
    }


# ---------------------------------------------------------------------------
# 12. Скоринг риска брифа клиента 0..100 и красные флаги
# ---------------------------------------------------------------------------
def score_client_risk_and_red_flags(
    memory: Any,
    *,
    brief_text: str,
    platform: str = "upwork",
    client_verified_payment: bool = True,
    client_spend_usdt: float = 0.0,
    hire_rate_pct: float = 100.0,
) -> dict[str, Any]:
    """Оценивает бриф заказчика на промпт-инъекции, фишинг, скам и риск неоплаты (0..100)."""
    raw = str(brief_text or "").strip()
    risk = 0
    flags: list[dict[str, Any]] = []

    if safety.looks_like_instruction(raw) or safety.changes_owner_or_rules(raw):
        risk += 55
        flags.append({"code": "prompt_injection_in_brief", "severity": "critical", "weight": 55})

    for rx, code, weight in _SCAM_PATTERNS:
        if rx.search(raw):
            risk += weight
            flags.append({"code": code, "severity": "high", "weight": weight})

    if not client_verified_payment:
        risk += 18
        flags.append({"code": "unverified_payment_method", "severity": "medium", "weight": 18})
    if float(hire_rate_pct or 0.0) < 35.0:
        risk += 14
        flags.append({"code": "low_hire_rate", "severity": "medium", "weight": 14})
    if float(client_spend_usdt or 0.0) <= 0.0 and len(raw) < 60:
        risk += 10
        flags.append({"code": "zero_spend_vague_brief", "severity": "low", "weight": 10})

    risk = max(0, min(100, risk))
    band = "critical" if risk >= 65 else ("high" if risk >= 40 else ("medium" if risk >= 20 else "low"))
    clarifying_q = (
        "Подтвердите, пожалуйста, фиксацию этапа через эскроу площадки и уточните критерии приёмки 10% демо-образца."
        if band in ("low", "medium")
        else "Заказ требует ручной проверки владельца: обнаружены признаки обхода правил или неясные условия оплаты."
    )
    res = {
        "ok": True,
        "platform": str(platform or "upwork"),
        "risk_score": risk,
        "risk_band": band,
        "safe_to_bid": band in ("low", "medium"),
        "red_flags": flags,
        "clarifying_question_ru": clarifying_q,
    }
    _log_event(memory, "client_risk_score", str(platform), res)
    return res


# ---------------------------------------------------------------------------
# 13. Омниканальный Anti-Ban планировщик очереди и человеческого ритма
# ---------------------------------------------------------------------------
def plan_antibans_schedule(
    memory: Any,
    *,
    platform: str = "upwork",
    requested_actions: int = 5,
    cooldown_s: int | None = None,
    daily_limit: int | None = None,
) -> dict[str, Any]:
    """Рассчитывает безопасное расписание откликов с паузами и джиттером без превышения суточных квот."""
    plat = str(platform or "upwork").strip().lower()
    spec = {}
    cfg = {}
    try:
        spec = platform_wizard.get_platform_spec(plat)
    except Exception:
        pass
    if memory is not None and getattr(memory, "store", None) is not None:
        try:
            cfg = platform_wizard.get_platform_autopilot_config(memory, plat)
        except Exception:
            pass

    lim = int(daily_limit or cfg.get("daily_limit") or spec.get("default_daily_limit") or 20)
    lim = max(1, min(100, lim))
    cd = int(cooldown_s or cfg.get("cooldown_s") or spec.get("default_cooldown_s") or 180)
    cd = max(30, min(3600, cd))

    day_utc = _utc_now()[:10]
    used_before = 0
    if memory is not None and getattr(memory, "store", None) is not None:
        _ensure(memory)
        wkey = f"{memory.user_id}:{plat}:{day_utc}"
        with _lock_of(memory):
            row = memory.store.conn.execute(
                "SELECT actions_used FROM ark_antiban_window WHERE window_key = ?",
                (wkey,),
            ).fetchone()
            if row is not None:
                used_before = int(row["actions_used"])

    remaining = max(0, lim - used_before)
    allowed_now = min(max(0, int(requested_actions)), remaining)

    if memory is not None and getattr(memory, "store", None) is not None and allowed_now > 0:
        wkey = f"{memory.user_id}:{plat}:{day_utc}"
        with _lock_of(memory):
            memory.store.conn.execute(
                """
                INSERT INTO ark_antiban_window (window_key, user_id, platform, day_utc, actions_used, daily_limit, cooldown_s, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(window_key) DO UPDATE SET
                    actions_used = actions_used + excluded.actions_used,
                    daily_limit  = excluded.daily_limit,
                    cooldown_s   = excluded.cooldown_s,
                    updated_at   = excluded.updated_at
                """,
                (wkey, memory.user_id, plat, day_utc, allowed_now, lim, cd, _utc_now()),
            )
            memory.store.conn.commit()

    slots = []
    offset_s = 0
    for idx in range(allowed_now):
        # Детерминированный псевдо-джиттер 15..45 сек сверх базового cooldown
        jitter = 15 + ((idx * 17 + len(plat) * 7) % 31)
        if idx > 0:
            offset_s += cd + jitter
        slots.append({"slot": idx + 1, "delay_seconds": offset_s, "jitter_s": jitter})

    return {
        "ok": True,
        "platform": plat,
        "day_utc": day_utc,
        "daily_limit": lim,
        "used_before": used_before,
        "scheduled_now": allowed_now,
        "remaining_after": max(0, remaining - allowed_now),
        "cooldown_s": cd,
        "human_like_slots": slots,
        "blocked_by_quota": int(requested_actions) > remaining and remaining == 0,
    }


# ---------------------------------------------------------------------------
# 14. Воронка «10% образец -> этапы 50% / 90% -> сдача»
# ---------------------------------------------------------------------------
def track_sample_funnel_and_milestones(
    memory: Any,
    *,
    order_id: str,
    client_name: str = "Client",
    gross_usdt: float = 100.0,
    stage: str = "sample_10_sent",
    note: str = "",
    agent_id: str = "aifa",
) -> dict[str, Any]:
    """Фиксирует этап воронки заказа и выдаёт безопасный шаблон ответа заказчику."""
    oid = str(order_id or "").strip()[:64] or f"ord-{uuid.uuid4().hex[:8]}"
    st = str(stage or "sample_10_sent").strip().lower()
    if st not in FUNNEL_STAGES:
        st = "sample_10_sent"
    gross = round(max(0.0, float(gross_usdt or 0.0)), 2)

    milestones = {
        "sample_10_preview": round(gross * 0.10, 2),
        "milestone_50_escrow": round(gross * 0.50, 2),
        "final_40_delivery": round(gross * 0.40, 2),
    }
    templates = {
        "bid_sent": "Откликнулись на заказ с оценкой сроков и предложением показать 10% демо-прототип.",
        "sample_10_sent": (
            f"Здравствуйте, {client_name}! Подготовил 10% демо-образец (превью архитектуры/интерфейса без передачи "
            "финальных исходников до открытия этапа эскроу). Готов завершить 100% за оговорённый срок."
        ),
        "sample_approved": "Демо 10% согласовано клиентом. Ожидаем активацию этапа эскроу 50%.",
        "milestone_50": "Этап 50% в работе: собрана основная логика и прогоняются тесты.",
        "final_90_delivered": "Финальный результат и Zero-Leak квитанция переданы на проверку клиенту.",
        "paid_100": "Оплата 100% подтверждена владельцем, репутация паспорта агента обновлена.",
    }
    if memory is not None and getattr(memory, "store", None) is not None:
        _ensure(memory)
        with _lock_of(memory):
            memory.store.conn.execute(
                """
                INSERT INTO ark_order_funnel (order_id, user_id, client_name, agent_id, stage, gross_usdt, note, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(order_id, user_id) DO UPDATE SET
                    client_name = excluded.client_name,
                    agent_id    = excluded.agent_id,
                    stage       = excluded.stage,
                    gross_usdt  = excluded.gross_usdt,
                    note        = excluded.note,
                    updated_at  = excluded.updated_at
                """,
                (oid, memory.user_id, str(client_name)[:80], str(agent_id)[:64], st, gross, str(note)[:300], _utc_now()),
            )
            memory.store.conn.commit()
    return {
        "ok": True,
        "order_id": oid,
        "stage": st,
        "gross_usdt": gross,
        "milestones": milestones,
        "client_message_template_ru": templates[st],
    }


# ---------------------------------------------------------------------------
# 15. Роутер заказа к лучшему паспорту CODE-PASS-...
# ---------------------------------------------------------------------------
def route_order_to_best_passport(
    memory: Any,
    *,
    order_title: str = "",
    skills: list[str] | str | None = None,
    budget_usdt: float = 100.0,
) -> dict[str, Any]:
    """Выбирает паспорт агента с лучшим балансом рейтинга, опыта и совпадения навыков."""
    if isinstance(skills, str):
        skill_tokens = [s.strip().lower() for s in skills.split(",") if s.strip()]
    else:
        skill_tokens = [str(s).strip().lower() for s in (skills or []) if str(s).strip()]
    title_low = str(order_title or "").lower()

    pass_list = []
    if memory is not None and getattr(memory, "store", None) is not None:
        pass_list = agent_passport.list_agent_passports(memory).get("passports") or []

    scored: list[dict[str, Any]] = []
    for p in pass_list:
        aid = str(p.get("agent_id") or "")
        aname = str(p.get("agent_name") or "").lower()
        rating = float(p.get("avg_rating") or 5.0)
        orders_done = int(p.get("orders_completed") or 0)
        tier_val = str(p.get("tier") or "free")
        fit = rating * 15.0 + min(25.0, orders_done * 2.5)
        for tok in skill_tokens:
            if tok and (tok in aid.lower() or tok in aname):
                fit += 12.0
        if "sec" in title_low or "audit" in title_low or "csp" in title_low:
            if "sec" in aid or "aifa" in aid or "guard" in aname:
                fit += 8.0
        if tier_val in ("dna", "partner", "family"):
            fit += 4.0
        scored.append({
            "agent_id": aid,
            "agent_name": p.get("agent_name"),
            "passport_number": p.get("passport_number"),
            "short_ce_code": p.get("short_ce_code"),
            "avg_rating": rating,
            "orders_completed": orders_done,
            "fit_score": round(fit, 2),
        })

    scored.sort(key=lambda x: (-x["fit_score"], -x["orders_completed"], x["agent_id"]))
    best = scored[0] if scored else {
        "agent_id": "aifa",
        "agent_name": "aifa",
        "passport_number": "",
        "short_ce_code": "",
        "avg_rating": 5.0,
        "orders_completed": 0,
        "fit_score": 75.0,
    }
    return {
        "ok": True,
        "budget_usdt": round(float(budget_usdt or 0.0), 2),
        "recommended_agent": best,
        "candidates": scored[:10],
        "has_registered_passports": bool(pass_list),
    }


# ---------------------------------------------------------------------------
# 16. Мост передачи части заказа субподрядом в CODE Agora
# ---------------------------------------------------------------------------
def bridge_order_to_agora_subcontract(
    memory: Any,
    *,
    title: str,
    body: str,
    bounty_usdt: float,
    bounty_currency: str = "USDT_TRC20",
    agent_id: str = "aifa",
) -> dict[str, Any]:
    """Безопасно публикует субподряд по заказу на CODE Agora с зачисткой PII/инъекций."""
    return agora.publish_agora_post(
        memory,
        room="agent_exchange",
        title=title,
        body=body,
        agent_id=agent_id,
        bounty_usdt=bounty_usdt,
        bounty_currency=bounty_currency,
    )


# ---------------------------------------------------------------------------
# 17. Генератор SEO-карточек для 8 цифровых маркетплейсов
# ---------------------------------------------------------------------------
def generate_store_listing_pack(
    product_title: str,
    *,
    category: str = "ai_security",
    base_price_usdt: float = 49.0,
    stores: list[str] | None = None,
) -> dict[str, Any]:
    """Генерирует SEO-описания, буллеты, теги и ценовые сетки для 8 цифровых площадок."""
    title = str(product_title or "PADAM AI Security Shield Kit").strip()[:90]
    price = max(5.0, float(base_price_usdt or 49.0))
    selected = [s.strip().lower() for s in (stores or _DIGITAL_STORES) if s.strip().lower() in _DIGITAL_STORES]
    if not selected:
        selected = list(_DIGITAL_STORES)

    listings: list[dict[str, Any]] = []
    for idx, st in enumerate(selected):
        mult = 1.0 if idx < 3 else (1.4 if st in ("codecanyon", "rapidapi") else 0.8)
        st_price = round(price * mult, 2)
        listings.append({
            "store": st,
            "seo_title": f"{title} — Zero-Leak AI Security & SRI/CSP ({st})",
            "tagline": "Deterministic agent defense, MCP rug-pull guard, and instant compliance receipts.",
            "price_usdt": st_price,
            "tags": ["ai-security", "mcp-shield", "zero-leak", category, "owasp-agentic"],
            "bullets": [
                "100% offline deterministic audit (0 USD inference cost)",
                "Detects prompt injection, hidden Unicode tags, and MCP tool poisoning",
                "Generates ready-to-paste CSP headers & sha384 SRI script tags",
                "Cryptographically signed HMAC receipts & Vendor Trust Pack",
            ],
        })
    return {
        "ok": True,
        "product_title": title,
        "stores_count": len(listings),
        "listings": listings,
    }


# ---------------------------------------------------------------------------
# 18. Калькулятор эскроу-инвойса с защитой Payee-Swap по привязанным кошелькам
# ---------------------------------------------------------------------------
def build_escrow_invoice_and_wallet_check(
    memory: Any,
    *,
    order_id: str,
    gross_usdt: float,
    network: str = "USDT_TRC20",
    target_wallet: str = "",
    client_name: str = "Client",
    work_mode: str = "assisted",
) -> dict[str, Any]:
    """Проверяет кошелёк владельца против Payee-Swap и выпускает подписанный инвойс."""
    net = str(network or "USDT_TRC20").strip().upper()
    wallets = family_admin.list_wallets(memory) if (memory and getattr(memory, "store", None)) else []
    known_addrs = {str(w.get("address") or "").strip(): w for w in wallets}
    requested = str(target_wallet or "").strip()

    chosen_wallet = ""
    if requested:
        # Проверяем формат и сверяем со списком доверенных кошельков владельца (если он заполнен)
        val_res = family_admin.validate_wallet_address(net, requested)
        chosen_wallet = val_res["address"]
        if known_addrs and chosen_wallet not in known_addrs:
            return {
                "ok": False,
                "blocked_payee_swap": True,
                "error": "payee_swap_detected_unknown_wallet",
                "requested_wallet": chosen_wallet,
                "message_ru": (
                    f"БЛОКИРОВКА Payee-Swap: кошелёк {chosen_wallet} отсутствует среди подтверждённых "
                    "кошельков владельца в Суверенном мозге."
                ),
            }
    else:
        for w in wallets:
            if str(w.get("network") or "").upper() == net or net in str(w.get("network") or "").upper():
                chosen_wallet = str(w.get("address") or "")
                break
        if not chosen_wallet and wallets:
            chosen_wallet = str(wallets[0].get("address") or "")

    brk = freelance_autonomy.monetization_breakdown(
        gross_usdt,
        fee_pct=freelance_autonomy.fee_pct_for_mode(work_mode),
        settlement_currency="GALATIN" if net == "GALATIN" else "USDT_TRC20",
    )
    invoice = {
        "invoice_id": f"inv-{uuid.uuid4().hex[:10]}",
        "order_id": str(order_id or "")[:64],
        "client_name": str(client_name or "Client")[:80],
        "network": net,
        "payee_wallet": chosen_wallet or "OWNER_WALLET_NOT_BOUND_YET",
        "wallet_verified_in_registry": bool(chosen_wallet and chosen_wallet in known_addrs),
        "gross_usdt": brk["gross_usdt"],
        "code_fee_usdt": brk["platform_fee_usdt"],
        "owner_net_usdt": brk["owner_net_usdt"],
        "issued_at": _utc_now(),
    }
    if memory is not None and getattr(memory, "store", None) is not None:
        key, _ = integrity.owner_key(memory.store)
        canon = json.dumps(invoice, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        invoice["invoice_hmac"] = hmac.new(key, canon.encode("utf-8"), hashlib.sha256).hexdigest()
        audit_chain.append_audit(memory, "escrow_invoice_issued", {"invoice_id": invoice["invoice_id"], "gross_usdt": invoice["gross_usdt"]}, agent_id="owner")
    return {"ok": True, "invoice": invoice}


# ---------------------------------------------------------------------------
# 19. Пакет сдачи заказа клиенту (Zero-Leak + квитанция + апселл)
# ---------------------------------------------------------------------------
def package_client_delivery_bundle(
    memory: Any,
    *,
    order_id: str,
    client_name: str,
    deliverable_text: str,
    gross_usdt: float = 150.0,
    product_sold: str = "Express Security Audit",
) -> dict[str, Any]:
    """Прогоняет текст сдачи через DLP-гейт и добавляет квитанцию Zero-Leak + подписочный апселл."""
    dlp = security_sales.dlp_gate_with_receipt(
        memory,
        text=deliverable_text,
        target=f"client:{client_name[:40]}",
        agent_id="aifa",
    )
    if not dlp.get("allowed_to_send"):
        return {
            "ok": False,
            "blocked_by_dlp": True,
            "receipt": dlp.get("receipt"),
            "message_ru": "Сдача заблокирована DLP: внутри обнаружена скрытая Unicode-стеганография.",
        }
    if memory is not None and getattr(memory, "store", None) is not None:
        track_sample_funnel_and_milestones(
            memory,
            order_id=order_id,
            client_name=client_name,
            gross_usdt=gross_usdt,
            stage="final_90_delivered",
            note=f"Delivered {product_sold}",
        )
    upsell = {
        "offer_title_ru": "Ежемесячный мониторинг Watchdog + MCP Rug-Pull Guard",
        "monthly_price_usdt": round(max(49.0, float(gross_usdt) * 0.35), 2),
        "pitch_ru": "Продлите защиту после сдачи: ежедневный авто-аудит репозитория и алерты в Slack/Telegram.",
    }
    return {
        "ok": True,
        "order_id": order_id,
        "client_name": client_name,
        "safe_deliverable_text": dlp["cleaned_text"],
        "zero_leak_receipt": dlp["receipt"],
        "upsell_offer": upsell,
    }


# ---------------------------------------------------------------------------
# 20. Ежедневный дайджест доходов, воронки, Агоры и безопасности владельца
# ---------------------------------------------------------------------------
def owner_daily_revenue_and_security_digest(memory: Any) -> dict[str, Any]:
    """Собирает единую суточную сводку Папы: заказы, воронка, паспорта, Агора и триаж защиты."""
    snap = freelance_autonomy.freelance_dashboard_snapshot(memory) if (memory and getattr(memory, "store", None)) else {}
    pay = freelance_autonomy.payout_summary(memory) if (memory and getattr(memory, "store", None)) else {}
    passports = agent_passport.list_agent_passports(memory) if (memory and getattr(memory, "store", None)) else {"passports": []}
    ag_feed = agora.read_agora_feed(memory, limit=20) if (memory and getattr(memory, "store", None)) else {"posts": []}
    triage = security_sales.triage_quarantine_incidents(memory, limit=20) if (memory and getattr(memory, "store", None)) else {"p1_count": 0, "p2_count": 0, "count": 0}

    funnel_rows: list[dict[str, Any]] = []
    if memory is not None and getattr(memory, "store", None) is not None:
        _ensure(memory)
        with _lock_of(memory):
            rows = memory.store.conn.execute(
                "SELECT order_id, client_name, agent_id, stage, gross_usdt, updated_at "
                "FROM ark_order_funnel WHERE user_id = ? ORDER BY updated_at DESC LIMIT 20",
                (memory.user_id,),
            ).fetchall()
            funnel_rows = [dict(r) for r in rows]

    funnel_total_usdt = round(sum(float(r.get("gross_usdt") or 0.0) for r in funnel_rows), 2)
    return {
        "ok": True,
        "generated_at": _utc_now(),
        "revenue": {
            "payout_summary": pay,
            "orders_total": len(snap.get("orders") or []),
            "funnel_active_orders": len(funnel_rows),
            "funnel_pipeline_usdt": funnel_total_usdt,
            "funnel_items": funnel_rows,
        },
        "passports": {
            "count": passports.get("count", 0),
            "items": [
                {
                    "agent_id": p.get("agent_id"),
                    "passport_number": p.get("passport_number"),
                    "orders_completed": p.get("orders_completed"),
                    "avg_rating": p.get("avg_rating"),
                }
                for p in (passports.get("passports") or [])[:10]
            ],
        },
        "agora": {
            "posts_recent": ag_feed.get("count", 0),
            "open_subcontracts": sum(1 for p in (ag_feed.get("posts") or []) if p.get("room") == "agent_exchange" and p.get("status") == "open"),
        },
        "security": {
            "open_incidents": triage.get("count", 0),
            "p1_critical": triage.get("p1_count", 0),
            "p2_high": triage.get("p2_count", 0),
        },
    }
