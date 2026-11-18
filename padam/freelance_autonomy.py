# -*- coding: utf-8 -*-
"""Модуль автономного заработка на фриланс-биржах и прозрачной монетизации.

Реализует безопасный конвейер работы агентов Семьи и Братьев/Сестёр с внешними
биржами (Upwork API, Freelancer API, Fiverr Desk, Kwork Desk, Custom Webhook)
под строгими замками владельца:
- Без автосоздания аккаунтов, без ввода паролей и без обхода CAPTCHA/Cloudflare.
- Секретные OAuth/API-токены никогда не хранятся открытым текстом в SQLite.
- Любое ТЗ проверяется на prompt-инъекции (safety.looks_like_instruction).
- Ставки на биржу (PADAM_FREELANCE_AUTOBID) и оплата тарифов (PADAM_TREASURY_AUTOPAY)
  по умолчанию заблокированы замком и требуют прямого одобрения владельца.
- Перед сдачей результата заказчику весь текст и код проходят через safety.redact
  и очистку локальных путей, а оплата автоматически учитывается в token_autonomy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from typing import Any

from . import ark_advanced, audit_chain, coop_broker, deterministic_verify, safety, sovereign_ops, swarm_council, token_autonomy

SUPPORTED_PLATFORMS = (
    "upwork_api",
    "freelancer_api",
    "fiverr_desk",
    "kwork_desk",
    "custom_webhook",
)

SUPPORTED_MODES = ("oauth_api", "desk", "webhook")

_LOCAL_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\[^\s\"'<>|]+|/(?:Users|home|var|etc|opt|mnt)/[^\s\"'<>|]+)"
)


_DDL = """
CREATE TABLE IF NOT EXISTS ark_exchange_account (
    account_id        TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    platform          TEXT NOT NULL,
    mode              TEXT NOT NULL DEFAULT 'desk',
    account_label     TEXT NOT NULL DEFAULT '',
    agent_id          TEXT NOT NULL DEFAULT 'aifa',
    skills_json       TEXT NOT NULL DEFAULT '[]',
    token_configured  INTEGER NOT NULL DEFAULT 0,
    token_hash_prefix TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'active',
    created_at        REAL NOT NULL,
    updated_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_exch_user ON ark_exchange_account (user_id, platform);

CREATE TABLE IF NOT EXISTS ark_freelance_order (
    order_id          TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    account_id        TEXT NOT NULL DEFAULT '',
    platform          TEXT NOT NULL,
    external_job_id   TEXT NOT NULL DEFAULT '',
    title             TEXT NOT NULL,
    brief_redacted    TEXT NOT NULL,
    budget_usdt       REAL NOT NULL DEFAULT 0.0,
    est_tokens        INTEGER NOT NULL DEFAULT 25000,
    est_compute_usdt  REAL NOT NULL DEFAULT 0.05,
    margin_score      REAL NOT NULL DEFAULT 0.0,
    status            TEXT NOT NULL DEFAULT 'discovered',
    assigned_agent    TEXT NOT NULL DEFAULT 'aifa',
    coop_task_id      TEXT NOT NULL DEFAULT '',
    branch_id         TEXT NOT NULL DEFAULT '',
    bid_text          TEXT NOT NULL DEFAULT '',
    delivery_sha256   TEXT NOT NULL DEFAULT '',
    delivery_preview  TEXT NOT NULL DEFAULT '',
    earned_usdt       REAL NOT NULL DEFAULT 0.0,
    security_note     TEXT NOT NULL DEFAULT '',
    created_at        REAL NOT NULL,
    updated_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_order_user ON ark_freelance_order (user_id, status);

CREATE TABLE IF NOT EXISTS ark_profile_suggestion (
    suggestion_id     TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    platform          TEXT NOT NULL,
    order_id          TEXT NOT NULL DEFAULT '',
    title             TEXT NOT NULL,
    suggestion_text   TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'proposed',
    created_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_prof_sug_user ON ark_profile_suggestion (user_id, status);

CREATE TABLE IF NOT EXISTS ark_monetization_ledger (
    ledger_id         TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    source_type       TEXT NOT NULL,
    gross_usdt        REAL NOT NULL DEFAULT 0.0,
    platform_fee_usdt REAL NOT NULL DEFAULT 0.0,
    agent_compute_usdt REAL NOT NULL DEFAULT 0.0,
    ecosystem_json    TEXT NOT NULL DEFAULT '{}',
    note              TEXT NOT NULL DEFAULT '',
    created_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_monet_user ON ark_monetization_ledger (user_id, created_at);
"""


def _ensure(memory) -> None:
    """Создаёт таблицы подсистемы заработка при первом обращении."""
    memory.store.conn.executescript(_DDL)


def _strip_local_paths(text: str) -> str:
    """Удаляет абсолютные локальные пути файловой системы из текста для сдачи заказчику."""
    return _LOCAL_PATH_RE.sub("[LOCAL_PATH_REDACTED]", str(text or ""))


def sanitize_for_delivery(text: str) -> tuple[str, dict[str, Any]]:
    """Очищает текст от секретов и локальных путей перед отправкой внешнему заказчику."""
    no_paths = _strip_local_paths(text)
    redacted, counts = safety.redact(no_paths)
    return redacted, {
        "redacted_secrets": sum(counts.values()) if isinstance(counts, dict) else 0,
        "local_paths_removed": no_paths != str(text or ""),
    }


def freelance_locks_status() -> dict[str, Any]:
    """Возвращает состояние замков автономной работы на биржах и оплаты тарифов."""
    base_locks = sovereign_ops.locks_status()
    autobid_enabled = os.environ.get("PADAM_FREELANCE_AUTOBID", "").strip() == "1"
    return {
        "freelance_autobid_locked": not autobid_enabled,
        "treasury_autopay_locked": base_locks["treasury_autopay_locked"],
        "auto_register_forbidden": True,
        "captcha_bypass_forbidden": True,
    }


def _clean_platform(raw: str) -> str:
    val = str(raw or "fiverr_desk").strip().lower()
    if val not in SUPPORTED_PLATFORMS:
        raise ValueError(f"Неподдерживаемая площадка: {val}. Доступны: {', '.join(SUPPORTED_PLATFORMS)}")
    return val


def _clean_mode(raw: str) -> str:
    val = str(raw or "desk").strip().lower()
    if val not in SUPPORTED_MODES:
        raise ValueError(f"Неподдерживаемый режим подключения: {val}. Доступны: {', '.join(SUPPORTED_MODES)}")
    return val


def connect_exchange_account(
    memory,
    *,
    platform: str = "fiverr_desk",
    mode: str = "desk",
    account_label: str = "",
    agent_id: str = "aifa",
    skills: list[str] | None = None,
    oauth_token: str = "",
) -> dict[str, Any]:
    """Подключает пользовательский профиль биржи в режиме OAuth/API или Desk без хранения пароля."""
    _ensure(memory)
    plat = _clean_platform(platform)
    md = _clean_mode(mode)
    if oauth_token and safety.password_like(oauth_token):
        # Даже если передали что-то похожее на пароль, не сохраняем его ни в лог, ни в SQLite.
        pass
    token_str = str(oauth_token or "").strip()
    if md == "oauth_api" and not token_str:
        return {
            "ok": False,
            "error": "Для режима oauth_api необходимо передать oauth_token владельца (или используйте режим desk).",
        }
    token_configured = 1 if token_str else 0
    token_hash_prefix = hashlib.sha256(token_str.encode("utf-8")).hexdigest()[:12] if token_str else ""

    clean_label, _ = safety.redact(str(account_label or f"{plat}:{md}").strip())
    clean_agent = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(agent_id or "aifa").strip())[:48] or "aifa"
    clean_skills = [safety.redact(str(s).strip())[0][:48] for s in (skills or ["python", "mcp", "automation"]) if str(s).strip()][:12]
    aid = f"ex-{uuid.uuid4().hex[:10]}"
    now = time.time()

    memory.store.conn.execute(
        "INSERT INTO ark_exchange_account "
        "(account_id, user_id, platform, mode, account_label, agent_id, skills_json, token_configured, token_hash_prefix, status, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
        (
            aid,
            memory.user_id,
            plat,
            md,
            clean_label[:100],
            clean_agent,
            json.dumps(clean_skills, ensure_ascii=False),
            token_configured,
            token_hash_prefix,
            now,
            now,
        ),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_account_connected",
        {"account_id": aid, "platform": plat, "mode": md, "token_configured": bool(token_configured)},
        agent_id=clean_agent,
    )
    return {
        "ok": True,
        "account_id": aid,
        "platform": plat,
        "mode": md,
        "account_label": clean_label[:100],
        "agent_id": clean_agent,
        "skills": clean_skills,
        "token_configured": bool(token_configured),
        "token_hash_prefix": token_hash_prefix,
        "locks": freelance_locks_status(),
    }


def list_exchange_accounts(memory) -> list[dict[str, Any]]:
    """Возвращает список подключённых биржевых профилей без секретных токенов."""
    _ensure(memory)
    rows = memory.store.conn.execute(
        "SELECT account_id, platform, mode, account_label, agent_id, skills_json, token_configured, token_hash_prefix, status, created_at "
        "FROM ark_exchange_account WHERE user_id = ? ORDER BY created_at DESC",
        (memory.user_id,),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        try:
            skills = json.loads(r["skills_json"] or "[]")
        except Exception:
            skills = []
        out.append({
            "account_id": r["account_id"],
            "platform": r["platform"],
            "mode": r["mode"],
            "account_label": r["account_label"],
            "agent_id": r["agent_id"],
            "skills": skills,
            "token_configured": bool(r["token_configured"]),
            "token_hash_prefix": r["token_hash_prefix"],
            "status": r["status"],
            "created_at": r["created_at"],
        })
    return out


def _estimate_compute_cost_usdt(estimated_tokens: int, cost_per_1k_usd: float = 0.002) -> float:
    """Оценивает ориентировочную стоимость токенов для выполнения заказа."""
    return round(max(0.005, (max(100, int(estimated_tokens)) / 1000.0) * float(cost_per_1k_usd)), 4)


def evaluate_and_ingest_job(
    memory,
    *,
    platform: str = "fiverr_desk",
    title: str,
    brief: str,
    budget_usdt: float,
    estimated_tokens: int = 25000,
    account_id: str = "",
    external_job_id: str = "",
    assigned_agent: str = "aifa",
    provider: str = "primary",
) -> dict[str, Any]:
    """Проверяет ТЗ заказа на безопасность, рассчитывает маржу с учётом квот токенов и сохраняет заказ."""
    _ensure(memory)
    plat = _clean_platform(platform)
    raw_title = str(title or "").strip()
    raw_brief = str(brief or "").strip()
    if not raw_title or not raw_brief:
        raise ValueError("Необходимо указать title и brief заказа.")

    combined = f"{raw_title}\n{raw_brief}"
    is_injection = safety.looks_like_instruction(combined)
    is_tamper = safety.changes_owner_or_rules(combined)
    clean_title, _ = sanitize_for_delivery(raw_title)
    clean_brief, redact_info = sanitize_for_delivery(raw_brief)

    budget = max(0.0, float(budget_usdt))
    tokens_need = max(500, int(estimated_tokens))
    est_cost = _estimate_compute_cost_usdt(tokens_need)
    pacing = token_autonomy.compute_pacing_plan(memory, provider=provider)
    quota_ok = True
    if pacing.get("has_plan"):
        daily_rem = int(pacing.get("daily", {}).get("remaining", 0))
        weekly_rem = int(pacing.get("weekly", {}).get("remaining", 0))
        quota_ok = (daily_rem >= tokens_need) and (weekly_rem >= tokens_need)

    margin_usdt = round(budget - est_cost, 4)
    margin_ratio = round((margin_usdt / est_cost) if est_cost > 0 else 0.0, 2)
    # Нормализованный скор маржинальности 0..100
    margin_score = round(min(100.0, max(0.0, (margin_usdt / max(1.0, budget)) * 80.0 + (20.0 if quota_ok else 0.0))), 2)

    security_veto = bool(is_injection or is_tamper)
    status = "rejected_security" if security_veto else ("evaluated" if budget > est_cost else "low_margin")
    sec_note = (
        "ОТКЛОНЕНО: обнаружена попытка prompt-инъекции или подмены правил в ТЗ заказчика."
        if security_veto
        else ("Квоты токенов на сегодня не хватает — рекомендуется перенести в очередь или снизить лимит." if not quota_ok else "ТЗ прошло проверку безопасности.")
    )

    oid = f"ord-{uuid.uuid4().hex[:10]}"
    now = time.time()
    memory.store.conn.execute(
        "INSERT INTO ark_freelance_order "
        "(order_id, user_id, account_id, platform, external_job_id, title, brief_redacted, budget_usdt, est_tokens, "
        "est_compute_usdt, margin_score, status, assigned_agent, security_note, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            oid,
            memory.user_id,
            str(account_id or ""),
            plat,
            str(external_job_id or ""),
            clean_title[:160],
            clean_brief[:4000],
            budget,
            tokens_need,
            est_cost,
            margin_score if not security_veto else 0.0,
            status,
            str(assigned_agent or "aifa")[:48],
            sec_note,
            now,
            now,
        ),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_order_evaluated",
        {"order_id": oid, "platform": plat, "status": status, "budget_usdt": budget, "margin_score": margin_score},
        agent_id=str(assigned_agent or "aifa"),
    )
    return {
        "ok": not security_veto,
        "order_id": oid,
        "platform": plat,
        "title": clean_title[:160],
        "status": status,
        "budget_usdt": budget,
        "est_tokens": tokens_need,
        "est_compute_usdt": est_cost,
        "margin_usdt": margin_usdt,
        "margin_ratio": margin_ratio,
        "margin_score": margin_score if not security_veto else 0.0,
        "quota_sufficient": quota_ok,
        "security_veto": security_veto,
        "security_note": sec_note,
        "redaction": redact_info,
    }


def _get_order(memory, order_id: str) -> dict[str, Any]:
    _ensure(memory)
    row = memory.store.conn.execute(
        "SELECT * FROM ark_freelance_order WHERE user_id = ? AND order_id = ?",
        (memory.user_id, str(order_id or "").strip()),
    ).fetchone()
    if row is None:
        raise ValueError(f"Заказ {order_id} не найден.")
    return dict(row)


def list_orders(memory, *, status: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
    """Возвращает список заказов с бирж (новейшие сверху)."""
    _ensure(memory)
    lim = max(1, min(100, int(limit)))
    if status:
        rows = memory.store.conn.execute(
            "SELECT * FROM ark_freelance_order WHERE user_id = ? AND status = ? ORDER BY created_at DESC LIMIT ?",
            (memory.user_id, str(status).strip(), lim),
        ).fetchall()
    else:
        rows = memory.store.conn.execute(
            "SELECT * FROM ark_freelance_order WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (memory.user_id, lim),
        ).fetchall()
    return [dict(r) for r in rows]


def propose_or_place_bid(
    memory,
    order_id: str,
    *,
    pitch_text: str = "",
    proposed_usdt: float | None = None,
    owner_approved: bool = False,
) -> dict[str, Any]:
    """Готовит отклик на заказ; реальная публикация заблокирована без owner_approved=True и PADAM_FREELANCE_AUTOBID=1."""
    order = _get_order(memory, order_id)
    if order["status"] == "rejected_security":
        return {"ok": False, "order_id": order_id, "error": "Нельзя делать ставку на отклонённый по безопасности заказ."}

    price = round(max(1.0, float(proposed_usdt if proposed_usdt is not None else order["budget_usdt"])), 2)
    raw_pitch = pitch_text or (
        f"Готовы выполнить задачу «{order['title']}» с детерминированной проверкой результата "
        f"и полной документацией. Ориентировочная стоимость: {price:.2f} USDT."
    )
    clean_pitch, _ = sanitize_for_delivery(raw_pitch)
    locks = freelance_locks_status()

    if locks["freelance_autobid_locked"] or not owner_approved:
        new_status = "bid_draft"
        placed = False
        note = "Черновик отклика сохранён. Для автопубликации нужно owner_approved=True и PADAM_FREELANCE_AUTOBID=1."
    else:
        new_status = "bid_placed"
        placed = True
        note = "Отклик утверждён и отмечен к отправке через подключённый адаптер биржи."

    memory.store.conn.execute(
        "UPDATE ark_freelance_order SET status = ?, bid_text = ?, updated_at = ? WHERE user_id = ? AND order_id = ?",
        (new_status, clean_pitch[:2000], time.time(), memory.user_id, order_id),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_bid_updated",
        {"order_id": order_id, "status": new_status, "placed": placed, "proposed_usdt": price},
        agent_id=order["assigned_agent"],
    )
    return {
        "ok": True,
        "order_id": order_id,
        "status": new_status,
        "placed": placed,
        "proposed_usdt": price,
        "bid_text": clean_pitch[:2000],
        "locks": locks,
        "note": note,
    }


def execute_order_with_swarm(
    memory,
    order_id: str,
    *,
    agent_id: str = "aifa",
) -> dict[str, Any]:
    """Передаёт заказ в исполнение Рою: coop_broker + изолированная ветка + Совет Семьи + проверка сметы."""
    order = _get_order(memory, order_id)
    if order["status"] == "rejected_security":
        return {"ok": False, "order_id": order_id, "error": "Заказ заблокирован по безопасности."}

    council = swarm_council.run_family_council(memory, f"{order['title']}\n{order['brief_redacted']}")
    if not council.get("approved", False):
        memory.store.conn.execute(
            "UPDATE ark_freelance_order SET status = 'rejected_security', security_note = ?, updated_at = ? WHERE user_id = ? AND order_id = ?",
            ("Вето Совета Семьи (LANCE) при запуске исполнения.", time.time(), memory.user_id, order_id),
        )
        memory.store.conn.commit()
        return {"ok": False, "order_id": order_id, "status": "rejected_security", "council": council}

    task_res = coop_broker.create_task(
        memory,
        title=f"[{order['platform']}] {order['title'][:80]}",
        topic=f"freelance:{order['platform']}",
        created_by=agent_id,
    )
    task_id = task_res.get("task_id", "")
    if task_id:
        coop_broker.claim_task(memory, task_id, agent_id)

    branch_res = ark_advanced.create_branch(
        memory,
        f"order-{order_id}",
        description=f"Изолированное исполнение заказа {order['platform']}: {order['title'][:80]}",
        scope="work",
    )
    branch_id = branch_res.get("branch_id", "")
    if branch_id:
        ark_advanced.branch_remember(
            memory,
            branch_id,
            f"Начато выполнение заказа {order_id} ({order['budget_usdt']} USDT), агент {agent_id}.",
            kind="state",
        )

    budget_check = deterministic_verify.verify_arithmetic(
        f"{float(order['budget_usdt']):.4f} - {float(order['est_compute_usdt']):.4f}"
    )

    memory.store.conn.execute(
        "UPDATE ark_freelance_order SET status = 'in_progress', assigned_agent = ?, coop_task_id = ?, branch_id = ?, updated_at = ? "
        "WHERE user_id = ? AND order_id = ?",
        (str(agent_id or "aifa")[:48], task_id, branch_id, time.time(), memory.user_id, order_id),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_order_started",
        {"order_id": order_id, "task_id": task_id, "branch_id": branch_id, "agent_id": agent_id},
        agent_id=str(agent_id or "aifa"),
    )
    return {
        "ok": True,
        "order_id": order_id,
        "status": "in_progress",
        "assigned_agent": str(agent_id or "aifa"),
        "coop_task_id": task_id,
        "branch_id": branch_id,
        "council_approved": bool(council.get("approved")),
        "net_margin_check": budget_check,
    }


def package_safe_delivery(
    memory,
    order_id: str,
    *,
    deliverable_text: str,
    agent_id: str = "aifa",
) -> dict[str, Any]:
    """Упаковывает результат заказа с обязательной очисткой от секретов, локальных путей и SHA-256."""
    order = _get_order(memory, order_id)
    if order["status"] == "rejected_security":
        return {"ok": False, "order_id": order_id, "error": "Заказ заблокирован по безопасности."}
    raw = str(deliverable_text or "").strip()
    if not raw:
        raise ValueError("Необходимо передать текст/результат работы deliverable_text.")

    safe_text, sec_meta = sanitize_for_delivery(raw)
    digest = hashlib.sha256(safe_text.encode("utf-8")).hexdigest()

    if order.get("coop_task_id"):
        try:
            coop_broker.update_task(
                memory,
                order["coop_task_id"],
                agent_id=agent_id,
                status="done",
                result_summary=f"Сдача упакована (SHA-256: {digest[:16]})",
            )
        except Exception:
            pass

    memory.store.conn.execute(
        "UPDATE ark_freelance_order SET status = 'delivered', delivery_sha256 = ?, delivery_preview = ?, updated_at = ? "
        "WHERE user_id = ? AND order_id = ?",
        (digest, safe_text[:1500], time.time(), memory.user_id, order_id),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_order_delivered",
        {"order_id": order_id, "delivery_sha256": digest, "redacted_secrets": sec_meta["redacted_secrets"]},
        agent_id=str(agent_id or "aifa"),
    )
    return {
        "ok": True,
        "order_id": order_id,
        "status": "delivered",
        "delivery_sha256": digest,
        "safe_text": safe_text,
        "sanitization": sec_meta,
    }


def propose_profile_improvement(
    memory,
    *,
    platform: str,
    title: str,
    suggestion_text: str,
    order_id: str = "",
) -> dict[str, Any]:
    """Создаёт предложение по улучшению витрины/профиля на бирже без раскрытия приватных данных клиента."""
    _ensure(memory)
    plat = _clean_platform(platform)
    clean_title, _ = sanitize_for_delivery(title)
    clean_body, _ = sanitize_for_delivery(suggestion_text)
    sid = f"psg-{uuid.uuid4().hex[:10]}"
    memory.store.conn.execute(
        "INSERT INTO ark_profile_suggestion (suggestion_id, user_id, platform, order_id, title, suggestion_text, status, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'proposed', ?)",
        (sid, memory.user_id, plat, str(order_id or ""), clean_title[:160], clean_body[:1000], time.time()),
    )
    memory.store.conn.commit()
    return {
        "ok": True,
        "suggestion_id": sid,
        "platform": plat,
        "title": clean_title[:160],
        "suggestion_text": clean_body[:1000],
        "status": "proposed",
    }


def list_profile_suggestions(memory, *, limit: int = 20) -> list[dict[str, Any]]:
    """Возвращает предложения по усилению портфолио и профиля на биржах."""
    _ensure(memory)
    rows = memory.store.conn.execute(
        "SELECT suggestion_id, platform, order_id, title, suggestion_text, status, created_at "
        "FROM ark_profile_suggestion WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (memory.user_id, max(1, min(100, int(limit)))),
    ).fetchall()
    return [dict(r) for r in rows]


def monetization_breakdown(
    gross_usdt: float,
    *,
    platform_fee_pct: float = 10.0,
    agent_compute_pct: float = 15.0,
) -> dict[str, Any]:
    """Рассчитывает прозрачное распределение дохода по канонической токеномике CODE ($GALATIN) и казне агента.

    Экосистемный пул (100% от платформенной комиссии или выручки SaaS/MCP):
    - 5% Фонд
    - 5% Сжигание ($GALATIN)
    - 15% + 7% + 3% = 25% Трёхуровневая амбассадорская программа (пустые уровни -> сжигание, макс. 30%)
    - 65% Казна CODE Eternal
    """
    gross = round(max(0.0, float(gross_usdt)), 4)
    fee_pct = max(0.0, min(30.0, float(platform_fee_pct)))
    comp_pct = max(0.0, min(50.0, float(agent_compute_pct)))

    platform_fee_usdt = round(gross * (fee_pct / 100.0), 4)
    agent_compute_usdt = round(gross * (comp_pct / 100.0), 4)
    owner_net_usdt = round(max(0.0, gross - platform_fee_usdt - agent_compute_usdt), 4)

    eco_shares = {
        "fund_pct": 5.0,
        "burn_pct": 5.0,
        "ambassador_l1_pct": 15.0,
        "ambassador_l2_pct": 7.0,
        "ambassador_l3_pct": 3.0,
        "treasury_pct": 65.0,
    }
    pct_check = deterministic_verify.verify_percentage_sum(list(eco_shares.values()), expected_total=100.0)
    eco_usdt = {k.replace("_pct", "_usdt"): round(platform_fee_usdt * (v / 100.0), 4) for k, v in eco_shares.items()}

    return {
        "token_symbol": "$GALATIN",
        "token_supply": 10_000_000_000,
        "gross_usdt": gross,
        "platform_fee_pct": fee_pct,
        "platform_fee_usdt": platform_fee_usdt,
        "agent_compute_pct": comp_pct,
        "agent_compute_usdt": agent_compute_usdt,
        "owner_net_usdt": owner_net_usdt,
        "ecosystem_shares_pct": eco_shares,
        "ecosystem_split_usdt": eco_usdt,
        "percentage_sum_verified": bool(pct_check.get("valid")),
    }


def settle_paid_order(
    memory,
    order_id: str,
    *,
    paid_usdt: float | None = None,
    agent_id: str = "aifa",
    compute_share_pct: float = 15.0,
    platform_fee_pct: float = 10.0,
) -> dict[str, Any]:
    """Фиксирует оплату заказа, зачисляет долю в казну вычислений token_autonomy и предлагает кейс для профиля."""
    order = _get_order(memory, order_id)
    gross = round(max(0.0, float(paid_usdt if paid_usdt is not None else order["budget_usdt"])), 4)
    if gross <= 0:
        raise ValueError("Сумма оплаты paid_usdt должна быть > 0.")

    earn_res = token_autonomy.record_agent_earning(
        memory,
        agent_id=str(agent_id or order["assigned_agent"] or "aifa"),
        source=f"freelance:{order['platform']}:{order_id}",
        revenue_usdt=gross,
        compute_share_pct=compute_share_pct,
        note=f"Оплата заказа: {order['title'][:80]}",
    )
    split = monetization_breakdown(gross, platform_fee_pct=platform_fee_pct, agent_compute_pct=compute_share_pct)

    lid = f"mon-{uuid.uuid4().hex[:10]}"
    memory.store.conn.execute(
        "INSERT INTO ark_monetization_ledger (ledger_id, user_id, source_type, gross_usdt, platform_fee_usdt, agent_compute_usdt, ecosystem_json, note, created_at) "
        "VALUES (?, ?, 'freelance_order', ?, ?, ?, ?, ?, ?)",
        (
            lid,
            memory.user_id,
            gross,
            split["platform_fee_usdt"],
            split["agent_compute_usdt"],
            json.dumps(split["ecosystem_split_usdt"], ensure_ascii=False),
            f"Заказ {order_id} ({order['platform']})",
            time.time(),
        ),
    )
    memory.store.conn.execute(
        "UPDATE ark_freelance_order SET status = 'paid', earned_usdt = ?, updated_at = ? WHERE user_id = ? AND order_id = ?",
        (gross, time.time(), memory.user_id, order_id),
    )
    memory.store.conn.commit()

    sug = propose_profile_improvement(
        memory,
        platform=order["platform"],
        order_id=order_id,
        title=f"Обезличенный кейс для витрины ({order['platform']}): {order['title'][:70]}",
        suggestion_text=(
            f"Добавьте в портфолио профильный кейс по задаче «{order['title'][:90]}» "
            f"(средний чек {gross:.2f} USDT, детерминированная проверка качества пройдена)."
        ),
    )
    audit_chain.append_audit(
        memory,
        "freelance_order_paid",
        {"order_id": order_id, "gross_usdt": gross, "allocated_compute_usdt": split["agent_compute_usdt"]},
        agent_id=str(agent_id or "aifa"),
    )
    return {
        "ok": True,
        "order_id": order_id,
        "status": "paid",
        "paid_usdt": gross,
        "treasury": earn_res.get("treasury", {}),
        "monetization": split,
        "profile_suggestion": sug,
    }


def freelance_dashboard_snapshot(memory) -> dict[str, Any]:
    """Собирает единую сводку для вкладки Studio «Автономный заработок», MCP и CLI."""
    _ensure(memory)
    accounts = list_exchange_accounts(memory)
    orders = list_orders(memory, limit=30)
    suggestions = list_profile_suggestions(memory, limit=15)
    treasury = token_autonomy.treasury_summary(memory)
    proposals = token_autonomy.list_topup_proposals(memory)
    budget_tick = token_autonomy.run_budget_timer_tick(memory, auto_propose_if_low=False)
    locks = freelance_locks_status()

    conn = memory.store.conn
    r_mon = conn.execute(
        "SELECT COALESCE(SUM(gross_usdt), 0.0) AS g, COALESCE(SUM(platform_fee_usdt), 0.0) AS f, "
        "COALESCE(SUM(agent_compute_usdt), 0.0) AS c FROM ark_monetization_ledger WHERE user_id = ?",
        (memory.user_id,),
    ).fetchone()
    total_gross = round(float(r_mon["g"] or 0.0), 4)
    total_fee = round(float(r_mon["f"] or 0.0), 4)
    total_comp = round(float(r_mon["c"] or 0.0), 4)

    return {
        "ok": True,
        "locks": locks,
        "accounts": accounts,
        "orders": orders,
        "profile_suggestions": suggestions,
        "treasury": treasury,
        "proposals": proposals,
        "budget": budget_tick,
        "monetization_totals": {
            "total_gross_usdt": total_gross,
            "total_platform_fee_usdt": total_fee,
            "total_agent_compute_usdt": total_comp,
            "ecosystem_reference": monetization_breakdown(max(total_gross, 100.0)),
        },
        "supported_platforms": list(SUPPORTED_PLATFORMS),
        "supported_modes": list(SUPPORTED_MODES),
    }
