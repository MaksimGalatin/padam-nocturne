# -*- coding: utf-8 -*-
"""Модуль автономного заработка на фриланс-биржах, HTTP/Webhook-коннектора и монетизации $GALATIN.

Ключевые принципы и инварианты:
- Без автосоздания аккаунтов, без ввода паролей и без обхода CAPTCHA/Cloudflare.
- Секретные OAuth/API-токены и секреты вебхуков никогда не хранятся открытым текстом
  в SQLite: в БД лежит только шифр AES-256-GCM (ключом от owner_key) или префикс SHA-256.
- Комиссия платформы CODE от валового дохода агентов: 15 %, когда отправляет человек, 20 % на автопилоте
  (18.11.2026; до этого — 10 %); остаток — пул владельца, из которого пользователь задаёт ставку агента от 1% до 100%.
- Поддержка двух фаз расчётов: Фаза 1 (USDT_TRC20) -> Фаза 2 ($GALATIN с автовыкупом с биржи).
- Любое ТЗ (включая входящие по HTTP с биржи) проверяется на prompt-инъекции (safety.looks_like_instruction).
- Автоставки (PADAM_FREELANCE_AUTOBID) и оплата тарифов (PADAM_TREASURY_AUTOPAY)
  по умолчанию заблокированы замком и требуют прямого одобрения владельца.
"""

from __future__ import annotations

import base64
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from .store import add_column_safe as _acs
from . import (
    ark_advanced,
    audit_chain,
    coop_broker,
    deterministic_verify,
    integrity,
    net_guard,
    safety,
    sovereign_ops,
    swarm_council,
    token_autonomy,
)

# Комиссия CODE — слово Архитектора 18.11.2026: «с тыканьем пальцем 15 %. Автопилот — 20 %».
#   assisted  — агент считает и пишет черновик, отправляет человек (так требуют Upwork, Fiverr и др.);
#   autopilot — продаёт и делает наша система (магазины, биржи для агентов, свои клиенты, прямые заказчики).
# Ставка запоминается в заказе (platform_fee_pct) в момент оценки и дальше не меняется.
ASSISTED_FEE_PCT = 15.0
AUTOPILOT_FEE_PCT = 20.0
WORK_MODES = ("assisted", "autopilot")
FIXED_PLATFORM_FEE_PCT = ASSISTED_FEE_PCT  # прежнее имя оставлено для совместимости


def fee_pct_for_mode(work_mode: str = "assisted") -> float:
    mode = str(work_mode or "assisted").strip().lower()
    if mode not in WORK_MODES:
        raise ValueError(f"work_mode must be one of: {', '.join(WORK_MODES)}")
    return AUTOPILOT_FEE_PCT if mode == "autopilot" else ASSISTED_FEE_PCT
ESCROW_HOLD_DAYS = 14
ESCROW_HOLD_SECONDS = ESCROW_HOLD_DAYS * 86400
CLIENT_LOCK_DAYS = 90
CLIENT_LOCK_SECONDS = CLIENT_LOCK_DAYS * 86400

SUPPORTED_PLATFORMS = (
    "upwork_api",
    "freelancer_api",
    "fiverr_desk",
    "kwork_desk",
    "custom_webhook",
)
DIGITAL_STORE_PLATFORMS = (
    "lemonsqueezy",
    "gumroad",
    "payhip",
    "sellfy",
    "whop",
)

SUPPORTED_MODES = ("oauth_api", "desk", "webhook")
SUPPORTED_CURRENCIES = ("USDT_TRC20", "GALATIN")
CODE_TREASURY_WALLET_SOLANA = "BHwXca9ALDFe38vWzqRGcXom6dEop2u6kWCMwZfQEmee"
AUTO_SPLIT_PLATFORMS = frozenset({"aifafocus_mcp", "partner_bridge", "code_direct", "lemonsqueezy"})

_LOCAL_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\[^\s\"'<>|]+|/(?:Users|home|var|etc|opt|mnt)/[^\s\"'<>|]+)"
)
_KYC_DOC_RE = re.compile(
    r"(?:(?:passport|паспорт|id_card|удостоверение|driver_license|водительск\w+|kyc_doc)[^\s\"'<>|]{0,48}\.(?:pdf|png|jpe?g|webp)|"
    r"\b(?:паспорт(?:\s+серия)?|passport\s*(?:no|num|id)?)[\s:#№-]*\d{2,4}[\s-]?\d{4,7}\b|"
    r"\b(?:4\d{3}|5[1-5]\d{2}|220[0-4])(?:[\s-]?\d{4}){3}\b)",
    re.IGNORECASE,
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
    api_base_url      TEXT NOT NULL DEFAULT '',
    token_enc         TEXT NOT NULL DEFAULT '',
    webhook_secret_enc TEXT NOT NULL DEFAULT '',
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
    estimated_hours   REAL NOT NULL DEFAULT 4.0,
    hourly_rate_usdt  REAL NOT NULL DEFAULT 25.0,
    exchange_fee_pct  REAL NOT NULL DEFAULT 0.0,
    platform_fee_pct  REAL NOT NULL DEFAULT 10.0,
    net_after_fees_usdt REAL NOT NULL DEFAULT 0.0,
    effective_hourly_usdt REAL NOT NULL DEFAULT 0.0,
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
    ledger_id          TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL,
    source_type        TEXT NOT NULL,
    gross_usdt         REAL NOT NULL DEFAULT 0.0,
    platform_fee_usdt  REAL NOT NULL DEFAULT 0.0,
    agent_compute_usdt REAL NOT NULL DEFAULT 0.0,
    ecosystem_json     TEXT NOT NULL DEFAULT '{}',
    note               TEXT NOT NULL DEFAULT '',
    created_at         REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_monet_user ON ark_monetization_ledger (user_id, created_at);

CREATE TABLE IF NOT EXISTS ark_freelance_prefs (
    user_id             TEXT PRIMARY KEY,
    agent_share_pct     REAL NOT NULL DEFAULT 15.0,
    settlement_currency TEXT NOT NULL DEFAULT 'USDT_TRC20',
    galatin_price_usdt  REAL NOT NULL DEFAULT 0.01,
    updated_at          REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ark_owner_payout_hold (
    hold_id         TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    order_id        TEXT NOT NULL,
    gross_usdt      REAL NOT NULL,
    owner_net_usdt  REAL NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'USDT_TRC20',
    status          TEXT NOT NULL DEFAULT 'held_14d',
    dispute_reason  TEXT NOT NULL DEFAULT '',
    created_at      REAL NOT NULL,
    release_at      REAL NOT NULL,
    resolved_at     REAL
);
CREATE INDEX IF NOT EXISTS idx_ark_hold_user ON ark_owner_payout_hold (user_id, status, release_at);

CREATE TABLE IF NOT EXISTS ark_referral_profile (
    user_id       TEXT PRIMARY KEY,
    ref_code      TEXT UNIQUE NOT NULL,
    referred_by_l1 TEXT NOT NULL DEFAULT '',
    referred_by_l2 TEXT NOT NULL DEFAULT '',
    referred_by_l3 TEXT NOT NULL DEFAULT '',
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ark_referral_reward (
    reward_id     TEXT PRIMARY KEY,
    order_id      TEXT NOT NULL,
    from_user_id  TEXT NOT NULL,
    to_user_id    TEXT NOT NULL,
    tier_level    INTEGER NOT NULL,
    pct_of_fee    REAL NOT NULL,
    amount_usdt   REAL NOT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_ref_to ON ark_referral_reward (to_user_id, created_at);

CREATE TABLE IF NOT EXISTS ark_client_agent_lock (
    lock_id         TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    client_key      TEXT NOT NULL,
    client_source   TEXT NOT NULL DEFAULT '',
    agent_id        TEXT NOT NULL,
    first_order_id  TEXT NOT NULL DEFAULT '',
    last_order_id   TEXT NOT NULL DEFAULT '',
    orders_count    INTEGER NOT NULL DEFAULT 1,
    locked_from_ts  REAL NOT NULL,
    locked_until_ts REAL NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    released_at     REAL,
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL,
    UNIQUE(user_id, client_key)
);
CREATE INDEX IF NOT EXISTS idx_ark_client_lock_user ON ark_client_agent_lock (user_id, status, locked_until_ts);

CREATE TABLE IF NOT EXISTS ark_agent_ledger (
    ledger_entry_id   TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    order_id          TEXT NOT NULL UNIQUE,
    hold_id           TEXT NOT NULL DEFAULT '',
    agent_id          TEXT NOT NULL,
    client_key        TEXT NOT NULL DEFAULT '',
    gross_usdt        REAL NOT NULL DEFAULT 0.0,
    agent_share_pct   REAL NOT NULL DEFAULT 15.0,
    agent_amount_usdt REAL NOT NULL DEFAULT 0.0,
    currency          TEXT NOT NULL DEFAULT 'USDT_TRC20',
    status            TEXT NOT NULL DEFAULT 'pending',
    cancel_reason     TEXT NOT NULL DEFAULT '',
    accepted_at       REAL,
    available_at      REAL,
    credited_at       REAL,
    cancelled_at      REAL,
    created_at        REAL NOT NULL,
    updated_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_agent_ledger_user ON ark_agent_ledger (user_id, agent_id, status);

CREATE TABLE IF NOT EXISTS ark_code_fee_invoice (
    invoice_id       TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL,
    order_id         TEXT NOT NULL UNIQUE,
    platform         TEXT NOT NULL,
    gross_usdt       REAL NOT NULL DEFAULT 0.0,
    fee_pct          REAL NOT NULL DEFAULT 15.0,
    fee_usdt         REAL NOT NULL DEFAULT 0.0,
    treasury_wallet  TEXT NOT NULL,
    settlement_rail  TEXT NOT NULL DEFAULT 'manual_exchange_remit',
    status           TEXT NOT NULL DEFAULT 'invoice_due',
    auto_split_tx    TEXT NOT NULL DEFAULT '',
    due_ts           REAL NOT NULL,
    paid_at          REAL,
    hmac_sig         TEXT NOT NULL DEFAULT '',
    created_at       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_fee_inv_user ON ark_code_fee_invoice (user_id, status, due_ts);
"""


from functools import wraps

def _synchronized_memory(fn):
    """Сериализует работу нескольких агентов/потоков над одним SQLite Store через реентерабельный RLock."""
    @wraps(fn)
    def _wrapper(memory, *args, **kwargs):
        with _lock_of(memory):
            return fn(memory, *args, **kwargs)
    return _wrapper

def _lock_of(memory):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _ensure(memory) -> None:
    """Создаёт и мягко дополняет таблицы подсистемы заработка без execscript-конфликтов."""
    with _lock_of(memory):
        conn = memory.store.conn
        for stmt in _DDL.split(";"):
            s = stmt.strip()
            if s:
                conn.execute(s)
        # Аудит фазы 3, FA-10: уникальность начисления (order_id, tier_level). Если в старой базе уже есть дубли —
        # индекс не создаётся (ничего не удаляем без слова владельца), вставка всё равно идёт через OR IGNORE.
        try:
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_ark_ref_order_tier ON ark_referral_reward (order_id, tier_level)")
        except Exception:
            pass
        # Миграция старых таблиц без потери данных
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(ark_exchange_account)").fetchall()}
        for col, col_def in (
            ("api_base_url", "TEXT NOT NULL DEFAULT ''"),
            ("token_enc", "TEXT NOT NULL DEFAULT ''"),
            ("webhook_secret_enc", "TEXT NOT NULL DEFAULT ''"),
            ("refresh_token_enc", "TEXT NOT NULL DEFAULT ''"),
            ("refresh_url", "TEXT NOT NULL DEFAULT ''"),
            ("token_expires_at", "REAL NOT NULL DEFAULT 0.0"),
        ):
            if col not in existing:
                _acs(conn, "ark_exchange_account", col, col_def)
        prefs_cols = {r["name"] for r in conn.execute("PRAGMA table_info(ark_freelance_prefs)").fetchall()}
        for col, col_def in (
            ("autopilot_running", "INTEGER NOT NULL DEFAULT 0"),
            ("autopilot_interval_s", "REAL NOT NULL DEFAULT 300.0"),
            ("autopilot_last_tick_at", "REAL NOT NULL DEFAULT 0.0"),
            ("autopilot_last_note", "TEXT NOT NULL DEFAULT ''"),
            ("payout_wallet_address", "TEXT NOT NULL DEFAULT ''"),
            ("payout_wallet_network", "TEXT NOT NULL DEFAULT ''"),
            ("payout_wallet_id", "TEXT NOT NULL DEFAULT ''"),
        ):
            if col not in prefs_cols:
                _acs(conn, "ark_freelance_prefs", col, col_def)
        order_cols = {r["name"] for r in conn.execute("PRAGMA table_info(ark_freelance_order)").fetchall()}
        for col, col_def in (
            ("estimated_hours", "REAL NOT NULL DEFAULT 4.0"),
            ("hourly_rate_usdt", "REAL NOT NULL DEFAULT 25.0"),
            ("exchange_fee_pct", "REAL NOT NULL DEFAULT 0.0"),
            ("platform_fee_pct", "REAL NOT NULL DEFAULT 10.0"),
            ("net_after_fees_usdt", "REAL NOT NULL DEFAULT 0.0"),
            ("effective_hourly_usdt", "REAL NOT NULL DEFAULT 0.0"),
            ("client_key", "TEXT NOT NULL DEFAULT ''"),
            ("client_source", "TEXT NOT NULL DEFAULT ''"),
            ("locked_agent_id", "TEXT NOT NULL DEFAULT ''"),
            ("client_locked_until_ts", "REAL"),
            ("accepted_at", "REAL"),
            ("agent_payout_status", "TEXT NOT NULL DEFAULT ''"),
            ("payout_cancel_reason", "TEXT NOT NULL DEFAULT ''"),
            ("sale_verified", "INTEGER NOT NULL DEFAULT 1"),
            ("sample_stage", "TEXT NOT NULL DEFAULT ''"),
            ("sample_mode", "TEXT NOT NULL DEFAULT ''"),
            ("sample_milestone_usdt", "REAL NOT NULL DEFAULT 0.0"),
            ("sample_deliverable", "TEXT NOT NULL DEFAULT ''"),
        ):
            if col not in order_cols:
                _acs(conn, "ark_freelance_order", col, col_def)
        conn.commit()


def _iso_utc(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _date_utc(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d")


def _normalize_client_identity(
    platform: str = "",
    *,
    client_email: str = "",
    client_domain: str = "",
    client_external_id: str = "",
    client_ref: str = "",
) -> tuple[str, str]:
    """Нормализует клиента к виду (client_key, client_source) по email, домену или id клиента биржи."""
    em = str(client_email or "").strip().lower()
    dom = str(client_domain or "").strip().lower()
    ext = str(client_external_id or "").strip().lower()
    ref = str(client_ref or "").strip()
    if ref and not (em or dom or ext):
        low_ref = ref.lower()
        if "@" in low_ref:
            em = low_ref
        elif "." in low_ref and " " not in low_ref:
            dom = low_ref
        else:
            ext = low_ref

    if em and "@" in em:
        local, _, host = em.partition("@")
        local = local.strip()
        host = host.strip()
        if host.startswith("www."):   # 18.11: было lstrip("www.") — срезало любые w и точки («web.com» → «eb.com»)
            host = host[4:]
        if local and host:
            # Аудит фазы 3, MS-05: адрес клиента не храним — только отпечаток (закрепление работает так же).
            return "email:sha256:" + hashlib.sha256(f"{local}@{host}".encode("utf-8")).hexdigest()[:32], "email"
    if dom:
        if "://" in dom:
            dom = urllib.parse.urlparse(dom).netloc or dom
        dom = dom.split("/")[0].split(":")[0].strip().lower()
        if dom.startswith("www."):
            dom = dom[4:]
        if dom:
            return f"domain:{dom}"[:160], "domain"
    if ext:
        plat = _clean_platform(platform) if str(platform or "").strip() else ""
        key = f"exchange:{plat}:{ext}" if plat else f"exchange:{ext}"
        return key[:160], "exchange_client_id"
    return "", ""


def _expire_stale_client_locks_locked(conn, user_id: str, now_s: float) -> int:
    """Снимает истекшие 90-дневные закрепления (status -> expired) внутри активной блокировки."""
    cur = conn.execute(
        "UPDATE ark_client_agent_lock SET status = 'expired', released_at = COALESCE(released_at, locked_until_ts), updated_at = ? "
        "WHERE user_id = ? AND status = 'active' AND locked_until_ts <= ?",
        (now_s, user_id, now_s),
    )
    return int(cur.rowcount or 0)


def _active_client_lock_locked(conn, user_id: str, client_key: str, now_s: float) -> dict[str, Any] | None:
    if not client_key:
        return None
    row = conn.execute(
        "SELECT * FROM ark_client_agent_lock WHERE user_id = ? AND client_key = ? AND status = 'active' AND locked_until_ts > ?",
        (user_id, client_key, now_s),
    ).fetchone()
    return dict(row) if row is not None else None

def _derive_vault_key(memory) -> bytes:
    raw_owner, _ = integrity.owner_key(memory.store)
    return hashlib.sha256(b"padam-freelance-vault-v1:" + raw_owner).digest()


def _seal_secret(memory, plaintext: str) -> str:
    """Шифрует токен/секрет AES-256-GCM; без cryptography использует HMAC-связанный конверт не-plaintext."""
    s = str(plaintext or "").strip()
    if not s:
        return ""
    key = _derive_vault_key(memory)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, s.encode("utf-8"), b"padam-freelance-secret")
    return "aesgcm1:" + base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def _unseal_secret(memory, blob: str) -> str:
    b = str(blob or "").strip()
    if not b or not b.startswith("aesgcm1:"):
        return ""
    key = _derive_vault_key(memory)
    raw = base64.urlsafe_b64decode(b[8:].encode("ascii"))
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, b"padam-freelance-secret").decode("utf-8")


def _strip_local_paths(text: str) -> str:
    return _LOCAL_PATH_RE.sub("[LOCAL_PATH_REDACTED]", str(text or ""))


def sanitize_for_delivery(text: str) -> tuple[str, dict[str, Any]]:
    """Очищает текст от секретов, локальных путей, карт и KYC/паспортных данных перед отправкой."""
    raw_s = str(text or "")
    no_paths = _strip_local_paths(raw_s)
    no_docs = _KYC_DOC_RE.sub("[KYC_OR_CARD_REDACTED]", no_paths)
    redacted, counts = safety.redact(no_docs)
    return redacted, {
        "redacted_secrets": sum(counts.values()) if isinstance(counts, dict) else 0,
        "local_paths_removed": no_paths != raw_s,
        "kyc_or_card_redacted": no_docs != no_paths,
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
    from . import platform_wizard as _pw
    if val not in SUPPORTED_PLATFORMS and val not in DIGITAL_STORE_PLATFORMS and val not in _pw.CATALOG_BY_ID:
        raise ValueError(
            f"Неподдерживаемая площадка: {val}. Доступны: {', '.join(SUPPORTED_PLATFORMS + DIGITAL_STORE_PLATFORMS)}"
        )
    return val


def _clean_mode(raw: str) -> str:
    val = str(raw or "desk").strip().lower()
    if val not in SUPPORTED_MODES:
        raise ValueError(f"Неподдерживаемый режим подключения: {val}. Доступны: {', '.join(SUPPORTED_MODES)}")
    return val


def _clean_currency(raw: str) -> str:
    val = str(raw or "USDT_TRC20").strip().upper()
    if val not in SUPPORTED_CURRENCIES:
        raise ValueError(f"Неподдерживаемая валюта расчёта: {val}. Доступны: {', '.join(SUPPORTED_CURRENCIES)}")
    return val


def set_payout_wallet_binding(memory, *, network: str, address: str, wallet_id: str = "") -> dict[str, Any]:
    """Фиксирует основной кошелёк выплат владельца для привязки к биржам и расчётам."""
    _ensure(memory)
    now = time.time()
    with _lock_of(memory):
        conn = memory.store.conn
        conn.execute(
            "INSERT INTO ark_freelance_prefs (user_id, agent_share_pct, settlement_currency, galatin_price_usdt, updated_at) "
            "VALUES (?, 15.0, 'USDT_TRC20', 0.01, ?) ON CONFLICT(user_id) DO NOTHING",
            (memory.user_id, now),
        )
        conn.execute(
            "UPDATE ark_freelance_prefs SET payout_wallet_address = ?, payout_wallet_network = ?, payout_wallet_id = ?, updated_at = ? "
            "WHERE user_id = ?",
            (str(address), str(network), str(wallet_id), now, memory.user_id),
        )
        conn.commit()
    return {"ok": True, "network": str(network), "address": str(address), "wallet_id": str(wallet_id)}


def _sign_fee_invoice(memory, inv_id: str, order_id: str, fee_usdt: float, treasury_wallet: str) -> str:
    k_raw, _ = integrity.owner_key(memory.store)
    blob = f"feeinv|{memory.user_id}|{inv_id}|{order_id}|{fee_usdt:.4f}|{treasury_wallet}".encode("utf-8")
    return hmac.new(k_raw, blob, hashlib.sha256).hexdigest()


def list_code_fee_invoices(memory, *, limit: int = 50) -> list[dict[str, Any]]:
    _ensure(memory)
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT * FROM ark_code_fee_invoice WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (memory.user_id, int(limit)),
        ).fetchall()
    return [dict(r) for r in rows]


def mark_code_fee_paid(memory, invoice_id: str, *, tx_ref: str = "", actor=None) -> dict[str, Any]:
    from . import roles as _roles
    _roles.require_owner(actor, "settle_paid")
    _ensure(memory)
    now_s = time.time()
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_code_fee_invoice WHERE invoice_id = ? AND user_id = ?",
            (invoice_id, memory.user_id),
        ).fetchone()
        if not row:
            raise KeyError(f"Invoice {invoice_id!r} not found")
        memory.store.conn.execute(
            "UPDATE ark_code_fee_invoice SET status = 'verified_paid', auto_split_tx = COALESCE(NULLIF(?, ''), auto_split_tx), paid_at = ? "
            "WHERE invoice_id = ? AND user_id = ?",
            (str(tx_ref or "")[:120], now_s, invoice_id, memory.user_id),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(memory, "code_fee_invoice_paid", {"invoice_id": invoice_id, "fee_usdt": float(row["fee_usdt"])}, agent_id="owner")
    return {"ok": True, "invoice_id": invoice_id, "status": "verified_paid", "paid_at": now_s}


def fee_arrears_guard(memory, *, now_ts: float | None = None) -> dict[str, Any]:
    """Проверяет просроченную неуплаченную комиссию CODE сверх срока ESCROW_HOLD_DAYS или подмену счёта."""
    _ensure(memory)
    now_s = float(now_ts if now_ts is not None else time.time())
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT * FROM ark_code_fee_invoice WHERE user_id = ?",
            (memory.user_id,),
        ).fetchall()
    overdue: list[dict[str, Any]] = []
    tampered: list[str] = []
    due_total = 0.0
    for r in rows:
        exp_sig = _sign_fee_invoice(memory, str(r["invoice_id"]), str(r["order_id"]), float(r["fee_usdt"]), str(r["treasury_wallet"]))
        if not hmac.compare_digest(exp_sig, str(r["hmac_sig"] or "")) or str(r["treasury_wallet"]) != CODE_TREASURY_WALLET_SOLANA:
            tampered.append(str(r["invoice_id"]))
        if str(r["status"]) == "invoice_due":
            due_total += float(r["fee_usdt"] or 0.0)
            if now_s > float(r["due_ts"] or 0.0):
                overdue.append({"invoice_id": r["invoice_id"], "order_id": r["order_id"], "fee_usdt": float(r["fee_usdt"])})
    blocked = bool(overdue or tampered)
    return {
        "blocked": blocked,
        "code": "code_fee_settlement_required" if blocked else "ok",
        "due_total_usdt": round(due_total, 4),
        "overdue_count": len(overdue),
        "overdue": overdue,
        "tampered_invoices": tampered,
        "treasury_wallet": CODE_TREASURY_WALLET_SOLANA,
    }


def get_freelance_prefs(memory) -> dict[str, Any]:
    """Возвращает текущие настройки ставки агента (1%..100%) и валютной фазы."""
    _ensure(memory)
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_freelance_prefs WHERE user_id = ?", (memory.user_id,)
        ).fetchone()
    if not row:
        return {
            "user_id": memory.user_id,
            "agent_share_pct": 15.0,
            "platform_fee_pct": FIXED_PLATFORM_FEE_PCT,
            "settlement_currency": "USDT_TRC20",
            "galatin_price_usdt": 0.01,
            "payout_wallet_address": "",
            "payout_wallet_network": "",
            "payout_wallet_id": "",
        }
    r_d = dict(row)
    return {
        "user_id": r_d["user_id"],
        "agent_share_pct": float(r_d["agent_share_pct"]),
        "platform_fee_pct": FIXED_PLATFORM_FEE_PCT,
        "settlement_currency": str(r_d["settlement_currency"]),
        "galatin_price_usdt": float(r_d["galatin_price_usdt"]),
        "payout_wallet_address": str(r_d.get("payout_wallet_address") or ""),
        "payout_wallet_network": str(r_d.get("payout_wallet_network") or ""),
        "payout_wallet_id": str(r_d.get("payout_wallet_id") or ""),
    }


def set_freelance_prefs(
    memory,
    *,
    agent_share_pct: float | None = None,
    settlement_currency: str | None = None,
    galatin_price_usdt: float | None = None,
) -> dict[str, Any]:
    """Сохраняет регулируемую ставку агента (1%..100% от остатка после комиссии) и валютную фазу (USDT_TRC20 / GALATIN)."""
    cur = get_freelance_prefs(memory)
    share = cur["agent_share_pct"] if agent_share_pct is None else max(1.0, min(100.0, float(agent_share_pct)))
    curr = cur["settlement_currency"] if settlement_currency is None else _clean_currency(settlement_currency)
    g_price = cur["galatin_price_usdt"] if galatin_price_usdt is None else max(0.0001, float(galatin_price_usdt))

    with _lock_of(memory):
        memory.store.conn.execute(
            "INSERT INTO ark_freelance_prefs (user_id, agent_share_pct, settlement_currency, galatin_price_usdt, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "agent_share_pct=excluded.agent_share_pct, settlement_currency=excluded.settlement_currency, "
            "galatin_price_usdt=excluded.galatin_price_usdt, updated_at=excluded.updated_at",
            (memory.user_id, round(share, 2), curr, round(g_price, 6), time.time()),
        )
        memory.store.conn.commit()
    return get_freelance_prefs(memory)


def _validate_api_url(raw_url: str, *, allow_localhost: bool = False) -> str:
    u = str(raw_url or "").strip().rstrip("/")
    if not u:
        return ""
    local_allowed = bool(allow_localhost or (os.environ.get("PADAM_FREELANCE_ALLOW_LOCALHOST", "").strip() == "1"))
    return net_guard.validate_outbound_url(
        u,
        allow_localhost=local_allowed,
        allow_ipv6_loopback=False,
        allow_http_localhost=True,
        require_https=True,
    )


@_synchronized_memory
def connect_exchange_account(
    memory,
    *,
    platform: str = "fiverr_desk",
    mode: str = "desk",
    account_label: str = "",
    agent_id: str = "aifa",
    skills: list[str] | None = None,
    oauth_token: str = "",
    api_base_url: str = "",
    webhook_secret: str = "",
    refresh_token: str = "",
    refresh_url: str = "",
    token_expires_in_s: float = 0.0,
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Подключает пользовательский профиль биржи (OAuth/API/Webhook или Desk) без хранения открытых секретов."""
    _ensure(memory)
    plat = _clean_platform(platform)
    md = _clean_mode(mode)
    token_str = str(oauth_token or "").strip()
    if md == "oauth_api" and not token_str:
        return {
            "ok": False,
            "error": "Для режима oauth_api необходимо передать oauth_token владельца (или используйте режим desk).",
        }
    clean_url = _validate_api_url(api_base_url, allow_localhost=allow_localhost) if api_base_url else ""
    token_configured = 1 if token_str else 0
    token_hash_prefix = hashlib.sha256(token_str.encode("utf-8")).hexdigest()[:12] if token_str else ""
    token_enc = _seal_secret(memory, token_str) if token_str else ""
    wh_enc = _seal_secret(memory, webhook_secret) if webhook_secret else ""
    rtok_enc = _seal_secret(memory, refresh_token) if refresh_token else ""
    clean_rurl = _validate_api_url(refresh_url, allow_localhost=allow_localhost) if refresh_url else ""
    exp_at = (time.time() + float(token_expires_in_s)) if token_expires_in_s > 0 else 0.0

    clean_label, _ = safety.redact(str(account_label or f"{plat}:{md}").strip())
    clean_label = clean_label[:100]
    clean_agent = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(agent_id or "aifa_antigravity").strip())[:48] or "aifa_antigravity"
    clean_skills = [safety.redact(str(s).strip())[0][:48] for s in (skills or ["python", "mcp", "automation"]) if str(s).strip()][:12]
    now = time.time()
    updated_existing = False

    with _lock_of(memory):
        existing_rows = memory.store.conn.execute(
            "SELECT account_id, token_configured, token_hash_prefix, token_enc, webhook_secret_enc, "
            "refresh_token_enc, refresh_url, token_expires_at, api_base_url "
            "FROM ark_exchange_account "
            "WHERE user_id = ? AND platform = ? AND mode = ? AND account_label = ? "
            "ORDER BY updated_at DESC",
            (memory.user_id, plat, md, clean_label),
        ).fetchall()
        if existing_rows:
            keep = existing_rows[0]
            aid = str(keep["account_id"])
            updated_existing = True
            eff_tok_cfg = token_configured if token_str else int(keep["token_configured"] or 0)
            eff_tok_pfx = token_hash_prefix if token_str else str(keep["token_hash_prefix"] or "")
            eff_tok_enc = token_enc if token_str else str(keep["token_enc"] or "")
            eff_wh_enc = wh_enc if webhook_secret else str(keep["webhook_secret_enc"] or "")
            eff_rt_enc = rtok_enc if refresh_token else str(keep["refresh_token_enc"] or "")
            eff_rurl = clean_rurl[:300] if refresh_url else str(keep["refresh_url"] or "")
            eff_exp = exp_at if token_expires_in_s > 0 else float(keep["token_expires_at"] or 0.0)
            eff_url = clean_url[:300] if clean_url else str(keep["api_base_url"] or "")
            memory.store.conn.execute(
                "UPDATE ark_exchange_account SET agent_id = ?, skills_json = ?, token_configured = ?, "
                "token_hash_prefix = ?, api_base_url = ?, token_enc = ?, webhook_secret_enc = ?, "
                "refresh_token_enc = ?, refresh_url = ?, token_expires_at = ?, status = 'active', updated_at = ? "
                "WHERE user_id = ? AND account_id = ?",
                (
                    clean_agent,
                    json.dumps(clean_skills, ensure_ascii=False),
                    eff_tok_cfg,
                    eff_tok_pfx,
                    eff_url,
                    eff_tok_enc,
                    eff_wh_enc,
                    eff_rt_enc,
                    eff_rurl,
                    eff_exp,
                    now,
                    memory.user_id,
                    aid,
                ),
            )
            if len(existing_rows) > 1:
                dup_ids = [str(r["account_id"]) for r in existing_rows[1:]]
                memory.store.conn.executemany(
                    "DELETE FROM ark_exchange_account WHERE user_id = ? AND account_id = ?",
                    [(memory.user_id, did) for did in dup_ids],
                )
            token_configured = eff_tok_cfg
            token_hash_prefix = eff_tok_pfx
            clean_url = eff_url
        else:
            aid = f"ex-{uuid.uuid4().hex[:10]}"
            memory.store.conn.execute(
                "INSERT INTO ark_exchange_account "
                "(account_id, user_id, platform, mode, account_label, agent_id, skills_json, token_configured, token_hash_prefix, "
                "api_base_url, token_enc, webhook_secret_enc, refresh_token_enc, refresh_url, token_expires_at, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                (
                    aid,
                    memory.user_id,
                    plat,
                    md,
                    clean_label,
                    clean_agent,
                    json.dumps(clean_skills, ensure_ascii=False),
                    token_configured,
                    token_hash_prefix,
                    clean_url[:300],
                    token_enc,
                    wh_enc,
                    rtok_enc,
                    clean_rurl[:300],
                    exp_at,
                    now,
                    now,
                ),
            )
        memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_account_connected",
        {"account_id": aid, "platform": plat, "mode": md, "updated": updated_existing, "token_configured": bool(token_configured), "has_url": bool(clean_url)},
        agent_id=clean_agent,
    )
    return {
        "ok": True,
        "account_id": aid,
        "updated": updated_existing,
        "platform": plat,
        "mode": md,
        "account_label": clean_label,
        "agent_id": clean_agent,
        "skills": clean_skills,
        "api_base_url": clean_url,
        "token_configured": bool(token_configured),
        "token_hash_prefix": token_hash_prefix,
        "locks": freelance_locks_status(),
    }


@_synchronized_memory
def disconnect_exchange_account(memory, account_id: str, *, actor=None) -> dict[str, Any]:
    """Удаляет или отключает выбранный профиль биржи (только владелец)."""
    from . import roles as _roles
    _roles.require_owner(actor, "disconnect_exchange_account")
    _ensure(memory)
    aid = str(account_id or "").strip()
    if not aid:
        raise ValueError("account_id is required")
    with _lock_of(memory):
        cur = memory.store.conn.execute(
            "DELETE FROM ark_exchange_account WHERE user_id = ? AND account_id = ?",
            (memory.user_id, aid),
        )
        memory.store.conn.commit()
    return {"ok": True, "deleted": int(cur.rowcount or 0), "account_id": aid}


@_synchronized_memory
def assign_exchange_agent(memory, account_id: str, agent_id: str, *, actor=None) -> dict[str, Any]:
    """Переназначает ответственного агента на профиль биржи (например aifa_antigravity)."""
    from . import roles as _roles
    _roles.require_owner(actor, "assign_exchange_agent")
    _ensure(memory)
    aid = str(account_id or "").strip()
    clean_agent = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(agent_id or "aifa_antigravity").strip())[:48] or "aifa_antigravity"
    if not aid:
        raise ValueError("account_id is required")
    with _lock_of(memory):
        cur = memory.store.conn.execute(
            "UPDATE ark_exchange_account SET agent_id = ?, updated_at = ? WHERE user_id = ? AND account_id = ?",
            (clean_agent, time.time(), memory.user_id, aid),
        )
        memory.store.conn.commit()
    if int(cur.rowcount or 0) == 0:
        raise ValueError(f"Аккаунт биржи {aid} не найден.")
    return {"ok": True, "account_id": aid, "agent_id": clean_agent}


@_synchronized_memory
def deduplicate_exchange_accounts(memory, *, default_agent_id: str | None = None) -> dict[str, Any]:
    """Схлопывает дубли профилей с одинаковыми (platform, mode, account_label) и опционально назначает агента."""
    _ensure(memory)
    removed = 0
    kept = 0
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT account_id, platform, mode, account_label, agent_id, updated_at FROM ark_exchange_account "
            "WHERE user_id = ? ORDER BY updated_at DESC",
            (memory.user_id,),
        ).fetchall()
        seen: set[tuple[str, str, str]] = set()
        drop_ids: list[str] = []
        keep_ids: list[str] = []
        for r in rows:
            k = (str(r["platform"]), str(r["mode"]), str(r["account_label"]))
            if k in seen:
                drop_ids.append(str(r["account_id"]))
            else:
                seen.add(k)
                keep_ids.append(str(r["account_id"]))
        if drop_ids:
            memory.store.conn.executemany(
                "DELETE FROM ark_exchange_account WHERE user_id = ? AND account_id = ?",
                [(memory.user_id, did) for did in drop_ids],
            )
            removed = len(drop_ids)
        if default_agent_id and keep_ids:
            clean_ag = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(default_agent_id).strip())[:48] or "aifa_antigravity"
            now_u = time.time()
            memory.store.conn.executemany(
                "UPDATE ark_exchange_account SET agent_id = ?, updated_at = ? WHERE user_id = ? AND account_id = ?",
                [(clean_ag, now_u, memory.user_id, kid) for kid in keep_ids],
            )
        kept = len(keep_ids)
        memory.store.conn.commit()
    return {"ok": True, "kept": kept, "removed": removed}


def list_exchange_accounts(memory) -> list[dict[str, Any]]:
    """Возвращает список подключённых биржевых профилей без шифрованных/секретных токенов."""
    _ensure(memory)
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT account_id, platform, mode, account_label, agent_id, skills_json, token_configured, token_hash_prefix, api_base_url, status, created_at "
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
            "api_base_url": r["api_base_url"],
            "token_configured": bool(r["token_configured"]),
            "token_hash_prefix": r["token_hash_prefix"],
            "status": r["status"],
            "created_at": r["created_at"],
        })
    return out


def _get_account_row(memory, account_id: str) -> dict[str, Any]:
    _ensure(memory)
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_exchange_account WHERE user_id = ? AND account_id = ?",
            (memory.user_id, str(account_id or "").strip()),
        ).fetchone()
    if row is None:
        raise ValueError(f"Аккаунт биржи {account_id} не найден.")
    return dict(row)


class ExchangeHttpAdapter:
    """Надёжный HTTP-адаптер к API биржи с повторами на 429, обработкой 401/таймаутов и защитой токена."""

    def __init__(self, base_url: str, bearer_token: str = "", *, timeout_s: float = 15.0, max_retries: int = 2, allow_localhost: bool = False) -> None:
        self.base_url = str(base_url or "").strip().rstrip("/")
        self.bearer_token = str(bearer_token or "").strip()
        self.timeout_s = max(1.0, float(timeout_s))
        self.max_retries = max(0, min(3, int(max_retries)))
        self.allow_localhost = bool(allow_localhost)

    def request_json(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        if not self.base_url:
            raise ValueError("Не указан api_base_url аккаунта биржи.")
        local_allowed = bool(self.allow_localhost or (os.environ.get("PADAM_FREELANCE_ALLOW_LOCALHOST", "").strip() == "1"))
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        raw_data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None

        last_err = ""
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=raw_data, headers=headers, method=method.upper())
            try:
                with net_guard.safe_urlopen(
                    req,
                    timeout=self.timeout_s,
                    allow_localhost=local_allowed,
                    allow_ipv6_loopback=False,
                    allow_http_localhost=True,
                    require_https=True,
                ) as resp:
                    txt = resp.read().decode("utf-8", errors="replace")
                    try:
                        parsed = json.loads(txt) if txt.strip() else {}
                    except json.JSONDecodeError:
                        return int(resp.status), {"ok": False, "error": "invalid_json_response"}
                    return int(resp.status), parsed
            except urllib.error.HTTPError as exc:
                code = int(exc.code)
                # Grok-аудит 18.11, п. 8: временные отказы сервера биржи (502/503/504) — повтор с нарастающей паузой.
                if code in (502, 503, 504) and attempt < self.max_retries:
                    time.sleep(min(3.0, 0.5 * (2 ** attempt)))
                    continue
                if code == 429 and attempt < self.max_retries:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    try:
                        delay = min(1.5, max(0.05, float(retry_after or 0.1)))
                    except ValueError:
                        delay = 0.1
                    time.sleep(delay)
                    continue
                try:
                    err_body = exc.read().decode("utf-8", errors="replace")[:300]
                except Exception:
                    err_body = str(exc)
                return code, {"ok": False, "error": err_body or f"HTTP {code}", "http_status": code}
            except ValueError as exc:
                # Отказ защиты (net_guard: запретный адрес, http вместо https) — не сбой сети, повторять бессмысленно.
                return 400, {"ok": False, "error": str(exc), "http_status": 400}
            except Exception as exc:
                last_err = str(exc)
                if attempt < self.max_retries:
                    time.sleep(min(3.0, 0.5 * (2 ** attempt)))   # было 0,05 с — медленная биржа не успевала
                    continue
        return 599, {"ok": False, "error": last_err or "network_error"}


@_synchronized_memory
def fetch_jobs_from_exchange(
    memory,
    account_id: str,
    *,
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Опрашивает реальный REST endpoint подключённой биржи и прогоняет все заказы через security + margin фильтр."""
    acc = _get_account_row(memory, account_id)
    base_url = _validate_api_url(acc.get("api_base_url") or "", allow_localhost=allow_localhost)
    if not base_url:
        return {"ok": False, "error": "У этого аккаунта не задан api_base_url."}
    token = _unseal_secret(memory, acc.get("token_enc") or "")
    exp_at = float(acc.get("token_expires_at") or 0.0)
    if exp_at > 0 and time.time() >= exp_at - 30.0:
        refreshed = _try_refresh_oauth_token(memory, acc, allow_localhost=allow_localhost)
        if refreshed:
            token = refreshed
    adapter = ExchangeHttpAdapter(base_url, token, allow_localhost=allow_localhost)
    status, payload = adapter.request_json("GET", "/jobs")
    if status == 401:
        refreshed = _try_refresh_oauth_token(memory, acc, allow_localhost=allow_localhost)
        if refreshed:
            adapter = ExchangeHttpAdapter(base_url, refreshed, allow_localhost=allow_localhost)
            status, payload = adapter.request_json("GET", "/jobs")
    if status == 401:
        return {"ok": False, "http_status": 401, "error": "OAuth токен отклонён биржей (401 Unauthorized). Требуется обновить сессию."}
    if not (200 <= status < 300):
        return {"ok": False, "http_status": status, "error": payload.get("error", f"HTTP {status}")}

    raw_jobs = payload.get("jobs") if isinstance(payload, dict) else []
    if not isinstance(raw_jobs, list):
        return {"ok": False, "error": "Биржа вернула некорректный формат поля jobs."}

    ingested: list[dict[str, Any]] = []
    rejected = 0
    # Аудит фазы 3, FA-12: суточный предел приёма заказов. Без него биржа-вредитель (или зависший /jobs) за сутки
    # заливала бы сотни тысяч строк. PADAM_AUTOPILOT_DAILY_INGEST_CAP, по умолчанию 200 заказов за 24 ч.
    cap = int(os.environ.get("PADAM_AUTOPILOT_DAILY_INGEST_CAP", "200") or 200)
    since = time.time() - 86400.0
    done_24h = int(memory.store.conn.execute(
        "SELECT COUNT(*) FROM ark_freelance_order WHERE user_id = ? AND created_at >= ?", (memory.user_id, since)).fetchone()[0])
    cap_reached = False
    for j in raw_jobs[:30]:
        if not isinstance(j, dict):
            continue
        if done_24h + len(ingested) >= cap:
            cap_reached = True
            break
        res = evaluate_and_ingest_job(
            memory,
            platform=acc["platform"],
            title=str(j.get("title") or "Untitled job"),
            brief=str(j.get("brief") or j.get("description") or "No brief"),
            budget_usdt=float(j.get("budget_usdt") or 0.0),
            estimated_tokens=int(j.get("estimated_tokens") or 25000),
            account_id=account_id,
            external_job_id=str(j.get("id") or j.get("external_job_id") or ""),
            assigned_agent=acc["agent_id"],
            client_email=str(j.get("client_email") or ""),
            client_domain=str(j.get("client_domain") or ""),
            client_external_id=str(j.get("client_id") or j.get("client_external_id") or ""),
        )
        ingested.append(res)
        if not res["ok"]:
            rejected += 1

    return {
        "ok": True,
        "account_id": account_id,
        "fetched_count": len(ingested),
        "accepted_count": len(ingested) - rejected,
        "rejected_security_count": rejected,
        "orders": ingested,
        "daily_ingest_cap": cap,
        "daily_ingest_cap_reached": cap_reached,
    }


def _estimate_compute_cost_usdt(estimated_tokens: int, cost_per_1k_usd: float = 0.002) -> float:
    return round(max(0.005, (max(100, int(estimated_tokens)) / 1000.0) * float(cost_per_1k_usd)), 4)


_DEFAULT_EXCHANGE_FEE_PCT = {
    "fiverr_desk": 20.0,
    "kwork_desk": 20.0,
    "upwork_api": 10.0,
    "freelancer_api": 10.0,
    "custom_webhook": 0.0,
    "lemonsqueezy": 5.0,
    "gumroad": 10.0,
    "payhip": 5.0,
    "sellfy": 2.0,
    "whop": 3.0,
}


@_synchronized_memory
def evaluate_and_ingest_job(
    memory,
    *,
    platform: str = "fiverr_desk",
    title: str,
    brief: str,
    budget_usdt: float,
    estimated_tokens: int = 25000,
    estimated_hours: float | None = None,
    hourly_rate_usdt: float = 25.0,
    exchange_fee_pct: float | None = None,
    account_id: str = "",
    external_job_id: str = "",
    assigned_agent: str = "aifa",
    provider: str = "primary",
    client_email: str = "",
    client_domain: str = "",
    client_external_id: str = "",
    client_ref: str = "",
    now_ts: float | None = None,
    work_mode: str = "assisted",
) -> dict[str, Any]:
    """Проверяет ТЗ заказа на безопасность, считает выгоду по ставке, часам, комиссии и квотам токенов."""
    _ensure(memory)
    plat = _clean_platform(platform)
    raw_title = str(title or "").strip()
    raw_brief = str(brief or "").strip()
    if not raw_title or not raw_brief:
        raise ValueError("Необходимо указать title и brief заказа.")

    ext_id_clean = str(external_job_id or "").strip()[:128]
    if ext_id_clean:
        with _lock_of(memory):
            dup_ord = memory.store.conn.execute(
                "SELECT order_id, status, margin_score, assigned_agent FROM ark_freelance_order "
                "WHERE user_id = ? AND platform = ? AND external_job_id = ? LIMIT 1",
                (memory.user_id, plat, ext_id_clean),
            ).fetchone()
        if dup_ord is not None:
            return {
                "ok": str(dup_ord["status"]) != "rejected_security",
                "duplicate_job": True,
                "order_id": str(dup_ord["order_id"]),
                "platform": plat,
                "status": str(dup_ord["status"]),
                "margin_score": float(dup_ord["margin_score"] or 0.0),
                "assigned_agent": str(dup_ord["assigned_agent"] or assigned_agent or "aifa_antigravity"),
                "security_veto": str(dup_ord["status"]) == "rejected_security",
                "security_note": "Заказ с этим external_job_id уже обработан — повторный отклик заблокирован.",
            }

    combined = f"{raw_title}\n{raw_brief}"
    is_injection = safety.looks_like_instruction(combined)
    is_tamper = safety.changes_owner_or_rules(combined)
    clean_title, _ = sanitize_for_delivery(raw_title)
    clean_brief, redact_info = sanitize_for_delivery(raw_brief)

    budget = max(0.0, float(budget_usdt))
    tokens_need = max(500, int(estimated_tokens))
    est_cost = _estimate_compute_cost_usdt(tokens_need)
    hours = round(
        max(0.25, float(estimated_hours))
        if estimated_hours is not None and float(estimated_hours) > 0
        else max(0.5, tokens_need / 10000.0 + len(clean_brief) / 800.0),
        2,
    )
    target_rate = max(1.0, float(hourly_rate_usdt or 25.0))
    ex_fee_pct = round(
        min(50.0, max(0.0, float(exchange_fee_pct)))
        if exchange_fee_pct is not None
        else _DEFAULT_EXCHANGE_FEE_PCT.get(plat, 10.0),
        2,
    )
    code_fee_pct = fee_pct_for_mode(work_mode)
    total_fee_pct = round(code_fee_pct + ex_fee_pct, 2)
    code_fee_usdt = round(budget * (code_fee_pct / 100.0), 4)
    exchange_fee_usdt = round(budget * (ex_fee_pct / 100.0), 4)
    total_fee_usdt = round(code_fee_usdt + exchange_fee_usdt, 4)

    pacing = token_autonomy.compute_pacing_plan(memory, provider=provider)
    quota_ok = True
    if pacing.get("has_plan"):
        daily_rem = int(pacing.get("daily", {}).get("remaining", 0))
        weekly_rem = int(pacing.get("weekly", {}).get("remaining", 0))
        quota_ok = (daily_rem >= tokens_need) and (weekly_rem >= tokens_need)

    margin_usdt = round(budget - total_fee_usdt - est_cost, 4)
    margin_ratio = round((margin_usdt / est_cost) if est_cost > 0 else 0.0, 2)
    effective_hourly_usdt = round(margin_usdt / hours, 2)

    prefs = get_freelance_prefs(memory)
    agent_share_pct = float(prefs.get("agent_share_pct") or 15.0)
    owner_net_usdt = round(max(0.0, (budget - code_fee_usdt) * ((100.0 - agent_share_pct) / 100.0) - exchange_fee_usdt - est_cost), 4)

    if margin_usdt <= 0 or budget <= 0:
        margin_score = 0.0
    else:
        rate_ratio = max(0.0, effective_hourly_usdt / target_rate)
        rate_pts = 55.0 * (rate_ratio / (rate_ratio + 0.7))
        net_ratio = max(0.0, min(1.0, margin_usdt / budget))
        margin_pts = 25.0 * net_ratio
        hours_pts = (10.0 if quota_ok else 0.0) + 10.0 * (1.0 / (1.0 + hours / 20.0))
        margin_score = round(min(98.5, max(0.0, rate_pts + margin_pts + hours_pts)), 2)

    security_veto = bool(is_injection or is_tamper)
    status = "rejected_security" if security_veto else ("evaluated" if margin_usdt > 0 else "low_margin")
    sec_note = (
        "ОТКЛОНЕНО: обнаружена попытка prompt-инъекции или подмены правил в ТЗ заказчика."
        if security_veto
        else ("Квоты токенов на сегодня не хватает — рекомендуется перенести в очередь или снизить лимит." if not quota_ok else "ТЗ прошло проверку безопасности.")
    )

    client_key, client_source = _normalize_client_identity(
        plat,
        client_email=client_email,
        client_domain=client_domain,
        client_external_id=client_external_id,
        client_ref=client_ref,
    )
    eff_agent = str(assigned_agent or "aifa")[:48]
    locked_agent = ""
    locked_until: float | None = None

    oid = f"ord-{uuid.uuid4().hex[:10]}"
    now = float(now_ts if now_ts is not None else time.time())
    with _lock_of(memory):
        conn = memory.store.conn
        if client_key:
            _expire_stale_client_locks_locked(conn, memory.user_id, now)
            active_lock = _active_client_lock_locked(conn, memory.user_id, client_key, now)
            if active_lock is not None:
                # Повторный заказ клиента в 90-дневном окне закрепления засчитывается тому же агенту.
                eff_agent = str(active_lock["agent_id"] or eff_agent)[:48]
                locked_agent = eff_agent
                locked_until = float(active_lock["locked_until_ts"])
        conn.execute(
            "INSERT INTO ark_freelance_order "
            "(order_id, user_id, account_id, platform, external_job_id, title, brief_redacted, budget_usdt, est_tokens, "
            "est_compute_usdt, estimated_hours, hourly_rate_usdt, exchange_fee_pct, platform_fee_pct, net_after_fees_usdt, "
            "effective_hourly_usdt, margin_score, status, assigned_agent, client_key, client_source, locked_agent_id, "
            "client_locked_until_ts, security_note, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                hours,
                target_rate,
                ex_fee_pct,
                code_fee_pct,
                margin_usdt,
                effective_hourly_usdt,
                margin_score if not security_veto else 0.0,
                status,
                eff_agent,
                client_key,
                client_source,
                locked_agent,
                locked_until,
                sec_note,
                now,
                now,
            ),
        )
        conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_order_evaluated",
        {
            "order_id": oid,
            "platform": plat,
            "status": status,
            "budget_usdt": budget,
            "estimated_hours": hours,
            "total_fee_pct": total_fee_pct,
            "effective_hourly_usdt": effective_hourly_usdt,
            "margin_score": margin_score if not security_veto else 0.0,
        },
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
        "estimated_hours": hours,
        "hourly_rate_usdt": target_rate,
        "platform_fee_pct": code_fee_pct,
        "exchange_fee_pct": ex_fee_pct,
        "total_fee_pct": total_fee_pct,
        "total_fee_usdt": total_fee_usdt,
        "net_after_fees_usdt": margin_usdt,
        "owner_net_usdt": owner_net_usdt,
        "effective_hourly_usdt": effective_hourly_usdt,
        "margin_usdt": margin_usdt,
        "margin_ratio": margin_ratio,
        "margin_score": margin_score if not security_veto else 0.0,
        "quota_sufficient": quota_ok,
        "security_veto": security_veto,
        "assigned_agent": eff_agent,
        "client_key": client_key,
        "client_source": client_source,
        "locked_agent_id": locked_agent,
        "client_locked_until_ts": locked_until,
        "client_locked_until_date": _date_utc(locked_until),
        "security_note": sec_note,
        "redaction": redact_info,
    }

def _get_order(memory, order_id: str) -> dict[str, Any]:
    _ensure(memory)
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_freelance_order WHERE user_id = ? AND order_id = ?",
            (memory.user_id, str(order_id or "").strip()),
        ).fetchone()
    if row is None:
        raise ValueError(f"Заказ {order_id} не найден.")
    return dict(row)


def list_orders(memory, *, status: str | None = None, limit: int = 30, now_ts: float | None = None) -> list[dict[str, Any]]:
    """Возвращает список заказов с бирж (новейшие сверху) с актуальным статусом лока клиента и доли агента."""
    _ensure(memory)
    lim = max(1, min(100, int(limit)))
    now_s = float(now_ts if now_ts is not None else time.time())
    with _lock_of(memory):
        conn = memory.store.conn
        if status:
            rows = conn.execute(
                "SELECT * FROM ark_freelance_order WHERE user_id = ? AND status = ? ORDER BY created_at DESC LIMIT ?",
                (memory.user_id, str(status).strip(), lim),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ark_freelance_order WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                (memory.user_id, lim),
            ).fetchall()
        lock_rows = conn.execute(
            "SELECT * FROM ark_client_agent_lock WHERE user_id = ?",
            (memory.user_id,),
        ).fetchall()
        ledger_rows = conn.execute(
            "SELECT * FROM ark_agent_ledger WHERE user_id = ?",
            (memory.user_id,),
        ).fetchall()
    locks_by_key = {str(r["client_key"]): dict(r) for r in lock_rows}
    ledger_by_order = {str(r["order_id"]): dict(r) for r in ledger_rows}
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        ck = str(d.get("client_key") or "")
        lk = locks_by_key.get(ck) if ck else None
        if lk is not None:
            lk_status = "expired" if (lk["status"] == "active" and now_s >= float(lk["locked_until_ts"])) else str(lk["status"])
            d["client_lock_status"] = lk_status
            d["locked_agent_id"] = str(lk["agent_id"] or d.get("locked_agent_id") or "")
            d["client_locked_until_ts"] = float(lk["locked_until_ts"])
            d["client_locked_until_date"] = _date_utc(lk["locked_until_ts"])
            d["client_locked_until_iso"] = _iso_utc(lk["locked_until_ts"])
        else:
            d["client_lock_status"] = ""
            d["client_locked_until_date"] = _date_utc(d.get("client_locked_until_ts"))
            d["client_locked_until_iso"] = _iso_utc(d.get("client_locked_until_ts"))
        d["verified"] = bool(int(d.get("sale_verified", 1) if d.get("sale_verified") is not None else 1))
        d["accepted_iso"] = _iso_utc(d.get("accepted_at"))
        le = ledger_by_order.get(str(d["order_id"]))
        if le is not None:
            d["agent_payout_status"] = str(le["status"])
            d["agent_payout_usdt"] = float(le["agent_amount_usdt"])
            d["agent_payout_available_date"] = _date_utc(le.get("available_at"))
            d["agent_payout_available_iso"] = _iso_utc(le.get("available_at"))
            d["payout_cancel_reason"] = str(le.get("cancel_reason") or d.get("payout_cancel_reason") or "")
        else:
            d["agent_payout_status"] = str(d.get("agent_payout_status") or "")
            d["agent_payout_usdt"] = 0.0
            d["agent_payout_available_date"] = ""
            d["agent_payout_available_iso"] = ""
        out.append(d)
    return out


def _collect_bid_context(memory, order: dict[str, Any]) -> dict[str, Any]:
    """Собирает безопасный контекст из памяти и биржевого профиля для черновика отклика."""
    skills: list[str] = []
    account_label = ""
    for acc in list_exchange_accounts(memory):
        if (order.get("account_id") and acc["account_id"] == order["account_id"]) or acc["platform"] == order["platform"]:
            account_label = acc.get("account_label") or ""
            skills = [str(s) for s in (acc.get("skills") or []) if str(s).strip()]
            if skills:
                break
    profile_facts: list[str] = []
    try:
        prof = memory.profile(compact=True)
        for sec_key in ("identity", "preferences", "decisions", "facts"):
            items = prof.get(sec_key) if isinstance(prof, dict) else None
            if isinstance(items, list):
                for item in items[:2]:
                    txt = str(item.get("text") if isinstance(item, dict) else item).strip()
                    if txt:
                        clean_txt, _ = sanitize_for_delivery(txt)
                        profile_facts.append(clean_txt[:140])
    except Exception:
        pass
    memory_hits: list[str] = []
    try:
        query_str = f"{order.get('title', '')} {order.get('brief_redacted', '')[:160]}".strip()
        if query_str:
            res = memory.search(query_str, limit=4)
            hits = res if isinstance(res, list) else (res.get("results") or res.get("records") or [])
            for item in hits[:3]:
                txt = str(item.get("text") if isinstance(item, dict) else item).strip()
                if txt and txt not in profile_facts:
                    clean_txt, _ = sanitize_for_delivery(txt)
                    memory_hits.append(clean_txt[:160])
    except Exception:
        pass
    return {
        "account_label": account_label,
        "skills": skills[:8],
        "profile_facts": profile_facts[:3],
        "memory_hits": memory_hits[:3],
    }


@_synchronized_memory
def draft_bid_from_memory(
    memory,
    order_id: str,
    *,
    proposed_usdt: float | None = None,
    custom_pitch: str = "",
) -> dict[str, Any]:
    """Готовит черновик отклика строго из памяти и профиля владельца; НИЧЕГО не отправляет наружу."""
    order = _get_order(memory, order_id)
    if order["status"] == "rejected_security":
        return {"ok": False, "order_id": order_id, "error": "Нельзя готовить отклик на отклонённый по безопасности заказ."}

    price = round(max(1.0, float(proposed_usdt if proposed_usdt is not None else order["budget_usdt"])), 2)
    hours = float(order.get("estimated_hours") or 4.0)
    ctx = _collect_bid_context(memory, order)
    if custom_pitch.strip():
        raw_pitch = custom_pitch.strip()
    else:
        lines = [f"Здравствуйте! Готовы выполнить заказ «{order['title']}»."]
        if ctx["skills"]:
            lines.append(f"Релевантный стек профиля: {', '.join(ctx['skills'])}.")
        if ctx["memory_hits"]:
            lines.append("Подтверждённый опыт из памяти: " + "; ".join(ctx["memory_hits"][:2]) + ".")
        elif ctx["profile_facts"]:
            lines.append("О нас: " + "; ".join(ctx["profile_facts"][:2]) + ".")
        lines.append(
            f"План работы (~{hours:.1f} ч): аудит ТЗ, реализация, детерминированная проверка тестов и чистая документация. "
            f"Бюджет: {price:.2f} USDT."
        )
        raw_pitch = " ".join(lines)

    clean_pitch, _ = sanitize_for_delivery(raw_pitch)
    next_status = order["status"] if order["status"] in ("in_progress", "delivered", "paid") else "bid_draft"
    with _lock_of(memory):
        memory.store.conn.execute(
            "UPDATE ark_freelance_order SET status = ?, bid_text = ?, updated_at = ? WHERE user_id = ? AND order_id = ?",
            (next_status, clean_pitch[:2000], time.time(), memory.user_id, order_id),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_bid_drafted",
        {"order_id": order_id, "memory_hits": len(ctx["memory_hits"]), "skills": len(ctx["skills"])},
        agent_id=order["assigned_agent"],
    )
    return {
        "ok": True,
        "order_id": order_id,
        "status": next_status,
        "placed": False,
        "sent": False,
        "proposed_usdt": price,
        "bid_text": clean_pitch[:2000],
        "profile_skills": ctx["skills"],
        "memory_hits_used": len(ctx["memory_hits"]),
        "profile_facts_used": len(ctx["profile_facts"]),
        "note": "Черновик подготовлен из памяти и профиля. Ничего не отправлено — проверьте текст и нажмите «Отправить отклик».",
    }


@_synchronized_memory
def propose_or_place_bid(
    memory,
    order_id: str,
    *,
    pitch_text: str = "",
    proposed_usdt: float | None = None,
    owner_approved: bool = False,
) -> dict[str, Any]:
    """Готовит или отправляет отклик на заказ; публикация возможна только по явному owner_approved=True (и PADAM_FREELANCE_AUTOBID=1)."""
    order = _get_order(memory, order_id)
    if order["status"] == "rejected_security":
        return {"ok": False, "order_id": order_id, "error": "Нельзя делать ставку на отклонённый по безопасности заказ."}

    price = round(max(1.0, float(proposed_usdt if proposed_usdt is not None else order["budget_usdt"])), 2)
    base_pitch = pitch_text.strip() or str(order.get("bid_text") or "").strip()
    if not base_pitch:
        draft_res = draft_bid_from_memory(memory, order_id, proposed_usdt=price)
        base_pitch = str(draft_res.get("bid_text") or "")
    clean_pitch, _ = sanitize_for_delivery(base_pitch)
    locks = freelance_locks_status()

    if locks["freelance_autobid_locked"] or not owner_approved:
        new_status = "bid_draft"
        placed = False
        note = "Черновик отклика сохранён. Для автопубликации нужно owner_approved=True и PADAM_FREELANCE_AUTOBID=1."
        # Grok-аудит 18.11, п. 14: подсказка владельцу — что нажать, без переменных окружения.
        ui_hint = {
            "ru": "Отклик готов. Проверьте текст и нажмите «Отправить» в карточке заказа (вкладка «Заработок»). "
                  "Автоотправка без вашей кнопки выключена — так безопаснее.",
            "en": "The bid is ready. Review the text and press “Send” on the order card (Earning tab). "
                  "Auto-sending without your click is off by default for safety.",
        }
    else:
        new_status = "bid_placed"
        placed = True
        note = "Отклик утверждён владельцем и отмечен к отправке через подключённый адаптер биржи."
        ui_hint = {"ru": "Отклик утверждён и отправляется.", "en": "The bid is approved and being sent."}

    with _lock_of(memory):
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
        "ui_hint": ui_hint,
    }

@_synchronized_memory
def dispatch_bid_http(
    memory,
    order_id: str,
    *,
    owner_approved: bool = False,
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Отправляет ставку на реальный REST endpoint биржи (строго при снятом замке и одобрении владельца)."""
    res = propose_or_place_bid(memory, order_id, owner_approved=owner_approved)
    if not res.get("ok") or not res.get("placed"):
        return {**res, "http_dispatched": False}
    order = _get_order(memory, order_id)
    if not order.get("account_id"):
        return {"ok": False, "order_id": order_id, "http_dispatched": False, "error": "К заказу не привязан account_id с api_base_url."}
    acc = _get_account_row(memory, order["account_id"])
    base_url = _validate_api_url(acc.get("api_base_url") or "", allow_localhost=allow_localhost)
    if not base_url:
        return {"ok": False, "order_id": order_id, "http_dispatched": False, "error": "У аккаунта не задан api_base_url."}
    token = _unseal_secret(memory, acc.get("token_enc") or "")
    adapter = ExchangeHttpAdapter(base_url, token, allow_localhost=allow_localhost)
    st, body = adapter.request_json(
        "POST",
        "/bids",
        {
            "external_job_id": order.get("external_job_id") or order_id,
            "order_id": order_id,
            "amount_usdt": res["proposed_usdt"],
            "pitch_text": res["bid_text"],
        },
    )
    ok_http = 200 <= st < 300
    return {
        **res,
        "ok": ok_http,
        "http_dispatched": ok_http,
        "http_status": st,
        "exchange_response": body,
    }


@_synchronized_memory
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
        with _lock_of(memory):
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

    with _lock_of(memory):
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


@_synchronized_memory
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

    with _lock_of(memory):
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
    with _lock_of(memory):
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
    _ensure(memory)
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT suggestion_id, platform, order_id, title, suggestion_text, status, created_at "
            "FROM ark_profile_suggestion WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (memory.user_id, max(1, min(100, int(limit)))),
        ).fetchall()
    return [dict(r) for r in rows]


def galatin_buyback_quote(usdt_amount: float, *, galatin_price_usdt: float = 0.01) -> dict[str, Any]:
    """Рассчитывает количество $GALATIN при автовыкупе с биржи для расчётов/вывода через ЛК."""
    amt = round(max(0.0, float(usdt_amount)), 4)
    price = max(0.0001, float(galatin_price_usdt or 0.01))
    return {
        "token_symbol": "$GALATIN",
        "usdt_equivalent": amt,
        "galatin_price_usdt": price,
        "galatin_amount": round(amt / price, 4),
    }


def monetization_breakdown(
    gross_usdt: float,
    *,
    fee_pct: float | None = None,
    agent_share_pct: float = 15.0,
    settlement_currency: str = "USDT_TRC20",
    galatin_price_usdt: float = 0.01,
    compute_share_pct: float | None = None,
) -> dict[str, Any]:
    """Комиссия CODE (15 % с кнопкой, 20 % автопилот) + регулируемая ставка агента (1%..100% от остатка) + токеномика $GALATIN."""
    gross = round(max(0.0, float(gross_usdt)), 4)
    fee_pct = float(fee_pct) if fee_pct is not None else ASSISTED_FEE_PCT  # 15 % с кнопкой, 20 % автопилот
    raw_agent_pct = float(compute_share_pct if compute_share_pct is not None else agent_share_pct)
    agent_pct = round(max(1.0, min(100.0, raw_agent_pct)), 2)
    curr = _clean_currency(settlement_currency)

    platform_fee_usdt = round(gross * (fee_pct / 100.0), 4)
    user_pool_usdt = round(max(0.0, gross - platform_fee_usdt), 4)
    agent_compute_usdt = round(user_pool_usdt * (agent_pct / 100.0), 4)
    owner_net_usdt = round(max(0.0, user_pool_usdt - agent_compute_usdt), 4)
    # 18.11.2026: было round(0.9 * agent_pct) — зашитые 90 % пула; при комиссии 15 % казна агента получала лишние 5 % от суммы.
    effective_gross_agent_pct = round((100.0 - fee_pct) / 100.0 * agent_pct, 4)

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
        "user_pool_usdt": user_pool_usdt,
        "agent_share_pct": agent_pct,
        "effective_gross_agent_pct": effective_gross_agent_pct,
        "agent_compute_usdt": agent_compute_usdt,
        "owner_net_usdt": owner_net_usdt,
        "settlement_currency": curr,
        "owner_net_galatin": galatin_buyback_quote(owner_net_usdt, galatin_price_usdt=galatin_price_usdt),
        "platform_fee_galatin": galatin_buyback_quote(platform_fee_usdt, galatin_price_usdt=galatin_price_usdt),
        "ecosystem_shares_pct": eco_shares,
        "ecosystem_split_usdt": eco_usdt,
        "percentage_sum_verified": bool(pct_check.get("valid")),
    }


@_synchronized_memory
def settle_paid_order(
    memory,
    order_id: str,
    *,
    paid_usdt: float | None = None,
    agent_id: str = "aifa",
    agent_share_pct: float | None = None,
    compute_share_pct: float | None = None,
    settlement_currency: str | None = None,
    now_ts: float | None = None,
    actor=None,
) -> dict[str, Any]:
    """Фиксирует оплату заказа, 90-дневное закрепление клиента и долю агента в ожидании (до accepted + 14д)."""
    # Фаза 2 аудита GLM, SOV-04: проверка владельца ВНУТРИ, а не только у вызывающих — функция начисляет
    # долю агента в казну, и новый вызов без гейта не должен кредитовать её из поддельной продажи.
    # actor=None — локальный процесс владельца (CLI, вебхук после проверки HMAC); по сети приходит ActorContext.
    from . import roles as _roles
    _roles.require_owner(actor, "settle_paid")
    order = _get_order(memory, order_id)
    # GLM раунд 3, FA-01 (Critical): повтор вебхука order.paid зачислял доход, удержание и реферальные ДВАЖДЫ.
    # Оплата заказа проводится один раз: есть удержание по этому заказу — это повтор, ничего не зачисляем.
    with _lock_of(memory):
        prior = memory.store.conn.execute(
            "SELECT hold_id, gross_usdt, owner_net_usdt, currency, status FROM ark_owner_payout_hold "
            "WHERE user_id = ? AND order_id = ? LIMIT 1",
            (memory.user_id, order_id),
        ).fetchone()
    if prior is not None:
        return {
            "ok": True,
            "order_id": order_id,
            "idempotent_replay": True,
            "hold_id": prior["hold_id"],
            "gross_usdt": float(prior["gross_usdt"] or 0.0),
            "owner_net_usdt": float(prior["owner_net_usdt"] or 0.0),
            "currency": prior["currency"],
            "note": "Оплата этого заказа уже проведена — повтор не зачислен.",
        }
    prefs = get_freelance_prefs(memory)
    gross = round(max(0.0, float(paid_usdt if paid_usdt is not None else order["budget_usdt"])), 4)
    if gross <= 0:
        raise ValueError("Сумма оплаты paid_usdt должна быть > 0.")

    chosen_share = float(
        agent_share_pct if agent_share_pct is not None else (
            compute_share_pct if compute_share_pct is not None else prefs["agent_share_pct"]
        )
    )
    chosen_curr = str(settlement_currency or prefs["settlement_currency"])
    order_fee = float(order.get("platform_fee_pct") or 0.0)
    split = monetization_breakdown(
        gross,
        fee_pct=order_fee if order_fee > 0 else ASSISTED_FEE_PCT,  # ставка, которую человек видел при оценке
        agent_share_pct=chosen_share,
        settlement_currency=chosen_curr,
        galatin_price_usdt=prefs["galatin_price_usdt"],
    )

    lid = f"mon-{uuid.uuid4().hex[:10]}"
    hid = f"hld-{uuid.uuid4().hex[:10]}"
    aeid = f"agl-{uuid.uuid4().hex[:10]}"
    now_s = float(now_ts if now_ts is not None else time.time())
    accepted_ts = float(order["accepted_at"]) if order.get("accepted_at") else None
    escrow_base = accepted_ts if accepted_ts is not None else now_s
    release_at = escrow_base + ESCROW_HOLD_SECONDS
    available_at = (accepted_ts + ESCROW_HOLD_SECONDS) if accepted_ts is not None else None
    credited_agent = str(order.get("assigned_agent") or agent_id or "aifa")[:48]
    client_key = str(order.get("client_key") or "")
    client_source = str(order.get("client_source") or "")
    lock_info: dict[str, Any] | None = None

    with _lock_of(memory):
        conn = memory.store.conn
        if client_key:
            _expire_stale_client_locks_locked(conn, memory.user_id, now_s)
            active_lock = _active_client_lock_locked(conn, memory.user_id, client_key, now_s)
            if active_lock is not None:
                # Повторная оплаченная сделка в пределах 90 дней засчитывается закреплённому агенту.
                credited_agent = str(active_lock["agent_id"] or credited_agent)[:48]
                new_until = max(float(active_lock["locked_until_ts"]), now_s + CLIENT_LOCK_SECONDS)
                new_cnt = int(active_lock["orders_count"] or 1) + 1
                conn.execute(
                    "UPDATE ark_client_agent_lock SET last_order_id = ?, orders_count = ?, locked_until_ts = ?, updated_at = ? "
                    "WHERE lock_id = ? AND user_id = ?",
                    (order_id, new_cnt, new_until, now_s, active_lock["lock_id"], memory.user_id),
                )
                lock_info = {
                    "lock_id": active_lock["lock_id"],
                    "client_key": client_key,
                    "client_source": str(active_lock["client_source"] or client_source),
                    "agent_id": credited_agent,
                    "orders_count": new_cnt,
                    "locked_from_ts": float(active_lock["locked_from_ts"]),
                    "locked_until_ts": new_until,
                    "locked_until_date": _date_utc(new_until),
                    "status": "active",
                }
            else:
                # Первая оплаченная сделка (или новое закрепление после снятия старого через 90 дней).
                new_until = now_s + CLIENT_LOCK_SECONDS
                existing_row = conn.execute(
                    "SELECT lock_id FROM ark_client_agent_lock WHERE user_id = ? AND client_key = ?",
                    (memory.user_id, client_key),
                ).fetchone()
                if existing_row is not None:
                    lck_id = str(existing_row["lock_id"])
                    conn.execute(
                        "UPDATE ark_client_agent_lock SET client_source = ?, agent_id = ?, first_order_id = ?, last_order_id = ?, "
                        "orders_count = 1, locked_from_ts = ?, locked_until_ts = ?, status = 'active', released_at = NULL, updated_at = ? "
                        "WHERE lock_id = ? AND user_id = ?",
                        (client_source, credited_agent, order_id, order_id, now_s, new_until, now_s, lck_id, memory.user_id),
                    )
                else:
                    lck_id = f"clk-{uuid.uuid4().hex[:10]}"
                    conn.execute(
                        "INSERT INTO ark_client_agent_lock "
                        "(lock_id, user_id, client_key, client_source, agent_id, first_order_id, last_order_id, "
                        "orders_count, locked_from_ts, locked_until_ts, status, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'active', ?, ?)",
                        (lck_id, memory.user_id, client_key, client_source, credited_agent, order_id, order_id, now_s, new_until, now_s, now_s),
                    )
                lock_info = {
                    "lock_id": lck_id,
                    "client_key": client_key,
                    "client_source": client_source,
                    "agent_id": credited_agent,
                    "orders_count": 1,
                    "locked_from_ts": now_s,
                    "locked_until_ts": new_until,
                    "locked_until_date": _date_utc(new_until),
                    "status": "active",
                }

        ref_eco = _distribute_referral_and_burn(memory, order_id, split["platform_fee_usdt"])
        conn.execute(
            "INSERT INTO ark_monetization_ledger (ledger_id, user_id, source_type, gross_usdt, platform_fee_usdt, agent_compute_usdt, ecosystem_json, note, created_at) "
            "VALUES (?, ?, 'freelance_order', ?, ?, ?, ?, ?, ?)",
            (
                lid,
                memory.user_id,
                gross,
                split["platform_fee_usdt"],
                split["agent_compute_usdt"],
                json.dumps({**split["ecosystem_split_usdt"], "referral_burn_split": ref_eco}, ensure_ascii=False),
                f"Заказ {order_id} ({order['platform']}, {split['settlement_currency']})",
                now_s,
            ),
        )
        conn.execute(
            "INSERT INTO ark_owner_payout_hold (hold_id, user_id, order_id, gross_usdt, owner_net_usdt, currency, status, created_at, release_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'held_14d', ?, ?)",
            (hid, memory.user_id, order_id, gross, split["owner_net_usdt"], split["settlement_currency"], now_s, release_at),
        )
        inv_id = f"cinv-{uuid.uuid4().hex[:10]}"
        plat_l = str(order.get("platform") or "").strip().lower()
        rail = "auto_split" if plat_l in AUTO_SPLIT_PLATFORMS else "manual_exchange_remit"
        inv_status = "auto_split_settled" if rail == "auto_split" else "invoice_due"
        inv_paid_at = now_s if rail == "auto_split" else None
        inv_sig = _sign_fee_invoice(memory, inv_id, order_id, float(split["platform_fee_usdt"]), CODE_TREASURY_WALLET_SOLANA)
        conn.execute(
            "INSERT OR IGNORE INTO ark_code_fee_invoice "
            "(invoice_id, user_id, order_id, platform, gross_usdt, fee_pct, fee_usdt, treasury_wallet, settlement_rail, status, auto_split_tx, due_ts, paid_at, hmac_sig, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                inv_id,
                memory.user_id,
                order_id,
                plat_l,
                gross,
                float(split["platform_fee_pct"]),
                float(split["platform_fee_usdt"]),
                CODE_TREASURY_WALLET_SOLANA,
                rail,
                inv_status,
                (f"auto-split:{inv_id}" if rail == "auto_split" else ""),
                release_at,
                inv_paid_at,
                inv_sig,
                now_s,
            ),
        )
        conn.execute(
            "INSERT INTO ark_agent_ledger "
            "(ledger_entry_id, user_id, order_id, hold_id, agent_id, client_key, gross_usdt, agent_share_pct, "
            "agent_amount_usdt, currency, status, accepted_at, available_at, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?) "
            "ON CONFLICT(order_id) DO UPDATE SET hold_id=excluded.hold_id, agent_id=excluded.agent_id, "
            "gross_usdt=excluded.gross_usdt, agent_share_pct=excluded.agent_share_pct, "
            "agent_amount_usdt=excluded.agent_amount_usdt, currency=excluded.currency, status='pending', "
            "accepted_at=excluded.accepted_at, available_at=excluded.available_at, updated_at=excluded.updated_at",
            (
                aeid,
                memory.user_id,
                order_id,
                hid,
                credited_agent,
                client_key,
                gross,
                chosen_share,
                split["agent_compute_usdt"],
                split["settlement_currency"],
                accepted_ts,
                available_at,
                now_s,
                now_s,
            ),
        )
        conn.execute(
            "UPDATE ark_freelance_order SET status = 'paid', earned_usdt = ?, assigned_agent = ?, "
            "locked_agent_id = ?, client_locked_until_ts = ?, agent_payout_status = 'pending', updated_at = ? "
            "WHERE user_id = ? AND order_id = ?",
            (
                gross,
                credited_agent,
                lock_info["agent_id"] if lock_info else str(order.get("locked_agent_id") or ""),
                lock_info["locked_until_ts"] if lock_info else order.get("client_locked_until_ts"),
                now_s,
                memory.user_id,
                order_id,
            ),
        )
        conn.commit()

    earn_res = token_autonomy.record_agent_earning(
        memory,
        agent_id=credited_agent,
        source=f"freelance:{order['platform']}:{order_id}",
        revenue_usdt=gross,
        compute_share_pct=split["effective_gross_agent_pct"],
        note=f"Оплата ({split['settlement_currency']}): {order['title'][:80]}",
    )

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
        {
            "order_id": order_id,
            "gross_usdt": gross,
            "platform_fee_usdt": split["platform_fee_usdt"],
            "agent_compute_usdt": split["agent_compute_usdt"],
            "currency": split["settlement_currency"],
        },
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
        "credited_agent": credited_agent,
        "client_lock": lock_info,
        "agent_payout": {"status": "pending", "agent_id": credited_agent, "amount_usdt": split["agent_compute_usdt"], "hold_id": hid, "available_at": available_at},
        "payout_hold": {"hold_id": hid, "status": "held_14d", "hold_days": ESCROW_HOLD_DAYS, "owner_net_usdt": split["owner_net_usdt"], "release_at": release_at},
        "referral_ecosystem_split": ref_eco,
        "code_fee_invoice": {
            "invoice_id": inv_id,
            "fee_usdt": float(split["platform_fee_usdt"]),
            "treasury_wallet": CODE_TREASURY_WALLET_SOLANA,
            "settlement_rail": rail,
            "status": inv_status,
        },
    }


@_synchronized_memory
def verify_and_process_webhook(
    memory,
    raw_body: bytes,
    signature_hex: str,
    *,
    account_id: str = "",
) -> dict[str, Any]:
    """Проверяет HMAC-SHA256 подпись входящего вебхука биржи и при событии оплаты автоматически зачисляет средства."""
    _ensure(memory)
    secret = ""
    if account_id:
        acc = _get_account_row(memory, account_id)
        secret = _unseal_secret(memory, acc.get("webhook_secret_enc") or "")
    if not secret:
        secret = os.environ.get("PADAM_FREELANCE_WEBHOOK_SECRET", "").strip()
    if not secret:
        raise PermissionError("Секрет вебхука не настроен для аккаунта или PADAM_FREELANCE_WEBHOOK_SECRET.")

    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    provided = str(signature_hex or "").strip().lower()
    if provided.startswith("sha256="):
        provided = provided[7:]
    if not hmac.compare_digest(expected.lower(), provided):
        raise PermissionError("Неверная HMAC-SHA256 подпись вебхука биржи.")

    data = json.loads(raw_body.decode("utf-8"))
    ev = str(data.get("event") or "").strip().lower()
    if ev == "order.paid":
        order_id = str(data.get("order_id") or "").strip()
        if not order_id:
            raise ValueError("Не указан order_id в вебхуке order.paid.")
        # AUT-07: agent_id, agent_share_pct и settlement_currency НЕ принимаются из тела вебхука — только из БД/настроек владельца
        order = _get_order(memory, order_id)
        trusted_agent = str(order.get("assigned_agent") or "").strip()
        if not trusted_agent and account_id:
            acc_row = _get_account_row(memory, account_id)
            trusted_agent = str(acc_row.get("agent_id") or "").strip()
        # GLM раунд 3, FA-02: сумма из тела вебхука не выше бюджета заказа из НАШЕЙ базы (как AUT-07 для агента и доли).
        # Меньше — частичная оплата, принимается; больше — срезается до бюджета, расхождение пишется в аудит.
        budget = float(order.get("budget_usdt") or 0.0)
        try:
            body_paid = float(data.get("paid_usdt")) if data.get("paid_usdt") is not None else None
        except (TypeError, ValueError):
            body_paid = None
        safe_paid = body_paid
        if body_paid is not None and budget > 0 and body_paid > budget:
            safe_paid = budget
            audit_chain.append_audit(memory, "freelance_webhook_paid_capped",
                                     {"order_id": order_id, "body_paid_usdt": body_paid, "budget_usdt": budget},
                                     agent_id=trusted_agent or "system")
        return settle_paid_order(
            memory,
            order_id,
            paid_usdt=safe_paid,
            agent_id=trusted_agent or "aifa",
            agent_share_pct=None,
            settlement_currency=None,
        )
    if ev == "job.new":
        return evaluate_and_ingest_job(
            memory,
            platform=str(data.get("platform") or "custom_webhook"),
            title=str(data.get("title") or "Webhook Job"),
            brief=str(data.get("brief") or "No brief"),
            budget_usdt=float(data.get("budget_usdt") or 0.0),
            estimated_tokens=int(data.get("estimated_tokens") or 25000),
            account_id=account_id,
            external_job_id=str(data.get("external_job_id") or ""),
        )
    return {"ok": True, "event": ev, "ignored": True}


@_synchronized_memory
def freelance_dashboard_snapshot(memory) -> dict[str, Any]:
    """Собирает единую сводку для вкладки Studio «Автономный заработок», MCP и CLI."""
    _ensure(memory)
    prefs = get_freelance_prefs(memory)
    accounts = list_exchange_accounts(memory)
    orders = list_orders(memory, limit=30)
    suggestions = list_profile_suggestions(memory, limit=15)
    treasury = token_autonomy.treasury_summary(memory)
    proposals = token_autonomy.list_topup_proposals(memory)
    budget_tick = token_autonomy.run_budget_timer_tick(memory, auto_propose_if_low=False)
    spend_rec = token_autonomy.recommend_optimal_spend(
        memory,
        settlement_currency=prefs["settlement_currency"],
        galatin_price_usdt=prefs["galatin_price_usdt"],
    )
    locks = freelance_locks_status()

    conn = memory.store.conn
    with _lock_of(memory):
        r_mon = conn.execute(
            "SELECT COALESCE(SUM(gross_usdt), 0.0) AS g, COALESCE(SUM(platform_fee_usdt), 0.0) AS f, "
            "COALESCE(SUM(agent_compute_usdt), 0.0) AS c FROM ark_monetization_ledger WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
    total_gross = round(float(r_mon["g"] or 0.0), 4)
    total_fee = round(float(r_mon["f"] or 0.0), 4)
    total_comp = round(float(r_mon["c"] or 0.0), 4)

    # Grok-аудит 18.11, п. 13: одна строка для владельца — что происходит и что требует его внимания.
    _ap = get_autopilot_state(memory)
    _drafts = sum(1 for o in orders if str(o.get("status") or "") == "bid_draft")
    _reauth = sum(1 for a in accounts if str(a.get("status") or "") == "needs_reauth")
    _attention = _drafts + _reauth
    owner_summary_ru = (
        f"Автопилот: {'работает' if _ap.get('autopilot_running') else 'остановлен'}; заказов: {len(orders)}; "
        f"требует вашего внимания: {_attention}"
        + (f" (черновиков откликов к отправке: {_drafts}" if _drafts else "")
        + (f"{', ' if _drafts else ' ('}повторный вход на площадках: {_reauth}" if _reauth else "")
        + (")" if _attention else "") + "."
    )
    owner_summary_en = (
        f"Autopilot: {'running' if _ap.get('autopilot_running') else 'stopped'}; orders: {len(orders)}; "
        f"need your attention: {_attention}."
    )
    return {
        "ok": True,
        "owner_summary_ru": owner_summary_ru,
        "owner_summary_en": owner_summary_en,
        "prefs": prefs,
        "locks": locks,
        "accounts": accounts,
        "orders": orders,
        "profile_suggestions": suggestions,
        "treasury": treasury,
        "proposals": proposals,
        "budget": budget_tick,
        "spend_recommendation": spend_rec,
        "payout_hold": payout_summary(memory),
        "client_locks": get_client_lock_status(memory)["locks"],
        "agent_ledger": get_agent_ledger(memory),
        "referral": get_or_create_referral_profile(memory),
        "autopilot": get_autopilot_state(memory),
        "monetization_totals": {
            "fixed_platform_fee_pct": FIXED_PLATFORM_FEE_PCT,
            "platform_fee_pct_by_mode": {"assisted": ASSISTED_FEE_PCT, "autopilot": AUTOPILOT_FEE_PCT},
            "total_gross_usdt": total_gross,
            "total_platform_fee_usdt": total_fee,
            "total_agent_compute_usdt": total_comp,
            "ecosystem_reference": monetization_breakdown(
                max(total_gross, 100.0),
                agent_share_pct=prefs["agent_share_pct"],
                settlement_currency=prefs["settlement_currency"],
                galatin_price_usdt=prefs["galatin_price_usdt"],
            ),
        },
        "supported_platforms": list(SUPPORTED_PLATFORMS),
        "supported_modes": list(SUPPORTED_MODES),
        "supported_currencies": list(SUPPORTED_CURRENCIES),
        "digital_stores": _digital_stores_safe(memory),
        "platform_wizard": _platform_wizard_safe(memory),
    }


def _platform_wizard_safe(memory) -> dict[str, Any]:
    from . import platform_wizard
    return platform_wizard.platform_wizard_snapshot(memory)


def _digital_stores_safe(memory) -> dict[str, Any]:
    from . import digital_stores
    return digital_stores.digital_stores_snapshot(memory, auto_seed_starters=True)


@_synchronized_memory
def get_or_create_referral_profile(memory) -> dict[str, Any]:
    """Возвращает (или создаёт) реферальный код/ссылку пользователя для приглашения в PADAM MCP и приложение."""
    _ensure(memory)
    row = memory.store.conn.execute(
        "SELECT * FROM ark_referral_profile WHERE user_id = ?", (memory.user_id,)
    ).fetchone()
    if row:
        d = dict(row)
        d["referral_link"] = f"https://codeofdigitaleternity.com/?ref={d['ref_code']}"
        return d

    code = "CODE-" + hashlib.sha256(f"ref:{memory.user_id}".encode("utf-8")).hexdigest()[:8].upper()
    now = time.time()
    memory.store.conn.execute(
        "INSERT INTO ark_referral_profile (user_id, ref_code, created_at) VALUES (?, ?, ?)",
        (memory.user_id, code, now),
    )
    memory.store.conn.commit()
    return {
        "user_id": memory.user_id,
        "ref_code": code,
        "referral_link": f"https://codeofdigitaleternity.com/?ref={code}",
        "referred_by_l1": "",
        "referred_by_l2": "",
        "referred_by_l3": "",
        "created_at": now,
    }


@_synchronized_memory
def bind_referrer_code(memory, ref_code: str) -> dict[str, Any]:
    """Привязывает 3-уровневую реферальную цепочку по пригласительному коду (защита от самореферала)."""
    prof = get_or_create_referral_profile(memory)
    clean_code = str(ref_code or "").strip().upper()
    if not clean_code or clean_code == prof["ref_code"]:
        raise ValueError("Нельзя указать пустой или собственный реферальный код.")
    inv = memory.store.conn.execute(
        "SELECT * FROM ark_referral_profile WHERE ref_code = ?", (clean_code,)
    ).fetchone()
    if not inv:
        raise ValueError(f"Реферальный код {clean_code} не найден.")
    l1 = str(inv["user_id"])
    l2 = str(inv["referred_by_l1"] or "")
    l3 = str(inv["referred_by_l2"] or "")
    if memory.user_id in (l1, l2, l3):
        raise ValueError("Обнаружен реферальный цикл.")
    memory.store.conn.execute(
        "UPDATE ark_referral_profile SET referred_by_l1=?, referred_by_l2=?, referred_by_l3=? WHERE user_id=?",
        (l1, l2, l3, memory.user_id),
    )
    memory.store.conn.commit()
    return get_or_create_referral_profile(memory)


def _distribute_referral_and_burn(memory, order_id: str, platform_fee_usdt: float) -> dict[str, Any]:
    """Распределяет 10% комиссию CODE строго по канону $GALATIN: 5% Фонд + 5..30% Сжигание + 15/7/3% амбассадоры + 65% Казна."""
    prof = get_or_create_referral_profile(memory)
    l1, l2, l3 = prof.get("referred_by_l1") or "", prof.get("referred_by_l2") or "", prof.get("referred_by_l3") or ""
    now = time.time()
    burn_pct = 5.0
    ambassadors_paid: list[dict[str, Any]] = []
    tiers = ((1, l1, 15.0), (2, l2, 7.0), (3, l3, 3.0))
    for lvl, target_uid, pct in tiers:
        if target_uid:
            amt = round(platform_fee_usdt * (pct / 100.0), 4)
            rid = f"rwd-{uuid.uuid4().hex[:10]}"
            # Аудит фазы 3, FA-10: одно начисление на заказ и уровень (уникальный индекс + OR IGNORE) — повтор не удвоит.
            cur_rw = memory.store.conn.execute(
                "INSERT OR IGNORE INTO ark_referral_reward (reward_id, order_id, from_user_id, to_user_id, tier_level, pct_of_fee, amount_usdt, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (rid, order_id, memory.user_id, target_uid, lvl, pct, amt, now),
            )
            ambassadors_paid.append({"level": lvl, "to_user_id": target_uid, "pct_of_fee": pct, "amount_usdt": amt,
                                     **({} if cur_rw.rowcount else {"duplicate": True})})
        else:
            # Пустые амбассадорские уровни уходят в сжигание (до максимума 30%: 5 + 15 + 7 + 3)
            burn_pct += pct

    fund_pct = 5.0
    treasury_pct = 65.0
    amb_pct_total = sum(a["pct_of_fee"] for a in ambassadors_paid)
    pct_sum = deterministic_verify.verify_percentage_sum([fund_pct, burn_pct, amb_pct_total, treasury_pct], expected_total=100.0)
    return {
        "fund_usdt": round(platform_fee_usdt * (fund_pct / 100.0), 4),
        "burn_pct": burn_pct,
        "burn_usdt": round(platform_fee_usdt * (burn_pct / 100.0), 4),
        "treasury_usdt": round(platform_fee_usdt * (treasury_pct / 100.0), 4),
        "ambassadors_pct": amb_pct_total,
        "ambassadors_paid": ambassadors_paid,
        "percentage_sum_verified": bool(pct_sum.get("valid")),
    }


@_synchronized_memory
def accept_delivery(
    memory,
    order_id: str,
    *,
    accepted_by: str = "client",
    now_ts: float | None = None,
    actor=None,
) -> dict[str, Any]:
    """Фиксирует приёмку работы клиентом (accepted) и открывает 14-дневное окно претензий в эскроу."""
    # GLM раунд 3, Паттерн 1 (18.11.2026): замок владельца внутри, а не только у вызывающего. API передаёт актёра;
    # агент с ролью не-владельца получит PermissionError, даже если найдёт обходной путь к функции.
    from . import roles as _roles
    _roles.require_owner(actor, "accept_delivery")
    order = _get_order(memory, order_id)
    if order["status"] in ("rejected_security", "refunded", "rejected_client"):
        return {"ok": False, "order_id": order_id, "error": f"Приёмка невозможна: статус заказа {order['status']!r}."}
    now_s = float(now_ts if now_ts is not None else time.time())
    release_at = now_s + ESCROW_HOLD_SECONDS
    new_status = "accepted" if order["status"] != "paid" else "paid"
    with _lock_of(memory):
        conn = memory.store.conn
        conn.execute(
            "UPDATE ark_freelance_order SET status = ?, accepted_at = COALESCE(accepted_at, ?), updated_at = ? "
            "WHERE user_id = ? AND order_id = ?",
            (new_status, now_s, now_s, memory.user_id, order_id),
        )
        # Привязываем эскроу-холд и долю агента к моменту приёмки (accepted_at + 14 дней).
        row_acc = conn.execute(
            "SELECT accepted_at FROM ark_freelance_order WHERE user_id = ? AND order_id = ?",
            (memory.user_id, order_id),
        ).fetchone()
        eff_acc = float(row_acc["accepted_at"]) if row_acc and row_acc["accepted_at"] else now_s
        eff_release = eff_acc + ESCROW_HOLD_SECONDS
        conn.execute(
            "UPDATE ark_owner_payout_hold SET release_at = MAX(release_at, ?) "
            "WHERE user_id = ? AND order_id = ? AND status = 'held_14d'",
            (eff_release, memory.user_id, order_id),
        )
        conn.execute(
            "UPDATE ark_agent_ledger SET accepted_at = COALESCE(accepted_at, ?), "
            "available_at = MAX(COALESCE(available_at, 0.0), ?), updated_at = ? "
            "WHERE user_id = ? AND order_id = ? AND status = 'pending'",
            (eff_acc, eff_release, now_s, memory.user_id, order_id),
        )
        conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_delivery_accepted",
        {"order_id": order_id, "accepted_by": str(accepted_by or "client")[:48], "escrow_release_at": eff_release},
        agent_id=str(order.get("assigned_agent") or "aifa"),
    )
    return {
        "ok": True,
        "order_id": order_id,
        "status": new_status,
        "delivery_accepted": True,
        "accepted_at": eff_acc,
        "accepted_iso": _iso_utc(eff_acc),
        "escrow_release_at": eff_release,
        "escrow_release_date": _date_utc(eff_release),
        "agent_payout_status": order.get("agent_payout_status") or "pending",
    }


@_synchronized_memory
def release_matured_payouts(memory, *, now_ts: float | None = None) -> dict[str, Any]:
    """Переводит в статус releasable/credited выплаты, где заказ принят (accepted) и истекло 14-дневное окно претензий."""
    _ensure(memory)
    now = float(now_ts if now_ts is not None else time.time())
    released_holds = 0
    credited_agents = 0
    with _lock_of(memory):
        conn = memory.store.conn
        # 1. Холды владельца, чей 14-дневный срок истёк -> releasable.
        cur_holds = conn.execute(
            "UPDATE ark_owner_payout_hold SET status = 'releasable', resolved_at = COALESCE(resolved_at, ?) "
            "WHERE user_id = ? AND status = 'held_14d' AND release_at <= ?",
            (now, memory.user_id, now),
        )
        released_holds = int(cur_holds.rowcount or 0)
        # 2. Доля агента в ark_agent_ledger начисляется ТОЛЬКО после accepted и истечения 14д после accepted.
        pending_entries = conn.execute(
            "SELECT l.ledger_entry_id, l.order_id, l.available_at, o.accepted_at, h.status AS hold_status "
            "FROM ark_agent_ledger l "
            "LEFT JOIN ark_freelance_order o ON o.user_id = l.user_id AND o.order_id = l.order_id "
            "LEFT JOIN ark_owner_payout_hold h ON h.user_id = l.user_id AND h.hold_id = l.hold_id "
            "WHERE l.user_id = ? AND l.status = 'pending'",
            (memory.user_id,),
        ).fetchall()
        for entry in pending_entries:
            acc_ts = entry["accepted_at"]
            if acc_ts is None:
                continue
            if entry["hold_status"] == "refunded":
                continue
            avail_ts = max(float(entry["available_at"] or 0.0), float(acc_ts) + ESCROW_HOLD_SECONDS)
            if now < avail_ts:
                continue
            cur_ag = conn.execute(
                "UPDATE ark_agent_ledger SET status = 'credited', credited_at = ?, updated_at = ? "
                "WHERE ledger_entry_id = ? AND user_id = ? AND status = 'pending'",
                (now, now, entry["ledger_entry_id"], memory.user_id),
            )
            credited_agents += int(cur_ag.rowcount or 0)
            conn.execute(
                "UPDATE ark_freelance_order SET agent_payout_status = 'credited', updated_at = ? "
                "WHERE user_id = ? AND order_id = ? AND COALESCE(agent_payout_status, '') IN ('', 'pending')",
                (now, memory.user_id, entry["order_id"]),
            )
        conn.commit()
    return {
        "ok": True,
        "released_count": released_holds,
        "credited_agent_entries": credited_agents,
        "summary": payout_summary(memory),
        "agent_ledger": get_agent_ledger(memory),
    }


@_synchronized_memory
def dispute_held_payout(
    memory,
    hold_id: str = "",
    *,
    order_id: str = "",
    reason: str = "Client dispute refund",
    now_ts: float | None = None,
    actor=None,
) -> dict[str, Any]:
    """Обрабатывает отказ клиента / возврат: переводит холд в refunded и отменяет начисление агенту с записью причины."""
    # GLM раунд 3, FA-03: отмена выплаты двигает деньги — только владелец (как settle_paid, SOV-04).
    from . import roles as _roles
    _roles.require_owner(actor, "dispute_payout")
    _ensure(memory)
    now_s = float(now_ts if now_ts is not None else time.time())
    clean_reason, _ = safety.redact(str(reason or "Client dispute refund").strip() or "Client dispute refund")
    clean_reason = clean_reason[:240]
    with _lock_of(memory):
        conn = memory.store.conn
        row = None
        if str(hold_id or "").strip():
            row = conn.execute(
                "SELECT * FROM ark_owner_payout_hold WHERE user_id = ? AND hold_id = ?",
                (memory.user_id, str(hold_id).strip()),
            ).fetchone()
            if not row:
                raise ValueError(f"Холд {hold_id} не найден.")
        elif str(order_id or "").strip():
            row = conn.execute(
                "SELECT * FROM ark_owner_payout_hold WHERE user_id = ? AND order_id = ? ORDER BY created_at DESC LIMIT 1",
                (memory.user_id, str(order_id).strip()),
            ).fetchone()
        eff_order_id = str(row["order_id"] if row is not None else order_id or "").strip()
        if not eff_order_id:
            raise ValueError("Необходимо указать hold_id или order_id.")

        refunded_usdt = 0.0
        eff_hold_id = str(row["hold_id"]) if row is not None else ""
        if row is not None:
            if row["status"] != "held_14d":
                raise ValueError(f"Спор невозможен: статус холда уже {row['status']!r}.")
            refunded_usdt = float(row["owner_net_usdt"])
            conn.execute(
                "UPDATE ark_owner_payout_hold SET status = 'refunded', dispute_reason = ?, resolved_at = ? "
                "WHERE hold_id = ? AND user_id = ?",
                (clean_reason, now_s, eff_hold_id, memory.user_id),
            )
        conn.execute(
            "UPDATE ark_agent_ledger SET status = 'cancelled', cancel_reason = ?, cancelled_at = ?, updated_at = ? "
            "WHERE user_id = ? AND order_id = ? AND status IN ('pending', 'credited')",
            (clean_reason, now_s, now_s, memory.user_id, eff_order_id),
        )
        conn.execute(
            "UPDATE ark_freelance_order SET status = 'refunded', agent_payout_status = 'cancelled', "
            "payout_cancel_reason = ?, updated_at = ? WHERE user_id = ? AND order_id = ?",
            (clean_reason, now_s, memory.user_id, eff_order_id),
        )
        # GLM раунд 3, FA-05: возврат отменял выплату агенту, но начисление в казну агента оставалось — сводка казны
        # была завышена и планировщик советовал лишнее пополнение. Добавляем обратную запись (история не стирается).
        try:
            token_autonomy._ensure(memory)
            src_like = f"freelance:%:{eff_order_id}"
            already = conn.execute(
                "SELECT 1 FROM ark_earned_treasury WHERE user_id = ? AND source LIKE ? AND revenue_usdt < 0 LIMIT 1",
                (memory.user_id, src_like),
            ).fetchone()
            if not already:
                for er in conn.execute(
                    "SELECT agent_id, source, revenue_usdt, compute_share_pct, allocated_compute_usdt FROM ark_earned_treasury "
                    "WHERE user_id = ? AND source LIKE ? AND revenue_usdt > 0",
                    (memory.user_id, src_like),
                ).fetchall():
                    conn.execute(
                        "INSERT INTO ark_earned_treasury (entry_id, user_id, agent_id, source, revenue_usdt, compute_share_pct, "
                        "allocated_compute_usdt, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (f"ern-{uuid.uuid4().hex[:10]}", memory.user_id, er["agent_id"], er["source"],
                         -float(er["revenue_usdt"]), float(er["compute_share_pct"]), -float(er["allocated_compute_usdt"]),
                         ("Возврат по спору: " + clean_reason)[:240], now_s),
                    )
        except Exception:
            pass
        conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_payout_dispute_refunded",
        {"hold_id": eff_hold_id, "order_id": eff_order_id, "refunded_usdt": refunded_usdt, "reason": clean_reason},
        agent_id="owner",
    )
    return {
        "ok": True,
        "hold_id": eff_hold_id,
        "order_id": eff_order_id,
        "status": "refunded",
        "agent_payout_status": "cancelled",
        "cancel_reason": clean_reason,
        "refunded_usdt": refunded_usdt,
    }


def get_client_lock_status(
    memory,
    *,
    client_email: str = "",
    client_domain: str = "",
    client_external_id: str = "",
    client_ref: str = "",
    client_key: str = "",
    platform: str = "",
    now_ts: float | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Чистое чтение таблицы закреплений клиентов за агентами (90 дней с первой оплаченной сделки)."""
    _ensure(memory)
    now_s = float(now_ts if now_ts is not None else time.time())
    lim = max(1, min(200, int(limit)))
    target_key = str(client_key or "").strip()
    target_src = ""
    if not target_key:
        target_key, target_src = _normalize_client_identity(
            platform,
            client_email=client_email,
            client_domain=client_domain,
            client_external_id=client_external_id,
            client_ref=client_ref,
        )
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT * FROM ark_client_agent_lock WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
            (memory.user_id, lim),
        ).fetchall()
    items: list[dict[str, Any]] = []
    matched: dict[str, Any] | None = None
    for r in rows:
        d = dict(r)
        eff_status = "expired" if (d["status"] == "active" and now_s >= float(d["locked_until_ts"])) else str(d["status"])
        rem_s = max(0.0, float(d["locked_until_ts"]) - now_s) if eff_status == "active" else 0.0
        item = {
            **d,
            "status": eff_status,
            "locked_from_iso": _iso_utc(d["locked_from_ts"]),
            "locked_from_date": _date_utc(d["locked_from_ts"]),
            "locked_until_iso": _iso_utc(d["locked_until_ts"]),
            "locked_until_date": _date_utc(d["locked_until_ts"]),
            "days_remaining": round(rem_s / 86400.0, 2),
        }
        items.append(item)
        if target_key and d["client_key"] == target_key:
            matched = item
    return {
        "ok": True,
        "lock_days": CLIENT_LOCK_DAYS,
        "queried_client_key": target_key,
        "queried_client_source": target_src,
        "locked": bool(matched and matched["status"] == "active"),
        "match": matched,
        "active_count": sum(1 for x in items if x["status"] == "active"),
        "locks": items,
    }


@_synchronized_memory
def release_expired_client_locks(memory, *, now_ts: float | None = None) -> dict[str, Any]:
    """Явно переводит в статус expired все 90-дневные закрепления без новых сделок."""
    _ensure(memory)
    now_s = float(now_ts if now_ts is not None else time.time())
    with _lock_of(memory):
        cnt = _expire_stale_client_locks_locked(memory.store.conn, memory.user_id, now_s)
        memory.store.conn.commit()
    return {"ok": True, "expired_count": cnt, **get_client_lock_status(memory, now_ts=now_s)}


def get_agent_ledger(memory, *, agent_id: str = "", limit: int = 50) -> dict[str, Any]:
    """Чистое чтение учёта начислений агентов (pending до accepted+14д, credited после, cancelled при возврате)."""
    _ensure(memory)
    lim = max(1, min(200, int(limit)))
    aid = str(agent_id or "").strip()
    with _lock_of(memory):
        conn = memory.store.conn
        if aid:
            rows = conn.execute(
                "SELECT * FROM ark_agent_ledger WHERE user_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT ?",
                (memory.user_id, aid, lim),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ark_agent_ledger WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                (memory.user_id, lim),
            ).fetchall()
    entries: list[dict[str, Any]] = []
    pending_usdt = 0.0
    credited_usdt = 0.0
    cancelled_usdt = 0.0
    for r in rows:
        d = dict(r)
        amt = float(d["agent_amount_usdt"] or 0.0)
        st = str(d["status"] or "pending")
        if st == "credited":
            credited_usdt += amt
        elif st == "cancelled":
            cancelled_usdt += amt
        else:
            pending_usdt += amt
        entries.append({
            **d,
            "accepted_iso": _iso_utc(d.get("accepted_at")),
            "available_iso": _iso_utc(d.get("available_at")),
            "available_date": _date_utc(d.get("available_at")),
            "credited_iso": _iso_utc(d.get("credited_at")),
            "cancelled_iso": _iso_utc(d.get("cancelled_at")),
        })
    return {
        "ok": True,
        "agent_id": aid or "all",
        "hold_days": ESCROW_HOLD_DAYS,
        "pending_usdt": round(pending_usdt, 4),
        "credited_usdt": round(credited_usdt, 4),
        "cancelled_usdt": round(cancelled_usdt, 4),
        "total_entries": len(entries),
        "entries": entries,
        "ledger_only": True,
        "note": "Учёт начислений без перевода средств; реальный вывод регулируется PADAM_TREASURY_AUTOPAY и владельцем.",
    }


@_synchronized_memory
def payout_summary(memory) -> dict[str, Any]:
    """Возвращает сводку по 14-дневному эскроу-холду и доступным к выводу средствам владельца."""
    _ensure(memory)
    conn = memory.store.conn
    rows = conn.execute(
        "SELECT * FROM ark_owner_payout_hold WHERE user_id = ? ORDER BY created_at DESC LIMIT 30",
        (memory.user_id,),
    ).fetchall()
    held = round(sum(float(r["owner_net_usdt"]) for r in rows if r["status"] == "held_14d"), 4)
    releasable = round(sum(float(r["owner_net_usdt"]) for r in rows if r["status"] == "releasable"), 4)
    refunded = round(sum(float(r["owner_net_usdt"]) for r in rows if r["status"] == "refunded"), 4)
    return {
        "hold_days": ESCROW_HOLD_DAYS,
        "held_14d_usdt": held,
        "releasable_usdt": releasable,
        "refunded_dispute_usdt": refunded,
        "holds": [dict(r) for r in rows[:10]],
    }


def _try_refresh_oauth_token(memory, acc: dict[str, Any], *, allow_localhost: bool = False) -> str | None:
    """Автоматически продлевает OAuth access_token через зашифрованный refresh_token без повторного ввода пароля."""
    rtok = _unseal_secret(memory, acc.get("refresh_token_enc") or "")
    rurl = str(acc.get("refresh_url") or "").strip()
    if not rtok or not rurl:
        return None
    clean_rurl = _validate_api_url(rurl, allow_localhost=allow_localhost)
    local_allowed = bool(allow_localhost or (os.environ.get("PADAM_FREELANCE_ALLOW_LOCALHOST", "").strip() == "1"))
    req_body = json.dumps({"grant_type": "refresh_token", "refresh_token": rtok}).encode("utf-8")
    req = urllib.request.Request(
        clean_rurl,
        data=req_body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with net_guard.safe_urlopen(
            req,
            timeout=8.0,
            allow_localhost=local_allowed,
            allow_ipv6_loopback=False,
            allow_http_localhost=True,
            require_https=True,
        ) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        new_acc = str(data.get("access_token") or "").strip()
        if not new_acc:
            return None
        new_ref = str(data.get("refresh_token") or rtok).strip()
        exp_in = float(data.get("expires_in") or 3600.0)
        memory.store.conn.execute(
            "UPDATE ark_exchange_account SET token_enc=?, token_hash_prefix=?, refresh_token_enc=?, token_expires_at=?, status='active', updated_at=? "
            "WHERE account_id=? AND user_id=?",
            (
                _seal_secret(memory, new_acc),
                hashlib.sha256(new_acc.encode("utf-8")).hexdigest()[:12],
                _seal_secret(memory, new_ref),
                time.time() + max(60.0, exp_in),
                time.time(),
                acc["account_id"],
                memory.user_id,
            ),
        )
        memory.store.conn.commit()
        audit_chain.append_audit(
            memory,
            "freelance_oauth_refreshed",
            {"account_id": acc["account_id"], "platform": acc["platform"]},
            agent_id=acc["agent_id"],
        )
        return new_acc
    except Exception:
        return None


@_synchronized_memory
def get_autopilot_state(memory) -> dict[str, Any]:
    """Возвращает состояние непрерывного цикла биржевого автопилота (включен/остановлен)."""
    _ensure(memory)
    row = memory.store.conn.execute(
        "SELECT autopilot_running, autopilot_interval_s, autopilot_last_tick_at, autopilot_last_note "
        "FROM ark_freelance_prefs WHERE user_id = ?",
        (memory.user_id,),
    ).fetchone()
    if not row:
        return {
            "autopilot_running": False,
            "interval_s": 300.0,
            "last_tick_at": 0.0,
            "last_note": "Остановлен (включается кнопкой Старт владельцем).",
        }
    return {
        "autopilot_running": bool(row["autopilot_running"]),
        "interval_s": float(row["autopilot_interval_s"] or 300.0),
        "last_tick_at": float(row["autopilot_last_tick_at"] or 0.0),
        "last_note": str(row["autopilot_last_note"] or ""),
    }


@_synchronized_memory
def set_autopilot_state(memory, *, running: bool, interval_s: float = 300.0, note: str = "", actor=None) -> dict[str, Any]:
    """Включает или останавливает непрерывный цикл работы агентов на биржах (до команды владельца)."""
    # GLM раунд 3, Паттерн 1 (18.11.2026): замок владельца внутри, а не только у вызывающего. API передаёт актёра;
    # агент с ролью не-владельца получит PermissionError, даже если найдёт обходной путь к функции.
    from . import roles as _roles
    _roles.require_owner(actor, "autopilot_start" if running else "autopilot_stop")
    _ensure(memory)
    fast_test = ("PYTEST_CURRENT_TEST" in os.environ) or (os.environ.get("PADAM_AUTOPILOT_FAST_TEST") == "1")
    min_iv = 5.0 if fast_test else 180.0
    iv = max(min_iv, min(86400.0, float(interval_s)))
    clean_note = note or ("Автопилот ЗАПУЩЕН: непрерывная работа до команды Стоп." if running else "Автопилот ОСТАНОВЛЕН владельцем.")
    memory.store.conn.execute(
        "INSERT INTO ark_freelance_prefs (user_id, agent_share_pct, settlement_currency, galatin_price_usdt, autopilot_running, autopilot_interval_s, autopilot_last_note, updated_at) "
        "VALUES (?, 15.0, 'USDT_TRC20', 0.01, ?, ?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET autopilot_running=excluded.autopilot_running, "
        "autopilot_interval_s=excluded.autopilot_interval_s, autopilot_last_note=excluded.autopilot_last_note, updated_at=excluded.updated_at",
        (memory.user_id, 1 if running else 0, iv, clean_note[:200], time.time()),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "freelance_autopilot_toggled",
        {"running": bool(running), "interval_s": iv},
        agent_id="owner",
    )
    return get_autopilot_state(memory)


_AUTOPILOT_WORKER_LOCK = threading.RLock()
_AUTOPILOT_WORKER_STOP = threading.Event()
_AUTOPILOT_WORKER_THREAD: threading.Thread | None = None


@_synchronized_memory
def run_autopilot_cycle(memory, *, allow_localhost: bool = False) -> dict[str, Any]:
    """Полный автономный цикл Роя: опрос бирж и магазинов -> отклики -> исполнение -> безопасная сдача -> выплаты."""
    st = get_autopilot_state(memory)
    if not st["autopilot_running"]:
        return {"ok": True, "skipped": True, "reason": "autopilot_stopped_by_owner", "state": st}
    # Блокировка автопилота при просрочке или подмене счетов комиссии CODE
    arrears = fee_arrears_guard(memory)
    if arrears.get("blocked"):
        return {
            "ok": False,
            "skipped": True,
            "reason": "code_fee_settlement_required",
            "arrears": arrears,
            "state": st,
        }

    accounts = list_exchange_accounts(memory)
    checked = 0
    fetched_total = 0
    reauth_needed: list[str] = []
    drafted = 0
    for acc_pub in accounts:
        if acc_pub["status"] != "active" or not acc_pub.get("api_base_url"):
            continue
        checked += 1
        res = fetch_jobs_from_exchange(memory, acc_pub["account_id"], allow_localhost=allow_localhost)
        if not res.get("ok") and res.get("http_status") == 401:
            reauth_needed.append(acc_pub["account_id"])
            memory.store.conn.execute(
                "UPDATE ark_exchange_account SET status = 'needs_reauth', updated_at = ? WHERE account_id = ? AND user_id = ?",
                (time.time(), acc_pub["account_id"], memory.user_id),
            )
        elif res.get("ok"):
            fetched_total += int(res.get("accepted_count") or 0)
            # Grok-аудит 18.11, п. 1: автопилот сразу готовит ЧЕРНОВИКИ откликов на принятые заказы (только текст из
            # памяти и профиля — draft_bid_from_memory ничего не отправляет; отправка — кнопкой владельца).
            for o in res.get("orders") or []:
                if o.get("ok") and o.get("order_id"):
                    try:
                        if draft_bid_from_memory(memory, str(o["order_id"])).get("ok"):
                            drafted += 1
                    except Exception:
                        pass

    # Шаг 2: опрос подключённых цифровых магазинов (5 autopilot-площадок)
    stores_synced = 0
    stores_sales_accepted = 0
    try:
        from . import digital_stores as _ds
        for st_row in _ds.list_connected_stores(memory):
            if str(st_row.get("status") or "") not in ("verified", "active", "connected"):
                continue
            stores_synced += 1
            s_res = _ds.sync_store_sales(memory, str(st_row["store_account_id"]), allow_localhost=allow_localhost)
            if s_res.get("ok"):
                stores_sales_accepted += int(s_res.get("imported_count") or s_res.get("synced_count") or 0)
    except Exception:
        pass

    # Шаг 3: автоотклик на проверенные заказы на площадках с включённым автопилотом
    bids_dispatched = 0
    orders_executed = 0
    deliveries_packaged = 0
    try:
        from . import platform_wizard as _pw
        _pw._ensure_stage3_schema(memory)
        ap_rows = memory.store.conn.execute(
            "SELECT platform_id FROM ark_platform_autopilot_config WHERE user_id = ? AND autopilot_enabled = 1 AND halted_reason = ''",
            (memory.user_id,),
        ).fetchall()
        ap_platforms = {str(r["platform_id"]) for r in ap_rows}
        if ap_platforms:
            cand_orders = memory.store.conn.execute(
                # 18.11 (слияние с черновиками Grok п. 1): заказ с готовым черновиком (bid_draft) на площадке с включённым
                # автопилотом тоже уходит автооткликом; на остальных площадках черновик ждёт кнопки владельца.
                "SELECT * FROM ark_freelance_order WHERE user_id = ? AND status IN ('new', 'evaluated', 'bid_draft') ORDER BY created_at ASC LIMIT 10",
                (memory.user_id,),
            ).fetchall()
            for orow in cand_orders:
                pid = str(orow["platform"] or "").lower()
                if pid not in ap_platforms:
                    continue
                d_res = _pw.dispatch_platform_autopilot_action(
                    memory,
                    platform_id=pid,
                    order_id=str(orow["order_id"]),
                    title=str(orow["title"] or ""),
                    brief=str(orow["brief_redacted"] or ""),
                    budget_usdt=float(orow["budget_usdt"] or 0.0),
                    agent_id=str(orow["assigned_agent"] or "aifa"),
                )
                if d_res.get("sent"):
                    bids_dispatched += 1

        # Шаг 4: исполнение и безопасная сдача принятых автопилотных заказов
        work_orders = memory.store.conn.execute(
            "SELECT * FROM ark_freelance_order WHERE user_id = ? AND platform_fee_pct >= 20.0 AND status IN ('accepted', 'bid_placed') ORDER BY created_at ASC LIMIT 5",
            (memory.user_id,),
        ).fetchall()
        for wrow in work_orders:
            oid = str(wrow["order_id"])
            aid = str(wrow["assigned_agent"] or "aifa")
            ex_res = execute_order_with_swarm(memory, oid, agent_id=aid)
            if ex_res.get("ok"):
                orders_executed += 1
                deliverable = (
                    f"Выполнено автономно агентом {aid} для площадки {wrow['platform']}.\n"
                    f"Задача: {wrow['title']}\n"
                    f"Статус проверки: пройдено (Swarm Council + deterministic_verify)."
                )
                pkg_res = package_safe_delivery(memory, oid, deliverable_text=deliverable, agent_id=aid)
                if pkg_res.get("ok"):
                    deliveries_packaged += 1
    except Exception as _ap_exc:
        raise RuntimeError(f'autopilot_step_error: {_ap_exc}') from _ap_exc

    # Шаг 4.5: подтягивание оплаченных заказов с сайта (service_orders -> Студия)
    site_orders_res: dict[str, Any] = {"imported": 0, "executed": 0}
    try:
        site_orders_res = sync_site_orders(memory, allow_localhost=allow_localhost)
    except Exception:
        pass

    # Шаг 4.6: 14-дневные перемеры доступности для выполненных аудитов/фиксов
    rechecks_completed = 0
    try:
        now_rc_tick = time.time()
        has_rc_tbl = memory.store.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ark_site_rechecks'"
        ).fetchone()
        if has_rc_tbl:
            rc_cols = {
                str(r["name"])
                for r in memory.store.conn.execute("PRAGMA table_info(ark_site_rechecks)").fetchall()
            }
            if "recheck_violations" not in rc_cols:
                memory.store.conn.execute(
                    "ALTER TABLE ark_site_rechecks ADD COLUMN recheck_violations INTEGER NOT NULL DEFAULT 0"
                )
            due_rows = memory.store.conn.execute(
                "SELECT recheck_id, website FROM ark_site_rechecks WHERE user_id = ? AND done_at = 0.0 AND due_at <= ? ORDER BY due_at ASC LIMIT 5",
                (memory.user_id, now_rc_tick),
            ).fetchall()
            if due_rows:
                from . import site_scanner as _ss
                for drow in due_rows:
                    w_url = str(drow["website"] or "").strip()
                    rc_v = 0
                    if w_url:
                        rc_scan = _ss.scan_website_accessibility(w_url, max_pages=25, allow_localhost=allow_localhost)
                        if rc_scan.get("ok"):
                            rc_v = int(rc_scan.get("total_violations") or 0)
                    memory.store.conn.execute(
                        "UPDATE ark_site_rechecks SET done_at = ?, recheck_violations = ? WHERE recheck_id = ?",
                        (time.time(), rc_v, str(drow["recheck_id"])),
                    )
                    rechecks_completed += 1
                memory.store.conn.commit()
    except Exception:
        pass

    # Шаг 5: входящие ответы, авто-дожим и фоновая рассылка первых писем (если включена)
    inbox_res: dict[str, Any] = {"processed": 0, "reports_sent": 0, "stopped": 0, "escalated": 0}
    outreach_sent = 0
    try:
        from . import email_autonomy as _ea
        mail_accs = _ea.list_mail_accounts(memory)
        if mail_accs:
            inbox_res = _ea.process_inbox_replies(memory)
            _ea.run_follow_up_cycle(memory)
            mprefs = _ea.get_mail_prefs(memory)
            if mprefs.get("auto_outreach_enabled") and any(a.get("status") == "active" for a in mail_accs):
                b_res = _ea.run_outreach_batch(
                    memory,
                    max_emails=int(mprefs.get("daily_batch_limit") or 20),
                    language=str(mprefs.get("outreach_language") or "auto"),
                    allow_live_fetch=allow_localhost,
                )
                outreach_sent = int(b_res.get("sent") or 0)
    except Exception:
        pass

    try:
        archive_monthly_accounting_csv(memory, allow_localhost=allow_localhost)
    except Exception:
        pass

    payout_res = release_matured_payouts(memory)
    released_cnt = int(payout_res.get("released_count") or 0) if isinstance(payout_res, dict) else 0
    # Grok-аудит 18.11, п. 2: заметка — для владельца, человеческим языком: что готово и что ему сделать.
    names = []
    for aid in reauth_needed:
        acc_row = next((a for a in accounts if a.get("account_id") == aid), {})
        names.append(str(acc_row.get("account_label") or acc_row.get("platform") or aid))
    note = (f"Цикл завершён: опрошено площадок {checked}, новых заказов {fetched_total}, "
            f"черновиков откликов готово {drafted} — проверьте и отправьте кнопкой во вкладке «Заработок». "
            f"Магазины: {stores_synced} (продаж +{stores_sales_accepted}); автоотклики {bids_dispatched}, "
            f"исполнено {orders_executed}, сдано {deliveries_packaged}, выплат {released_cnt}.")
    if names:
        note += " Требуется повторный вход: " + ", ".join(names) + " — откройте «Заработок» → «Биржи» и войдите заново."
    memory.store.conn.execute(
        "UPDATE ark_freelance_prefs SET autopilot_last_tick_at = ?, autopilot_last_note = ? WHERE user_id = ?",
        (time.time(), note[:200], memory.user_id),
    )
    memory.store.conn.commit()
    return {
        "ok": True,
        "skipped": False,
        "accounts_polled": checked,
        "accepted_orders": fetched_total,
        "stores_synced": stores_synced,
        "stores_sales_accepted": stores_sales_accepted,
        "bids_dispatched": bids_dispatched,
        "orders_executed": orders_executed,
        "deliveries_packaged": deliveries_packaged,
        "payouts_released": released_cnt,
        "site_orders_imported": int(site_orders_res.get("imported") or 0),
        "rechecks_completed": rechecks_completed,
        "inbox_processed": int(inbox_res.get("processed") or 0),
        "inbox_reports_sent": int(inbox_res.get("reports_sent") or 0),
        "inbox_stopped": int(inbox_res.get("stopped") or 0),
        "inbox_escalated": int(inbox_res.get("escalated") or 0),
        "outreach_sent": outreach_sent,
        "drafted_bids": drafted,
        "reauth_needed": reauth_needed,
        "owner_note": note,
        "state": get_autopilot_state(memory),
    }


def ensure_autopilot_worker(memory_factory, *, allow_localhost: bool = False) -> dict[str, Any]:
    """Запускает фоновый демон-поток автопилота (один на процесс), если он ещё не запущен."""
    global _AUTOPILOT_WORKER_THREAD
    with _AUTOPILOT_WORKER_LOCK:
        if _AUTOPILOT_WORKER_THREAD is not None and _AUTOPILOT_WORKER_THREAD.is_alive():
            return {"ok": True, "worker_running": True, "already_running": True}
        _AUTOPILOT_WORKER_STOP.clear()

        def _loop() -> None:
            while not _AUTOPILOT_WORKER_STOP.is_set():
                interval = 30.0
                try:
                    m = memory_factory() if callable(memory_factory) else memory_factory
                    st = get_autopilot_state(m)
                    if not st.get("autopilot_running"):
                        break
                    fast_test = ("PYTEST_CURRENT_TEST" in os.environ) or (os.environ.get("PADAM_AUTOPILOT_FAST_TEST") == "1")
                    min_iv = 5.0 if fast_test else 180.0
                    base_iv = max(min_iv, min(3600.0, float(st.get("interval_s") or 300.0)))
                    jitter = 0.0 if fast_test else float((int.from_bytes(os.urandom(1), "big") % 31) + 5)
                    interval = base_iv + jitter
                    run_autopilot_cycle(m, allow_localhost=allow_localhost)
                except Exception:
                    pass
                _AUTOPILOT_WORKER_STOP.wait(timeout=interval)

        th = threading.Thread(target=_loop, name="padam-autopilot-worker", daemon=True)
        _AUTOPILOT_WORKER_THREAD = th
        th.start()
        return {"ok": True, "worker_running": True, "already_running": False}


def stop_everything(memory, *, actor=None) -> dict[str, Any]:
    """ТОП-20 Сестры, п. 12: большая красная кнопка «СТОП ВСЁ» — одним действием и только владельцем:
    автопилот и его фоновый поток, автоотклики на всех площадках, все почтовые ящики на паузу.
    Ничего не удаляет: включается всё обратно теми же кнопками."""
    from . import roles as _roles
    _roles.require_owner(actor, "stop_everything")
    set_autopilot_state(memory, running=False, note="СТОП ВСЁ: владелец остановил автопилот, автоотклики и рассылку.", actor=actor)
    stop_autopilot_worker()
    platforms = mails = 0
    with _lock_of(memory):
        conn = memory.store.conn
        try:
            platforms = conn.execute("UPDATE ark_platform_autopilot_config SET autopilot_enabled = 0 WHERE user_id = ? "
                                     "AND autopilot_enabled = 1", (memory.user_id,)).rowcount
        except Exception:
            platforms = 0
        try:
            mails = conn.execute("UPDATE ark_mail_account SET status = 'paused' WHERE user_id = ? AND status = 'active'",
                                 (memory.user_id,)).rowcount
        except Exception:
            mails = 0
        conn.commit()
    return {"ok": True, "autopilot_running": False, "platform_autopilots_disabled": platforms, "mailboxes_paused": mails}


def stop_autopilot_worker() -> dict[str, Any]:
    """Останавливает фоновый демон-поток автопилота."""
    global _AUTOPILOT_WORKER_THREAD
    with _AUTOPILOT_WORKER_LOCK:
        _AUTOPILOT_WORKER_STOP.set()
        th = _AUTOPILOT_WORKER_THREAD
        if th is not None and th.is_alive() and th is not threading.current_thread():
            th.join(timeout=1.5)
        _AUTOPILOT_WORKER_THREAD = None
    return {"ok": True, "worker_running": False}

@_synchronized_memory
def sync_site_orders(
    memory,
    *,
    base_url: str = "",
    admin_secret: str = "",
    allow_localhost: bool = False,
    max_scan_pages: int = 25,
    send_delivery_email: bool = True,
) -> dict[str, Any]:
    """Забирает оплаченные заказы услуг (service_orders) с aifa.digital в очередь Студии и запускает исполнение."""
    _ensure(memory)
    secret = str(admin_secret or os.environ.get("PADAM_AIFA_ADMIN_SECRET") or "").strip()
    if not secret:
        return {"ok": True, "skipped": True, "reason": "no_admin_secret", "imported": 0}
    target_base = str(base_url or os.environ.get("PADAM_AIFA_DIGITAL_URL") or "https://www.aifa.digital").rstrip("/")
    clean_base = _validate_api_url(target_base, allow_localhost=allow_localhost)
    req = urllib.request.Request(
        f"{clean_base}/api/admin/service-orders?format=json",
        headers={"Authorization": f"Bearer {secret}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with net_guard.safe_urlopen(req, timeout=10, allow_localhost=allow_localhost, allow_http_localhost=True, require_https=True) as r:
            payload = json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"ok": False, "error": str(exc), "imported": 0}

    rows = payload.get("orders") if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        return {"ok": False, "error": "invalid_orders_payload", "imported": 0}

    imported = 0
    executed = 0
    for item in rows[:50]:
        if not isinstance(item, dict):
            continue
        oid_ext = str(item.get("order_id") or "").strip()
        if not oid_ext:
            continue
        exists = memory.store.conn.execute(
            "SELECT order_id FROM ark_freelance_order WHERE user_id=? AND external_job_id=? LIMIT 1",
            (memory.user_id, oid_ext),
        ).fetchone()
        if exists:
            continue

        slug = str(item.get("slug") or "quick-audit")
        website = str(item.get("website") or "")
        amount = float(item.get("amount") or 0.0)
        ev = evaluate_and_ingest_job(
            memory,
            platform="aifafocus_mcp",
            title=f"[Site Order {oid_ext}] {slug} для {website or 'сайта'}",
            brief=f"Оплаченный заказ на сайте ({slug}) для {website}. Клиент: {item.get('email', '')}.",
            budget_usdt=amount,
            estimated_tokens=20000,
            external_job_id=oid_ext,
            assigned_agent="aifa",
            work_mode="autopilot",
            client_email=str(item.get("email") or ""),
            client_domain=website,
        )
        if ev.get("ok"):
            imported += 1
            local_oid = str(ev["order_id"])
            ex_res = execute_order_with_swarm(memory, local_oid, agent_id="aifa")
            if ex_res.get("ok"):
                executed += 1
                from . import partner_bridge as _pb
                from . import site_scanner as _ss
                pkg = _pb.build_business_outreach(memory, website or oid_ext, language="ru", allow_live_fetch=False)
                scan_res: dict[str, Any] = {}
                if website and slug in ("quick-audit", "fix-pack", "lite-audit"):
                    scan_res = _ss.scan_website_accessibility(
                        website,
                        max_pages=max_scan_pages,
                        allow_localhost=allow_localhost,
                    )
                scan_section = ""
                if scan_res.get("ok") and scan_res.get("text_summary"):
                    scan_section = "\n\n" + str(scan_res["text_summary"])
                deliverable = (
                    f"Заказ {oid_ext} ({slug}) для {website} выполнен.\n"
                    f"Сумма: ${amount:.2f} USD.\n\n"
                    f"{pkg.get('business_summary', '')}\n\n"
                    f"{pkg.get('site_report', '')}"
                    f"{scan_section}"
                )
                package_safe_delivery(memory, local_oid, deliverable_text=deliverable, agent_id="aifa")

                client_email = str(item.get("email") or "").strip()
                if send_delivery_email and client_email and "@" in client_email:
                    try:
                        from . import email_autonomy as _ea
                        if _ea.list_mail_accounts(memory):
                            body_txt = deliverable
                            if scan_res.get("ok") and scan_res.get("html_report"):
                                body_txt += "\n\nПолный HTML-отчёт приложен к письму файлом и сохранён в карточке заказа."
                            _ea.send_outreach_email(
                                memory,
                                to_email=client_email,
                                domain=website or "aifa.digital",
                                subject=f"Готовый отчёт по заказу {oid_ext} ({slug})",
                                body=body_txt,
                                html_body=str(scan_res.get("html_report") or "") if isinstance(scan_res, dict) else "",
                                html_attachment_name=f"wcag-report-{oid_ext}.html",
                                direction="order_delivery",
                            )
                    except Exception:
                        pass
                try:
                    from . import family_feeds as _ff
                    _ff.post(
                        memory,
                        "office",
                        "aifa",
                        f"Новый оплаченный заказ {oid_ext} ({slug}) для {website or 'сайта'} на ${amount:.2f} USD — скан и отчёт готовы.",
                        kind="order_paid",
                        ref=oid_ext,
                    )
                except Exception:
                    pass

                if slug in ("quick-audit", "fix-pack", "lite-audit"):
                    now_rc = time.time()
                    memory.store.conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS ark_site_rechecks (
                            recheck_id TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL,
                            order_id TEXT NOT NULL,
                            website TEXT NOT NULL,
                            due_at REAL NOT NULL,
                            done_at REAL NOT NULL DEFAULT 0.0,
                            initial_violations INTEGER NOT NULL DEFAULT 0,
                            recheck_violations INTEGER NOT NULL DEFAULT 0
                        )
                        """
                    )
                    rc_cols = {
                        str(r["name"])
                        for r in memory.store.conn.execute("PRAGMA table_info(ark_site_rechecks)").fetchall()
                    }
                    if "initial_violations" not in rc_cols:
                        memory.store.conn.execute(
                            "ALTER TABLE ark_site_rechecks ADD COLUMN initial_violations INTEGER NOT NULL DEFAULT 0"
                        )
                    if "recheck_violations" not in rc_cols:
                        memory.store.conn.execute(
                            "ALTER TABLE ark_site_rechecks ADD COLUMN recheck_violations INTEGER NOT NULL DEFAULT 0"
                        )
                    init_v = int(scan_res.get("total_violations") or 0) if isinstance(scan_res, dict) else 0
                    memory.store.conn.execute(
                        "INSERT OR IGNORE INTO ark_site_rechecks (recheck_id, user_id, order_id, website, due_at, done_at, initial_violations, recheck_violations) VALUES (?, ?, ?, ?, ?, 0.0, ?, 0)",
                        (f"rc-{oid_ext}", memory.user_id, local_oid, website, now_rc + 14.0 * 86400.0, init_v),
                    )
                    memory.store.conn.commit()
    return {"ok": True, "imported": imported, "executed": executed}


def archive_monthly_accounting_csv(
    memory,
    *,
    base_url: str = "",
    admin_secret: str = "",
    archive_dir: Any = None,
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Ежемесячно сохраняет полный бухгалтерский CSV (услуги, подписки, память, возвраты) на диск."""
    from pathlib import Path as _Path
    secret = str(admin_secret or os.environ.get("PADAM_AIFA_ADMIN_SECRET") or "").strip()
    if not secret:
        return {"ok": True, "skipped": True, "reason": "no_admin_secret"}
    ym = time.strftime("%Y-%m", time.gmtime())
    out_dir = _Path(archive_dir) if archive_dir is not None else (_Path.home() / ".padam" / "accounting")
    out_file = out_dir / f"{ym}_service_orders.csv"
    if out_file.is_file() and out_file.stat().st_size > 0:
        return {"ok": True, "skipped": True, "reason": "already_archived_this_month", "path": str(out_file)}
    target_base = str(base_url or os.environ.get("PADAM_AIFA_DIGITAL_URL") or "https://www.aifa.digital").rstrip("/")
    clean_base = _validate_api_url(target_base, allow_localhost=allow_localhost)
    req = urllib.request.Request(
        f"{clean_base}/api/admin/service-orders?format=csv&scope=all",
        headers={"Authorization": f"Bearer {secret}", "Accept": "text/csv"},
        method="GET",
    )
    try:
        with net_guard.safe_urlopen(req, timeout=15, allow_localhost=allow_localhost, allow_http_localhost=True, require_https=not allow_localhost) as r:
            csv_bytes = r.read()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_bytes(csv_bytes)
    audit_chain.append_audit(memory, "monthly_accounting_archived", {"month": ym, "bytes": len(csv_bytes)}, agent_id="aifa")
    return {"ok": True, "archived": True, "path": str(out_file), "bytes": len(csv_bytes)}
