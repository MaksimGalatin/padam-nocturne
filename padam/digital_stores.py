from __future__ import annotations

"""Адаптеры 5 магазинов цифровых товаров (ЭТАП 1) и автопилот продаж (комиссия CODE 20%).

Поддерживаемые площадки строго по официальной документации API:
- Lemon Squeezy (https://docs.lemonsqueezy.com/api): GET /v1/users/me, /v1/stores, /v1/products (read-only), /v1/orders; webhook HMAC-SHA256 (X-Signature).
- Gumroad (https://gumroad.com/api): GET /v2/user, /v2/products, POST/PUT /v2/products (только при owner_approved=True), GET /v2/sales; Gumroad Ping webhook.
- Payhip (https://help.payhip.com/article/112-api): GET /api/v2/coupons (проверка ключа; создание товаров и GET /sales отсутствуют в публичном API), webhook sha256(api_key).
- Sellfy (https://docs.sellfy.com/): GET /v1/products, POST/PATCH /v1/products (только при owner_approved=True), GET /v1/orders; webhook HMAC-SHA256.
- Whop (https://docs.whop.com/api-reference): GET /api/v1/accounts/me (Api-Version-Date: 2026-07-01), /v1/products, POST/PATCH /v1/products (только при owner_approved=True), GET /v1/payments; webhook Standard Webhooks (v1,<base64>, ключ ws_ целиком UTF-8).
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import audit_chain, freelance_autonomy


_SCHEMA_LOCK = threading.RLock()
_INITIALIZED_DBS: set[int] = set()

# Канонический реестр возможностей API 5 магазинов цифровых товаров.
STORE_SPECS: dict[str, dict[str, Any]] = {
    "lemonsqueezy": {
        "store_type": "lemonsqueezy",
        "title": "Lemon Squeezy",
        "default_base_url": "https://api.lemonsqueezy.com/v1",
        "docs_url": "https://docs.lemonsqueezy.com/api",
        "supports_product_read": True,
        "supports_product_write": False,
        "supports_sales_pull": True,
        "webhook_sig_scheme": "X-Signature HMAC-SHA256 (hex по raw body)",
        "default_fee_pct": 5.0,
    },
    "gumroad": {
        "store_type": "gumroad",
        "title": "Gumroad",
        "default_base_url": "https://api.gumroad.com/v2",
        "docs_url": "https://gumroad.com/api",
        "supports_product_read": True,
        "supports_product_write": True,
        "supports_sales_pull": True,
        "webhook_sig_scheme": "seller_id (Gumroad Ping) + опц. X-Padam-Signature HMAC-SHA256",
        "default_fee_pct": 10.0,
    },
    "payhip": {
        "store_type": "payhip",
        "title": "Payhip",
        "default_base_url": "https://payhip.com/api/v2",
        "docs_url": "https://help.payhip.com/article/112-api",
        "supports_product_read": False,
        "supports_product_write": False,
        "supports_sales_pull": False,
        "webhook_sig_scheme": "Поле signature в JSON = sha256(api_key)",
        "default_fee_pct": 5.0,
    },
    "sellfy": {
        "store_type": "sellfy",
        "title": "Sellfy",
        "default_base_url": "https://api.sellfy.com",
        "docs_url": "https://docs.sellfy.com/",
        "supports_product_read": True,
        "supports_product_write": True,
        "supports_sales_pull": True,
        "webhook_sig_scheme": "X-Sellfy-Signature / X-Signature HMAC-SHA256",
        "default_fee_pct": 2.0,
    },
    "whop": {
        "store_type": "whop",
        "title": "Whop",
        "default_base_url": "https://api.whop.com/api/v1",
        "docs_url": "https://docs.whop.com/api-reference",
        "supports_product_read": True,
        "supports_product_write": True,
        "supports_sales_pull": True,
        "webhook_sig_scheme": "Standard Webhooks (webhook-id.webhook-timestamp.body -> HMAC-SHA256(ws_...), v1,<b64>)",
        "default_fee_pct": 3.0,
    },
}

DIGITAL_STORES = tuple(STORE_SPECS.keys())
WHOP_API_VERSION = "2026-07-01"

# Стартовый каталог из 3 черновиков товаров (создаются только как черновики в SQLite, без автоотправки наружу).
STARTER_PRODUCT_DRAFTS: tuple[dict[str, Any], ...] = (
    {
        "draft_id": "draft-starter-30-platforms",
        "store_type": "gumroad",
        "title": "Методичка по 30 площадкам заработка ИИ-агентов (CODE Edition)",
        "description": (
            "Пошаговое руководство по подключению агентов к 30 цифровым и фриланс-площадкам "
            "без хранения паролей: API-ключи, вебхуки, закрепление клиента на 90 дней и контроль маржи."
        ),
        "price_usdt": 29.0,
        "currency": "USD",
        "delivery_url": "https://codeofdigitaleternity.com/catalog/platforms-guide-v1",
        "file_ref": "starter:platforms_guide_v1",
    },
    {
        "draft_id": "draft-starter-a11y-leads",
        "store_type": "lemonsqueezy",
        "title": "Базы лидов из исследования цифровой доступности",
        "description": (
            "Кураторская выборка публичных B2B-доменов и технических отчётов по доступности интерфейсов (WCAG) "
            "для подготовки коммерческих предложений по аудиту и исправлению UI."
        ),
        "price_usdt": 49.0,
        "currency": "USD",
        "delivery_url": "https://codeofdigitaleternity.com/catalog/a11y-leads-v1",
        "file_ref": "starter:a11y_leads_v1",
    },
    {
        "draft_id": "draft-starter-padam-templates",
        "store_type": "whop",
        "title": "Готовые шаблоны и интеграции PADAM",
        "description": (
            "Набор типовых конфигураций автономной памяти PADAM, MCP-схем, локальных моделей ($0) "
            "и шаблонов эскроу/агентской монетизации для быстрого старта."
        ),
        "price_usdt": 19.0,
        "currency": "USD",
        "delivery_url": "https://codeofdigitaleternity.com/catalog/padam-templates-v1",
        "file_ref": "starter:padam_templates_v1",
    },
)


def _norm_store(store_type: str) -> str:
    st = str(store_type or "").strip().lower()
    if st not in STORE_SPECS:
        raise ValueError(f"Неизвестный цифровой магазин: {store_type!r}. Доступны: {', '.join(DIGITAL_STORES)}")
    return st


_DDL_STMTS = (
    """
    CREATE TABLE IF NOT EXISTS ark_digital_store_account (
        store_account_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        store_type TEXT NOT NULL,
        store_label TEXT NOT NULL DEFAULT '',
        api_base_url TEXT NOT NULL DEFAULT '',
        external_store_id TEXT NOT NULL DEFAULT '',
        owner_name TEXT NOT NULL DEFAULT '',
        owner_email TEXT NOT NULL DEFAULT '',
        currency TEXT NOT NULL DEFAULT 'USD',
        agent_id TEXT NOT NULL DEFAULT 'aifa',
        api_key_enc TEXT NOT NULL DEFAULT '',
        webhook_secret_enc TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'verified',
        capabilities_json TEXT NOT NULL DEFAULT '{}',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_digital_store_user
        ON ark_digital_store_account(user_id, store_type, updated_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS ark_digital_product_draft (
        draft_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        store_type TEXT NOT NULL,
        store_account_id TEXT NOT NULL DEFAULT '',
        title TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        price_usdt REAL NOT NULL DEFAULT 0.0,
        currency TEXT NOT NULL DEFAULT 'USD',
        delivery_url TEXT NOT NULL DEFAULT '',
        file_ref TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'draft',
        owner_approved INTEGER NOT NULL DEFAULT 0,
        external_product_id TEXT NOT NULL DEFAULT '',
        external_url TEXT NOT NULL DEFAULT '',
        publish_note TEXT NOT NULL DEFAULT '',
        is_starter INTEGER NOT NULL DEFAULT 0,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_digital_draft_user
        ON ark_digital_product_draft(user_id, store_type, updated_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS ark_store_webhook_event (
        event_key TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        store_type TEXT NOT NULL,
        store_account_id TEXT NOT NULL DEFAULT '',
        external_event_id TEXT NOT NULL DEFAULT '',
        event_kind TEXT NOT NULL DEFAULT '',
        order_id TEXT NOT NULL DEFAULT '',
        payload_sha256 TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL
    )
    """,
)


def _ensure_schema(memory) -> None:
    """Создаёт таблицы учёта магазинов, черновиков товаров и обработанных вебхуков без executescript-конфликтов."""
    with freelance_autonomy._lock_of(memory):
        freelance_autonomy._ensure(memory)
        conn = memory.store.conn
        key = id(conn)
        if key in _INITIALIZED_DBS:
            try:
                conn.execute("SELECT 1 FROM ark_digital_store_account LIMIT 1")
                return
            except Exception:
                _INITIALIZED_DBS.discard(key)
        for stmt in _DDL_STMTS:
            conn.execute(stmt.strip())
        conn.commit()
        _INITIALIZED_DBS.add(key)


def _http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    form_body: dict[str, Any] | None = None,
    allow_localhost: bool = False,
    timeout_s: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    """Безопасный HTTP-вызов к официальному API магазина через проверку SSRF."""
    clean_url = freelance_autonomy._validate_api_url(url, allow_localhost=allow_localhost)
    hdrs: dict[str, str] = {"User-Agent": "PADAM-DigitalStores/1.0"}
    if headers:
        hdrs.update(headers)
    data: bytes | None = None
    if json_body is not None:
        data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    elif form_body is not None:
        data = urllib.parse.urlencode(form_body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = urllib.request.Request(clean_url, data=data, headers=hdrs, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return int(resp.status), (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw_err = e.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(raw_err) if raw_err.strip() else {}
        except Exception:
            err_json = {"raw": raw_err[:240]}
        raise RuntimeError(f"HTTP {e.code} от {clean_url}: {err_json}") from e


def _store_headers(store_type: str, api_key: str) -> dict[str, str]:
    """Формирует заголовки авторизации строго по официальной спецификации магазина."""
    if store_type == "lemonsqueezy":
        return {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/vnd.api+json",
            "Content-Type": "application/vnd.api+json",
        }
    if store_type == "payhip":
        return {
            "Authorization": f"Bearer {api_key}",
            "payhip-api-key": api_key,
            "Accept": "application/json",
        }
    if store_type == "whop":
        return {
            "Authorization": f"Bearer {api_key}",
            "Api-Version-Date": WHOP_API_VERSION,
            "Accept": "application/json",
        }
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }


def _verify_store_credentials(
    store_type: str,
    base_url: str,
    api_key: str,
    *,
    seller_id: str = "",
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Проверяет API-ключ в живом/тестовом контуре магазина и извлекает владельца и валюту."""
    hdrs = _store_headers(store_type, api_key)
    base = base_url.rstrip("/")

    if store_type == "lemonsqueezy":
        _, me = _http_json("GET", f"{base}/users/me", headers=hdrs, allow_localhost=allow_localhost)
        me_attr = ((me.get("data") or {}).get("attributes") or {}) if isinstance(me, dict) else {}
        owner_name = str(me_attr.get("name") or "")
        owner_email = str(me_attr.get("email") or "")
        ext_store_id = ""
        currency = "USD"
        try:
            _, st = _http_json("GET", f"{base}/stores", headers=hdrs, allow_localhost=allow_localhost)
            stores_data = st.get("data") if isinstance(st, dict) else None
            if isinstance(stores_data, list) and stores_data:
                s0 = stores_data[0]
                ext_store_id = str(s0.get("id") or "")
                s0_attr = s0.get("attributes") or {}
                currency = str(s0_attr.get("currency") or "USD").upper()
                if not owner_name:
                    owner_name = str(s0_attr.get("name") or "")
        except Exception:
            pass
        return {
            "external_store_id": ext_store_id or str((me.get("data") or {}).get("id") or ""),
            "owner_name": owner_name,
            "owner_email": owner_email,
            "currency": currency,
        }

    if store_type == "gumroad":
        _, res = _http_json("GET", f"{base}/user", headers=hdrs, allow_localhost=allow_localhost)
        if isinstance(res, dict) and res.get("success") is False:
            raise RuntimeError(f"Gumroad отклонил ключ: {res.get('message') or 'success=false'}")
        user = (res.get("user") or {}) if isinstance(res, dict) else {}
        return {
            "external_store_id": str(seller_id or user.get("id") or user.get("user_id") or ""),
            "owner_name": str(user.get("name") or ""),
            "owner_email": str(user.get("email") or ""),
            "currency": str(user.get("currency_type") or "USD").upper(),
        }

    if store_type == "payhip":
        _, res = _http_json("GET", f"{base}/coupons", headers=hdrs, allow_localhost=allow_localhost)
        return {
            "external_store_id": str(seller_id or (res.get("store_id") if isinstance(res, dict) else "") or "payhip-account"),
            "owner_name": str((res.get("owner_name") if isinstance(res, dict) else "") or "Payhip Seller"),
            "owner_email": str((res.get("owner_email") if isinstance(res, dict) else "") or ""),
            "currency": str((res.get("currency") if isinstance(res, dict) else "") or "USD").upper(),
        }

    if store_type == "sellfy":
        _, res = _http_json("GET", f"{base}/v1/products?limit=1", headers=hdrs, allow_localhost=allow_localhost)
        store_meta = (res.get("store") or {}) if isinstance(res, dict) else {}
        return {
            "external_store_id": str(seller_id or store_meta.get("id") or "sellfy-store"),
            "owner_name": str(store_meta.get("name") or "Sellfy Store"),
            "owner_email": str(store_meta.get("email") or ""),
            "currency": str(store_meta.get("currency") or "USD").upper(),
        }

    # Whop (v1)
    _, res = _http_json("GET", f"{base}/accounts/me", headers=hdrs, allow_localhost=allow_localhost)
    data = res.get("data") if isinstance(res.get("data"), dict) else res
    return {
        "external_store_id": str(seller_id or data.get("id") or ""),
        "owner_name": str(data.get("title") or data.get("name") or ""),
        "owner_email": str(data.get("email") or ""),
        "currency": str(data.get("currency") or "USD").upper(),
    }


def _get_store_row(memory, store_account_id: str) -> dict[str, Any]:
    _ensure_schema(memory)
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        row = conn.execute(
            "SELECT * FROM ark_digital_store_account WHERE user_id = ? AND store_account_id = ?",
            (memory.user_id, store_account_id),
        ).fetchone()
    if row is None:
        raise KeyError(f"Аккаунт магазина не найден: {store_account_id}")
    return dict(row)


def _find_store_row(memory, store_type: str, store_account_id: str = "") -> dict[str, Any] | None:
    _ensure_schema(memory)
    if store_account_id:
        return _get_store_row(memory, store_account_id)
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        row = conn.execute(
            "SELECT * FROM ark_digital_store_account WHERE user_id = ? AND store_type = ? "
            "ORDER BY updated_at DESC LIMIT 1",
            (memory.user_id, _norm_store(store_type)),
        ).fetchone()
    return dict(row) if row is not None else None


def _public_store_dict(row: dict[str, Any]) -> dict[str, Any]:
    """Безопасное представление магазина без расшифровки ключей."""
    spec = STORE_SPECS.get(str(row.get("store_type") or ""), {})
    caps = json.loads(row.get("capabilities_json") or "{}") if row.get("capabilities_json") else {}
    return {
        "store_account_id": row["store_account_id"],
        "store_type": row["store_type"],
        "title": spec.get("title", row["store_type"]),
        "store_label": row["store_label"],
        "api_base_url": row["api_base_url"],
        "external_store_id": row["external_store_id"],
        "owner_name": row["owner_name"],
        "owner_email": row["owner_email"],
        "currency": row["currency"],
        "agent_id": row["agent_id"],
        "status": row["status"],
        "has_api_key": bool(row.get("api_key_enc")),
        "has_webhook_secret": bool(row.get("webhook_secret_enc")),
        "docs_url": spec.get("docs_url", ""),
        "webhook_sig_scheme": spec.get("webhook_sig_scheme", ""),
        "capabilities": caps or {
            "supports_product_read": bool(spec.get("supports_product_read")),
            "supports_product_write": bool(spec.get("supports_product_write")),
            "supports_sales_pull": bool(spec.get("supports_sales_pull")),
        },
        "updated_at": row["updated_at"],
    }


def connect_and_verify_store(
    memory,
    *,
    store_type: str,
    api_key: str,
    api_base_url: str = "",
    store_label: str = "",
    webhook_secret: str = "",
    agent_id: str = "aifa",
    seller_id: str = "",
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Проверяет API-ключ выбранного магазина, сохраняет метаданные владельца и шифрует секреты AES-256-GCM."""
    _ensure_schema(memory)
    st = _norm_store(store_type)
    raw_key = str(api_key or "").strip()
    if not raw_key:
        raise ValueError("Необходимо указать api_key (токен API магазина; пароли запрещены).")

    spec = STORE_SPECS[st]
    base_url = freelance_autonomy._validate_api_url(
        str(api_base_url or spec["default_base_url"]).strip(),
        allow_localhost=allow_localhost,
    )
    verified = _verify_store_credentials(
        st,
        base_url,
        raw_key,
        seller_id=seller_id,
        allow_localhost=allow_localhost,
    )

    now = time.time()
    acc_id = f"store-{st}-{secrets.token_hex(4)}"
    label = str(store_label or verified.get("owner_name") or spec["title"]).strip()[:120]
    aid = str(agent_id or "aifa").strip() or "aifa"
    caps = {
        "supports_product_read": bool(spec["supports_product_read"]),
        "supports_product_write": bool(spec["supports_product_write"]),
        "supports_sales_pull": bool(spec["supports_sales_pull"]),
    }

    api_key_enc = freelance_autonomy._seal_secret(memory, raw_key)
    wh_sec = str(webhook_secret or "").strip()
    webhook_secret_enc = freelance_autonomy._seal_secret(memory, wh_sec) if wh_sec else ""

    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        conn.execute(
            """
            INSERT INTO ark_digital_store_account (
                store_account_id, user_id, store_type, store_label, api_base_url,
                external_store_id, owner_name, owner_email, currency, agent_id,
                api_key_enc, webhook_secret_enc, status, capabilities_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?)
            """,
            (
                acc_id,
                memory.user_id,
                st,
                label,
                base_url,
                str(verified.get("external_store_id") or "")[:128],
                str(verified.get("owner_name") or "")[:128],
                str(verified.get("owner_email") or "")[:128],
                str(verified.get("currency") or "USD")[:12],
                aid[:64],
                api_key_enc,
                webhook_secret_enc,
                json.dumps(caps, ensure_ascii=False),
                now,
                now,
            ),
        )
        conn.commit()

    audit_chain.append_audit(
        memory,
        "digital_store_connected",
        {
            "store_account_id": acc_id,
            "store_type": st,
            "currency": verified.get("currency") or "USD",
            "supports_product_write": caps["supports_product_write"],
        },
        agent_id=aid,
    )
    return {
        "ok": True,
        "verified": True,
        "store": _public_store_dict(_get_store_row(memory, acc_id)),
    }


def list_connected_stores(memory) -> list[dict[str, Any]]:
    """Возвращает список подключённых магазинов без раскрытия ключей."""
    _ensure_schema(memory)
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        rows = conn.execute(
            "SELECT * FROM ark_digital_store_account WHERE user_id = ? ORDER BY updated_at DESC",
            (memory.user_id,),
        ).fetchall()
    return [_public_store_dict(dict(r)) for r in rows]


def _public_draft_dict(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "draft_id": row["draft_id"],
        "store_type": row["store_type"],
        "store_account_id": row["store_account_id"],
        "title": row["title"],
        "description": row["description"],
        "price_usdt": float(row["price_usdt"]),
        "currency": row["currency"],
        "delivery_url": row["delivery_url"],
        "file_ref": row["file_ref"],
        "status": row["status"],
        "owner_approved": bool(row["owner_approved"]),
        "external_product_id": row["external_product_id"],
        "external_url": row["external_url"],
        "publish_note": row["publish_note"],
        "is_starter": bool(row["is_starter"]),
        "proposal_disclaimer": "цена и текст — предложение агента",
        "updated_at": row["updated_at"],
    }


def upsert_product_draft(
    memory,
    *,
    draft_id: str = "",
    store_type: str = "gumroad",
    store_account_id: str = "",
    title: str,
    description: str = "",
    price_usdt: float = 19.0,
    currency: str = "USD",
    delivery_url: str = "",
    file_ref: str = "",
    is_starter: bool = False,
) -> dict[str, Any]:
    """Создаёт или обновляет карточку-черновик товара в локальном реестре (без отправки наружу)."""
    _ensure_schema(memory)
    st = _norm_store(store_type)
    clean_title, _ = freelance_autonomy.sanitize_for_delivery(str(title or "").strip())
    if not clean_title:
        raise ValueError("Необходимо указать title товара.")
    clean_desc, _ = freelance_autonomy.sanitize_for_delivery(str(description or "").strip())
    price = round(max(0.0, float(price_usdt or 0.0)), 2)
    cur = str(currency or "USD").strip().upper()[:12] or "USD"
    deliv = str(delivery_url or "").strip()[:512]
    fref = str(file_ref or "").strip()[:256]
    did = str(draft_id or "").strip() or f"draft-{secrets.token_hex(4)}"
    now = time.time()

    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        existing = conn.execute(
            "SELECT * FROM ark_digital_product_draft WHERE user_id = ? AND draft_id = ?",
            (memory.user_id, did),
        ).fetchone()
        if existing is not None:
            conn.execute(
                """
                UPDATE ark_digital_product_draft
                SET store_type = ?, store_account_id = ?, title = ?, description = ?,
                    price_usdt = ?, currency = ?, delivery_url = ?, file_ref = ?,
                    updated_at = ?
                WHERE user_id = ? AND draft_id = ?
                """,
                (
                    st,
                    str(store_account_id or existing["store_account_id"] or ""),
                    clean_title[:200],
                    clean_desc[:4000],
                    price,
                    cur,
                    deliv,
                    fref or existing["file_ref"],
                    now,
                    memory.user_id,
                    did,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO ark_digital_product_draft (
                    draft_id, user_id, store_type, store_account_id, title, description,
                    price_usdt, currency, delivery_url, file_ref, status, owner_approved,
                    is_starter, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', 0, ?, ?, ?)
                """,
                (
                    did,
                    memory.user_id,
                    st,
                    str(store_account_id or ""),
                    clean_title[:200],
                    clean_desc[:4000],
                    price,
                    cur,
                    deliv,
                    fref,
                    1 if is_starter else 0,
                    now,
                    now,
                ),
            )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM ark_digital_product_draft WHERE user_id = ? AND draft_id = ?",
            (memory.user_id, did),
        ).fetchone()
    return {"ok": True, "draft": _public_draft_dict(dict(row))}


def seed_starter_product_drafts(memory) -> dict[str, Any]:
    """Идемпотентно создаёт 3 стартовых черновика товаров для начала продаж без чтения/правки внешних файлов."""
    _ensure_schema(memory)
    created = 0
    drafts: list[dict[str, Any]] = []
    conn = memory.store.conn
    for item in STARTER_PRODUCT_DRAFTS:
        with freelance_autonomy._lock_of(memory):
            existing = conn.execute(
                "SELECT * FROM ark_digital_product_draft WHERE user_id = ? AND draft_id = ?",
                (memory.user_id, item["draft_id"]),
            ).fetchone()
        if existing is None:
            res = upsert_product_draft(
                memory,
                draft_id=item["draft_id"],
                store_type=item["store_type"],
                title=item["title"],
                description=item["description"],
                price_usdt=item["price_usdt"],
                currency=item["currency"],
                delivery_url=item["delivery_url"],
                file_ref=item["file_ref"],
                is_starter=True,
            )
            drafts.append(res["draft"])
            created += 1
        else:
            ex_dict = dict(existing)
            if "персональных данных" in str(ex_dict.get("description") or ""):
                res = upsert_product_draft(
                    memory,
                    draft_id=item["draft_id"],
                    store_type=item["store_type"],
                    title=item["title"],
                    description=item["description"],
                    price_usdt=float(ex_dict.get("price_usdt") or item["price_usdt"]),
                    currency=str(ex_dict.get("currency") or item["currency"]),
                    delivery_url=str(ex_dict.get("delivery_url") or item["delivery_url"]),
                    file_ref=str(ex_dict.get("file_ref") or item["file_ref"]),
                    is_starter=True,
                )
                drafts.append(res["draft"])
            else:
                drafts.append(_public_draft_dict(ex_dict))
    return {"ok": True, "created_count": created, "drafts": drafts}


def list_product_drafts(memory, *, store_type: str = "") -> list[dict[str, Any]]:
    """Список карточек-черновиков товаров (при необходимости с фильтром по магазину)."""
    _ensure_schema(memory)
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        if store_type:
            rows = conn.execute(
                "SELECT * FROM ark_digital_product_draft WHERE user_id = ? AND store_type = ? ORDER BY is_starter DESC, updated_at DESC",
                (memory.user_id, _norm_store(store_type)),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ark_digital_product_draft WHERE user_id = ? ORDER BY is_starter DESC, updated_at DESC",
                (memory.user_id,),
            ).fetchall()
    return [_public_draft_dict(dict(r)) for r in rows]


def publish_product_to_store(
    memory,
    draft_id: str,
    *,
    store_account_id: str = "",
    store_type: str = "",
    owner_approved: bool = False,
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Создаёт или обновляет товар в магазине СТРОГО после явного подтверждения владельца (owner_approved=True)."""
    _ensure_schema(memory)
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        row = conn.execute(
            "SELECT * FROM ark_digital_product_draft WHERE user_id = ? AND draft_id = ?",
            (memory.user_id, str(draft_id or "").strip()),
        ).fetchone()
    if row is None:
        raise KeyError(f"Черновик товара не найден: {draft_id}")
    draft = dict(row)

    if not owner_approved:
        return {
            "ok": True,
            "published_via_api": False,
            "status": "awaiting_owner_approval",
            "note": "Карточка сохранена как черновик. Для отправки в магазин нужно явное «да» владельца (owner_approved=True).",
            "draft": _public_draft_dict(draft),
        }

    target_st = _norm_store(store_type or draft["store_type"])
    acc = _find_store_row(memory, target_st, str(store_account_id or draft.get("store_account_id") or ""))
    if acc is None:
        raise KeyError(f"Нет подключённого аккаунта для магазина {target_st!r}.")
    api_key = freelance_autonomy._unseal_secret(memory, acc["api_key_enc"])
    if not api_key:
        raise PermissionError("API-ключ магазина недоступен.")

    spec = STORE_SPECS[target_st]
    base = str(acc["api_base_url"]).rstrip("/")
    hdrs = _store_headers(target_st, api_key)
    price_cents = int(round(float(draft["price_usdt"]) * 100))
    now = time.time()

    # Для Lemon Squeezy и Payhip публичный API не поддерживает создание/изменение товаров — честно сообщаем.
    if not spec["supports_product_write"]:
        found_id = str(draft.get("external_product_id") or "")
        if target_st == "lemonsqueezy":
            _, prod_res = _http_json("GET", f"{base}/products", headers=hdrs, allow_localhost=allow_localhost)
            for item in (prod_res.get("data") or []):
                p_attr = item.get("attributes") or {}
                if str(p_attr.get("name") or "").strip().lower() == str(draft["title"]).strip().lower():
                    found_id = str(item.get("id") or "")
                    break
        note = (
            f"API {spec['title']} не поддерживает программное создание/редактирование товаров (read-only). "
            f"Создайте товар в кабинете {spec['title']} по данным этого черновика."
        )
        with freelance_autonomy._lock_of(memory):
            conn.execute(
                """
                UPDATE ark_digital_product_draft
                SET store_type = ?, store_account_id = ?, owner_approved = 1,
                    status = 'manual_dashboard_required', external_product_id = ?, publish_note = ?, updated_at = ?
                WHERE user_id = ? AND draft_id = ?
                """,
                (target_st, acc["store_account_id"], found_id, note, now, memory.user_id, draft["draft_id"]),
            )
            conn.commit()
            updated_row = conn.execute(
                "SELECT * FROM ark_digital_product_draft WHERE user_id = ? AND draft_id = ?",
                (memory.user_id, draft["draft_id"]),
            ).fetchone()
        return {
            "ok": True,
            "published_via_api": False,
            "dashboard_manual_required": True,
            "note": note,
            "draft": _public_draft_dict(dict(updated_row)),
        }

    ext_id = str(draft.get("external_product_id") or "").strip()
    ext_url = str(draft.get("external_url") or "").strip()

    if target_st == "gumroad":
        form_payload: dict[str, Any] = {
            "name": draft["title"],
            "price": price_cents,
            "description": draft["description"],
        }
        if draft.get("delivery_url"):
            form_payload["url"] = draft["delivery_url"]
        if ext_id:
            _, resp = _http_json("PUT", f"{base}/products/{ext_id}", headers=hdrs, form_body=form_payload, allow_localhost=allow_localhost)
        else:
            _, resp = _http_json("POST", f"{base}/products", headers=hdrs, form_body=form_payload, allow_localhost=allow_localhost)
        prod = resp.get("product") if isinstance(resp, dict) and isinstance(resp.get("product"), dict) else resp
        ext_id = str(prod.get("id") or ext_id or "")
        ext_url = str(prod.get("short_url") or prod.get("url") or ext_url or "")

    elif target_st == "sellfy":
        body = {
            "title": draft["title"],
            "description": draft["description"],
            "price": price_cents,
            "currency": draft["currency"] or acc["currency"] or "USD",
            "delivery_url": draft.get("delivery_url") or "",
        }
        if ext_id:
            _, resp = _http_json("PATCH", f"{base}/v1/products/{ext_id}", headers=hdrs, json_body=body, allow_localhost=allow_localhost)
        else:
            _, resp = _http_json("POST", f"{base}/v1/products", headers=hdrs, json_body=body, allow_localhost=allow_localhost)
        prod = resp.get("product") if isinstance(resp, dict) and isinstance(resp.get("product"), dict) else resp
        ext_id = str(prod.get("id") or ext_id or "")
        ext_url = str(prod.get("url") or ext_url or "")

    elif target_st == "whop":
        body = {
            "title": draft["title"],
            "description": draft["description"],
            "company_id": acc.get("external_store_id") or "",
            "price": float(draft["price_usdt"]),
            "currency": (draft["currency"] or acc["currency"] or "usd").lower(),
            "delivery_url": draft.get("delivery_url") or "",
        }
        if ext_id:
            _, resp = _http_json("PATCH", f"{base}/products/{ext_id}", headers=hdrs, json_body=body, allow_localhost=allow_localhost)
        else:
            _, resp = _http_json("POST", f"{base}/products", headers=hdrs, json_body=body, allow_localhost=allow_localhost)
        prod = resp.get("data") if isinstance(resp, dict) and isinstance(resp.get("data"), dict) else resp
        ext_id = str(prod.get("id") or ext_id or "")
        ext_url = str(prod.get("url") or prod.get("route") or ext_url or "")

    note = f"Товар отправлен в {spec['title']} с подтверждением владельца (external_product_id={ext_id})."
    with freelance_autonomy._lock_of(memory):
        conn.execute(
            """
            UPDATE ark_digital_product_draft
            SET store_type = ?, store_account_id = ?, owner_approved = 1, status = 'published',
                external_product_id = ?, external_url = ?, publish_note = ?, updated_at = ?
            WHERE user_id = ? AND draft_id = ?
            """,
            (target_st, acc["store_account_id"], ext_id, ext_url, note, now, memory.user_id, draft["draft_id"]),
        )
        conn.commit()
        updated_row = conn.execute(
            "SELECT * FROM ark_digital_product_draft WHERE user_id = ? AND draft_id = ?",
            (memory.user_id, draft["draft_id"]),
        ).fetchone()

    audit_chain.append_audit(
        memory,
        "digital_product_published",
        {"draft_id": draft["draft_id"], "store_type": target_st, "external_product_id": ext_id},
        agent_id=str(acc.get("agent_id") or "aifa"),
    )
    return {
        "ok": True,
        "published_via_api": True,
        "external_product_id": ext_id,
        "external_url": ext_url,
        "draft": _public_draft_dict(dict(updated_row)),
    }


def _money_from_cents_or_float(val: Any, *, always_cents: bool = True) -> float:
    if val is None or val == "":
        return 0.0
    if isinstance(val, (int, float)):
        num = float(val)
        if always_cents and isinstance(val, int):
            return round(num / 100.0, 2)
        return round(num / 100.0, 2) if (always_cents and num.is_integer() and num >= 100) else round(num, 2)
    s = str(val).strip().lstrip("$")
    if "." in s:
        return round(float(s), 2)
    num = float(s)
    return round(num / 100.0, 2) if always_cents else round(num, 2)


def _find_order_by_external_sale(memory, store_type: str, external_sale_id: str) -> dict[str, Any] | None:
    if not external_sale_id:
        return None
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        row = conn.execute(
            "SELECT * FROM ark_freelance_order WHERE user_id = ? AND platform = ? AND external_job_id = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (memory.user_id, store_type, external_sale_id),
        ).fetchone()
    return dict(row) if row is not None else None


def _ingest_autopilot_sale_or_refund(
    memory,
    *,
    acc: dict[str, Any],
    external_sale_id: str,
    product_title: str,
    gross_usd: float,
    customer_email: str,
    is_refund: bool = False,
    refund_reason: str = "Возврат по цифровому заказу",
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Записывает продажу из магазина с work_mode='autopilot' (20% CODE), либо фиксирует возврат."""
    st = str(acc["store_type"])
    aid = str(acc.get("agent_id") or "aifa")
    ext_id = str(external_sale_id or "").strip()
    existing = _find_order_by_external_sale(memory, st, ext_id)

    if is_refund:
        if existing is None:
            return {"ok": True, "action": "refund_ignored_unknown_order", "external_sale_id": ext_id}
        if existing["status"] == "refunded":
            return {"ok": True, "action": "refund_already_recorded", "order_id": existing["order_id"], "external_sale_id": ext_id}
        if existing["status"] == "unverified_payout":
            now_r = float(now_ts if now_ts is not None else time.time())
            with freelance_autonomy._lock_of(memory):
                memory.store.conn.execute(
                    "UPDATE ark_freelance_order SET status = 'refunded', payout_cancel_reason = ?, updated_at = ? "
                    "WHERE user_id = ? AND order_id = ?",
                    (refund_reason[:200], now_r, memory.user_id, existing["order_id"]),
                )
                memory.store.conn.commit()
            return {"ok": True, "action": "refund_processed", "order_id": existing["order_id"], "external_sale_id": ext_id}
        disputed = freelance_autonomy.dispute_held_payout(
            memory,
            order_id=existing["order_id"],
            reason=refund_reason,
            now_ts=now_ts,
        )
        return {
            "ok": True,
            "action": "refund_processed",
            "order_id": existing["order_id"],
            "external_sale_id": ext_id,
            "dispute": disputed,
        }

    if existing is not None:
        return {
            "ok": True,
            "action": "already_synced",
            "order_id": existing["order_id"],
            "external_sale_id": ext_id,
            "work_mode": ("autopilot" if float(existing.get("platform_fee_pct") or 0.0) >= freelance_autonomy.AUTOPILOT_FEE_PCT else "assisted"),
            "platform_fee_pct": existing.get("platform_fee_pct"),
        }

    spec = STORE_SPECS[st]
    price = round(max(0.01, float(gross_usd or 0.0)), 2)
    ingested = freelance_autonomy.evaluate_and_ingest_job(
        memory,
        platform=st,
        title=str(product_title or f"Digital Product ({spec['title']})"),
        brief=f"Автоматическая продажа цифрового товара в {spec['title']} (order={ext_id}).",
        budget_usdt=price,
        estimated_tokens=500,
        estimated_hours=0.25,
        exchange_fee_pct=float(spec.get("default_fee_pct") or 0.0),
        account_id=str(acc["store_account_id"]),
        external_job_id=ext_id,
        assigned_agent=aid,
        client_email=str(customer_email or "").strip(),
        work_mode="autopilot",
        now_ts=now_ts,
    )
    order_id = str(ingested["order_id"])
    # Замечание 1 (Payhip): подпись sha256(api_key) постоянная и не зависит от тела, а API продаж у Payhip нет.
    # Продажи с Payhip помечаются «не подтверждена» (verified=False) и НЕ начисляются в итоговые суммы до кнопки владельца.
    if st == "payhip":
        now_s = float(now_ts if now_ts is not None else time.time())
        with freelance_autonomy._lock_of(memory):
            conn = memory.store.conn
            conn.execute(
                "UPDATE ark_freelance_order SET status = 'unverified_payout', sale_verified = 0, "
                "updated_at = ? WHERE user_id = ? AND order_id = ?",
                (now_s, memory.user_id, order_id),
            )
            conn.commit()
        return {
            "ok": True,
            "action": "sale_pending_owner_verification",
            "verified": False,
            "order_id": order_id,
            "external_sale_id": ext_id,
            "work_mode": "autopilot",
            "code_fee_pct": freelance_autonomy.AUTOPILOT_FEE_PCT,
            "gross_usdt": price,
            "note": "Payhip: продажа не подтверждена (verified=false) — подпись sha256(api_key) статична; доли и комиссия не начислены до подтверждения владельцем.",
            "client_lock": ingested.get("client_lock"),
        }

    settled = freelance_autonomy.settle_paid_order(
        memory,
        order_id,
        paid_usdt=price,
        agent_id=aid,
        now_ts=now_ts,
    )
    accepted = freelance_autonomy.accept_delivery(
        memory,
        order_id,
        accepted_by=f"{st}:instant_delivery",
        now_ts=now_ts,
    )
    return {
        "ok": True,
        "action": "sale_ingested_autopilot",
        "verified": True,
        "order_id": order_id,
        "external_sale_id": ext_id,
        "work_mode": "autopilot",
        "code_fee_pct": freelance_autonomy.AUTOPILOT_FEE_PCT,
        "gross_usdt": price,
        "settled": settled,
        "accepted": accepted,
        "client_lock": ingested.get("client_lock"),
    }


def confirm_unverified_store_sale(
    memory,
    order_id: str,
    *,
    owner_approved: bool = False,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Подтверждает продажу Payhip кнопкой владельца (owner_approved=True) после сверки с выплатой и начисляет доли."""
    _ensure_schema(memory)
    if not owner_approved:
        raise PermissionError("Подтверждение выплаты Payhip требует явного действия владельца (owner_approved=True).")
    oid = str(order_id or "").strip()
    with freelance_autonomy._lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_freelance_order WHERE user_id = ? AND order_id = ?",
            (memory.user_id, oid),
        ).fetchone()
    if row is None:
        raise KeyError(f"Заказ не найден: {oid}")
    ord_d = dict(row)
    if ord_d.get("status") == "paid" and int(ord_d.get("sale_verified", 1)) == 1:
        return {"ok": True, "verified": True, "already_confirmed": True, "order_id": oid}

    price = float(ord_d.get("proposed_usdt") or ord_d.get("budget_usdt") or 0.0)
    aid = str(ord_d.get("assigned_agent") or "aifa")
    now_s = float(now_ts if now_ts is not None else time.time())
    with freelance_autonomy._lock_of(memory):
        memory.store.conn.execute(
            "UPDATE ark_freelance_order SET sale_verified = 1, status = 'evaluated', updated_at = ? "
            "WHERE user_id = ? AND order_id = ?",
            (now_s, memory.user_id, oid),
        )
        memory.store.conn.commit()
    settled = freelance_autonomy.settle_paid_order(
        memory,
        oid,
        paid_usdt=price,
        agent_id=aid,
        now_ts=now_s,
    )
    accepted = freelance_autonomy.accept_delivery(
        memory,
        oid,
        accepted_by="owner_verified_payhip",
        now_ts=now_s,
    )
    return {
        "ok": True,
        "verified": True,
        "order_id": oid,
        "settled": settled,
        "accepted": accepted,
    }


def sync_store_sales(
    memory,
    store_account_id: str,
    *,
    allow_localhost: bool = False,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Читает заказы и продажи из API магазина и заводит их в автономный учёт с work_mode='autopilot' (20%)."""
    acc = _get_store_row(memory, store_account_id)
    st = str(acc["store_type"])
    spec = STORE_SPECS[st]
    if not spec["supports_sales_pull"]:
        return {
            "ok": True,
            "store_account_id": store_account_id,
            "store_type": st,
            "pull_supported": False,
            "imported_count": 0,
            "refunded_count": 0,
            "note": f"{spec['title']} не предоставляет endpoint чтения продаж в публичном API; используйте webhook.",
        }

    api_key = freelance_autonomy._unseal_secret(memory, acc["api_key_enc"])
    if not api_key:
        raise PermissionError("API-ключ магазина недоступен.")
    base = str(acc["api_base_url"]).rstrip("/")
    hdrs = _store_headers(st, api_key)

    parsed_items: list[dict[str, Any]] = []
    if st == "lemonsqueezy":
        _, res = _http_json("GET", f"{base}/orders", headers=hdrs, allow_localhost=allow_localhost)
        for item in (res.get("data") or []):
            attr = item.get("attributes") or {}
            first_item = attr.get("first_order_item") or {}
            status_s = str(attr.get("status") or "").lower()
            parsed_items.append({
                "sale_id": str(item.get("id") or ""),
                "title": str(first_item.get("product_name") or attr.get("product_name") or "Lemon Squeezy Order"),
                "gross_usd": _money_from_cents_or_float(attr.get("total"), always_cents=True),
                "email": str(attr.get("user_email") or ""),
                "is_refund": status_s == "refunded" or bool(attr.get("refunded")),
            })
    elif st == "gumroad":
        _, res = _http_json("GET", f"{base}/sales", headers=hdrs, allow_localhost=allow_localhost)
        for sale in (res.get("sales") or []):
            parsed_items.append({
                "sale_id": str(sale.get("id") or ""),
                "title": str(sale.get("product_name") or "Gumroad Sale"),
                "gross_usd": _money_from_cents_or_float(sale.get("price"), always_cents=True),
                "email": str(sale.get("email") or ""),
                "is_refund": bool(sale.get("refunded")) or bool(sale.get("chargebacked")),
            })
    elif st == "sellfy":
        _, res = _http_json("GET", f"{base}/v1/orders", headers=hdrs, allow_localhost=allow_localhost)
        orders_list = res.get("orders") if isinstance(res.get("orders"), list) else (res.get("data") or [])
        for ord_item in orders_list:
            cust = ord_item.get("customer") or {}
            items = ord_item.get("items") or []
            p_title = str(items[0].get("title") or items[0].get("name")) if items else "Sellfy Order"
            status_s = str(ord_item.get("status") or "").upper()
            parsed_items.append({
                "sale_id": str(ord_item.get("id") or ""),
                "title": p_title,
                "gross_usd": _money_from_cents_or_float(ord_item.get("amount"), always_cents=True),
                "email": str(cust.get("email") or ord_item.get("email") or ""),
                "is_refund": status_s in ("REFUNDED", "CANCELED", "CANCELLED"),
            })
    elif st == "whop":
        _, res = _http_json("GET", f"{base}/payments", headers=hdrs, allow_localhost=allow_localhost)
        payments = res.get("data") if isinstance(res.get("data"), list) else (res.get("payments") or [])
        for pay in payments:
            usr = pay.get("user") or {}
            prd = pay.get("product") or {}
            status_s = str(pay.get("status") or "").lower()
            amt = pay.get("final_amount") if pay.get("final_amount") is not None else pay.get("amount")
            parsed_items.append({
                "sale_id": str(pay.get("id") or ""),
                "title": str(prd.get("title") or pay.get("product_title") or "Whop Payment"),
                "gross_usd": _money_from_cents_or_float(amt, always_cents=False),
                "email": str(usr.get("email") or pay.get("email") or ""),
                "is_refund": status_s == "refunded" or bool(pay.get("amount_after_refunds") == 0 and float(pay.get("refunded_amount") or 0) > 0),
            })

    imported = 0
    refunded = 0
    skipped = 0
    results: list[dict[str, Any]] = []
    for entry in parsed_items:
        if not entry["sale_id"]:
            continue
        r = _ingest_autopilot_sale_or_refund(
            memory,
            acc=acc,
            external_sale_id=entry["sale_id"],
            product_title=entry["title"],
            gross_usd=entry["gross_usd"],
            customer_email=entry["email"],
            is_refund=entry["is_refund"],
            now_ts=now_ts,
        )
        results.append(r)
        if r["action"] == "sale_ingested_autopilot":
            imported += 1
        elif r["action"] == "refund_processed":
            refunded += 1
        else:
            skipped += 1

    return {
        "ok": True,
        "pull_supported": True,
        "store_account_id": store_account_id,
        "store_type": st,
        "imported_count": imported,
        "refunded_count": refunded,
        "skipped_count": skipped,
        "results": results,
    }


def _header_ci(headers: dict[str, str], name: str) -> str:
    low = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == low:
            return str(v or "")
    return ""


def _verify_hmac_hex(secret: str, raw_body: bytes, provided_sig: str) -> bool:
    if not secret or not provided_sig:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    clean = provided_sig.strip().lower()
    if clean.startswith("sha256="):
        clean = clean[7:]
    return hmac.compare_digest(expected.lower(), clean)


def verify_and_process_store_webhook(
    memory,
    store_type: str,
    raw_body: bytes,
    headers: dict[str, str],
    *,
    store_account_id: str = "",
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Криптографически проверяет подпись вебхука каждого магазина и заводит продажу (20% автопилот) или возврат."""
    _ensure_schema(memory)
    st = _norm_store(store_type)
    acc = _find_store_row(memory, st, store_account_id)
    if acc is None:
        raise KeyError(f"Аккаунт для вебхука {st!r} не найден.")

    api_key = freelance_autonomy._unseal_secret(memory, acc.get("api_key_enc") or "")
    wh_secret = freelance_autonomy._unseal_secret(memory, acc.get("webhook_secret_enc") or "")
    body_text = raw_body.decode("utf-8", errors="replace")
    ctype = _header_ci(headers, "Content-Type").lower()

    payload: dict[str, Any]
    if "application/x-www-form-urlencoded" in ctype or (st == "gumroad" and not body_text.lstrip().startswith("{")):
        qs = urllib.parse.parse_qs(body_text, keep_blank_values=True)
        payload = {k: (v[0] if len(v) == 1 else v) for k, v in qs.items()}
    else:
        payload = json.loads(body_text)

    # 1. Криптографическая проверка подписи по правилам конкретной площадки
    ext_event_id = ""
    if st == "lemonsqueezy":
        sig = _header_ci(headers, "X-Signature")
        if not wh_secret or not _verify_hmac_hex(wh_secret, raw_body, sig):
            raise PermissionError("Неверная подпись X-Signature для вебхука Lemon Squeezy.")
        ev_name = (_header_ci(headers, "X-Event-Name") or str((payload.get("meta") or {}).get("event_name") or "")).lower()
        data_obj = payload.get("data") or {}
        attr = data_obj.get("attributes") or {}
        first_item = attr.get("first_order_item") or {}
        sale_id = str(data_obj.get("id") or "")
        ext_event_id = f"{ev_name}:{sale_id}"
        is_refund = "refund" in ev_name or str(attr.get("status") or "").lower() == "refunded"
        title = str(first_item.get("product_name") or attr.get("product_name") or "Lemon Squeezy Product")
        gross = _money_from_cents_or_float(attr.get("total"), always_cents=True)
        email = str(attr.get("user_email") or "")

    elif st == "gumroad":
        sig = _header_ci(headers, "X-Padam-Signature") or _header_ci(headers, "X-Signature")
        if wh_secret and sig:
            if not _verify_hmac_hex(wh_secret, raw_body, sig):
                raise PermissionError("Неверная подпись вебхука Gumroad.")
        elif wh_secret and not sig:
            # Если настроен секрет, разрешаем либо явный X-Padam-Signature, либо точное совпадение seller_id
            inc_seller = str(payload.get("seller_id") or "")
            expected_seller = str(acc.get("external_store_id") or "")
            if not expected_seller or not hmac.compare_digest(expected_seller, inc_seller):
                raise PermissionError("Неверный seller_id или отсутствует подпись вебхука Gumroad.")
        else:
            inc_seller = str(payload.get("seller_id") or "")
            expected_seller = str(acc.get("external_store_id") or "")
            if not expected_seller or not hmac.compare_digest(expected_seller, inc_seller):
                raise PermissionError("Неверный seller_id в Gumroad Ping вебхуке.")

        sale_id = str(payload.get("sale_id") or payload.get("id") or "")
        is_refund = str(payload.get("refunded") or "").lower() in ("true", "1", "yes")
        ext_event_id = f"{'refund' if is_refund else 'sale'}:{sale_id}"
        title = str(payload.get("product_name") or "Gumroad Product")
        gross = _money_from_cents_or_float(payload.get("price"), always_cents=True)
        email = str(payload.get("email") or "")

    elif st == "payhip":
        sig_field = str(payload.get("signature") or "").strip().lower()
        expected_api_sha = hashlib.sha256(api_key.encode("utf-8")).hexdigest().lower() if api_key else ""
        x_sig = _header_ci(headers, "X-Signature")
        sig_ok = bool(expected_api_sha and sig_field and hmac.compare_digest(expected_api_sha, sig_field))
        if not sig_ok and wh_secret and x_sig:
            sig_ok = _verify_hmac_hex(wh_secret, raw_body, x_sig)
        if not sig_ok:
            raise PermissionError("Неверная подпись sha256(api_key) в вебхуке Payhip.")

        ev_type = str(payload.get("type") or "paid").lower()
        sale_id = str(payload.get("id") or "")
        ext_event_id = f"{ev_type}:{sale_id}"
        is_refund = "refund" in ev_type or "deleted" in ev_type
        items = payload.get("items") or []
        title = str(items[0].get("product_name")) if items else str(payload.get("product_name") or "Payhip Product")
        gross = _money_from_cents_or_float(payload.get("price"), always_cents=True)
        email = str(payload.get("email") or "")

    elif st == "sellfy":
        sig = _header_ci(headers, "X-Sellfy-Signature") or _header_ci(headers, "X-Signature")
        if not wh_secret or not _verify_hmac_hex(wh_secret, raw_body, sig):
            raise PermissionError("Неверная HMAC-подпись вебхука Sellfy.")
        ev_type = str(payload.get("event") or payload.get("status") or "New order").lower()
        sale_id = str(payload.get("id") or "")
        ext_event_id = f"{ev_type}:{sale_id}"
        is_refund = "refund" in ev_type or "cancel" in ev_type or str(payload.get("status") or "").upper() == "REFUNDED"
        cust = payload.get("customer") or {}
        items = payload.get("items") or []
        title = str(items[0].get("title") or items[0].get("name")) if items else str(payload.get("product_name") or "Sellfy Product")
        gross = _money_from_cents_or_float(payload.get("amount"), always_cents=True)
        email = str(cust.get("email") or payload.get("email") or "")

    else:
        # Whop Standard Webhooks: webhook-id, webhook-timestamp, webhook-signature (v1,<base64>)
        wh_id = _header_ci(headers, "webhook-id").strip()
        wh_ts_str = _header_ci(headers, "webhook-timestamp").strip()
        wh_sig_hdr = _header_ci(headers, "webhook-signature").strip()
        if not wh_secret or not wh_id or not wh_ts_str or not wh_sig_hdr:
            raise PermissionError("Отсутствуют заголовки Standard Webhooks или секрет для Whop.")
        try:
            wh_ts = int(float(wh_ts_str))
        except ValueError as e:
            raise PermissionError("Некорректный webhook-timestamp для Whop.") from e
        ref_now = int(now_ts if now_ts is not None else time.time())
        if abs(ref_now - wh_ts) > 300:
            raise PermissionError("Устаревший webhook-timestamp Whop (> 300с).")

        # Ключ Whop (ws_...) по официальной документации используется напрямую в UTF-8 без декодирования base64.
        signed_content = f"{wh_id}.{wh_ts_str}.{body_text}".encode("utf-8")
        expected_b64 = base64.b64encode(
            hmac.new(wh_secret.encode("utf-8"), signed_content, hashlib.sha256).digest()
        ).decode("ascii")
        expected_token = f"v1,{expected_b64}"
        sig_tokens = [tok.strip() for tok in wh_sig_hdr.split() if tok.strip()]
        if not any(hmac.compare_digest(expected_token, tok) for tok in sig_tokens):
            raise PermissionError("Неверная подпись Standard Webhooks для Whop.")

        ev_type = str(payload.get("type") or payload.get("action") or "payment.succeeded").lower()
        data_obj = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        sale_id = str(data_obj.get("id") or payload.get("id") or wh_id)
        ext_event_id = wh_id
        is_refund = "refund" in ev_type or str(data_obj.get("status") or "").lower() == "refunded"
        usr = data_obj.get("user") or {}
        prd = data_obj.get("product") or {}
        amt = data_obj.get("final_amount") if data_obj.get("final_amount") is not None else data_obj.get("amount")
        title = str(prd.get("title") or data_obj.get("product_title") or "Whop Product")
        gross = _money_from_cents_or_float(amt, always_cents=False)
        email = str(usr.get("email") or data_obj.get("email") or "")

    # 2. Идемпотентность вебхука
    payload_hash = hashlib.sha256(raw_body).hexdigest()
    event_key = f"{st}:{acc['store_account_id']}:{ext_event_id or payload_hash[:16]}"
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        dup = conn.execute(
            "SELECT * FROM ark_store_webhook_event WHERE user_id = ? AND event_key = ?",
            (memory.user_id, event_key),
        ).fetchone()
    if dup is not None:
        return {
            "ok": True,
            "duplicate": True,
            "store_type": st,
            "event_key": event_key,
            "order_id": dup["order_id"],
        }

    res = _ingest_autopilot_sale_or_refund(
        memory,
        acc=acc,
        external_sale_id=sale_id,
        product_title=title,
        gross_usd=gross,
        customer_email=email,
        is_refund=is_refund,
        refund_reason=f"Возврат по вебхуку {st} ({ext_event_id})",
        now_ts=now_ts,
    )
    order_id = str(res.get("order_id") or "")
    now = float(now_ts if now_ts is not None else time.time())
    with freelance_autonomy._lock_of(memory):
        conn.execute(
            """
            INSERT OR IGNORE INTO ark_store_webhook_event (
                event_key, user_id, store_type, store_account_id, external_event_id,
                event_kind, order_id, payload_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_key,
                memory.user_id,
                st,
                acc["store_account_id"],
                ext_event_id,
                "refund" if is_refund else "sale",
                order_id,
                payload_hash,
                now,
            ),
        )
        conn.commit()

    return {
        "ok": True,
        "duplicate": False,
        "store_type": st,
        "event_key": event_key,
        **res,
    }


def digital_stores_snapshot(memory, *, auto_seed_starters: bool = False) -> dict[str, Any]:
    """Сводка 5 магазинов цифровых товаров, подключённых аккаунтов и черновиков для Studio/MCP."""
    _ensure_schema(memory)
    stores = list_connected_stores(memory)
    drafts = list_product_drafts(memory)
    if auto_seed_starters and not drafts:
        seed_starter_product_drafts(memory)
        drafts = list_product_drafts(memory)
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        events = conn.execute(
            "SELECT event_key, store_type, store_account_id, event_kind, order_id, created_at "
            "FROM ark_store_webhook_event WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
            (memory.user_id,),
        ).fetchall()
    return {
        "supported_stores": list(STORE_SPECS.values()),
        "connected_stores": stores,
        "product_drafts": drafts,
        "recent_webhook_events": [dict(r) for r in events],
        "autopilot_code_fee_pct": freelance_autonomy.AUTOPILOT_FEE_PCT,
    }
