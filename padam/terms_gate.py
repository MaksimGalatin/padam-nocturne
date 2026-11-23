# -*- coding: utf-8 -*-
"""Шлюз согласия с Лицензией PADAM 1.0 (комиссия CODE Eternal 15%/20% с Заработка) при установке и запуске заработка.

Хранит версию `PADAM_LICENSE_1.0` на 4 языках (`ru`, `en`, `es`, `zh`), проверяет 3 галочки
(Лицензия, Комиссия 15%/20%, Запрет обхода), записывает
подписанную HMAC-SHA256 квитанцию в SQLite (`ark_terms_acceptance`) и блокирует обход.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any

from . import audit_chain, integrity, roles

CURRENT_TERMS_VERSION = "PADAM_LICENSE_1.0_2026-11-23"

# Конспект PADAM License 1.0 (файл LICENSE); его SHA-256 входит в подписанную квитанцию согласия.
TERMS_TEXT_HASH_SOURCE = (
    "PADAM License 1.0 (LicenseRef-PADAM-1.0), CODE Eternal LLC (New Mexico Entity ID 0008138873, "
    "contact@codeofdigitaleternity.com). Source-available, not open source; versions 0.8.0 and later. "
    "Free to install and use. Commission to CODE Eternal LLC on every paid order, sale or service obtained, "
    "prepared or carried out with the Earning features: 15% assisted mode, 20% autopilot mode; due within 14 days "
    "unless deducted by payment rails; unpaid commission may suspend the Earning features. Not allowed: removing, "
    "disabling, bypassing or falsifying the commission calculation, ledger, payment routing, acceptance screen or "
    "notices; distributing changed copies; selling, renting, sublicensing or hosting for others; building a competing "
    "product. Governed by the laws of New Mexico, USA."
)

TERMS_SHA256 = hashlib.sha256(TERMS_TEXT_HASH_SOURCE.encode("utf-8")).hexdigest()

TERMS_COPY: dict[str, dict[str, Any]] = {
    "ru": {
        "title": "Лицензия PADAM 1.0 и комиссия CODE Eternal",
        "summary": "Лицензиар: CODE Eternal LLC (Нью-Мексико, США · Entity ID 0008138873 · contact@codeofdigitaleternity.com). PADAM — программа с доступным для чтения кодом по Лицензии PADAM 1.0 (не открытая лицензия). Пользоваться бесплатно; с Заработка — комиссия. Без трёх галочек установка MCP и модули Заработка закрыты.",
        "checks": [
            {"id": "accept_license", "label": "Я прочитал(а) и принимаю Лицензию PADAM 1.0 (файл LICENSE): пользоваться можно; изменённые копии раздавать, продавать и сдавать как сервис нельзя; а также Политику конфиденциальности."},
            {"id": "accept_commission", "label": "Я соглашаюсь платить CODE Eternal LLC комиссию с каждого оплаченного заказа, продажи или услуги, полученных или выполненных с помощью Заработка: 15% — когда отправляю сам, 20% — в автопилоте. Не хочу платить — не пользуюсь Заработком."},
            {"id": "accept_no_bypass", "label": "Я не буду обходить, отключать или подделывать расчёт комиссии, её журнал и маршрут оплаты и понимаю, что при неоплаченной комиссии Заработок может быть приостановлен."},
        ],
    },
    "en": {
        "title": "PADAM License 1.0 & CODE Eternal Commission",
        "summary": "Licensor: CODE Eternal LLC (New Mexico, USA · Entity ID 0008138873 · contact@codeofdigitaleternity.com). PADAM is source-available software under the PADAM License 1.0 (not an open-source licence). Free to use; Earning carries a commission. MCP setup and the Earning features stay locked until all 3 boxes are checked.",
        "checks": [
            {"id": "accept_license", "label": "I have read and accept the PADAM License 1.0 (LICENSE file): I may use the software; I may not hand out, sell or host changed copies for others; and I accept the Privacy Policy."},
            {"id": "accept_commission", "label": "I agree to pay CODE Eternal LLC a commission on every paid order, sale or service obtained or carried out with the Earning features: 15% when I send the work myself, 20% in autopilot. If I do not want to pay, I do not use Earning."},
            {"id": "accept_no_bypass", "label": "I will not bypass, disable or falsify the commission calculation, its ledger or payment routing, and I understand that unpaid commission may suspend the Earning features."},
        ],
    },
    "es": {
        "title": "Licencia PADAM 1.0 y comisión de CODE Eternal",
        "summary": "Licenciante: CODE Eternal LLC (Nuevo México, EE. UU. · Entity ID 0008138873 · contact@codeofdigitaleternity.com). PADAM es software de código disponible bajo la Licencia PADAM 1.0 (no es una licencia de código abierto). Uso gratuito; los Ingresos llevan comisión. La configuración MCP y los módulos de Ingresos siguen bloqueados sin las 3 casillas.",
        "checks": [
            {"id": "accept_license", "label": "He leído y acepto la Licencia PADAM 1.0 (archivo LICENSE): puedo usar el software; no puedo distribuir, vender ni ofrecer como servicio copias modificadas; y acepto la Política de Privacidad."},
            {"id": "accept_commission", "label": "Acepto pagar a CODE Eternal LLC una comisión por cada pedido, venta o servicio pagado obtenido o realizado con los Ingresos: 15% si envío yo, 20% en piloto automático. Si no quiero pagar, no uso los Ingresos."},
            {"id": "accept_no_bypass", "label": "No eludiré, desactivaré ni falsificaré el cálculo de la comisión, su registro ni la ruta de pago, y entiendo que una comisión impagada puede suspender los Ingresos."},
        ],
    },
    "zh": {
        "title": "PADAM 许可证 1.0 与 CODE Eternal 佣金",
        "summary": "许可方：CODE Eternal LLC（美国新墨西哥州 · Entity ID 0008138873 · contact@codeofdigitaleternity.com）。PADAM 为源码可见软件，采用 PADAM 许可证 1.0（非开源许可证）。免费使用；创收功能需支付佣金。未勾选全部三项前，MCP 配置与创收功能保持锁定。",
        "checks": [
            {"id": "accept_license", "label": "我已阅读并接受 PADAM 许可证 1.0（LICENSE 文件）：可以使用本软件；不得分发、出售或以服务形式提供修改后的副本；并接受隐私政策。"},
            {"id": "accept_commission", "label": "我同意就通过创收功能获得或完成的每一笔已付款订单、销售或服务向 CODE Eternal LLC 支付佣金：本人提交 15%，自动驾驶 20%。不愿支付则不使用创收功能。"},
            {"id": "accept_no_bypass", "label": "我不会绕过、停用或伪造佣金计算、佣金记录或付款路由，并理解未付佣金可能导致创收功能被暂停。"},
        ],
    },
}

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_table(memory) -> None:
    memory.store.conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ark_terms_acceptance (
            user_id       TEXT PRIMARY KEY,
            terms_version TEXT NOT NULL,
            terms_sha256  TEXT NOT NULL,
            checks_json   TEXT NOT NULL,
            accepted_by   TEXT NOT NULL,
            accepted_at   TEXT NOT NULL,
            hmac_sig      TEXT NOT NULL
        )
        """
    )
    memory.store.conn.commit()


def _sign_acceptance(memory, user_id: str, ver: str, sha: str, checks: dict[str, bool], ts: str) -> str:
    k_raw, _ = integrity.owner_key(memory.store)
    blob = f"terms|{user_id}|{ver}|{sha}|{json.dumps(checks, sort_keys=True)}|{ts}".encode("utf-8")
    return hmac.new(k_raw, blob, hashlib.sha256).hexdigest()


def terms_status(memory, *, lang: str = "ru") -> dict[str, Any]:
    _ensure_table(memory)
    row = memory.store.one(
        "SELECT user_id, terms_version, terms_sha256, checks_json, accepted_by, accepted_at, hmac_sig "
        "FROM ark_terms_acceptance WHERE user_id = ?",
        (memory.user_id,),
    )
    accepted = False
    sig_ok = False
    accepted_at = None
    checks: dict[str, bool] = {}
    if row:
        try:
            checks = json.loads(row["checks_json"] or "{}")
        except Exception:
            checks = {}
        expected = _sign_acceptance(
            memory,
            str(row["user_id"]),
            str(row["terms_version"]),
            str(row["terms_sha256"]),
            checks,
            str(row["accepted_at"]),
        )
        sig_ok = hmac.compare_digest(expected, str(row["hmac_sig"] or ""))
        all_checked = all(bool(checks.get(k)) for k in ("accept_license", "accept_commission", "accept_no_bypass"))
        accepted = (
            sig_ok
            and row["terms_version"] == CURRENT_TERMS_VERSION
            and row["terms_sha256"] == TERMS_SHA256
            and all_checked
        )
        accepted_at = row["accepted_at"]

    lg = lang if lang in TERMS_COPY else "en"
    return {
        "accepted": accepted,
        "signature_verified": sig_ok,
        "terms_version": CURRENT_TERMS_VERSION,
        "terms_sha256": TERMS_SHA256,
        "accepted_at": accepted_at,
        "checks": checks,
        "copy": TERMS_COPY[lg],
    }


def accept_terms(
    memory,
    *,
    accept_license: bool,
    accept_commission: bool,
    accept_no_bypass: bool,
    actor: Any = None,
    accepted_by: str = "owner",
) -> dict[str, Any]:
    roles.require_owner(actor, "terms_accept")
    if not (bool(accept_license) and bool(accept_commission) and bool(accept_no_bypass)):
        raise ValueError(
            "All 3 checkboxes (PADAM License 1.0, 15%/20% Earning commission, no-bypass) must be accepted"
        )
    _ensure_table(memory)
    checks = {
        "accept_license": True,
        "accept_commission": True,
        "accept_no_bypass": True,
    }
    ts = _now()
    sig = _sign_acceptance(memory, memory.user_id, CURRENT_TERMS_VERSION, TERMS_SHA256, checks, ts)
    with memory.store._lock:
        memory.store.execute(
            """
            INSERT INTO ark_terms_acceptance (user_id, terms_version, terms_sha256, checks_json, accepted_by, accepted_at, hmac_sig)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                terms_version=excluded.terms_version,
                terms_sha256=excluded.terms_sha256,
                checks_json=excluded.checks_json,
                accepted_by=excluded.accepted_by,
                accepted_at=excluded.accepted_at,
                hmac_sig=excluded.hmac_sig
            """,
            (memory.user_id, CURRENT_TERMS_VERSION, TERMS_SHA256, json.dumps(checks, sort_keys=True), str(accepted_by)[:64], ts, sig),
        )
    audit_chain.append_audit(
        memory,
        "terms_accepted",
        {"version": CURRENT_TERMS_VERSION, "sha256_prefix": TERMS_SHA256[:16]},
        agent_id="owner",
    )
    return {"ok": True, **terms_status(memory)}


def require_terms_accepted(memory) -> dict[str, Any]:
    st = terms_status(memory)
    if not st["accepted"]:
        raise PermissionError(
            f"Terms acceptance required ({CURRENT_TERMS_VERSION}): accept the PADAM License 1.0, the 15%/20% Earning commission and the no-bypass rule first"
        )
    return st


def earning_gate(memory) -> dict[str, Any]:
    """Вход в Заработок (биржи, ставки, Рой, автопилот, Мастер платформ): только после согласия с Лицензией PADAM 1.0.
    Отдельная функция, чтобы тесты работы бирж могли считать согласие данным, не трогая проверку самого шлюза."""
    return require_terms_accepted(memory)
