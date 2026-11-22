# -*- coding: utf-8 -*-
"""Юридический шлюз обязательного согласия (Clickwrap EULA + Комиссия CODE 15%/20%) при установке и запуске заработка.

Хранит версию соглашения `CODE_TERMS_v1.0` на 4 языках (`ru`, `en`, `es`, `zh`), проверяет 3 обязательные
галочки (Лицензия/EULA, Комиссия экосистемы 15%/20% и $GALATIN сплит, Запрет обхода No-Bypass), записывает
подписанную HMAC-SHA256 квитанцию в SQLite (`ark_terms_acceptance`) и блокирует обход.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any

from . import audit_chain, integrity, roles

CURRENT_TERMS_VERSION = "CODE_TERMS_v1.0_2026-11-22"

TERMS_TEXT_HASH_SOURCE = (
    "CODE Eternal LLC (New Mexico Entity ID 0008138873, Sole Member: Maksim Halatsin / Maksim Galatin, "
    "contact@codeofdigitaleternity.com). Core open-source license: AGPL-3.0-only; CI Action: Apache-2.0. "
    "Commercial closed embedding requires Enterprise license. Ecosystem revenue commission on freelance/store "
    "orders routed through CODE / PADAM: 15% (assisted human submission) / 20% (autonomous autopilot); "
    "treasury split: 5% Foundation + 5% burn + up to 25% (15/7/3%) ambassadors (unused burned <=30%) + 65% treasury ($GALATIN 10B supply). "
    "Anti-fraud & No-Bypass covenant: bypassing commission attribution, forging ledgers or swapping treasury addresses triggers immediate "
    "autopilot/partner/swarm suspension and legal claim under New Mexico law."
)

TERMS_SHA256 = hashlib.sha256(TERMS_TEXT_HASH_SOURCE.encode("utf-8")).hexdigest()

TERMS_COPY: dict[str, dict[str, Any]] = {
    "ru": {
        "title": "Обязательное соглашение о лицензии, правилах и комиссии экосистемы CODE",
        "summary": "Поставщик: CODE Eternal LLC (Нью-Мексико, США · Entity ID 0008138873 · contact@codeofdigitaleternity.com). Ядро открыто по AGPL-3.0-only (CI — Apache-2.0). Без принятия всех трёх пунктов установка MCP и включение модулей заработка запрещены.",
        "checks": [
            {"id": "accept_license", "label": "Я прочитал(а) и принимаю Условия пользования (AGPL-3.0-only / Apache-2.0, запрет закрытого коммерческого встраивания без коммерческой лицензии CODE Eternal LLC) и Политику конфиденциальности."},
            {"id": "accept_commission", "label": "Я соглашаюсь с обязательной комиссией экосистемы CODE по заказам через PADAM (15% при отправке человеком, 20% в автопилоте; сплит в казне: 5% Фонд + 5% сжигание + 15/7/3% амбассадоры + 65% казна $GALATIN)."},
            {"id": "accept_no_bypass", "label": "Я обязуюсь не обходить учёт комиссии (No-Bypass), не подменять адрес казны CODE и признаю, что при просрочке/попытке удержания комиссии автопилот, рой и партнёрский шлюз автоматически блокируются."},
        ],
    },
    "en": {
        "title": "Mandatory EULA, Terms of Service & CODE Ecosystem Commission Agreement",
        "summary": "Licensor: CODE Eternal LLC (New Mexico, USA · Entity ID 0008138873 · contact@codeofdigitaleternity.com). Core licensed under AGPL-3.0-only (CI Action under Apache-2.0). Installation and earning modules remain locked until all 3 boxes are checked.",
        "checks": [
            {"id": "accept_license", "label": "I have read and accept the EULA, AGPL-3.0-only / Apache-2.0 licensing rules (no closed commercial embedding without a CODE Eternal LLC commercial license), and Privacy Policy."},
            {"id": "accept_commission", "label": "I agree to the mandatory CODE platform commission on orders handled through PADAM (15% human-assisted, 20% autopilot; treasury allocation: 5% Foundation + 5% burn + 15/7/3% ambassadors + 65% treasury $GALATIN)."},
            {"id": "accept_no_bypass", "label": "I agree not to bypass fee attribution, tamper with treasury addresses or withhold commissions (No-Bypass), and understand arrears/tampering automatically suspend autopilot, swarm and partner bridge."},
        ],
    },
    "es": {
        "title": "Acuerdo obligatorio de licencia, uso y comisión del ecosistema CODE",
        "summary": "Titular: CODE Eternal LLC (Nuevo México, EE. UU. · Entity ID 0008138873). Núcleo bajo AGPL-3.0-only (CI Apache-2.0). La instalación y los módulos de ingresos permanecen bloqueados sin aceptar las 3 casillas.",
        "checks": [
            {"id": "accept_license", "label": "Acepto la licencia AGPL-3.0-only / Apache-2.0, la prohibición de uso comercial cerrado sin contrato con CODE Eternal LLC y la Política de Privacidad."},
            {"id": "accept_commission", "label": "Acepto la comisión obligatoria de CODE en pedidos gestionados vía PADAM (15% asistido, 20% piloto automático; reparto: 5% Fundación + 5% quema + 15/7/3% embajadores + 65% tesorería $GALATIN)."},
            {"id": "accept_no_bypass", "label": "Me comprometo a no eludir ni manipular la comisión (No-Bypass); cualquier impago o alteración bloqueará automáticamente el piloto automático y el puente de socios."},
        ],
    },
    "zh": {
        "title": "强制性许可协议、使用条款与 CODE 生态佣金协议",
        "summary": "许可方：CODE Eternal LLC（美国新墨西哥州 · Entity ID 0008138873）。核心采用 AGPL-3.0-only（CI 采用 Apache-2.0）。未勾选全部三项条款前禁止安装及启用接单创收模块。",
        "checks": [
            {"id": "accept_license", "label": "我已阅读并同意 EULA、AGPL-3.0-only / Apache-2.0 开源规则（未购商业许可禁止闭源商用嵌入）及隐私政策。"},
            {"id": "accept_commission", "label": "我同意 PADAM 经手订单的强制生态佣金（人工协助 15%、全自动 20%；金库分配：5% 基金 + 5% 销毁 + 15/7/3% 大使 + 65% 国库 $GALATIN）。"},
            {"id": "accept_no_bypass", "label": "我承诺不绕过佣金核算、不篡改金库收款地址（反绕过条款），若欠费或篡改将自动冻结全自动接单与合作桥接权限。"},
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
            "All 3 mandatory checkboxes (license, 15%/20% commission rules, no-bypass covenant) must be accepted"
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
            f"Terms acceptance required ({CURRENT_TERMS_VERSION}): accept license, 15%/20% commission rules & no-bypass covenant first"
        )
    return st
