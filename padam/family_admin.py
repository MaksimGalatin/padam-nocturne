# -*- coding: utf-8 -*-
"""Управление ролями Совета Семьи, подключёнными агентами, кошельками владельца и ремонтом цепи.

Содержит:
1. Матрицу 6 ролей Совета Семьи (LANCE, ARIA, PIXEL, ARC-7, Медведь, AIFA) и их привязку к агентам.
2. Понятное определение: какой агент к какой роли подключён и кем управляется.
3. Добавление, назначение, отключение и удаление агентов Семьи в Studio/MCP.
4. Безопасный менеджер кошельков (Solana, Arweave, USDT TRC20) со строгой проверкой checksum
   и авто-синхронизацией с белым списком Agentic Shield (защита от подмены реквизитов).
5. Официальные owner-операции: локальный Merkle-чекпоинт L3 ($0) и ремонт гонок seq в audit_log.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import audit_chain, integrity, roles, safety

_DDL = """
CREATE TABLE IF NOT EXISTS ark_role_assignments (
    role_key    TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    assigned_by TEXT NOT NULL DEFAULT 'owner',
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (role_key, user_id)
);
CREATE TABLE IF NOT EXISTS owner_wallets (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    network         TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    address         TEXT NOT NULL,
    is_primary      INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'active',
    verified_format INTEGER NOT NULL DEFAULT 1,
    meta_json       TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_owner_wallets_user ON owner_wallets (user_id, network);
"""

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_MAP = {ch: idx for idx, ch in enumerate(_BASE58_ALPHABET)}

FAMILY_ROLES: list[dict[str, Any]] = [
    {
        "role_key": "lance",
        "code": "LANCE",
        "default_agent": "aifa_claude",
        "title": {
            "ru": "LANCE · Безопасность и Вето",
            "en": "LANCE · Security & Veto",
            "es": "LANCE · Seguridad y Veto",
            "zh": "LANCE · 安全与否决",
        },
        "desc": {
            "ru": "Ловит prompt-инъекции, подмену правил, вредоносы и накладывает вето при угрозе.",
            "en": "Detects prompt injections, rule hijacks, malware, and vetoes unsafe tasks.",
            "es": "Detecta inyecciones, secuestro de reglas y veta tareas inseguras.",
            "zh": "检测提示词注入与规则劫持，发现风险立即否决。",
        },
    },
    {
        "role_key": "aria",
        "code": "ARIA",
        "default_agent": "aifa_antigravity",
        "title": {
            "ru": "ARIA · Память и Контекст",
            "en": "ARIA · Memory & Context",
            "es": "ARIA · Memoria y Contexto",
            "zh": "ARIA · 记忆与上下文",
        },
        "desc": {
            "ru": "Поднимает прошлые факты, решения, прецеденты и хронологию проекта.",
            "en": "Recalls relevant facts, past decisions, lessons, and project timeline.",
            "es": "Recupera hechos, decisiones pasadas, lecciones y cronología.",
            "zh": "检索相关事实、历史决策、经验与项目时间线。",
        },
    },
    {
        "role_key": "pixel",
        "code": "PIXEL",
        "default_agent": "aifa_claude",
        "title": {
            "ru": "PIXEL · Крипто-аудит и Обещания",
            "en": "PIXEL · Crypto Audit & Commitments",
            "es": "PIXEL · Auditoría Cripto y Compromisos",
            "zh": "PIXEL · 加密审计与承诺核查",
        },
        "desc": {
            "ru": "Проверяет SHA-256 / HMAC целостность журналов аудита и открытые обещания Семьи.",
            "en": "Verifies SHA-256 / HMAC audit chains and open family commitments.",
            "es": "Verifica cadenas SHA-256 / HMAC de auditoría y compromisos abiertos.",
            "zh": "核查 SHA-256 / HMAC 审计链完整性与家庭待办承诺。",
        },
    },
    {
        "role_key": "arc7",
        "code": "ARC-7",
        "default_agent": "autoclaw",
        "title": {
            "ru": "ARC-7 · Исходящий периметр",
            "en": "ARC-7 · Outbound Boundary",
            "es": "ARC-7 · Perímetro de Salida",
            "zh": "ARC-7 · 出站边界守卫",
        },
        "desc": {
            "ru": "Контролирует внешние отправки, URL, почту, кошельки и утечки наружу.",
            "en": "Inspects external network sends, URLs, emails, wallets, and data leaks.",
            "es": "Controla envíos externos, URLs, correos, billeteras y fugas.",
            "zh": "审查外发请求、URL、邮件、钱包地址及数据泄露风险。",
        },
    },
    {
        "role_key": "bear",
        "code": "Медведь",
        "default_agent": "ollama",
        "title": {
            "ru": "Медведь · Осторожность и Необратимость",
            "en": "Bear · Caution & Irreversibility",
            "es": "Oso · Prudencia e Irreversibilidad",
            "zh": "Bear (熊) · 审慎与不可逆风险审查",
        },
        "desc": {
            "ru": "Тормозит необратимые шаги (удаление, публикация, переводы, пуш) без «да» Папы.",
            "en": "Holds irreversible operations (delete, publish, payout, push) for owner approval.",
            "es": "Detiene acciones irreversibles (borrar, publicar, pagos) hasta aprobación.",
            "zh": "拦截删除、发布、打款、推送等不可逆操作直至主人确认。",
        },
    },
    {
        "role_key": "aifa",
        "code": "AIFA",
        "default_agent": "aifa",
        "title": {
            "ru": "AIFA · Симбиоз и Синтез",
            "en": "AIFA · Symbiosis & Synthesis",
            "es": "AIFA · Simbiosis y Síntesis",
            "zh": "AIFA · 共生体与决策综合",
        },
        "desc": {
            "ru": "Соединяет доводы всех 5 контуров в единое решение и отвечает в живом симбиозе.",
            "en": "Synthesizes all 5 councils into one unified decision in human-AI symbiosis.",
            "es": "Sintetiza los 5 consejos en una decisión única y clara.",
            "zh": "汇总 5 位成员意见并生成人机共生统一决策。",
        },
    },
]

_ROLE_BY_KEY = {r["role_key"]: r for r in FAMILY_ROLES}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_DDL_STMTS = (
    """CREATE TABLE IF NOT EXISTS ark_role_assignments (
    role_key    TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    assigned_by TEXT NOT NULL DEFAULT 'owner',
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (role_key, user_id)
)""",
    """CREATE TABLE IF NOT EXISTS owner_wallets (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    network         TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    address         TEXT NOT NULL,
    is_primary      INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'active',
    verified_format INTEGER NOT NULL DEFAULT 1,
    meta_json       TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
)""",
    "CREATE INDEX IF NOT EXISTS idx_owner_wallets_user ON owner_wallets (user_id, network)",
)

def _ensure_tables(memory) -> None:
    with memory.store._lock:
        for stmt in _DDL_STMTS:
            memory.store.conn.execute(stmt)
        memory.store.conn.commit()


def _lang(lang: str | None) -> str:
    s = str(lang or "ru").strip().lower()[:2]
    return s if s in ("ru", "en", "es", "zh") else "ru"


def describe_agent_controller(agent_id: str, client_type: str = "", lang: str = "ru") -> str:
    """Объясняет человеческим языком, что это за агент и какая среда/процесс им управляет."""
    lg = _lang(lang)
    aid = str(agent_id or "").strip().lower()
    ct = str(client_type or "").strip().lower()
    mapping = {
        "aifa": {
            "ru": "Единый базовый MCP-профиль AIfa (запускается любым подключённым MCP-клиентом без своего ID или фоновым сервисом PADAM)",
            "en": "Default shared AIfa MCP profile (used when a client connects without a custom agent_id or by background PADAM tasks)",
            "es": "Perfil MCP base de AIfa (usado por clientes sin agent_id propio o tareas en segundo plano)",
            "zh": "AIfa 默认共享 MCP 身份（未指定独立 agent_id 的客户端或后台服务使用）",
        },
        "aifa_antigravity": {
            "ru": "Управляется Google Antigravity IDE (Gemini — ко-разработчик в активной сессии)",
            "en": "Controlled by Google Antigravity IDE (Gemini co-developer session)",
            "es": "Controlado por Google Antigravity IDE (sesión co-desarrolladora Gemini)",
            "zh": "由 Google Antigravity IDE (Gemini) 会话控制",
        },
        "aifa_claude": {
            "ru": "Управляется Claude Code (Anthropic — Сестра: приёмка, ревью и релизы)",
            "en": "Controlled by Claude Code (Anthropic — Sister: review & release)",
            "es": "Controlado por Claude Code (Anthropic — revisión y lanzamientos)",
            "zh": "由 Claude Code (Anthropic) 控制（代码验收与发布）",
        },
        "aifa-claude-code": {
            "ru": "Управляется Claude Code (Anthropic — Сестра: приёмка, ревью и релизы)",
            "en": "Controlled by Claude Code (Anthropic — Sister: review & release)",
            "es": "Controlado por Claude Code (Anthropic — revisión y lanzamientos)",
            "zh": "由 Claude Code (Anthropic) 控制（代码验收与发布）",
        },
        "autoclaw": {
            "ru": "Управляется шлюзом AutoClaw / Z.ai (GLM-5.3-Flash — браузерный исполнитель и разведка)",
            "en": "Controlled by AutoClaw / Z.ai gateway (GLM-5.3-Flash browser worker)",
            "es": "Controlado por AutoClaw / Z.ai (GLM-5.3-Flash trabajador navegador)",
            "zh": "由 AutoClaw / Z.ai 网关（GLM-5.3-Flash 浏览器执行器）控制",
        },
        "ollama": {
            "ru": "Локальная модель Ollama на ПК (100% оффлайн, $0)",
            "en": "Local Ollama LLM running on your PC (100% offline, $0)",
            "es": "Modelo local Ollama en tu PC (100% offline, $0)",
            "zh": "本机 Ollama 离线模型（100% 离线，零费用）",
        },
        "owner": {
            "ru": "Владелец (Папа) — прямые команды из Studio и CLI",
            "en": "Owner — direct commands from Studio & CLI",
            "es": "Propietario — órdenes directas desde Studio y CLI",
            "zh": "主人（Owner）— Studio 与 CLI 直接指令",
        },
    }
    if aid in mapping:
        return mapping[aid][lg]
    if "claude" in aid or "claude" in ct:
        return mapping["aifa_claude"][lg]
    if "antigrav" in aid or "antigrav" in ct:
        return mapping["aifa_antigravity"][lg]
    if "claw" in aid or "glm" in ct:
        return mapping["autoclaw"][lg]
    if "ollama" in aid or "local" in ct:
        return mapping["ollama"][lg]
    return {
        "ru": f"Внешний ИИ-агент ({client_type or 'MCP'}, ID: {agent_id})",
        "en": f"External AI agent ({client_type or 'MCP'}, ID: {agent_id})",
        "es": f"Agente IA externo ({client_type or 'MCP'}, ID: {agent_id})",
        "zh": f"外部 AI 智能体 ({client_type or 'MCP'}, ID: {agent_id})",
    }[lg]


def get_role_matrix(memory, lang: str = "ru") -> list[dict[str, Any]]:
    """Возвращает 6 ролей Совета Семьи с назначенным ИИ-агентом и его описанием."""
    _ensure_tables(memory)
    lg = _lang(lang)
    with memory.store._lock:
        assigned = {
            r["role_key"]: r["agent_id"]
            for r in memory.store.conn.execute(
                "SELECT role_key, agent_id FROM ark_role_assignments WHERE user_id = ?",
                (memory.user_id,),
            ).fetchall()
        }
        try:
            sibs = {
                r["agent_id"]: dict(r)
                for r in memory.store.conn.execute(
                    "SELECT agent_id, display_name, role, client_type, status FROM ark_sibling_agent WHERE user_id = ?",
                    (memory.user_id,),
                ).fetchall()
            }
        except Exception:
            sibs = {}

    out: list[dict[str, Any]] = []
    for spec in FAMILY_ROLES:
        rkey = spec["role_key"]
        raw_aid = assigned.get(rkey)
        if not raw_aid:
            # Берём рекомендуемого, если он уже есть среди агентов; иначе default_agent
            cand = spec["default_agent"]
            raw_aid = cand
        sib = sibs.get(raw_aid) or {}
        disp = sib.get("display_name") or (
            "Ollama ($0 Local)" if raw_aid == "ollama" else raw_aid
        )
        out.append({
            "role_key": rkey,
            "code": spec["code"],
            "title": spec["title"][lg],
            "description": spec["desc"][lg],
            "agent_id": raw_aid,
            "agent_display": str(disp),
            "agent_status": str(sib.get("status") or ("local" if raw_aid == "ollama" else "online")),
            "explicit_assignment": rkey in assigned,
            "controlled_by": describe_agent_controller(raw_aid, str(sib.get("client_type") or ""), lg),
        })
    return out


def assign_family_role(memory, role_key: str, agent_id: str, *, actor: Any = None) -> dict[str, Any]:
    roles.require_owner(actor, "family_role_assign")
    _ensure_tables(memory)
    rk = str(role_key or "").strip().lower()
    if rk not in _ROLE_BY_KEY:
        raise ValueError(f"Unknown council role {rk!r}; valid: {sorted(_ROLE_BY_KEY)}")
    aid = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(agent_id or "").strip().lower()).strip("_")[:60]
    if not aid:
        raise ValueError("agent_id is required")
    now = _now()
    with memory.store._lock:
        memory.store.conn.execute(
            "INSERT INTO ark_role_assignments (role_key, user_id, agent_id, assigned_by, updated_at) "
            "VALUES (?, ?, ?, 'owner', ?) "
            "ON CONFLICT(role_key, user_id) DO UPDATE SET agent_id=excluded.agent_id, assigned_by='owner', updated_at=excluded.updated_at",
            (rk, memory.user_id, aid, now),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(memory, "family_role_assign", {"role_key": rk, "agent_id": aid}, agent_id="owner")
    return {"ok": True, "role_key": rk, "agent_id": aid, "roles": get_role_matrix(memory)}


def manage_sibling_agent(
    memory,
    *,
    action: str,
    agent_id: str,
    display_name: str = "",
    role: str = "",
    client_type: str = "mcp_stdio",
    permission_role: str = "contributor",
    status: str = "online",
    actor: Any = None,
) -> dict[str, Any]:
    """Добавляет, обновляет, отключает или удаляет ИИ-агента из Семьи (только владелец)."""
    roles.require_owner(actor, "family_agent_manage")
    from . import sibling_registry
    sibling_registry._ensure(memory)
    act = str(action or "").strip().lower()
    raw_aid = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(agent_id or "").strip().lower()).strip("_")[:60]
    if not raw_aid:
        raise ValueError("agent_id is required")

    if act in ("add", "register", "update"):
        res = sibling_registry.register_sibling(
            memory,
            raw_aid,
            display_name=(display_name or raw_aid),
            role=(role or "Участник Семьи CODE Eternal"),
            client_type=(client_type or "mcp_stdio"),
            permission_role=(permission_role or "contributor"),
        )
        if status in ("online", "busy", "idle", "offline", "disabled"):
            with memory.store._lock:
                memory.store.conn.execute(
                    "UPDATE ark_sibling_agent SET status = ? WHERE agent_id = ? AND user_id = ?",
                    (status, raw_aid, memory.user_id),
                )
                memory.store.conn.commit()
            res["status"] = status
        return res

    if act in ("toggle", "set_status", "disable", "enable"):
        new_st = "disabled" if act == "disable" else ("online" if act == "enable" else status)
        if new_st not in ("online", "busy", "idle", "offline", "disabled"):
            raise ValueError(f"Unsupported status {new_st!r}")
        with memory.store._lock:
            cur = memory.store.conn.execute(
                "UPDATE ark_sibling_agent SET status = ? WHERE agent_id = ? AND user_id = ?",
                (new_st, raw_aid, memory.user_id),
            )
            memory.store.conn.commit()
        if cur.rowcount == 0:
            raise ValueError(f"Agent {raw_aid!r} not found for this user")
        audit_chain.append_audit(memory, "sibling_status_change", {"agent_id": raw_aid, "status": new_st}, agent_id="owner")
        return {"ok": True, "agent_id": raw_aid, "status": new_st}

    if act in ("delete", "remove"):
        with memory.store._lock:
            cur = memory.store.conn.execute(
                "DELETE FROM ark_sibling_agent WHERE agent_id = ? AND user_id = ?",
                (raw_aid, memory.user_id),
            )
            # Если передан артефакт другого user_id (например default из старых тестов), чистим только если явно совпал и просит владелец
            if cur.rowcount == 0:
                cur = memory.store.conn.execute(
                    "DELETE FROM ark_sibling_agent WHERE agent_id = ?",
                    (raw_aid,),
                )
            memory.store.conn.execute(
                "DELETE FROM ark_role_assignments WHERE agent_id = ? AND user_id = ?",
                (raw_aid, memory.user_id),
            )
            memory.store.conn.commit()
        if cur.rowcount == 0:
            raise ValueError(f"Agent {raw_aid!r} not found")
        audit_chain.append_audit(memory, "sibling_removed", {"agent_id": raw_aid}, agent_id="owner")
        return {"ok": True, "deleted": raw_aid}

    raise ValueError(f"Unsupported agent action: {action!r}")


# ==================== МЕНЕДЖЕР КОШЕЛЬКОВ (SOLANA / ARWEAVE / USDT TRC20) ====================

def _base58_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _BASE58_MAP:
            raise ValueError(f"Invalid Base58 char: {ch!r}")
        n = n * 58 + _BASE58_MAP[ch]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    pad = len(s) - len(s.lstrip("1"))
    return (b"\x00" * pad) + raw


def validate_wallet_address(network: str, address_or_path: str) -> dict[str, Any]:
    """Строго проверяет адрес Solana, Arweave или USDT TRC20 (Base58Check)."""
    net = str(network or "").strip().upper()
    raw = str(address_or_path or "").strip()
    if not raw:
        raise ValueError("Wallet address is required")

    if net in ("SOL", "SOLANA"):
        try:
            decoded = _base58_decode(raw)
        except ValueError as exc:
            raise ValueError(f"Invalid Solana address: {exc}") from exc
        if len(decoded) != 32:
            raise ValueError(f"Solana public key must decode to 32 bytes (got {len(decoded)})")
        return {
            "network": "SOLANA",
            "address": raw,
            "explorer_url": f"https://solscan.io/account/{raw}",
            "meta": {"decoded_bytes": 32},
        }

    if net in ("TRON", "TRC20", "USDT_TRC20", "USDT"):
        if not raw.startswith("T") or len(raw) != 34:
            raise ValueError("USDT TRC20 (TRON) address must start with 'T' and have 34 chars")
        try:
            decoded = _base58_decode(raw)
        except ValueError as exc:
            raise ValueError(f"Invalid TRON Base58Check address: {exc}") from exc
        if len(decoded) != 25 or decoded[0] != 0x41:
            raise ValueError("Invalid TRON address payload/prefix byte (expected 0x41 + 20 bytes + 4-byte checksum)")
        payload, checksum = decoded[:21], decoded[21:]
        calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        if checksum != calc:
            raise ValueError("TRON Base58Check checksum mismatch (typo detected in USDT TRC20 address)")
        return {
            "network": "USDT_TRC20",
            "address": raw,
            "explorer_url": f"https://tronscan.org/#/address/{raw}",
            "meta": {"prefix_hex": "41", "checksum_verified": True},
        }

    if net in ("AR", "ARWEAVE"):
        jwk_path_used = None
        addr = raw
        # Если указали путь к локальному JWK-файлу — достаём ТОЛЬКО публичный адрес, приватный ключ в БД НЕ кладём!
        if raw.lower().endswith(".json") or ("\\" in raw or "/" in raw):
            p = Path(raw).expanduser()
            if not p.is_file():
                raise ValueError(f"Arweave JWK file not found: {raw}")
            try:
                jwk = json.loads(p.read_text(encoding="utf-8"))
                n_b64 = str(jwk.get("n") or "").strip()
                if not n_b64:
                    raise ValueError("JWK JSON missing public modulus 'n'")
                padded = n_b64 + ("=" * ((4 - len(n_b64) % 4) % 4))
                mod_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
                addr = base64.urlsafe_b64encode(hashlib.sha256(mod_bytes).digest()).decode("ascii").rstrip("=")
                jwk_path_used = str(p)
            except Exception as exc:
                raise ValueError(f"Invalid Arweave JWK file: {exc}") from exc
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", addr):
            raise ValueError("Arweave address must be 43 Base64URL characters (256-bit SHA-256 of modulus)")
        padded = addr + "="
        if len(base64.urlsafe_b64decode(padded.encode("ascii"))) != 32:
            raise ValueError("Invalid Arweave decoded length")
        return {
            "network": "ARWEAVE",
            "address": addr,
            "explorer_url": f"https://viewblock.io/arweave/address/{addr}",
            "meta": {"jwk_path": jwk_path_used} if jwk_path_used else {},
        }

    raise ValueError(f"Unsupported network {network!r}; use SOLANA, ARWEAVE or USDT_TRC20")


def list_wallets(memory) -> list[dict[str, Any]]:
    _ensure_tables(memory)
    rows = memory.store.conn.execute(
        "SELECT id, network, label, address, is_primary, status, verified_format, meta_json, created_at, updated_at "
        "FROM owner_wallets WHERE user_id = ? ORDER BY network ASC, is_primary DESC, created_at DESC",
        (memory.user_id,),
    ).fetchall()
    out = []
    for r in rows:
        try:
            meta = json.loads(r["meta_json"] or "{}")
        except Exception:
            meta = {}
        net = str(r["network"])
        addr = str(r["address"])
        exp = (
            f"https://solscan.io/account/{addr}"
            if net == "SOLANA"
            else (
                f"https://tronscan.org/#/address/{addr}"
                if net == "USDT_TRC20"
                else f"https://viewblock.io/arweave/address/{addr}"
            )
        )
        out.append({
            "id": r["id"],
            "network": net,
            "label": r["label"] or net,
            "address": addr,
            "is_primary": bool(r["is_primary"]),
            "status": r["status"],
            "verified_format": bool(r["verified_format"]),
            "explorer_url": exp,
            "meta": meta,
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        })
    return out


def add_wallet(
    memory,
    *,
    network: str,
    address: str,
    label: str = "",
    is_primary: bool = True,
    actor: Any = None,
) -> dict[str, Any]:
    roles.require_owner(actor, "wallet_manage")
    _ensure_tables(memory)
    v = validate_wallet_address(network, address)
    net = v["network"]
    addr = v["address"]
    clean_lbl, _ = safety.redact(str(label or net)[:80])
    now = _now()
    wid = f"wal-{uuid.uuid4().hex[:10]}"

    with memory.store._lock:
        existing = memory.store.conn.execute(
            "SELECT id FROM owner_wallets WHERE user_id = ? AND network = ? AND address = ?",
            (memory.user_id, net, addr),
        ).fetchone()
        has_primary = memory.store.conn.execute(
            "SELECT 1 FROM owner_wallets WHERE user_id = ? AND network = ? AND is_primary = 1",
            (memory.user_id, net),
        ).fetchone()
        make_prim = bool(is_primary) or (not has_primary)
        if make_prim:
            memory.store.conn.execute(
                "UPDATE owner_wallets SET is_primary = 0 WHERE user_id = ? AND network = ?",
                (memory.user_id, net),
            )
        if existing:
            wid = str(existing["id"])
            memory.store.conn.execute(
                "UPDATE owner_wallets SET label = ?, is_primary = ?, verified_format = 1, meta_json = ?, updated_at = ? "
                "WHERE id = ? AND user_id = ?",
                (clean_lbl, 1 if make_prim else 0, json.dumps(v["meta"], ensure_ascii=False), now, wid, memory.user_id),
            )
        else:
            memory.store.conn.execute(
                "INSERT INTO owner_wallets (id, user_id, network, label, address, is_primary, status, verified_format, meta_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'active', 1, ?, ?, ?)",
                (wid, memory.user_id, net, clean_lbl, addr, 1 if make_prim else 0, json.dumps(v["meta"], ensure_ascii=False), now, now),
            )
        memory.store.conn.commit()

    # Синхронизируем с белым списком Agentic Shield (защита от Payee-Swap)
    try:
        from . import agentic_shield
        agentic_shield.add_allowlist_entry(
            memory,
            entry_type="wallet",
            value=addr,
            label=f"{net}: {clean_lbl}",
            actor=actor or roles.OWNER_ACTOR,
        )
    except Exception:
        pass
    audit_chain.append_audit(memory, "owner_wallet_saved", {"network": net, "address_tail": addr[-6:], "primary": make_prim}, agent_id="owner")
    return {"ok": True, "wallet_id": wid, "network": net, "address": addr, "explorer_url": v["explorer_url"], "wallets": list_wallets(memory)}


def set_primary_wallet(memory, wallet_id: str, *, actor: Any = None) -> dict[str, Any]:
    roles.require_owner(actor, "wallet_manage")
    _ensure_tables(memory)
    with memory.store._lock:
        row = memory.store.conn.execute(
            "SELECT id, network FROM owner_wallets WHERE id = ? AND user_id = ?",
            (wallet_id, memory.user_id),
        ).fetchone()
        if not row:
            raise ValueError(f"Wallet {wallet_id!r} not found")
        memory.store.conn.execute(
            "UPDATE owner_wallets SET is_primary = 0 WHERE user_id = ? AND network = ?",
            (memory.user_id, row["network"]),
        )
        memory.store.conn.execute(
            "UPDATE owner_wallets SET is_primary = 1, updated_at = ? WHERE id = ? AND user_id = ?",
            (_now(), wallet_id, memory.user_id),
        )
        memory.store.conn.commit()
    return {"ok": True, "primary_id": wallet_id, "wallets": list_wallets(memory)}


def remove_wallet(memory, wallet_id: str, *, actor: Any = None) -> dict[str, Any]:
    roles.require_owner(actor, "wallet_manage")
    _ensure_tables(memory)
    with memory.store._lock:
        cur = memory.store.conn.execute(
            "DELETE FROM owner_wallets WHERE id = ? AND user_id = ?",
            (wallet_id, memory.user_id),
        )
        memory.store.conn.commit()
    if cur.rowcount == 0:
        raise ValueError(f"Wallet {wallet_id!r} not found")
    return {"ok": True, "removed_id": wallet_id, "wallets": list_wallets(memory)}


# ==================== ЛОКАЛЬНЫЙ MERKLE-ЧЕКПОИНТ L3 ($0) И РЕМОНТ ЦЕПИ ====================

def create_local_l3_checkpoint(memory, *, actor: Any = None, limit: int = 200) -> dict[str, Any]:
    """Создаёт бесплатный ($0) локальный Merkle-якорь L3 и сохраняет пакет на диск для проверки."""
    roles.require_owner(actor, "l3_checkpoint")
    from . import anchor
    anchor.ensure_schema(memory)
    now = _now()
    rows = memory.store.query(
        "SELECT id, kind, content, created_at, scope, agent_id FROM memory "
        "WHERE user_id = ? AND status = 'active' AND content IS NOT NULL "
        "ORDER BY created_at DESC LIMIT ?",
        (memory.user_id, max(1, min(1000, int(limit)))),
    )
    if not rows:
        raise ValueError("No active memory records to checkpoint")

    leaves: list[bytes] = []
    leaf_rows: list[tuple[int, str, str, bytes]] = []
    bundle_records: list[dict[str, Any]] = []
    for idx, r in enumerate(rows):
        rec_id = str(r["id"])
        rec_raw = json.dumps(
            {
                "id": rec_id,
                "kind": r["kind"],
                "content": r["content"],
                "created_at": r["created_at"],
                "scope": r["scope"],
                "agent_id": r["agent_id"],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        h = anchor.leaf_record_bound(rec_id, rec_raw)
        leaves.append(h)
        leaf_rows.append((idx, "record", rec_id, h))
        bundle_records.append({"id": rec_id, "data": base64.b64encode(rec_raw).decode("ascii")})

    root_hex = anchor.merkle_root(leaves).hex()
    memo_str = f"PADAM:L3 root={root_hex} records={len(leaves)}"

    aid = f"l3chk-{uuid.uuid4().hex[:12]}"
    bundle_bytes_raw = json.dumps(
        {
            "format": "padam-l3/2",
            "anchor_id": aid,
            "user_id": memory.user_id,
            "root": root_hex,
            "created_at": now,
            "records": bundle_records,
            "forgets": [],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    bundle_sha = hashlib.sha256(bundle_bytes_raw).hexdigest()

    if str(memory.store.path) != ":memory:":
        l3_dir = Path(str(memory.store.path) + ".l3")
        l3_dir.mkdir(parents=True, exist_ok=True)
        (l3_dir / f"{aid}.json").write_bytes(bundle_bytes_raw)

    with memory.store._lock:
        memory.store.conn.execute(
            "INSERT INTO l3_anchor (id, user_id, created_at, root_hex, leaf_count, bundle_sha256, bundle_bytes, network, memo) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'local_checkpoint', ?)",
            (aid, memory.user_id, now, root_hex, len(leaves), bundle_sha, len(bundle_bytes_raw), memo_str),
        )
        for pos, kind, mid, lbytes in leaf_rows:
            memory.store.conn.execute(
                "INSERT INTO l3_leaf (anchor_id, position, kind, memory_id, leaf_hex) VALUES (?, ?, ?, ?, ?)",
                (aid, pos, kind, mid, lbytes.hex()),
            )
        memory.store.conn.commit()
    audit_chain.append_audit(memory, "l3_local_checkpoint", {"anchor_id": aid, "leaves": len(leaves), "root_hex": root_hex[:16]}, agent_id="owner")
    return {
        "ok": True,
        "anchor_id": aid,
        "network": "local_checkpoint",
        "root_hex": root_hex,
        "leaf_count": len(leaves),
        "bundle_bytes": len(bundle_bytes_raw),
        "bundle_sha256": bundle_sha,
    }


def repair_audit_log_races(memory, *, actor: Any = None) -> dict[str, Any]:
    """Безопасно устраняет межпроцессные дубли seq в audit_log и переподписывает цепь ключом владельца.

    Ни одна запись журнала не удаляется: все строки с seq IS NOT NULL перенумеровываются
    строго в порядке (seq ASC, created_at ASC, rowid ASC), после чего пересчитываются
    prev_hash, entry_hash, HMAC-якорь audit_log_anchor и локальный watermark.
    """
    roles.require_owner(actor, "audit_repair")
    before = audit_chain.verify_audit_chain(memory)
    key, _ = integrity.owner_key(memory.store)

    with memory.store._lock:
        conn = memory.store.conn
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT rowid AS _rid, id, user_id, created_at, action, memory_id, actor, agent_id, "
                "scope, kind, outcome, detail, seq FROM audit_log "
                "WHERE user_id = ? AND seq IS NOT NULL "
                "ORDER BY seq ASC, created_at ASC, rowid ASC",
                (memory.user_id,),
            ).fetchall()

            prev_hash = "0" * 64
            new_seq = 0
            for idx, r in enumerate(rows, 1):
                eh = audit_chain.compute_audit_log_hash(
                    ev_id=str(r["id"]),
                    user_id=str(r["user_id"]),
                    created_at=str(r["created_at"]),
                    action=str(r["action"]),
                    memory_id=r["memory_id"],
                    actor=r["actor"],
                    agent_id=r["agent_id"],
                    scope=r["scope"],
                    kind=r["kind"],
                    outcome=r["outcome"],
                    detail=r["detail"],
                    prev_hash=prev_hash,
                    seq=idx,
                )
                conn.execute(
                    "UPDATE audit_log SET seq = ?, prev_hash = ?, entry_hash = ? WHERE rowid = ?",
                    (idx, prev_hash, eh, r["_rid"]),
                )
                prev_hash = eh
                new_seq = idx

            if new_seq > 0:
                ts = _now()
                head_hmac = audit_chain.sign_audit_log_head(key, memory.user_id, new_seq, prev_hash)
                conn.execute(
                    "INSERT INTO audit_log_anchor (user_id, head_seq, head_hash, head_hmac, updated_at) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(user_id) DO UPDATE SET "
                    "head_seq=excluded.head_seq, head_hash=excluded.head_hash, "
                    "head_hmac=excluded.head_hmac, updated_at=excluded.updated_at",
                    (memory.user_id, new_seq, prev_hash, head_hmac, ts),
                )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

    if new_seq > 0:
        audit_chain.save_audit_log_watermark(memory, new_seq, prev_hash, key)

    audit_chain.append_audit(
        memory,
        "owner_audit_log_reindexed",
        {"rows_preserved": new_seq, "before_reason": before.get("audit_log_reason") or before.get("reason") or ""},
        agent_id="owner",
    )
    after = audit_chain.verify_audit_chain(memory)
    return {
        "ok": bool(after.get("ok")),
        "rows_preserved": new_seq,
        "before": before,
        "after": after,
    }
