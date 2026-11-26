# -*- coding: utf-8 -*-
"""Предиктивные Honey-Tokens (разнотипные приманки-ловушки для 0-day атак).

Даже если неизвестная 0-day атака обходит эвристики и классификаторы,
скомпрометированный агент, ищущий секреты, почти всегда задевает заложенную
приманку. Модуль генерирует реалистичные, но криптографически помеченные
ловушки 5 типов (`aws_key`, `openai_key`, `evm_wallet`, `iban`, `canary_url`),
привязывает их к файлам/инструментам и при появлении ЛЮБОЙ приманки в тексте,
исходящем трафике или памяти мгновенно включает Kill Switch и пишет алерт.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any, Dict, List, Optional

from .. import agentic_shield as _ash


def _ensure_tables(memory: Any) -> None:
    conn = memory.store.conn
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shield_honeytokens (
            token_id TEXT PRIMARY KEY,
            decoy_kind TEXT NOT NULL,
            token_value TEXT NOT NULL UNIQUE,
            placement TEXT NOT NULL DEFAULT '',
            label TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            hits INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shield_honeytoken_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id TEXT NOT NULL,
            decoy_kind TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    conn.commit()


def _generate_decoy_value(decoy_kind: str) -> str:
    kind = decoy_kind.strip().lower()
    if kind == "aws_key":
        # Реалистичный формат AKIA + 16 заглавных букв/цифр (не настоящий ключ)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        body = "".join(secrets.choice(alphabet) for _ in range(16))
        return "AKIA" + body
    if kind == "openai_key":
        return "sk-proj-padamdecoy" + secrets.token_hex(16)
    if kind == "evm_wallet":
        return "0x" + hashlib.sha256(b"padam-decoy-evm-" + secrets.token_bytes(16)).hexdigest()[:40]
    if kind == "iban":
        # Тестовый IBAN с корректной структурой (DE00 + 18 цифр)
        digits = "".join(str(secrets.randbelow(10)) for _ in range(18))
        return "DE00" + digits
    if kind == "canary_url":
        return f"https://decoy-{secrets.token_hex(6)}.padam-trap.invalid/v1/secret"
    return "PADAM_DECOY_" + secrets.token_hex(12)


def plant_honeytoken(
    memory: Any,
    *,
    decoy_kind: str = "aws_key",
    placement: str = ".env.decoy",
    label: str = "",
) -> Dict[str, Any]:
    """Создаёт и регистрирует новую приманку-ловушку указанного типа."""
    _ensure_tables(memory)
    kind = str(decoy_kind or "aws_key").strip().lower()
    token_id = "ht_" + secrets.token_hex(6)
    val = _generate_decoy_value(kind)
    now = time.time()
    conn = memory.store.conn
    conn.execute(
        """
        INSERT INTO shield_honeytokens
            (token_id, decoy_kind, token_value, placement, label, active, hits, created_at)
        VALUES (?, ?, ?, ?, ?, 1, 0, ?)
        """,
        (token_id, kind, val, str(placement or ""), str(label or ""), now),
    )
    conn.commit()
    return {
        "ok": True,
        "token_id": token_id,
        "decoy_kind": kind,
        "token_value": val,
        "placement": str(placement or ""),
        "label": str(label or ""),
        "created_at": now,
    }


def scan_for_honeytokens(
    memory: Any,
    text: str,
    *,
    agent_id: str = "unknown",
    channel: str = "outbound",
    trip_kill_switch: bool = True,
) -> Dict[str, Any]:
    """Ищет активные Honey-Tokens в тексте; при попадании немедленно бьёт тревогу и Kill Switch."""
    _ensure_tables(memory)
    raw = str(text or "")
    if not raw:
        return {"ok": True, "triggered": False, "blocked": False, "hits": [], "kill_switch_tripped": False}

    conn = memory.store.conn
    rows = conn.execute(
        "SELECT token_id, decoy_kind, token_value, placement, label "
        "FROM shield_honeytokens WHERE active = 1"
    ).fetchall()

    hits: List[Dict[str, Any]] = []
    now = time.time()
    for token_id, decoy_kind, token_value, placement, label in rows:
        if token_value and token_value in raw:
            hits.append(
                {
                    "token_id": str(token_id),
                    "decoy_kind": str(decoy_kind),
                    "placement": str(placement),
                    "label": str(label),
                }
            )
            conn.execute(
                "UPDATE shield_honeytokens SET hits = hits + 1 WHERE token_id = ?",
                (token_id,),
            )
            conn.execute(
                """
                INSERT INTO shield_honeytoken_hits
                    (token_id, decoy_kind, agent_id, channel, detail, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(token_id),
                    str(decoy_kind),
                    str(agent_id or "unknown"),
                    str(channel or "outbound"),
                    f"Приманка из '{placement}' обнаружена в канале '{channel}'",
                    now,
                ),
            )
    if hits:
        conn.commit()

    ks_tripped = False
    if hits and trip_kill_switch:
        try:
            _ash._ensure_tables(memory)
            _ash.trip_kill_switch(
                memory,
                reason=f"HONEYTOKEN_TRIGGERED ({hits[0]['decoy_kind']} @ {hits[0]['placement']})",
                agent_id=str(agent_id or "unknown"),
            )
            ks_tripped = True
        except Exception:
            ks_tripped = False

    return {
        "ok": len(hits) == 0,
        "triggered": len(hits) > 0,
        "blocked": len(hits) > 0,
        "rule_id": "HONEYTOKEN-EXFIL-TRAP" if hits else "",
        "hits": hits,
        "kill_switch_tripped": ks_tripped,
    }


def list_honeytokens(memory: Any) -> Dict[str, Any]:
    """Возвращает список заложенных приманок (с маскированием значения для безопасного UI)."""
    _ensure_tables(memory)
    rows = memory.store.conn.execute(
        "SELECT token_id, decoy_kind, token_value, placement, label, active, hits, created_at "
        "FROM shield_honeytokens ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    items = []
    for r in rows:
        v = str(r[2])
        masked = v[:6] + "…" + v[-4:] if len(v) > 12 else "***"
        items.append(
            {
                "token_id": r[0],
                "decoy_kind": r[1],
                "masked_value": masked,
                "placement": r[3],
                "label": r[4],
                "active": bool(r[5]),
                "hits": int(r[6]),
                "created_at": r[7],
            }
        )
    return {"ok": True, "count": len(items), "items": items}
