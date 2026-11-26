# -*- coding: utf-8 -*-
"""Самозащита Щита от подмены SQLite (Tamper-Proof HMAC Seal для allowlist и shield_state).

Если вредоносный процесс в обход API напрямую изменил SQLite-файл (например, дописал
чужой кошелёк/домен в `shield_allowlist` или сбросил `lockdown = 0` в `shield_state`),
модуль мгновенно обнаруживает расхождение HMAC-SHA256 с ключом владельца (`integrity.owner_key`),
отбрасывает поддельные записи allowlist и принудительно включает Lockdown!
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
from typing import Any

from .. import integrity
from ..store import add_column_safe

_SEAL_DDL = """
CREATE TABLE IF NOT EXISTS shield_integrity_seals (
    user_id TEXT PRIMARY KEY,
    state_hmac TEXT NOT NULL,
    allowlist_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_tamper_seal_schema(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_tamper_seal_ready", False):
        return
    from .. import agentic_shield as _ash

    _ash._ensure_tables(memory)
    with store._lock:
        store.conn.executescript(_SEAL_DDL)
        add_column_safe(store.conn, "shield_allowlist", "owner_hmac", "TEXT DEFAULT ''")
        store.conn.commit()
        store._shield_tamper_seal_ready = True


def _hmac_hex(memory: Any, msg: str) -> str:
    key, _ = integrity.owner_key(memory.store)
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_allowlist_row_hmac(memory: Any, *, entry_id: str, entry_type: str, value: str) -> str:
    return _hmac_hex(memory, f"padam-al-v1|{memory.user_id}|{entry_id}|{entry_type}|{value}")


def compute_state_hmac(memory: Any, state_row: dict[str, Any]) -> str:
    msg = (
        f"padam-st-v1|{memory.user_id}|"
        f"{int(state_row.get('lockdown') or 0)}|"
        f"{int(state_row.get('block_writes') or 0)}|"
        f"{int(state_row.get('auto_kill_enabled') or 0)}|"
        f"{int(state_row.get('threshold') or 8)}|"
        f"{str(state_row.get('policy_profile') or 'balanced')}"
    )
    return _hmac_hex(memory, msg)


def seal_allowlist_entry(memory: Any, *, entry_id: str, entry_type: str, value: str) -> str:
    """Подписывает строку `shield_allowlist` ключом владельца."""
    ensure_tamper_seal_schema(memory)
    sig = compute_allowlist_row_hmac(memory, entry_id=entry_id, entry_type=entry_type, value=value)
    with memory.store._lock:
        memory.store.conn.execute(
            "UPDATE shield_allowlist SET owner_hmac = ? WHERE id = ? AND user_id = ?",
            (sig, entry_id, memory.user_id),
        )
        memory.store.conn.commit()
    return sig


def seal_shield_state(memory: Any) -> str:
    """Подписывает текущее состояние `shield_state` (lockdown, profile, пороги) ключом владельца."""
    from .. import agentic_shield as _ash

    ensure_tamper_seal_schema(memory)
    st = _ash._default_state(memory)
    sig = compute_state_hmac(memory, st)
    cnt_row = memory.store.one(
        "SELECT COUNT(*) AS c FROM shield_allowlist WHERE user_id = ?",
        (memory.user_id,),
    )
    cnt = int(cnt_row["c"]) if cnt_row else 0
    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT INTO shield_integrity_seals (user_id, state_hmac, allowlist_count, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                   state_hmac=excluded.state_hmac,
                   allowlist_count=excluded.allowlist_count,
                   updated_at=excluded.updated_at""",
            (memory.user_id, sig, cnt, _utc_iso()),
        )
        memory.store.conn.commit()
    return sig


def verify_shield_integrity(memory: Any, *, enforce_lockdown_on_tamper: bool = True) -> dict[str, Any]:
    """Проверяет целостность `shield_state` и `shield_allowlist` по HMAC-подписи владельца."""
    from .. import agentic_shield as _ash

    ensure_tamper_seal_schema(memory)
    st = _ash._default_state(memory)
    tampered_reasons: list[str] = []
    forged_allowlist_ids: list[str] = []

    # 1. Проверка подписи состояния щита
    seal_row = memory.store.one(
        "SELECT state_hmac, allowlist_count FROM shield_integrity_seals WHERE user_id = ?",
        (memory.user_id,),
    )
    if seal_row is not None:
        expected_st = compute_state_hmac(memory, st)
        if not hmac.compare_digest(expected_st, str(seal_row["state_hmac"] or "")):
            tampered_reasons.append("shield_state_tampered_in_sqlite")

    # 2. Проверка каждой записи allowlist (подписанные записи обязаны сходиться; неподписанные после включения seal — подделка!)
    rows = memory.store.query(
        "SELECT id, entry_type, value, owner_hmac FROM shield_allowlist WHERE user_id = ?",
        (memory.user_id,),
    )
    valid_entries: list[dict[str, Any]] = []
    for r in rows:
        sig = str(r["owner_hmac"] or "")
        expected = compute_allowlist_row_hmac(memory, entry_id=r["id"], entry_type=r["entry_type"], value=r["value"])
        if sig and hmac.compare_digest(expected, sig):
            valid_entries.append(dict(r))
        elif seal_row is not None or sig:
            forged_allowlist_ids.append(str(r["id"]))
            tampered_reasons.append(f"forged_allowlist_entry:{r['entry_type']}:{str(r['value'])[:24]}")
        else:
            # Наследие до первого включения tamper_seal: не считаем подделкой, если seal ещё ни разу не ставился
            valid_entries.append(dict(r))

    tampered = bool(tampered_reasons)
    lockdown_forced = False
    if tampered and enforce_lockdown_on_tamper:
        _ash.trip_kill_switch(
            memory,
            reason=f"Tamper-Proof Seal violation: {'; '.join(tampered_reasons[:2])}",
            agent_id="tamper_seal",
            block_writes=True,
        )
        seal_shield_state(memory)
        lockdown_forced = True

    return {
        "ok": not tampered,
        "tampered": tampered,
        "reasons": tampered_reasons,
        "forged_allowlist_ids": forged_allowlist_ids,
        "valid_allowlist_count": len(valid_entries),
        "lockdown_forced": lockdown_forced,
    }
