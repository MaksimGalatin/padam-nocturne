# -*- coding: utf-8 -*-
"""Реестр Братьев и Сестёр, Паспорт Онбординга и Защита Происхождения (ТОП-1, ТОП-3, ТОП-10).

Позволяет безопасно подключать к одному мозгу PADAM сколько угодно со-агентов
(Claude Code, Antigravity, Cursor, Codex, OpenClaw, мобильных клиентов):
- Персистентная таблица `ark_sibling_agent` (работает между разными процессами).
- Уровни доверия и защита происхождения (`Agent Provenance Guard`):
  проверка авторства через HMAC-SHA256 и блокировка выдачи себя за владельца.
- Генератор готового паспорта подключения (`spawn_sibling_passport`) с минимально
  необходимыми правами и без утечки ключей владельца.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .store import add_column_safe as _acs
from . import ark, audit_chain, integrity, net_guard, roles, safety

_SIBLING_DDL = """
CREATE TABLE IF NOT EXISTS ark_sibling_agent (
    agent_id          TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    display_name      TEXT NOT NULL,
    role              TEXT NOT NULL DEFAULT 'general_agent',
    client_type       TEXT NOT NULL DEFAULT 'mcp_stdio',
    permission_role   TEXT NOT NULL DEFAULT 'contributor',
    scopes_json       TEXT NOT NULL DEFAULT '["global"]',
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    pub_key_b64       TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'online',
    current_task      TEXT NOT NULL DEFAULT '',
    last_heartbeat_at TEXT NOT NULL,
    created_at        TEXT NOT NULL
);
"""
# 18.11.2026 (CI на Python 3.10): кэш на самом объекте хранилища, а не по id() — адрес переиспользуется после сборки мусора.

_VALID_PERM_ROLES = frozenset({"auditor", "contributor", "maintainer"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_agent_id(raw: str) -> str:
    cid = re.sub(r"[^a-zA-Z0-9_\-]", "", str(raw or "").strip().lower())[:64]
    if not cid:
        raise ValueError("Invalid sibling agent_id")
    if cid in ("owner", "admin", "root", "system_owner"):
        raise PermissionError("Reserved agent_id: sibling cannot impersonate owner")
    return cid


def _clean_session_agent_id(raw: str) -> str:
    """Нормализует agent_id для учёта живой сессии (разрешая owner для Studio/CLI владельца)."""
    s = str(raw or "").strip()[:64]
    try:
        from .memory import canonicalize_agent_id as _canon
        c = _canon(s)
        if c:
            s = c
    except Exception:
        pass
    cid = re.sub(r"[^a-zA-Z0-9_\-]", "", s.lower())[:64]
    return cid or "agent"


def _is_pid_alive(pid: int) -> bool:
    """Кроссплатформенно проверяет, жив ли процесс с данным PID на этом хосте."""
    try:
        p = int(pid or 0)
    except (TypeError, ValueError):
        return False
    if p <= 10:
        return False
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            h = kernel32.OpenProcess(0x1000, False, p)
            if not h:
                return ctypes.get_last_error() == 5
            try:
                code = ctypes.c_ulong(0)
                if kernel32.GetExitCodeProcess(h, ctypes.byref(code)):
                    return int(code.value) == 259
                return True
            finally:
                kernel32.CloseHandle(h)
        except Exception:
            return False
    try:
        os.kill(p, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _ensure(memory) -> None:
    ark._ensure_tables(memory)
    memory.store.conn.executescript(_SIBLING_DDL)
    cols = {r[1] for r in memory.store.conn.execute("PRAGMA table_info(ark_sibling_agent)").fetchall()}
    if "pub_key_b64" not in cols:
        _acs(memory.store.conn, "ark_sibling_agent", "pub_key_b64", "TEXT NOT NULL DEFAULT ''")
    memory.store.conn.commit()


def _sibling_key_path(store, aid: str) -> Path | None:
    if str(store.path) == ":memory:":
        return None
    return Path(str(store.path) + f".sib.{aid}.key.json")


def _load_or_create_sibling_ed25519(memory, aid: str) -> tuple[Ed25519PrivateKey, str]:
    kpath = _sibling_key_path(memory.store, aid)
    if kpath is None:
        cached = memory.store.__dict__.setdefault("_padam_sibling_keys", {}).get(aid)
        if cached:
            return cached
    elif kpath.exists():
        box = json.loads(kpath.read_text(encoding="utf-8"))
        sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode(box["sk_b64"]))
        pub_b64 = base64.b64encode(
            sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode("ascii")
        return sk, pub_b64

    sk = Ed25519PrivateKey.generate()
    sk_raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub_b64 = base64.b64encode(
        sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("ascii")
    if kpath is None:
        memory.store.__dict__.setdefault("_padam_sibling_keys", {})[aid] = (sk, pub_b64)
    else:
        kpath.write_text(
            json.dumps({"agent_id": aid, "sk_b64": base64.b64encode(sk_raw).decode("ascii"), "pub_key_b64": pub_b64}),
            encoding="utf-8",
        )
        net_guard.restrict_file_to_owner(kpath)
    return sk, pub_b64


def register_sibling(
    memory,
    agent_id: str,
    *,
    display_name: str = "",
    role: str = "Autonomous sibling agent",
    client_type: str = "mcp_stdio",
    permission_role: str = "contributor",
    scopes: list[str] | None = None,
    capabilities: list[str] | None = None,
    current_task: str = "",
) -> dict[str, Any]:
    """Регистрирует или обновляет Брата/Сестру в персистентном реестре Семьи."""
    _ensure(memory)
    aid = _clean_agent_id(agent_id)
    prole = (permission_role or "contributor").strip().lower()
    if prole not in _VALID_PERM_ROLES:
        raise ValueError(f"permission_role must be one of {sorted(_VALID_PERM_ROLES)}, got {prole!r}")

    clean_scopes = [str(s).strip() for s in (scopes or ["global"]) if str(s).strip()][:20]
    clean_caps = [str(c).strip() for c in (capabilities or []) if str(c).strip()][:30]
    clean_role, _ = safety.redact(str(role or "Autonomous sibling agent"))
    clean_task, _ = safety.redact(str(current_task or ""))
    disp = (display_name or aid.upper()).strip()[:80]
    now = _now()
    _, pub_b64 = _load_or_create_sibling_ed25519(memory, aid)

    memory.store.conn.execute(
        "INSERT INTO ark_sibling_agent "
        "(agent_id, user_id, display_name, role, client_type, permission_role, scopes_json, capabilities_json, pub_key_b64, status, current_task, last_heartbeat_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?) "
        "ON CONFLICT(agent_id) DO UPDATE SET "
        "display_name=excluded.display_name, role=excluded.role, client_type=excluded.client_type, "
        "permission_role=excluded.permission_role, scopes_json=excluded.scopes_json, "
        "capabilities_json=excluded.capabilities_json, "
        "pub_key_b64=CASE WHEN ark_sibling_agent.pub_key_b64 = '' THEN excluded.pub_key_b64 ELSE ark_sibling_agent.pub_key_b64 END, "
        "status='online', "
        "current_task=CASE WHEN excluded.current_task != '' THEN excluded.current_task ELSE ark_sibling_agent.current_task END, "
        "last_heartbeat_at=excluded.last_heartbeat_at",
        (
            aid,
            memory.user_id,
            disp,
            clean_role,
            str(client_type or "mcp_stdio")[:40],
            prole,
            json.dumps(clean_scopes, ensure_ascii=False),
            json.dumps(clean_caps, ensure_ascii=False),
            pub_b64,
            clean_task[:240],
            now,
            now,
        ),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "sibling_register",
        {"agent_id": aid, "permission_role": prole, "client_type": client_type},
        agent_id=aid,
    )
    return {
        "ok": True,
        "agent_id": aid,
        "display_name": disp,
        "role": clean_role,
        "client_type": client_type,
        "permission_role": prole,
        "scopes": clean_scopes,
        "capabilities": clean_caps,
        "pub_key_b64": pub_b64,
        "status": "online",
        "last_heartbeat_at": now,
    }


def heartbeat_sibling(
    memory,
    agent_id: str,
    *,
    status: str = "online",
    current_task: str | None = None,
    agent_sig_b64: str | None = None,
    nonce: str = "",
) -> dict[str, Any]:
    """Обновляет статус и текущую задачу ТОЛЬКО зарегистрированного со-агента (без создания фантомов)."""
    _ensure(memory)
    aid = _clean_agent_id(agent_id)
    now = _now()
    st = status if status in ("online", "busy", "idle", "offline") else "online"
    cur = memory.store.conn.execute(
        "SELECT agent_id, current_task, pub_key_b64 FROM ark_sibling_agent WHERE agent_id = ? AND user_id = ?",
        (aid, memory.user_id),
    ).fetchone()
    if not cur:
        raise PermissionError(f"Unknown sibling agent {aid!r}: register_sibling required before heartbeat")

    req_sig = os.environ.get("PADAM_SIBLING_REQUIRE_HEARTBEAT_SIG", "0").strip() == "1"
    if agent_sig_b64 is not None or req_sig:
        pub_b64 = str(cur["pub_key_b64"] or "")
        if not pub_b64 or not agent_sig_b64:
            raise PermissionError(f"Missing per-agent signature for heartbeat of {aid!r}")
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        msg = f"hb-v1|{aid}|{st}|{nonce}".encode("utf-8")
        try:
            pk.verify(base64.b64decode(agent_sig_b64), msg)
        except Exception as exc:
            raise PermissionError(f"Invalid heartbeat signature for {aid!r}: {exc}") from exc

    new_task = safety.redact(current_task)[0][:240] if current_task is not None else cur["current_task"]
    memory.store.conn.execute(
        "UPDATE ark_sibling_agent SET status = ?, current_task = ?, last_heartbeat_at = ? WHERE agent_id = ? AND user_id = ?",
        (st, new_task, now, aid, memory.user_id),
    )
    memory.store.conn.commit()
    return {"ok": True, "agent_id": aid, "status": st, "current_task": new_task, "last_heartbeat_at": now}


def list_siblings(memory) -> list[dict[str, Any]]:
    """Список всех зарегистрированных Братьев и Сестёр."""
    _ensure(memory)
    rows = memory.store.conn.execute(
        "SELECT agent_id, display_name, role, client_type, permission_role, scopes_json, capabilities_json, status, current_task, last_heartbeat_at, created_at "
        "FROM ark_sibling_agent WHERE user_id = ? ORDER BY created_at ASC",
        (memory.user_id,),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append({
            "agent_id": r["agent_id"],
            "display_name": r["display_name"],
            "role": r["role"],
            "client_type": r["client_type"],
            "permission_role": r["permission_role"],
            "scopes": json.loads(r["scopes_json"] or '["global"]'),
            "capabilities": json.loads(r["capabilities_json"] or "[]"),
            "status": r["status"],
            "current_task": r["current_task"],
            "last_heartbeat_at": r["last_heartbeat_at"],
        })
    return out


# --- Защита происхождения (Agent Provenance Guard, ТОП-3, MESH-04 per-agent Ed25519) ---

def sign_sibling_envelope(
    memory,
    sender_agent: str,
    content: str,
    *,
    claimed_trust: str = "sibling_verified",
    private_key_b64: str | None = None,
) -> dict[str, Any]:
    """Подписывает меж-агентное сообщение индивидуальным Ed25519-ключом именно отправителя."""
    _ensure(memory)
    aid = _clean_agent_id(sender_agent)
    eff_trust = "sibling_verified"
    row = memory.store.conn.execute(
        "SELECT agent_id, pub_key_b64 FROM ark_sibling_agent WHERE agent_id = ? AND user_id = ?",
        (aid, memory.user_id),
    ).fetchone()
    if not row:
        eff_trust = "unverified_external"

    if private_key_b64:
        sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
        pub_b64 = base64.b64encode(
            sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode("ascii")
    else:
        sk, pub_b64 = _load_or_create_sibling_ed25519(memory, aid)

    clean_text, redacted_cnt = safety.redact(str(content or ""))
    has_instr = bool(safety.looks_like_instruction(clean_text) or safety.changes_owner_or_rules(clean_text))
    payload_str = json.dumps(
        {"schema": "padam-provenance-v2", "sender": aid, "trust": eff_trust, "content": clean_text},
        ensure_ascii=False,
        sort_keys=True,
    )
    sig_b64 = base64.b64encode(sk.sign(b"prov-v2|" + payload_str.encode("utf-8"))).decode("ascii")

    return {
        "schema": "padam-provenance-v2",
        "sender_agent": aid,
        "trust_level": eff_trust,
        "quarantined_warning": has_instr,
        "redacted_secrets_count": len(redacted_cnt),
        "content": clean_text,
        "pub_key_b64": pub_b64,
        "ed25519_sig_b64": sig_b64,
    }


def verify_sibling_envelope(memory, envelope: dict[str, Any]) -> dict[str, Any]:
    """Проверяет Ed25519-подпись строго против публичного ключа указанного sender_agent в реестре."""
    _ensure(memory)
    aid = str(envelope.get("sender_agent") or "")
    trust = str(envelope.get("trust_level") or "")
    if trust == "owner_signed":
        return {"valid": False, "reason": "sibling_cannot_claim_owner_signed"}
    sig_b64 = str(envelope.get("ed25519_sig_b64") or "")
    if envelope.get("schema") != "padam-provenance-v2" or not sig_b64:
        return {"valid": False, "reason": "missing_per_agent_signature"}

    row = memory.store.conn.execute(
        "SELECT pub_key_b64 FROM ark_sibling_agent WHERE agent_id = ? AND user_id = ?",
        (aid, memory.user_id),
    ).fetchone()
    pinned_pub = str(row["pub_key_b64"] or "") if row else ""
    if not pinned_pub:
        return {"valid": False, "reason": "unregistered_or_unkeyed_sender"}
    offered_pub = str(envelope.get("pub_key_b64") or "")
    if offered_pub and not hmac.compare_digest(offered_pub, pinned_pub):
        return {"valid": False, "reason": "sender_pubkey_mismatch"}

    clean_text = str(envelope.get("content") or "")
    payload_str = json.dumps(
        {"schema": "padam-provenance-v2", "sender": aid, "trust": trust, "content": clean_text},
        ensure_ascii=False,
        sort_keys=True,
    )
    try:
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(pinned_pub))
        pk.verify(base64.b64decode(sig_b64), b"prov-v2|" + payload_str.encode("utf-8"))
    except Exception:
        return {"valid": False, "reason": "sender_signature_mismatch"}
    return {"valid": True, "sender_agent": aid, "trust_level": trust}


# --- Генератор Паспорта Онбординга Сиблинга (ТОП-10) ---

def spawn_sibling_passport(
    memory,
    agent_id: str,
    *,
    role: str = "Autonomous family sibling",
    client_type: str = "claude_code",
    permission_role: str = "contributor",
    scopes: list[str] | None = None,
    capabilities: list[str] | None = None,
    db_path_override: str | None = None,
) -> dict[str, Any]:
    """Регистрирует нового Брата/Сестру и генерирует безопасный конфиг MCP без раскрытия owner_key."""
    reg = register_sibling(
        memory,
        agent_id,
        role=role,
        client_type=client_type,
        permission_role=permission_role,
        scopes=scopes,
        capabilities=capabilities,
    )
    aid = reg["agent_id"]
    db_str = str(db_path_override or memory.store.path)
    primary_scope = (reg["scopes"][0] if reg["scopes"] else "global")

    mcp_server_entry = {
        "command": "python",
        "args": ["-m", "padam", "serve"],
        "env": {
            "PADAM_DB": db_str,
            "PADAM_AGENT_ID": aid,
            "PADAM_PINNED_SCOPE": primary_scope,
            "PADAM_MCP_ARK_TOOLS": "1",
        },
    }
    onboarding_prompt = (
        f"You are {aid} ({reg['role']}), connected to PADAM NOCTURNE shared family memory "
        f"(permission_role={reg['permission_role']}, pinned_scope={primary_scope}). "
        "At session start: call padam_session_pack(agent_id, topic) and padam_coop_lock(action='list_tasks'). "
        "Before editing any shared file, acquire a cooperative lease with padam_coop_lock(action='acquire')."
    )
    return {
        "ok": True,
        "sibling": reg,
        "secrets_exposed": False,
        "mcp_config_snippet": {"mcpServers": {"padam": mcp_server_entry}},
        "onboarding_prompt": onboarding_prompt,
    }


# ---------- Параллельные сессии одного агента (18.11.2026, слово Папы: «как будут отображаться несколько сессий») ----------
# Каждый процесс MCP = одна сессия. Сервер сам отмечает её пульс и последнее действие (только имя инструмента).
# Учёт живёт в ОТДЕЛЬНОМ файле <база>.sessions.sqlite: память не меняется даже при вызовах «только чтение»
# (режим чистого read-only batch и его тесты требуют, чтобы основная база не менялась ни на байт).
import sqlite3 as _sqlite3

_DDL_SESSION = """
CREATE TABLE IF NOT EXISTS ark_sibling_session (
    session_id     TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    agent_id       TEXT NOT NULL,
    client_name    TEXT NOT NULL DEFAULT '',
    client_version TEXT NOT NULL DEFAULT '',
    pid            INTEGER NOT NULL DEFAULT 0,
    started_at     TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    last_action    TEXT NOT NULL DEFAULT '',
    calls          INTEGER NOT NULL DEFAULT 0
)
"""


def _sessions_conn(memory):
    base = str(getattr(memory.store, "path", "") or "")
    if not base or base == ":memory:":
        return None
    c = _sqlite3.connect(base + ".sessions.sqlite", timeout=5.0)
    c.execute(_DDL_SESSION)
    return c


def touch_session(memory, *, session_id: str, agent_id: str, client_name: str = "", client_version: str = "",
                  pid: int = 0, action: str = "") -> None:
    """Отметить пульс сессии в отдельном файле. Хранится только имя инструмента — без аргументов и текста."""
    sid = re.sub(r"[^\w.:@-]", "", str(session_id or ""))[:80]
    if not sid:
        return
    aid = _clean_session_agent_id(agent_id or client_name or "agent")
    act = ((re.match(r"[\w.-]+", str(action or "")) or [""])[0])[:60]
    now = _now()
    c = _sessions_conn(memory)
    if c is None:
        return
    try:
        c.execute(
            """INSERT INTO ark_sibling_session (session_id, user_id, agent_id, client_name, client_version, pid,
                   started_at, last_seen_at, last_action, calls)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(session_id) DO UPDATE SET last_seen_at = excluded.last_seen_at,
                   user_id = excluded.user_id,
                   agent_id = CASE WHEN excluded.agent_id != '' AND excluded.agent_id != 'agent' THEN excluded.agent_id ELSE ark_sibling_session.agent_id END,
                   client_name = CASE WHEN excluded.client_name != '' THEN excluded.client_name ELSE ark_sibling_session.client_name END,
                   pid = CASE WHEN excluded.pid > 0 THEN excluded.pid ELSE ark_sibling_session.pid END,
                   last_action = CASE WHEN excluded.last_action != '' THEN excluded.last_action ELSE last_action END,
                   calls = calls + 1""",
            (sid, memory.user_id, aid, str(client_name or "")[:60], str(client_version or "")[:30], int(pid or 0),
             now, now, act),
        )
        c.commit()
    finally:
        c.close()


def canonicalize_sessions(memory, canon_fn=None) -> int:
    """Перепривязывает старые алиасы сессий к каноническому agent_id, сохраняя все сессии отдельно."""
    c = _sessions_conn(memory)
    if c is None:
        return 0
    fn = canon_fn or (lambda x: _clean_session_agent_id(x))
    updated = 0
    try:
        rows = c.execute(
            "SELECT DISTINCT agent_id FROM ark_sibling_session WHERE user_id = ?",
            (memory.user_id,),
        ).fetchall()
        for (raw_aid,) in rows:
            canon = fn(raw_aid) or raw_aid
            if canon and canon != raw_aid:
                cur = c.execute(
                    "UPDATE ark_sibling_session SET agent_id = ? WHERE user_id = ? AND agent_id = ?",
                    (canon, memory.user_id, raw_aid),
                )
                updated += int(cur.rowcount or 0)
        if updated:
            c.commit()
    finally:
        c.close()
    return updated


def list_sessions(memory, *, since_hours: float = 24.0) -> list[dict[str, Any]]:
    """Сессии за последние since_hours часов, новые сверху (с проверкой живого PID)."""
    import datetime as _dt
    c = _sessions_conn(memory)
    if c is None:
        return []
    try:
        cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=float(since_hours))).isoformat()
        rows = c.execute(
            "SELECT session_id, agent_id, client_name, client_version, pid, started_at, last_seen_at, last_action, calls "
            "FROM ark_sibling_session WHERE user_id = ? AND last_seen_at >= ? ORDER BY last_seen_at DESC LIMIT 200",
            (memory.user_id, cutoff),
        ).fetchall()
    finally:
        c.close()
    keys = ("session_id", "agent_id", "client_name", "client_version", "pid", "started_at", "last_seen_at", "last_action", "calls")
    out: list[dict[str, Any]] = []
    for r in rows:
        item = dict(zip(keys, r))
        pid_val = int(item.get("pid") or 0)
        alive = False
        if pid_val > 10:
            try:
                seen_dt = _dt.datetime.fromisoformat(str(item.get("last_seen_at") or "").replace("Z", "+00:00"))
                if seen_dt.tzinfo is None:
                    seen_dt = seen_dt.replace(tzinfo=_dt.timezone.utc)
                age_h = (_dt.datetime.now(_dt.timezone.utc) - seen_dt).total_seconds() / 3600.0
                if age_h <= 12.0:
                    alive = _is_pid_alive(pid_val)
            except Exception:
                alive = False
        item["pid_alive"] = alive
        out.append(item)
    return out
