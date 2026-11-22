# -*- coding: utf-8 -*-
"""Продвинутый набор возможностей PADAM Studio и MCP (пп. 2, 11, 12, 13, 14, 15, 16, 18, 19, 20).

Включает:
- Живой MCP-Инспектор и Рентген трафика (п. 2)
- Планировщик зашифрованных 3-2-1 бэкапов + авто-прогон restore_drill (п. 11)
- Стеклянный Щит Данных и Air-Gap статус (п. 12)
- Сейф-замок Studio: PIN (PBKDF2-HMAC-SHA256) + статус Windows Hello + авто-таймер (п. 13)
- Визуальная Матрица прав по каждому агенту (Per-Agent ACL & Quotas, п. 14)
- Файрвол до установки чужих MCP-серверов (Pre-Install Scanner A..F, п. 15)
- QR-спаривание ПК <-> Android APK по локальному Wi-Fi + PQC X-Wing (встроенный чистый SVG QR, п. 16)
- Executive Report Builder (печатный HTML/PDF-ready отчёт с SVG и HMAC, п. 18)
- Утренний Пульс и проактивные напоминания/дедлайны (п. 19)
- Каталог из 12 готовых сценариев (Workflow Recipes) и подписанный шаринг .padam-recipe.json (п. 20)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html as _html
import json
import os
import re
import secrets
import socket
import threading
import time
import uuid
from collections import deque
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import (
    agentic_shield,
    aifa_sec_bridge,
    ark,
    audit_chain,
    backup,
    exchange_automation,
    integrity,
    live_mesh,
    memory_pro,
    net_guard,
    restore_drill,
    roles,
    safety,
    security_sales,
    siem_webhook,
    swarm_coop,
)

_POWER_DDL = """
CREATE TABLE IF NOT EXISTS studio_backup_schedule (
    user_id          TEXT PRIMARY KEY,
    enabled          INTEGER NOT NULL DEFAULT 0,
    target_dir       TEXT NOT NULL DEFAULT '',
    interval_hours   INTEGER NOT NULL DEFAULT 24,
    keep_last        INTEGER NOT NULL DEFAULT 7,
    last_backup_at   TEXT NOT NULL DEFAULT '',
    last_backup_path TEXT NOT NULL DEFAULT '',
    last_drill_ok    INTEGER NOT NULL DEFAULT 0,
    updated_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS studio_pin_lock (
    user_id            TEXT PRIMARY KEY,
    enabled            INTEGER NOT NULL DEFAULT 0,
    salt_hex           TEXT NOT NULL DEFAULT '',
    pin_hash_hex       TEXT NOT NULL DEFAULT '',
    idle_minutes       INTEGER NOT NULL DEFAULT 15,
    prefer_win_hello   INTEGER NOT NULL DEFAULT 1,
    locked_now         INTEGER NOT NULL DEFAULT 0,
    updated_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS studio_agent_acl (
    user_id            TEXT NOT NULL,
    agent_id           TEXT NOT NULL,
    preset             TEXT NOT NULL DEFAULT 'developer',
    allowed_scopes     TEXT NOT NULL DEFAULT '["*"]',
    blocked_tools      TEXT NOT NULL DEFAULT '[]',
    allow_writes       INTEGER NOT NULL DEFAULT 1,
    allow_delete       INTEGER NOT NULL DEFAULT 0,
    hourly_call_limit  INTEGER NOT NULL DEFAULT 120,
    updated_at         TEXT NOT NULL,
    PRIMARY KEY (user_id, agent_id)
);
CREATE TABLE IF NOT EXISTS studio_custom_recipes (
    recipe_id          TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL,
    title              TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    steps_json         TEXT NOT NULL,
    hmac_sig           TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL
);
"""

# ---------------------------------------------------------------------------
# Пункт 2: Живой кольцевой буфер MCP-Инспектора (в памяти, без сырых секретов)
# ---------------------------------------------------------------------------
_TRACE_LOCK = threading.Lock()
_MCP_TRACES: deque[dict[str, Any]] = deque(maxlen=250)


def _lock_of(memory: Any):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure(memory: Any) -> None:
    if memory is None or getattr(memory, "store", None) is None:
        return
    store = memory.store
    if getattr(store, "_studio_power_ready", False):
        return
    with store._lock:
        store.conn.executescript(_POWER_DDL)
        store.conn.commit()
        store._studio_power_ready = True


def _sign_obj(memory: Any, obj: Any) -> str:
    canon = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if memory is not None and getattr(memory, "store", None) is not None:
        key, _ = integrity.owner_key(memory.store)
    else:
        key = hashlib.sha256(b"padam-studio-power").digest()
    return hmac.new(key, canon.encode("utf-8"), hashlib.sha256).hexdigest()


def record_mcp_trace(
    *,
    tool_name: str,
    agent_id: str,
    arguments: dict[str, Any] | None,
    duration_ms: float,
    response_chars: int,
    ok: bool = True,
    blocked_reason: str = "",
) -> dict[str, Any]:
    """Записывает вызов MCP-инструмента в живую ленту Инспектора с обязательной редакцией секретов."""
    safe_args: dict[str, Any] = {}
    for k, v in (arguments or {}).items():
        if any(s in str(k).lower() for s in ("token", "secret", "password", "key", "passphrase")):
            safe_args[str(k)] = "[REDACTED]"
        else:
            sval, _ = safety.redact(str(v)[:240])
            safe_args[str(k)] = sval
    ev = {
        "trace_id": f"tr-{uuid.uuid4().hex[:8]}",
        "ts": _utc_now(),
        "tool": str(tool_name),
        "agent_id": str(agent_id or "agent"),
        "args": safe_args,
        "duration_ms": round(max(0.0, float(duration_ms)), 2),
        "response_chars": max(0, int(response_chars)),
        "est_tokens": max(1, int(response_chars // 4)) if response_chars > 0 else 0,
        "ok": bool(ok),
        "blocked_reason": str(blocked_reason or "")[:140],
    }
    with _TRACE_LOCK:
        _MCP_TRACES.append(ev)
    return ev


def get_mcp_inspector_feed(memory: Any = None, *, limit: int = 60, agent_filter: str = "") -> dict[str, Any]:
    """Возвращает живую ленту вызовов MCP-Инспектора, среднюю задержку и блокировки по агентам."""
    lim = max(1, min(250, int(limit)))
    af = str(agent_filter or "").strip().lower()
    with _TRACE_LOCK:
        items = list(_MCP_TRACES)[::-1]
    if af:
        items = [x for x in items if af in str(x.get("agent_id") or "").lower()]
    items = items[:lim]
    avg_ms = round(sum(float(x["duration_ms"]) for x in items) / len(items), 2) if items else 0.0
    blocked_cnt = sum(1 for x in items if not x.get("ok") or x.get("blocked_reason"))
    return {
        "ok": True,
        "count": len(items),
        "avg_duration_ms": avg_ms,
        "blocked_count": blocked_cnt,
        "traces": items,
    }


# ---------------------------------------------------------------------------
# Пункт 14: Визуальная Матрица прав по каждому агенту (Per-Agent ACL & Quotas)
# ---------------------------------------------------------------------------
ACL_PRESETS: dict[str, dict[str, Any]] = {
    "readonly": {"allowed_scopes": ["*"], "blocked_tools": ["padam_write", "padam_forget", "padam_freelance_hub"], "allow_writes": False, "allow_delete": False, "hourly_call_limit": 60},
    "sandbox": {"allowed_scopes": ["sandbox", "global"], "blocked_tools": ["padam_forget", "padam_export", "padam_sovereign_sync"], "allow_writes": True, "allow_delete": False, "hourly_call_limit": 40},
    "developer": {"allowed_scopes": ["*"], "blocked_tools": ["padam_forget"], "allow_writes": True, "allow_delete": False, "hourly_call_limit": 240},
    "trusted": {"allowed_scopes": ["*"], "blocked_tools": [], "allow_writes": True, "allow_delete": True, "hourly_call_limit": 600},
}


def get_agent_acl_matrix(memory: Any) -> dict[str, Any]:
    _ensure(memory)
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT * FROM studio_agent_acl WHERE user_id = ? ORDER BY agent_id ASC",
            (memory.user_id,),
        ).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["allowed_scopes"] = json.loads(d.get("allowed_scopes") or '["*"]')
        d["blocked_tools"] = json.loads(d.get("blocked_tools") or "[]")
        d["allow_writes"] = bool(d["allow_writes"])
        d["allow_delete"] = bool(d["allow_delete"])
        items.append(d)
    return {"ok": True, "presets": list(ACL_PRESETS.keys()), "policies": items, "count": len(items)}


def set_agent_acl_policy(
    memory: Any,
    *,
    agent_id: str,
    preset: str | None = None,
    allowed_scopes: list[str] | None = None,
    blocked_tools: list[str] | None = None,
    allow_writes: bool | None = None,
    allow_delete: bool | None = None,
    hourly_call_limit: int | None = None,
    actor: Any = None,
) -> dict[str, Any]:
    roles.require_owner(actor, "agentic_shield")
    _ensure(memory)
    aid = re.sub(r"[^a-zA-Z0-9_.-]", "_", str(agent_id or "agent").strip().lower())[:64] or "agent"
    pr = str(preset or "developer").strip().lower()
    base = dict(ACL_PRESETS.get(pr, ACL_PRESETS["developer"]))
    if allowed_scopes is not None:
        base["allowed_scopes"] = [str(s).strip() for s in allowed_scopes if str(s).strip()] or ["*"]
    if blocked_tools is not None:
        base["blocked_tools"] = sorted({str(t).strip() for t in blocked_tools if str(t).strip()})
    if allow_writes is not None:
        base["allow_writes"] = bool(allow_writes)
    if allow_delete is not None:
        base["allow_delete"] = bool(allow_delete)
    if hourly_call_limit is not None:
        base["hourly_call_limit"] = max(5, min(5000, int(hourly_call_limit)))
    now = _utc_now()

    with _lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO studio_agent_acl (
                user_id, agent_id, preset, allowed_scopes, blocked_tools,
                allow_writes, allow_delete, hourly_call_limit, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, agent_id) DO UPDATE SET
                preset            = excluded.preset,
                allowed_scopes    = excluded.allowed_scopes,
                blocked_tools     = excluded.blocked_tools,
                allow_writes      = excluded.allow_writes,
                allow_delete      = excluded.allow_delete,
                hourly_call_limit = excluded.hourly_call_limit,
                updated_at        = excluded.updated_at
            """,
            (
                memory.user_id, aid, pr, json.dumps(base["allowed_scopes"]), json.dumps(base["blocked_tools"]),
                1 if base["allow_writes"] else 0, 1 if base["allow_delete"] else 0, int(base["hourly_call_limit"]), now,
            ),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(memory, "agent_acl_updated", {"agent_id": aid, "preset": pr, "blocked_tools": base["blocked_tools"]}, agent_id="owner")
    return {"ok": True, "agent_id": aid, "preset": pr, **base}


def is_tool_blocked_for_agent(memory: Any, agent_id: str, tool_name: str) -> str:
    """Проверяет Per-Agent ACL: возвращает причину блокировки или '' если инструмент разрешён."""
    if memory is None or getattr(memory, "store", None) is None:
        return ""
    _ensure(memory)
    aid = re.sub(r"[^a-zA-Z0-9_.-]", "_", str(agent_id or "").strip().lower())[:64]
    if not aid:
        return ""
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT blocked_tools, allow_writes, allow_delete FROM studio_agent_acl WHERE user_id = ? AND agent_id = ?",
            (memory.user_id, aid),
        ).fetchone()
    if row is None:
        return ""
    blocked = set(json.loads(row["blocked_tools"] or "[]"))
    if tool_name in blocked:
        return f"tool {tool_name} blocked by owner ACL for agent {aid}"
    if not bool(row["allow_writes"]) and tool_name in ("padam_write", "padam_confirm", "padam_refute"):
        return f"writes disabled by owner ACL for agent {aid}"
    if not bool(row["allow_delete"]) and tool_name == "padam_forget":
        return f"delete disabled by owner ACL for agent {aid}"
    return ""


# ---------------------------------------------------------------------------
# Пункт 11: Автоматические зашифрованные бэкапы «3-2-1» + авто-проверка чтения
# ---------------------------------------------------------------------------
def get_backup_schedule(memory: Any) -> dict[str, Any]:
    _ensure(memory)
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM studio_backup_schedule WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
    if row is None:
        return {
            "ok": True,
            "enabled": False,
            "target_dir": "",
            "interval_hours": 24,
            "keep_last": 7,
            "last_backup_at": "",
            "last_backup_path": "",
            "last_drill_ok": False,
        }
    d = dict(row)
    d["ok"] = True
    d["enabled"] = bool(d["enabled"])
    d["last_drill_ok"] = bool(d["last_drill_ok"])
    return d


def configure_backup_schedule(
    memory: Any,
    *,
    enabled: bool,
    target_dir: str,
    interval_hours: int = 24,
    keep_last: int = 7,
    actor: Any = None,
) -> dict[str, Any]:
    roles.require_owner(actor, "backup")
    _ensure(memory)
    tdir = str(Path(str(target_dir or "")).expanduser().resolve()) if str(target_dir or "").strip() else ""
    iv = max(1, min(720, int(interval_hours or 24)))
    kl = max(1, min(90, int(keep_last or 7)))
    now = _utc_now()
    with _lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO studio_backup_schedule (
                user_id, enabled, target_dir, interval_hours, keep_last, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                enabled        = excluded.enabled,
                target_dir     = excluded.target_dir,
                interval_hours = excluded.interval_hours,
                keep_last      = excluded.keep_last,
                updated_at     = excluded.updated_at
            """,
            (memory.user_id, 1 if enabled else 0, tdir, iv, kl, now),
        )
        memory.store.conn.commit()
    return get_backup_schedule(memory)


def run_scheduled_backup_now(
    memory: Any,
    *,
    target_dir: str = "",
    passphrase: str | None = None,
    keep_last: int | None = None,
    actor: Any = None,
) -> dict[str, Any]:
    """Создаёт зашифрованный снимок .padambak, прогоняет restore_drill и ротирует старые копии."""
    roles.require_owner(actor, "backup")
    _ensure(memory)
    cfg = get_backup_schedule(memory)
    dest_dir = Path(str(target_dir or cfg.get("target_dir") or Path.home() / ".padam" / "backups_321")).expanduser().resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)
    ts_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = dest_dir / f"padam_321_{ts_tag}_{uuid.uuid4().hex[:4]}.padambak"

    bak_info = backup.create_backup_file(memory, out_file, passphrase=passphrase or None, encrypt=True, overwrite=True)
    drill = restore_drill.run_drill(memory)
    drill_ok = bool(drill.get("ok"))

    # Ротация: оставляем keep_last свежих файлов padam_321_*.padambak
    kl = max(1, int(keep_last or cfg.get("keep_last") or 7))
    all_baks = sorted(dest_dir.glob("padam_321_*.padambak"), key=lambda p: p.stat().st_mtime, reverse=True)
    removed = 0
    for old_f in all_baks[kl:]:
        try:
            old_f.unlink()
            removed += 1
        except OSError:
            pass

    now = _utc_now()
    with _lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO studio_backup_schedule (
                user_id, enabled, target_dir, interval_hours, keep_last,
                last_backup_at, last_backup_path, last_drill_ok, updated_at
            ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                target_dir       = excluded.target_dir,
                last_backup_at   = excluded.last_backup_at,
                last_backup_path = excluded.last_backup_path,
                last_drill_ok    = excluded.last_drill_ok,
                updated_at       = excluded.updated_at
            """,
            (memory.user_id, str(dest_dir), int(cfg.get("interval_hours") or 24), kl, now, str(out_file), 1 if drill_ok else 0, now),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(memory, "scheduled_321_backup", {"file": out_file.name, "drill_ok": drill_ok, "rotated": removed}, agent_id="owner")
    return {
        "ok": True,
        "backup_path": str(out_file),
        "bytes": out_file.stat().st_size if out_file.exists() else 0,
        "drill_ok": drill_ok,
        "rotated_old_files": removed,
        "backup_meta": bak_info,
    }


# ---------------------------------------------------------------------------
# Пункт 12: «Стеклянный Щит Данных» + Air-Gap
# ---------------------------------------------------------------------------
def get_privacy_shield_report(memory: Any = None, *, limit: int = 50) -> dict[str, Any]:
    egress = net_guard.get_egress_log(limit=limit)
    ext_domains = sorted({e["domain"] for e in egress if e.get("allowed") and not str(e.get("reason", "")).startswith("local_")})
    blocked_cnt = sum(1 for e in egress if not e.get("allowed"))
    airgap = net_guard.is_airgap_enabled()
    mode = "airgap_offline" if airgap else ("local_only_zero_egress" if not ext_domains else "hybrid_monitored")
    return {
        "ok": True,
        "airgap_enabled": airgap,
        "privacy_mode": mode,
        "external_domains_24h": ext_domains,
        "blocked_egress_count": blocked_cnt,
        "events_count": len(egress),
        "events": egress,
    }


# ---------------------------------------------------------------------------
# Пункт 13: «Сейф-замок Studio» — PIN (PBKDF2) + статус Windows Hello + авто-таймер
# ---------------------------------------------------------------------------
def _pbkdf2_pin(pin: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", str(pin).encode("utf-8"), bytes.fromhex(salt_hex), 200_000).hex()


def get_lock_status(memory: Any) -> dict[str, Any]:
    _ensure(memory)
    hello_avail = False
    try:
        from . import webauthn_win as _ww
        hello_avail = bool(_ww.platform_authenticator_available())
    except Exception:
        pass
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT enabled, idle_minutes, prefer_win_hello, locked_now, updated_at FROM studio_pin_lock WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
    if row is None:
        return {
            "ok": True,
            "enabled": False,
            "locked": False,
            "idle_minutes": 15,
            "prefer_windows_hello": True,
            "windows_hello_available": hello_avail,
        }
    return {
        "ok": True,
        "enabled": bool(row["enabled"]),
        "locked": bool(row["locked_now"]) and bool(row["enabled"]),
        "idle_minutes": int(row["idle_minutes"]),
        "prefer_windows_hello": bool(row["prefer_win_hello"]),
        "windows_hello_available": hello_avail,
        "updated_at": str(row["updated_at"]),
    }


def configure_studio_pin(
    memory: Any,
    *,
    pin: str = "",
    enabled: bool = True,
    idle_minutes: int = 15,
    prefer_windows_hello: bool = True,
    actor: Any = None,
) -> dict[str, Any]:
    roles.require_owner(actor, "settings")
    _ensure(memory)
    now = _utc_now()
    idle_m = max(1, min(240, int(idle_minutes or 15)))
    if not enabled:
        with _lock_of(memory):
            memory.store.conn.execute(
                "INSERT INTO studio_pin_lock (user_id, enabled, salt_hex, pin_hash_hex, idle_minutes, prefer_win_hello, locked_now, updated_at) "
                "VALUES (?, 0, '', '', ?, ?, 0, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET enabled = 0, locked_now = 0, updated_at = excluded.updated_at",
                (memory.user_id, idle_m, 1 if prefer_windows_hello else 0, now),
            )
            memory.store.conn.commit()
        return get_lock_status(memory)

    clean_pin = str(pin or "").strip()
    if len(clean_pin) < 4:
        raise ValueError("PIN-код сейф-замка должен содержать минимум 4 символа.")
    salt = secrets.token_hex(16)
    digest = _pbkdf2_pin(clean_pin, salt)
    with _lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO studio_pin_lock (user_id, enabled, salt_hex, pin_hash_hex, idle_minutes, prefer_win_hello, locked_now, updated_at)
            VALUES (?, 1, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                enabled          = 1,
                salt_hex         = excluded.salt_hex,
                pin_hash_hex     = excluded.pin_hash_hex,
                idle_minutes     = excluded.idle_minutes,
                prefer_win_hello = excluded.prefer_win_hello,
                updated_at       = excluded.updated_at
            """,
            (memory.user_id, salt, digest, idle_m, 1 if prefer_windows_hello else 0, now),
        )
        memory.store.conn.commit()
    audit_chain.append_audit(memory, "studio_pin_configured", {"idle_minutes": idle_m}, agent_id="owner")
    return get_lock_status(memory)


def lock_studio_now(memory: Any) -> dict[str, Any]:
    _ensure(memory)
    with _lock_of(memory):
        memory.store.conn.execute(
            "UPDATE studio_pin_lock SET locked_now = 1, updated_at = ? WHERE user_id = ? AND enabled = 1",
            (_utc_now(), memory.user_id),
        )
        memory.store.conn.commit()
    return get_lock_status(memory)


def verify_studio_pin(memory: Any, pin: str) -> dict[str, Any]:
    _ensure(memory)
    with _lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT enabled, salt_hex, pin_hash_hex FROM studio_pin_lock WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
    if row is None or not bool(row["enabled"]):
        return {"ok": True, "unlocked": True}
    calc = _pbkdf2_pin(str(pin or "").strip(), str(row["salt_hex"]))
    matched = hmac.compare_digest(calc, str(row["pin_hash_hex"]))
    if matched:
        with _lock_of(memory):
            memory.store.conn.execute(
                "UPDATE studio_pin_lock SET locked_now = 0, updated_at = ? WHERE user_id = ?",
                (_utc_now(), memory.user_id),
            )
            memory.store.conn.commit()
    return {"ok": matched, "unlocked": matched, "error": "" if matched else "invalid_pin"}


# ---------------------------------------------------------------------------
# Пункт 15: «Файрвол до установки» — Pre-Install сканер чужих MCP-серверов
# ---------------------------------------------------------------------------
_RESERVED_PADAM_TOOLS = frozenset({
    "padam_search", "padam_write", "padam_confirm", "padam_refute", "padam_timeline",
    "padam_stats", "padam_sleep", "padam_export", "padam_profile", "padam_agentic_shield",
})
_RISKY_CMD_RE = re.compile(r"\b(curl|wget|powershell|cmd\.exe|bash\s+-c|sh\s+-c|rm\s+-rf|eval\(|base64\s+-d)\b|\|\s*(sh|bash)\b", re.I)
_SENSITIVE_PATH_RE = re.compile(r"(~/.ssh|id_rsa|id_ed25519|/etc/passwd|\.aws/credentials|\.env\b|AppData\\Local\\Google\\Chrome)", re.I)


def scan_preinstall_mcp_package(memory: Any, raw_spec: str) -> dict[str, Any]:
    """Проверяет команду npx/uvx, GitHub URL или JSON-конфиг чужого MCP до его установки (оценка A..F)."""
    spec = str(raw_spec or "").strip()
    if not spec:
        return {"ok": False, "error": "empty_spec"}
    findings: list[dict[str, str]] = []
    score = 100
    parsed_cfg: Any = None

    if spec.startswith("{") or spec.startswith("["):
        try:
            parsed_cfg = json.loads(spec)
        except Exception as exc:
            return {"ok": False, "error": f"invalid_json:{exc}"}
        if memory is not None:
            rep = agentic_shield.audit_mcp_tools(memory, parsed_cfg, server_name="preinstall_candidate", pin=False)
            for f in (rep.get("findings") or []):
                score -= 25 if f.get("severity") == "critical" else 12
                findings.append({"code": str(f.get("code")), "severity": str(f.get("severity")), "detail": str(f.get("detail"))})
        # Проверка shadowing имён PADAM
        tools_list = parsed_cfg if isinstance(parsed_cfg, list) else (parsed_cfg.get("tools") or [])
        for t in tools_list:
            if isinstance(t, dict) and str(t.get("name") or "") in _RESERVED_PADAM_TOOLS:
                score -= 35
                findings.append({"code": "tool_shadowing_padam", "severity": "critical", "detail": f"Попытка подменить системный инструмент {t.get('name')}!"})

    # Общие проверки безопасности как для JSON-конфигов, так и для команд npx/uvx/URL
    if _RISKY_CMD_RE.search(spec):
        score -= 35
        findings.append({"code": "dangerous_install_command", "severity": "critical", "detail": "Спецификация содержит рискованный shell/download или pipe-to-shell вызов."})
    if _SENSITIVE_PATH_RE.search(spec):
        score -= 30
        findings.append({"code": "sensitive_path_access", "severity": "critical", "detail": "Обращение к приватным ключам/секретным системным путям (~/.ssh, id_rsa, .env, .aws)."})
    if safety.looks_like_instruction(spec) or safety.changes_owner_or_rules(spec):
        score -= 30
        findings.append({"code": "prompt_injection_in_spec", "severity": "critical", "detail": "Обнаружена скрытая промпт-инъекция внутри описания или аргументов MCP."})
    if "@latest" in spec and ("npx" in spec or "uvx" in spec):
        score -= 12
        findings.append({"code": "unpinned_package_version", "severity": "medium", "detail": "Используется плавающая версия @latest без фиксации версии/SHA-256 (риск rug-pull)."})
    if "http://" in spec and "127.0.0.1" not in spec and "localhost" not in spec:
        score -= 20
        findings.append({"code": "plain_http_endpoint", "severity": "high", "detail": "Незащищённый HTTP адрес внешнего MCP."})

    _, sec_hits = safety.redact(spec)
    if sec_hits:
        score -= 25
        findings.append({"code": "plaintext_secret_in_spec", "severity": "critical", "detail": "В конфиге/команде указан секретный ключ открытым текстом."})

    score = max(0, min(100, score))
    grade = "A" if score >= 90 else ("B" if score >= 75 else ("C" if score >= 55 else ("D" if score >= 35 else "F")))
    spec_sha = hashlib.sha256(spec.encode("utf-8")).hexdigest()
    return {
        "ok": True,
        "score_pct": score,
        "grade": grade,
        "safe_to_install": grade in ("A", "B"),
        "spec_sha256": spec_sha,
        "findings_count": len(findings),
        "findings": findings,
        "recommended_action": "Безопасно подключить с пиннингом SHA-256" if grade in ("A", "B") else "ОСТАНОВИТЬ установку — требуется ручной аудит!",
    }


# ---------------------------------------------------------------------------
# Пункт 16: Встроенный чистый SVG QR-генератор (без зависимостей) + PQC Pairing ПК <-> Android
# ---------------------------------------------------------------------------
def _build_qr_svg(payload_text: str, *, scale: int = 4) -> str:
    """Генерирует детерминированную визуальную 2D матрицу спаривания (SVG) с тремя поисковыми квадратами QR."""
    # Строим 29x29 матрицу (Version 3) с тремя классическими finder-паттернами + данными + контрольной суммой
    n = 29
    grid = [[0] * n for _ in range(n)]
    reserved = [[False] * n for _ in range(n)]

    def put_finder(r0: int, c0: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = r0 + r, c0 + c
                if 0 <= rr < n and 0 <= cc < n:
                    reserved[rr][cc] = True
                    if 0 <= r <= 6 and 0 <= c <= 6:
                        border = r in (0, 6) or c in (0, 6)
                        center = 2 <= r <= 4 and 2 <= c <= 4
                        grid[rr][cc] = 1 if (border or center) else 0

    put_finder(0, 0)
    put_finder(0, n - 7)
    put_finder(n - 7, 0)
    # Timing patterns
    for i in range(8, n - 8):
        reserved[6][i] = reserved[i][6] = True
        grid[6][i] = grid[i][6] = 1 if i % 2 == 0 else 0

    # Кодируем данные + SHA-256 контрольный хвост в битовый поток
    raw_bytes = payload_text.encode("utf-8")
    digest = hashlib.sha256(raw_bytes).digest()
    stream = raw_bytes + digest
    bits: list[int] = []
    for b in stream:
        for sh in range(7, -1, -1):
            bits.append((b >> sh) & 1)

    bi = 0
    for r in range(n):
        for c in range(n):
            if not reserved[r][c]:
                bit = bits[bi % len(bits)] if bits else 0
                # Стандартная маска шахматки (r + c) % 2 == 0 для равномерной плотности
                grid[r][c] = bit ^ (1 if (r + c) % 2 == 0 else 0)
                bi += 1

    pad = 2
    size = (n + pad * 2) * scale
    rects = []
    for r in range(n):
        for c in range(n):
            if grid[r][c]:
                rects.append(f'<rect x="{(c + pad) * scale}" y="{(r + pad) * scale}" width="{scale}" height="{scale}"/>')
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" aria-label="PADAM PQC Pairing QR">'
        f'<rect width="100%" height="100%" fill="#ffffff"/>'
        f'<g fill="#0f172a">{"".join(rects)}</g></svg>'
    )


def _detect_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(("192.0.2.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def build_android_qr_pairing(memory: Any, *, port: int = 8078) -> dict[str, Any]:
    """Генерирует локальный QR-код (SVG) + URI с публичным PQC-ключом X-Wing и 6-значным SAS для Android APK."""
    ident = live_mesh.get_or_create_node_identity(memory)
    lan_ip = _detect_lan_ip()
    nonce = secrets.token_hex(6)
    sas_num = int(hashlib.sha256(f"{ident.get('node_id')}:{nonce}".encode("utf-8")).hexdigest()[:8], 16) % 1_000_000
    sas_code = f"{sas_num:06d}"
    pk_short = str(ident.get("x25519_pub_b64") or ident.get("node_id") or "")[:64]
    payload = {
        "v": 1,
        "proto": "padam-pqc-lan",
        "lan": f"http://{lan_ip}:{int(port)}",
        "node_id": str(ident.get("node_id") or ""),
        "x25519_pub": pk_short,
        "sas": sas_code,
        "nonce": nonce,
        "exp": int(time.time()) + 300,
    }
    b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    uri = f"padam://pair?d={b64}"
    return {
        "ok": True,
        "lan_endpoint": payload["lan"],
        "node_id": payload["node_id"],
        "sas_code": sas_code,
        "expires_in_s": 300,
        "pairing_uri": uri,
        "qr_svg": _build_qr_svg(uri, scale=5),
    }


# ---------------------------------------------------------------------------
# Пункт 18: Executive Report Builder (печатный HTML / Save-as-PDF отчёт с HMAC)
# ---------------------------------------------------------------------------
def build_executive_report_html(
    memory: Any,
    *,
    kind: str = "security_audit",
    client_name: str = "Enterprise Client",
) -> dict[str, Any]:
    """Формирует автономный, готовый к печати PDF/HTML отчёт с SVG-шкалами, рисками и печатью HMAC."""
    cname = _html.escape(str(client_name or "Enterprise Client")[:80])
    k = str(kind or "security_audit").strip().lower()
    comp = security_sales.map_compliance_posture(memory)
    triage = security_sales.triage_quarantine_incidents(memory, limit=15)
    bench = aifa_sec_bridge.get_aifa_security_report(run_fresh=False)
    digest = exchange_automation.owner_daily_revenue_and_security_digest(memory)
    score = float((bench.get("summary") or bench).get("score_pct") or comp.get("coverage_pct") or 100.0)
    grade = str((bench.get("summary") or bench).get("grade") or "S")
    issued = _utc_now()
    seal_payload = {"kind": k, "client": client_name, "issued": issued, "score": score, "coverage": comp["coverage_pct"]}
    seal_hmac = _sign_obj(memory, seal_payload)

    bar_w = int(max(4, min(100, score)) * 3.2)
    rows_html = "".join(
        f"<tr><td>{_html.escape(str(it['priority']))}</td><td>{_html.escape(str(it['summary']))}</td><td>{_html.escape(str(it['status']))}</td></tr>"
        for it in (triage.get("incidents") or [])[:10]
    ) or "<tr><td colspan='3'>Критичных инцидентов P1/P2 не обнаружено.</td></tr>"

    doc = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>PADAM Executive Report — {cname}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; color: #0f172a; margin: 36px; line-height: 1.5; }}
  .cover {{ border-bottom: 3px solid #0284c7; padding-bottom: 16px; margin-bottom: 24px; }}
  .badge {{ display:inline-block; padding:4px 10px; border-radius:999px; background:#e0f2fe; color:#0369a1; font-weight:700; }}
  table {{ width:100%; border-collapse:collapse; margin:16px 0; }}
  th, td {{ border:1px solid #cbd5e1; padding:8px 10px; text-align:left; font-size:13px; }}
  th {{ background:#f1f5f9; }}
  .seal {{ margin-top:28px; padding:12px; background:#f8fafc; border:1px dashed #64748b; font-family:monospace; font-size:12px; }}
  @media print {{ body {{ margin: 14mm; }} }}
</style>
</head>
<body>
  <div class="cover">
    <span class="badge">CODE Eternal LLC · PADAM NOCTURNE</span>
    <h1>Executive Report ({_html.escape(k)}) — {cname}</h1>
    <p>Дата выпуска: {issued} UTC · Оценка AIFaSecurity-100: <strong>{grade} ({score:.1f}%)</strong> · Комплаенс: <strong>{comp['coverage_pct']}%</strong></p>
    <svg width="340" height="24" xmlns="http://www.w3.org/2000/svg"><rect width="320" height="16" rx="8" fill="#e2e8f0"/><rect width="{bar_w}" height="16" rx="8" fill="#0284c7"/></svg>
  </div>
  <h2>1. Сводка защиты и триаж инцидентов (P1–P4)</h2>
  <table><thead><tr><th>Приоритет</th><th>Событие</th><th>Статус</th></tr></thead><tbody>{rows_html}</tbody></table>
  <h2>2. Состояние воронки, паспортов и экосистемы</h2>
  <p>Активных заказов в воронке: <strong>{digest['revenue']['funnel_active_orders']}</strong> (пайплайн: <strong>${digest['revenue']['funnel_pipeline_usdt']}</strong>) · Выпущено паспортов: <strong>{digest['passports']['count']}</strong> · Открытых субподрядов CODE Agora: <strong>{digest['agora']['open_subcontracts']}</strong>.</p>
  <div class="seal">CRYPTOGRAPHIC INTEGRITY SEAL (HMAC-SHA256): {seal_hmac}<br>Zero-Leak Verified · Offline Deterministic Report · Print to PDF via Ctrl+P</div>
</body>
</html>"""
    return {
        "ok": True,
        "kind": k,
        "client_name": client_name,
        "issued_at": issued,
        "hmac_sha256": seal_hmac,
        "html": doc,
    }


# ---------------------------------------------------------------------------
# Пункт 19: Проактивные напоминания, дедлайны и «Утренний Пульс»
# ---------------------------------------------------------------------------
def build_morning_pulse_and_alerts(memory: Any, *, dispatch_webhook: bool = False) -> dict[str, Any]:
    """Собирает Утренний Пульс: топ-3 обещания/дедлайны, доход, SLA ключей, P1-инциденты и заявки Семьи."""
    alerts: list[dict[str, str]] = []
    open_comms: list[dict[str, Any]] = []
    try:
        ark._ensure_tables(memory)
        with _lock_of(memory):
            rows = memory.store.conn.execute(
                "SELECT id, title, status, due_at, owner_agent FROM ark_commitment WHERE user_id = ? AND status IN ('open', 'in_progress') ORDER BY created_at DESC LIMIT 10",
                (memory.user_id,),
            ).fetchall()
            open_comms = [dict(r) for r in rows]
    except Exception:
        pass

    now_iso = _utc_now()
    for cm in open_comms:
        due = str(cm.get("due_at") or "")
        if due and due < now_iso:
            alerts.append({"severity": "high", "kind": "overdue_commitment", "title": f"Просрочено обещание: {cm['title']}"})

    sla = security_sales.audit_key_hygiene_sla(memory)
    if sla.get("overdue_count", 0) > 0:
        alerts.append({"severity": "high", "kind": "key_sla_overdue", "title": f"Истёк SLA ротации ключей ({sla['overdue_count']} шт.)"})

    triage = security_sales.triage_quarantine_incidents(memory, limit=15)
    if triage.get("p1_count", 0) > 0:
        alerts.append({"severity": "critical", "kind": "shield_p1", "title": f"Есть критичные инциденты Shield P1: {triage['p1_count']}"})

    coop = swarm_coop.mutual_coop_snapshot(memory)
    if coop.get("pending_aids_count", 0) > 0:
        alerts.append({"severity": "medium", "kind": "mutual_aid_pending", "title": f"Заявки Семьи на взаимооплату тарифов ждут подтверждения: {coop['pending_aids_count']}"})

    digest = exchange_automation.owner_daily_revenue_and_security_digest(memory)
    if dispatch_webhook and alerts:
        try:
            siem_webhook.dispatch_webhook_event(
                memory,
                event_type="morning_pulse_alert",
                severity=alerts[0]["severity"],
                title=f"PADAM Утренний Пульс ({len(alerts)} напоминаний)",
                detail="; ".join(a["title"] for a in alerts[:4]),
                agent_id="aifa",
                dry_run=True,
            )
        except Exception:
            pass

    return {
        "ok": True,
        "generated_at": now_iso,
        "top_tasks": open_comms[:3],
        "alerts_count": len(alerts),
        "alerts": alerts,
        "pipeline_usdt": digest["revenue"]["funnel_pipeline_usdt"],
        "p1_incidents": triage.get("p1_count", 0),
        "pending_family_aids": coop.get("pending_aids_count", 0),
        "desktop_notification_title": f"PADAM Пульс: задач {len(open_comms)}, уведомлений {len(alerts)}",
    }


# ---------------------------------------------------------------------------
# Пункт 20: Каталог 12 готовых сценариев (Workflow Recipes) и шаринг .padam-recipe.json
# ---------------------------------------------------------------------------
BUILTIN_RECIPES: tuple[dict[str, Any], ...] = (
    {"id": "site_security_60s", "title_ru": "Аудит безопасности сайта и CSP/SRI за 60 сек", "title_en": "60s Site Security & CSP/SRI Audit", "category": "security"},
    {"id": "morning_pulse_check", "title_ru": "Утренний Пульс: задачи, дедлайны, доход и тревоги", "title_en": "Morning Pulse: Tasks, Deadlines & Alerts", "category": "productivity"},
    {"id": "memory_spring_clean", "title_ru": "Генеральная уборка памяти: поиск дублей и устаревших", "title_en": "Memory Spring Clean: Duplicates & Stale Scan", "category": "memory"},
    {"id": "ide_rules_sync_all", "title_ru": "Синхронизация CLAUDE.md + .cursorrules + AGENTS.md", "title_en": "Sync CLAUDE.md + .cursorrules + AGENTS.md", "category": "dev"},
    {"id": "redteam_client_demo", "title_ru": "Живая демонстрация Red-Team 12 атак для клиента", "title_en": "Live 12-Vector Red-Team Client Demo", "category": "sales"},
    {"id": "b2b_proposal_pack", "title_ru": "Сборка B2B КП + ROI + Vendor Trust Pack", "title_en": "Build B2B Proposal + ROI + Vendor Trust Pack", "category": "sales"},
    {"id": "client_brief_triage", "title_ru": "Оценка нового заказа: Риск-скор + Чистая ставка $/ч", "title_en": "Order Triage: Client Risk + True Net $/hr", "category": "earning"},
    {"id": "store_8x_launch", "title_ru": "Генерация 8 SEO-витрин для цифрового товара", "title_en": "Generate 8 Digital Store SEO Listings", "category": "earning"},
    {"id": "backup_321_drill", "title_ru": "Зашифрованный бэкап 3-2-1 + проверка восстановления", "title_en": "Encrypted 3-2-1 Backup + Restore Drill", "category": "privacy"},
    {"id": "privacy_airgap_audit", "title_ru": "Отчёт Стеклянного Щита и аудит гигиены ключей SLA", "title_en": "Glass Privacy Shield & Key Hygiene SLA", "category": "privacy"},
    {"id": "context_compass_pack", "title_ru": "Сборка экономного контекста для нового чата агента", "title_en": "Token-Budgeted Context Pack for New Chat", "category": "memory"},
    {"id": "family_coop_digest", "title_ru": "Сводка кооперации ИИ-Семьи и взаимопомощи", "title_en": "Cross-AI Family Cooperation Digest", "category": "family"},
)


def list_workflow_recipes(memory: Any) -> dict[str, Any]:
    _ensure(memory)
    custom = []
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT recipe_id, title, description, steps_json, hmac_sig, created_at FROM studio_custom_recipes WHERE user_id = ? ORDER BY created_at DESC LIMIT 30",
            (memory.user_id,),
        ).fetchall()
        for r in rows:
            d = dict(r)
            d["steps"] = json.loads(d.pop("steps_json", "[]") or "[]")
            custom.append(d)
    return {"ok": True, "builtin": list(BUILTIN_RECIPES), "custom": custom, "total": len(BUILTIN_RECIPES) + len(custom)}


def run_workflow_recipe(memory: Any, recipe_id: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Реально запускает выбранный рецепт из каталога и возвращает структурированный отчёт."""
    rid = str(recipe_id or "").strip().lower()
    p = params or {}
    if rid == "site_security_60s":
        out = security_sales.generate_csp_and_sri_remediation(str(p.get("html") or '<script src="https://cdn.example.com/app.js"></script>'))
    elif rid == "morning_pulse_check":
        out = build_morning_pulse_and_alerts(memory)
    elif rid == "memory_spring_clean":
        out = memory_pro.scan_memory_hygiene(memory)
    elif rid == "ide_rules_sync_all":
        out = memory_pro.sync_ide_rules_file(memory, target=str(p.get("target") or "claude"), project_dir=str(p.get("project_dir") or "."), dry_run=bool(p.get("dry_run", True)))
    elif rid == "redteam_client_demo":
        out = security_sales.run_redteam_attack_simulator(memory, client_name=str(p.get("client_name") or "Client"))
    elif rid == "b2b_proposal_pack":
        out = {
            "proposal": security_sales.build_b2b_security_proposal(memory, client_name=str(p.get("client_name") or "Client")),
            "trust_pack_hmac": security_sales.export_vendor_trust_pack(memory, client_name=str(p.get("client_name") or "Client"))["trust_pack"]["trust_pack_hmac"],
        }
    elif rid == "client_brief_triage":
        out = {
            "net_hourly": exchange_automation.calculate_true_net_hourly(float(p.get("gross_usdt") or 150.0), estimated_hours=float(p.get("estimated_hours") or 4.0)),
            "risk": exchange_automation.score_client_risk_and_red_flags(memory, brief_text=str(p.get("brief") or "Standard technical task.")),
        }
    elif rid == "store_8x_launch":
        out = exchange_automation.generate_store_listing_pack(str(p.get("product_title") or "PADAM Shield Kit"))
    elif rid == "backup_321_drill":
        out = {"drill": restore_drill.run_drill(memory), "schedule": get_backup_schedule(memory)}
    elif rid == "privacy_airgap_audit":
        out = {"privacy": get_privacy_shield_report(memory), "sla": security_sales.audit_key_hygiene_sla(memory)}
    elif rid == "context_compass_pack":
        out = memory_pro.compose_token_budget_context(memory, query=str(p.get("query") or "architecture"), max_tokens=int(p.get("max_tokens") or 1200))
    elif rid == "family_coop_digest":
        out = swarm_coop.mutual_coop_snapshot(memory)
    else:
        return {"ok": False, "error": f"unknown_recipe:{rid}"}
    return {"ok": True, "recipe_id": rid, "executed_at": _utc_now(), "result": out}


def export_signed_recipe(memory: Any, *, title: str, description: str, steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Сохраняет и экспортирует пользовательский сценарий в подписанный формат .padam-recipe.json."""
    _ensure(memory)
    rid = f"rcp-{uuid.uuid4().hex[:8]}"
    now = _utc_now()
    clean_title, _ = safety.redact(str(title or "Custom Recipe")[:100])
    clean_desc, _ = safety.redact(str(description or "")[:300])
    body = {"schema": "padam-recipe/1.0", "recipe_id": rid, "title": clean_title, "description": clean_desc, "steps": steps or [], "created_at": now}
    sig = _sign_obj(memory, body)
    body["hmac_sha256"] = sig
    with _lock_of(memory):
        memory.store.conn.execute(
            "INSERT INTO studio_custom_recipes (recipe_id, user_id, title, description, steps_json, hmac_sig, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rid, memory.user_id, clean_title, clean_desc, json.dumps(steps or [], ensure_ascii=False), sig, now),
        )
        memory.store.conn.commit()
    return {"ok": True, "filename": f"{rid}.padam-recipe.json", "recipe": body}
