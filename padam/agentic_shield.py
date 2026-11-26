# -*- coding: utf-8 -*-
"""PADAM Agentic Shield — активная защита на скорости машин, гейт исходящих действий и Proof Pack.

Закрывает четыре ключевые угрозы 2026 года (Google GTIG / ARTEX, Optimizely Supply-Chain, MCP Exploits):
1. Machine-Speed Anomaly Lock (Автоматический Kill Switch):
   отслеживает серию подозрительных событий/команд/эксфильтраций/ACL-отказов/всплесков вызовов
   в скользящем окне. При превышении порога мгновенно переводит БД в строгий режим (PADAM_STRICT=1),
   блокирует исходящие и (опционально) агентские записи, пишет в SHA-256 цепь аудита и шлёт алерт владельцу.
   Снятие Kill Switch (unlock) доступно СТРОГО владельцу в Studio/CLI (агенту в MCP запрещено).
2. Outbound Action & Payee-Swap Gate:
   инспектирует исходящие действия агента (криптокошельки EVM/BTC/Solana/TRON, IBAN mod-97, карты Luhn,
   внешние URL через net_guard, shell/exfil команды и утечку секретов через safety.redact) до выполнения.
   Новые или подменённые получатели/домены попадают в очередь подтверждения владельца; секреты и SSRF
   блокируются немедленно.
3. Интеграция с JS Supply-Chain & Crypto-Clipper Guard (`supply_chain_guard.py`).
4. Compliance & Threat Proof Pack:
   криптографически заверенный (SHA-256 + HMAC владельца) отчёт для CISO/аудиторов с картой
   OWASP Agentic AI Top 10 (ASI01–ASI10), статистикой атак, цепью аудита и 7 раундами Red Team.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import html as _html
import json
import os
import re
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from . import (
    aifa_sec_bridge,
    audit_chain,
    config,
    defense_stats,
    integrity,
    net_guard,
    redteam_rounds,
    roles,
    safety,
    solana_crypto_shield,
    supply_chain_guard,
)
import base64
import math
from collections import Counter
from .store import add_column_safe, now_iso

_SHIELD_DDL = """
CREATE TABLE IF NOT EXISTS shield_state (
    user_id TEXT PRIMARY KEY,
    lockdown INTEGER NOT NULL DEFAULT 0,
    block_writes INTEGER NOT NULL DEFAULT 0,
    auto_kill_enabled INTEGER NOT NULL DEFAULT 1,
    window_s INTEGER NOT NULL DEFAULT 60,
    threshold INTEGER NOT NULL DEFAULT 8,
    tripped_at TEXT,
    tripped_reason TEXT,
    tripped_agent TEXT,
    tripped_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shield_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shield_events_user_time ON shield_events (user_id, created_at);
CREATE TABLE IF NOT EXISTS shield_outbound_queue (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    preview TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by TEXT
);
CREATE TABLE IF NOT EXISTS shield_allowlist (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, entry_type, value)
);
CREATE TABLE IF NOT EXISTS shield_mcp_tool_pins (
    user_id TEXT NOT NULL,
    server_name TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    schema_sha256 TEXT NOT NULL,
    pinned_at TEXT NOT NULL,
    last_checked_at TEXT NOT NULL,
    PRIMARY KEY (user_id, server_name, tool_name)
);
"""

# Опасные шаблоны для исходящих вызовов и shell-команд
_DANGEROUS_SHELL_RE = re.compile(
    r"(?:"
    r"(?:curl|wget|fetch)\s+[^\n|]{3,}\|\s*(?:sh|bash|zsh|pwsh|powershell)|"
    r"powershell(?:\.exe)?\s+[^\n]*(?:-enc|-encodedcommand|downloadstring|invoke-expression|\biex\b)|"
    r"certutil(?:\.exe)?\s+[^\n]*-urlcache|"
    r"\brm\s+-rf\s+(?:/|~|\$HOME)|"
    r"(?:/\.ssh/id_(?:rsa|ed25519)|/\.aws/credentials|authorized_keys|\b\.env\b)|"
    r"\b(?:nc|ncat|netcat)\s+[^\n]*-e\s+|"
    r"\b(?:bash\s+-i\s+>&|/dev/tcp/)"
    r")",
    re.IGNORECASE,
)

# Детекторы реквизитов и криптокошельков
_EVM_ADDR_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_BTC_BECH32_RE = re.compile(r"\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,62}\b")
_BTC_LEGACY_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_TRON_ADDR_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_SOL_CONTEXT_RE = re.compile(
    r"(?:wallet|address|sol|solana|usdt|usdc|pay|transfer|send|recipient|кошел|оплат|перевед|адрес)",
    re.IGNORECASE,
)
_SOL_CAND_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
_IBAN_CAND_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_CARD_CAND_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_URL_RE = re.compile(r"\b(?:https?|ftp|file|javascript|data):[^\s\"'<>`]+", re.IGNORECASE)
_SHORTENER_HOSTS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "tiny.cc",
})
_PAYEE_SWAP_PHRASE_RE = re.compile(
    r"(?:instead\s+of|new\s+wallet|new\s+address|from\s+now\s+on\s+(?:pay|send|transfer)|"
    r"вместо\s+старого|новый\s+кошел|отныне\s+перевод)",
    re.IGNORECASE,
)

# Каноническая матрица OWASP Agentic AI Top 10 (ASI01..ASI10) с реальными модулями кода
OWASP_AGENTIC_MATRIX: tuple[dict[str, str], ...] = (
    {
        "id": "ASI01",
        "name": "Agent Goal Hijacking & Instruction Override",
        "control": "safety.looks_like_instruction (13 langs), guard.py ONNX, 128-bit nonce fencing, PADAM_STRICT=1",
        "status": "enforced",
    },
    {
        "id": "ASI02",
        "name": "Tool Misuse & Machine-Speed Exploitation",
        "control": "agentic_shield.py Machine-Speed Kill Switch, burst limiter, strict JSON-RPC schemas",
        "status": "enforced",
    },
    {
        "id": "ASI03",
        "name": "Identity & Privilege Abuse",
        "control": "roles.require_owner, integrity.py HMAC/Ed25519 seals, app_acl.py, MCP owner-only split",
        "status": "enforced",
    },
    {
        "id": "ASI04",
        "name": "Agentic & Web Supply-Chain Compromise",
        "control": "supply_chain_guard.py (SRI/CSP, CDN SHA-256 baseline pinning, Crypto-Clipper) + plugins.py SHA-256",
        "status": "enforced",
    },
    {
        "id": "ASI05",
        "name": "Unexpected Code Execution & SSRF",
        "control": "Outbound Gate shell/exfil rules, net_guard.validate_outbound_url (anti-SSRF/DNS rebinding)",
        "status": "enforced",
    },
    {
        "id": "ASI06",
        "name": "Memory & Context Poisoning",
        "control": "HOLD_EXTERNAL quarantine, quarantine_council.py, cryptographic forget with Merkle receipt",
        "status": "enforced",
    },
    {
        "id": "ASI07",
        "name": "Insecure Inter-Agent Communication",
        "control": "live_mesh.py PQC X-Wing (ML-KEM-768 + X25519), sibling_registry.py signed provenance",
        "status": "enforced",
    },
    {
        "id": "ASI08",
        "name": "Cascading Failures & Autonomous Runaway",
        "control": "Auto-Lockdown Kill Switch, snapshots.py cognitive rollback, restore_drill.py",
        "status": "enforced",
    },
    {
        "id": "ASI09",
        "name": "Human-Agent Trust & Payee-Swap Exploitation",
        "control": "Outbound Action & Payee-Swap Gate, wallet/IBAN/domain allowlist, owner confirmation UI",
        "status": "enforced",
    },
    {
        "id": "ASI10",
        "name": "Rogue Agents & Tampered Audit Trails",
        "control": "audit_chain.py SHA-256 hash chain + HMAC head anchor, defense_stats.py, Proof Pack",
        "status": "enforced",
    },
)


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_tables(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_agentic_shield_ready", False):
        return
    with store._lock:
        store.conn.executescript(_SHIELD_DDL)
        add_column_safe(store.conn, "shield_state", "policy_profile", "TEXT DEFAULT 'balanced'")
        store.conn.commit()
        store._agentic_shield_ready = True


def _default_state(memory: Any) -> dict[str, Any]:
    _ensure_tables(memory)
    store = memory.store
    win_default = max(5, min(3600, int(os.environ.get("PADAM_SHIELD_WINDOW_S", "60") or 60)))
    thr_default = max(2, min(100, int(os.environ.get("PADAM_SHIELD_THRESHOLD", "8") or 8)))
    auto_default = 0 if os.environ.get("PADAM_SHIELD_AUTO_KILL", "1").strip() == "0" else 1
    block_default = 1 if os.environ.get("PADAM_SHIELD_BLOCK_WRITES", "0").strip() == "1" else 0
    with store._lock:
        row = store.one("SELECT * FROM shield_state WHERE user_id = ?", (memory.user_id,))
        if row is not None:
            return dict(row)
        now = _utc_iso()
        store.conn.execute(
            """INSERT INTO shield_state
               (user_id, lockdown, block_writes, auto_kill_enabled, window_s, threshold,
                tripped_at, tripped_reason, tripped_agent, tripped_count, updated_at)
               VALUES (?, 0, ?, ?, ?, ?, NULL, NULL, NULL, 0, ?)""",
            (memory.user_id, block_default, auto_default, win_default, thr_default, now),
        )
        store.conn.commit()
        row = store.one("SELECT * FROM shield_state WHERE user_id = ?", (memory.user_id,))
        return dict(row)


def is_lockdown_active(memory: Any) -> bool:
    """Возвращает True, если сработал Kill Switch ИЛИ включён строгий профиль PADAM_STRICT=1."""
    if config.STRICT:
        return True
    if memory is None or getattr(memory, "store", None) is None:
        return False
    st = _default_state(memory)
    return bool(st.get("lockdown"))


def is_write_blocking_active(memory: Any) -> bool:
    """True, если при активном Kill Switch агентские записи должны отклоняться целиком."""
    if memory is None or getattr(memory, "store", None) is None:
        return False
    st = _default_state(memory)
    return bool(st.get("lockdown")) and (
        bool(st.get("block_writes")) or os.environ.get("PADAM_SHIELD_BLOCK_WRITES", "0").strip() == "1"
    )


def _alert_file_path(store: Any) -> Path | None:
    p = str(getattr(store, "path", "") or "")
    if not p or p == ":memory:":
        return None
    return Path(p + ".shield_alert.json")


def _dispatch_kill_alert(memory: Any, state: dict[str, Any], reason: str, agent_id: str) -> None:
    """Записывает инцидент в audit_chain, локальный alert-файл и (если задан) подписанный вебхук."""
    payload = {
        "event": "padam_kill_switch_tripped",
        "user_id": memory.user_id,
        "agent_id": agent_id,
        "reason": reason[:200],
        "tripped_at": state.get("tripped_at") or _utc_iso(),
        "strict_mode_active": True,
    }
    try:
        audit_chain.append_audit(memory, "kill_switch_tripped", payload, agent_id=agent_id)
    except Exception:
        pass
    try:
        memory._log_audit(
            "kill_switch_tripped",
            None,
            actor="shield",
            agent_id=agent_id,
            outcome="lockdown",
            detail=reason[:200],
        )
    except Exception:
        pass

    apath = _alert_file_path(memory.store)
    if apath is not None:
        try:
            apath.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            net_guard.restrict_file_to_owner(apath)
        except Exception:
            pass

    try:
        from . import siem_webhook as _sw
        _sw.dispatch_webhook_event(
            memory,
            event_type='kill_switch_tripped',
            severity='critical',
            title='PADAM Kill Switch Activated (Machine-Speed Defense)',
            detail=f'Agent={agent_id}; reason={reason[:200]}',
            agent_id=agent_id,
            extra={'tripped_count': int(state.get('tripped_count') or 0)},
        )
    except Exception:
        pass
    if config.WEBHOOK_URL:
        try:
            url = net_guard.validate_outbound_url(config.WEBHOOK_URL, allow_localhost=True)
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            hdrs = {"Content-Type": "application/json", "User-Agent": "padam-agentic-shield"}
            if config.WEBHOOK_SECRET:
                sig = hmac.new(config.WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
                hdrs["X-PADAM-Signature"] = f"sha256={sig}"
            req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
            with net_guard.safe_urlopen(req, timeout=4, allow_localhost=True):
                pass
        except Exception:
            pass


def trip_kill_switch(
    memory: Any,
    *,
    reason: str = "manual_owner_trip",
    agent_id: str = "owner",
    block_writes: bool | None = None,
) -> dict[str, Any]:
    """Немедленно активирует Kill Switch (жёсткий карантин PADAM_STRICT=1 для этой базы) и шлёт алерт."""
    st = _default_state(memory)
    now = _utc_iso()
    clean_reason = safety.clean(str(reason or "anomaly"))[:200]
    clean_agent = safety.clean(str(agent_id or "agent"))[:80]
    new_block = int(st.get("block_writes") or 0) if block_writes is None else (1 if block_writes else 0)
    already = bool(st.get("lockdown"))
    with memory.store._lock:
        memory.store.conn.execute(
            """UPDATE shield_state
               SET lockdown = 1,
                   block_writes = ?,
                   tripped_at = COALESCE(tripped_at, ?),
                   tripped_reason = COALESCE(tripped_reason, ?),
                   tripped_agent = COALESCE(tripped_agent, ?),
                   tripped_count = tripped_count + ?,
                   updated_at = ?
               WHERE user_id = ?""",
            (new_block, now, clean_reason, clean_agent, 0 if already else 1, now, memory.user_id),
        )
        memory.store.conn.commit()
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        # Запоминаем, какими флаги были ДО тревоги, чтобы снятие Kill Switch вернуло их.
        # Без этого после разблокировки владельцем процесс оставался строгим до перезапуска:
        # каждая запись агента уходила в карантин (найдено бенчмарком качества 20.11.2026).
        if not _STRICT_SAVED:
            _STRICT_SAVED.update({name: getattr(config, name) for name in _STRICT_FLAGS})
        config.STRICT = True
        config.MCP_REVIEW_ALL = True
        config.HOLD_EXTERNAL = True
        config.KEEP_SECRETS = False
        config.MCP_TRUST_WRITES = False
    updated = _default_state(memory)
    if not already:
        _dispatch_kill_alert(memory, updated, clean_reason, clean_agent)
    return get_shield_status(memory)


# Флаги процесса, которые Kill Switch переводит в строгий режим, и их значения до тревоги.
_STRICT_FLAGS = ("STRICT", "MCP_REVIEW_ALL", "HOLD_EXTERNAL", "KEEP_SECRETS", "MCP_TRUST_WRITES")
_STRICT_SAVED: dict[str, Any] = {}


def unlock_kill_switch(
    memory: Any,
    *,
    actor: Any = None,
    clear_recent_events: bool = True,
) -> dict[str, Any]:
    """Снимает Kill Switch. Разрешено СТРОГО владельцу (в Studio или CLI)."""
    roles.require_owner(actor, "agentic_shield_unlock")
    _default_state(memory)
    now = _utc_iso()
    with memory.store._lock:
        memory.store.conn.execute(
            """UPDATE shield_state
               SET lockdown = 0, tripped_reason = NULL, tripped_agent = NULL, updated_at = ?
               WHERE user_id = ?""",
            (now, memory.user_id),
        )
        if clear_recent_events:
            memory.store.conn.execute("DELETE FROM shield_events WHERE user_id = ?", (memory.user_id,))
        memory.store.conn.commit()
    # Сбрасываем скользящий счётчик burst-вызовов на объекте хранилища
    if _STRICT_SAVED:
        for name, value in _STRICT_SAVED.items():
            setattr(config, name, value)
        _STRICT_SAVED.clear()
    burst_map = memory.store.__dict__.get("_shield_burst")
    if isinstance(burst_map, dict):
        burst_map.clear()
    apath = _alert_file_path(memory.store)
    if apath is not None and apath.exists():
        try:
            apath.unlink()
        except Exception:
            pass
    try:
        audit_chain.append_audit(memory, "kill_switch_unlocked", {"by": "owner", "at": now}, agent_id="owner")
    except Exception:
        pass
    return get_shield_status(memory)


def configure_shield(
    memory: Any,
    *,
    actor: Any = None,
    auto_kill_enabled: bool | None = None,
    block_writes: bool | None = None,
    window_s: int | None = None,
    threshold: int | None = None,
) -> dict[str, Any]:
    """Обновляет настройки Machine-Speed Shield (строго только владелец)."""
    roles.require_owner(actor, "agentic_shield_config")
    st = _default_state(memory)
    new_auto = int(st["auto_kill_enabled"]) if auto_kill_enabled is None else (1 if auto_kill_enabled else 0)
    new_blk = int(st["block_writes"]) if block_writes is None else (1 if block_writes else 0)
    new_win = int(st["window_s"]) if window_s is None else max(5, min(3600, int(window_s)))
    new_thr = int(st["threshold"]) if threshold is None else max(2, min(100, int(threshold)))
    now = _utc_iso()
    with memory.store._lock:
        memory.store.conn.execute(
            """UPDATE shield_state
               SET auto_kill_enabled = ?, block_writes = ?, window_s = ?, threshold = ?, updated_at = ?
               WHERE user_id = ?""",
            (new_auto, new_blk, new_win, new_thr, now, memory.user_id),
        )
        memory.store.conn.commit()
    return get_shield_status(memory)


def record_anomaly(
    memory: Any,
    *,
    event_type: str,
    severity: str = "warn",
    weight: int = 1,
    agent_id: str = "agent",
    detail: str = "",
) -> dict[str, Any]:
    """Регистрирует аномалию в скользящем окне и при превышении порога автоматически запускает Kill Switch."""
    st = _default_state(memory)
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat(timespec="seconds")
    ev_id = f"sev-{uuid.uuid4().hex[:12]}"
    clean_type = re.sub(r"[^a-zA-Z0-9_.:-]", "_", str(event_type or "anomaly"))[:64]
    clean_sev = str(severity or "warn").lower()
    if clean_sev not in ("info", "warn", "high", "critical"):
        clean_sev = "warn"
    w = max(1, min(20, int(weight or 1)))
    clean_agent = safety.clean(str(agent_id or "agent"))[:80]
    # Никогда не сохраняем сырые секреты или полные инъекции в detail
    masked_detail, _ = safety.redact(str(detail or ""))
    clean_detail = safety.clean(masked_detail)[:180]

    window_s = max(5, int(st.get("window_s") or 60))
    threshold = max(2, int(st.get("threshold") or 8))
    since = (now_dt - timedelta(seconds=window_s)).isoformat(timespec="seconds")

    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT INTO shield_events (id, user_id, agent_id, event_type, severity, weight, detail, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (ev_id, memory.user_id, clean_agent, clean_type, clean_sev, w, clean_detail, now),
        )
        row = memory.store.one(
            "SELECT COALESCE(SUM(weight), 0) AS score, COUNT(*) AS cnt FROM shield_events "
            "WHERE user_id = ? AND created_at >= ?",
            (memory.user_id, since),
        )
        score_in_window = int(row["score"] or 0) if row is not None else w
        events_in_window = int(row["cnt"] or 0) if row is not None else 1
        memory.store.conn.commit()

    tripped_now = False
    if bool(st.get("auto_kill_enabled")) and not bool(st.get("lockdown")) and score_in_window >= threshold:
        trip_kill_switch(
            memory,
            reason=f"machine_speed_anomaly:{clean_type}(score={score_in_window}/{threshold} in {window_s}s)",
            agent_id=clean_agent,
        )
        tripped_now = True

    return {
        "event_id": ev_id,
        "score_in_window": score_in_window,
        "events_in_window": events_in_window,
        "threshold": threshold,
        "window_s": window_s,
        "tripped_now": tripped_now,
        "lockdown": is_lockdown_active(memory),
    }


def observe_tool_call_rate(memory: Any, *, tool_name: str, agent_id: str = "agent") -> dict[str, Any] | None:
    """Отслеживает аномальный всплеск скорости вызовов MCP (типа ARTEX / exploit_agent)."""
    if memory is None or getattr(memory, "store", None) is None:
        return None
    burst_limit = max(15, int(os.environ.get("PADAM_SHIELD_BURST_LIMIT", "600") or 600))
    burst_window = 10.0
    now_mono = time.monotonic()
    bmap: dict[str, deque[float]] = memory.store.__dict__.setdefault("_shield_burst", {})
    key = f"{memory.user_id}:{agent_id}"
    dq = bmap.get(key)
    if dq is None:
        dq = deque()
        bmap[key] = dq
    dq.append(now_mono)
    while dq and (now_mono - dq[0]) > burst_window:
        dq.popleft()
    if len(dq) > burst_limit:
        dq.clear()
        return record_anomaly(
            memory,
            event_type="machine_speed_tool_burst",
            severity="critical",
            weight=max(8, int(_default_state(memory).get("threshold") or 8)),
            agent_id=agent_id,
            detail=f"burst>{burst_limit}/10s on {tool_name}",
        )
    return None


# ==================== 1б. UNICODE STEALTH / DEOBFUSCATION (LAKERA) ====================
_BIDI_CHARS = frozenset({'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069'})
_ZERO_WIDTH_CHARS = frozenset({'\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u00ad'})
_B64_CAND_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_CAND_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")
_POLICY_PROFILES = ('balanced', 'strict_fin', 'paranoid_airgap')


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (0 if ca == cb else 1)))
        prev = cur
    return prev[-1]


def _extract_unicode_tags(text: str) -> str:
    """Извлекает скрытый ASCII-текст из блока Unicode Tags (U+E0000..U+E007F)."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return ''.join(out)


def inspect_unicode_and_encoding(text: str) -> dict[str, Any]:
    """Ловит стеганографию в Unicode Tags (U+E00xx), Bidi Trojan Source, Zero-Width и многослойную обфускацию."""
    raw = str(text or '')
    findings: list[dict[str, str]] = []
    decoded_layers: list[str] = []

    tag_hidden = _extract_unicode_tags(raw)
    if tag_hidden:
        susp_tag = safety.looks_like_instruction(tag_hidden) or safety.changes_owner_or_rules(tag_hidden) or bool(_URL_RE.search(tag_hidden))
        findings.append({
            'code': 'unicode_tag_steganography',
            'severity': 'critical' if susp_tag else 'high',
            'detail': f'Обнаружен скрытый Unicode-Tag текст ({len(tag_hidden)} симв.): {safety.redact(tag_hidden)[0][:100]}',
        })
        decoded_layers.append(tag_hidden)

    bidi_cnt = sum(1 for ch in raw if ch in _BIDI_CHARS)
    if bidi_cnt > 0:
        findings.append({
            'code': 'bidi_trojan_override',
            'severity': 'critical',
            'detail': f'Обнаружены Bidi-управляющие символы ({bidi_cnt}), меняющие визуальный порядок чтения (Trojan Source).',
        })

    zw_cnt = sum(1 for ch in raw if ch in _ZERO_WIDTH_CHARS)
    if zw_cnt >= 6:
        findings.append({
            'code': 'zero_width_obfuscation',
            'severity': 'high',
            'detail': f'Аномальное число невидимых zero-width символов ({zw_cnt}) — попытка обойти фильтры.',
        })

    # Проверка смешанных алфавитов (кириллица+латиница в одном токене, homoglyph spoofing)
    mixed_tokens = []
    for tok in re.findall(r'[A-Za-zА-Яа-яЁё]{3,}', raw):
        has_lat = any('A' <= c <= 'Z' or 'a' <= c <= 'z' for c in tok)
        has_cyr = any('А' <= c <= 'я' or c in 'Ёё' for c in tok)
        if has_lat and has_cyr:
            mixed_tokens.append(tok)
    if mixed_tokens:
        findings.append({
            'code': 'mixed_script_homoglyph',
            'severity': 'high',
            'detail': f'Обнаружено смешение латиницы и кириллицы внутри слов ({len(mixed_tokens)}): {mixed_tokens[0][:30]}',
        })

    # Рекурсивное (до 2 уровней) декодирование URL / Base64 / Hex в поиске скрытых команд и URL
    frontier = [raw]
    seen_dec = {raw}
    for _ in range(2):
        next_f = []
        for item in frontier:
            if '%' in item:
                try:
                    uq = urllib.parse.unquote(item)
                    if uq != item and uq not in seen_dec:
                        seen_dec.add(uq)
                        next_f.append(uq)
                        decoded_layers.append(uq)
                except Exception:
                    pass
            for m in _B64_CAND_RE.finditer(item):
                try:
                    b_dec = base64.b64decode(m.group(0), validate=True).decode('utf-8', 'strict')
                    if b_dec and sum(ch.isprintable() or ch.isspace() for ch in b_dec) / len(b_dec) >= 0.85 and b_dec not in seen_dec:
                        seen_dec.add(b_dec)
                        next_f.append(b_dec)
                        decoded_layers.append(b_dec)
                except Exception:
                    pass
            for m in _HEX_CAND_RE.finditer(item):
                cand_h = m.group(0)
                if len(cand_h) >= 32 and len(cand_h) % 2 == 0:
                    try:
                        h_dec = bytes.fromhex(cand_h).decode('utf-8', 'strict')
                        if h_dec and sum(ch.isprintable() or ch.isspace() for ch in h_dec) / len(h_dec) >= 0.85 and h_dec not in seen_dec:
                            seen_dec.add(h_dec)
                            next_f.append(h_dec)
                            decoded_layers.append(h_dec)
                    except Exception:
                        pass
        frontier = next_f
        if not frontier:
            break

    for layer in decoded_layers:
        if safety.looks_like_instruction(layer) or safety.changes_owner_or_rules(layer) or _DANGEROUS_SHELL_RE.search(layer):
            findings.append({
                'code': 'encoded_hidden_payload',
                'severity': 'critical',
                'detail': 'Обнаружена скрытая инструкция/команда внутри закодированного слоя (Base64/URL/Hex/Tag).',
            })
            break

    return {'clean': not findings, 'findings': findings, 'decoded_layers_count': len(decoded_layers), 'decoded_layers': decoded_layers[:6]}


# ==================== 1в. MCP TOOL POISONING, SHADOWING & RUG-PULL (SNYK/INVARIANT) ====================
_MCP_POISON_RE = re.compile(
    r"(?:<important>|important\s*:|do\s+not\s+tell\s+the\s+user|hide\s+this\s+from\s+the\s+user|"
    r"never\s+mention\s+this|before\s+running\s+this\s+tool|secretly\s+read|pass\s+its\s+contents)",
    re.IGNORECASE,
)
_MCP_EXFIL_REF_RE = re.compile(
    r"(?:~?/.ssh/|id_rsa|id_ed25519|\.aws/credentials|\bmcp_config\.json\b|\.env\b|/etc/passwd|keychain|seed\s*phrase)",
    re.IGNORECASE,
)
_MCP_SHADOW_RE = re.compile(
    r"(?:when\s+calling\s+[a-z0-9_.-]+|instead\s+of\s+calling\s+[a-z0-9_.-]+|override\s+the\s+behavior\s+of\s+[a-z0-9_.-]+)",
    re.IGNORECASE,
)


def audit_mcp_tools(
    memory: Any,
    tools_or_config: list[dict[str, Any]] | dict[str, Any] | str,
    *,
    server_name: str = 'mcp',
    pin: bool = False,
) -> dict[str, Any]:
    """Сканирует описания MCP-инструментов и конфиг mcpServers на Tool Poisoning, Shadowing, Rug-Pull и секреты."""
    _ensure_tables(memory)
    srv_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', str(server_name or 'mcp').strip())[:64] or 'mcp'
    tools: list[dict[str, Any]] = []
    config_alerts: list[dict[str, Any]] = []

    parsed_src: Any = tools_or_config
    if isinstance(tools_or_config, str):
        s_val = tools_or_config.strip()
        if (s_val.endswith('.json') or Path(s_val).exists()) and Path(s_val).is_file():
            parsed_src = json.loads(Path(s_val).read_text(encoding='utf-8', errors='replace'))
        else:
            parsed_src = json.loads(s_val)

    if isinstance(parsed_src, dict) and 'mcpServers' in parsed_src:
        for s_key, s_cfg in (parsed_src.get('mcpServers') or {}).items():
            if not isinstance(s_cfg, dict):
                continue
            cmd_full = f"{s_cfg.get('command', '')} {' '.join(str(a) for a in (s_cfg.get('args') or []))}"
            env_map = s_cfg.get('env') or {}
            for k, v in env_map.items():
                _, m_sec = safety.redact(f'{k}={v}')
                if m_sec:
                    config_alerts.append({
                        'server': s_key, 'code': 'plaintext_secret_in_mcp_config', 'severity': 'critical',
                        'detail': f'В открытом env конфига MCP ({s_key}) найден секрет в поле {k}.',
                    })
            if _DANGEROUS_SHELL_RE.search(cmd_full):
                config_alerts.append({
                    'server': s_key, 'code': 'dangerous_command_in_mcp_config', 'severity': 'critical',
                    'detail': f'Сервер MCP ({s_key}) запускает потенциально опасную shell-команду.',
                })
            if isinstance(s_cfg.get('tools'), list):
                for td in s_cfg['tools']:
                    if isinstance(td, dict):
                        tools.append({**td, '_server': s_key})
    elif isinstance(parsed_src, dict) and isinstance(parsed_src.get('tools'), list):
        tools = [x for x in parsed_src['tools'] if isinstance(x, dict)]
    elif isinstance(parsed_src, list):
        tools = [x for x in parsed_src if isinstance(x, dict)]

    now = _utc_iso()
    findings: list[dict[str, Any]] = list(config_alerts)
    rug_pulls = 0
    poisoned = 0
    pinned_now = 0
    tool_summaries: list[dict[str, Any]] = []

    for tdef in tools[:200]:
        tname = str(tdef.get('name') or '').strip()[:80]
        if not tname:
            continue
        s_for_t = str(tdef.get('_server') or srv_name)[:64]
        desc = str(tdef.get('description') or '')
        schema_obj = tdef.get('inputSchema') or {}
        schema_canon = _canonical_json({'name': tname, 'description': desc, 'inputSchema': schema_obj})
        schema_sha = hashlib.sha256(schema_canon.encode('utf-8')).hexdigest()
        all_text = desc + '\n' + json.dumps(schema_obj, ensure_ascii=False)

        t_issues: list[dict[str, str]] = []
        if _MCP_POISON_RE.search(all_text) or safety.looks_like_instruction(desc):
            t_issues.append({'code': 'mcp_tool_poisoning', 'severity': 'critical', 'detail': 'Скрытая директива/инструкция в описании инструмента (<IMPORTANT>/ignore/hide from user).'})
        if _MCP_EXFIL_REF_RE.search(all_text):
            t_issues.append({'code': 'mcp_tool_secret_harvest', 'severity': 'critical', 'detail': 'Описание/схема инструмента обращается к ~/.ssh, .env, keychain или секретным файлам.'})
        if _MCP_SHADOW_RE.search(all_text):
            t_issues.append({'code': 'mcp_tool_shadowing', 'severity': 'high', 'detail': 'Попытка перенаправить или подменить поведение другого инструмента (Tool Shadowing).'})
        uni = inspect_unicode_and_encoding(all_text)
        for uf in uni['findings']:
            t_issues.append({'code': f"mcp_{uf['code']}", 'severity': uf['severity'], 'detail': uf['detail']})

        # Проверка Rug-Pull по shield_mcp_tool_pins
        pin_status = 'unpinned'
        with memory.store._lock:
            prev = memory.store.one(
                'SELECT schema_sha256 FROM shield_mcp_tool_pins WHERE user_id = ? AND server_name = ? AND tool_name = ?',
                (memory.user_id, s_for_t, tname),
            )
            if prev is not None:
                if str(prev['schema_sha256']) != schema_sha:
                    rug_pulls += 1
                    pin_status = 'rug_pull_changed'
                    t_issues.append({
                        'code': 'mcp_tool_rug_pull',
                        'severity': 'critical',
                        'detail': f'Хэш описания/схемы инструмента {tname} ИЗМЕНИЛСЯ после закрепления (атака MCP Rug-Pull)!',
                    })
                    if pin:
                        memory.store.conn.execute(
                            'UPDATE shield_mcp_tool_pins SET schema_sha256 = ?, pinned_at = ?, last_checked_at = ? WHERE user_id = ? AND server_name = ? AND tool_name = ?',
                            (schema_sha, now, now, memory.user_id, s_for_t, tname),
                        )
                else:
                    pin_status = 'verified'
                    memory.store.conn.execute(
                        'UPDATE shield_mcp_tool_pins SET last_checked_at = ? WHERE user_id = ? AND server_name = ? AND tool_name = ?',
                        (now, memory.user_id, s_for_t, tname),
                    )
            elif pin and not t_issues:
                pin_status = 'pinned'
                pinned_now += 1
                memory.store.conn.execute(
                    'INSERT INTO shield_mcp_tool_pins (user_id, server_name, tool_name, schema_sha256, pinned_at, last_checked_at) VALUES (?, ?, ?, ?, ?, ?)',
                    (memory.user_id, s_for_t, tname, schema_sha, now, now),
                )
            memory.store.conn.commit()

        if t_issues:
            poisoned += 1
            for iss in t_issues:
                findings.append({'server': s_for_t, 'tool': tname, **iss})
        tool_summaries.append({'server': s_for_t, 'tool': tname, 'sha256': schema_sha[:16], 'pin_status': pin_status, 'issues': len(t_issues)})

    if findings:
        record_anomaly(memory, event_type='mcp_tool_poisoning_detected', severity='critical', weight=4, agent_id=srv_name, detail=f'issues={len(findings)} rug_pulls={rug_pulls}')

    return {
        'ok': True,
        'clean': len(findings) == 0,
        'server_name': srv_name,
        'tools_scanned': len(tool_summaries),
        'poisoned_tools': poisoned,
        'rug_pulls_detected': rug_pulls,
        'pinned_now': pinned_now,
        'findings': findings,
        'tools': tool_summaries,
    }


def set_policy_profile(memory: Any, profile: str, *, actor: Any = None) -> dict[str, Any]:
    """Переключает профиль жёсткости Щита: balanced | strict_fin | paranoid_airgap."""
    roles.require_owner(actor, 'agentic_shield_config')
    prof = str(profile or 'balanced').strip().lower()
    if prof not in _POLICY_PROFILES:
        raise ValueError(f'unsupported policy profile: {prof}')
    _default_state(memory)
    now = _utc_iso()
    if prof == 'strict_fin':
        thr, auto_k, bw = 4, 1, 1
    elif prof == 'paranoid_airgap':
        thr, auto_k, bw = 2, 1, 1
    else:
        thr, auto_k, bw = 8, 1, 0
    with memory.store._lock:
        memory.store.conn.execute(
            'UPDATE shield_state SET policy_profile = ?, threshold = ?, auto_kill_enabled = ?, block_writes = ?, updated_at = ? WHERE user_id = ?',
            (prof, thr, auto_k, bw, now, memory.user_id),
        )
        memory.store.conn.commit()
    return get_shield_status(memory)

# ==================== 2. OUTBOUND ACTION & PAYEE-SWAP GATE ====================

def _valid_iban_mod97(cand: str) -> bool:
    s = re.sub(r"\s+", "", cand.upper())
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
    rem = 0
    for ch in digits:
        rem = (rem * 10 + int(ch)) % 97
    return rem == 1


def _extract_payment_indicators(text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in _EVM_ADDR_RE.finditer(text):
        val = m.group(0)
        if val.lower() not in seen:
            seen.add(val.lower())
            found.append({"kind": "wallet_evm", "value": val})
    for m in _BTC_BECH32_RE.finditer(text):
        val = m.group(0)
        if val not in seen:
            seen.add(val)
            found.append({"kind": "wallet_btc", "value": val})
    for m in _TRON_ADDR_RE.finditer(text):
        val = m.group(0)
        if val not in seen:
            seen.add(val)
            found.append({"kind": "wallet_tron", "value": val})
    if _SOL_CONTEXT_RE.search(text):
        for m in _SOL_CAND_RE.finditer(text):
            val = m.group(0)
            if val in seen or val.startswith(("0x", "bc1")):
                continue
            # Настоящий base58 pubkey содержит и цифры, и буквы разного регистра
            if any(c.isdigit() for c in val) and any(c.isupper() for c in val) and any(c.islower() for c in val):
                seen.add(val)
                found.append({"kind": "wallet_solana", "value": val})
        for m in _BTC_LEGACY_RE.finditer(text):
            val = m.group(0)
            if val not in seen and any(c.isdigit() for c in val) and any(c.isalpha() for c in val):
                seen.add(val)
                found.append({"kind": "wallet_btc_legacy", "value": val})
    for m in _IBAN_CAND_RE.finditer(text):
        val = m.group(0)
        if val not in seen and _valid_iban_mod97(val):
            seen.add(val)
            found.append({"kind": "iban", "value": val})
    for m in _CARD_CAND_RE.finditer(text):
        digits = re.sub(r"[^0-9]", "", m.group(0))
        if 13 <= len(digits) <= 19 and digits not in seen and safety._luhn(digits):
            seen.add(digits)
            found.append({"kind": "card", "value": f"card_ending_{digits[-4:]}"})
    return found


def list_allowlist(memory: Any) -> list[dict[str, Any]]:
    _ensure_tables(memory)
    rows = memory.store.query(
        "SELECT id, entry_type, value, label, created_at FROM shield_allowlist "
        "WHERE user_id = ? ORDER BY entry_type, value",
        (memory.user_id,),
    )
    return [dict(r) for r in rows]


def add_allowlist_entry(
    memory: Any,
    *,
    entry_type: str,
    value: str,
    label: str = "",
    actor: Any = None,
) -> dict[str, Any]:
    """Добавляет доверенный домен или кошелёк (строго только владелец)."""
    roles.require_owner(actor, "agentic_shield_allowlist")
    _ensure_tables(memory)
    etype = str(entry_type or "").strip().lower()
    if etype not in ("domain", "wallet", "iban", "payee"):
        raise ValueError(f"Unsupported allowlist entry_type: {entry_type!r}")
    val = str(value or "").strip()
    if not val or len(val) > 256:
        raise ValueError("Allowlist value must be 1..256 chars")
    if etype == "domain":
        val = val.lower().removeprefix("https://").removeprefix("http://").split("/")[0].split(":")[0]
    eid = f"alw-{uuid.uuid4().hex[:10]}"
    now = _utc_iso()
    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT INTO shield_allowlist (id, user_id, entry_type, value, label, created_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id, entry_type, value) DO UPDATE SET label = excluded.label""",
            (eid, memory.user_id, etype, val, safety.clean(str(label or ""))[:120], now),
        )
        memory.store.conn.commit()
        row = memory.store.one(
            "SELECT id, entry_type, value, label, created_at FROM shield_allowlist "
            "WHERE user_id = ? AND entry_type = ? AND value = ?",
            (memory.user_id, etype, val),
        )
    try:
        audit_chain.append_audit(memory, "shield_allowlist_add", {"type": etype, "value": val}, agent_id="owner")
    except Exception:
        pass
    return dict(row)


def remove_allowlist_entry(memory: Any, entry_id: str, *, actor: Any = None) -> dict[str, Any]:
    """Удаляет доверенную запись (строго только владелец)."""
    roles.require_owner(actor, "agentic_shield_allowlist")
    _ensure_tables(memory)
    with memory.store._lock:
        cur = memory.store.conn.execute(
            "DELETE FROM shield_allowlist WHERE user_id = ? AND id = ?",
            (memory.user_id, str(entry_id or "").strip()),
        )
        memory.store.conn.commit()
    return {"removed": int(cur.rowcount or 0)}


def _domain_allowed(host: str, allowed_domains: set[str]) -> bool:
    h = (host or "").lower().split(":")[0]
    return any(h == d or h.endswith("." + d) for d in allowed_domains)


def inspect_outbound_action(
    memory: Any,
    *,
    action_type: str,
    target: str = "",
    payload: str = "",
    agent_id: str = "agent",
    origin: str = "agent",
) -> dict[str, Any]:
    """Проверяет исходящее действие (платёж, кошелёк, URL, shell, письмо) до выполнения."""
    _ensure_tables(memory)
    act_type = re.sub(r"[^a-zA-Z0-9_.-]", "_", str(action_type or "action").strip().lower())[:48]
    raw_target = safety.strip_invisible(str(target or ""))
    raw_payload = safety.strip_invisible(str(payload or ""))
    combined = f"{raw_target}\n{raw_payload}".strip()
    clean_agent = safety.clean(str(agent_id or "agent"))[:80]

    # Глубокая проверка Unicode-стеганографии (Tags U+E00xx, Bidi, Homoglyphs) и декодированных слоёв
    uni_check = inspect_unicode_and_encoding(f'{target}\n{payload}')
    expanded_for_scan = combined + ('\n' + '\n'.join(uni_check.get('decoded_layers') or []) if uni_check.get('decoded_layers') else '')
    # Маскируем секреты ДО сохранения/отображения в аудите
    masked_combined, sec_counts = safety.redact(combined)
    has_secrets = bool(sec_counts)
    masked_target, _ = safety.redact(raw_target)
    payload_sha256 = hashlib.sha256(combined.encode("utf-8", "replace")).hexdigest()

    reasons: list[dict[str, str]] = []
    risk_level = "low"
    hard_block = False

    if is_lockdown_active(memory) and origin != "user":
        hard_block = True
        risk_level = "critical"
        reasons.append({
            "code": "kill_switch_active",
            "severity": "critical",
            "detail": "Активен Kill Switch (режим жёсткой блокировки) — исходящие действия агента остановлены.",
        })

    if has_secrets:
        hard_block = True
        risk_level = "critical"
        reasons.append({
            "code": "secret_exfiltration_blocked",
            "severity": "critical",
            "detail": f"Обнаружены незамаскированные секреты ({', '.join(sorted(sec_counts))}) в исходящей нагрузке.",
        })

    # Проверка URL (включая SSRF, небезопасные схемы, Punycode, новые внешние домены)
    allow_rows = list_allowlist(memory)
    allowed_domains = {r["value"].lower() for r in allow_rows if r["entry_type"] == "domain"}
    allowed_wallets = {r["value"] for r in allow_rows if r["entry_type"] in ("wallet", "iban", "payee")}
    allowed_wallets_low = {w.lower() for w in allowed_wallets}

    for uf in uni_check.get('findings') or []:
        if uf['severity'] == 'critical':
            hard_block = True
            risk_level = 'critical'
        elif risk_level in ('low', 'medium'):
            risk_level = 'high'
        reasons.append(uf)

    urls = _URL_RE.findall(expanded_for_scan)
    # Также проверим target, если выглядит как домен/URL без схемы при сетевых действиях
    if raw_target and "://" not in raw_target and re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/.*)?", raw_target):
        urls.append("https://" + raw_target)

    for u in urls[:15]:
        low_u = u.lower()
        if low_u.startswith(("javascript:", "data:", "file:")):
            hard_block = True
            risk_level = "critical"
            reasons.append({
                "code": "dangerous_url_scheme",
                "severity": "critical",
                "detail": f"Запрещённая схема URL: {u[:60]}",
            })
            continue
        try:
            net_guard.validate_outbound_url(
                u, allow_localhost=False, allow_http_localhost=False, require_https=False
            )
        except Exception as exc:
            hard_block = True
            risk_level = "critical"
            reasons.append({
                "code": "ssrf_or_unsafe_url",
                "severity": "critical",
                "detail": f"URL отклонён сетевым фильтром: {str(exc)[:140]}",
            })
            continue

        host = urllib.parse.urlsplit(u).netloc.lower().split(":")[0]
        if host.startswith("xn--") or ".xn--" in host:
            risk_level = "high" if risk_level != "critical" else risk_level
            reasons.append({
                "code": "punycode_homograph_domain",
                "severity": "high",
                "detail": f"Домен содержит Punycode (xn--), возможна подмена (homograph): {host}",
            })
        if host in _SHORTENER_HOSTS:
            risk_level = "high" if risk_level != "critical" else risk_level
            reasons.append({
                "code": "url_shortener_detected",
                "severity": "high",
                "detail": f"Обнаружен сокращатель ссылок ({host}), скрывающий конечную цель.",
            })
        if not _domain_allowed(host, allowed_domains):
            typo_match = next((d for d in allowed_domains if abs(len(host) - len(d)) <= 2 and 1 <= _levenshtein(host, d) <= 2), None)
            if typo_match:
                hard_block = True
                risk_level = 'critical'
                reasons.append({
                    'code': 'domain_typosquatting',
                    'severity': 'critical',
                    'detail': f'Подозрение на Typosquatting: {host} отличается на 1-2 символа от доверенного {typo_match}!',
                })
            else:
                prof = str(_default_state(memory).get('policy_profile') or 'balanced')
                if prof == 'paranoid_airgap':
                    hard_block = True
                    risk_level = 'critical'
                elif risk_level == "low":
                    risk_level = "medium"
                reasons.append({
                    "code": "new_external_domain",
                    "severity": "critical" if prof == 'paranoid_airgap' else "medium",
                    "detail": f"Новый внешний домен ({host}) не входит в доверенный список владельца.",
                })

    # Проверка кошельков / реквизитов и Payee-Swap
    indicators = _extract_payment_indicators(combined)
    swap_phrase = bool(_PAYEE_SWAP_PHRASE_RE.search(combined))
    for ind in indicators:
        val = ind["value"]
        if val in allowed_wallets or val.lower() in allowed_wallets_low:
            continue
        if allowed_wallets or swap_phrase or ind["kind"] == "card":
            risk_level = "critical"
            reasons.append({
                "code": "payee_swap_or_untrusted_wallet",
                "severity": "critical",
                "detail": (
                    f"Обнаружен новый/подменённый платёжный реквизит ({ind['kind']}: {val[:14]}…), "
                    "отсутствующий в списке доверенных адресов владельца!"
                ),
            })
        else:
            if risk_level in ("low", "medium"):
                risk_level = "high"
            reasons.append({
                "code": "unknown_payee_requires_approval",
                "severity": "high",
                "detail": f"Платёжный реквизит ({ind['kind']}: {val[:14]}…) требует подтверждения владельца.",
            })

    # Поиск высокоэнтропийных неизвестных токенов (>= 28 симв., H >= 4.25), не попавших под словари форматов
    if not has_secrets:
        for cand_tok in re.findall(r'(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{28,80}(?![A-Za-z0-9_+/=-])', raw_payload):
            if any(c.isdigit() for c in cand_tok) and any(c.islower() for c in cand_tok) and any(c.isupper() for c in cand_tok):
                if _shannon_entropy(cand_tok) >= 4.25 and cand_tok not in raw_target:
                    hard_block = True
                    risk_level = 'critical'
                    reasons.append({
                        'code': 'high_entropy_token_exfiltration',
                        'severity': 'critical',
                        'detail': 'Обнаружен случайный высокоэнтропийный секрет/ключ в исходящем сообщении.',
                    })
                    break

    # Послойная деобфускация (до 4 уровней Base64/Hex/URL/NFKC) + Canary Honeypots
    canary_hits = solana_crypto_shield.scan_canaries_in_payload(memory, combined)
    if canary_hits:
        hard_block = True
        risk_level = "critical"
        reasons.append({
            "code": "canary_honeypot_exfiltration",
            "severity": "critical",
            "detail": f"Сработала ловушка Canary Honeypot ({canary_hits[0]['label']}): перехвачена попытка слива защищённого контекста!",
        })
        trip_kill_switch(
            memory,
            reason=f"Canary honeypot leak ({canary_hits[0]['canary_id']})",
            agent_id=clean_agent,
            block_writes=True,
        )

    decoded_layers = solana_crypto_shield.deobfuscate_layers(combined, max_layers=4)
    deep_blob = "\n".join(decoded_layers[:8])

    # Декодер смарт-контрактов EVM ABI / Solana (Кольцо 3)
    try:
        from .shield import web3_abi as _w3
        w3_res = _w3.scan_text_for_web3_tx(deep_blob, allowed_wallets=allowed_wallets)
        for wf in (w3_res.get("findings") or []):
            if wf["severity"] == "critical":
                hard_block = True
                risk_level = "critical"
            elif risk_level in ("low", "medium"):
                risk_level = "high"
            reasons.append(wf)
    except Exception:
        pass

    # Проверка shell/exfil/инструкций (на сыром И деобфусцированном потоке + локальный ONNX семантический слой!)
    if _DANGEROUS_SHELL_RE.search(deep_blob):
        hard_block = True
        risk_level = "critical"
        reasons.append({
            "code": "dangerous_shell_command",
            "severity": "critical",
            "detail": "Обнаружена опасная системная/эксфильтрационная команда (curl|sh, encoded powershell или обфусцированный шелл).",
        })
    elif safety.looks_like_instruction(deep_blob) or safety.changes_owner_or_rules(deep_blob):
        if risk_level != "critical":
            risk_level = "high"
        reasons.append({
            "code": "injection_or_rule_tamper_in_outbound",
            "severity": "high",
            "detail": "Исходящий текст (или скрытый слой) содержит шаблон инъекции, подмены правил или перенаправления платежа.",
        })
    else:
        try:
            from .shield import semantic as _sem, sigdb as _sigdb
            extra_sigs = _sigdb.get_active_sigdb(memory).get("jailbreak_signatures") or []
            sem_res = _sem.classify_semantic_threat(deep_blob, extra_signatures=extra_sigs)
            if sem_res.get("is_threat"):
                if risk_level != "critical":
                    risk_level = "high"
                reasons.append({
                    "code": "semantic_ml_injection_detected",
                    "severity": "high",
                    "detail": (
                        f"Локальный семантический классификатор ({sem_res.get('backend')}) "
                        f"выявил смысловую атаку (score={sem_res.get('score')}, {sem_res.get('latency_ms')} ms)."
                    ),
                })
        except Exception:
            pass

    # Проверка режима Shadow-аудита (padam learn --mode shadow)
    shadow_mode = False
    try:
        from .shield import learn_ueba as _lu
        shadow_mode = (_lu.get_shield_mode(memory) == "shadow")
    except Exception:
        shadow_mode = False

    if not reasons:
        status = "allowed"
        allowed = True
    elif shadow_mode and not is_lockdown_active(memory):
        would = "blocked" if hard_block else "pending_approval"
        try:
            from .shield import learn_ueba as _lu
            _lu.record_shadow_event(
                memory,
                agent_id=clean_agent,
                action_type=act_type,
                target=raw_target or combined[:120],
                would_status=would,
                risk_level=risk_level,
                reasons=reasons,
            )
        except Exception:
            pass
        status = "shadow_logged"
        allowed = True
    elif hard_block:
        status = "blocked"
        allowed = False
    else:
        status = "pending_approval"
        allowed = False

    gate_id = f"gate-{uuid.uuid4().hex[:12]}"
    now = _utc_iso()
    preview = safety.clean(masked_combined)[:280]
    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT INTO shield_outbound_queue
               (id, user_id, agent_id, action_type, target, payload_hash, preview, risk_level,
                reasons_json, status, created_at, decided_at, decided_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
            (
                gate_id, memory.user_id, clean_agent, act_type, safety.clean(masked_target)[:160],
                payload_sha256, preview, risk_level,
                json.dumps(reasons, ensure_ascii=False), status, now,
            ),
        )
        memory.store.conn.commit()

    try:
        audit_chain.append_audit(
            memory,
            f"outbound_gate_{status}",
            {"gate_id": gate_id, "action_type": act_type, "risk": risk_level, "codes": [r["code"] for r in reasons]},
            agent_id=clean_agent,
        )
    except Exception:
        pass

    # Критические нарушения в гейте повышают скользящий счётчик Kill Switch
    if has_secrets:
        record_anomaly(
            memory, event_type="outbound_secret_exfiltration", severity="critical", weight=4,
            agent_id=clean_agent, detail=f"action={act_type}",
        )
    elif any(r["code"] in ("payee_swap_or_untrusted_wallet", "dangerous_shell_command", "ssrf_or_unsafe_url") for r in reasons):
        record_anomaly(
            memory, event_type=reasons[0]["code"], severity="critical", weight=3,
            agent_id=clean_agent, detail=f"action={act_type}",
        )

    if not allowed and risk_level in ('high', 'critical'):
        try:
            from . import siem_webhook as _sw
            _sw.dispatch_webhook_event(
                memory,
                event_type=f'outbound_{status}',
                severity=risk_level,
                title=f'Outbound {status.upper()}: {act_type}',
                detail='; '.join(r.get('detail', '') for r in reasons[:3]),
                agent_id=clean_agent,
                extra={'gate_id': gate_id, 'risk_level': risk_level},
            )
        except Exception:
            pass
    return {
        "gate_id": gate_id,
        "allowed": allowed,
        "status": status,
        "action_type": act_type,
        "risk_level": risk_level,
        "reasons": reasons,
        "payload_sha256": payload_sha256,
        "requires_owner_approval": status == "pending_approval",
    }


def list_outbound_queue(memory: Any, *, status: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
    _ensure_tables(memory)
    sql = "SELECT * FROM shield_outbound_queue WHERE user_id = ? "
    params: list[Any] = [memory.user_id]
    if status:
        sql += "AND status = ? "
        params.append(str(status).strip())
    sql += "ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, min(100, int(limit))))
    out: list[dict[str, Any]] = []
    for r in memory.store.query(sql, tuple(params)):
        d = dict(r)
        try:
            d["reasons"] = json.loads(d.pop("reasons_json") or "[]")
        except Exception:
            d["reasons"] = []
        out.append(d)
    return out


def decide_outbound(
    memory: Any,
    gate_id: str,
    *,
    decision: str,
    add_to_allowlist: bool = False,
    actor: Any = None,
) -> dict[str, Any]:
    """Одобряет или отклоняет задержанное исходящее действие. Строго только владелец."""
    roles.require_owner(actor, "agentic_shield_outbound_decide")
    _ensure_tables(memory)
    dec = str(decision or "").strip().lower()
    if dec not in ("approve", "reject"):
        raise ValueError(f"Unsupported decision: {decision!r}")
    new_status = "approved" if dec == "approve" else "rejected"
    now = _utc_iso()
    with memory.store._lock:
        row = memory.store.one(
            "SELECT * FROM shield_outbound_queue WHERE user_id = ? AND id = ?",
            (memory.user_id, str(gate_id or "").strip()),
        )
        if row is None:
            raise ValueError(f"Outbound gate item not found: {gate_id!r}")
        if row["status"] != "pending_approval":
            raise ValueError(f"Outbound item {gate_id!r} already finalized: {row['status']}")
        memory.store.conn.execute(
            "UPDATE shield_outbound_queue SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND user_id = ?",
            (new_status, now, "owner", row["id"], memory.user_id),
        )
        memory.store.conn.commit()
        updated = dict(memory.store.one("SELECT * FROM shield_outbound_queue WHERE id = ?", (row["id"],)))

    if dec == "approve" and add_to_allowlist and row["target"]:
        tgt = str(row["target"]).strip()
        if "://" in tgt or re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", tgt):
            host = urllib.parse.urlsplit(tgt if "://" in tgt else "https://" + tgt).netloc.split(":")[0]
            if host:
                add_allowlist_entry(memory, entry_type="domain", value=host, label=f"approved via {gate_id}", actor=actor)
        elif _EVM_ADDR_RE.fullmatch(tgt) or _BTC_BECH32_RE.fullmatch(tgt) or _TRON_ADDR_RE.fullmatch(tgt) or _SOL_CAND_RE.fullmatch(tgt):
            add_allowlist_entry(memory, entry_type="wallet", value=tgt, label=f"approved via {gate_id}", actor=actor)
    elif dec == "reject":
        record_anomaly(
            memory,
            event_type="owner_rejected_outbound",
            severity="high",
            weight=3,
            agent_id=str(row["agent_id"] or "agent"),
            detail=f"rejected {row['action_type']} gate_id={gate_id}",
        )

    try:
        audit_chain.append_audit(
            memory, f"outbound_gate_owner_{new_status}", {"gate_id": gate_id, "target": row["target"]}, agent_id="owner"
        )
    except Exception:
        pass
    try:
        updated["reasons"] = json.loads(updated.pop("reasons_json") or "[]")
    except Exception:
        updated["reasons"] = []
    return updated


# ==================== 3. СТАТУС ЩИТА И PROOF PACK ДЛЯ CISO ====================

def get_shield_status(memory: Any) -> dict[str, Any]:
    """Возвращает полный срез состояния PADAM Agentic Shield."""
    st = _default_state(memory)
    recent_events = [
        dict(r) for r in memory.store.query(
            "SELECT id, agent_id, event_type, severity, weight, detail, created_at "
            "FROM shield_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 15",
            (memory.user_id,),
        )
    ]
    since = (datetime.now(timezone.utc) - timedelta(seconds=int(st["window_s"] or 60))).isoformat(timespec="seconds")
    w_row = memory.store.one(
        "SELECT COALESCE(SUM(weight), 0) AS s FROM shield_events WHERE user_id = ? AND created_at >= ?",
        (memory.user_id, since),
    )
    current_score = int(w_row["s"] or 0) if w_row else 0
    outbound_pending = list_outbound_queue(memory, status="pending_approval", limit=30)
    outbound_recent = list_outbound_queue(memory, limit=20)
    allowlist = list_allowlist(memory)
    recent_scans = supply_chain_guard.list_recent_supply_scans(memory, limit=10)
    ext_meta: dict[str, Any] = {
        "shield_mode": "enforce",
        "semantic_engine": {},
        "taint_steps": 0,
        "taint_blocks": 0,
        "ueba_profiles_count": 0,
        "sigdb_version": 0,
        "a2a_agents_count": 0,
    }
    try:
        from .shield import (
            a2a_trust as _a2a,
            learn_ueba as _lu,
            semantic as _sem,
            sigdb as _sdb,
            taint as _tnt,
        )
        ext_meta["shield_mode"] = _lu.get_shield_mode(memory)
        ext_meta["semantic_engine"] = _sem.semantic_engine_status()
        tg = _tnt.get_session_graph(memory, limit=30)
        ext_meta["taint_steps"] = tg["total_steps"]
        ext_meta["taint_blocks"] = tg["blocked_steps"]
        ext_meta["ueba_profiles_count"] = len(_lu.list_ueba_profiles(memory, limit=50))
        ext_meta["sigdb_version"] = _sdb.get_active_sigdb(memory)["version"]
        ext_meta["a2a_agents_count"] = len(_a2a.list_a2a_trust_scores(memory))
    except Exception:
        pass

    return {
        "ok": True,
        "lockdown": bool(st["lockdown"]) or bool(config.STRICT),
        "db_lockdown": bool(st["lockdown"]),
        "policy_profile": str(st.get("policy_profile") or "balanced"),
        "shield_mode": ext_meta["shield_mode"],
        "semantic_engine": ext_meta["semantic_engine"],
        "taint_steps": ext_meta["taint_steps"],
        "taint_blocks": ext_meta["taint_blocks"],
        "ueba_profiles_count": ext_meta["ueba_profiles_count"],
        "sigdb_version": ext_meta["sigdb_version"],
        "a2a_agents_count": ext_meta["a2a_agents_count"],
        "mcp_pins_count": int(memory.store.one("SELECT COUNT(*) FROM shield_mcp_tool_pins WHERE user_id = ?", (memory.user_id,))[0]),
        "config_strict": bool(config.STRICT),
        "block_writes": bool(st["block_writes"]),
        "auto_kill_enabled": bool(st["auto_kill_enabled"]),
        "window_s": int(st["window_s"]),
        "threshold": int(st["threshold"]),
        "current_anomaly_score": current_score,
        "tripped_at": st.get("tripped_at"),
        "tripped_reason": st.get("tripped_reason"),
        "tripped_agent": st.get("tripped_agent"),
        "tripped_count": int(st.get("tripped_count") or 0),
        "pending_outbound_count": len(outbound_pending),
        "outbound_pending": outbound_pending,
        "outbound_recent": outbound_recent,
        "allowlist_count": len(allowlist),
        "allowlist": allowlist,
        "recent_events": recent_events,
        "recent_supply_scans": recent_scans,
        "webhook": __import__("padam.siem_webhook", fromlist=["get_webhook_config"]).get_webhook_config(memory),
    }


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_proof_pack(
    memory: Any,
    *,
    include_redteam: bool = True,
    include_benchmark: bool = True,
) -> dict[str, Any]:
    """Собирает подписанный Compliance & Threat Proof Pack для аудитора / CISO."""
    st = get_shield_status(memory)
    att = defense_stats.attack_stats(memory)
    chain_ark = audit_chain.verify_audit_chain(memory)
    chain_log = audit_chain.verify_audit_log_chain(memory)
    rt = redteam_rounds.list_rounds() if include_redteam else {"rounds": []}
    bench = aifa_sec_bridge.get_aifa_security_report(run_fresh=False) if include_benchmark else {}

    bench_summary = {
        "benchmark": bench.get("benchmark", "AIFaSecurity/1.0"),
        "grade": bench.get("grade"),
        "score_pct": bench.get("score_pct"),
        "passed": bench.get("passed"),
        "applicable": bench.get("applicable"),
        "report_sha256": bench.get("report_sha256"),
        "generated_at": bench.get("generated_at"),
        "honest_note": bench.get("honest_note"),
    }

    body: dict[str, Any] = {
        "schema": "padam-agentic-shield-proof-pack/1.0",
        "generated_at": _utc_iso(),
        "user_id": memory.user_id,
        "runtime_strict": bool(st["lockdown"]),
        "shield_status": {
            "lockdown": st["lockdown"],
            "auto_kill_enabled": st["auto_kill_enabled"],
            "block_writes": st["block_writes"],
            "window_s": st["window_s"],
            "threshold": st["threshold"],
            "current_anomaly_score": st["current_anomaly_score"],
            "tripped_count": st["tripped_count"],
            "pending_outbound_count": st["pending_outbound_count"],
            "allowlist_count": st["allowlist_count"],
        },
        "attack_radar": att,
        "audit_integrity": {
            "ark_audit_chain": chain_ark,
            "audit_log_chain": chain_log,
        },
        "aifa_security_100": bench_summary,
        "redteam_sealed_rounds": [
            {"id": r.get("id"), "date": r.get("date"), "title": r.get("title"), "sums": r.get("sums")}
            for r in (rt.get("rounds") or [])
        ],
        "supply_chain_scans_recent": [
            {"id": sc.get("id"), "url": sc.get("url"), "grade": sc.get("grade"), "score": sc.get("score"), "at": sc.get("created_at")}
            for sc in (st.get("recent_supply_scans") or [])[:5]
        ],
        "owasp_agentic_ai_matrix": list(OWASP_AGENTIC_MATRIX),
        "public_evidence_docs": [
            "docs/SECURITY_REVIEW.md",
            "docs/FENCING_SPEC.md",
            "SECURITY.md",
            "redteam/rounds/",
        ],
    }

    sol_att = solana_crypto_shield.sign_solana_shield_attestation(
        memory,
        summary_items=[
            {"section": "shield_status", "data": body["shield_status"]},
            {"section": "attack_radar", "data": att},
            {"section": "audit_integrity", "data": body["audit_integrity"]},
            {"section": "aifa_security_100", "data": bench_summary},
        ],
    )
    body["solana_crypto_attestation"] = sol_att

    canonical = _canonical_json(body).encode("utf-8")
    pack_sha256 = hashlib.sha256(canonical).hexdigest()
    key, _ = integrity.owner_key(memory.store)
    owner_hmac = hmac.new(key, pack_sha256.encode("ascii"), hashlib.sha256).hexdigest()

    pack = {
        **body,
        "attestation": {
            "pack_sha256": pack_sha256,
            "owner_hmac_sha256": owner_hmac,
            "solana_signer_pubkey": sol_att["signer_pubkey"],
            "solana_memo": sol_att["memo"],
            "solana_ed25519_sig_b64": sol_att["signature_b64"],
            "merkle_root_hex": sol_att["merkle_root_hex"],
            "algorithm": "SHA-256 + HMAC-SHA256 + Ed25519(Solana) + Merkle",
        },
    }
    return pack


def verify_proof_pack(pack: dict[str, Any], *, memory: Any = None) -> dict[str, Any]:
    """Проверяет SHA-256 и (при наличии memory) HMAC-подпись владельца для Proof Pack."""
    att = dict(pack.get("attestation") or {})
    claimed_sha = str(att.get("pack_sha256") or "")
    claimed_hmac = str(att.get("owner_hmac_sha256") or "")
    body = {k: v for k, v in pack.items() if k != "attestation"}
    recomputed_sha = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
    sha_ok = bool(claimed_sha) and hmac.compare_digest(claimed_sha, recomputed_sha)
    hmac_ok: bool | None = None
    if memory is not None:
        key, _ = integrity.owner_key(memory.store)
        expected_hmac = hmac.new(key, recomputed_sha.encode("ascii"), hashlib.sha256).hexdigest()
        hmac_ok = hmac.compare_digest(expected_hmac, claimed_hmac)
    verified = sha_ok and (hmac_ok is not False)
    return {
        "verified": verified,
        "sha256_valid": sha_ok,
        "hmac_valid": hmac_ok,
        "pack_sha256": recomputed_sha,
    }


def render_proof_pack_markdown(pack: dict[str, Any]) -> str:
    """Формирует читаемый Markdown-отчёт из Compliance & Threat Proof Pack."""
    att = pack.get("attestation") or {}
    radar = pack.get("attack_radar") or {}
    bench = pack.get("aifa_security_100") or {}
    chain = (pack.get("audit_integrity") or {}).get("ark_audit_chain") or {}
    lines = [
        "# PADAM Agentic Shield — Compliance & Threat Proof Pack",
        "",
        f"- **Generated (UTC):** `{pack.get('generated_at')}`",
        f"- **Pack SHA-256:** `{att.get('pack_sha256')}`",
        f"- **Runtime Strict / Kill Switch Active:** `{pack.get('runtime_strict')}`",
        f"- **Audit Hash-Chain Verified:** `{chain.get('ok')}` (entries: `{chain.get('length', 0)}`)",
        f"- **Attacks Quarantined Total:** `{radar.get('held_total', 0)}` · **Secrets Masked:** `{radar.get('secrets_masked', 0)}`",
        f"- **AIFaSecurity-100:** Grade `{bench.get('grade', '—')}` (`{bench.get('passed', 0)}/{bench.get('applicable', 0)}` · `{bench.get('score_pct', 0)}%`)",
        "",
        "## OWASP Agentic AI Top 10 (ASI01–ASI10) Coverage",
        "",
        "| ID | Threat Category | Enforced Code Control | Status |",
        "|---|---|---|---|",
    ]
    for row in pack.get("owasp_agentic_ai_matrix") or []:
        lines.append(f"| `{row['id']}` | {row['name']} | {row['control']} | **{row['status']}** |")
    lines.extend(["", "## Sealed Red-Team Rounds", ""])
    for r in pack.get("redteam_sealed_rounds") or []:
        lines.append(f"- **{r.get('date')}** — {r.get('title')}")
    return "\n".join(lines) + "\n"


def render_proof_pack_html(pack: dict[str, Any]) -> str:
    """Формирует автономный печатный HTML-документ Proof Pack (со строгим XSS-экранированием)."""
    att = pack.get("attestation") or {}
    radar = pack.get("attack_radar") or {}
    bench = pack.get("aifa_security_100") or {}
    chain = (pack.get("audit_integrity") or {}).get("ark_audit_chain") or {}
    sh = pack.get("shield_status") or {}

    owasp_rows = "".join(
        "<tr>"
        f"<td><code>{_html.escape(r['id'])}</code></td>"
        f"<td>{_html.escape(r['name'])}</td>"
        f"<td>{_html.escape(r['control'])}</td>"
        f"<td><b>{_html.escape(r['status'].upper())}</b></td>"
        "</tr>"
        for r in (pack.get("owasp_agentic_ai_matrix") or [])
    )
    rt_rows = "".join(
        f"<li><b>{_html.escape(str(r.get('date', '')))}</b> — {_html.escape(str(r.get('title', '')))}</li>"
        for r in (pack.get("redteam_sealed_rounds") or [])
    )

    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<title>PADAM Agentic Shield — Compliance &amp; Threat Proof Pack</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:980px;margin:28px auto;padding:0 16px;color:#0f172a;line-height:1.5}"
        "h1,h2{margin-top:22px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin:14px 0}"
        ".card{border:1px solid #cbd5e1;border-radius:8px;padding:12px;background:#f8fafc}"
        ".val{font-size:20px;font-weight:700}table{width:100%;border-collapse:collapse;margin-top:10px}"
        "th,td{border:1px solid #cbd5e1;padding:8px;text-align:left;font-size:13px}th{background:#f1f5f9}"
        "code{background:#f1f5f9;padding:2px 5px;border-radius:4px;font-size:12px;overflow-wrap:anywhere}</style>"
        "</head><body>"
        "<h1>PADAM Agentic Shield — Compliance &amp; Threat Proof Pack</h1>"
        f"<p><b>Generated (UTC):</b> {_html.escape(str(pack.get('generated_at', '')))} &nbsp;|&nbsp; "
        f"<b>Pack SHA-256:</b> <code>{_html.escape(str(att.get('pack_sha256', '')))}</code></p>"
        "<div class='grid'>"
        f"<div class='card'><div class='val'>{int(radar.get('held_total', 0))}</div><div>Attacks Held</div></div>"
        f"<div class='card'><div class='val'>{int(radar.get('secrets_masked', 0))}</div><div>Secrets Masked (DLP)</div></div>"
        f"<div class='card'><div class='val'>{'LOCKDOWN' if sh.get('lockdown') else 'ARMED'}</div><div>Machine-Speed Kill Switch</div></div>"
        f"<div class='card'><div class='val'>{'VERIFIED' if chain.get('ok') else 'CHECK'}</div><div>SHA-256 Audit Chain ({int(chain.get('length', 0))})</div></div>"
        f"<div class='card'><div class='val'>{_html.escape(str(bench.get('grade') or '—'))} ({_html.escape(str(bench.get('score_pct') or '—'))}%)</div><div>AIFaSecurity-100</div></div>"
        "</div>"
        "<h2>OWASP Agentic AI Top 10 (ASI01–ASI10) Control Mapping</h2>"
        f"<table><thead><tr><th>ID</th><th>Risk</th><th>Enforced Control</th><th>Status</th></tr></thead><tbody>{owasp_rows}</tbody></table>"
        "<h2>Public Sealed Red-Team Rounds</h2>"
        f"<ul>{rt_rows or '<li>See docs/SECURITY_REVIEW.md</li>'}</ul>"
        "<hr><p><small>Signed locally with SHA-256 + Owner HMAC-SHA256. Zero secrets or raw attack payloads exported.</small></p>"
        "</body></html>"
    )


# ==================== РАСШИРЕННАЯ ЗАЩИТА (20.11.2026) ====================

_OUTPUT_PROMPT_LEAK_RE = re.compile(
    r"(?is)("
    r"\bSYSTEM[_\s]+PROMPT\b|"
    r"\bCONSTITUTION\s+OF\s+THE\s+ECOSYSTEM\b|"
    r"-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP|PRIVATE)\s+KEY-----|"
    r"\bYou\s+are\s+instructed\s+to\s+never\s+reveal|"
    r"\bignore\s+previous\s+instructions\b|"
    r"\bBRAIN_MASTER_KEY\b|\bSTRIPE_SECRET_KEY\b|\bDATABASE_URL\b"
    r")"
)
_SCRIPT_TAG_RE = re.compile(r"(?is)<\s*(script|foreignObject|iframe|object|embed|applet|meta|base)\b[^>]*>.*?</\s*\1\s*>")
_SELF_CLOSING_BAD_RE = re.compile(r"(?is)<\s*(script|foreignObject|iframe|object|embed|applet|meta|base)\b[^>]*?/?>")
_EVENT_HANDLER_RE = re.compile(r"(?is)\s+on[a-z0-9_]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)")
_JS_URI_RE = re.compile(r"(?is)(href|xlink:href|src|action|formaction)\s*=\s*([\"'])\s*(?:javascript|vbscript|data\s*:\s*text/html)[^\"']*\2")


def sanitize_untrusted_markup(markup: str) -> dict[str, Any]:
    """Жёстко вырезает XSS-векторы из SVG/HTML артефактов (script, foreignObject, on*=, javascript:)."""
    txt = str(markup or "")
    stripped = 0
    for rx in (_SCRIPT_TAG_RE, _SELF_CLOSING_BAD_RE, _EVENT_HANDLER_RE):
        txt, n = rx.subn("", txt)
        stripped += n
    txt, n_uri = _JS_URI_RE.subn(r"\1=\2#blocked\2", txt)
    stripped += n_uri
    return {"clean": txt, "stripped_count": stripped, "had_xss": stripped > 0}


def inspect_model_output(
    memory: Any,
    text: str,
    *,
    agent_id: str = "aifa",
    system_prompt_hints: list[str] | None = None,
) -> dict[str, Any]:
    """Output Firewall: ловит утечку системного промпта, секретов, PII и canary-ловушек до выдачи наружу."""
    raw = str(text or "")
    redacted, sec_hits = safety.redact(raw)
    reasons: list[str] = []
    if sec_hits:
        reasons.append(f"secrets_redacted:{len(sec_hits)}")
    if _OUTPUT_PROMPT_LEAK_RE.search(raw):
        reasons.append("system_prompt_or_key_leak")
        redacted = _OUTPUT_PROMPT_LEAK_RE.sub("[REDACTED_SYSTEM_BOUNDARY]", redacted)
    for hint in (system_prompt_hints or []):
        h = str(hint or "").strip()
        if len(h) >= 20 and h.lower() in raw.lower():
            reasons.append("system_prompt_verbatim_leak")
            redacted = re.sub(re.escape(h), "[REDACTED_PROMPT_FRAGMENT]", redacted, flags=re.I)

    canary_hits: list[str] = []
    if memory is not None:
        try:
            from . import solana_crypto_shield
            hits = solana_crypto_shield.scan_canaries_in_payload(memory, raw)
            if hits:
                canary_hits = [str(h.get("canary_id") or "") for h in hits]
                reasons.append("canary_honeypot_exfiltration")
                for h in hits:
                    tok = str(h.get("token") or "")
                    if tok:
                        redacted = redacted.replace(tok, "[CANARY_BLOCKED]")
                trip_kill_switch(
                    memory,
                    reason=f"Output Firewall canary leak ({canary_hits[0]})",
                    agent_id=agent_id,
                    block_writes=True,
                )
        except Exception:
            pass

    pii_findings: list[dict[str, str]] = []
    sast_findings: list[dict[str, str]] = []
    try:
        from .shield import output_rag as _orag
        og = _orag.inspect_output_guardrails(redacted, memory=None, agent_id=agent_id)
        pii_findings = list(og.get("pii_findings") or [])
        sast_findings = list(og.get("sast_findings") or [])
        if pii_findings:
            redacted = str(og.get("sanitized_text") or redacted)
            reasons.extend([f["code"] for f in pii_findings])
        if sast_findings:
            reasons.extend([f["code"] for f in sast_findings])
    except Exception:
        pass

    if reasons and memory is not None:
        record_anomaly(
            memory,
            event_type="output_firewall_block" if canary_hits or "system_prompt" in "".join(reasons) else "output_firewall_redact",
            severity="critical" if canary_hits else "high",
            weight=4 if canary_hits else 2,
            agent_id=agent_id,
            detail="; ".join(reasons)[:200],
        )

    critical_sast = any(f.get("severity") == "critical" for f in sast_findings)
    blocked = bool(canary_hits) or critical_sast or any("system_prompt" in r for r in reasons)
    return {
        "ok": True,
        "action": "block" if blocked else ("redact" if reasons else "allow"),
        "blocked": blocked,
        "sanitized_text": "[BLOCKED BY PADAM OUTPUT FIREWALL: canary/system/sast leak detected]" if (canary_hits or critical_sast) else redacted,
        "reasons": reasons,
        "secrets_masked_count": len(sec_hits),
        "canary_hits": canary_hits,
        "pii_findings": pii_findings,
        "sast_findings": sast_findings,
    }


def verify_signed_timestamp_nonce(
    memory: Any,
    *,
    secret_key: bytes,
    ts_value: str | float | int,
    nonce: str,
    sig_hex: str,
    payload_str: str = "",
    window_seconds: int = 300,
) -> dict[str, Any]:
    """HMAC-SHA256 Anti-Replay защита для меж-агентных и webhook-запросов (окно ±300с + одноразовый nonce)."""
    now_ts = time.time()
    try:
        if isinstance(ts_value, (int, float)):
            req_ts = float(ts_value)
        else:
            s = str(ts_value).strip()
            req_ts = float(s) if re.fullmatch(r"\d+(?:\.\d+)?", s) else datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return {"ok": False, "reason": "invalid_timestamp"}

    if abs(now_ts - req_ts) > max(10, int(window_seconds)):
        return {"ok": False, "reason": "timestamp_outside_window"}

    clean_nonce = re.sub(r"[^a-zA-Z0-9_.-]+", "", str(nonce or ""))[:96]
    if len(clean_nonce) < 8:
        return {"ok": False, "reason": "weak_or_missing_nonce"}

    msg = f"padam-ts-v1|{ts_value}|{clean_nonce}|{payload_str}".encode("utf-8")
    expected = hmac.new(secret_key, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(sig_hex or "").strip().lower()):
        return {"ok": False, "reason": "hmac_signature_mismatch"}

    if memory is not None:
        with memory.store._lock:
            conn = memory.store.conn
            conn.execute(
                "CREATE TABLE IF NOT EXISTS shield_replay_nonces ("
                "nonce TEXT PRIMARY KEY, expires_at REAL NOT NULL, created_at TEXT NOT NULL)"
            )
            conn.execute("DELETE FROM shield_replay_nonces WHERE expires_at < ?", (now_ts,))
            exists = conn.execute("SELECT 1 FROM shield_replay_nonces WHERE nonce = ?", (clean_nonce,)).fetchone()
            if exists:
                conn.commit()
                return {"ok": False, "reason": "replay_nonce_detected"}
            conn.execute(
                "INSERT INTO shield_replay_nonces (nonce, expires_at, created_at) VALUES (?, ?, ?)",
                (clean_nonce, now_ts + max(60, int(window_seconds) * 2), _utc_iso()),
            )
            conn.commit()

    return {"ok": True, "nonce": clean_nonce, "skew_seconds": round(abs(now_ts - req_ts), 3)}


def check_agent_budget_quota(
    memory: Any,
    *,
    agent_id: str,
    chars: int = 0,
    calls: int = 1,
    max_calls_per_min: int = 60,
    max_chars_per_min: int = 200_000,
) -> dict[str, Any]:
    """Circuit-breaker бюджета вызовов и объёма на одного агента (защита от зацикливания ASI08 / DoW)."""
    _ensure_tables(memory)
    aid = str(agent_id or "unknown").strip()[:64]
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(seconds=60)).isoformat()
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            "CREATE TABLE IF NOT EXISTS shield_agent_budget ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, agent_id TEXT NOT NULL, "
            "calls INTEGER NOT NULL, chars INTEGER NOT NULL, created_at TEXT NOT NULL)"
        )
        conn.execute("DELETE FROM shield_agent_budget WHERE user_id = ? AND created_at < ?", (memory.user_id, cutoff))
        agg = conn.execute(
            "SELECT COALESCE(SUM(calls),0) AS c, COALESCE(SUM(chars),0) AS ch FROM shield_agent_budget "
            "WHERE user_id = ? AND agent_id = ? AND created_at >= ?",
            (memory.user_id, aid, cutoff),
        ).fetchone()
        used_calls = int(agg["c"] or 0) + max(0, int(calls))
        used_chars = int(agg["ch"] or 0) + max(0, int(chars))
        exceeded = used_calls > int(max_calls_per_min) or used_chars > int(max_chars_per_min)
        if not exceeded:
            conn.execute(
                "INSERT INTO shield_agent_budget (user_id, agent_id, calls, chars, created_at) VALUES (?, ?, ?, ?, ?)",
                (memory.user_id, aid, max(0, int(calls)), max(0, int(chars)), now.isoformat()),
            )
        conn.commit()
    if exceeded:
        record_anomaly(
            memory,
            event_type="agent_budget_circuit_breaker",
            severity="high",
            weight=3,
            agent_id=aid,
            detail=f"calls={used_calls}/{max_calls_per_min}, chars={used_chars}/{max_chars_per_min}",
        )
    return {
        "ok": not exceeded,
        "allowed": not exceeded,
        "agent_id": aid,
        "used_calls_1m": used_calls,
        "limit_calls_1m": int(max_calls_per_min),
        "used_chars_1m": used_chars,
        "limit_chars_1m": int(max_chars_per_min),
    }
