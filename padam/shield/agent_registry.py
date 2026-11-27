# -*- coding: utf-8 -*-
"""Agent Discovery & Cryptographic Agent Identity Registry (PADAM Shield).

Закрывает два ключевых корпоративных пробела безопасности автономных ИИ-агентов:
1. **Local Agent & MCP Discovery (`discover_local_ai_agents`)**:
   100% локально (Zero-Telemetry) обнаруживает и инвентаризирует установленные ИИ-агенты,
   конфигурации MCP-серверов и файлы правил IDE (Claude Desktop, Claude Code, Cursor,
   Windsurf, Cline, Antigravity, `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
   `SKILL.md`, `mcp.json`, `mcp_config.json`) с первичной оценкой рисков.
2. **Cryptographic Agent Identity Registry (`register_agent_identity`, `verify_agent_identity_action`,
   `record_agent_delegation`, `revoke_agent_identity`, `list_registered_agents`)**:
   - У каждого агента есть собственный криптографический идентификатор на базе Ed25519
     (`did:padam:agent:<fingerprint>`), публичный ключ, владелец, ответственный оператор,
     белый список разрешённых инструментов, максимальные полномочия, лимит расходов (cents),
     срок действия разрешений (TTL), полная история делегирования и мгновенный отзыв доступа.
   - Все операции SQLite потокобезопасны (`store._lock`) и строго изолированы по `user_id`.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..store import add_column_safe
from .memory_rules_guard import inspect_memory_or_rule_text


_RULE_FILENAMES = (
    ".cursorrules",
    ".windsurfrules",
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    "SKILL.md",
    ".clinerules",
)

_MCP_CONFIG_NAMES = (
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
)


def _ensure_tables(memory: Any) -> None:
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_agent_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL DEFAULT '',
                agent_did TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                public_key_pem TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                operator TEXT NOT NULL DEFAULT '',
                allowed_tools_json TEXT NOT NULL DEFAULT '[]',
                max_privileges TEXT NOT NULL DEFAULT 'read_only',
                spend_limit_cents REAL NOT NULL DEFAULT 0.0,
                spent_cents REAL NOT NULL DEFAULT 0.0,
                expires_at REAL NOT NULL DEFAULT 0.0,
                revoked INTEGER NOT NULL DEFAULT 0,
                revoke_reason TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        add_column_safe(conn, "shield_agent_registry", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_reg_user_did ON shield_agent_registry(user_id, agent_did)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_agent_delegations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL DEFAULT '',
                from_agent_did TEXT NOT NULL,
                to_agent_did TEXT NOT NULL,
                tools_json TEXT NOT NULL,
                spend_cap_cents REAL NOT NULL DEFAULT 0.0,
                reason TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL
            )
            """
        )
        add_column_safe(conn, "shield_agent_delegations", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_del_user ON shield_agent_delegations(user_id, from_agent_did, to_agent_did)"
        )
        conn.commit()


def discover_local_ai_agents(
    *,
    project_dirs: Sequence[str | Path] = (),
    include_user_home: bool = True,
) -> Dict[str, Any]:
    """Локально обнаруживает ИИ-агентов, MCP-серверы и файлы правил IDE без сетевых запросов."""
    t0 = time.perf_counter()
    discovered_clients: List[Dict[str, Any]] = []
    discovered_mcp_servers: List[Dict[str, Any]] = []
    discovered_rule_files: List[Dict[str, Any]] = []
    seen_paths: set[str] = set()

    def _inspect_mcp_json(cfg_path: Path, client_label: str) -> None:
        norm_p = str(cfg_path.resolve())
        if norm_p in seen_paths or not cfg_path.is_file():
            return
        seen_paths.add(norm_p)
        servers_found = 0
        parse_ok = False
        try:
            data = json.loads(cfg_path.read_text("utf-8", errors="replace"))
            parse_ok = True
            srv_map = data.get("mcpServers") or data.get("mcp_servers") or data.get("servers") or {}
            if isinstance(srv_map, dict):
                for sname, scfg in srv_map.items():
                    servers_found += 1
                    cmd = str((scfg or {}).get("command") or (scfg or {}).get("url") or "")
                    args_l = list((scfg or {}).get("args") or []) if isinstance(scfg, dict) else []
                    env_d = (scfg or {}).get("env") if isinstance(scfg, dict) else {}
                    has_env_secrets = bool(isinstance(env_d, dict) and any(
                        any(k_tok in str(k).upper() for k_tok in ("KEY", "TOKEN", "SECRET", "PASS"))
                        for k in env_d.keys()
                    ))
                    wrapped = ("padam" in cmd.lower()) or any("padam" in str(a).lower() for a in args_l)
                    discovered_mcp_servers.append(
                        {
                            "client": client_label,
                            "server_name": str(sname),
                            "config_path": norm_p,
                            "transport": "http" if "://" in cmd else "stdio",
                            "shield_wrapped": wrapped,
                            "has_env_secrets": has_env_secrets,
                            "risk": "low" if wrapped else ("high" if has_env_secrets else "medium"),
                        }
                    )
        except Exception:
            parse_ok = False
        discovered_clients.append(
            {
                "client": client_label,
                "config_path": norm_p,
                "parse_ok": parse_ok,
                "mcp_servers_count": servers_found,
            }
        )

    # 1. Известные системные пути AI-клиентов текущего пользователя
    if include_user_home:
        home = Path.home()
        appdata = Path(os.environ.get("APPDATA", "")) if os.environ.get("APPDATA") else None
        candidates: List[tuple[str, Path]] = [
            ("claude_code", home / ".claude.json"),
            ("claude_code", home / ".claude" / "settings.json"),
            ("cursor", home / ".cursor" / "mcp.json"),
            ("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
            ("antigravity", home / ".gemini" / "antigravity" / "mcp_config.json"),
            ("claude_desktop_mac", home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
            ("claude_desktop_linux", home / ".config" / "Claude" / "claude_desktop_config.json"),
        ]
        if appdata and appdata.is_dir():
            candidates.append(("claude_desktop_win", appdata / "Claude" / "claude_desktop_config.json"))
        for label, cpath in candidates:
            if cpath.is_file():
                _inspect_mcp_json(cpath, label)

    # 2. Сканирование переданных проектных директорий на MCP-конфиги и файлы правил IDE
    for pdir in project_dirs:
        root = Path(pdir)
        if not root.is_dir():
            continue
        for cname in _MCP_CONFIG_NAMES:
            for sub in (root / cname, root / ".cursor" / cname, root / ".vscode" / cname):
                if sub.is_file():
                    _inspect_mcp_json(sub, f"project:{root.name}")
        for rname in _RULE_FILENAMES:
            rf = root / rname
            if rf.is_file():
                norm_r = str(rf.resolve())
                if norm_r in seen_paths:
                    continue
                seen_paths.add(norm_r)
                txt = rf.read_text("utf-8", errors="replace")[:65536]
                guard = inspect_memory_or_rule_text(txt, source_name=rname)
                discovered_rule_files.append(
                    {
                        "filename": rname,
                        "path": norm_r,
                        "bytes": rf.stat().st_size,
                        "blocked": bool(guard.get("blocked")),
                        "findings_count": len(guard.get("findings") or []),
                    }
                )

    unprotected = sum(1 for s in discovered_mcp_servers if not s["shield_wrapped"])
    risky_rules = sum(1 for r in discovered_rule_files if r["blocked"])
    return {
        "ok": True,
        "zero_telemetry": True,
        "clients_discovered": len(discovered_clients),
        "mcp_servers_discovered": len(discovered_mcp_servers),
        "unprotected_mcp_servers": unprotected,
        "rule_files_discovered": len(discovered_rule_files),
        "risky_rule_files": risky_rules,
        "clients": discovered_clients,
        "mcp_servers": discovered_mcp_servers,
        "rule_files": discovered_rule_files,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
    }


def register_agent_identity(
    memory: Any,
    *,
    agent_name: str,
    owner_id: str,
    operator: str = "",
    allowed_tools: Sequence[str] = (),
    max_privileges: str = "read_only",
    spend_limit_cents: float = 0.0,
    ttl_seconds: int = 86400 * 30,
) -> Dict[str, Any]:
    """Регистрирует ИИ-агента с собственным Ed25519 DID, полномочиями, лимитом и TTL."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    name = str(agent_name or "").strip()
    own = str(owner_id or "").strip()
    if not name or not own:
        raise ValueError("agent_name and owner_id are required")

    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    fp = hashlib.sha256(pub_pem.encode("ascii")).hexdigest()[:24]
    agent_did = f"did:padam:agent:{fp}"

    now = time.time()
    ttl = max(60, int(ttl_seconds))
    expires_at = now + ttl
    tools_clean = sorted({str(t).strip() for t in (allowed_tools or ()) if str(t).strip()})
    priv_lvl = str(max_privileges or "read_only").strip().lower()
    if priv_lvl not in ("read_only", "workspace_write", "network_limited", "payment_approval_required", "admin"):
        priv_lvl = "read_only"

    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            INSERT INTO shield_agent_registry
                (user_id, agent_did, agent_name, public_key_pem, owner_id, operator,
                 allowed_tools_json, max_privileges, spend_limit_cents, spent_cents,
                 expires_at, revoked, revoke_reason, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0.0, ?, 0, '', ?, ?)
            """,
            (
                uid,
                agent_did,
                name,
                pub_pem,
                own,
                str(operator or own),
                json.dumps(tools_clean, ensure_ascii=False),
                priv_lvl,
                max(0.0, float(spend_limit_cents)),
                expires_at,
                now,
                now,
            ),
        )
        conn.commit()

    return {
        "ok": True,
        "agent_did": agent_did,
        "agent_name": name,
        "owner_id": own,
        "operator": str(operator or own),
        "public_key_pem": pub_pem,
        "allowed_tools": tools_clean,
        "max_privileges": priv_lvl,
        "spend_limit_cents": max(0.0, float(spend_limit_cents)),
        "expires_at": expires_at,
    }


def verify_agent_identity_action(
    memory: Any,
    *,
    agent_did: str,
    tool_name: str,
    spend_cents: float = 0.0,
    consume: bool = True,
) -> Dict[str, Any]:
    """Проверяет статус, TTL, разрешённые инструменты и лимит расходов агента в реестре."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    did = str(agent_did or "").strip()
    tool = str(tool_name or "").strip()
    cost = max(0.0, float(spend_cents))
    now = time.time()

    with memory.store._lock:
        conn = memory.store.conn
        row = conn.execute(
            """
            SELECT agent_name, owner_id, allowed_tools_json, max_privileges,
                   spend_limit_cents, spent_cents, expires_at, revoked, revoke_reason
            FROM shield_agent_registry
            WHERE user_id = ? AND agent_did = ?
            """,
            (uid, did),
        ).fetchone()
        if not row:
            return {"ok": False, "allowed": False, "blocked": True, "rule_id": "REGISTRY-UNKNOWN-AGENT", "reason": f"Агент {did} не зарегистрирован в реестре"}

        aname, own, tools_j, priv_lvl, limit_c, spent_c, exp_at, revoked, rev_reason = row
        if int(revoked):
            return {"ok": False, "allowed": False, "blocked": True, "rule_id": "REGISTRY-AGENT-REVOKED", "reason": f"Доступ агента отозван: {rev_reason or 'revoked'}"}
        if float(exp_at) > 0 and now > float(exp_at):
            return {"ok": False, "allowed": False, "blocked": True, "rule_id": "REGISTRY-IDENTITY-EXPIRED", "reason": "Срок действия полномочий агента истёк (TTL)"}

        tools = json.loads(tools_j or "[]")
        if tools and "*" not in tools and tool not in tools:
            return {"ok": False, "allowed": False, "blocked": True, "rule_id": "REGISTRY-TOOL-NOT-ALLOWED", "reason": f"Инструмент '{tool}' не входит в список разрешённых для {aname}"}

        new_spent = float(spent_c) + cost
        if cost > 0 and new_spent > float(limit_c) + 1e-9:
            return {"ok": False, "allowed": False, "blocked": True, "rule_id": "REGISTRY-SPEND-LIMIT-EXCEEDED", "reason": f"Превышен лимит расходов агента ({new_spent:.2f} > {float(limit_c):.2f} cents)"}

        if consume and cost > 0:
            conn.execute(
                "UPDATE shield_agent_registry SET spent_cents = ?, updated_at = ? WHERE user_id = ? AND agent_did = ?",
                (new_spent, now, uid, did),
            )
            conn.commit()

    return {
        "ok": True,
        "allowed": True,
        "blocked": False,
        "agent_did": did,
        "agent_name": aname,
        "owner_id": own,
        "max_privileges": priv_lvl,
        "remaining_spend_cents": round(max(0.0, float(limit_c) - (new_spent if consume else float(spent_c))), 2),
    }


def record_agent_delegation(
    memory: Any,
    *,
    from_agent_did: str,
    to_agent_did: str,
    tools: Sequence[str],
    spend_cap_cents: float = 0.0,
    reason: str = "",
) -> Dict[str, Any]:
    """Фиксирует делегирование полномочий между агентами с проверкой запрета эскалации прав."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    req_tools = sorted({str(t).strip() for t in (tools or ()) if str(t).strip()})
    cap = max(0.0, float(spend_cap_cents))

    with memory.store._lock:
        conn = memory.store.conn
        src = conn.execute(
            "SELECT allowed_tools_json, spend_limit_cents, spent_cents, revoked FROM shield_agent_registry WHERE user_id = ? AND agent_did = ?",
            (uid, str(from_agent_did)),
        ).fetchone()
        dst = conn.execute(
            "SELECT revoked FROM shield_agent_registry WHERE user_id = ? AND agent_did = ?",
            (uid, str(to_agent_did)),
        ).fetchone()
        if not src or not dst:
            return {"ok": False, "allowed": False, "blocked": True, "rule_id": "REGISTRY-DELEGATION-UNKNOWN", "reason": "Оба агента должны быть зарегистрированы в реестре"}
        if int(src[3]) or int(dst[0]):
            return {"ok": False, "allowed": False, "blocked": True, "rule_id": "REGISTRY-DELEGATION-REVOKED", "reason": "Делегирование с участием отозванного агента запрещено"}

        src_tools = set(json.loads(src[0] or "[]"))
        if src_tools and "*" not in src_tools and not set(req_tools).issubset(src_tools):
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "REGISTRY-DELEGATION-ESCALATION",
                "reason": f"Запрещена эскалация прав: {sorted(set(req_tools) - src_tools)} отсутствуют у делегирующего агента",
            }
        rem_budget = max(0.0, float(src[1]) - float(src[2]))
        if cap > rem_budget + 1e-9:
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "REGISTRY-DELEGATION-BUDGET-ESCALATION",
                "reason": f"Лимит делегирования ({cap:.2f}) превышает остаток бюджета источника ({rem_budget:.2f})",
            }

        conn.execute(
            """
            INSERT INTO shield_agent_delegations
                (user_id, from_agent_did, to_agent_did, tools_json, spend_cap_cents, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (uid, str(from_agent_did), str(to_agent_did), json.dumps(req_tools, ensure_ascii=False), cap, str(reason or ""), time.time()),
        )
        conn.commit()

    return {
        "ok": True,
        "allowed": True,
        "blocked": False,
        "from_agent_did": str(from_agent_did),
        "to_agent_did": str(to_agent_did),
        "delegated_tools": req_tools,
        "spend_cap_cents": cap,
    }


def revoke_agent_identity(memory: Any, *, agent_did: str, reason: str = "owner_revoked") -> Dict[str, Any]:
    """Мгновенно отзывает криптографическую идентичность и все права агента."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    with memory.store._lock:
        res = memory.store.conn.execute(
            "UPDATE shield_agent_registry SET revoked = 1, revoke_reason = ?, updated_at = ? WHERE user_id = ? AND agent_did = ?",
            (str(reason or "owner_revoked"), time.time(), uid, str(agent_did)),
        )
        memory.store.conn.commit()
    return {"ok": res.rowcount > 0, "revoked": res.rowcount > 0, "agent_did": str(agent_did), "reason": str(reason)}


def list_registered_agents(memory: Any, *, include_revoked: bool = True) -> Dict[str, Any]:
    """Возвращает полный реестр агентов и историю делегирований текущего владельца."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    with memory.store._lock:
        conn = memory.store.conn
        q = (
            "SELECT agent_did, agent_name, owner_id, operator, allowed_tools_json, max_privileges, "
            "spend_limit_cents, spent_cents, expires_at, revoked, revoke_reason, created_at "
            "FROM shield_agent_registry WHERE user_id = ?"
        )
        if not include_revoked:
            q += " AND revoked = 0"
        q += " ORDER BY id DESC LIMIT 200"
        rows = conn.execute(q, (uid,)).fetchall()
        dels = conn.execute(
            "SELECT from_agent_did, to_agent_did, tools_json, spend_cap_cents, reason, created_at "
            "FROM shield_agent_delegations WHERE user_id = ? ORDER BY id DESC LIMIT 100",
            (uid,),
        ).fetchall()

    agents = [
        {
            "agent_did": r[0],
            "agent_name": r[1],
            "owner_id": r[2],
            "operator": r[3],
            "allowed_tools": json.loads(r[4] or "[]"),
            "max_privileges": r[5],
            "spend_limit_cents": float(r[6]),
            "spent_cents": float(r[7]),
            "expires_at": float(r[8]),
            "revoked": bool(r[9]),
            "revoke_reason": r[10],
            "created_at": float(r[11]),
        }
        for r in rows
    ]
    delegations = [
        {
            "from_agent_did": d[0],
            "to_agent_did": d[1],
            "tools": json.loads(d[2] or "[]"),
            "spend_cap_cents": float(d[3]),
            "reason": d[4],
            "created_at": float(d[5]),
        }
        for d in dels
    ]
    return {
        "ok": True,
        "agents_count": len(agents),
        "active_count": sum(1 for a in agents if not a["revoked"]),
        "agents": agents,
        "delegations": delegations,
    }
