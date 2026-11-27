# -*- coding: utf-8 -*-
"""Policy Compiler — экспорт политик PADAM в промышленные форматы инфраструктуры.

Позволяет одной командой (`padam shield export-policy --target <target>`)
скомпилировать доверенные домены, кошельки и профиль защиты владельца из SQLite в:
- `claude_hooks`: готовый `.claude/settings.json` с `PreToolUse` / `PostToolUse` хуками PADAM Shield;
- `github_action`: готовый `.github/workflows/padam-shield.yml` (diff/rules/deps/aibom/pentest);
- `docker_egress`: JSON-профиль контейнера (`read_only`, `cap_drop: ["ALL"]`, `egress_allowlist`);
- `mcp_wrapper`: оборачивает существующий `mcp.json` в прозрачный `padam shield proxy --` (идемпотентно).
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .. import agentic_shield as _ash


def _load_owner_allowlists(memory: Any) -> Dict[str, List[str]]:
    _ash._ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    domains: List[str] = []
    wallets: List[str] = []
    with memory.store._lock:
        rows = memory.store.conn.execute(
            "SELECT entry_type, value FROM shield_allowlist WHERE user_id = ? ORDER BY entry_type, value",
            (uid,),
        ).fetchall()
    for etype, val in rows:
        et = str(etype or "").lower()
        v = str(val or "").strip()
        if et == "domain" and v:
            domains.append(v)
        elif et == "wallet" and v:
            wallets.append(v)
    return {"domains": domains, "wallets": wallets}


def export_policy_bundle(
    memory: Any,
    *,
    target: str = "claude_hooks",
    mcp_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Компилирует политики безопасности владельца в выбранный промышленный формат."""
    t = str(target or "claude_hooks").strip().lower()
    al = _load_owner_allowlists(memory)
    status = _ash.get_shield_status(memory)
    profile = str(status.get("profile") or "balanced")

    if t == "claude_hooks":
        cfg = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash|WebFetch|mcp__.*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python -m padam shield check-outbound --type tool_call --target \"$TOOL_NAME\" --payload \"$TOOL_INPUT\"",
                            }
                        ],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python -m padam shield verify-seal --no-lockdown",
                            }
                        ],
                    }
                ],
            },
            "x_padam_meta": {
                "profile": profile,
                "allowed_domains": al["domains"],
                "allowed_wallets_count": len(al["wallets"]),
            },
        }
        return {
            "ok": True,
            "target": t,
            "filename": ".claude/settings.json",
            "format": "json",
            "content": json.dumps(cfg, ensure_ascii=False, indent=2),
            "parsed": cfg,
        }

    if t == "github_action":
        yml = (
            "name: PADAM Agentic Shield CI Gate\n"
            "on:\n"
            "  pull_request:\n"
            "  push:\n"
            "    branches: [main]\n"
            "jobs:\n"
            "  padam-shield:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          fetch-depth: 2\n"
            "      - uses: actions/setup-python@v5\n"
            "        with:\n"
            "          python-version: '3.12'\n"
            "      - run: pip install padam-nocturne\n"
            "      - name: Scan IDE Rules & Skills\n"
            "        run: python -m padam shield scan-rules .\n"
            "      - name: Scan Dependencies (Slopsquatting)\n"
            "        run: python -m padam shield scan-deps pyproject.toml\n"
            "      - name: Scan Git Diff (Trojan Source & Backdoors)\n"
            "        run: git diff HEAD~1..HEAD > pr.diff && python -m padam shield scan-diff pr.diff\n"
            "      - name: Generate CycloneDX 1.6 AI-BOM\n"
            "        run: python -m padam shield aibom . --out aibom.cdx.json\n"
            "      - name: Local 1000-Vector Pentest Gate\n"
            "        run: python -m padam pentest\n"
        )
        return {
            "ok": True,
            "target": t,
            "filename": ".github/workflows/padam-shield.yml",
            "format": "yaml",
            "content": yml,
        }

    if t == "docker_egress":
        doc = {
            "security_profile": profile,
            "container_hardening": {
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "pids_limit": 128,
                "memory": "512m",
                "user": "65532:65532",
            },
            "egress_allowlist_domains": al["domains"],
            "blocked_cidrs": [
                "169.254.169.254/32",
                "169.254.170.2/32",
                "100.100.100.200/32",
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ],
        }
        return {
            "ok": True,
            "target": t,
            "filename": "padam-docker-egress.json",
            "format": "json",
            "content": json.dumps(doc, ensure_ascii=False, indent=2),
            "parsed": doc,
        }

    if t == "mcp_wrapper":
        src = mcp_config if isinstance(mcp_config, dict) else {"mcpServers": {}}
        servers = src.get("mcpServers") if isinstance(src.get("mcpServers"), dict) else {}
        wrapped_servers: Dict[str, Any] = {}
        wrapped_count = 0
        for sname, scfg in servers.items():
            if not isinstance(scfg, dict):
                wrapped_servers[sname] = scfg
                continue
            cmd = str(scfg.get("command") or "")
            args_list = list(scfg.get("args") or [])
            # Идемпотентность: уже завёрнутый в padam shield proxy сервер не заворачиваем дважды
            low_args = [str(x).lower() for x in args_list]
            already_wrapped = ("padam" in cmd.lower() or "padam" in low_args) and "proxy" in low_args
            if cmd and not already_wrapped:
                new_cfg = dict(scfg)
                new_cfg["command"] = "python"
                new_cfg["args"] = ["-m", "padam", "shield", "proxy", "--server", str(sname), "--", cmd] + args_list
                wrapped_servers[sname] = new_cfg
                wrapped_count += 1
            else:
                wrapped_servers[sname] = dict(scfg)
        out_obj = dict(src)
        out_obj["mcpServers"] = wrapped_servers
        return {
            "ok": True,
            "target": t,
            "filename": "mcp.shielded.json",
            "format": "json",
            "wrapped_count": wrapped_count,
            "content": json.dumps(out_obj, ensure_ascii=False, indent=2),
            "parsed": out_obj,
        }

    raise ValueError(f"Неизвестная цель экспорта: {t!r} (ожидается claude_hooks | github_action | docker_egress | mcp_wrapper)")
