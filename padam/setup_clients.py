"""Авто-установщик PADAM MCP в IDE и AI-клиенты в одну команду (padam setup).

Поддерживает 13 клиентов: Claude Desktop, Claude Code, Antigravity, Cursor, VS Code,
Codex, Gemini CLI, Windsurf, Zed, Cline, Roo Code, Continue.dev, JetBrains AI.
Перед изменением любого существующего файла создаёт резервную копию `.bak`
и никогда не затирает другие MCP-серверы пользователя.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

SUPPORTED_CLIENTS = (
    "claude_desktop",
    "claude_code",
    "antigravity",
    "cursor",
    "vscode",
    "codex",
    "gemini_cli",
    "windsurf",
    "zed",
    "cline",
    "roo_code",
    "continue_dev",
    "jetbrains",
)


def _client_config_path(client: str, *, home: Path, project_dir: Path) -> tuple[Path, str]:
    """Возвращает (путь_к_конфигу, формат: json_mcpServers | json_servers | json_zed | toml_codex)."""
    appdata = Path(os.environ.get("APPDATA") or (home / "AppData" / "Roaming"))
    if client == "claude_desktop":
        if sys.platform == "win32":
            return appdata / "Claude" / "claude_desktop_config.json", "json_mcpServers"
        if sys.platform == "darwin":
            return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json", "json_mcpServers"
        return home / ".config" / "Claude" / "claude_desktop_config.json", "json_mcpServers"
    if client == "claude_code":
        return project_dir / ".mcp.json", "json_mcpServers"
    if client == "cursor":
        return home / ".cursor" / "mcp.json", "json_mcpServers"
    if client == "vscode":
        return project_dir / ".vscode" / "mcp.json", "json_servers"
    if client == "codex":
        return home / ".codex" / "config.toml", "toml_codex"
    if client == "antigravity":
        cfg_modern = home / ".gemini" / "config" / "mcp_config.json"
        if cfg_modern.exists():
            return cfg_modern, "json_mcpServers"
        return home / ".gemini" / "antigravity" / "mcp_config.json", "json_mcpServers"
    if client == "gemini_cli":
        return home / ".gemini" / "settings.json", "json_mcpServers"
    if client == "windsurf":
        return home / ".codeium" / "windsurf" / "mcp_config.json", "json_mcpServers"
    if client == "zed":
        if sys.platform == "win32":
            return appdata / "Zed" / "settings.json", "json_zed"
        return home / ".config" / "zed" / "settings.json", "json_zed"
    if client == "cline":
        return appdata / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json", "json_mcpServers"
    if client == "roo_code":
        return appdata / "Code" / "User" / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json", "json_mcpServers"
    if client == "continue_dev":
        return home / ".continue" / "config.json", "json_mcpServers"
    if client == "jetbrains":
        return home / ".jetbrains" / "mcp.json", "json_mcpServers"
    raise ValueError(f"Unsupported client: {client}")


def _padam_entry(db_path: Path, user_id: str, command: str = "padam-mcp") -> dict[str, Any]:
    return {
        "command": command,
        "args": [],
        "env": {
            "PADAM_DB": str(db_path),
            "PADAM_USER": user_id,
        },
    }


def _merge_json_config(existing: dict[str, Any], fmt: str, entry: dict[str, Any]) -> dict[str, Any]:
    out = dict(existing) if isinstance(existing, dict) else {}
    if fmt == "json_servers":
        servers = dict(out.get("servers") or {})
        servers["padam"] = {"type": "stdio", **entry}
        out["servers"] = servers
        return out
    if fmt == "json_zed":
        ctx = dict(out.get("context_servers") or {})
        ctx["padam"] = {"command": {"path": entry["command"], "args": entry["args"], "env": entry["env"]}}
        out["context_servers"] = ctx
        return out
    mcp = dict(out.get("mcpServers") or {})
    mcp["padam"] = entry
    out["mcpServers"] = mcp
    return out


def _merge_codex_toml(existing_text: str, entry: dict[str, Any]) -> str:
    if "[mcp_servers.padam]" in existing_text:
        return existing_text
    block = (
        "\n[mcp_servers.padam]\n"
        f'command = "{entry["command"]}"\n'
        "args = []\n\n"
        "[mcp_servers.padam.env]\n"
        f'PADAM_DB = "{entry["env"]["PADAM_DB"].replace(chr(92), "/")}"\n'
        f'PADAM_USER = "{entry["env"]["PADAM_USER"]}"\n'
    )
    return (existing_text.rstrip() + "\n" + block).lstrip("\n")


def discover_clients(*, home: Path | None = None, project_dir: Path | None = None) -> list[dict[str, Any]]:
    h = home or Path.home()
    proj = project_dir or Path.cwd()
    out = []
    for cl in SUPPORTED_CLIENTS:
        cfg_path, fmt = _client_config_path(cl, home=h, project_dir=proj)
        detected = cfg_path.exists() or cfg_path.parent.exists()
        out.append({
            "client": cl,
            "path": str(cfg_path),
            "format": fmt,
            "exists": cfg_path.exists(),
            "detected": detected,
        })
    return out


def install_client(
    client: str,
    *,
    home: Path | None = None,
    project_dir: Path | None = None,
    db_path: Path | None = None,
    user_id: str = "default",
    command: str = "padam-mcp",
    backup: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    h = home or Path.home()
    proj = project_dir or Path.cwd()
    eff_db = db_path or (h / ".padam" / "memory.db")
    cfg_path, fmt = _client_config_path(client, home=h, project_dir=proj)
    entry = _padam_entry(eff_db, user_id, command=command)

    backup_path: str | None = None
    if fmt == "toml_codex":
        prev_text = cfg_path.read_text(encoding="utf-8") if cfg_path.exists() else ""
        new_text = _merge_codex_toml(prev_text, entry)
    else:
        prev_obj: dict[str, Any] = {}
        if cfg_path.exists():
            try:
                prev_obj = json.loads(cfg_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                prev_obj = {}
        new_obj = _merge_json_config(prev_obj, fmt, entry)
        new_text = json.dumps(new_obj, ensure_ascii=False, indent=2) + "\n"

    if not dry_run:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        if backup and cfg_path.exists():
            bak = cfg_path.with_suffix(cfg_path.suffix + ".bak")
            shutil.copy2(cfg_path, bak)
            backup_path = str(bak)
        cfg_path.write_text(new_text, encoding="utf-8")

    return {
        "client": client,
        "path": str(cfg_path),
        "format": fmt,
        "backup": backup_path,
        "status": "dry_run" if dry_run else "installed",
    }


def setup_clients(
    *,
    clients: list[str] | None = None,
    all_detected: bool = False,
    home: Path | None = None,
    project_dir: Path | None = None,
    db_path: Path | None = None,
    user_id: str = "default",
    dry_run: bool = False,
    verify: bool = False,
) -> dict[str, Any]:
    h = home or Path.home()
    proj = project_dir or Path.cwd()
    targets: list[str] = list(clients or [])
    if all_detected or not targets:
        disc = discover_clients(home=h, project_dir=proj)
        targets = [d["client"] for d in disc if d["detected"]]
        if not targets:
            targets = ["claude_code", "cursor", "vscode"]

    results = [
        install_client(
            cl,
            home=h,
            project_dir=proj,
            db_path=db_path,
            user_id=user_id,
            dry_run=dry_run,
        )
        for cl in targets
    ]

    verified = None
    if verify:
        from . import mcp_server
        init_r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "padam-setup", "version": "0.6.5"}}})
        tools_r = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = (tools_r.get("result") or {}).get("tools") or []
        verified = {
            "ok": ("result" in init_r) and len(tools) == 9,
            "tools_count": len(tools),
        }

    return {
        "installed_count": len(results),
        "results": results,
        "deeplinks": build_deeplinks(),
        "verified": verified,
    }


def build_deeplinks() -> dict[str, str]:
    """Строит One-Click ссылки установки для Cursor и VS Code."""
    cfg = {"command": "padam-mcp", "args": []}
    b64 = base64.b64encode(json.dumps(cfg, separators=(",", ":")).encode("utf-8")).decode("ascii")
    vs_payload = quote(json.dumps({"name": "padam", "command": "padam-mcp", "args": []}, separators=(",", ":")))
    return {
        "cursor": f"cursor://anysphere.cursor-deeplink/mcp/install?name=padam&config={quote(b64)}",
        "vscode": f"vscode:mcp/install?{vs_payload}",
    }


def rollback_client(
    client: str,
    *,
    home: Path | None = None,
    project_dir: Path | None = None,
) -> dict[str, Any]:
    """Откатывает конфиг клиента из резервной копии .bak или аккуратно убирает запись padam."""
    h = home or Path.home()
    proj = project_dir or Path.cwd()
    cfg_path, fmt = _client_config_path(client, home=h, project_dir=proj)
    bak = cfg_path.with_suffix(cfg_path.suffix + ".bak")
    if bak.exists():
        shutil.copy2(bak, cfg_path)
        return {"ok": True, "client": client, "path": str(cfg_path), "restored_from": str(bak)}
    if not cfg_path.exists():
        return {"ok": False, "client": client, "path": str(cfg_path), "error": "config_not_found"}
    if fmt == "toml_codex":
        raw = cfg_path.read_text(encoding="utf-8", errors="replace")
        idx = raw.find("[mcp_servers.padam]")
        if idx >= 0:
            cfg_path.write_text(raw[:idx].rstrip() + "\n", encoding="utf-8")
            return {"ok": True, "client": client, "path": str(cfg_path), "removed": True}
        return {"ok": False, "client": client, "error": "padam_not_found"}
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        changed = False
        for key in ("mcpServers", "servers", "context_servers"):
            if isinstance(data.get(key), dict) and "padam" in data[key]:
                del data[key]["padam"]
                changed = True
        if changed:
            cfg_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {"ok": changed, "client": client, "path": str(cfg_path), "removed": changed}
    except Exception as exc:
        return {"ok": False, "client": client, "error": str(exc)}


def ping_client_setup(
    client: str,
    *,
    home: Path | None = None,
    project_dir: Path | None = None,
) -> dict[str, Any]:
    """Проверяет конфиг клиента и живой ответ встроенного MCP-сервера PADAM."""
    h = home or Path.home()
    proj = project_dir or Path.cwd()
    cfg_path, fmt = _client_config_path(client, home=h, project_dir=proj)
    configured = False
    if cfg_path.exists():
        txt = cfg_path.read_text(encoding="utf-8", errors="replace")
        configured = ("padam" in txt)
    from . import mcp_server
    init_r = mcp_server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": f"ping-{client}", "version": "0.7.1"}},
    })
    tools_r = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools = (tools_r.get("result") or {}).get("tools") or []
    return {
        "ok": bool("result" in init_r and len(tools) >= 9),
        "client": client,
        "path": str(cfg_path),
        "format": fmt,
        "config_has_padam": configured,
        "mcp_tools_ready": len(tools),
    }
