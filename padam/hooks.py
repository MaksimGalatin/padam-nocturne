"""Хуки жизненного цикла (Lifecycle Hooks) для Claude Code, Codex и Gemini CLI.

Позволяет без единого облачного вызова ($0) автоматически подмешивать
релевантную память в начале сессии (SessionStart), при вводе запроса
(UserPromptSubmit / BeforeAgent) и перед вызовом инструмента (PreToolUse),
пропуская всё через DLP-очистку, бюджет токенов и защитную ограду,
и полностью исключая записи из карантина и чужих scope.

По умолчанию подсистема выключена (PADAM_HOOKS=0).
"""
from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

from . import config, safety
from .memory import Memory

SUPPORTED_CLIENTS = ("claude", "codex", "gemini")
CLAUDE_HOOK_EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse")
CODEX_HOOK_EVENTS = ("SessionStart", "UserPromptSubmit")
GEMINI_HOOK_EVENTS = ("SessionStart", "BeforeAgent", "BeforeTool")
HOOK_MARKER = "hooks run"


def _quote_cmd(parts: list[str]) -> str:
    return " ".join(shlex.quote(p) for p in parts)


def _build_hook_command(
    client: str,
    event: str,
    *,
    scope: str | None = None,
    token_budget: int = 800,
    python_exe: str | None = None,
) -> str:
    py = python_exe or sys.executable or "python"
    args = [py, "-m", "padam.cli", "hooks", "run", "--client", client, "--event", event, "--budget", str(int(token_budget))]
    if scope:
        args.extend(["--scope", scope])
    return _quote_cmd(args)


def render_hook_context(
    mem: Memory,
    *,
    event: str = "SessionStart",
    query: str = "",
    scope: str | None = None,
    token_budget: int = 800,
    tool_name: str = "",
    briefing: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Собирает безопасный контекст памяти для инъекции в хук жизненного цикла."""
    if briefing and (force or config.mcp_hooks_enabled() or config.mcp_briefing_enabled()):
        from .briefing import build_project_briefing
        br = build_project_briefing(
            mem,
            scope=scope,
            token_budget=token_budget,
            force=bool(force or config.mcp_briefing_enabled()),
        )
        fenced = br.get("fenced_text") or ""
        return {
            "enabled": bool(br.get("enabled")),
            "event": event,
            "scope": scope,
            "briefing": True,
            "items": br.get("sections", {}),
            "additionalContext": fenced,
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": fenced,
            },
        }
    if not force and not config.mcp_hooks_enabled():
        return {
            "enabled": False,
            "event": event,
            "scope": scope,
            "items": [],
            "additionalContext": "",
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": "",
            },
        }

    search_q = " ".join(part for part in (query.strip(), tool_name.strip()) if part).strip()
    if search_q:
        raw_hits = mem.recall(search_q, scope=scope, limit=20)
        candidates = [
            {
                "id": rec.id,
                "kind": rec.kind,
                "scope": rec.scope,
                "content": rec.content,
                "quarantined": bool(getattr(rec, "quarantine_reason", "")) or getattr(rec, "status", "active") == "quarantined",
            }
            for rec in raw_hits
        ]
    else:
        sql = (
            "SELECT id, kind, scope, content, status, quarantine_reason FROM memory "
            "WHERE user_id = ? AND status = 'active' AND (quarantine_reason IS NULL OR quarantine_reason = '') "
        )
        params: list[Any] = [mem.user_id]
        if scope is not None:
            sql += "AND scope = ? "
            params.append(scope)
        sql += "ORDER BY created_at DESC LIMIT 20"
        candidates = [
            {
                **dict(row),
                "quarantined": bool(row["quarantine_reason"]) or row["status"] == "quarantined",
            }
            for row in mem.store.query(sql, tuple(params))
        ]

    max_chars = max(120, int(token_budget) * 4)
    lines: list[str] = []
    selected: list[dict[str, Any]] = []
    used_chars = 0

    for rec in candidates:
        if rec.get("quarantined"):
            continue
        if scope is not None and rec.get("scope") != scope:
            continue
        cleaned, _ = safety.redact(str(rec.get("content") or ""))
        if config.mcp_dlp_shield_enabled():
            from .dlp_shield import DlpShield
            cleaned, _ = DlpShield(mem).scrub(cleaned)
        cleaned = safety.clean(cleaned)
        if not cleaned:
            continue
        entry = f"[{rec['kind']}|{rec['scope']}] {cleaned}"
        if lines and used_chars + len(entry) + 1 > max_chars:
            break
        if not lines and len(entry) > max_chars:
            entry = entry[:max_chars]
        lines.append(entry)
        used_chars += len(entry) + 1
        selected.append({"id": rec["id"], "kind": rec["kind"], "scope": rec["scope"], "text": entry})

    body = "\n".join(lines)
    fenced = safety.fence(body) if body else ""
    return {
        "enabled": True,
        "event": event,
        "scope": scope,
        "token_budget": int(token_budget),
        "items": selected,
        "additionalContext": fenced,
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": fenced,
        },
    }


def _padam_hook_entry(command: str, matcher: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "hooks": [
            {
                "type": "command",
                "command": command,
            }
        ]
    }
    if matcher is not None:
        entry["matcher"] = matcher
    return entry


def build_claude_hooks_config(
    *,
    scope: str | None = None,
    token_budget: int = 800,
    python_exe: str | None = None,
) -> dict[str, Any]:
    hooks: dict[str, list[dict[str, Any]]] = {}
    for ev in CLAUDE_HOOK_EVENTS:
        cmd = _build_hook_command("claude", ev, scope=scope, token_budget=token_budget, python_exe=python_exe)
        matcher = "*" if ev == "PreToolUse" else None
        hooks[ev] = [_padam_hook_entry(cmd, matcher=matcher)]
    return {"hooks": hooks}


def build_codex_hooks_config(
    *,
    scope: str | None = None,
    token_budget: int = 800,
    python_exe: str | None = None,
) -> dict[str, Any]:
    hooks: dict[str, list[dict[str, Any]]] = {}
    for ev in CODEX_HOOK_EVENTS:
        cmd = _build_hook_command("codex", ev, scope=scope, token_budget=token_budget, python_exe=python_exe)
        hooks[ev] = [_padam_hook_entry(cmd)]
    return {"hooks": hooks}


def build_gemini_hooks_config(
    *,
    scope: str | None = None,
    token_budget: int = 800,
    python_exe: str | None = None,
) -> dict[str, Any]:
    hooks: dict[str, list[dict[str, Any]]] = {}
    for ev in GEMINI_HOOK_EVENTS:
        cmd = _build_hook_command("gemini", ev, scope=scope, token_budget=token_budget, python_exe=python_exe)
        matcher = "*" if ev == "BeforeTool" else None
        hooks[ev] = [_padam_hook_entry(cmd, matcher=matcher)]
    return {"hooks": hooks}


def _is_padam_hook_item(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    for h in item.get("hooks") or []:
        if isinstance(h, dict) and HOOK_MARKER in str(h.get("command") or ""):
            return True
    return False


def _merge_hooks_json(existing: dict[str, Any], generated: dict[str, Any]) -> dict[str, Any]:
    out = dict(existing) if isinstance(existing, dict) else {}
    cur_hooks = dict(out.get("hooks") or {}) if isinstance(out.get("hooks"), dict) else {}
    gen_hooks = generated.get("hooks") or {}
    for ev, entries in gen_hooks.items():
        prev = cur_hooks.get(ev)
        kept = [x for x in (prev if isinstance(prev, list) else []) if not _is_padam_hook_item(x)]
        cur_hooks[ev] = kept + list(entries)
    out["hooks"] = cur_hooks
    return out


def _client_config_target(client: str, project_dir: Path) -> tuple[Path, dict[str, Any]]:
    if client == "claude":
        return project_dir / ".claude" / "settings.json", {}
    if client == "codex":
        return project_dir / ".codex" / "hooks.json", {}
    if client == "gemini":
        return project_dir / ".gemini" / "settings.json", {}
    raise ValueError(f"Unsupported hook client: {client}")


def install_hooks(
    client: str,
    *,
    project_dir: Path | str,
    scope: str | None = None,
    token_budget: int = 800,
    python_exe: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Устанавливает хуки жизненного цикла в локальные конфиги выбранного клиента (или all)."""
    root = Path(project_dir)
    targets = list(SUPPORTED_CLIENTS) if client == "all" else [client]
    builders = {
        "claude": build_claude_hooks_config,
        "codex": build_codex_hooks_config,
        "gemini": build_gemini_hooks_config,
    }
    installed: list[dict[str, Any]] = []
    for cl in targets:
        if cl not in builders:
            raise ValueError(f"Unsupported hook client: {cl}")
        cfg_path, _ = _client_config_target(cl, root)
        gen = builders[cl](scope=scope, token_budget=token_budget, python_exe=python_exe)
        existing: dict[str, Any] = {}
        if cfg_path.exists():
            try:
                existing = json.loads(cfg_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = {}
        merged = _merge_hooks_json(existing, gen)
        if not dry_run:
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            cfg_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        installed.append({"client": cl, "path": str(cfg_path), "events": list((gen.get("hooks") or {}).keys())})
    return {
        "status": "dry_run" if dry_run else "installed",
        "hooks_enabled": bool(config.mcp_hooks_enabled()),
        "installed": installed,
    }


def hooks_status(project_dir: Path | str) -> dict[str, Any]:
    root = Path(project_dir)
    clients: dict[str, Any] = {}
    for cl in SUPPORTED_CLIENTS:
        cfg_path, _ = _client_config_target(cl, root)
        events: list[str] = []
        if cfg_path.exists():
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
                for ev, arr in (data.get("hooks") or {}).items():
                    if isinstance(arr, list) and any(_is_padam_hook_item(x) for x in arr):
                        events.append(ev)
            except Exception:
                events = []
        clients[cl] = {"path": str(cfg_path), "exists": cfg_path.exists(), "padam_events": events}
    return {"hooks_enabled": bool(config.mcp_hooks_enabled()), "clients": clients}
