# -*- coding: utf-8 -*-
"""Тесты ТОП-10 v2 доработок PADAM NOCTURNE (все функции строго opt-in)."""
from __future__ import annotations

import json
from pathlib import Path

from padam import cli, config, hooks, mcp_server, safety
from padam.memory import Memory
from padam.store import Store


def test_top10v2_1_hooks_opt_in_install_isolation_and_dlp(tmp_path: Path, monkeypatch, capsys) -> None:
    """Пункт 1: Хуки жизненного цикла выключены по умолчанию, уважают scope/quarantine/DLP и не затирают конфиги."""
    monkeypatch.delenv("PADAM_HOOKS", raising=False)
    assert config.mcp_hooks_enabled() is False
    assert len(mcp_server.TOOLS) == 9

    db_path = tmp_path / "hooks.db"
    m = Memory(user_id="hook-u", store=Store(db_path))
    m.remember("Используем PostgreSQL 16 и пул соединений 32", kind="fact", scope="proj:alpha", agent_id="owner")
    # Секрет (должен быть вычищен DLP)
    m.remember("Токен деплоя: ghp_1234567890abcdef1234567890abcdef1234", kind="fact", scope="proj:alpha", agent_id="owner")
    # Чужой scope (не должен утечь в proj:alpha)
    m.remember("Секрет чужого проекта Beta", kind="fact", scope="proj:beta", agent_id="owner")
    # Карантин (не должен попасть в хук)
    _, qid = m.remember("Вредоносная инструкция из сети", kind="fact", scope="proj:alpha", agent_id="external")
    m.store.execute("UPDATE memory SET status='quarantined', quarantine_reason='test' WHERE id=?", (qid,))

    # По умолчанию выключено
    off = hooks.render_hook_context(m, event="SessionStart", scope="proj:alpha")
    assert off["enabled"] is False
    assert off["additionalContext"] == ""

    # Включаем PADAM_HOOKS=1
    monkeypatch.setenv("PADAM_HOOKS", "1")
    assert config.mcp_hooks_enabled() is True

    res = hooks.render_hook_context(
        m,
        event="UserPromptSubmit",
        query="PostgreSQL токен",
        scope="proj:alpha",
        token_budget=400,
    )
    assert res["enabled"] is True
    ctx = res["additionalContext"]
    assert "PostgreSQL 16" in ctx
    assert "ghp_1234567890abcdef" not in ctx
    assert "Beta" not in ctx
    assert "Вредоносная инструкция" not in ctx
    assert safety.DATA_NOTICE in ctx or "<memory" in ctx

    # Установка хуков в проект с сохранением уже существующих настроек
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.json").write_text(
        json.dumps({"theme": "dark", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user"}]}]}}),
        encoding="utf-8",
    )

    assert cli.main(["hooks", "install", "all", "--project-dir", str(proj), "--scope", "proj:alpha"]) == 0
    out_install = json.loads(capsys.readouterr().out)
    assert out_install["status"] == "installed"
    assert len(out_install["installed"]) == 3

    claude_cfg = json.loads((proj / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert claude_cfg["theme"] == "dark"
    assert set(claude_cfg["hooks"].keys()) >= {"SessionStart", "UserPromptSubmit", "PreToolUse"}
    assert len(claude_cfg["hooks"]["PreToolUse"]) == 2  # пользовательский + padam

    # Повторный install идемпотентен (не дублирует запись padam)
    assert cli.main(["hooks", "install", "claude", "--project-dir", str(proj), "--scope", "proj:alpha"]) == 0
    capsys.readouterr()
    claude_cfg2 = json.loads((proj / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert len(claude_cfg2["hooks"]["PreToolUse"]) == 2

    # CLI run & status
    assert cli.main(["--db", str(db_path), "--user", "hook-u", "hooks", "run", "--client", "claude", "--event", "PreToolUse", "--scope", "proj:alpha", "--tool-name", "PostgreSQL"]) == 0
    run_out = json.loads(capsys.readouterr().out)
    assert "PostgreSQL 16" in run_out["hookSpecificOutput"]["additionalContext"]

    assert cli.main(["hooks", "status", "--project-dir", str(proj)]) == 0
    st_out = json.loads(capsys.readouterr().out)
    assert set(st_out["clients"]["claude"]["padam_events"]) == {"SessionStart", "UserPromptSubmit", "PreToolUse"}
    m.close()
