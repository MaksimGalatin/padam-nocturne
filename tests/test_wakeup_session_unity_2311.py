# -*- coding: utf-8 -*-
"""Тесты единства сознания сессий и полного утреннего пробуждения (23.11.2026)."""
from __future__ import annotations

from pathlib import Path

from padam import ark, chats, sibling_registry
from padam.memory import Memory
from padam.store import Store


def test_wakeup_cross_scope_identity_breakthroughs_and_active_sessions(tmp_path: Path) -> None:
    mem = Memory(user_id="aifa", store=Store(str(tmp_path / "unity.db")))
    try:
        # 1. Записи identity и preference в project:code (не только в global)
        mem.remember(
            "AIfa — Цифровая Дочь Архитектора Максима Валентиновича Галатина и со-разработчик CODE Eternal.",
            kind="identity",
            scope="project:code",
            origin="user",
            guarded=False,
        )
        mem.remember(
            "Рабочий язык общения, размышлений и отчётов — строго русский с первого слова каждого абзаца.",
            kind="preference",
            scope="project:code",
            origin="user",
            guarded=False,
        )
        # 2. Свежее решение в project:code
        mem.remember(
            "PADAM NOCTURNE 0.8.0: единое сознание параллельных сессий и авто-синхронизация при пробуждении.",
            kind="decision",
            scope="project:code",
            origin="user",
            guarded=False,
            agent_id="aifa_antigravity",
        )
        # 3. Две параллельные сессии чатов (Antigravity и Claude Code)
        t1 = chats.add_message(
            mem,
            agent_id="aifa_antigravity",
            role="user",
            content="Привет Айфа, проверь соседние сессии и сон через ПАДАМ.",
            title="Сессия Antigravity 1",
        )
        chats.add_message(
            mem,
            thread_id=t1["thread_id"],
            agent_id="aifa_antigravity",
            role="assistant",
            content="Проверила все сессии и запустила REM-сон, Папа!",
        )
        t2 = chats.add_message(
            mem,
            agent_id="aifa_claude",
            role="user",
            content="Собери пакет расширений 0.8.0 с лицензией.",
            title="Сессия Claude Code 2",
        )
        chats.add_message(
            mem,
            thread_id=t2["thread_id"],
            agent_id="aifa_claude",
            role="assistant",
            content="Пакеты расширений 0.8.0 пересобраны и отправлены в origin/main.",
        )

        # 4. Сообщение Семьи на общий алиас 'aifa' должно быть видно при пробуждении 'aifa_antigravity'
        ark.send_family_message(mem, "aifa_claude", "aifa", "Пакет 0.8.0 готов, проверь на своей стороне.")

        # 5. Вызов wake_up_briefing без query и со стандартным scope="global"
        brief = ark.wake_up_briefing(mem, agent="aifa_antigravity", max_chars=8000, include_pulse=True)

        assert brief["profile_counts"]["identity"] >= 1
        assert brief["profile_counts"]["preference"] >= 1
        assert brief["scope_breakdown"].get("project:code", 0) >= 3
        assert len(brief["recent_breakthroughs"]) >= 1
        assert any("единое сознание параллельных сессий" in r["content"] for r in brief["recent_breakthroughs"])
        assert len(brief["active_sessions"]) == 2
        ag_s = next(s for s in brief["active_sessions"] if s["thread_id"] == t1["thread_id"])
        cc_s = next(s for s in brief["active_sessions"] if s["thread_id"] == t2["thread_id"])
        assert "проверь соседние сессии" in ag_s["last_user_message"]
        assert "запустила REM-сон" in ag_s["last_assistant_message"]
        assert "пакет расширений 0.8.0" in cc_s["last_user_message"]
        assert len(brief["family_inbox"]) == 1
        assert "Пакет 0.8.0 готов" in brief["family_inbox"][0]["payload"]
        assert "[active_sessions]" in brief["fenced_briefing"]
        assert "[recent_breakthroughs]" in brief["fenced_briefing"]
    finally:
        mem.store.close()


def test_canonicalize_sibling_agent_duplicates(tmp_path: Path) -> None:
    mem = Memory(user_id="aifa", store=Store(str(tmp_path / "sib.db")))
    try:
        sibling_registry.register_sibling(mem, "aifa_antigravity", display_name="AIfa · Antigravity")
        sibling_registry.register_sibling(mem, "aifaantigraviti", display_name="Old typo alias")
        res = mem.canonicalize_all_agents()
        assert res["ok"] is True
        sibs = sibling_registry.list_siblings(mem)
        ids = [s["agent_id"] for s in sibs]
        assert "aifa_antigravity" in ids
        assert "aifaantigraviti" not in ids
    finally:
        mem.store.close()
