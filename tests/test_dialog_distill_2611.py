"""Переписки → искомая память (26.11.2026).

Сообщения из chat_message раньше не находил поиск. Теперь слова владельца попадают в scope owner:words,
развёрнутые ответы агентов — в work:reports; служебные вставки и короткие реплики пропускаются; повторный
прогон ничего не дублирует.
"""
from __future__ import annotations

from pathlib import Path

from padam import chats
from padam.memory import Memory
from padam.store import Store


def _mem(tmp_path: Path) -> Memory:
    return Memory(user_id="owner-distill", store=Store(str(tmp_path / "d.db")))


def _thread(mem: Memory, messages: list[dict]) -> None:
    parsed = {"agent_id": "aifa_claude", "source_kind": "claude_code_jsonl", "source_ref": "x.jsonl",
              "title": "t", "messages": messages}
    chats.save_parsed_thread(mem, parsed)


def test_owner_words_and_reports_become_searchable(tmp_path, monkeypatch):
    monkeypatch.delenv("PADAM_DIALOG_DISTILL", raising=False)
    mem = _mem(tmp_path)
    _thread(mem, [
        {"role": "user", "content": "The Chrome Web Store fee of five dollars was paid long ago.", "created_at": "2026-11-22T14:34:40Z"},
        {"role": "assistant", "content": "ok", "created_at": "2026-11-22T14:35:00Z"},
        {"role": "assistant", "content": "Report: " + "the release went out to PyPI and the MCP registry. " * 20, "created_at": "2026-11-22T14:36:00Z"},
        {"role": "user", "content": "This session is being continued from a previous conversation ...", "created_at": "2026-11-22T14:37:00Z"},
    ])
    r = chats.distill_dialogs_to_memory(mem, pause_s=0)
    assert r["ok"] and r["owner_words"] == 1 and r["reports"] == 1, r
    hits = mem.recall("Chrome Web Store fee paid", limit=3, scope="owner:words")
    texts = [h["content"] if isinstance(h, dict) else getattr(h, "content", "") for h in hits]
    assert any("five dollars" in t for t in texts), texts
    # повторный прогон — ничего нового
    r2 = chats.distill_dialogs_to_memory(mem, pause_s=0)
    assert r2["owner_words"] == 0 and r2["reports"] == 0, r2


def test_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_DIALOG_DISTILL", "0")
    assert chats.distill_dialogs_to_memory(_mem(tmp_path))["disabled"] is True
