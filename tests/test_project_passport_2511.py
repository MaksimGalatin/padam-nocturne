"""0.9.0 (25.11.2026): паспорт проекта в padam_wake_up — важные факты поднимаются сами, без совпадения с query.

Повод: AIfa забыла 12 прогретых ящиков рассылки на 4 доменах — факт был в памяти, а сводка его не показывала."""
from __future__ import annotations

from pathlib import Path

from padam import ark
from padam.memory import Memory
from padam.store import Store


def test_wake_up_carries_project_passport(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = Memory(user_id="pp", store=Store(str(tmp_path / "pp.db")))
    try:
        m.remember("Outreach mailboxes: aifa@, aifa.team@, aifa.help@ on four outreach domains", kind="fact", importance=0.95, origin="user")
        m.remember("The office cat likes tuna", kind="fact", importance=0.4, origin="user")
        m.remember("Project decision: main domains never send cold email", kind="decision", importance=0.9, origin="user", scope="project:code")
        brief = ark.wake_up_briefing(m, agent="aifa", scope="global", query="music release schedule")
        texts = [p["content"] for p in brief["project_passport"]]
        assert any("Outreach mailboxes" in t for t in texts)
        assert not any("cat likes tuna" in t for t in texts)
        assert not any("main domains" in t for t in texts)   # другая область не попадает в сводку global
        assert "[project_passport]" in brief["fenced_briefing"]
        brief_code = ark.wake_up_briefing(m, agent="aifa", scope="project:code")
        assert any("main domains" in p["content"] for p in brief_code["project_passport"])
        # раздел защищён от сжатия: даже при маленьком бюджете он остаётся
        tiny = ark.wake_up_briefing(m, agent="aifa", scope="global", max_tokens=150)
        assert "project_passport" not in tiny["truncated_sections"]
        monkeypatch.setenv("PADAM_PASSPORT_MIN_IMPORTANCE", "0.99")
        assert ark.wake_up_briefing(m, agent="aifa", scope="global")["project_passport"] == []
    finally:
        m.close()
