"""0.4.1: PADAM_MCP_REVIEW_ALL=1 — каждая запись агента ждёт владельца, какую бы пометку источника он ни поставил.

Совет внешнего разбора 09.11.2026: пометку origin ставит сам агент, и агент, который врёт о происхождении текста,
обходит PADAM_HOLD_EXTERNAL. Проверить источник сервер MCP не может; эта граница от пометки не зависит.
"""

from padam import config
from padam.memory import Memory
from padam.store import Store


def test_review_all_holds_every_agent_write_whatever_the_label(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MCP_REVIEW_ALL", True)
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    for origin in ("agent", "user", "external"):
        исход, _ = m.remember(f"Обычная заметка о проекте, метка {origin}", kind="fact", origin=origin, guarded=True)
        assert исход == "quarantined", origin
    # Владелец из консоли (guarded=False) пишет как прежде.
    исход, _ = m.remember("Запись владельца из консоли", kind="fact")
    assert исход == "created"
    assert len(m.quarantined()) == 3
    assert all("метка" not in r.content for r in m.recall("заметка о проекте"))
    m.close()


def test_off_by_default_an_ordinary_agent_note_is_stored(tmp_path):
    assert config.MCP_REVIEW_ALL is False
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    исход, _ = m.remember("Сборка проекта проходит за 40 секунд", kind="fact", origin="agent", guarded=True)
    assert исход == "created"
    m.close()
