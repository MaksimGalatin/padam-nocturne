"""Фаза 2 аудита GLM, SOV-04: settle_paid_order сама требует владельца — не-владелец получает PermissionError."""
import pytest

from padam import freelance_autonomy as fa
from padam.memory import Memory
from padam.roles import ActorContext
from padam.store import Store


def test_не_владелец_не_проводит_оплату(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "s.db"))
    try:
        гость = ActorContext(role="contributor", subject="x", workspace_id="w", via_token=True)
        with pytest.raises(PermissionError):
            fa.settle_paid_order(m, "нет-такого-заказа", paid_usdt=10, actor=гость)
    finally:
        m.close()


def test_владелец_доходит_до_проверки_заказа(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "s.db"))
    try:
        with pytest.raises(Exception) as e:      # гейт пройден, дальше — «заказ не найден»
            fa.settle_paid_order(m, "нет-такого-заказа", paid_usdt=10)
        assert not isinstance(e.value, PermissionError)
    finally:
        m.close()
