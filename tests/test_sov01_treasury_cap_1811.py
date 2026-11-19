"""Фаза 2 аудита GLM, SOV-01: суточный предел казны действует и при прямом вызове execute_topup."""
import pytest

from padam import sovereign_ops as so


def test_прямые_вызовы_не_обходят_сутки(monkeypatch):
    monkeypatch.setenv("PADAM_TREASURY_AUTOPAY", "1")
    monkeypatch.setenv("PADAM_TREASURY_DAILY_CAP_USDT", "25")
    monkeypatch.setattr(so, "locks_status", lambda: {"treasury_autopay_locked": False})
    tm = so.TreasuryComputeManager()
    tm._transfer_fn = lambda req: {"simulated": True}
    tm.execute_topup(provider="p", amount_usdt=20, idempotency_key="k1", owner_confirmed=True)
    with pytest.raises(ValueError, match="Daily treasury cap"):
        tm.execute_topup(provider="p", amount_usdt=20, idempotency_key="k2", owner_confirmed=True)


def test_перезапуск_не_обнуляет_сутки(monkeypatch):
    """Аудит фазы 3, FA-06: новый экземпляр менеджера (как после перезапуска) видит прежние пополнения."""
    monkeypatch.setenv("PADAM_TREASURY_AUTOPAY", "1")
    monkeypatch.setenv("PADAM_TREASURY_DAILY_CAP_USDT", "25")
    monkeypatch.setattr(so, "locks_status", lambda: {"treasury_autopay_locked": False})
    первый = so.TreasuryComputeManager()
    первый._transfer_fn = lambda req: {"simulated": True}
    первый.execute_topup(provider="p", amount_usdt=20, idempotency_key="r1", owner_confirmed=True)
    второй = so.TreasuryComputeManager()
    второй._transfer_fn = lambda req: {"simulated": True}
    with pytest.raises(ValueError, match="Daily treasury cap"):
        второй.execute_topup(provider="p", amount_usdt=20, idempotency_key="r2", owner_confirmed=True)
