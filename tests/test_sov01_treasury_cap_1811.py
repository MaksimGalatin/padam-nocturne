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
