# -*- coding: utf-8 -*-
"""Комиссия CODE 18.11.2026: 15 % когда отправляет человек, 20 % на автопилоте; ставка запоминается в заказе."""
import pytest

from padam import freelance_autonomy as fa
from padam.memory import Memory
from padam.store import Store


def test_две_ставки(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "f.db"))
    a = fa.evaluate_and_ingest_job(m, platform="fiverr_desk", title="A", brief="Clean python CLI", budget_usdt=300.0,
                                   estimated_hours=6, hourly_rate_usdt=40)
    assert a["platform_fee_pct"] == 15.0 and a["total_fee_pct"] == 35.0          # Fiverr 20 % + наши 15 %
    assert a["net_after_fees_usdt"] == pytest.approx(300 * 0.65 - 0.05, abs=0.01)  # 194.95
    b = fa.evaluate_and_ingest_job(m, platform="custom_webhook", title="B", brief="Clean python CLI", budget_usdt=300.0,
                                   estimated_hours=6, hourly_rate_usdt=40, work_mode="autopilot")
    assert b["platform_fee_pct"] == 20.0 and b["total_fee_pct"] == 20.0
    sb = fa.settle_paid_order(m, b["order_id"], paid_usdt=300.0, agent_share_pct=10.0)
    assert sb["monetization"]["platform_fee_pct"] == 20.0 and sb["monetization"]["platform_fee_usdt"] == pytest.approx(60.0)
    sa = fa.settle_paid_order(m, a["order_id"], paid_usdt=300.0, agent_share_pct=10.0)
    assert sa["monetization"]["platform_fee_usdt"] == pytest.approx(45.0)
    with pytest.raises(ValueError):
        fa.evaluate_and_ingest_job(m, title="C", brief="Clean python CLI", budget_usdt=10.0, work_mode="turbo")
    assert fa.fee_pct_for_mode() == 15.0 and fa.fee_pct_for_mode("autopilot") == 20.0


def test_казна_агента_от_реального_остатка_и_старые_заказы(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "g.db"))
    b = fa.monetization_breakdown(100.0, fee_pct=15.0, agent_share_pct=50.0)
    assert b["effective_gross_agent_pct"] == pytest.approx(42.5)   # 85 % × 50 %, а не зашитые 90 %
    j = fa.evaluate_and_ingest_job(m, title="Old", brief="Clean python CLI", budget_usdt=100.0)
    m.store.conn.execute("UPDATE ark_freelance_order SET platform_fee_pct = 10.0 WHERE order_id = ?", (j["order_id"],))
    m.store.conn.commit()
    s = fa.settle_paid_order(m, j["order_id"], paid_usdt=100.0, agent_share_pct=10.0)
    assert s["monetization"]["platform_fee_pct"] == 10.0          # заказ, оценённый при 10 %, и оплачивается по 10 %


def test_общая_память_для_настольного_приложения(tmp_path, monkeypatch):
    import json as _json
    from padam import api
    db = tmp_path / "family.db"
    Memory(user_id="aifa", store=Store(db)).remember("Shared family fact", kind="fact", origin="user")
    (tmp_path / "PADAM Studio").mkdir()
    (tmp_path / "PADAM Studio" / "shared_memory.json").write_text(_json.dumps({"db": str(db), "user": "aifa"}), encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.delenv("PADAM_USER", raising=False)
    monkeypatch.delenv("PADAM_DB", raising=False)
    monkeypatch.delenv("PADAM_DESKTOP_EXE", raising=False)
    assert api._desktop_shared_memory() == {}                      # не окно приложения — файл не читается
    monkeypatch.setenv("PADAM_DESKTOP_EXE", "padam-studio-desktop.exe")
    assert api._desktop_shared_memory() == {"db": str(db), "user": "aifa"}
    prev = dict(api._state)
    api._state["memory"] = None
    try:
        m = api.mem()
        assert m.user_id == "aifa" and str(m.store.path) == str(db) and m.stats()["active"] == 1
        api._state["memory"] = None
        monkeypatch.setenv("PADAM_USER", "other")                  # явная переменная сильнее файла
        assert api.mem().user_id == "other"
    finally:
        api._state.clear(); api._state.update(prev)
