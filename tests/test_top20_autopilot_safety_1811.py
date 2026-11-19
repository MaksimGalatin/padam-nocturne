# -*- coding: utf-8 -*-
"""ТОП-20 Сестры, п. 8, 10, 12: режим симуляции автопилота, потолок одной ставки, «СТОП ВСЁ»."""
import pytest

from padam import email_autonomy, freelance_autonomy, platform_wizard
from padam.memory import Memory
from padam.roles import ActorContext
from padam.store import Store


def _mem(tmp_path):
    return Memory(user_id="u", store=Store(tmp_path / "t20.db"))


def test_потолок_ставки_и_симуляция(tmp_path, monkeypatch):
    m = _mem(tmp_path)
    отправлено = []
    platform_wizard.set_browser_session_transport(lambda req: (отправлено.append(req), {"status_code": 200, "sent": True})[1])
    try:
        platform_wizard.set_platform_autopilot(m, platform_id="upwork", autopilot_enabled=True, daily_bid_limit=10, min_pause_s=0.0)
        monkeypatch.setenv("PADAM_AUTOPILOT_MAX_BID_USDT", "500")
        дорого = platform_wizard.dispatch_platform_autopilot_action(m, platform_id="upwork", title="Big", budget_usdt=900.0)
        assert дорого["sent"] is False and дорого["status"] == "bid_over_ceiling_needs_owner"
        assert not отправлено

        platform_wizard.set_autopilot_simulation(m, True)
        сим = platform_wizard.dispatch_platform_autopilot_action(m, platform_id="upwork", title="Sim", budget_usdt=250.0)
        assert сим["status"] == "simulated" and сим["sent"] is False
        assert not отправлено                               # наружу ничего не ушло
        сводка = platform_wizard.autopilot_simulation_report(m)
        assert сводка["would_send_bids"] == 1 and сводка["would_bid_usdt"] == 250.0

        агент = ActorContext(role="member", subject="agent-x", workspace_id="w")
        with pytest.raises(PermissionError):                # выйти из симуляции в бой может только владелец
            platform_wizard.set_autopilot_simulation(m, False, actor=агент)
    finally:
        platform_wizard.set_browser_session_transport(None)


def test_стоп_всё(tmp_path):
    m = _mem(tmp_path)
    email_autonomy.set_mail_transport(lambda req: {"ok": True})
    try:
        platform_wizard.set_platform_autopilot(m, platform_id="upwork", autopilot_enabled=True)
        email_autonomy.connect_mail_account(m, email="box@code.test", provider="gmail", app_password_or_token="s", daily_limit=10)
        freelance_autonomy.set_autopilot_state(m, running=True)
        агент = ActorContext(role="member", subject="agent-x", workspace_id="w")
        with pytest.raises(PermissionError):
            freelance_autonomy.stop_everything(m, actor=агент)
        r = freelance_autonomy.stop_everything(m)
        assert r["ok"] and r["platform_autopilots_disabled"] == 1 and r["mailboxes_paused"] == 1
        assert freelance_autonomy.get_autopilot_state(m)["autopilot_running"] in (0, False)
        assert platform_wizard.get_platform_autopilot_config(m, "upwork")["autopilot_enabled"] is False
    finally:
        email_autonomy.set_mail_transport(None)
