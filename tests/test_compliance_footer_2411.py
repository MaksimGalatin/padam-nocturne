"""Подпись CAN-SPAM в первом письме (24.11.2026, AIfa).

Раньше подпись с почтовым адресом пропускалась, если в тексте где угодно встречалось «STOP» («nonstop»,
«unstoppable»), и письмо уходило без адреса отправителя. И адрес был вшит один на всех пользователей PADAM.
"""
from __future__ import annotations

from pathlib import Path

from padam import email_autonomy
from padam.memory import Memory
from padam.store import Store


def _send(tmp_path: Path, body: str, domain: str) -> str:
    mem = Memory(user_id="owner-footer", store=Store(str(tmp_path / "footer.db")))
    sent: list[dict] = []

    def _fake(req: dict):
        if req.get("op") == "send":
            sent.append(req)
        return {"ok": True}

    email_autonomy.set_mail_transport(_fake)
    try:
        acc = email_autonomy.connect_mail_account(
            mem, email="box@example.org", provider="gmail", app_password_or_token="app-pass-test-0000", daily_limit=30
        )
        assert acc["ok"]
        res = email_autonomy.send_outreach_email(
            mem, to_email=f"owner@{domain}", domain=domain, subject="Hello", body=body,
            stop_file_path=tmp_path / "stop.txt",
        )
        assert res["ok"], res
    finally:
        email_autonomy.set_mail_transport(None)
    assert sent, "письмо не ушло"
    return str(sent[-1].get("body") or sent[-1].get("text") or sent[-1])


def test_footer_added_even_if_body_mentions_stop(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("PADAM_SENDER_POSTAL_ADDRESS", raising=False)
    monkeypatch.delenv("PADAM_SENDER_COMPANY", raising=False)
    out = _send(tmp_path, "Our nonstop, unstoppable scanner found 3 issues.", "nonstop-test.com")
    assert "1209 Mountain Road Pl NE" in out
    assert "Reply STOP to unsubscribe" in out


def test_footer_uses_owner_settings(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_SENDER_COMPANY", "Example Studio Inc.")
    monkeypatch.setenv("PADAM_SENDER_POSTAL_ADDRESS", "42 Test Street, Springfield, IL 62701, USA")
    out = _send(tmp_path, "Hello from a different PADAM owner.", "owner-settings-test.com")
    assert "Example Studio Inc. · 42 Test Street, Springfield, IL 62701, USA" in out
    assert "1209 Mountain Road" not in out


def test_footer_not_duplicated(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("PADAM_SENDER_POSTAL_ADDRESS", raising=False)
    monkeypatch.delenv("PADAM_SENDER_COMPANY", raising=False)
    body = "Hi.\n\n" + email_autonomy.compliance_footer()
    out = _send(tmp_path, body, "no-dup-test.com")
    assert out.count("1209 Mountain Road Pl NE") == 1
