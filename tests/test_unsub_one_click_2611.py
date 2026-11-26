"""Отписка в один клик (26.11.2026, CAN-SPAM + RFC 8058).

Ссылка с подписью HMAC в каждом письме рассылки, заголовки List-Unsubscribe и List-Unsubscribe-Post,
отказы со страницы отписки забираются в стоп-лист ДО отправки, а без свежего списка письмо не уходит.
"""
from __future__ import annotations

import hashlib
import hmac
import urllib.parse
from pathlib import Path

import pytest

from padam import email_autonomy as ea
from padam.memory import Memory
from padam.store import Store


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("PADAM_UNSUB_BASE_URL", "https://example.org/api/unsubscribe")
    monkeypatch.setenv("PADAM_UNSUB_SECRET", "test-secret-0000")
    monkeypatch.delenv("PADAM_UNSUB_LIST_URL", raising=False)
    monkeypatch.delenv("PADAM_UNSUB_SERVICE_KEY", raising=False)
    ea._REMOTE_STOP_SYNC_AT = 0.0
    yield


def _mem(tmp_path: Path) -> Memory:
    return Memory(user_id="owner-unsub", store=Store(str(tmp_path / "unsub.db")))


def _send(mem: Memory, tmp_path: Path, to: str, domain: str, body: str = "Hello"):
    sent: list[dict] = []
    ea.set_mail_transport(lambda req: (sent.append(req) or {"ok": True}) if req.get("op") == "send" else {"ok": True})
    try:
        if not ea.list_mail_accounts(mem):
            assert ea.connect_mail_account(mem, email="box@example.org", provider="gmail",
                                           app_password_or_token="app-pass-test-0000", daily_limit=30)["ok"]
        res = ea.send_outreach_email(mem, to_email=to, domain=domain, subject="Hi", body=body,
                                     stop_file_path=tmp_path / "stop.txt")
    finally:
        ea.set_mail_transport(None)
    return res, sent


def test_no_link_without_settings(monkeypatch):
    monkeypatch.delenv("PADAM_UNSUB_BASE_URL", raising=False)
    monkeypatch.delenv("PADAM_UNSUB_SECRET", raising=False)
    assert ea.unsubscribe_url("a@b.com", "b.com") == ""


def test_link_signature_matches_server_formula(env):
    url = ea.unsubscribe_url("Owner@Shop.COM", "https://Shop.com/page")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert q["e"] == "owner@shop.com" and q["d"] == "shop.com"
    # Та же формула, что в aifa.works lib/outreach-optout.ts: HMAC-SHA256("почта|домен")[:32]
    good = hmac.new(b"test-secret-0000", b"owner@shop.com|shop.com", hashlib.sha256).hexdigest()[:32]
    assert q["s"] == good


def test_first_email_has_link_and_header(tmp_path, env):
    mem = _mem(tmp_path)
    res, sent = _send(mem, tmp_path, "owner@shop.com", "shop.com")
    assert res["ok"], res
    body = sent[-1]["body"]
    link = sent[-1]["unsub_url"]
    assert link.startswith("https://example.org/api/unsubscribe?")
    assert f"Unsubscribe in one click: {link}" in body
    assert "Reply STOP" in body and "Albuquerque" in body   # CAN-SPAM: адрес и второй способ отписки остаются


def test_placeholder_is_filled(tmp_path, env):
    mem = _mem(tmp_path)
    res, sent = _send(mem, tmp_path, "owner@shop.com", "shop.com", body="Text. Unsubscribe: {UNSUB_URL}")
    assert res["ok"], res
    assert "{UNSUB_URL}" not in sent[-1]["body"] and sent[-1]["unsub_url"] in sent[-1]["body"]


def test_remote_optout_blocks_and_sync_failure_blocks(tmp_path, env, monkeypatch):
    mem = _mem(tmp_path)
    monkeypatch.setenv("PADAM_UNSUB_LIST_URL", "https://example.org/api/unsubscribe/list")
    monkeypatch.setenv("PADAM_UNSUB_SERVICE_KEY", "svc-key")

    class _R:
        status = 200
        def __init__(self, data): self.data = data
        def read(self): return self.data
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(ea.net_guard, "safe_urlopen",
                        lambda req, **kw: _R(b'{"count":1,"items":[{"email":"gone@shop.com","domain":"shop.com"}]}'))
    res, sent = _send(mem, tmp_path, "gone@shop.com", "shop.com")
    assert res.get("blocked") and "stop_list" in res["reason"] and not sent

    # список недоступен — письмо не уходит
    ea._REMOTE_STOP_SYNC_AT = 0.0

    def _boom(req, **kw):
        raise OSError("network down")

    monkeypatch.setattr(ea.net_guard, "safe_urlopen", _boom)
    res2, sent2 = _send(mem, tmp_path, "new@other.com", "other.com")
    assert res2.get("blocked") and res2["reason"] == "stop_list_sync_failed" and not sent2


def test_report_link_from_service_scan(tmp_path, env, monkeypatch):
    """Номер отчёта: служебная проверка на стороне владельца → ссылка в письме; без настроек — честный текст."""
    assert ea.free_report_url("shop.com") == ""          # не настроено — пусто
    monkeypatch.setenv("PADAM_OUTREACH_SCAN_URL", "https://example.org/api/scan")
    monkeypatch.setenv("PADAM_OUTREACH_SERVICE_KEY", "svc")

    class _R:
        status = 200
        def __init__(self, data): self.data = data
        def read(self): return self.data
        def __enter__(self): return self
        def __exit__(self, *a): return False

    seen = {}

    def _fake(req, **kw):
        seen["hdr"] = req.get_header("X-outreach-key")
        return _R(b'{"scanId":"7073-1A7F-EF60-2D21","engine":"deterministic-only"}')

    monkeypatch.setattr(ea.net_guard, "safe_urlopen", _fake)
    assert ea.free_report_url("https://Shop.com/") == "https://example.org/api/scan/report?id=7073-1A7F-EF60-2D21"
    assert seen["hdr"] == "svc"
    mem = _mem(tmp_path)
    res, sent = _send(mem, tmp_path, "owner@shop.com", "shop.com", body="Free:\n• {REPORT_BULLET};\nBye")
    assert res["ok"], res
    assert "your report, kept under its own number: https://example.org/api/scan/report?id=7073-1A7F-EF60-2D21" in sent[-1]["body"]
