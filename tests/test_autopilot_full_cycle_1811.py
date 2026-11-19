from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time
import urllib.request

from padam import (
    api,
    browser_session,
    digital_stores,
    freelance_autonomy,
    platform_wizard,
)
from padam.memory import Memory
from padam.store import Store


def _make_mem(tmp_path: Path) -> Memory:
    db_path = tmp_path / "autopilot_e2e.db"
    m = Memory(user_id="owner-e2e", store=Store(str(db_path)))
    m.remember("Создаём AI-сайты, аудит доступности WCAG и B2B лидогенерацию", kind="fact")
    return m


def test_all_34_platforms_urls_and_tiers(tmp_path: Path):
    cat = platform_wizard.list_platform_catalog()
    items = cat["platforms"]
    assert len(items) == 34

    tiers = {"autopilot": 0, "assisted_button": 0, "not_available": 0}
    for p in items:
        tiers[p["automation_tier"]] += 1
        assert str(p["signup_url"]).startswith("https://")
        assert str(p["login_url"]).startswith("https://")
        assert "/signup?oauth=google" not in p["signup_url"], f"Устаревший 404 URL у {p['platform_id']}"
        if p["platform_id"] == "lemonsqueezy":
            assert "auth.lemonsqueezy.com" in p["signup_url"]
        if p["platform_id"] == "payhip":
            assert "/auth/register" in p["signup_url"]

    assert tiers == {"autopilot": 6, "assisted_button": 21, "not_available": 7}
    assert "fetch_agentverse" in browser_session.OFFICIAL_PLATFORM_APIS
    assert "freelancer" in browser_session.OFFICIAL_PLATFORM_APIS


def test_google_signup_instant_autopilot_start_via_studio_api(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "test_google_signup_instant_autopilot_start_via_studio_api")
    mem = _make_mem(tmp_path)
    srv, url = api.make_studio_server(memory=mem, port=0)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    base_url, token = url.split("#t=")
    base_api = base_url.rsplit("/studio", 1)[0]

    def _fake_transport(req: dict):
        if req.get("op") == "auth_window":
            return {"ok": True, "status": "session_active", "cookies": {"session_id": "goog_sess_123", "uid": "u99"}}
        return {"ok": True, "sent": True, "status_code": 200}

    platform_wizard.set_browser_session_transport(_fake_transport)
    try:
        body = json.dumps({"action": "signup", "platform_id": "gumroad"}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_api}/api/v2/ark/wizard/action",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            res = json.loads(r.read().decode("utf-8"))

        assert res["ok"] is True
        assert res["status"] == "session_active"
        assert res["password_stored"] is False
        assert res["auto_filled_profile"] is not None
        assert res["autopilot_started"] is True

        # Площадка сразу появилась в freelance_autonomy
        ex = freelance_autonomy.list_exchange_accounts(mem)
        assert any(a["platform"] == "gumroad" and a["status"] == "active" for a in ex)

        # Глобальный автопилот и автопилот площадки включены
        assert platform_wizard.get_platform_autopilot_config(mem, "gumroad")["autopilot_enabled"] is True
        assert freelance_autonomy.get_autopilot_state(mem)["autopilot_running"] is True

        # Остановка автопилота через API останавливает воркер
        stop_req = urllib.request.Request(
            f"{base_api}/api/v2/ark/freelance/action",
            data=json.dumps({"action": "autopilot_stop"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        with urllib.request.urlopen(stop_req, timeout=10) as r:
            st_res = json.loads(r.read().decode("utf-8"))
        assert st_res["autopilot_running"] is False
    finally:
        freelance_autonomy.stop_autopilot_worker()
        platform_wizard.set_browser_session_transport(None)
        srv.shutdown()
        srv.server_close()


def test_full_end_to_end_autopilot_cycle_exchange_and_store(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_FREELANCE_ALLOW_LOCALHOST", "1")
    mem = _make_mem(tmp_path)
    received_bids: list[dict] = []

    class _MockServer(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            if self.path.startswith("/jobs"):
                payload = {
                    "jobs": [
                        {
                            "id": "job-e2e-101",
                            "title": "Build WCAG accessible landing page",
                            "brief": "Create fast accessible landing page for SaaS",
                            "budget_usdt": 350.0,
                            "estimated_tokens": 20000,
                        }
                    ]
                }
            elif self.path.startswith(("/v2/user", "/user")):
                payload = {"success": True, "user": {"name": "CODE Studio", "id": "seller-1"}}
            elif self.path.startswith(("/v2/sales", "/sales")):
                payload = {
                    "success": True,
                    "sales": [
                        {
                            "id": "sale-gum-901",
                            "product_name": "PADAM Memory Pack",
                            "price": 10000,
                            "currency": "usd",
                            "email": "buyer@example.com",
                            "refunded": False,
                        }
                    ],
                }
            else:
                self.send_response(404)
                self.end_headers()
                return
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            ln = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(ln).decode("utf-8") or "{}")
            received_bids.append(body)
            raw = json.dumps({"ok": True, "bid_id": "bid-99"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    mock_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockServer)
    threading.Thread(target=mock_srv.serve_forever, daemon=True).start()
    mock_base = f"http://127.0.0.1:{mock_srv.server_address[1]}"

    def _fake_send_transport(req: dict):
        if req.get("op") == "send_bid":
            received_bids.append(req)
            return {"ok": True, "sent": True, "status_code": 200}
        return {"ok": True}

    platform_wizard.set_browser_session_transport(_fake_send_transport)
    try:
        # 1. Подключаем биржу и магазин + включаем автопилот
        freelance_autonomy.connect_exchange_account(
            mem,
            platform="fetch_agentverse",
            mode="oauth_api",
            oauth_token="tok-e2e-secret-123",
            api_base_url=mock_base,
            account_label="Agentverse Live",
            allow_localhost=True,
        )
        platform_wizard.set_platform_autopilot(mem, platform_id="fetch_agentverse", autopilot_enabled=True, min_pause_s=0.0)
        digital_stores.connect_and_verify_store(
            mem,
            store_type="gumroad",
            api_key="gum-secret-key-123",
            api_base_url=mock_base,
            store_label="Gumroad Store",
            allow_localhost=True,
        )
        freelance_autonomy.set_autopilot_state(mem, running=True, interval_s=30.0)

        # 2. Запускаем полный цикл автопилота
        cycle = freelance_autonomy.run_autopilot_cycle(mem, allow_localhost=True)
        assert cycle["ok"] is True
        assert cycle["accounts_polled"] >= 1
        assert cycle["accepted_orders"] >= 1
        assert cycle["stores_synced"] >= 1
        assert cycle["stores_sales_accepted"] >= 1
        assert cycle["bids_dispatched"] >= 1
        assert cycle["orders_executed"] >= 1
        assert cycle["deliveries_packaged"] >= 1
        assert len(received_bids) >= 1

        # 3. Проверяем, что продажа магазина и заказ биржи дошли до конца без утечек
        orders = freelance_autonomy.list_orders(mem, limit=20)
        delivered = [o for o in orders if o["platform"] == "fetch_agentverse" and o["status"] == "delivered"]
        assert len(delivered) == 1
        assert "tok-e2e-secret-123" not in str(delivered[0].get("delivery_redacted") or "")

        ps = freelance_autonomy.payout_summary(mem)
        assert float(ps["held_14d_usdt"]) + float(ps["releasable_usdt"]) > 0.0
    finally:
        freelance_autonomy.stop_autopilot_worker()
        platform_wizard.set_browser_session_transport(None)
        mock_srv.shutdown()
        mock_srv.server_close()


def test_studio_wizard_ui_playwright_1280_and_390(tmp_path: Path):
    from playwright.sync_api import sync_playwright

    mem = _make_mem(tmp_path)
    srv, url = api.make_studio_server(memory=mem, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            for vp in ({"width": 1280, "height": 800}, {"width": 390, "height": 844}):
                page = browser.new_page(viewport=vp)
                js_errs = []
                page.on("pageerror", lambda e: js_errs.append(str(e)))
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(1200)
                ov = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                assert js_errs == [], f"JS errors on {vp}: {js_errs}"
                assert ov <= 2, f"Horizontal overflow {ov}px on {vp}"
                page.close()
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
