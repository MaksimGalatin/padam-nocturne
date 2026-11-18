from __future__ import annotations

import json
from pathlib import Path
import threading
import time

import pytest

from padam import coop_broker, family_feeds, freelance_autonomy, mcp_server, platform_wizard
from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store


def test_one_click_google_signup_and_login_zero_password_leak(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    mem = Memory(user_id="s3_auth_u", store=Store(str(tmp_path / "s3_auth.db")))
    prev_mem = mcp_server._memory
    mcp_server._memory = mem
    calls_log: list[dict] = []

    def fake_browser_transport(req: dict) -> dict:
        calls_log.append(req)
        # Имитируем возврат кук из окна браузера + проверяем, что даже если сайт вернул поле password, мы его вычистим!
        return {
            "cookies": {
                "session_token": f"tok_{req['platform_id']}_{req['action']}",
                "oauth_provider": "google" if req["action"] == "signup_google" else "direct",
                "password": "SUPER_SECRET_USER_PASSWORD_NEVER_STORE",
                "login_password": "SUPER_SECRET_USER_PASSWORD_NEVER_STORE",
            }
        }

    platform_wizard.set_browser_session_transport(None)
    try:
        # 0. БЕЗ транспорта (и с отключённым реальным браузером в тестах — сеть 0) НИКАКОЙ выдуманной куки и session_active НЕТ!
        no_tr = platform_wizard.one_click_platform_auth(mem, platform_id="upwork", action="signup")
        assert no_tr["ok"] is False
        assert no_tr["connected"] is False
        assert no_tr["status"] == "awaiting_login"
        assert no_tr["status_label_ru"] == "ожидает входа"
        assert no_tr["session_fingerprint"] == ""

        platform_wizard.set_browser_session_transport(fake_browser_transport)
        # 1. Прямая передача пароля строго запрещена
        with pytest.raises(ValueError, match="ПАРОЛИ НЕ ХРАНИМ НИКОГДА"):
            platform_wizard.one_click_platform_auth(mem, platform_id="upwork", action="login", password="my_password")

        # 2. Вызов через MCP padam_platform_connect(action="signup"|"login", platform_id)
        r_sig = mcp_server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "padam_platform_connect", "arguments": {"action": "signup", "platform_id": "upwork"}},
        })["result"]
        assert r_sig.get("isError") is False
        sig_data = json.loads(r_sig["content"][0]["text"])
        assert sig_data["ok"] is True
        assert sig_data["auth_flow"] == "signup_google"
        assert sig_data["password_stored"] is False
        assert sig_data["session_fingerprint"].startswith("sha256:")
        assert sig_data["browser_profile_dir"] == "padam_browser_profile/upwork"
        assert len(sig_data["missing_questions"]) == 6

        # После заполнения анкеты повторный вход сразу видит 0 недостающих вопросов и сам заполняет профиль по сессии
        platform_wizard.submit_questionnaire_and_build_profile_draft(
            mem,
            platform_id="upwork",
            specializations="AI Websites, Lead Lists, WCAG Audits",
            hourly_rate_usdt=45.0,
            min_order_usdt=150.0,
            languages="ru, en",
            tone="деловой",
            excluded_topics="казино",
        )
        r_log = mcp_server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "padam_platform_connect", "arguments": {"action": "login", "platform_id": "upwork"}},
        })["result"]
        log_data = json.loads(r_log["content"][0]["text"])
        assert log_data["auth_flow"] == "login"
        assert log_data["missing_questions"] == []
        assert log_data["auto_filled_profile"] is not None

        # 3. Проверяем, что пароль НИГДЕ не записан (ни в БД, ни в расшифрованной сессии, ни в аудите, ни в Офисе)
        conn = mem.store.conn
        rows = conn.execute(
            "SELECT credential_enc, session_fingerprint, status FROM ark_platform_wizard_connection WHERE status = 'session_active'"
        ).fetchall()
        assert len(rows) == 2
        for r in rows:
            enc = str(r["credential_enc"])
            assert enc.startswith("aesgcm1:")
            assert "SUPER_SECRET_USER_PASSWORD_NEVER_STORE" not in enc
            unsealed = freelance_autonomy._unseal_secret(mem, enc)
            assert "SUPER_SECRET_USER_PASSWORD_NEVER_STORE" not in unsealed
            assert "tok_upwork_" in unsealed

        db_bytes = (tmp_path / "s3_auth.db").read_bytes()
        assert b"SUPER_SECRET_USER_PASSWORD_NEVER_STORE" not in db_bytes

        office_items = family_feeds.read(mem, "office", limit=10)
        assert any("upwork" in it["content"].lower() and "sha256:" in it["content"] for it in office_items)
        for it in office_items:
            assert "SUPER_SECRET_USER_PASSWORD_NEVER_STORE" not in it["content"]
    finally:
        platform_wizard.set_browser_session_transport(None)
        mcp_server._memory = prev_mem
        mem.close()


def test_full_autopilot_toggle_limits_pause_429_captcha_and_paid_guard(tmp_path: Path):
    mem = Memory(user_id="s3_ap_u", store=Store(str(tmp_path / "s3_ap.db")))
    sent_bids: list[dict] = []
    next_transport_reply: dict = {"status_code": 200, "captcha": False}

    def fake_transport(req: dict) -> dict:
        if req.get("op") == "send_bid":
            sent_bids.append(req)
            return dict(next_transport_reply)
        return {}

    platform_wizard.set_browser_session_transport(fake_transport)
    try:
        # 1. По умолчанию автопилот выключен (15% черновик и кнопка), предупреждение о правилах на месте
        cfg0 = platform_wizard.get_platform_autopilot_config(mem, "upwork")
        assert cfg0["autopilot_enabled"] is False
        assert cfg0["code_fee_pct"] == 15.0
        assert cfg0["forbids_bots"] is True
        assert cfg0["bot_warning_ru"] == "правила площадки запрещают автоматику, риск блокировки аккаунта"
        assert cfg0["bot_warning_url"].startswith("https://")

        # При выключенном автопилоте отклик НЕ уходит наружу
        t0 = 1_795_000_000.0
        d_off = platform_wizard.dispatch_platform_autopilot_action(
            mem, platform_id="upwork", title="Job Off", brief="Build site", budget_usdt=250.0, now_ts=t0
        )
        assert d_off["sent"] is False
        assert d_off["status"] == "bid_draft"
        assert d_off["code_fee_pct"] == 15.0
        assert len(sent_bids) == 0

        # 2. Включаем автопилот (20%), ставим суточный лимит 2 отклика и паузу 30с
        cfg_on = platform_wizard.set_platform_autopilot(
            mem, platform_id="upwork", autopilot_enabled=True, daily_bid_limit=2, min_pause_s=30.0
        )
        assert cfg_on["autopilot_enabled"] is True
        assert cfg_on["code_fee_pct"] == 20.0

        # 3. Платное действие без «да» владельца на сумму блокируется
        d_paid_block = platform_wizard.dispatch_platform_autopilot_action(
            mem, platform_id="upwork", title="Paid Boost Job", brief="Needs paid connects",
            budget_usdt=300.0, paid_action_cost_usdt=12.0, owner_approved_paid_usdt=0.0, now_ts=t0 + 10
        )
        assert d_paid_block["sent"] is False
        assert d_paid_block["status"] == "blocked_paid_action_requires_owner_yes"
        assert len(sent_bids) == 0

        # 4. БЕЗ живого транспорта даже при включённом автопилоте отклик НЕ помечается отправленным ('ready_to_send', sent=False)
        platform_wizard.set_browser_session_transport(None)
        d_no_tr = platform_wizard.dispatch_platform_autopilot_action(
            mem, platform_id="upwork", title="No Transport Job", brief="Next.js site", budget_usdt=350.0, now_ts=t0 + 20
        )
        assert d_no_tr["sent"] is False
        assert d_no_tr["status"] == "ready_to_send"
        assert d_no_tr["reason"] == "нет живой сессии/транспорта"
        assert d_no_tr["bids_sent_today"] == 0

        # Подключаем транспорт и отправляем первый бесплатный отклик на автопилоте (комиссия 20%)
        platform_wizard.set_browser_session_transport(fake_transport)
        d1 = platform_wizard.dispatch_platform_autopilot_action(
            mem, platform_id="upwork", title="Job 1", brief="Next.js site", budget_usdt=400.0, now_ts=t0 + 40
        )
        assert d1["sent"] is True and d1["status"] == "bid_placed"
        assert d1["code_fee_pct"] == 20.0 and d1["bids_sent_today"] == 1
        assert len(sent_bids) == 1

        # 5. Пауза между откликами: через 5с (< 30с) отклик не уходит
        d_pause = platform_wizard.dispatch_platform_autopilot_action(
            mem, platform_id="upwork", title="Job Pause", brief="Next.js site", budget_usdt=400.0, now_ts=t0 + 45
        )
        assert d_pause["sent"] is False and d_pause["status"] == "cooldown_pause_active"
        assert len(sent_bids) == 1

        # 6. Второй отклик после паузы (через 35с) уходит
        d2 = platform_wizard.dispatch_platform_autopilot_action(
            mem, platform_id="upwork", title="Job 2", brief="Next.js site", budget_usdt=400.0, now_ts=t0 + 80
        )
        assert d2["sent"] is True and d2["bids_sent_today"] == 2
        assert len(sent_bids) == 2

        # 7. Третий отклик в те же сутки блокируется суточным лимитом (daily_bid_limit=2)
        d_lim = platform_wizard.dispatch_platform_autopilot_action(
            mem, platform_id="upwork", title="Job 3", brief="Next.js site", budget_usdt=400.0, now_ts=t0 + 120
        )
        assert d_lim["sent"] is False and d_lim["status"] == "daily_limit_reached"
        assert len(sent_bids) == 2

        # 8. Проверка стопа при капче / 429 (на площадке kwork): капчу НИКОГДА не обходим, ставим задачу владельцу и пишем в Офис
        platform_wizard.set_platform_autopilot(mem, platform_id="kwork", autopilot_enabled=True, daily_bid_limit=5, min_pause_s=10.0)
        next_transport_reply = {"status_code": 200, "captcha": True}
        d_cap = platform_wizard.dispatch_platform_autopilot_action(
            mem, platform_id="kwork", title="Kwork Job", brief="Make landing", budget_usdt=150.0, now_ts=t0 + 200
        )
        assert d_cap["sent"] is False
        assert d_cap["status"] == "halted_on_guard"
        assert d_cap["halted_reason"] == "captcha_required"
        assert d_cap["captcha_bypassed"] is False
        assert platform_wizard.get_platform_autopilot_config(mem, "kwork")["autopilot_enabled"] is False
        tasks = coop_broker.list_tasks(mem)
        assert any("kwork" in str(t.get("title") or "").lower() or "captcha" in str(t.get("title") or "").lower() for t in tasks)
    finally:
        platform_wizard.set_browser_session_transport(None)
        mem.close()


def test_sample_10pct_paid_milestone_vs_free_sample_and_zero_charge_on_reject(tmp_path: Path):
    mem = Memory(user_id="s3_smp_u", store=Store(str(tmp_path / "s3_smp.db")))
    try:
        # 1. На Upwork / Fiverr / Kwork / FL.ru образец 10% оформляется как ПЕРВЫЙ ОПЛАЧИВАЕМЫЙ ЭТАП (paid_milestone_10pct)
        ord_upw = freelance_autonomy.evaluate_and_ingest_job(
            mem, platform="upwork", title="Upwork SaaS Portal", brief="Build SaaS portal", budget_usdt=500.0
        )
        smp_upw = platform_wizard.prepare_10pct_sample(mem, ord_upw["order_id"])
        assert smp_upw["sample_stage"] == "sample"
        assert smp_upw["sample_mode"] == "paid_milestone_10pct"
        assert smp_upw["requires_paid_milestone"] is True
        assert smp_upw["milestone_10pct_usdt"] == 50.0
        assert smp_upw["rules_url"].startswith("https://")

        # Образец принят -> весь заказ
        acc_upw = platform_wizard.accept_10pct_sample(mem, ord_upw["order_id"])
        assert acc_upw["transition"] == ["sample", "accepted", "full_order"]
        assert acc_upw["sample_stage"] == "full_order"
        assert acc_upw["status"] == "in_progress"

        # 2. На бирже для агентов (olas_mech) — демонстрационный образец 10%, а при отказе заказ закрывается БЕЗ начислений ($0)
        ord_olas = freelance_autonomy.evaluate_and_ingest_job(
            mem, platform="olas_mech", title="Agent Task", brief="Run data pipeline", budget_usdt=200.0, work_mode="autopilot"
        )
        smp_olas = platform_wizard.prepare_10pct_sample(mem, ord_olas["order_id"])
        assert smp_olas["sample_mode"] == "free_sample_10pct"
        assert smp_olas["requires_paid_milestone"] is False

        rej_olas = platform_wizard.reject_10pct_sample(mem, ord_olas["order_id"], reason="Клиент передумал")
        assert rej_olas["sample_stage"] == "rejected"
        assert rej_olas["status"] == "closed_no_charge"
        assert rej_olas["accrued_usdt"] == 0.0

        snap = freelance_autonomy.freelance_dashboard_snapshot(mem)
        assert snap["monetization_totals"]["total_gross_usdt"] == 0.0
        assert snap["agent_ledger"]["entries"] == []
    finally:
        mem.close()


def test_official_freelancer_api_and_browser_session_no_network_in_tests(tmp_path: Path, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from padam import browser_session

    # 1. В тестах настоящий интерактивный браузер не запускается (сеть 0)
    res_real = browser_session.run_interactive_browser_auth(
        platform_id="upwork",
        action="login",
        target_url="https://www.upwork.com/ab/account-security/login",
        profile_dir="padam_browser_profile/upwork",
        timeout_s=5.0,
    )
    assert res_real["ok"] is False
    assert res_real["status"] == "awaiting_login"
    assert "сеть 0" in res_real["error"]

    # 2. Локальный mock-сервер официального API Freelancer.com: whoami, search_jobs и place_bid
    received_headers: list[dict] = []

    class _FlHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):  # noqa: N802
            received_headers.append(dict(self.headers))
            if self.path.startswith("/users/0.1/self/"):
                body = json.dumps({"status": "success", "result": {"id": 777, "username": "code_aifa"}}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.startswith("/projects/0.1/projects/active/"):
                body = json.dumps({"status": "success", "result": {"projects": [{"id": 901, "title": "Next.js AI Site"}]}}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):  # noqa: N802
            received_headers.append(dict(self.headers))
            if self.path.startswith("/projects/0.1/bids/"):
                body = json.dumps({"status": "success", "result": {"id": 5001}}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FlHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base_u = f"http://127.0.0.1:{srv.server_address[1]}"
    mem = Memory(user_id="s3_fl_u", store=Store(str(tmp_path / "s3_fl.db")))
    try:
        platform_wizard.connect_platform_step(
            mem, platform_id="freelancer", auth_method="oauth", token_or_session="fl_oauth_tok_123"
        )
        r_who = platform_wizard.official_platform_api_action(
            mem, platform_id="freelancer", op="whoami", api_base_url=base_u, allow_localhost=True
        )
        assert r_who["ok"] is True
        assert r_who["data"]["result"]["username"] == "code_aifa"

        r_jobs = platform_wizard.official_platform_api_action(
            mem, platform_id="freelancer", op="search_jobs", query="Next.js", api_base_url=base_u, allow_localhost=True
        )
        assert r_jobs["ok"] is True
        assert len(r_jobs["data"]["result"]["projects"]) == 1

        r_bid = platform_wizard.official_platform_api_action(
            mem, platform_id="freelancer", op="place_bid", project_id="901", bid_amount_usdt=300.0,
            pitch_text="Ready to build", api_base_url=base_u, allow_localhost=True
        )
        assert r_bid["ok"] is True, r_bid  # диагностика: печатать ответ при сбое

        # На Upwork place_bid по API запрещён (возвращает ready_to_send)
        r_upw_bid = platform_wizard.official_platform_api_action(
            mem, platform_id="upwork", op="place_bid", token="upw_tok", api_base_url=base_u, allow_localhost=True
        )
        assert r_upw_bid["ok"] is False
        assert r_upw_bid["status"] == "ready_to_send"
    finally:
        srv.shutdown()
        srv.server_close()
        mem.close()


def test_studio_stage3_playwright_1280_and_390(tmp_path: Path):
    pw = pytest.importorskip("playwright.sync_api")
    mem = Memory(user_id="s3_ui_u", store=Store(str(tmp_path / "s3_ui.db")))
    srv_api = None
    t_api = None
    platform_wizard.set_browser_session_transport(
        lambda req: {"cookies": {"session_id": f"ui_cookie_{req.get('platform_id', 'upwork')}"}}
    )
    try:
        # Создадим заказ для проверки кнопок образца 10% в Studio
        freelance_autonomy.evaluate_and_ingest_job(
            mem, platform="upwork", title="UI Milestone Order", brief="Build AI landing page", budget_usdt=400.0
        )
        srv_api, url = make_studio_server(mem, port=0)
        t_api = threading.Thread(target=srv_api.serve_forever, daemon=True)
        t_api.start()

        with pw.sync_playwright() as p:
            browser = p.chromium.launch()
            for vp in ({"width": 1280, "height": 800}, {"width": 390, "height": 844}):
                page = browser.new_page(viewport=vp)
                js_errors: list[str] = []
                page.on("pageerror", lambda err: js_errors.append(str(err)))
                page.goto(url, wait_until="networkidle")
                page.click("#tab-earning")
                page.wait_for_selector("#earn-wiz-google-btn", timeout=5000)
                page.wait_for_function(
                    "() => document.querySelectorAll('#earn-wiz-catalog-list .earn-item').length === 34",
                    timeout=5000,
                )

                check = page.evaluate(
                    """() => {
                        const gBtn = document.querySelector('#earn-wiz-google-btn');
                        const lBtn = document.querySelector('#earn-wiz-login-btn');
                        const apChk = document.querySelector('#earn-wiz-autopilot-chk');
                        const warnTxt = (document.querySelector('#earn-wiz-bot-warn') || {}).textContent || '';
                        const cardSignupBtns = document.querySelectorAll('[data-wiz-action="signup"]').length;
                        const cardLoginBtns = document.querySelectorAll('[data-wiz-action="login"]').length;
                        return {
                            hasGoogleBtn: Boolean(gBtn && gBtn.textContent.trim()),
                            hasLoginBtn: Boolean(lBtn && lBtn.textContent.trim()),
                            autopilotDefaultOff: apChk ? apChk.checked === false : false,
                            hasBotWarning: warnTxt.includes('правила площадки запрещают автоматику'),
                            cardSignupBtns,
                            cardLoginBtns,
                            overflow: document.documentElement.scrollWidth > window.innerWidth,
                        };
                    }"""
                )
                assert check["hasGoogleBtn"] is True
                assert check["hasLoginBtn"] is True
                assert check["autopilotDefaultOff"] is True
                assert check["hasBotWarning"] is True
                assert check["cardSignupBtns"] == 34
                assert check["cardLoginBtns"] == 34
                assert check["overflow"] is False
                assert js_errors == []

                if vp["width"] == 1280:
                    # 0. До входа статус честный: «ожидает входа»
                    assert "ожидает входа" in (page.text_content("#earn-wiz-session-out") or "")

                    # 1. Нажимаем «Зарегистрироваться через Google» -> видим «подключено (сессия проверена ...» и sha256:...
                    page.click("#earn-wiz-google-btn")
                    page.wait_for_function(
                        "() => { const t = document.querySelector('#earn-wiz-session-out')?.textContent || ''; "
                        "return t.includes('подключено (сессия проверена') && t.includes('sha256:'); }",
                        timeout=5000,
                    )

                    # 2. Включаем переключатель полного автопилота на площадке и возвращаем в исходное состояние
                    page.check("#earn-wiz-autopilot-chk")
                    page.wait_for_timeout(150)
                    assert page.is_checked("#earn-wiz-autopilot-chk") is True
                    page.uncheck("#earn-wiz-autopilot-chk")
                    page.wait_for_timeout(150)

                    # 3. Проходим конвейер «Образец 10% / Этап 10%» -> «Образец принят → весь заказ»
                    page.locator("button[data-order-action='sample_prepare']").first.click()
                    page.wait_for_function(
                        "() => document.querySelectorAll('[data-order-sample-stage=\"sample\"]').length >= 1",
                        timeout=5000,
                    )
                    page.locator("button[data-order-action='sample_accept']").first.click()
                    page.wait_for_function(
                        "() => document.querySelectorAll('[data-order-sample-stage=\"full_order\"]').length >= 1",
                        timeout=5000,
                    )

                page.close()
            browser.close()
    finally:
        platform_wizard.set_browser_session_transport(None)
        if srv_api:
            srv_api.shutdown()
            srv_api.server_close()
        if t_api:
            t_api.join(timeout=2)
        time.sleep(0.15)
        mem.close()
