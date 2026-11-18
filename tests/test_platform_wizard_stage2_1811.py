from __future__ import annotations

import hashlib
import json
from pathlib import Path
import threading
import time
import urllib.parse
import urllib.request

import pytest

from padam import digital_stores, freelance_autonomy, mcp_server, platform_wizard
from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store
from tests.test_digital_stores_stage1_1811 import _http_post_raw, _start_mock_stores_server


def test_sister_remarks_1_and_2_payhip_unverified_and_draft_disclaimer(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_FREELANCE_ALLOW_LOCALHOST", "1")
    srv_mock, base, _ = _start_mock_stores_server()
    mem = Memory(user_id="rem12_u", store=Store(str(tmp_path / "rem12.db")))
    try:
        # Замечание 2: в черновике есть пометка «цена и текст — предложение агента», и в базах лидов НЕТ «без персональных данных»
        seeded = digital_stores.seed_starter_product_drafts(mem)
        assert len(seeded["drafts"]) == 3
        for dr in seeded["drafts"]:
            assert dr["proposal_disclaimer"] == "цена и текст — предложение агента"
            assert "персональных данных" not in dr["description"].lower()

        # Замечание 1: Payhip вебхук создаёт продажу со статусом unverified_payout (verified=False) и НЕ начисляет доли/комиссию
        ph = digital_stores.connect_and_verify_store(
            mem, store_type="payhip", api_key="ph_secret_key", api_base_url=f"{base}/ph"
        )["store"]
        ph_sig = hashlib.sha256(b"ph_secret_key").hexdigest()
        ph_body = json.dumps({
            "id": "ph-sale-777",
            "type": "paid",
            "price": 4900,
            "email": "buyer@payhip.example",
            "items": [{"product_name": "A11y Leads Pack"}],
            "signature": ph_sig,
        }).encode("utf-8")

        wh_res = digital_stores.verify_and_process_store_webhook(
            mem, "payhip", ph_body, {"Content-Type": "application/json"}, store_account_id=ph["store_account_id"]
        )
        assert wh_res["ok"] is True
        assert wh_res["verified"] is False
        assert wh_res["action"] == "sale_pending_owner_verification"
        order_id = wh_res["order_id"]

        # Проверяем, что в итоговых суммах и в ark_agent_ledger начислений НЕТ
        snap_before = freelance_autonomy.freelance_dashboard_snapshot(mem)
        assert snap_before["monetization_totals"]["total_gross_usdt"] == 0.0
        assert snap_before["monetization_totals"]["total_platform_fee_usdt"] == 0.0
        assert snap_before["agent_ledger"]["entries"] == []
        ord_before = next(o for o in snap_before["orders"] if o["order_id"] == order_id)
        assert ord_before["verified"] is False
        assert ord_before["status"] == "unverified_payout"

        # Без owner_approved=True подтверждение запрещено
        with pytest.raises(PermissionError):
            digital_stores.confirm_unverified_store_sale(mem, order_id, owner_approved=False)

        # Владелец сверяет выплату Payhip и подтверждает кнопкой (owner_approved=True)
        conf = digital_stores.confirm_unverified_store_sale(mem, order_id, owner_approved=True)
        assert conf["ok"] is True and conf["verified"] is True

        snap_after = freelance_autonomy.freelance_dashboard_snapshot(mem)
        assert snap_after["monetization_totals"]["total_gross_usdt"] == 49.0
        assert snap_after["monetization_totals"]["total_platform_fee_usdt"] == 9.8  # 20% автопилот
        assert len(snap_after["agent_ledger"]["entries"]) == 1
        ord_after = next(o for o in snap_after["orders"] if o["order_id"] == order_id)
        assert ord_after["verified"] is True
        assert ord_after["status"] == "paid"
    finally:
        srv_mock.shutdown()
        srv_mock.server_close()
        mem.close()


def test_stage2_catalog_30_plus_4_zero_passwords_and_full_wizard_flow(tmp_path: Path):
    mem = Memory(user_id="wiz_u", store=Store(str(tmp_path / "wiz.db")))
    try:
        mem.remember("Опыт разработки Next.js + AI чат-боты и WCAG 2.2 AA аудиты сайтов", kind="fact")

        # 1. Каталог: 30 площадок из методички + 4 биржи для ИИ-агентов = 34
        cat = platform_wizard.list_platform_catalog()
        assert cat["counts"]["total"] == 34
        assert cat["counts"]["methodology_30"] == 30
        assert cat["counts"]["agent_exchanges"] == 4
        assert cat["counts"]["autopilot"] == 12
        assert cat["counts"]["assisted_button"] == 16
        assert cat["counts"]["not_available"] == 6
        assert len(cat["questions"]) == 6

        for p in cat["platforms"]:
            assert p["automation_tier"] in ("autopilot", "assisted_button", "not_available")
            assert p["automation_label_ru"] in ("автопилот", "черновик и кнопка", "пока нельзя")
            assert len(p["reason_ru"]) > 15
            assert str(p["docs_url"]).startswith("https://")

        # 2. Запрет хранения паролей
        with pytest.raises(ValueError, match="ПАРОЛИ НЕ ХРАНИМ НИКОГДА"):
            platform_wizard.connect_platform_step(
                mem, platform_id="upwork", token_or_session="tok", password="my_password_123"
            )

        # Площадки со статусом «пока нельзя» честно отклоняются с причиной
        for blocked_id in ("toptal", "arc_dev", "bark", "youdo", "workzilla", "creative_market"):
            res_b = platform_wizard.connect_platform_step(mem, platform_id=blocked_id, token_or_session="x")
            assert res_b["ok"] is False and res_b["connected"] is False
            assert res_b["automation_tier"] == "not_available"

        # Вход через OAuth, API-ключ и зашифрованную сессию браузера
        c_upw = platform_wizard.connect_platform_step(
            mem, platform_id="upwork", auth_method="oauth", token_or_session="upw_oauth_tok_secret"
        )
        c_fiv = platform_wizard.connect_platform_step(
            mem, platform_id="fiverr", auth_method="browser_session", token_or_session="fiv_sess_cookie_secret"
        )
        c_olas = platform_wizard.connect_platform_step(
            mem, platform_id="olas_mech", auth_method="api_key", token_or_session="olas_api_key_secret"
        )
        assert c_upw["connected"] and c_upw["connection"]["code_fee_pct"] == 15.0
        assert c_fiv["connected"] and c_fiv["connection"]["auth_method"] == "browser_session"
        assert c_olas["connected"] and c_olas["connection"]["code_fee_pct"] == 20.0

        # Проверяем шифрование в SQLite
        raw_rows = mem.store.conn.execute("SELECT credential_enc FROM ark_platform_wizard_connection").fetchall()
        assert len(raw_rows) == 3
        for r in raw_rows:
            enc = str(r["credential_enc"])
            assert enc.startswith("aesgcm1:")
            for plain in ("upw_oauth_tok_secret", "fiv_sess_cookie_secret", "olas_api_key_secret"):
                assert plain not in enc

        # 3. 6 вопросов владельцу -> черновик профиля из памяти -> публикация кнопкой владельца
        q_res = platform_wizard.submit_questionnaire_and_build_profile_draft(
            mem,
            platform_id="upwork",
            specializations="Next.js сайты с ИИ-агентами, базы лидов США, WCAG аудиты",
            hourly_rate_usdt=45.0,
            min_order_usdt=200.0,
            languages="ru, en, es",
            tone="деловой, с расчётом окупаемости",
            excluded_topics="казино, арбитраж трафика, серый парсинг",
        )
        assert q_res["ok"] is True and q_res["questions_answered"] == 6
        draft = q_res["profile_draft"]
        assert draft["status"] == "draft" and draft["owner_approved"] is False
        assert "предложение агента" in draft["proposal_disclaimer"]
        assert "WCAG" in draft["overview"]

        # Без owner_approved=True профиль НЕ публикуется
        pub_no = platform_wizard.publish_profile_draft(mem, draft["draft_id"], owner_approved=False)
        assert pub_no["published"] is False and pub_no["status"] == "awaiting_owner_approval"

        pub_yes = platform_wizard.publish_profile_draft(mem, draft["draft_id"], owner_approved=True)
        assert pub_yes["published"] is True and pub_yes["status"] == "published"
        assert pub_yes["profile_draft"]["owner_approved"] is True

        # 4. «Дальше мы»: автоотбор посильных заказов по правилам анкеты владельца + черновик отклика
        auto_res = platform_wizard.autopick_and_prepare_jobs(
            mem,
            platform_id="upwork",
            candidate_jobs=[
                {"title": "Дешёвый заказ", "brief": "Сделать правку", "budget_usdt": 50.0, "estimated_hours": 2.0},
                {"title": "Сайт казино слоты", "brief": "Сделать казино", "budget_usdt": 500.0, "estimated_hours": 5.0},
                {"title": "Корпоративный сайт с ИИ-агентом", "brief": "Next.js лендинг и чат-бот для клиники", "budget_usdt": 450.0, "estimated_hours": 6.0},
            ],
        )
        assert auto_res["prepared_count"] == 1
        assert auto_res["skipped_count"] == 2
        prep = auto_res["prepared_jobs"][0]
        assert prep["code_fee_pct"] == 15.0
        assert prep["bid_status"] == "bid_draft"
        assert len(prep["bid_pitch_preview"]) > 20
    finally:
        mem.close()


def test_mcp_wizard_actions_and_batch_guard(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    mem = Memory(user_id="mcp_wiz_u", store=Store(str(tmp_path / "mcpw.db")))
    prev = mcp_server._memory
    mcp_server._memory = mem
    try:
        def hcall(name: str, args: dict) -> dict:
            return mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})["result"]

        # Пустые вызовы мутирующих действий мастера возвращают isError=True
        for act in ("wizard_connect", "wizard_questionnaire", "wizard_publish_profile", "wizard_autopick_jobs"):
            assert hcall("padam_freelance_hub", {"action": act})["isError"] is True

        # wizard_catalog работает внутри padam_batch
        b_ok = hcall("padam_batch", {"calls": [{"name": "padam_freelance_hub", "arguments": {"action": "wizard_catalog"}}]})
        assert b_ok.get("isError") is False
        txt_batch = b_ok["content"][0]["text"]
        assert "upwork" in txt_batch and "olas_mech" in txt_batch and "34" in txt_batch

        # Мутирующие действия мастера запрещены в padam_batch
        b_bad = hcall("padam_batch", {"calls": [{"name": "padam_freelance_hub", "arguments": {"action": "wizard_connect", "platform": "upwork", "oauth_token": "t"}}]})
        assert b_bad["isError"] is True

        # Создание черновика профиля через MCP и проверка блокировки автопубликации без кнопки владельца
        q_ok = hcall("padam_freelance_hub", {
            "action": "wizard_questionnaire",
            "platform": "kwork",
            "specializations": "Сайты с ИИ-агентами и базы лидов",
            "hourly_rate_usdt": 35,
            "min_order_usdt": 100,
        })
        assert q_ok.get("isError") is False
        pub_mcp = hcall("padam_freelance_hub", {"action": "wizard_publish_profile", "draft_id": "prof-kwork"})
        assert pub_mcp.get("isError") is False
        pub_payload = json.loads(pub_mcp["content"][0]["text"])
        assert pub_payload["published"] is False
        assert pub_payload["status"] == "awaiting_owner_approval"
    finally:
        mcp_server._memory = prev
        mem.close()


def test_studio_stage2_wizard_and_remarks_playwright(tmp_path: Path, monkeypatch):
    pw = pytest.importorskip("playwright.sync_api")
    monkeypatch.setenv("PADAM_FREELANCE_ALLOW_LOCALHOST", "1")
    srv_mock, base, _ = _start_mock_stores_server()
    mem = Memory(user_id="ui_wiz_u", store=Store(str(tmp_path / "ui_wiz.db")))
    srv_api = None
    t_api = None
    try:
        # Подготовим Payhip магазин и неподтверждённую продажу Payhip для проверки пометки и кнопки в Studio
        ph = digital_stores.connect_and_verify_store(
            mem, store_type="payhip", api_key="ph_secret_key", api_base_url=f"{base}/ph"
        )["store"]
        ph_sig = hashlib.sha256(b"ph_secret_key").hexdigest()
        digital_stores.verify_and_process_store_webhook(
            mem,
            "payhip",
            json.dumps({"id": "ph-ui-1", "type": "paid", "price": 1900, "email": "ui@ph.io", "signature": ph_sig}).encode("utf-8"),
            {"Content-Type": "application/json"},
            store_account_id=ph["store_account_id"],
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
                page.wait_for_selector("#earn-wiz-platform", timeout=5000)
                page.wait_for_function(
                    "() => document.querySelectorAll('#earn-wiz-catalog-list .earn-item').length === 34",
                    timeout=5000,
                )
                page.wait_for_load_state("networkidle")

                ui_state = page.evaluate(
                    """() => {
                        const wizOpts = document.querySelectorAll('#earn-wiz-platform option').length;
                        const catCards = document.querySelectorAll('#earn-wiz-catalog-list .earn-item').length;
                        const propBadges = document.querySelectorAll('[data-draft-proposal="1"]').length;
                        const draftsText = document.querySelector('#earn-drafts-list').textContent;
                        const unvBadges = document.querySelectorAll('[data-order-unverified="1"]').length;
                        return {
                            wizOpts,
                            catCards,
                            propBadges,
                            hasPiiClaim: draftsText.includes('персональных данных'),
                            unvBadges,
                            overflow: document.documentElement.scrollWidth > window.innerWidth,
                        };
                    }"""
                )
                assert ui_state["wizOpts"] == 34
                assert ui_state["catCards"] == 34
                assert ui_state["propBadges"] >= 3
                assert ui_state["hasPiiClaim"] is False
                assert ui_state["overflow"] is False
                assert js_errors == []

                if vp["width"] == 1280:
                    # 1) Проверяем пометку неподтверждённой продажи Payhip и подтверждаем её кнопкой
                    assert ui_state["unvBadges"] == 1
                    with page.expect_response("**/api/v2/ark/stores/action", timeout=5000) as r_conf:
                        page.click("button[data-order-action='confirm_sale']")
                    assert r_conf.value.status == 200
                    page.wait_for_function(
                        "() => document.querySelectorAll('[data-order-unverified=\"1\"]').length === 0",
                        timeout=5000,
                    )

                    # 2) Проходим мастер: выбираем Upwork -> входим по OAuth без пароля -> 6 вопросов -> черновик профиля -> публикация кнопкой
                    page.select_option("#earn-wiz-platform", "upwork")
                    page.select_option("#earn-wiz-auth-method", "oauth")
                    page.fill("#earn-wiz-secret", "upwork_oauth_test_token")
                    with page.expect_response("**/api/v2/ark/wizard/action", timeout=5000) as r_wconn:
                        page.click("#earn-wiz-connect-btn")
                    assert r_wconn.value.status == 200

                    page.fill("#earn-wiz-q-spec", "Создание сайтов с ИИ-агентами и аудит WCAG")
                    page.fill("#earn-wiz-q-rate", "45")
                    page.fill("#earn-wiz-q-min", "150")
                    with page.expect_response("**/api/v2/ark/wizard/action", timeout=5000) as r_wprof:
                        page.click("#earn-wiz-profile-btn")
                    assert r_wprof.value.status == 200
                    page.wait_for_function(
                        "() => document.querySelector('#earn-wiz-profiles-list').textContent.includes('status=draft')",
                        timeout=5000,
                    )

                    # Публикуем профиль кнопкой владельца
                    with page.expect_response("**/api/v2/ark/wizard/action", timeout=5000) as r_wpub:
                        page.locator("#earn-wiz-profiles-list button").first.click()
                    assert r_wpub.value.status == 200
                    page.wait_for_function(
                        "() => document.querySelector('#earn-wiz-profiles-list').textContent.includes('status=published')",
                        timeout=5000,
                    )

                    # Запускаем автоотбор посильных заказов
                    with page.expect_response("**/api/v2/ark/wizard/action", timeout=5000) as r_wauto:
                        page.click("#earn-wiz-autopick-btn")
                    assert r_wauto.value.status == 200

                page.wait_for_load_state("networkidle")
                page.close()
            browser.close()
    finally:
        if srv_api:
            srv_api.shutdown()
            srv_api.server_close()
        if t_api:
            t_api.join(timeout=2)
        time.sleep(0.15)
        srv_mock.shutdown()
        srv_mock.server_close()
        mem.close()
