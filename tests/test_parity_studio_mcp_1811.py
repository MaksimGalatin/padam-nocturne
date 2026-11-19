# -*- coding: utf-8 -*-
"""Полный паритет Studio ↔ MCP (18.11.2026): скрипт-таблица, API/MCP и Playwright 1280×800 / 390×844."""
from __future__ import annotations

import json
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from padam import api, cabinet, digital_stores, freelance_autonomy, mcp_server, platform_wizard, partner_bridge, studio
from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store
from scripts import generate_parity_studio_mcp as parity_gen


class _LocalPartnerCloud(BaseHTTPRequestHandler):
    calls: list[dict] = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        tool = (body.get("params") or {}).get("name") or ""
        _LocalPartnerCloud.calls.append({"tool": tool})
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": json.dumps({"ok": True, "tool": tool, "clients": [{"domain": "demo.example", "score": 42}], "url": "https://aifa.works/?ref=demo", "deals": []})}]}}
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def test_parity_matrix_zero_gaps_and_4_languages():
    """Скрипт паритета находит 100% соответствие MCP ↔ Studio ↔ API и 4 языка Studio полны."""
    rc = parity_gen.main()
    assert rc == 0
    doc = (parity_gen.ROOT / "docs" / "PARITY_STUDIO_MCP.md").read_text(encoding="utf-8")
    assert "174 из 174" in doc
    assert "Есть в Studio (вкладка + кнопка/поле): **174 из 174**" in doc
    assert "Есть в API (`padam/api.py`): **174 из 174**" in doc
    assert "НЕТ:" not in doc

    ru_keys = set(studio.STRINGS["ru"].keys())
    for lang in ("ru", "en", "es", "zh"):
        assert set(studio.STRINGS[lang].keys()) == ru_keys
        for k, v in studio.STRINGS[lang].items():
            assert isinstance(v, str) and v.strip(), (lang, k)


def test_parity_mcp_and_api_new_actions_and_owner_guards(tmp_path: Path, monkeypatch):
    """Все новые действия MCP и API работают через общие модули, а денежные остаются только у владельца."""
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    monkeypatch.setenv("PADAM_MCP_PARTNER_TOOLS", "1")
    m = Memory(user_id="parity_u", store=Store(str(tmp_path / "parity.db")))
    prev_m = mcp_server._memory
    mcp_server._memory = m
    try:
        def hcall(tool: str, args: dict):
            return mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})["result"]

        # Новые action padam_guardian_tick
        for act, extra in (
            ("tick", {}),
            ("health", {}),
            ("readiness", {}),
            ("audit_verify", {}),
            ("doctor", {}),
            ("l3_verify", {}),
            ("handover", {"notes": "parity"}),
            ("drift", {"text": "test check"}),
            ("self_heal", {}),
            ("aifa_security", {}),
            ("qa_benchmark", {}),
            ("entities", {}),
            ("graph", {}),
        ):
            r = hcall("padam_guardian_tick", {"action": act, **extra})
            assert r.get("isError") is not True, (act, r)

        # Новые action padam_phoenix_family
        r_hw = hcall("padam_phoenix_family", {"action": "hw_recommend"})
        assert r_hw.get("isError") is not True

        # Новые action padam_freelance_hub (safe + guard от AUT-02/03)
        r_ap = hcall("padam_freelance_hub", {"action": "autopilot_config", "platform": "upwork"})
        assert r_ap.get("isError") is not True
        r_sd = hcall("padam_freelance_hub", {"action": "seed_drafts"})
        assert r_sd.get("isError") is not True
        r_rp = hcall("padam_freelance_hub", {"action": "release_payouts"})
        assert r_rp.get("isError") is True        # аудит фазы 3, FA-11: разблокировка выплат — только владелец
        r_tk = hcall("padam_freelance_hub", {"action": "autopilot_tick"})
        assert r_tk.get("isError") is True        # FA-11: внеочередной шаг автопилота — только владелец
        # 18.11: письмо незнакомому и подключение ящика с паролем — только владелец в Studio, не агент через MCP
        r_so = hcall("padam_freelance_hub", {"action": "send_outreach", "to_email": "x@example.org", "domain": "example.org", "subject": "s", "body": "b"})
        assert r_so.get("isError") is True
        r_cm = hcall("padam_freelance_hub", {"action": "connect_mail", "email": "a@b.test", "app_password_or_token": "x"})
        assert r_cm.get("isError") is True
        for act_mass in ("run_outreach_batch", "run_follow_up"):   # массовая рассылка незнакомым — только владелец
            assert hcall("padam_freelance_hub", {"action": act_mass}).get("isError") is True, act_mass
        # sample_reject через оба алиаса (freelance_hub + platform_connect)
        o_smp = freelance_autonomy.evaluate_and_ingest_job(m, platform="upwork", title="Sample Rej", brief="Test", budget_usdt=100.0)
        assert hcall("padam_freelance_hub", {"action": "sample_reject", "order_id": o_smp["order_id"]}).get("isError") is not True
        o_smp2 = freelance_autonomy.evaluate_and_ingest_job(m, platform="upwork", title="Sample Rej 2", brief="Test", budget_usdt=100.0)
        assert hcall("padam_platform_connect", {"action": "sample_reject", "order_id": o_smp2["order_id"]}).get("isError") is not True

        # padam_cabinet.chat_history (с локальным моком cabinet, без внешней сети)
        monkeypatch.setenv("PADAM_MCP_CABINET_TOOL", "1")
        monkeypatch.setattr(cabinet, "fetch_aifa_history", lambda chat_type="main": {"ok": True, "messages": []})
        r_ch = hcall("padam_cabinet", {"action": "chat_history"})
        assert r_ch.get("isError") is not True

        # Безопасность AUT-02/03 и AUT-09: settle_paid / accept_delivery / set_autopilot / sample_accept НЕ открыты в MCP
        for forbidden in ("settle_paid", "accept_delivery", "confirm_sale", "set_autopilot", "sample_accept", "autopilot_start", "autopilot_stop"):
            r_forb = hcall("padam_freelance_hub", {"action": forbidden, "order_id": "x"})
            assert r_forb.get("isError") is True
    finally:
        mcp_server._memory = prev_m


def test_parity_studio_playwright_all_buttons_1280_and_390(tmp_path: Path, monkeypatch):
    """Playwright (1280x800 и 390x844): кликает каждую кнопку паритета, проверяет DOM, 0 JS ошибок, 0 внешней сети."""
    pw = pytest.importorskip("playwright.sync_api")
    cloud_srv = HTTPServer(("127.0.0.1", 0), _LocalPartnerCloud)
    threading.Thread(target=cloud_srv.serve_forever, daemon=True).start()
    _LocalPartnerCloud.calls = []
    monkeypatch.setenv("PADAM_AIFA_MCP_URL", f"http://127.0.0.1:{cloud_srv.server_port}/api/mcp")
    monkeypatch.delenv("PADAM_AIFA_MCP_TOKEN", raising=False)
    _cab = {"on": False}
    monkeypatch.setattr(cabinet, "_http_json", lambda method, path, body=None, **kw: {"ok": True, "sent": True, "messages": [{"role": "assistant", "text": "ok"}], "reply": "ok", "user": {"email": "a@example.com"}, "plan": "free"})
    monkeypatch.setattr(cabinet, "send_login_code", lambda *a, **kw: {"ok": True, "sent": True, "email": (a[0] if a else kw.get("email", ""))})
    def _mock_verify(*a, **kw):
        _cab["on"] = True
        return {"ok": True, "logged_in": True, "authenticated": True, "email": (a[0] if a else kw.get("email", "")), "user": {"email": "owner@example.com"}}
    def _mock_clear(*a, **kw):
        _cab["on"] = False
        return True
    monkeypatch.setattr(cabinet, "verify_login_code", _mock_verify)
    monkeypatch.setattr(cabinet, "clear_session", _mock_clear)
    monkeypatch.setattr(cabinet, "get_public_status", lambda *a, **kw: {"authenticated": _cab["on"], "logged_in": _cab["on"], "email": "owner@example.com" if _cab["on"] else "", "plan": {"id": "free", "name": "Free"}, "plans": cabinet.PLANS})
    monkeypatch.setattr(cabinet, "fetch_me_and_quota", lambda *a, **kw: {"authenticated": _cab["on"], "logged_in": _cab["on"], "email": "owner@example.com" if _cab["on"] else "", "tier": 0, "tier_name": "Free", "quota": {"used_mb": 0, "limit_mb": 10}, "plans": cabinet.PLANS, "user": {"email": "owner@example.com"}, "plan": {"id": "free", "name": "Free"}})
    monkeypatch.setattr(cabinet, "fetch_aifa_history", lambda *a, **kw: {"messages": [{"role": "assistant", "text": "ok"}]})
    monkeypatch.setattr(cabinet, "send_aifa_message", lambda *a, **kw: {"ok": True, "reply": "ok", "messages": [{"role": "assistant", "text": "ok"}]})
    monkeypatch.setattr(digital_stores, "connect_and_verify_store", lambda mem, **kw: {"ok": True, "store_account_id": "st-pw", "store_type": kw.get("store_type", "gumroad"), "verified": True})

    platform_wizard.set_browser_session_transport(
        lambda req: {"cookies": {"session_id": f"par_{req.get('platform_id', 'upwork')}"}}
    )

    m = Memory(user_id="parity_ui", store=Store(str(tmp_path / "ui.db")))
    _, rec_main_id = m.remember("Основной факт для проверки доказательства Меркла и поиска", kind="fact", origin="user")
    st1, _ = m.remember("Внешняя запись для проверки одобрения в Studio", kind="fact", origin="external", guarded=True)
    st2, _ = m.remember("Внешняя запись для проверки отклонения в Studio", kind="fact", origin="external", guarded=True)
    assert st1 == "quarantined" and st2 == "quarantined"
    partner_bridge.save_studio_key(m, "amcp_test_1234567890abcdef")

    portable_dir = tmp_path / "portable_ark_out"
    portable_dir.mkdir()

    prev_state = dict(api._state)
    srv, url = make_studio_server(m, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pw.sync_playwright() as p:
            browser = p.chromium.launch()
            for vp in ({"width": 1280, "height": 800}, {"width": 390, "height": 844}):
                page = browser.new_page(viewport=vp)
                js_errors: list[str] = []
                external_reqs: list[str] = []
                server_errors: list[tuple[str, int]] = []
                page.on("pageerror", lambda e: js_errors.append(str(e)))
                def _on_console(msg):
                    if msg.type != "error":
                        return
                    txt = msg.text
                    if any(k in txt for k in ("favicon.", "icon-192.png", "/sw.js", "status of 400", "status of 403")):
                        return
                    js_errors.append(txt)
                page.on("console", _on_console)
                page.on("response", lambda r: server_errors.append((r.url, r.status)) if r.status >= 500 else None)
                page.on("request", lambda req: external_reqs.append(req.url) if not req.url.startswith(("http://127.0.0.1:", "data:", "blob:", "about:")) else None)

                page.goto(url, wait_until="networkidle")

                def open_group_tab(grp_key: str, tab_id: str) -> None:
                    page.click(f".nav-group-btn[data-group='{grp_key}']")
                    page.wait_for_selector(f"#subnav", timeout=5000)
                    page.locator(f"#subnav button", has_text=page.evaluate(f"() => document.querySelector('#tab-{tab_id}').textContent.trim().split('\\n')[0].trim()")).first.click()
                    page.wait_for_selector(f"#panel-{tab_id}:not([hidden])", timeout=5000)

                def click_and_check_text(btn_sel: str, out_sel: str) -> None:
                    page.locator(btn_sel).scroll_into_view_if_needed()
                    page.click(btn_sel)
                    page.wait_for_function(
                        f"() => {{ const el = document.querySelector({json.dumps(out_sel)}); return el && el.textContent.trim().length > 0 && el.textContent.trim() !== 'Загрузка…'; }}",
                        timeout=30000,  # 18.11: тяжёлые проверки на загруженной машине не укладывались в 12 с
                    )

                assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth"), f"overflow at start ({vp})"

                if vp["width"] == 1280:
                    # 1. Вкладка СЕМЬЯ (#panel-family)
                    page.click("#tab-family")
                    page.wait_for_selector("#panel-family:not([hidden])", timeout=5000)

                    # Лента и каналы Семьи
                    page.click("#ff-ch-office")
                    page.fill("#ff-input", "Сообщение из Playwright 1280")
                    page.click("#ff-send")
                    page.wait_for_function("() => (document.querySelector('#ff-list')?.textContent || '').includes('Сообщение из Playwright 1280')", timeout=5000)
                    for ch_btn in ("#ff-ch-work", "#ff-ch-quarantine", "#ff-ch-smoke", "#ff-ch-office"):
                        page.click(ch_btn)
                        page.wait_for_timeout(80)
                    assert page.locator("#ff-reflexes").count() == 1

                    # Рефлексы: propose + match
                    page.fill("#ff-ref-trig-inp", "секретный токен")
                    page.fill("#ff-ref-resp-inp", "остановить и спросить")
                    click_and_check_text("#ff-ref-propose-btn", "#ff-ref-out")
                    click_and_check_text("#ff-ref-match-btn", "#ff-ref-out")

                    # Совет Семьи
                    page.fill("#ark-council-input", "Проверить план паритета")
                    click_and_check_text("#ark-council-btn", "#ark-council-out")

                    # Все кнопки #fam-ark-ops-box
                    for bsel in ("#ark-wakeup-btn", "#ark-sespack-btn", "#ark-tl-btn", "#ark-telem-btn", "#ark-batch-btn"):
                        click_and_check_text(bsel, "#fam-ark-ops-out")

                    page.fill("#ark-comm-title-inp", "Обещание паритета")
                    for bsel in ("#ark-comm-add-btn", "#ark-comm-list-btn", "#ark-comm-done-btn", "#ark-ckpt-save-btn", "#ark-ckpt-latest-btn"):
                        click_and_check_text(bsel, "#fam-ark-comm-out")
                    page.fill("#ark-lesson-inp", "Проверять URL до записи в отчёт")
                    for bsel in ("#ark-lesson-rec-btn", "#ark-lesson-list-btn"):
                        click_and_check_text(bsel, "#fam-ark-comm-out")
                    page.fill("#ark-relay-msg-inp", "Привет от Playwright")
                    for bsel in ("#ark-relay-send-btn", "#ark-relay-inbox-btn", "#ark-relay-ack-btn"):
                        click_and_check_text(bsel, "#fam-ark-comm-out")

                    for bsel in ("#ark-sib-hb-btn", "#ark-sib-pass-btn", "#ark-sib-sign-btn", "#ark-sib-ver-btn"):
                        click_and_check_text(bsel, "#fam-ark-coop-out")
                    page.fill("#ark-coop-key-inp", "padam/studio.py")
                    for bsel in ("#ark-coop-acq-btn", "#ark-coop-ren-btn", "#ark-coop-rel-btn", "#ark-coop-relall-btn"):
                        click_and_check_text(bsel, "#fam-ark-coop-out")
                    page.fill("#ark-coop-task-inp", "Проверить кнопки Studio")
                    for bsel in ("#ark-coop-tcreate-btn", "#ark-coop-tclaim-btn", "#ark-coop-tdone-btn", "#ark-coop-list-btn"):
                        click_and_check_text(bsel, "#fam-ark-coop-out")
                    page.fill("#ark-arb-topic-inp", "Спор о кнопке")
                    for bsel in ("#ark-arb-open-btn", "#ark-arb-ev-btn", "#ark-arb-res-btn", "#ark-arb-list-btn"):
                        click_and_check_text(bsel, "#fam-ark-coop-out")

                    # 2. Вкладка СУВЕРЕННЫЙ МОЗГ (#panel-brain)
                    page.click("#tab-brain")
                    page.wait_for_selector("#panel-brain:not([hidden])", timeout=5000)
                    for bsel in ("#brain-refresh-btn", "#brain-mode-toggle-btn"):
                        page.click(bsel)
                        page.wait_for_timeout(120)
                    click_and_check_text("#brain-distill-btn", "#brain-distill-out")
                    click_and_check_text("#brain-warmup-btn", "#brain-distill-out")
                    click_and_check_text("#brain-phoenix-arweave-btn", "#brain-phoenix-out")
                    click_and_check_text("#ark-drill-btn", "#ark-drill-out")
                    click_and_check_text("#ark-selfheal-btn", "#ark-drill-out")
                    page.fill("#ark-drift-input", "Основной факт для проверки")
                    click_and_check_text("#ark-drift-btn", "#ark-drill-out")
                    for bsel in ("#ark-audit-btn", "#ark-shamir-btn"):
                        click_and_check_text(bsel, "#ark-health-box")

                    page.fill("#ark-branch-input", "branch-1")
                    click_and_check_text("#ark-branch-create-btn", "#ark-branch-out")
                    click_and_check_text("#ark-branch-list-btn", "#ark-branch-out")
                    page.fill("#ark-branch-text-inp", "Факт внутри ветки")
                    for bsel in ("#ark-branch-rem-btn", "#ark-branch-merge-btn"):
                        click_and_check_text(bsel, "#ark-branch-out")
                    page.fill("#ark-branch-input", "branch-2")
                    click_and_check_text("#ark-branch-create-btn", "#ark-branch-out")
                    click_and_check_text("#ark-branch-abn-btn", "#ark-branch-out")

                    page.fill("#ark-proof-input", rec_main_id)
                    click_and_check_text("#ark-proof-btn", "#ark-proof-out")
                    click_and_check_text("#ark-proof-verify-btn", "#ark-proof-out")

                    for bsel in ("#ark-mesh-btn", "#ark-mesh-id-btn", "#ark-guardian-btn"):
                        click_and_check_text(bsel, "#ark-mesh-out")
                    for bsel in ("#ark-mesh-pairinit-btn", "#ark-mesh-pairacc-btn", "#ark-mesh-delta-btn", "#ark-mesh-apply-btn"):
                        click_and_check_text(bsel, "#ark-mesh-out")
                    page.fill("#ark-mesh-sas-inp", "123456")
                    click_and_check_text("#ark-mesh-pairconf-btn", "#ark-mesh-out")

                    click_and_check_text("#ark-ready-btn", "#ark-ready-out")
                    page.fill("#ark-handover-input", "Playwright handover")
                    click_and_check_text("#ark-handover-btn", "#ark-handover-out")
                    page.fill("#ark-portable-input", str(portable_dir))
                    click_and_check_text("#ark-portable-btn", "#ark-portable-out")
                    click_and_check_text("#ark-budget-btn", "#ark-budget-out")

                    page.fill("#ark-anchor-path-inp", "padam/__init__.py")
                    click_and_check_text("#ark-anchor-add-btn", "#ark-parity-brain-out")
                    click_and_check_text("#ark-anchor-chk-btn", "#ark-parity-brain-out")
                    page.fill("#ark-mm-path-inp", "README.md")
                    click_and_check_text("#ark-mm-btn", "#ark-parity-brain-out")
                    page.fill("#ark-snap-name-inp", "snap-parity")
                    for bsel in ("#ark-snap-create-btn", "#ark-snap-list-btn", "#ark-snap-diff-btn", "#ark-snap-rb-btn"):
                        click_and_check_text(bsel, "#ark-parity-brain-out")

                    # 3. Вкладка АВТОНОМНЫЙ ЗАРАБОТОК (#panel-earning + 9. AIfaFocus)
                    page.click("#tab-earning")
                    page.wait_for_selector("#panel-earning:not([hidden])", timeout=5000)
                    page.wait_for_selector("#earn-wiz-google-btn", timeout=5000)
                    page.fill("#earn-label", "My Upwork")
                    click_and_check_text("#earn-connect-btn", "#earn-accounts-list")
                    for bsel in ("#earn-auto-start-btn", "#earn-auto-stop-btn", "#earn-auto-tick-btn", "#earn-auto-cfg-btn"):
                        click_and_check_text(bsel, "#earn-accounts-list")

                    page.fill("#earn-job-title", "WCAG Audit Site")
                    page.fill("#earn-job-brief", "Audit and fix accessibility errors")
                    click_and_check_text("#earn-eval-btn", "#earn-orders-list")

                    # Действия по созданному заказу (ждём loadEarning чтобы перерисовка DOM не оторвала следующий locator)
                    for act in ("draft_bid", "dispatch_bid", "execute_swarm", "deliver", "sample_prepare", "sample_accept", "accept_delivery", "settle_paid"):
                        sel = f"button[data-order-action='{act}']"
                        page.wait_for_selector(sel, timeout=8000)
                        with page.expect_response(lambda r: "/api/v2/ark/freelance" in r.url and r.request.method == "GET", timeout=8000):
                            page.locator(sel).first.click()
                        # 18.11: перерисовка ленты заказов под нагрузкой машины занимала больше 5 с — ждём до 15 с
                        page.wait_for_selector("button[data-order-action='draft_bid']", timeout=15000)

                    for bsel in ("#earn-fetch-jobs-btn", "#earn-lock-chk-btn"):
                        click_and_check_text(bsel, "#earn-orders-list")

                    for bsel in ("#earn-plan-save-btn", "#earn-tick-btn", "#earn-propose-btn", "#earn-rec-usage-btn", "#earn-pacing-btn"):
                        click_and_check_text(bsel, "#earn-budget-summary")
                    click_and_check_text("#earn-rec-spend-btn", "#earn-spend-rec-out")
                    click_and_check_text("#earn-propose-sub-btn", "#earn-proposals-list")

                    page.fill("#earn-sib-id", "aifa_pw")
                    page.fill("#earn-sib-role", "QA")
                    for bsel in ("#earn-sib-reg-btn", "#earn-prefs-save-btn", "#earn-ledger-btn", "#earn-prop-prof-btn", "#earn-rel-payout-btn", "#earn-dispute-btn"):
                        click_and_check_text(bsel, "#earn-swarm-list")
                    page.fill("#earn-ref-inp", "CODE777")
                    click_and_check_text("#earn-bind-ref-btn", "#earn-swarm-list")
                    click_and_check_text("#earn-monet-btn", "#earn-monetization-summary")

                    page.fill("#earn-ollama-model", "llama3.2")
                    for bsel in ("#earn-ollama-btn", "#earn-ollama-pull-btn", "#earn-dev-btn", "#earn-dev-disp-btn", "#earn-hw-rec-btn"):
                        click_and_check_text(bsel, "#earn-ollama-out")

                    for bsel in ("#earn-lora-evo-btn", "#earn-beacon-btn", "#earn-beacon-ver-btn"):
                        click_and_check_text(bsel, "#earn-beacon-out")
                    page.fill("#earn-exp-inp", "Научилась проверять паритет Studio и MCP")
                    click_and_check_text("#earn-exp-btn", "#earn-beacon-out")
                    page.fill("#earn-kin-msg-inp", "Проверка маяка")
                    click_and_check_text("#earn-kin-send-btn", "#earn-beacon-out")
                    click_and_check_text("#earn-kin-recv-btn", "#earn-beacon-out")

                    page.click("#earn-store-seed-btn")
                    page.wait_for_function("() => (document.querySelector('#earn-drafts-list')?.textContent || '').trim().length > 0", timeout=5000)
                    page.fill("#earn-draft-title", "Audit Checklist Pack")
                    page.click("#earn-draft-save-btn")
                    page.wait_for_timeout(150)

                    page.fill("#earn-wiz-secret", "tok_test_oauth")
                    for bsel in ("#earn-wiz-connect-btn", "#earn-wiz-profile-btn", "#earn-wiz-autopick-btn", "#earn-wiz-google-btn", "#earn-wiz-login-btn", "#earn-wiz-disp-btn", "#earn-wiz-off-btn"):
                        page.locator(bsel).scroll_into_view_if_needed()
                        page.click(bsel)
                        page.wait_for_timeout(120)
                    page.check("#earn-wiz-autopilot-chk")
                    page.wait_for_timeout(100)
                    page.uncheck("#earn-wiz-autopilot-chk")
                    page.fill("#earn-store-label", "Playwright Gumroad")
                    page.fill("#earn-store-key", "gum_test_secret_key")
                    page.click("#earn-store-connect-btn")
                    page.wait_for_timeout(120)
                    assert page.locator("#earn-wiz-catalog-list .earn-item").count() == 34
                    assert page.locator("#earn-stores-list").count() == 1
                    if page.locator("#earn-stores-list button").count() > 0:
                        page.locator("#earn-stores-list button").first.click()
                        page.wait_for_timeout(100)
                    page.fill("#earn-job-title", "Sample Reject Order")
                    page.fill("#earn-job-brief", "Second order for sample reject button")
                    click_and_check_text("#earn-eval-btn", "#earn-orders-list")
                    page.locator("button[data-order-action='sample_reject']").first.click()
                    page.wait_for_timeout(120)
                    if page.locator("#earn-wiz-profiles-list button").count() > 0:
                        page.locator("#earn-wiz-profiles-list button").first.click()
                        page.wait_for_timeout(120)

                    # Блок 9. AIfaFocus
                    page.fill("#earn-partner-region", "US-CA")
                    click_and_check_text("#earn-partner-find-btn", "#earn-partner-out")
                    page.fill("#earn-partner-site", "demo.example")
                    for bsel in ("#earn-partner-report-btn", "#earn-partner-draft-btn", "#earn-partner-link-btn", "#earn-partner-kit-btn", "#earn-partner-deals-btn"):
                        click_and_check_text(bsel, "#earn-partner-out")

                    # 4. Остальные группы вкладок
                    open_group_tab("grp_memory", "overview")
                    assert page.is_visible("#panel-overview")
                    page.click("#ov-sleep-btn")
                    page.wait_for_timeout(150)

                    open_group_tab("grp_memory", "feed")
                    assert page.is_visible("#panel-feed")
                    page.fill("#feed-new-text", "Запись через Playwright feed-new-save")
                    page.click("#feed-new-save")
                    page.wait_for_function("() => (document.querySelector('#feed-list')?.textContent || '').includes('feed-new-save')", timeout=5000)

                    open_group_tab("grp_memory", "search")
                    page.fill("#search-input", "Меркла")
                    click_and_check_text("#search-btn", "#search-results")

                    open_group_tab("grp_memory", "asof")
                    click_and_check_text("#asof-btn", "#asof-results")

                    open_group_tab("grp_memory", "entities")
                    page.fill("#entities-filter", "Меркла")
                    page.wait_for_timeout(100)

                    open_group_tab("grp_memory", "graph")
                    page.fill("#graph-id-input", rec_main_id)
                    page.click("#graph-focus-btn")
                    page.wait_for_timeout(120)

                    open_group_tab("grp_cloud", "aifa")
                    page.wait_for_selector("#aifa-auth-box", timeout=3000)
                    assert page.locator("#aifa-chat-list").count() == 1
                    page.fill("#aifa-email-input", "owner@example.com")
                    page.click("#aifa-send-code-btn")
                    page.wait_for_selector("#aifa-code-input", state="visible", timeout=5000)
                    page.fill("#aifa-code-input", "123456")
                    page.click("#aifa-verify-code-btn")
                    page.wait_for_selector("#aifa-msg-input", state="visible", timeout=5000)
                    page.fill("#aifa-msg-input", "Привет")
                    page.click("#aifa-send-msg-btn")
                    page.wait_for_timeout(120)
                    if page.locator("#aifa-logout-btn").is_visible():
                        page.click("#aifa-logout-btn")
                        page.wait_for_timeout(100)

                    open_group_tab("grp_cloud", "plans")
                    assert page.locator("#plans-upgrade-btn").count() == 1
                    assert page.locator("#plans-current-val").count() == 1

                    open_group_tab("grp_cloud", "l3")
                    page.click("#l3-verify-latest-btn")
                    page.wait_for_timeout(120)

                    open_group_tab("grp_guard", "review")
                    page.wait_for_selector("#review-list button", timeout=5000)
                    assert page.locator("#review-list button").count() >= 4
                    page.locator("#review-list button").nth(0).click()
                    page.wait_for_timeout(200)
                    if page.locator("#review-list button").count() >= 2:
                        page.locator("#review-list button").nth(1).click()
                        page.wait_for_timeout(150)

                    # 18.11: бенчмарк вынесен из «Атак» в отдельную вкладку меню «Бенчмарк»
                    page.click("#tab-bench")
                    page.wait_for_selector("#panel-bench:not([hidden])", timeout=5000)
                    with page.expect_response(lambda r: "/api/v2/aifa-security/run" in r.url, timeout=30000) as resp_info:
                        page.click("#att-aifasec-run")
                    assert resp_info.value.status == 200
                    page.wait_for_function("() => (document.querySelector('#att-aifasec-summary')?.textContent || '').trim().length > 0", timeout=5000)
                    page.click("#att-qa-load")
                    page.wait_for_timeout(150)

                    open_group_tab("grp_more", "backup")
                    click_and_check_text("#backup-export-json-btn", "#backup-result")

                    open_group_tab("grp_more", "settings")
                    page.click("#lm-power-eco")
                    page.click("#lm-power-full")
                    page.click("#lm-power-half")
                    click_and_check_text("#lm-save", "#lm-out")

                    # Переключение на 4 языка (ru -> en -> es -> zh -> ru)
                    for lg in ("en", "es", "zh", "ru"):
                        page.click(f"#lang-{lg}")
                        page.wait_for_function(f"() => document.documentElement.lang === {json.dumps(lg)}", timeout=3000)

                else:
                    # 390x844: адаптивность и клики на мобильном экране
                    page.wait_for_selector("#ark-wakeup-btn", timeout=5000)
                    for tab_id, bsel, osel in (
                        ("family", "#ark-wakeup-btn", "#fam-ark-ops-out"),
                        ("brain", "#ark-anchor-chk-btn", "#ark-parity-brain-out"),
                        ("earning", "#earn-hw-rec-btn", "#earn-ollama-out"),
                    ):
                        page.click(f"#tab-{tab_id}")
                        page.wait_for_selector(f"#panel-{tab_id}:not([hidden])", timeout=5000)
                        assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth"), f"mobile overflow in {tab_id}"
                        click_and_check_text(bsel, osel)
                    open_group_tab("grp_more", "backup")
                    assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth"), "mobile overflow in backup"
                    click_and_check_text("#backup-export-json-btn", "#backup-result")

                assert js_errors == [], f"JS errors at {vp}: {js_errors}"
                assert server_errors == [], f"HTTP >=500 errors at {vp}: {server_errors}"
                assert external_reqs == [], f"External requests at {vp}: {external_reqs}"
                page.close()
            browser.close()
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
        cloud_srv.shutdown()
        cloud_srv.server_close()
        platform_wizard.set_browser_session_transport(None)
        api._state.clear()
        api._state.update(prev_state)
