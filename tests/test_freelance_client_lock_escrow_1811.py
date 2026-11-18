from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from padam import freelance_autonomy, mcp_server, sovereign_ops, studio
from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store


def _db_snapshot(conn) -> dict[str, list[tuple]]:
    tables = [
        r[0]
        for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    ]
    snap: dict[str, list[tuple]] = {}
    for tbl in tables:
        if tbl.startswith("memory_fts"):
            continue
        rows = conn.execute(f'SELECT * FROM "{tbl}"').fetchall()
        snap[tbl] = sorted(tuple(row) for row in rows)
    return snap


def test_client_90_day_lock_lifecycle_email_domain_exchange_id(tmp_path: Path):
    m = Memory(user_id="cl_u", store=Store(str(tmp_path / "cl.db")))
    try:
        t0 = 1_800_000_000.0

        # 1. Нормализация email, домена и ID клиента биржи
        k1, s1 = freelance_autonomy._normalize_client_identity("fiverr_desk", client_email="  Alice.Smith@ACME.IO ")
        k2, s2 = freelance_autonomy._normalize_client_identity("upwork_api", client_domain="https://www.Acme.IO/projects?x=1")
        k3, s3 = freelance_autonomy._normalize_client_identity("upwork_api", client_external_id="CL-77")
        assert (k1, s1) == ("email:alice.smith@acme.io", "email")
        assert (k2, s2) == ("domain:acme.io", "domain")
        assert (k3, s3) == ("exchange:upwork_api:cl-77", "exchange_client_id")

        # 2. До оплаты клиент ещё не закреплён
        j1 = freelance_autonomy.evaluate_and_ingest_job(
            m, platform="fiverr_desk", title="First order", brief="Build API endpoint",
            budget_usdt=100.0, assigned_agent="agent_alpha", client_email="Alice.Smith@ACME.IO", now_ts=t0,
        )
        assert j1["client_key"] == "email:alice.smith@acme.io"
        assert j1["locked_agent_id"] == ""
        assert freelance_autonomy.get_client_lock_status(m, client_email="alice.smith@acme.io", now_ts=t0)["locked"] is False

        # 3. Первая оплаченная сделка -> закрепление на 90 дней за agent_alpha
        p1 = freelance_autonomy.settle_paid_order(m, j1["order_id"], paid_usdt=100.0, agent_id="agent_alpha", now_ts=t0)
        assert p1["client_lock"]["agent_id"] == "agent_alpha"
        assert p1["client_lock"]["locked_from_ts"] == pytest.approx(t0)
        assert p1["client_lock"]["locked_until_ts"] == pytest.approx(t0 + 90 * 86400)

        # 4. Повторный заказ этого клиента на день 40 (пришёл через другого агента) -> засчитывается agent_alpha
        t_day40 = t0 + 40 * 86400
        j2 = freelance_autonomy.evaluate_and_ingest_job(
            m, platform="upwork_api", title="Repeat order", brief="Add monitoring script",
            budget_usdt=80.0, assigned_agent="agent_beta", client_email="alice.smith@acme.io", now_ts=t_day40,
        )
        assert j2["assigned_agent"] == "agent_alpha"
        assert j2["locked_agent_id"] == "agent_alpha"
        p2 = freelance_autonomy.settle_paid_order(m, j2["order_id"], paid_usdt=80.0, agent_id="agent_beta", now_ts=t_day40)
        assert p2["credited_agent"] == "agent_alpha"
        assert p2["client_lock"]["orders_count"] == 2

        # 5. Через 90 дней без новых сделок закрепление снимается
        t_after90 = p2["client_lock"]["locked_until_ts"] + 1.0
        st_exp = freelance_autonomy.get_client_lock_status(m, client_email="alice.smith@acme.io", now_ts=t_after90)
        assert st_exp["locked"] is False
        assert st_exp["match"]["status"] == "expired"

        rel = freelance_autonomy.release_expired_client_locks(m, now_ts=t_after90)
        assert rel["expired_count"] == 1
        assert rel["active_count"] == 0

        # Новый заказ после снятия лока -> закрепляется уже за agent_beta
        j3 = freelance_autonomy.evaluate_and_ingest_job(
            m, platform="fiverr_desk", title="Post-expiry order", brief="New microservice task",
            budget_usdt=120.0, assigned_agent="agent_beta", client_email="alice.smith@acme.io", now_ts=t_after90,
        )
        assert j3["assigned_agent"] == "agent_beta"
        assert j3["locked_agent_id"] == ""
        p3 = freelance_autonomy.settle_paid_order(m, j3["order_id"], paid_usdt=120.0, agent_id="agent_beta", now_ts=t_after90)
        assert p3["credited_agent"] == "agent_beta"
        assert p3["client_lock"]["agent_id"] == "agent_beta"
        assert p3["client_lock"]["orders_count"] == 1

        # Доменное и ID-закрепление работают аналогично
        jd = freelance_autonomy.evaluate_and_ingest_job(
            m, platform="upwork_api", title="Domain client job", brief="Write unit tests",
            budget_usdt=50.0, assigned_agent="agent_gamma", client_domain="https://WWW.BetaCorp.com/team", now_ts=t0,
        )
        freelance_autonomy.settle_paid_order(m, jd["order_id"], paid_usdt=50.0, agent_id="agent_gamma", now_ts=t0)
        st_dom = freelance_autonomy.get_client_lock_status(m, client_domain="betacorp.com", now_ts=t0 + 10)
        assert st_dom["locked"] is True and st_dom["match"]["client_source"] == "domain"
    finally:
        m.close()


def test_agent_payout_only_after_accepted_plus_14d_and_refund_cancel(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("PADAM_TREASURY_AUTOPAY", raising=False)
    m = Memory(user_id="led_u", store=Store(str(tmp_path / "led.db")))
    try:
        t0 = 1_800_100_000.0
        # Автовывод всегда выключен — только учёт
        assert sovereign_ops.locks_status()["treasury_autopay_locked"] is True

        j1 = freelance_autonomy.evaluate_and_ingest_job(
            m, platform="fiverr_desk", title="Order A", brief="Deliver clean python CLI",
            budget_usdt=100.0, assigned_agent="agent_one", client_external_id="C-1", now_ts=t0,
        )
        freelance_autonomy.package_safe_delivery(m, j1["order_id"], deliverable_text="Done CLI tool")
        # Оплата в t0, но клиент ещё НЕ принял (accepted_at=None)
        paid1 = freelance_autonomy.settle_paid_order(m, j1["order_id"], paid_usdt=100.0, agent_id="agent_one", agent_share_pct=20.0, now_ts=t0)
        assert paid1["agent_payout"]["status"] == "pending"
        # 100 * 85% * 20% = 17.0
        assert paid1["agent_payout"]["amount_usdt"] == pytest.approx(17.0)

        led0 = freelance_autonomy.get_agent_ledger(m, agent_id="agent_one")
        assert led0["pending_usdt"] == pytest.approx(17.0)
        assert led0["credited_usdt"] == pytest.approx(0.0)
        assert led0["cancelled_usdt"] == pytest.approx(0.0)

        # Прошло 20 дней, но приёмки (accepted) ещё нет -> начисления агенту НЕТ (pending)
        r_no_acc = freelance_autonomy.release_matured_payouts(m, now_ts=t0 + 20 * 86400)
        assert r_no_acc["credited_agent_entries"] == 0
        assert freelance_autonomy.get_agent_ledger(m, agent_id="agent_one")["credited_usdt"] == pytest.approx(0.0)

        # Клиент принимает работу в t_acc = t0 + 20d
        t_acc = t0 + 20 * 86400
        acc_res = freelance_autonomy.accept_delivery(m, j1["order_id"], accepted_by="client_c1", now_ts=t_acc)
        assert acc_res["ok"] is True
        assert acc_res["delivery_accepted"] is True

        # Прошло 13 дней после приёмки (< 14) -> доля агента всё ещё в ожидании
        r_before14 = freelance_autonomy.release_matured_payouts(m, now_ts=t_acc + 13 * 86400)
        assert r_before14["credited_agent_entries"] == 0
        assert freelance_autonomy.get_agent_ledger(m, agent_id="agent_one")["credited_usdt"] == pytest.approx(0.0)

        # Истекло 14 дней после приёмки -> доля агента НАЧИСЛЕНА (credited)
        r_after14 = freelance_autonomy.release_matured_payouts(m, now_ts=t_acc + 14 * 86400 + 1)
        assert r_after14["credited_agent_entries"] == 1
        led1 = freelance_autonomy.get_agent_ledger(m, agent_id="agent_one")
        assert led1["credited_usdt"] == pytest.approx(17.0)
        assert led1["pending_usdt"] == pytest.approx(0.0)

        # Второй заказ -> отказ клиента / возврат внутри 14 дней -> отмена с записью причины
        j2 = freelance_autonomy.evaluate_and_ingest_job(
            m, platform="fiverr_desk", title="Order B", brief="Write REST docs",
            budget_usdt=200.0, assigned_agent="agent_two", client_external_id="C-2", now_ts=t0,
        )
        paid2 = freelance_autonomy.settle_paid_order(m, j2["order_id"], paid_usdt=200.0, agent_id="agent_two", agent_share_pct=50.0, now_ts=t0)
        freelance_autonomy.accept_delivery(m, j2["order_id"], now_ts=t0 + 100)
        dis = freelance_autonomy.dispute_held_payout(m, paid2["payout_hold"]["hold_id"], reason="Client requested refund on delivery", now_ts=t0 + 2 * 86400)
        assert dis["status"] == "refunded"
        assert dis["agent_payout_status"] == "cancelled"
        assert "refund" in dis["cancel_reason"].lower()

        led2 = freelance_autonomy.get_agent_ledger(m, agent_id="agent_two")
        assert led2["credited_usdt"] == pytest.approx(0.0)
        assert led2["pending_usdt"] == pytest.approx(0.0)
        assert led2["cancelled_usdt"] == pytest.approx(85.0)
        assert led2["entries"][0]["cancel_reason"] == "Client requested refund on delivery"
        # Автовывод не трогался
        assert sovereign_ops.locks_status()["treasury_autopay_locked"] is True
    finally:
        m.close()


def test_mcp_client_lock_agent_ledger_batch_readonly_and_accept_blocked(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    monkeypatch.setenv("PADAM_AGENT_ID", "agent_mcp")
    mem = Memory(user_id="mcp_fl", store=Store(str(tmp_path / "mcp_fl.db")))
    prev = mcp_server._memory
    mcp_server._memory = mem
    try:
        def hcall(name: str, arguments: dict) -> dict:
            return mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})["result"]

        ev = hcall("padam_freelance_hub", {
            "action": "evaluate_job",
            "title": "MCP QA Job",
            "brief": "Audit MCP schemas and docs",
            "budget_usdt": 100.0,
            "client_email": "lead@startup.io",
        })
        assert ev["isError"] is False
        oid = ev["structuredContent"]["order_id"]
        hcall("padam_freelance_hub", {"action": "deliver", "order_id": oid, "deliverable_text": "All checked"})
        # 18.11.2026 (аудит GLM AUT-02): агент не фиксирует оплату — это делает владелец (Studio) или вебхук площадки
        bad_settle = hcall("padam_freelance_hub", {"action": "settle_paid", "order_id": oid, "paid_usdt": 100.0})
        assert bad_settle["isError"] is True
        from padam import freelance_autonomy as _fa
        _fa.settle_paid_order(mem, oid, paid_usdt=100.0, agent_id="agent_mcp")

        # Прогрев ленивых таблиц до снимка
        hcall("padam_stats", {})
        hcall("padam_freelance_hub", {"action": "client_lock_status", "client_email": "lead@startup.io"})
        hcall("padam_freelance_hub", {"action": "agent_ledger", "agent_id": "agent_mcp"})
        snap_before = _db_snapshot(mem.store.conn)

        # Чтения client_lock_status и agent_ledger работают внутри padam_batch без единой записи в БД
        bat_ok = hcall("padam_batch", {"calls": [
            {"name": "padam_freelance_hub", "arguments": {"action": "client_lock_status", "client_email": "lead@startup.io"}},
            {"name": "padam_freelance_hub", "arguments": {"action": "agent_ledger", "agent_id": "agent_mcp"}},
        ]})
        assert bat_ok["isError"] is False
        assert bat_ok["structuredContent"]["results"][0]["structured"]["locked"] is True
        assert bat_ok["structuredContent"]["results"][1]["structured"]["pending_usdt"] == pytest.approx(12.75)
        assert _db_snapshot(mem.store.conn) == snap_before

        # accept_delivery внутри batch -> PermissionError и isError=True, БД нетронута
        with pytest.raises(PermissionError):
            mcp_server._call_tool_full_impl("padam_batch", {"calls": [
                {"name": "padam_freelance_hub", "arguments": {"action": "accept_delivery", "order_id": oid}},
            ]})
        bat_bad = hcall("padam_batch", {"calls": [
            {"name": "padam_freelance_hub", "arguments": {"action": "accept_delivery", "order_id": oid}},
        ]})
        assert bat_bad["isError"] is True
        assert _db_snapshot(mem.store.conn) == snap_before

        # 18.11.2026 (аудит GLM AUT-03): прямой вызов accept_delivery агентом отклоняется, БД нетронута
        acc = hcall("padam_freelance_hub", {"action": "accept_delivery", "order_id": oid, "accepted_by": "client_lead"})
        assert acc["isError"] is True
        assert _db_snapshot(mem.store.conn) == snap_before
        # владелец принимает работу в Studio (та же функция без MCP)
        assert _fa.accept_delivery(mem, oid, accepted_by="client_lead")["delivery_accepted"] is True
    finally:
        mcp_server._memory = prev
        mem.close()


def test_studio_playwright_client_lock_and_agent_payout_all_langs(tmp_path: Path):
    pw = pytest.importorskip("playwright.sync_api")
    mem = Memory(user_id="ui_lock_owner", store=Store(str(tmp_path / "ui_lock.db")))
    srv = None
    try:
        ru_keys = set(studio.STRINGS["ru"].keys())
        for lg in ("en", "es", "zh"):
            assert set(studio.STRINGS[lg].keys()) == ru_keys
        for k in (
            "earn_job_client_lbl", "earn_client_locked_prefix", "earn_agent_share_prefix",
            "earn_payout_pending", "earn_payout_credited", "earn_payout_cancelled",
            "earn_btn_accept", "earn_btn_refund",
        ):
            assert k in ru_keys

        srv, url = make_studio_server(mem, port=0)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

        with pw.sync_playwright() as p:
            browser = p.chromium.launch()
            for vp in ({"width": 1280, "height": 800}, {"width": 390, "height": 844}):
                page = browser.new_page(viewport=vp)
                js_errors: list[str] = []
                page.on("pageerror", lambda err: js_errors.append(str(err)))
                page.goto(url, wait_until="networkidle")
                page.click("#tab-earning")
                page.wait_for_selector("label[for='earn-job-client']", timeout=5000)

                # Проверяем на ОБОИХ экранах (1280 и 390): оценка -> «Зачислить оплату» -> строка «Доля агента» видна в <=3с БЕЗ перезагрузки
                title_marker = f"Client Lock UI {vp['width']}"
                page.fill("#earn-job-title", title_marker)
                page.fill("#earn-job-brief", "Build clean analytics widget")
                page.fill("#earn-job-budget", "300")
                page.fill("#earn-job-client", f"vip{vp['width']}@clientcorp.com")
                page.click("#earn-eval-btn")
                card = page.locator("#earn-orders-list .earn-item", has_text=title_marker).first
                card.wait_for(state="visible", timeout=3000)

                card.locator("[data-order-action='settle_paid']").click()
                lock_el = card.locator("[data-order-client-lock='1']")
                pay_el = card.locator("[data-order-agent-payout='1']")
                lock_el.wait_for(state="visible", timeout=3000)
                pay_el.wait_for(state="visible", timeout=3000)
                lock_txt = lock_el.text_content() or ""
                pay_txt = pay_el.text_content() or ""
                assert "aifa" in lock_txt and "20" in lock_txt
                assert "Доля агента" in pay_txt and "в ожидании" in pay_txt and "38.25" in pay_txt

                if vp["width"] == 1280:
                    # Принимаем работу клиентом (accept_delivery), затем тестируем возврат (отменено) без перезагрузки
                    card.locator("[data-order-action='accept_delivery']").click()
                    page.wait_for_timeout(200)
                    card.locator("[data-order-action='refund']").click()
                    page.wait_for_function(
                        "(t) => { const c = [...document.querySelectorAll('#earn-orders-list .earn-item')].find(e => e.textContent.includes(t)); return Boolean(c && (c.querySelector('[data-order-agent-payout=\"1\"]')?.textContent || '').includes('отменено')); }",
                        arg=title_marker,
                        timeout=3000,
                    )

                overflow = page.evaluate("() => document.documentElement.scrollWidth > window.innerWidth")
                lbl_ok = page.evaluate("() => { const l = document.querySelector(\"label[for='earn-job-client']\"); return Boolean(l && l.textContent.trim() && l.getBoundingClientRect().height > 5); }")
                assert overflow is False, f"Horizontal overflow on {vp}"
                assert lbl_ok is True
                assert js_errors == [], f"JS errors on {vp}: {js_errors}"
                page.close()
            browser.close()
    finally:
        if srv:
            srv.shutdown()
        mem.close()
