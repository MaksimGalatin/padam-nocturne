# -*- coding: utf-8 -*-
"""Тесты оффлайн-генератора кошельков (5 сетей), Clickwrap-согласия и инвойсов комиссии CODE (22.11.2026)."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest

from padam import agentic_shield, family_admin, freelance_autonomy, terms_gate, wallet_keygen
from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store


def _http_json(url: str, *, token: str | None = None, payload: dict | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers=headers, method=("POST" if payload is not None else "GET"),
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")


def test_offline_wallet_keygen_5_networks_and_binding(tmp_path: Path):
    assert wallet_keygen.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    mem = Memory(user_id="wal_gen_u", store=Store(tmp_path / "wal.db"))
    try:
        conn_res = freelance_autonomy.connect_exchange_account(
            mem, platform="upwork_api", mode="oauth_api", oauth_token="tok-upwork-demo-001", account_label="MyUpwork",
        )
        assert conn_res["ok"] is True
        for net in ("SOLANA", "USDT_TRC20", "EVM", "BITCOIN", "ARWEAVE"):
            res = family_admin.generate_offline_wallet(
                mem, network=net, label=f"Gen {net}", is_primary=True, bind_to_exchanges=True,
            )
            assert res["ok"] is True
            assert res["network"] == net
            assert res["one_time_secret"]
            v = family_admin.validate_wallet_address(net, res["address"])
            assert v["address"] == res["address"]
            assert "upwork_api" in res["bound_exchanges"]

        # Приватные ключи никогда не утекают в list_wallets, а лежат зашифрованными в БД
        listed = family_admin.list_wallets(mem)
        assert len(listed) == 5
        assert all("one_time_secret" not in w for w in listed)
        sec_rows = mem.store.conn.execute("SELECT secret_enc FROM owner_wallet_secrets").fetchall()
        assert len(sec_rows) == 5
        assert all(str(r["secret_enc"]).startswith(("w1:", "kv1:", "aesgcm")) for r in sec_rows)

        # Последний сгенерированный кошелёк привязан к настройкам выплат и к белому списку Shield
        prefs = freelance_autonomy.get_freelance_prefs(mem)
        assert prefs["payout_wallet_network"] == "ARWEAVE"
        assert prefs["payout_wallet_address"]
        st = agentic_shield.get_shield_status(mem)
        wl_vals = [x.get("value") for x in st.get("allowlist", [])]
        assert prefs["payout_wallet_address"] in wl_vals
    finally:
        mem.close()


def test_terms_clickwrap_cli_setup_and_api_enforcement(tmp_path: Path):
    mem = Memory(user_id="terms_u", store=Store(tmp_path / "terms.db"))
    try:
        assert terms_gate.terms_status(mem)["accepted"] is False
        with pytest.raises(PermissionError):
            terms_gate.require_terms_accepted(mem)
        with pytest.raises(ValueError):
            terms_gate.accept_terms(mem, accept_license=True, accept_commission=False, accept_no_bypass=True)

        # CLI setup без --accept-terms должен отказать в записи конфигов!
        db_cli = tmp_path / "cli_terms.db"
        repo_root = Path(__file__).resolve().parents[1]
        proj = tmp_path / "proj"
        proj.mkdir()
        r_no = subprocess.run(
            [sys.executable, "-m", "padam", "--db", str(db_cli), "setup", "--client", "claude_code", "--project-dir", str(proj)],
            cwd=str(repo_root), stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
        )
        assert r_no.returncode == 2
        assert "terms_acceptance_required" in r_no.stdout
        assert not (proj / ".mcp.json").exists()

        # С --accept-terms установка разрешается и квитанция пишется в БД
        r_yes = subprocess.run(
            [sys.executable, "-m", "padam", "--db", str(db_cli), "setup", "--client", "claude_code", "--project-dir", str(proj), "--accept-terms"],
            cwd=str(repo_root), capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
        )
        assert r_yes.returncode == 0, r_yes.stderr
        assert (proj / ".mcp.json").is_file()
        m_cli = Memory(user_id="default", store=Store(db_cli))
        try:
            assert terms_gate.terms_status(m_cli)["accepted"] is True
        finally:
            m_cli.close()
    finally:
        mem.close()


def test_code_fee_invoice_autosplit_and_arrears_tamper_guard(tmp_path: Path):
    mem = Memory(user_id="fee_inv_u", store=Store(tmp_path / "fee.db"))
    try:
        # 1. Наш канал (aifafocus_mcp) -> автоматический сплит settled
        ev_auto = freelance_autonomy.evaluate_and_ingest_job(
            mem,
            platform="aifafocus_mcp",
            title="Direct Site Audit",
            brief="Audit website",
            budget_usdt=200.0,
            work_mode="autopilot",
        )
        set_auto = freelance_autonomy.settle_paid_order(mem, ev_auto["order_id"], paid_usdt=200.0)
        assert set_auto["code_fee_invoice"]["settlement_rail"] == "auto_split"
        assert set_auto["code_fee_invoice"]["status"] == "auto_split_settled"
        assert set_auto["code_fee_invoice"]["fee_usdt"] == 40.0  # 20% autopilot
        assert freelance_autonomy.fee_arrears_guard(mem)["blocked"] is False

        # 2. Внешняя биржа (upwork_api) -> счёт invoice_due; при просрочке (>14д) блокирует автопилот!
        ev_ext = freelance_autonomy.evaluate_and_ingest_job(
            mem,
            platform="upwork_api",
            title="External React Dashboard",
            brief="Build React app",
            budget_usdt=400.0,
            work_mode="assisted",
        )
        t_start = 1_700_000_000.0
        set_ext = freelance_autonomy.settle_paid_order(mem, ev_ext["order_id"], paid_usdt=400.0, now_ts=t_start)
        inv_id = set_ext["code_fee_invoice"]["invoice_id"]
        assert set_ext["code_fee_invoice"]["status"] == "invoice_due"
        assert set_ext["code_fee_invoice"]["fee_usdt"] == 60.0  # 15% assisted

        # Через 15 дней без погашения срабатывает fee_arrears_guard и блокирует автопилот
        guard_late = freelance_autonomy.fee_arrears_guard(mem, now_ts=t_start + 15 * 86400)
        assert guard_late["blocked"] is True
        assert guard_late["overdue_count"] == 1

        # Активируем автопилот на старых просроченных записях — цикл должен отказаться с code_fee_settlement_required
        mem.store.conn.execute("UPDATE ark_code_fee_invoice SET due_ts = 100.0 WHERE invoice_id = ?", (inv_id,))
        mem.store.conn.commit()
        freelance_autonomy.set_autopilot_state(mem, running=True)
        cyc = freelance_autonomy.run_autopilot_cycle(mem)
        assert cyc["ok"] is False and cyc["reason"] == "code_fee_settlement_required"

        # Погашаем счёт -> блокировка снимается
        freelance_autonomy.mark_code_fee_paid(mem, inv_id, tx_ref="soltx-verified-001")
        assert freelance_autonomy.fee_arrears_guard(mem)["blocked"] is False

        # Подмена адреса казны в таблице мгновенно ловится HMAC/treasury проверкой!
        mem.store.conn.execute("UPDATE ark_code_fee_invoice SET treasury_wallet = 'FakeAttackerWallet111' WHERE invoice_id = ?", (inv_id,))
        mem.store.conn.commit()
        guard_tamper = freelance_autonomy.fee_arrears_guard(mem)
        assert guard_tamper["blocked"] is True
        assert inv_id in guard_tamper["tampered_invoices"]
    finally:
        mem.close()


def test_studio_terms_and_offline_wallet_gen_playwright(tmp_path: Path):
    pw = pytest.importorskip("playwright.sync_api")
    mem = Memory(user_id="ui_wal_terms_u", store=Store(tmp_path / "ui_wt.db"))
    srv = None
    t_srv = None
    try:
        srv, url = make_studio_server(mem, port=0)
        t_srv = threading.Thread(target=srv.serve_forever, daemon=True)
        t_srv.start()
        with pw.sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            js_errs: list[str] = []
            page.on("pageerror", lambda e: js_errs.append(str(e)))
            page.goto(url, wait_until="networkidle")
            page.click("#tab-earning")
            page.wait_for_selector("#earn-terms-box", timeout=15000)

            # Клик без 3 галочек не принимает соглашение
            page.click("#terms-accept-btn")
            assert terms_gate.terms_status(mem)["accepted"] is False

            # Отмечаем все 3 обязательные галочки и подтверждаем
            page.check("#terms-chk-license")
            page.check("#terms-chk-commission")
            page.check("#terms-chk-nobypass")
            with page.expect_response("**/api/v2/ark/terms", timeout=15000) as r_terms:
                page.click("#terms-accept-btn")
            assert r_terms.value.status == 200
            assert terms_gate.terms_status(mem)["accepted"] is True

            # Генерируем оффлайн USDT_TRC20 кошелёк прямо в браузере и видим разовый секрет + карточку
            page.select_option("#wal-earn-net", "USDT_TRC20")
            page.fill("#wal-earn-lbl", "My Safe TRON")
            with page.expect_response("**/api/v2/wallets", timeout=15000) as r_wal:
                page.click("#wal-earn-gen-btn")
            assert r_wal.value.status == 200
            page.wait_for_function(
                "() => !document.querySelector('#wal-earn-secret-out').hidden && document.querySelector('#wal-earn-secret-out').textContent.includes('USDT_TRC20')",
                timeout=15000,
            )
            page.wait_for_function(
                "() => document.querySelector('#wal-earn-list').textContent.includes('My Safe TRON')",
                timeout=15000,
            )
            assert js_errs == []
            page.close()
            browser.close()
    finally:
        if srv:
            srv.shutdown()
            srv.server_close()
        if t_srv:
            t_srv.join(timeout=2)
        time.sleep(0.1)
        mem.close()
