"""GLM раунд 3, FA-01 (Critical): повторная оплата одного заказа (повтор вебхука order.paid) не зачисляет деньги дважды."""
from padam import freelance_autonomy as fa
from padam.memory import Memory
from padam.store import Store


def test_повтор_оплаты_не_удваивает_учёт(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "fa01.db"))
    try:
        j = fa.evaluate_and_ingest_job(m, platform="fiverr_desk", title="Order", brief="Build API endpoint",
                                       budget_usdt=100.0, assigned_agent="agent_alpha", client_email="a@b.io")
        p1 = fa.settle_paid_order(m, j["order_id"], paid_usdt=100.0)
        p2 = fa.settle_paid_order(m, j["order_id"], paid_usdt=100.0)   # повтор того же вебхука
        conn = m.store.conn
        n_mon = conn.execute("SELECT COUNT(*) FROM ark_monetization_ledger WHERE user_id = ? AND note LIKE ?",
                             ("u", f"%{j['order_id']}%")).fetchone()[0]
        n_hold = conn.execute("SELECT COUNT(*) FROM ark_owner_payout_hold WHERE user_id = ? AND order_id = ?",
                              ("u", j["order_id"])).fetchone()[0]
        assert n_mon == 1, f"доход записан {n_mon} раз"
        assert n_hold == 1, f"удержаний {n_hold}"
        assert p2.get("idempotent_replay") is True
    finally:
        m.close()


def test_fa02_сумма_вебхука_не_выше_бюджета(tmp_path):
    import hashlib, hmac, json
    m = Memory(user_id="u2", store=Store(tmp_path / "fa02.db"))
    try:
        acc = fa.connect_exchange_account(m, platform="upwork", api_base_url="https://api.upwork.com",
                                          webhook_secret="fl_wh_sec_123", agent_id="aifa")
        oid = fa.evaluate_and_ingest_job(m, platform="upwork", title="Python Backend Audit", brief="Check API security",
                                         budget_usdt=200.0, work_mode="assisted", account_id=acc["account_id"])["order_id"]
        body = json.dumps({"event": "order.paid", "order_id": oid, "paid_usdt": 250000.0}).encode()
        sig = hmac.new(b"fl_wh_sec_123", body, hashlib.sha256).hexdigest()
        res = fa.verify_and_process_webhook(m, body, sig, account_id=acc["account_id"])
        assert res["ok"] is True
        gross = m.store.conn.execute("SELECT gross_usdt FROM ark_owner_payout_hold WHERE order_id = ?", (oid,)).fetchone()[0]
        assert gross == 200.0, gross                 # не 250 000
    finally:
        m.close()


def test_fa03_отмена_выплаты_только_владелец(tmp_path):
    import pytest
    from padam.roles import ActorContext
    from padam import mcp_server
    m = Memory(user_id="u3", store=Store(tmp_path / "fa03.db"))
    try:
        гость = ActorContext(role="contributor", subject="x", workspace_id="w", via_token=True)
        with pytest.raises(PermissionError):
            fa.dispute_held_payout(m, "hold-x", actor=гость)
        src = open(mcp_server.__file__, encoding="utf-8").read()
        assert 'elif act in ("accept_delivery", "settle_paid", "dispute_payout")' in src
        assert '"bind_referral", "dispute_payout"' not in src            # убрано из схемы MCP
    finally:
        m.close()


def test_fa05_спор_возвращает_начисление_казны(tmp_path):
    from padam import token_autonomy as ta
    m = Memory(user_id="u5", store=Store(tmp_path / "fa05.db"))
    try:
        j = fa.evaluate_and_ingest_job(m, platform="fiverr_desk", title="Order", brief="Build API endpoint",
                                       budget_usdt=100.0, assigned_agent="agent_alpha", client_email="c@d.io")
        fa.settle_paid_order(m, j["order_id"], paid_usdt=100.0)
        до = ta.treasury_summary(m)
        fa.dispute_held_payout(m, order_id=j["order_id"], reason="Client refund")
        после = ta.treasury_summary(m)
        fa.dispute_held_payout  # повторный спор невозможен (статус refunded) — обратная запись одна
        n_neg = m.store.conn.execute("SELECT COUNT(*) FROM ark_earned_treasury WHERE revenue_usdt < 0").fetchone()[0]
        assert n_neg == 1
        def num(sm):
            return [v for k, v in sm.items() if isinstance(v, (int, float)) and "revenue" in k]
        assert num(после) and num(до) and num(после)[0] < num(до)[0], (до, после)
    finally:
        m.close()
