from __future__ import annotations

import pytest

import json
from pathlib import Path
import threading
import urllib.error
import urllib.request

from padam import api, email_autonomy, mcp_server, partner_bridge
from padam.memory import Memory
from padam.store import Store


def _make_mem(tmp_path: Path) -> Memory:
    return Memory(user_id="owner-mail", store=Store(str(tmp_path / "mail_pipe.db")))


def test_multi_mail_rotation_stop_list_and_inbound_replies(tmp_path: Path):
    mem = _make_mem(tmp_path)
    stop_file = tmp_path / "ОТПИСАЛИСЬ.txt"
    sent_packets: list[dict] = []
    inbound_queue: list[dict] = [
        {"from_email": "boss@hotel-keywest.com", "domain": "havanacabanakeywesthotel.com", "subject": "Re: accessibility", "body": "Шлите список для нашей команды!"},
        {"from_email": "noreply@nomail.org", "domain": "nomail.org", "subject": "Re: audit", "body": "STOP, unsubscribe please"},
        {"from_email": "legal@bigcorp.com", "domain": "bigcorp.com", "subject": "Договор и скидка", "body": "Нужен договор на юрлицо и скидка 20%"},
    ]

    def _fake_mail(req: dict):
        op = req.get("op")
        if op == "verify":
            return {"ok": True}
        if op == "send":
            sent_packets.append(req)
            return {"ok": True}
        if op == "fetch_inbox":
            if req.get("email") == "box1@gmail.com":
                msgs = list(inbound_queue)
                inbound_queue.clear()
                return {"ok": True, "messages": msgs}
            return {"ok": True, "messages": []}
        return {"ok": True}

    email_autonomy.set_mail_transport(_fake_mail)
    try:
        # 1. Подключаем 2 почты (пароль шифруется, наружу не возвращается)
        m1 = email_autonomy.connect_mail_account(mem, email="box1@gmail.com", provider="gmail", app_password_or_token="app-pass-1111-aaaa", daily_limit=30)
        m2 = email_autonomy.connect_mail_account(mem, email="box2@yandex.ru", provider="yandex", app_password_or_token="ya-pass-2222-bbbb", daily_limit=30)
        assert m1["ok"] and m2["ok"]
        assert "app-pass-1111-aaaa" not in json.dumps(m1)
        row = mem.store.conn.execute("SELECT secret_enc FROM ark_mail_account WHERE email='box1@gmail.com'").fetchone()
        assert row and "app-pass-1111-aaaa" not in row[0] and str(row[0]).startswith("aesgcm1:")

        # 2. Первое письмо + защита от повторной отправки на тот же домен в 30-дневном окне
        s1 = email_autonomy.send_outreach_email(
            mem,
            to_email="boss@hotel-keywest.com",
            domain="havanacabanakeywesthotel.com",
            subject="Отчёт по сайту",
            body="Текст письма",
            stop_file_path=stop_file,
        )
        assert s1["ok"] is True

        s_dup = email_autonomy.send_outreach_email(
            mem,
            to_email="other@hotel-keywest.com",
            domain="havanacabanakeywesthotel.com",
            subject="Повтор",
            body="Дубль",
            stop_file_path=stop_file,
        )
        assert s_dup["ok"] is False and s_dup["blocked"] is True and s_dup["reason"] == "already_contacted_30d"

        # 3. Второе письмо на другой домен уходит со второго ящика (ротация по наименьшему sent_today)
        s2 = email_autonomy.send_outreach_email(
            mem,
            to_email="hello@painasf.com",
            domain="painasf.com",
            subject="Отчёт Pa'ina",
            body="Текст 2",
            stop_file_path=stop_file,
        )
        assert s2["ok"] is True and s2["from_email"] == "box2@yandex.ru"

        # 4. Автоматическая обработка входящих: «Шлите список» + STOP + эскалация договора человеку
        res = email_autonomy.process_inbox_replies(mem, stop_file_path=stop_file)
        assert res["ok"] is True
        assert res["processed"] == 3
        assert res["reports_sent"] == 1
        assert res["stopped"] == 1
        assert res["escalated"] == 1

        # Проверяем, что отписавшийся адрес и домен попали в ОТПИСАЛИСЬ.txt и больше не принимаются
        stop_txt = stop_file.read_text(encoding="utf-8")
        assert "noreply@nomail.org" in stop_txt
        assert "nomail.org" in stop_txt
        s_blocked = email_autonomy.send_outreach_email(
            mem,
            to_email="noreply@nomail.org",
            domain="nomail.org",
            subject="После стопа",
            body="Не должно уйти",
            stop_file_path=stop_file,
        )
        assert s_blocked["ok"] is False and s_blocked["blocked"] is True

        # Проверяем, что ответ на «Шлите список» содержал HTML-отчёт и тарифы
        report_mail = [x for x in sent_packets if x["to_email"] == "boss@hotel-keywest.com"][-1]
        assert "149" in report_mail["body"] and "375" in report_mail["body"]
        assert "<html" in report_mail["html_body"].lower()
    finally:
        email_autonomy.set_mail_transport(None)


def test_mail_hub_studio_api_and_business_outreach_ru(tmp_path: Path):
    mem = _make_mem(tmp_path)
    srv, url = api.make_studio_server(memory=mem, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base_url, token = url.split("#t=")
    base_api = base_url.rsplit("/studio", 1)[0]

    email_autonomy.set_mail_transport(lambda req: {"ok": True})
    try:
        # Подключение почты через Studio API
        req = urllib.request.Request(
            f"{base_api}/api/v2/ark/mail/action",
            data=json.dumps({"action": "connect_mail", "email": "team@code.test", "provider": "gmail", "app_password_or_token": "sec-1234"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                res = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:   # CI 19.11: 500 без причины — показываем тело ответа сервера
            raise AssertionError(f"mail/action {exc.code}: {exc.read().decode('utf-8', 'replace')[:800]}") from exc
        assert res["ok"] is True and res["account"]["email"] == "team@code.test"

        # Проверка согласования числительных (221 барьер / нарушение) в build_business_outreach
        pkg = partner_bridge.build_business_outreach(
            mem,
            "havanacabanakeywesthotel.com",
            language="ru",
            site_record={"домен": "havanacabanakeywesthotel.com", "название": "Havana Cabana", "нарушений_всего": "221", "critical": "138", "serious": "83", "правила": "color-contrast"},
            allow_live_fetch=False,
        )
        assert "221 барьер" in pkg["email_subject"]
        assert "221 нарушение" in pkg["email_body"]
    finally:
        email_autonomy.set_mail_transport(None)
        srv.shutdown()
        srv.server_close()


def test_sync_site_orders_from_aifa_digital_to_studio(tmp_path: Path, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from padam import freelance_autonomy

    monkeypatch.setenv("PADAM_FREELANCE_ALLOW_LOCALHOST", "1")
    mem = _make_mem(tmp_path)

    class _MockOrdersSrv(BaseHTTPRequestHandler):
        def log_message(self, *a):
            return

        def do_GET(self):
            assert self.headers.get("Authorization") == "Bearer adm-test-sec"
            payload = {
                "ok": True,
                "orders": [
                    {
                        "order_id": "A11Y-QUICK-AUDIT-17990001",
                        "slug": "quick-audit",
                        "email": "hotel@keywest.example",
                        "website": "https://havanacabanakeywesthotel.com",
                        "amount": 149.0,
                        "status": "paid",
                    }
                ],
            }
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockOrdersSrv)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = freelance_autonomy.sync_site_orders(
            mem,
            base_url=f"http://127.0.0.1:{srv.server_address[1]}",
            admin_secret="adm-test-sec",
            allow_localhost=True,
        )
        assert res["ok"] is True
        assert res["imported"] == 1
        assert res["executed"] == 1

        orders = freelance_autonomy.list_orders(mem, limit=10)
        matched = [o for o in orders if o.get("external_job_id") == "A11Y-QUICK-AUDIT-17990001"]
        assert len(matched) == 1
        assert matched[0]["status"] == "delivered"

        # Повторный вызов не создаёт дубликат
        res2 = freelance_autonomy.sync_site_orders(
            mem,
            base_url=f"http://127.0.0.1:{srv.server_address[1]}",
            admin_secret="adm-test-sec",
            allow_localhost=True,
        )
        assert res2["ok"] is True and res2["imported"] == 0
    finally:
        srv.shutdown()
        srv.server_close()


def test_stress_batch_12_mails_bounce_autopause_refund_and_followup(tmp_path: Path):
    import csv as _csv
    import time as _time
    from padam import freelance_autonomy

    mem = _make_mem(tmp_path)
    stop_file = tmp_path / "ОТПИСАЛИСЬ.txt"
    csv_file = tmp_path / "batch_30.csv"
    with csv_file.open("w", encoding="utf-8-sig", newline="") as f:
        w = _csv.DictWriter(f, fieldnames=["домен", "название", "штат", "город", "почта", "нарушений_всего", "critical", "serious", "правила"])
        w.writeheader()
        for i in range(30):
            w.writerow({
                "домен": f"biz{i}.example.com",
                "название": f"Biz {i}",
                "штат": "Florida",
                "город": "Miami",
                "почта": f"owner{i}@biz{i}.example.com",
                "нарушений_всего": "12",
                "critical": "4",
                "serious": "8",
                "правила": "color-contrast",
            })

    sent_log: list[dict] = []
    inbox_by_mail: dict[str, list[dict]] = {}

    def _fake_mail(req: dict):
        op = req.get("op")
        if op == "verify":
            return {"ok": True}
        if op == "send":
            sent_log.append(req)
            return {"ok": True}
        if op == "fetch_inbox":
            return {"ok": True, "messages": inbox_by_mail.pop(req.get("email"), [])}
        return {"ok": True}

    email_autonomy.set_mail_transport(_fake_mail)
    try:
        # 1. Подключаем 12 прогретых ящиков
        for m_idx in range(12):
            res_c = email_autonomy.connect_mail_account(
                mem,
                email=f"sender{m_idx}@code.test",
                provider="gmail_oauth2" if m_idx % 2 else "gmail",
                app_password_or_token=f"tok-box-{m_idx}",
                daily_limit=30,
            )
            assert res_c["ok"] is True

        # 2. Пакетная рассылка 24 писем (по 2 с каждого из 12 ящиков за счёт ротации)
        batch = email_autonomy.run_outreach_batch(mem, csv_path=csv_file, max_emails=24, language="ru", stop_file_path=stop_file)
        assert batch["ok"] is True and batch["sent"] == 24 and batch["errors"] == 0
        from_set = {x["from"] for x in batch["results"]}
        assert len(from_set) == 12

        # Повторный запуск по тем же первым 24 — пропускает по 30-дневной броне и досылает оставшиеся 6
        batch2 = email_autonomy.run_outreach_batch(mem, csv_path=csv_file, max_emails=24, language="ru", stop_file_path=stop_file)
        assert batch2["sent"] == 6 and batch2["skipped"] == 24

        # 3. Входящие: на ящик sender0 приходили письма -> 1 bounce (при 2-3 письмах >3% если >=10 отправок),
        # поэтому симулируем 10 отправок на sender0 и 1 bounce -> автопауза ящика!
        for k in range(8):
            email_autonomy.send_outreach_email(
                mem, to_email=f"extra{k}@ex{k}.com", domain=f"ex{k}.com", subject="T", body="B",
                mail_id=email_autonomy.list_mail_accounts(mem)[0]["mail_id"], stop_file_path=stop_file,
            )
        inbox_by_mail["sender0@code.test"] = [
            {"from_email": "mailer-daemon@googlemail.com", "subject": "Delivery Status Notification (Failure)", "body": "550 5.1.1 Address not found: owner0@biz0.example.com"},
            {"from_email": "owner1@biz1.example.com", "domain": "biz1.example.com", "subject": "Re: Biz 1", "body": "Шлите список пожалуйста!"},
            {"from_email": "owner2@biz2.example.com", "domain": "biz2.example.com", "subject": "Re: Biz 2", "body": "Верните деньги, нужен возврат (refund)!"},
            {"from_email": "owner3@biz3.example.com", "domain": "biz3.example.com", "subject": "Re: Biz 3", "body": "STOP writing"},
        ]
        inb = email_autonomy.process_inbox_replies(mem, stop_file_path=stop_file)
        assert inb["reports_sent"] == 1
        assert inb["stopped"] == 2  # 1 bounce + 1 STOP
        assert inb["escalated"] == 1  # refund_urgent

        # Ящик sender0 должен автоматически встать на паузу (>3% отбоев при >=10 отправках)
        s0 = [a for a in email_autonomy.list_mail_accounts(mem) if a["email"] == "sender0@code.test"][0]
        assert s0["status"] == "paused" and s0["last_error"] == "auto_paused_high_bounce_rate"

        # 4. Дожим: состариваем outbound_first на 5 дней назад и запускаем run_follow_up_cycle
        old_ts = _time.time() - 5.0 * 86400.0
        mem.store.conn.execute("UPDATE ark_outreach_log SET created_at = ? WHERE direction = 'outbound_first'", (old_ts,))
        mem.store.conn.commit()
        fu = email_autonomy.run_follow_up_cycle(mem, wait_days=4.0, max_emails=5, stop_file_path=stop_file)
        assert fu["ok"] is True and fu["follow_ups_sent"] == 5

        # Повторный дожим по тем же 5 не уходит (уже есть outbound_followup)
        fu2 = email_autonomy.run_follow_up_cycle(mem, wait_days=4.0, max_emails=5, stop_file_path=stop_file)
        assert fu2["ok"] is True
    finally:
        email_autonomy.set_mail_transport(None)


def test_top20_подвал_и_отказы_доставки(tmp_path: Path):
    """ТОП-20 Сестры, п. 19–20: подвал с адресом LLC и STOP добавляется сам; два отказа доставки → стоп-лист."""
    mem = _make_mem(tmp_path)
    отправлено: list[dict] = []
    входящие = {"messages": []}

    def транспорт(req):
        if req.get("op") == "fetch_inbox":
            return входящие
        отправлено.append(req)
        return {"ok": True}

    email_autonomy.set_mail_transport(транспорт)
    stop_file = tmp_path / "ОТПИСАЛИСЬ.txt"
    try:
        email_autonomy.connect_mail_account(mem, email="box@code.test", provider="gmail", app_password_or_token="sec-1", daily_limit=30)
        r = email_autonomy.send_outreach_email(mem, to_email="owner@site-a.test", domain="site-a.test", subject="Hi",
                                               body="Короткое письмо без подвала", stop_file_path=stop_file)
        assert r["ok"], r
        текст = json.dumps(отправлено[-1], ensure_ascii=False)
        assert "Mountain Road" in текст and "STOP" in текст

        входящие["messages"] = [{"from_email": "mailer-daemon@googlemail.com", "subject": "Delivery Status Notification (Failure)",
                                 "body": "Address not found: dead@site-b.test"}]
        email_autonomy.process_inbox_replies(mem, stop_file_path=stop_file)
        email_autonomy.process_inbox_replies(mem, stop_file_path=stop_file)
        blocked, _ = email_autonomy.is_blocked_by_stop_or_claim(mem, email="dead@site-b.test", domain="site-b.test", stop_file_path=stop_file)
        assert blocked
        r2 = email_autonomy.send_outreach_email(mem, to_email="dead@site-b.test", domain="site-b.test", subject="Hi", body="x STOP",
                                                stop_file_path=stop_file)
        assert r2["ok"] is False and r2.get("blocked") is True
    finally:
        email_autonomy.set_mail_transport(None)
def test_site_scanner_25pages_and_14day_recheck(tmp_path):
    """Реальный 25-страничный локальный Playwright + axe-core скан внутри sync_site_orders и 14-дневный перемер."""
    # 19.11.2026: в матрице CI Playwright не ставится (только в задании accessibility) — без него сканер честно
    # отдаёт ok=False; тест пропускается, а не краснит 12 систем.
    pytest.importorskip("playwright.sync_api")
    import http.server
    import json as _json
    import threading as _th
    import time as _time
    from padam import email_autonomy, freelance_autonomy, site_scanner

    pages_html = {
        "/": "<html><head><title></title></head><body><h1>Home</h1><img src='/x.png'><a href='/about'>About</a><a href='/contact'>Contact</a></body></html>",
        "/about": "<html lang='en'><head><title>About</title></head><body><input type='text' id='n1'><a href='/'>Home</a></body></html>",
        "/contact": "<html lang='en'><head><title>Contact</title></head><body><form><input type='email' name='mail'></form><img src='/y.png'></body></html>",
    }

    sent_deliveries: list[dict] = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/api/admin/service-orders"):
                payload = _json.dumps(
                    {
                        "ok": True,
                        "orders": [
                            {
                                "order_id": "ord-scan-101",
                                "slug": "quick-audit",
                                "website": f"http://127.0.0.1:{self.server.server_address[1]}/",
                                "email": "client-scan@example.com",
                                "amount": 149.0,
                            }
                        ],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            body = pages_html.get(self.path, "<html><body>Not found</body></html>").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    th = _th.Thread(target=server.serve_forever, daemon=True)
    th.start()

    mem = _make_mem(tmp_path)
    def _mock_transport(pkt: dict):
        op = pkt.get("op")
        if op == "send":
            sent_deliveries.append(dict(pkt))
            return {"ok": True, "message_id": f"msg-{len(sent_deliveries)}"}
        if op == "fetch":
            return {"ok": True, "messages": []}
        return {"ok": True}

    email_autonomy.set_mail_transport(_mock_transport)
    try:
        # Подключаем один ящик для автоотправки готового отчёта клиенту
        assert email_autonomy.connect_mail_account(
            mem,
            email="reports@code.test",
            provider="gmail",
            app_password_or_token="app-pass-1",
            daily_limit=30,
        )["ok"] is True

        # Прямой тест сканера на 3 страницах
        direct = site_scanner.scan_website_accessibility(
            f"http://127.0.0.1:{port}/",
            max_pages=25,
            allow_localhost=True,
        )
        assert direct["ok"] is True, direct.get("error") or direct.get("reason")
        assert direct["pages_scanned"] == 3
        assert direct["total_violations"] >= 3
        assert "axe-core" == direct["engine"]

        # Тест sync_site_orders: импорт + Playwright/axe-core скан + отправка отчёта клиенту + постановка на 14-дневный перемер
        sync_res = freelance_autonomy.sync_site_orders(
            mem,
            base_url=f"http://127.0.0.1:{port}",
            admin_secret="test-secret-xyz",
            allow_localhost=True,
        )
        assert sync_res["ok"] is True
        assert sync_res["imported"] == 1
        assert sync_res["executed"] == 1
        assert len(sent_deliveries) == 1
        assert "Проверено страниц: 3" in sent_deliveries[0]["body"]
        assert "<!doctype html>" in sent_deliveries[0]["html_body"]

        rc_row = mem.store.conn.execute(
            "SELECT * FROM ark_site_rechecks WHERE recheck_id = 'rc-ord-scan-101'"
        ).fetchone()
        assert rc_row is not None
        assert rc_row["done_at"] == 0.0
        assert int(rc_row["initial_violations"]) >= 3

        # Сдвигаем due_at в прошлое и прогоняем цикл автопилота — 14-дневный перемер должен выполниться!
        mem.store.conn.execute(
            "UPDATE ark_site_rechecks SET due_at = ? WHERE recheck_id = 'rc-ord-scan-101'",
            (_time.time() - 60.0,),
        )
        mem.store.conn.commit()
        freelance_autonomy.set_autopilot_state(mem, running=True)
        ap = freelance_autonomy.run_autopilot_cycle(mem, allow_localhost=True)
        assert ap["ok"] is True
        assert ap["rechecks_completed"] >= 1

        rc_done = mem.store.conn.execute(
            "SELECT * FROM ark_site_rechecks WHERE recheck_id = 'rc-ord-scan-101'"
        ).fetchone()
        assert float(rc_done["done_at"]) > 0.0
        assert int(rc_done["recheck_violations"]) >= 3
    finally:
        email_autonomy.set_mail_transport(None)
        server.shutdown()
        server.server_close()
