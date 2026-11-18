from __future__ import annotations

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
