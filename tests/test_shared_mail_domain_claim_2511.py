# 25.11.2026: адрес на общем почтовом сервисе не бронирует и не закрывает весь сервис.
#
# Раньше первое письмо на ivan@gmail.com без сайта организации бронировало «gmail.com» на 30 дней, а ответ STOP
# от одного такого адреса вносил «gmail.com» в стоп-лист навсегда — Феникс больше не мог написать ни одному
# получателю на gmail. Для общих сервисов ключ брони и стоп-листа — полный адрес; домен организации — как прежде.
from padam import email_autonomy as ea
from padam.memory import Memory
from padam.store import Store


def _m(tmp_path):
    return Memory(user_id="u", store=Store(tmp_path / "mail.db"))


def _письмо_отправлено(m, to_email, domain=""):
    ea._ensure_mail_schema(m)
    ключ = ea._ключ_брони(domain, ea._clean_email(to_email))
    import time
    with m.store._lock:
        m.store.conn.execute(
            "INSERT INTO ark_outreach_log (msg_id, user_id, mail_id, domain, recipient_email, direction, subject, status, summary, created_at)"
            " VALUES (?, ?, 'mx', ?, ?, 'outbound_first', 's', 'sent', 'test', ?)",
            (f"msg-{to_email}", m.user_id, ключ, to_email, time.time()),
        )
        m.store.conn.commit()
    return ключ


def test_ключ_брони_общего_сервиса_это_адрес():
    assert ea._ключ_брони("", "Ivan@Gmail.com") == "ivan@gmail.com"
    assert ea._ключ_брони("", "boss@clinic-example.com") == "clinic-example.com"
    assert ea._ключ_брони("clinic-example.com", "owner@gmail.com") == "clinic-example.com"


def test_бронь_одного_адреса_на_gmail_не_закрывает_другой(tmp_path):
    m = _m(tmp_path)
    стоп = tmp_path / "stop.txt"
    _письмо_отправлено(m, "ivan@gmail.com")
    занят, причина = ea.is_blocked_by_stop_or_claim(m, email="ivan@gmail.com", stop_file_path=стоп)
    assert занят and причина == "already_contacted_30d"
    свободен, _ = ea.is_blocked_by_stop_or_claim(m, email="maria@gmail.com", stop_file_path=стоп)
    assert свободен is False


def test_бронь_домена_организации_по_прежнему_общая(tmp_path):
    m = _m(tmp_path)
    стоп = tmp_path / "stop.txt"
    _письмо_отправлено(m, "boss@clinic-example.com")
    занят, причина = ea.is_blocked_by_stop_or_claim(m, email="hr@clinic-example.com", stop_file_path=стоп)
    assert занят and причина == "already_contacted_30d"


def test_stop_с_gmail_не_вносит_весь_gmail_в_стоп_лист(tmp_path):
    m = _m(tmp_path)
    стоп = tmp_path / "stop.txt"
    стоп.write_text("", encoding="utf-8")
    res = ea.add_to_stop_list(m, "ivan@gmail.com", stop_file_path=стоп)
    assert res["added_keys"] == ["ivan@gmail.com"]
    assert "gmail.com" not in стоп.read_text(encoding="utf-8").split()
    занят, _ = ea.is_blocked_by_stop_or_claim(m, email="ivan@gmail.com", stop_file_path=стоп)
    свободен, _ = ea.is_blocked_by_stop_or_claim(m, email="maria@gmail.com", stop_file_path=стоп)
    assert занят is True and свободен is False


def test_stop_с_домена_организации_закрывает_организацию(tmp_path):
    m = _m(tmp_path)
    стоп = tmp_path / "stop.txt"
    стоп.write_text("", encoding="utf-8")
    res = ea.add_to_stop_list(m, "boss@clinic-example.com", stop_file_path=стоп)
    assert set(res["added_keys"]) == {"boss@clinic-example.com", "clinic-example.com"}
    занят, _ = ea.is_blocked_by_stop_or_claim(m, email="hr@clinic-example.com", stop_file_path=стоп)
    assert занят is True


def test_общий_домен_не_уходит_в_бронь_на_сайт(monkeypatch):
    вызовы = []
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("PADAM_AIFA_MCP_TOKEN", "test-token")
    monkeypatch.setattr(ea.urllib.request, "Request", lambda *a, **k: вызовы.append(a) or (_ for _ in ()).throw(RuntimeError("стоп")))
    ea._sync_claim_to_aifa_works("gmail.com")
    ea._sync_claim_to_aifa_works("ivan@gmail.com")
    assert вызовы == []
    ea._sync_claim_to_aifa_works("clinic-example.com")
    assert len(вызовы) == 1
