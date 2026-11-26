# 26.11.2026: письмо о нарушениях доступности уходит, только если нарушения есть.
#
# Образец письма для репетиции (наш сайт, 0 нарушений) сказал: «flagged 0 WCAG 2.1 AA rule instances … in these
# categories: • unlabeled interactive buttons, missing keyboard focus indicators, or low-contrast text» — шаблон
# подставлял запасную категорию и при нуле. Теперь запасная строка — только при нарушениях без названий правил,
# а пакетная рассылка пропускает сайт без нарушений.
from pathlib import Path

from padam import email_autonomy, partner_bridge
from padam.memory import Memory
from padam.store import Store


def _m(tmp_path: Path, name: str) -> Memory:
    return Memory(user_id="owner-nofind", store=Store(str(tmp_path / f"{name}.db")))


def test_шаблон_без_нарушений_не_выдумывает_категорий(tmp_path):
    m = _m(tmp_path, "tpl")
    for lang in ("en", "ru"):
        pkg = partner_bridge.build_business_outreach(
            m, "clean-example.org", language=lang, allow_live_fetch=False,
            site_record={"domain": "clean-example.org", "нарушений_всего": 0, "critical": 0, "serious": 0, "правила": ""})
        assert pkg["has_findings"] is False
        body = pkg["email_body"]
        assert "unlabeled interactive buttons" not in body
        assert "барьеры контрастности, навигации с клавиатуры" not in body


def test_шаблон_с_нарушениями_без_правил_оставляет_запасную_строку(tmp_path):
    m = _m(tmp_path, "tpl2")
    pkg = partner_bridge.build_business_outreach(
        m, "broken-example.org", language="en", allow_live_fetch=False,
        site_record={"domain": "broken-example.org", "нарушений_всего": 7, "critical": 2, "serious": 3, "правила": ""})
    assert pkg["has_findings"] is True
    assert "unlabeled interactive buttons" in pkg["email_body"]


def test_пакетная_рассылка_пропускает_сайт_без_нарушений(tmp_path):
    m = _m(tmp_path, "batch")
    отправлено: list[dict] = []

    def _fake(req: dict):
        if req.get("op") == "send":
            отправлено.append(req)
        return {"ok": True}

    email_autonomy.set_mail_transport(_fake)
    try:
        assert email_autonomy.connect_mail_account(
            m, email="box@example.org", provider="gmail", app_password_or_token="app-pass-test-0000", daily_limit=30)["ok"]
        csv_path = tmp_path / "leads.csv"
        csv_path.write_text(
            "домен,название,почта,нарушений_всего,critical,serious,правила\n"
            "clean-example.org,Clean Co,owner@clean-example.org,0,0,0,\n"
            "broken-example.org,Broken Co,owner@broken-example.org,7,2,3,color-contrast;image-alt\n",
            encoding="utf-8")
        res = email_autonomy.run_outreach_batch(m, csv_path=csv_path, max_emails=10, language="en",
                                                stop_file_path=tmp_path / "stop.txt")
    finally:
        email_autonomy.set_mail_transport(None)
    assert res["sent"] == 1, res
    assert {"domain": "clean-example.org", "skipped": "no_findings"} in res["results"]
    assert len(отправлено) == 1


def test_без_лидов_старая_база_только_по_явному_флагу(tmp_path, monkeypatch):
    # 26.11.2026: при пустой таблице лидов автопилот не берёт старую базу (замер 07.09) сам — только с флагом.
    m = _m(tmp_path, "stale")
    старая = tmp_path / "old.csv"
    старая.write_text("домен,почта,нарушений_всего,critical,serious,правила\nold-example.org,a@old-example.org,5,1,1,image-alt\n",
                      encoding="utf-8")
    monkeypatch.setattr(email_autonomy, "_DEFAULT_US_CSV", старая)
    monkeypatch.delenv("PADAM_OUTREACH_ALLOW_STALE_CSV", raising=False)
    res = email_autonomy.run_outreach_batch(m, max_emails=5, stop_file_path=tmp_path / "stop.txt")
    assert res["ok"] is False and res["sent"] == 0 and "замером" in res["error"]


def test_объяснения_правил_одинаковы_на_двух_языках():
    # 26.11.2026: каждое объяснённое правило объяснено и по-английски, и по-русски.
    en, ru = partner_bridge._WCAG_RULE_EXPLANATIONS_EN, partner_bridge._WCAG_RULE_EXPLANATIONS_RU
    assert set(en) == set(ru)
    for частое in ("region", "heading-order", "landmark-one-main", "frame-title", "select-name", "page-has-heading-one"):
        assert частое in en and len(en[частое]) > 40
