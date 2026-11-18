"""Ошибка ввода — 400 с понятным текстом, а не «внутренняя» 500 (обход кнопок 18.11: «Предложить рефлекс» → 500)."""
import json
import threading
import urllib.error
import urllib.request

from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store


def test_пустой_рефлекс_даёт_400(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "e.db"))
    srv, url = make_studio_server(m, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = url.split("/studio")[0]
        tok = url.split("#t=")[1]
        req = urllib.request.Request(base + "/api/v2/family/reflex/propose", data=json.dumps({"trigger": "", "response": ""}).encode(),
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok, "X-PADAM-Token": tok}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            raise AssertionError("ожидался отказ")
        except urllib.error.HTTPError as e:
            assert e.code == 400, e.code
            assert "3 characters" in json.loads(e.read())["error"]
    finally:
        srv.shutdown(); srv.server_close(); m.close()


def test_кнопка_проверяет_поля_до_запроса():
    from padam import studio
    html = studio.page()[0]
    assert "tr.length < 3 || rs.length < 3" in html
    src = open(studio.__file__, encoding="utf-8").read()
    assert src.count('"ff_ref_short"') == 4


def test_бенчмарк_на_4_языках():
    from padam import studio
    src = open(studio.__file__, encoding="utf-8").read()
    for k in ("bench_html", "bench_qa", "bench_fuzz", "bench_verify", "bench_qa_title", "bench_f1", "bench_d1", "bench_d10"):
        assert src.count(f'"{k}": ') == 4, k
    html = studio.page()[0]
    assert ">HTML Report<" not in html and ">Verify Ed25519 Seal<" not in html


def test_бенчмарк_честный_и_свежесть(tmp_path):
    from padam import aifa_sec_bridge as b
    r = b.get_aifa_security_report()
    assert r["cached"] is True and "generated_at" in r and r["cache_age_hours"] >= 0
    assert "deterministic" in r["honest_note"] and isinstance(r["stale"], bool)
    from padam import studio
    src = open(studio.__file__, encoding="utf-8").read()
    for k in ("bench_cached", "bench_fresh", "bench_stale", "bench_honest"):
        assert src.count(f'"{k}": ') == 4, k
