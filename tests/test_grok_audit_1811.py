"""Доработки по экспертному аудиту Grok (18.11.2026): понятные владельцу статусы и подсказки."""
from padam import platform_wizard as w


def test_каждая_площадка_со_статусом_и_шагом():
    ps = w.list_platform_catalog()["platforms"]
    assert len(ps) == 34
    for p in ps:
        for k in ("owner_status_ru", "owner_status_en", "next_action_ru", "next_action_en"):
            assert p.get(k), (p.get("platform_id"), k)
    fv = next(p for p in ps if p["platform_id"] == "fiverr")
    assert "запрещают ботов" in fv["owner_status_ru"]


def test_адаптер_биржи_повторяет_503_и_не_повторяет_запрет():
    import json, threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from padam.freelance_autonomy import ExchangeHttpAdapter
    счёт = {"n": 0}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            счёт["n"] += 1
            if счёт["n"] == 1:
                self.send_response(503); self.end_headers(); return
            b = json.dumps({"jobs": []}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        a = ExchangeHttpAdapter(f"http://127.0.0.1:{srv.server_address[1]}", allow_localhost=True)
        assert a.timeout_s == 15.0
        code, data = a.request_json("GET", "/jobs")
        assert code == 200 and счёт["n"] == 2          # 503 повторён
    finally:
        srv.shutdown(); srv.server_close()
    code2, data2 = ExchangeHttpAdapter("http://169.254.169.254").request_json("GET", "/x")
    assert code2 == 400                                  # запрет защиты — сразу, без повторов


def test_сводка_фриланса_для_владельца(tmp_path):
    from padam import freelance_autonomy as fa
    from padam.memory import Memory
    from padam.store import Store
    m = Memory(user_id="u", store=Store(tmp_path / "ds.db"))
    try:
        j = fa.evaluate_and_ingest_job(m, platform="fiverr_desk", title="Order", brief="Build API endpoint", budget_usdt=50.0)
        fa.draft_bid_from_memory(m, j["order_id"])
        d = fa.freelance_dashboard_snapshot(m)
        assert d["owner_summary_ru"].startswith("Автопилот: остановлен; заказов: 1;")
        assert "need your attention" in d["owner_summary_en"]
    finally:
        m.close()


def test_магазины_подсказывают_шаг(tmp_path):
    from padam import digital_stores as ds
    from padam.memory import Memory
    from padam.store import Store
    m = Memory(user_id="u", store=Store(tmp_path / "st.db"))
    try:
        r = ds.seed_starter_product_drafts(m)
        assert "Опубликовать" in r["next_step"]["ru"] and "Publish" in r["next_step"]["en"]
        if r.get("drafts"):
            d = r["drafts"][0]
            did = d.get("draft_id") or d.get("id")
            p = ds.publish_product_to_store(m, draft_id=did)
            assert p["requires_owner_confirm"] is True and "Опубликовать" in p["ui_hint"]["ru"]
    finally:
        m.close()


def test_тест_качества_показывает_дату(tmp_path):
    import json, threading, urllib.request
    from pathlib import Path
    from padam.api import make_studio_server
    from padam.memory import Memory
    from padam.store import Store
    m = Memory(user_id="u", store=Store(tmp_path / "qa.db"))
    srv, url = make_studio_server(m, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = url.split("/studio")[0]; tok = url.split("#t=")[1]
        req = urllib.request.Request(base + "/api/v2/qa-benchmark", headers={"Authorization": "Bearer " + tok, "X-PADAM-Token": tok})
        d = json.loads(urllib.request.urlopen(req, timeout=10).read())
        if "results_date" in d:
            assert len(d["results_date"]) == 10
            hint = d["rerun_hint"].split()[-1]
            assert (Path(__file__).resolve().parents[1] / hint).exists(), hint
    finally:
        srv.shutdown(); srv.server_close(); m.close()
