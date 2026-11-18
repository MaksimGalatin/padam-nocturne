from __future__ import annotations

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from padam import digital_stores, freelance_autonomy, mcp_server
from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store


class _MockStoresState:
    def __init__(self) -> None:
        self.created_products: list[tuple[str, dict]] = []
        self.updated_products: list[tuple[str, dict]] = []
        self.ls_orders: list[dict] = [
            {
                "id": "ls-ord-101",
                "attributes": {
                    "total": 4900,
                    "currency": "USD",
                    "user_email": "buyer.ls@example.com",
                    "status": "paid",
                    "first_order_item": {"product_id": "ls-p-1", "product_name": "A11y Leads Pack"},
                },
            }
        ]
        self.gumroad_sales: list[dict] = [
            {
                "id": "gr-sale-201",
                "product_id": "gr-p-1",
                "product_name": "30 Platforms Guide",
                "price": 2900,
                "currency": "usd",
                "email": "buyer.gr@example.com",
                "refunded": False,
            }
        ]
        self.sellfy_orders: list[dict] = [
            {
                "id": "sf-ord-301",
                "status": "COMPLETED",
                "amount": 1900,
                "currency": "USD",
                "customer": {"email": "buyer.sf@example.com"},
                "items": [{"title": "PADAM Templates"}],
            }
        ]
        self.whop_payments: list[dict] = [
            {
                "id": "pay_whop_401",
                "status": "paid",
                "final_amount": 35.0,
                "user": {"email": "buyer.wh@example.com"},
                "product": {"title": "Whop Starter Kit"},
            }
        ]


def _start_mock_stores_server():
    state = _MockStoresState()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

        def _send(self, code: int, payload: dict) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_body(self) -> bytes:
            ln = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(ln) if ln > 0 else b""

        def do_GET(self) -> None:  # noqa: N802
            auth = self.headers.get("Authorization") or ""
            path = urllib.parse.urlparse(self.path).path

            # Lemon Squeezy
            if path == "/ls/users/me":
                if auth != "Bearer ls_secret_key":
                    return self._send(401, {"error": "bad ls key"})
                return self._send(200, {"data": {"id": "usr_1", "attributes": {"name": "Maksim LS", "email": "ls@example.com"}}})
            if path == "/ls/stores":
                return self._send(200, {"data": [{"id": "store_ls_1", "attributes": {"name": "CODE LS Store", "currency": "USD"}}]})
            if path == "/ls/products":
                return self._send(200, {"data": [{"id": "ls-p-1", "attributes": {"name": "Базы лидов из исследования цифровой доступности"}}]})
            if path == "/ls/orders":
                return self._send(200, {"data": state.ls_orders})

            # Gumroad
            if path == "/gr/user":
                if auth != "Bearer gr_secret_key":
                    return self._send(401, {"success": False, "message": "invalid token"})
                return self._send(200, {"success": True, "user": {"id": "seller_gr_99", "name": "Maksim GR", "email": "gr@example.com", "currency_type": "usd"}})
            if path == "/gr/sales":
                return self._send(200, {"success": True, "sales": state.gumroad_sales})

            # Payhip
            if path == "/ph/coupons":
                if auth != "Bearer ph_secret_key" and self.headers.get("payhip-api-key") != "ph_secret_key":
                    return self._send(401, {"error": "bad payhip key"})
                return self._send(200, {"store_id": "ph_store_1", "owner_name": "Maksim PH", "currency": "USD", "coupons": []})

            # Sellfy
            if path == "/sf/v1/products":
                if auth != "Bearer sf_secret_key":
                    return self._send(401, {"error": "bad sellfy key"})
                return self._send(200, {"store": {"id": "sf_1", "name": "CODE Sellfy", "currency": "USD"}, "products": []})
            if path == "/sf/v1/orders":
                return self._send(200, {"orders": state.sellfy_orders})

            # Whop
            if path == "/wh/accounts/me":
                if auth != "Bearer wh_secret_key" or self.headers.get("Api-Version-Date") != digital_stores.WHOP_API_VERSION:
                    return self._send(401, {"error": "bad whop auth or version header"})
                return self._send(200, {"data": {"id": "biz_whop_1", "title": "CODE Whop", "email": "wh@example.com", "currency": "USD"}})
            if path == "/wh/payments":
                return self._send(200, {"data": state.whop_payments})

            return self._send(404, {"error": f"unknown GET {path}"})

        def do_POST(self) -> None:  # noqa: N802
            path = urllib.parse.urlparse(self.path).path
            raw = self._read_body().decode("utf-8", errors="replace")

            if path == "/gr/products":
                qs = urllib.parse.parse_qs(raw)
                parsed = {k: v[0] for k, v in qs.items()}
                state.created_products.append(("gumroad", parsed))
                return self._send(200, {"success": True, "product": {"id": "gr-prod-new", "short_url": "https://gum.co/guide"}})
            if path == "/sf/v1/products":
                parsed = json.loads(raw)
                state.created_products.append(("sellfy", parsed))
                return self._send(201, {"product": {"id": "sf-prod-new", "url": "https://sellfy.com/p/new"}})
            if path == "/wh/products":
                parsed = json.loads(raw)
                state.created_products.append(("whop", parsed))
                return self._send(201, {"data": {"id": "prod_whop_new", "route": "https://whop.com/code/tpl"}})

            return self._send(404, {"error": f"unknown POST {path}"})

        def do_PUT(self) -> None:  # noqa: N802
            path = urllib.parse.urlparse(self.path).path
            raw = self._read_body().decode("utf-8", errors="replace")
            if path.startswith("/gr/products/"):
                parsed = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                state.updated_products.append(("gumroad", parsed))
                return self._send(200, {"success": True, "product": {"id": path.rsplit("/", 1)[-1], "short_url": "https://gum.co/guide-v2"}})
            return self._send(404, {"error": f"unknown PUT {path}"})

        def do_PATCH(self) -> None:  # noqa: N802
            path = urllib.parse.urlparse(self.path).path
            parsed = json.loads(self._read_body().decode("utf-8", errors="replace"))
            if path.startswith("/sf/v1/products/"):
                state.updated_products.append(("sellfy", parsed))
                return self._send(200, {"product": {"id": path.rsplit("/", 1)[-1]}})
            if path.startswith("/wh/products/"):
                state.updated_products.append(("whop", parsed))
                return self._send(200, {"data": {"id": path.rsplit("/", 1)[-1]}})
            return self._send(404, {"error": f"unknown PATCH {path}"})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}", state


def _http_post_raw(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return int(r.status), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return int(e.code), json.loads(e.read().decode("utf-8"))


def test_five_stores_verify_encrypt_drafts_publish_and_autopilot_sales(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_FREELANCE_ALLOW_LOCALHOST", "1")
    srv, base, state = _start_mock_stores_server()
    mem = Memory(user_id="stores_owner", store=Store(str(tmp_path / "stores.db")))
    try:
        # 1. Подключаем и проверяем ключи всех 5 магазинов
        ls = digital_stores.connect_and_verify_store(
            mem, store_type="lemonsqueezy", api_key="ls_secret_key", api_base_url=f"{base}/ls", webhook_secret="ls_wh_sec"
        )
        gr = digital_stores.connect_and_verify_store(
            mem, store_type="gumroad", api_key="gr_secret_key", api_base_url=f"{base}/gr", webhook_secret="gr_wh_sec"
        )
        ph = digital_stores.connect_and_verify_store(
            mem, store_type="payhip", api_key="ph_secret_key", api_base_url=f"{base}/ph"
        )
        sf = digital_stores.connect_and_verify_store(
            mem, store_type="sellfy", api_key="sf_secret_key", api_base_url=f"{base}/sf", webhook_secret="sf_wh_sec"
        )
        wh = digital_stores.connect_and_verify_store(
            mem, store_type="whop", api_key="wh_secret_key", api_base_url=f"{base}/wh", webhook_secret="ws_whop_raw_secret_key_123"
        )
        assert ls["verified"] and ls["store"]["owner_name"] == "Maksim LS"
        assert gr["verified"] and gr["store"]["external_store_id"] == "seller_gr_99"
        assert ph["verified"] and ph["store"]["capabilities"]["supports_sales_pull"] is False
        assert sf["verified"] and sf["store"]["capabilities"]["supports_product_write"] is True
        assert wh["verified"] and wh["store"]["external_store_id"] == "biz_whop_1"

        # Проверка: открытые ключи и секреты НИГДЕ не лежат в SQLite
        rows = mem.store.conn.execute("SELECT api_key_enc, webhook_secret_enc FROM ark_digital_store_account").fetchall()
        assert len(rows) == 5
        for r in rows:
            assert str(r["api_key_enc"]).startswith("aesgcm1:")
            for sec_plain in ("ls_secret_key", "gr_secret_key", "ph_secret_key", "sf_secret_key", "wh_secret_key", "ls_wh_sec", "ws_whop_raw_secret_key_123"):
                assert sec_plain not in str(r["api_key_enc"])
                assert sec_plain not in str(r["webhook_secret_enc"])

        # 2. Стартовые 3 черновика (строго черновики, идемпотентно)
        s1 = digital_stores.seed_starter_product_drafts(mem)
        assert s1["created_count"] == 3
        titles = {d["title"] for d in s1["drafts"]}
        assert any("Методичка по 30 площадкам" in t for t in titles)
        assert any("Базы лидов" in t for t in titles)
        assert any("шаблоны" in t.lower() for t in titles)
        assert digital_stores.seed_starter_product_drafts(mem)["created_count"] == 0

        # 3. Блокировка отправки наружу без owner_approved=True
        res_block = digital_stores.publish_product_to_store(mem, "draft-starter-30-platforms", owner_approved=False)
        assert res_block["published_via_api"] is False
        assert res_block["status"] == "awaiting_owner_approval"
        assert state.created_products == []

        # 4. Публикация с owner_approved=True (Gumroad + Whop + новый Sellfy пишутся в API; Lemon Squeezy + Payhip честно read-only)
        res_gr = digital_stores.publish_product_to_store(mem, "draft-starter-30-platforms", owner_approved=True, allow_localhost=True)
        assert res_gr["published_via_api"] is True and res_gr["external_product_id"] == "gr-prod-new"
        # Повторный вызов обновляет PUT /products/{id}
        res_gr_upd = digital_stores.publish_product_to_store(mem, "draft-starter-30-platforms", owner_approved=True, allow_localhost=True)
        assert res_gr_upd["published_via_api"] is True and state.updated_products[0][0] == "gumroad"

        res_wh = digital_stores.publish_product_to_store(mem, "draft-starter-padam-templates", owner_approved=True, allow_localhost=True)
        assert res_wh["published_via_api"] is True and res_wh["external_product_id"] == "prod_whop_new"

        sf_draft = digital_stores.upsert_product_draft(mem, store_type="sellfy", title="Sellfy Custom Pack", description="Pack", price_usdt=15.0)
        res_sf = digital_stores.publish_product_to_store(mem, sf_draft["draft"]["draft_id"], owner_approved=True, allow_localhost=True)
        assert res_sf["published_via_api"] is True and res_sf["external_product_id"] == "sf-prod-new"

        res_ls = digital_stores.publish_product_to_store(mem, "draft-starter-a11y-leads", owner_approved=True, allow_localhost=True)
        assert res_ls["published_via_api"] is False and res_ls["dashboard_manual_required"] is True
        assert res_ls["draft"]["external_product_id"] == "ls-p-1"

        ph_draft = digital_stores.upsert_product_draft(mem, store_type="payhip", title="Payhip Pack", description="Desc", price_usdt=12.0)
        res_ph = digital_stores.publish_product_to_store(mem, ph_draft["draft"]["draft_id"], owner_approved=True, allow_localhost=True)
        assert res_ph["published_via_api"] is False and res_ph["dashboard_manual_required"] is True

        # 5. Синхронизация продаж: все продажи идут как work_mode='autopilot' (комиссия CODE 20%)
        for st_res in (ls, gr, sf, wh):
            syn = digital_stores.sync_store_sales(mem, st_res["store"]["store_account_id"], allow_localhost=True)
            assert syn["pull_supported"] is True and syn["imported_count"] == 1
            assert syn["results"][0]["work_mode"] == "autopilot"
            assert syn["results"][0]["code_fee_pct"] == 20.0
            # Повторный вызов идемпотентен
            syn2 = digital_stores.sync_store_sales(mem, st_res["store"]["store_account_id"], allow_localhost=True)
            assert syn2["imported_count"] == 0

        syn_ph = digital_stores.sync_store_sales(mem, ph["store"]["store_account_id"], allow_localhost=True)
        assert syn_ph["pull_supported"] is False and syn_ph["imported_count"] == 0

        # Проверяем в БД: 4 заказа с platform_fee_pct=20.0 (autopilot), accepted_at IS NOT NULL, и 4 закреплённых клиента на 90 дней
        orders = freelance_autonomy.list_orders(mem)
        assert len(orders) == 4
        for o in orders:
            assert float(o["platform_fee_pct"]) == 20.0
            assert o["accepted_at"] is not None
        locks = freelance_autonomy.get_client_lock_status(mem)["locks"]
        assert len(locks) == 4
        ledger = freelance_autonomy.get_agent_ledger(mem, agent_id="aifa")
        assert len(ledger["entries"]) == 4

        # Проверяем долю агента по Whop ($35 -> после 20% CODE = $28 -> 15% агенту = $4.20)
        wh_ord = next(o for o in orders if o["platform"] == "whop")
        wh_entry = next(e for e in ledger["entries"] if e["order_id"] == wh_ord["order_id"])
        assert abs(float(wh_entry["agent_amount_usdt"]) - 4.2) < 1e-4

        # 6. Проверяем откат по возврату (Gumroad sale refunded=True)
        state.gumroad_sales[0]["refunded"] = True
        syn_ref = digital_stores.sync_store_sales(mem, gr["store"]["store_account_id"], allow_localhost=True)
        assert syn_ref["refunded_count"] == 1
        gr_ord = next(o for o in freelance_autonomy.list_orders(mem) if o["platform"] == "gumroad")
        assert gr_ord["status"] == "refunded"
    finally:
        srv.shutdown()
        srv.server_close()
        mem.close()


def test_store_webhooks_cryptographic_verification_all_five(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_FREELANCE_ALLOW_LOCALHOST", "1")
    srv_mock, base, _ = _start_mock_stores_server()
    mem = Memory(user_id="wh_owner", store=Store(str(tmp_path / "wh.db")))
    srv_api = None
    try:
        ls = digital_stores.connect_and_verify_store(mem, store_type="lemonsqueezy", api_key="ls_secret_key", api_base_url=f"{base}/ls", webhook_secret="ls_hmac_secret")["store"]
        gr = digital_stores.connect_and_verify_store(mem, store_type="gumroad", api_key="gr_secret_key", api_base_url=f"{base}/gr", webhook_secret="gr_hmac_secret")["store"]
        ph = digital_stores.connect_and_verify_store(mem, store_type="payhip", api_key="ph_secret_key", api_base_url=f"{base}/ph")["store"]
        sf = digital_stores.connect_and_verify_store(mem, store_type="sellfy", api_key="sf_secret_key", api_base_url=f"{base}/sf", webhook_secret="sf_hmac_secret")["store"]
        wh_secret = "ws_test_whop_secret_utf8"
        wh = digital_stores.connect_and_verify_store(mem, store_type="whop", api_key="wh_secret_key", api_base_url=f"{base}/wh", webhook_secret=wh_secret)["store"]

        srv_api, url = make_studio_server(mem, port=0)
        p_u = urllib.parse.urlparse(url)
        api_url = f"{p_u.scheme}://{p_u.netloc}"
        t_api = threading.Thread(target=srv_api.serve_forever, daemon=True)
        t_api.start()

        # 1) Lemon Squeezy HMAC-SHA256 (X-Signature)
        ls_body = json.dumps({"data": {"id": "wh-ls-1", "attributes": {"total": 2500, "user_email": "alice@ls.io", "status": "paid", "first_order_item": {"product_name": "Guide"}}}}).encode("utf-8")
        ls_sig = hmac.new(b"ls_hmac_secret", ls_body, hashlib.sha256).hexdigest()
        c_bad, _ = _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=lemonsqueezy", ls_body, {"Content-Type": "application/json", "X-Signature": "deadbeef", "X-Event-Name": "order_created"})
        assert c_bad == 403
        c_ok, r_ok = _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=lemonsqueezy", ls_body, {"Content-Type": "application/json", "X-Signature": ls_sig, "X-Event-Name": "order_created"})
        assert c_ok == 200 and r_ok["code_fee_pct"] == 20.0

        # 2) Gumroad Ping (form-urlencoded + seller_id / HMAC)
        gr_body = urllib.parse.urlencode({"seller_id": gr["external_store_id"], "sale_id": "wh-gr-1", "product_name": "Templates", "price": "1900", "email": "bob@gr.io"}).encode("utf-8")
        gr_bad = urllib.parse.urlencode({"seller_id": "wrong_seller", "sale_id": "wh-gr-x", "price": "1900"}).encode("utf-8")
        c_bad, _ = _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=gumroad", gr_bad, {"Content-Type": "application/x-www-form-urlencoded"})
        assert c_bad == 403
        c_ok, r_ok = _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=gumroad", gr_body, {"Content-Type": "application/x-www-form-urlencoded"})
        assert c_ok == 200 and r_ok["work_mode"] == "autopilot"

        # 3) Payhip (signature == sha256(api_key)) + refund
        ph_sig = hashlib.sha256(b"ph_secret_key").hexdigest()
        ph_bad = json.dumps({"id": "ph-1", "type": "paid", "price": 1000, "email": "x@y.z", "signature": "0000"}).encode("utf-8")
        ph_ok = json.dumps({"id": "ph-1", "type": "paid", "price": 1000, "email": "carol@ph.io", "items": [{"product_name": "Payhip Guide"}], "signature": ph_sig}).encode("utf-8")
        assert _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=payhip", ph_bad, {"Content-Type": "application/json"})[0] == 403
        c_ok, r_ok = _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=payhip", ph_ok, {"Content-Type": "application/json"})
        assert c_ok == 200 and r_ok["code_fee_pct"] == 20.0
        ph_ref = json.dumps({"id": "ph-1", "type": "refunded", "price": 1000, "email": "carol@ph.io", "signature": ph_sig}).encode("utf-8")
        c_ref, r_ref = _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=payhip", ph_ref, {"Content-Type": "application/json"})
        assert c_ref == 200 and r_ref["action"] == "refund_processed"

        # 4) Sellfy HMAC-SHA256
        sf_body = json.dumps({"id": "sf-wh-1", "event": "New order", "status": "COMPLETED", "amount": 2200, "customer": {"email": "dave@sf.io"}, "items": [{"title": "Sellfy Kit"}]}).encode("utf-8")
        sf_sig = hmac.new(b"sf_hmac_secret", sf_body, hashlib.sha256).hexdigest()
        assert _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=sellfy", sf_body, {"Content-Type": "application/json", "X-Sellfy-Signature": "wrong"})[0] == 403
        assert _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=sellfy", sf_body, {"Content-Type": "application/json", "X-Sellfy-Signature": sf_sig})[0] == 200

        # 5) Whop Standard Webhooks (v1,<base64>, raw ws_ UTF-8 key, replay window)
        wh_id = "msg_whop_9001"
        wh_ts = str(int(time.time()))
        wh_body = json.dumps({"type": "payment.succeeded", "data": {"id": "pay_wh_99", "final_amount": 40.0, "user": {"email": "eve@wh.io"}, "product": {"title": "Whop Pack"}}}).encode("utf-8")
        signed = f"{wh_id}.{wh_ts}.{wh_body.decode('utf-8')}".encode("utf-8")
        wh_sig = "v1," + base64.b64encode(hmac.new(wh_secret.encode("utf-8"), signed, hashlib.sha256).digest()).decode("ascii")
        assert _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=whop", wh_body, {"Content-Type": "application/json", "webhook-id": wh_id, "webhook-timestamp": wh_ts, "webhook-signature": "v1,bad=="})[0] == 403
        # Просроченный timestamp (> 300с) отклоняется
        old_ts = str(int(time.time()) - 900)
        old_signed = f"{wh_id}.{old_ts}.{wh_body.decode('utf-8')}".encode("utf-8")
        old_sig = "v1," + base64.b64encode(hmac.new(wh_secret.encode("utf-8"), old_signed, hashlib.sha256).digest()).decode("ascii")
        assert _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=whop", wh_body, {"Content-Type": "application/json", "webhook-id": wh_id, "webhook-timestamp": old_ts, "webhook-signature": old_sig})[0] == 403

        c_ok, r_ok = _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=whop", wh_body, {"Content-Type": "application/json", "webhook-id": wh_id, "webhook-timestamp": wh_ts, "webhook-signature": wh_sig})
        assert c_ok == 200 and r_ok["duplicate"] is False and r_ok["code_fee_pct"] == 20.0
        # Повторная доставка идемпотентна
        c_dup, r_dup = _http_post_raw(f"{api_url}/api/v2/ark/stores/webhook?store_type=whop", wh_body, {"Content-Type": "application/json", "webhook-id": wh_id, "webhook-timestamp": wh_ts, "webhook-signature": wh_sig})
        assert c_dup == 200 and r_dup["duplicate"] is True
    finally:
        if srv_api:
            srv_api.shutdown()
            srv_api.server_close()
            t_api.join(timeout=2)
        srv_mock.shutdown()
        srv_mock.server_close()
        mem.close()


def test_mcp_stores_batch_validation_and_publish_lock(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    mem = Memory(user_id="mcp_stores_u", store=Store(str(tmp_path / "mcps.db")))
    prev = mcp_server._memory
    mcp_server._memory = mem
    try:
        def hcall(name: str, args: dict) -> dict:
            return mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})["result"]

        # Пустые вызовы отклоняются с isError=True
        for act in ("connect_store", "create_product_draft", "publish_product", "sync_store_sales"):
            assert hcall("padam_freelance_hub", {"action": act})["isError"] is True

        # padam_batch разрешает stores_status и блокирует мутирующие publish_product
        b_ok = hcall("padam_batch", {"calls": [{"name": "padam_freelance_hub", "arguments": {"action": "stores_status"}}]})
        assert b_ok.get("isError") is False
        assert "Методичка по 30 площадкам" in b_ok["content"][0]["text"]

        b_bad = hcall("padam_batch", {"calls": [{"name": "padam_freelance_hub", "arguments": {"action": "publish_product", "draft_id": "draft-starter-30-platforms"}}]})
        assert b_bad["isError"] is True

        # Прямой вызов publish_product через MCP НИКОГДА не обходит owner_approved=False
        pub_res = hcall("padam_freelance_hub", {"action": "publish_product", "draft_id": "draft-starter-30-platforms"})
        assert pub_res.get("isError") is False
        pub_json = json.loads(pub_res["content"][0]["text"])
        assert pub_json["published_via_api"] is False
        assert pub_json["status"] == "awaiting_owner_approval"
    finally:
        mcp_server._memory = prev
        mem.close()


def test_studio_digital_stores_ui_playwright(tmp_path: Path, monkeypatch):
    pw = pytest.importorskip("playwright.sync_api")
    monkeypatch.setenv("PADAM_FREELANCE_ALLOW_LOCALHOST", "1")
    srv_mock, base, _ = _start_mock_stores_server()
    mem = Memory(user_id="ui_stores_u", store=Store(str(tmp_path / "ui_stores.db")))
    srv_api = None
    t_api = None
    try:
        srv_api, url = make_studio_server(mem, port=0)
        t_api = threading.Thread(target=srv_api.serve_forever, daemon=True)
        t_api.start()
        with pw.sync_playwright() as p:
            browser = p.chromium.launch()
            for vp in ({"width": 1280, "height": 800}, {"width": 390, "height": 844}):
                page = browser.new_page(viewport=vp)
                js_errors: list[str] = []
                page.on("pageerror", lambda err: js_errors.append(str(err)))
                page.goto(url, wait_until="networkidle")
                page.click("#tab-earning")
                page.wait_for_selector("#earn-store-type", timeout=5000)
                page.wait_for_function(
                    "() => document.querySelectorAll('#earn-drafts-list .earn-item').length >= 3",
                    timeout=5000,
                )
                page.wait_for_load_state("networkidle")
                check = page.evaluate(
                    """() => {
                        const opts = Array.from(document.querySelectorAll('#earn-store-type option')).map(o => o.value);
                        const draftsTxt = document.querySelector('#earn-drafts-list').textContent;
                        return {
                            opts,
                            draftsCount: document.querySelectorAll('#earn-drafts-list .earn-item').length,
                            hasGuide: draftsTxt.includes('Методичка по 30 площадкам') || draftsTxt.includes('30'),
                            overflow: document.documentElement.scrollWidth > window.innerWidth,
                        };
                    }"""
                )
                assert check["opts"] == ["lemonsqueezy", "gumroad", "payhip", "sellfy", "whop"]
                assert check["draftsCount"] >= 3 and check["hasGuide"] is True
                assert check["overflow"] is False
                assert js_errors == []

                # Только на десктопном проходе подключаем магазин Gumroad и нажимаем Одобрить и отправить
                if vp["width"] == 1280:
                    page.select_option("#earn-store-type", "gumroad")
                    page.fill("#earn-store-label", "Мой Gumroad UI")
                    page.fill("#earn-store-api-url", f"{base}/gr")
                    page.fill("#earn-store-key", "gr_secret_key")
                    with page.expect_response("**/api/v2/ark/stores/action", timeout=5000) as r_conn:
                        page.click("#earn-store-connect-btn")
                    assert r_conn.value.status == 200
                    page.wait_for_function(
                        "() => document.querySelector('#earn-stores-list').textContent.includes('Мой Gumroad UI')",
                        timeout=5000,
                    )
                    # Нажимаем публикацию стартового черновика для Gumroad
                    with page.expect_response("**/api/v2/ark/stores/action", timeout=5000) as r_pub:
                        page.locator("#earn-drafts-list .earn-item", has_text="gumroad").locator("button").click()
                    assert r_pub.value.status == 200
                    page.wait_for_function(
                        "() => document.querySelector('#earn-drafts-list').textContent.includes('published')",
                        timeout=5000,
                    )
                page.wait_for_load_state("networkidle")
                page.close()
            browser.close()
    finally:
        if srv_api:
            srv_api.shutdown()
            srv_api.server_close()
        if t_api:
            t_api.join(timeout=2)
        time.sleep(0.15)
        srv_mock.shutdown()
        srv_mock.server_close()
        mem.close()
