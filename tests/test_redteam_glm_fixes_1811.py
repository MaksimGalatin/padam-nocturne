# -*- coding: utf-8 -*-
"""Тесты закрытия уязвимостей красной команды GLM 5.1 (ветка redteam-fixes-1811):

1. SSRF (MCP-04, MCP-06, AUT-05, SAFETY-05) — единый валидатор net_guard и защита от редиректов.
2. SAFETY-01/02 — маскировка секретов в URL после key=/token=/sig= (25 вариантов + публичные URL).
3. MCP-05 / API-01 — права доступа строго для владельца на mcp-daemon-*.json и cabinet_session.json.
4. AUT-07 / API-02 — строгий HMAC по raw_body для всех 5 магазинов и запрет подмены agent_id/share в вебхуке.
"""

from __future__ import annotations

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import threading
import urllib.parse

import pytest

from padam import (
    browser_session,
    cabinet,
    device_mesh_swarm,
    digital_stores,
    freelance_autonomy,
    net_guard,
    partner_bridge,
    safety,
)
from padam.mcp_daemon import write_daemon_state
from padam.memory import Memory
from padam.store import Store


# ---------------------------------------------------------------------------
# 1. SSRF (MCP-04, MCP-06, AUT-05, SAFETY-05)
# ---------------------------------------------------------------------------

_SSRF_ATTACK_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "https://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "https://metadata.aws.internal/2021-03-23/meta-data/",
    "http://10.0.0.1:8080/v1",
    "https://172.16.5.4/api",
    "https://192.168.1.50/api",
    "https://100.64.0.1/internal",
    "http://[::1]:11434/api/tags",
    "https://[::1]/oauth/token",
    "http://[fc00::1]:8080/api",
    "https://[fd00:ec2::254]/latest/meta-data/",
    "http://[fe80::1]/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "https://[::ffff:10.0.0.1]/admin",
    "http://2852039166/latest/meta-data/",          # 169.254.169.254 в десятичном виде
    "http://2130706433:11434/",                     # 127.0.0.1 в десятичном виде
    "http://0xa9fea9fe/latest/meta-data/",          # 169.254.169.254 в hex
    "http://0177.0.0.1:11434/",                     # 127.0.0.1 в octal
    "http://127.1:11434/",                          # сокращённый IPv4
    "http://user:pass@api.example.com/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "http://127.0.0.1.internal/hook",
]


@pytest.mark.parametrize("bad_url", _SSRF_ATTACK_URLS)
def test_ssrf_blocked_across_all_validators(bad_url: str, tmp_path: Path):
    # API бирж и магазинов: запрещены и метаданные, и RFC1918, и localhost, и числовые IP
    with pytest.raises(ValueError):
        net_guard.validate_outbound_url(bad_url, allow_localhost=False)
    with pytest.raises(ValueError):
        freelance_autonomy._validate_api_url(bad_url, allow_localhost=False)
    with pytest.raises(ValueError):
        browser_session._validate_official_api_url(bad_url, allow_localhost=False)
    # Даже при allow_localhost=True (режим Ollama / локальных тестов) эти векторы обязаны падать!
    with pytest.raises(ValueError):
        device_mesh_swarm._clean_ollama_url(bad_url)

    mem = Memory(user_id="ssrf_u", store=Store(str(tmp_path / "ssrf.db")))
    try:
        with pytest.raises(ValueError):
            freelance_autonomy.connect_exchange_account(mem, platform="upwork", api_base_url=bad_url)
        with pytest.raises(ValueError):
            freelance_autonomy.connect_exchange_account(
                mem, platform="upwork", api_base_url="https://api.upwork.com", refresh_url=bad_url
            )
        with pytest.raises(ValueError):
            digital_stores.connect_and_verify_store(
                mem, store_type="gumroad", api_key="k_test", api_base_url=bad_url
            )
    finally:
        mem.close()


def test_ssrf_blocks_localhost_for_api_urls_and_dns_rebinding(monkeypatch):
    # Для api_base_url / refresh_url без allow_localhost и 127.0.0.1/localhost/::1 запрещены
    monkeypatch.delenv("PADAM_FREELANCE_ALLOW_LOCALHOST", raising=False)
    for local in ("https://127.0.0.1/api", "http://127.0.0.1:8080/api", "https://localhost/api", "https://[::1]/api"):
        with pytest.raises(ValueError):
            freelance_autonomy._validate_api_url(local, allow_localhost=False)

    # Легальный Ollama loopback 127.0.0.1 / localhost разрешён, а домен-оборотень 127.0.0.1.evil.test через DNS в 10.0.0.2 падает
    assert device_mesh_swarm._clean_ollama_url("http://127.0.0.1:11434/") == "http://127.0.0.1:11434"
    assert device_mesh_swarm._clean_ollama_url("http://localhost:11434/") == "http://localhost:11434"

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", int(port or 443)))],
    )
    with pytest.raises(ValueError):
        net_guard.validate_outbound_url("https://evil-rebinding.example/v1", allow_localhost=True)
    with pytest.raises(ValueError):
        device_mesh_swarm._clean_ollama_url("https://127.0.0.1.nip.io:11434")

    monkeypatch.setenv("PADAM_AIFA_MCP_URL", "http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ValueError):
        partner_bridge._адрес()


def test_ssrf_blocks_http_redirects_to_internal_and_metadata_targets():
    redirect_hits = {"evil_followed": 0}

    class _TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            redirect_hits["evil_followed"] += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"SECRET_SHOULD_NEVER_BE_READ")

        def log_message(self, *args):
            return

    target_srv = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    target_port = target_srv.server_address[1]
    t_target = threading.Thread(target=target_srv.serve_forever, daemon=True)
    t_target.start()

    redirect_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/admin",
        "http://192.168.1.1/config",
        "http://[::1]:11434/api/tags",
        "http://[fc00::1]/secret",
        "http://2852039166/latest/meta-data/",
        f"http://127.0.0.1:{target_port}/only-when-disallowed",
        "file:///etc/passwd",
    ]
    current_loc = {"url": redirect_targets[0]}

    class _Redirector(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", current_loc["url"])
            self.end_headers()

        def do_POST(self):
            self.do_GET()

        def log_message(self, *args):
            return

    redir_srv = ThreadingHTTPServer(("127.0.0.1", 0), _Redirector)
    redir_port = redir_srv.server_address[1]
    t_redir = threading.Thread(target=redir_srv.serve_forever, daemon=True)
    t_redir.start()

    try:
        base = f"http://127.0.0.1:{redir_port}"
        for loc in redirect_targets[:-2]:
            current_loc["url"] = loc
            with pytest.raises(ValueError):
                net_guard.safe_urlopen(f"{base}/start", allow_localhost=True, timeout=2.0)

        # Проверка через probe_ollama_models: редирект на metadata не даёт online=True и блокируется
        current_loc["url"] = "http://169.254.169.254/latest/meta-data/"
        res = device_mesh_swarm.probe_ollama_models(base, timeout_s=2.0)
        assert res["online"] is False

        # Проверка защиты от редиректа с внешнего allow_localhost=False + downgrade file://
        current_loc["url"] = redirect_targets[-1]
        with pytest.raises(ValueError):
            net_guard.safe_urlopen(f"{base}/start", allow_localhost=True, timeout=2.0)

        # Ни один запрещённый редирект не должен был дойти до внутреннего целевого сервера
        assert redirect_hits["evil_followed"] == 0
    finally:
        redir_srv.shutdown()
        redir_srv.server_close()
        target_srv.shutdown()
        target_srv.server_close()


# ---------------------------------------------------------------------------
# 2. SAFETY-01/02: секреты в URL-параметрах (25 вариантов + публичные URL)
# ---------------------------------------------------------------------------

_SECRET_URL_CASES = [
    ("https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key=AIzaSyB9xK2mN4pQ8rT1uV3wX5yZ", "AIzaSyB9xK2mN4pQ8rT1uV3wX5yZ"),
    ("https://api.example.com/v1/export?key=K9mN4pQ8rT1uV3wX5yZ", "K9mN4pQ8rT1uV3wX5yZ"),
    ("https://api.example.com/v1/items?page=2&token=ghp_a1B2c3D4e5F6g7H8i9J0", "ghp_a1B2c3D4e5F6g7H8i9J0"),
    ("https://api.example.com/v1/items?token=tok_9f8e7d6c5b4a3210fedc", "tok_9f8e7d6c5b4a3210fedc"),
    ("https://app.example.com/callback#token=ya29.a0AfH6SMBx9K2mN4pQ8r", "ya29.a0AfH6SMBx9K2mN4pQ8r"),
    ("https://app.example.com/callback#access_token=at_9f8e7d6c5b4a3210fedc", "at_9f8e7d6c5b4a3210fedc"),
    ("https://api.example.com/hook?sig=8f4e2a1c9b7d6e5f4a3b2c1d0e9f8a7b", "8f4e2a1c9b7d6e5f4a3b2c1d0e9f8a7b"),
    ("https://api.example.com/hook?v=1&sig=deadbeef1234567890abcdef12345678", "deadbeef1234567890abcdef12345678"),
    ("https://api.example.com/hook#sig=3f7a9c2e1b4d8f6a0c5e2b7d9a4f1c8e", "3f7a9c2e1b4d8f6a0c5e2b7d9a4f1c8e"),
    ("https://api.example.com/hook?signature=99887766554433221100aabbccddeeff", "99887766554433221100aabbccddeeff"),
    ("https://storage.googleapis.com/bucket/obj?GoogleAccessId=a@b&X-Goog-Signature=4a5b6c7d8e9f00112233445566778899", "4a5b6c7d8e9f00112233445566778899"),
    ("https://s3.amazonaws.com/bucket/file?X-Amz-Security-Token=IQoJb3JpZ2luX2VjECYaCXVz", "IQoJb3JpZ2luX2VjECYaCXVz"),
    ("https://s3.amazonaws.com/bucket/file?X-Amz-Signature=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"),
    ("https://acct.blob.core.windows.net/c/b?sv=2021-06-08&sig=rK8x%2FpQ9vL2mN4bX7zW1", "rK8x%2FpQ9vL2mN4bX7zW1"),
    ("https://api.example.com/v1?api_key=sk_live_998877665544332211", "sk_live_998877665544332211"),
    ("https://api.example.com/v1?apikey=ak_9f8e7d6c5b4a3210abcd", "ak_9f8e7d6c5b4a3210abcd"),
    ("https://api.example.com/v1?auth=Basic_9f8e7d6c5b4a3210", "Basic_9f8e7d6c5b4a3210"),
    ("https://api.example.com/v1?auth_token=at_9f8e7d6c5b4a3210xyz", "at_9f8e7d6c5b4a3210xyz"),
    ("https://api.example.com/v1?refresh_token=rt_9f8e7d6c5b4a3210xyz", "rt_9f8e7d6c5b4a3210xyz"),
    ("https://api.example.com/v1?secret=sec_9f8e7d6c5b4a3210xyz", "sec_9f8e7d6c5b4a3210xyz"),
    ("https://api.example.com/v1?client_secret=cs_9f8e7d6c5b4a3210xyz", "cs_9f8e7d6c5b4a3210xyz"),
    ("https://api.example.com/v1?webhook_secret=whs_9f8e7d6c5b4a3210xyz", "whs_9f8e7d6c5b4a3210xyz"),
    ("https://api.example.com/v1?password=MyS3cretP@ss99", "MyS3cretP@ss99"),
    ("https://api.example.com/v1?session_id=sess_9f8e7d6c5b4a3210xyz", "sess_9f8e7d6c5b4a3210xyz"),
    ("api.example.com/v1?key=noSchemeKey9f8e7d6c", "noSchemeKey9f8e7d6c"),
    ("https://very-long-cdn-domain.example.com/assets/2026/11/18/subdir/download/archive.zip?sig=7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f", "7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f"),
]


@pytest.mark.parametrize("url,secret", _SECRET_URL_CASES)
def test_safety_redacts_url_parameter_secrets(url: str, secret: str):
    redacted, counts = safety.redact(url)
    assert secret not in redacted, f"Секрет утек в URL: {redacted}"
    assert "[REDACTED:" in redacted
    assert sum(counts.values()) >= 1


def test_safety_preserves_public_urls_and_ids():
    public_urls = [
        "https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://github.com/padam-ai/code/commit/1234567890abcdef1234567890abcdef12345678",
        "https://example.com/docs?key=getting_started",
        "https://example.com/login?auth=google_oauth",
        "https://example.com/item?id=item_public_99112233",
    ]
    for u in public_urls:
        redacted, counts = safety.redact(u)
        assert redacted == u, f"Публичная ссылка была ложно замаскирована: {u} -> {redacted}"
        assert sum(counts.values()) == 0


# ---------------------------------------------------------------------------
# 3. MCP-05 / API-01: права доступа к файлам токенов (только владелец)
# ---------------------------------------------------------------------------

def test_token_files_owner_only_permissions(tmp_path: Path, monkeypatch):
    # 3a. mcp-daemon-*.json
    state_path = tmp_path / "mcp-daemon-abc123.json"
    write_daemon_state(state_path, {"pid": 1234, "port": 9411, "token": "daemon_tok_secret_123"})
    assert state_path.exists()
    if not net_guard.verify_owner_only_permissions(state_path):
        import os as _os
        diag = ""
        if _os.name == "nt":
            import subprocess as _sp
            diag = (f"owner={net_guard._windows_current_user_sid()} dacl={net_guard._windows_file_dacl_sids(state_path)} "
                    f"icacls={_sp.run(['icacls', str(state_path)], capture_output=True, text=True).stdout!r}")
        raise AssertionError(f"файл с токеном доступен не только владельцу: {diag}")

    # 3b. cabinet_session.json (без внешнего keystore — проверка файлового fallback)
    sess_file = tmp_path / "cabinet" / "session.json"
    monkeypatch.setattr(cabinet, "_keystore_backend", None)
    monkeypatch.setattr(cabinet, "_session_path", lambda: sess_file)
    cabinet.save_session("owner@code.test", "cab_secret_cookie_tok_987", "https://aifa.works")
    assert sess_file.exists()
    assert net_guard.verify_owner_only_permissions(sess_file) is True


# ---------------------------------------------------------------------------
# 4. AUT-07 / API-02: вебхуки (подпись raw_body и иммунитет agent_id/share)
# ---------------------------------------------------------------------------

def test_freelance_webhook_ignores_body_agent_id_and_share(tmp_path: Path):
    mem = Memory(user_id="wh_sec_u", store=Store(str(tmp_path / "whsec.db")))
    try:
        freelance_autonomy.set_freelance_prefs(mem, agent_share_pct=15.0, settlement_currency="USDT_TRC20")
        acc = freelance_autonomy.connect_exchange_account(
            mem,
            platform="upwork",
            api_base_url="https://api.upwork.com",
            webhook_secret="fl_wh_sec_123",
            agent_id="aifa",
        )
        ord_res = freelance_autonomy.evaluate_and_ingest_job(
            mem,
            platform="upwork",
            title="Python Backend Audit",
            brief="Check API security",
            budget_usdt=200.0,
            work_mode="assisted",
            account_id=acc["account_id"],
        )
        oid = ord_res["order_id"]

        # Атакующий (или взломанный вебхук) пытается подменить agent_id, agent_share_pct и валюту прямо в теле order.paid
        evil_payload = json.dumps({
            "event": "order.paid",
            "order_id": oid,
            "paid_usdt": 200.0,
            "agent_id": "attacker_steal_agent",
            "agent_share_pct": 100.0,
            "settlement_currency": "BTC",
        }).encode("utf-8")
        sig = hmac.new(b"fl_wh_sec_123", evil_payload, hashlib.sha256).hexdigest()

        res = freelance_autonomy.verify_and_process_webhook(mem, evil_payload, sig, account_id=acc["account_id"])
        assert res["ok"] is True
        assert res["agent_payout"]["agent_id"] == "aifa"
        assert res["monetization"]["agent_share_pct"] == 15.0
        assert res["monetization"]["settlement_currency"] == "USDT_TRC20"
        assert freelance_autonomy.get_agent_ledger(mem, agent_id="attacker_steal_agent")["entries"] == []
    finally:
        mem.close()


def test_store_webhooks_reject_tampered_raw_body_and_missing_hmac_all_five(tmp_path: Path, monkeypatch):
    import base64
    import time

    monkeypatch.setattr(
        digital_stores,
        "_verify_store_credentials",
        lambda st, base, raw_key, seller_id="", allow_localhost=False: {"owner_name": st, "external_store_id": f"{st}_ext_1"},
    )
    mem = Memory(user_id="st_sec_u", store=Store(str(tmp_path / "stsec.db")))
    try:
        stores = [
            ("lemonsqueezy", "ls_key", "ls_wh", "X-Signature"),
            ("gumroad", "gr_key", "gr_wh", "X-Padam-Signature"),
            ("payhip", "ph_key", "ph_wh", "X-Signature"),
            ("sellfy", "sf_key", "sf_wh", "X-Sellfy-Signature"),
        ]
        for st_type, api_k, wh_s, _ in stores:
            digital_stores.connect_and_verify_store(
                mem, store_type=st_type, api_key=api_k, webhook_secret=wh_s
            )
        digital_stores.connect_and_verify_store(
            mem, store_type="whop", api_key="wh_key", webhook_secret="ws_whop_secret_00"
        )

        # Gumroad с верным external_store_id, но БЕЗ HMAC подписи — отказ
        gr_body = urllib.parse.urlencode({"sale_id": "g1", "price": "1500"}).encode("utf-8")
        with pytest.raises(PermissionError):
            digital_stores.verify_and_process_store_webhook(mem, "gumroad", gr_body, {"Content-Type": "application/x-www-form-urlencoded"})

        # Payhip со статическим sha256(api_key), но БЕЗ HMAC по raw_body — отказ
        ph_static = hashlib.sha256(b"ph_key").hexdigest()
        ph_body = json.dumps({"id": "p1", "type": "paid", "price": 1500, "signature": ph_static}).encode("utf-8")
        with pytest.raises(PermissionError):
            digital_stores.verify_and_process_store_webhook(mem, "payhip", ph_body, {"Content-Type": "application/json"})

        # Изменение 1 байта в raw_body ломает подпись для каждого магазина
        ls_body = json.dumps({"data": {"id": "l1", "attributes": {"total": 1000, "status": "paid"}}}).encode("utf-8")
        ls_sig = hmac.new(b"ls_wh", ls_body, hashlib.sha256).hexdigest()
        ls_tampered = json.dumps({"data": {"id": "l1", "attributes": {"total": 9900, "status": "paid"}}}).encode("utf-8")
        with pytest.raises(PermissionError):
            digital_stores.verify_and_process_store_webhook(mem, "lemonsqueezy", ls_tampered, {"X-Signature": ls_sig})

        sf_body = json.dumps({"id": "s1", "event": "New order", "amount": 1000}).encode("utf-8")
        sf_sig = hmac.new(b"sf_wh", sf_body, hashlib.sha256).hexdigest()
        sf_tampered = sf_body.replace(b"1000", b"9000")
        with pytest.raises(PermissionError):
            digital_stores.verify_and_process_store_webhook(mem, "sellfy", sf_tampered, {"X-Sellfy-Signature": sf_sig})

        gr_sig = hmac.new(b"gr_wh", gr_body, hashlib.sha256).hexdigest()
        gr_tampered = gr_body + b"&price=9900"
        with pytest.raises(PermissionError):
            digital_stores.verify_and_process_store_webhook(mem, "gumroad", gr_tampered, {"X-Padam-Signature": gr_sig})

        ph_sig = hmac.new(b"ph_wh", ph_body, hashlib.sha256).hexdigest()
        ph_tampered = ph_body.replace(b"1500", b"9900")
        with pytest.raises(PermissionError):
            digital_stores.verify_and_process_store_webhook(mem, "payhip", ph_tampered, {"X-Signature": ph_sig})

        # Whop: изменение 1 байта raw_body ломает v1 подпись
        wh_ts = str(int(time.time()))
        wh_body = json.dumps({"type": "payment.succeeded", "data": {"id": "p_w1", "final_amount": 10.0}}).encode("utf-8")
        wh_sig = "v1," + base64.b64encode(hmac.new(b"ws_whop_secret_00", f"msg_w1.{wh_ts}.{wh_body.decode('utf-8')}".encode("utf-8"), hashlib.sha256).digest()).decode("ascii")
        wh_tampered = wh_body.replace(b"10.0", b"99.0")
        with pytest.raises(PermissionError):
            digital_stores.verify_and_process_store_webhook(
                mem,
                "whop",
                wh_tampered,
                {"webhook-id": "msg_w1", "webhook-timestamp": wh_ts, "webhook-signature": wh_sig},
                now_ts=float(wh_ts),
            )
    finally:
        mem.close()


def test_явные_чужие_права_снимаются_как_на_runner(tmp_path):
    """CI 18.11.2026: на GitHub runner файл Temp создаётся с ЯВНЫМИ записями SYSTEM, Administrators, OWNER RIGHTS;
    /inheritance:r их не снимал, токен читали не только владельцем. Воспроизводим и требуем, чтобы остался один владелец."""
    import os, subprocess
    import pytest
    if os.name != "nt":
        pytest.skip("проверка ACL Windows")
    from padam import net_guard as g
    f = tmp_path / "tok.json"
    f.write_text("{}", encoding="utf-8")
    subprocess.run(["icacls", str(f), "/grant", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)", "*S-1-3-4:(F)"],
                   capture_output=True, check=False)
    assert len(set(g._windows_file_dacl_sids(f))) > 1
    assert g.restrict_file_to_owner(f) is True
    assert g.verify_owner_only_permissions(f), g._windows_file_dacl_sids(f)
