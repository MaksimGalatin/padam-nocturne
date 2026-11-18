# Блок «9. AIfaFocus» в Studio (18.11.2026): те же действия, что у padam_partner_*, ключ хранится зашифрованным,
# письма не отправляются, облако подменено локальным сервером (сети наружу нет).
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from padam import partner_bridge
from padam.memory import Memory
from padam.store import Store


class _Облако(BaseHTTPRequestHandler):
    вызовы: list = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        _Облако.вызовы.append({"tool": body["params"]["name"], "auth": self.headers.get("Authorization", "")})
        ответ = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": f"ok:{body['params']['name']}"}]}}
        data = json.dumps(ответ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def облако(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Облако)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    _Облако.вызовы = []
    monkeypatch.setenv("PADAM_AIFA_MCP_URL", f"http://127.0.0.1:{srv.server_port}/api/mcp")
    monkeypatch.delenv("PADAM_AIFA_MCP_TOKEN", raising=False)
    yield _Облако
    srv.shutdown()


@pytest.fixture
def mem(tmp_path):
    return Memory(user_id="owner", store=Store(tmp_path / "p.db"))


def test_без_ключа_статус_и_отказ(mem, облако):
    st = partner_bridge.studio_status(mem)
    assert st["configured"] is False and st["source"] == "none" and st["sends_email"] is False
    with pytest.raises(PermissionError):
        partner_bridge.studio_action(mem, "find_clients", {"region": "US-CA"})
    assert облако.вызовы == []


def test_ключ_хранится_зашифрованным_и_не_возвращается(mem, облако):
    ключ = "amcp_test_1234567890abcdef"
    st = partner_bridge.studio_action(mem, "save_key", {"key": ключ})
    assert st["configured"] and st["source"] == "saved" and len(st["fingerprint"]) == 12
    assert ключ not in json.dumps(st)
    row = mem.store.conn.execute("SELECT key_enc FROM ark_partner_key").fetchone()
    assert row and ключ not in row[0] and row[0].startswith("aesgcm1:")


def test_неверный_ключ_отвергается(mem):
    with pytest.raises(ValueError):
        partner_bridge.save_studio_key(mem, "sk-not-a-cabinet-key")


def test_кнопки_равны_инструментам_mcp(mem, облако):
    partner_bridge.save_studio_key(mem, "amcp_test_1234567890abcdef")
    for act, args, tool in (
        ("find_clients", {"region": "US-CA"}, "find_clients"),
        ("client_report", {"site": "example.com"}, "client_report"),
        ("client_link", {}, "client_link"),
        ("kit", {"language": "ru"}, "partner_kit"),
        ("deals", {}, "my_deals"),
    ):
        r = partner_bridge.studio_action(mem, act, args)
        assert f"ok:{tool}" in r["data"], act
    assert [v["tool"] for v in облако.вызовы] == ["find_clients", "client_report", "client_link", "partner_kit", "my_deals"]
    assert all(v["auth"] == "Bearer amcp_test_1234567890abcdef" for v in облако.вызовы)
    # после вызова ключ студии не «залипает» в процессе
    assert partner_bridge._ключ_студии.get() == ""


def test_черновик_письма_не_отправляется(mem, облако):
    partner_bridge.save_studio_key(mem, "amcp_test_1234567890abcdef")
    r = partner_bridge.studio_action(mem, "draft_outreach", {"site": "example.com", "language": "en"})
    assert r["sent"] is False and r["council"]["needs_owner"] is True
    assert "DRAFT" in r["draft"]


def test_неизвестное_действие(mem):
    with pytest.raises(ValueError):
        partner_bridge.studio_action(mem, "send_email", {})


def test_studio_содержит_блок_на_4_языках():
    from padam import studio
    html = studio.render_studio_html() if hasattr(studio, "render_studio_html") else None
    src = open(studio.__file__, encoding="utf-8").read()
    assert src.count('"earn_partner_t":') == 4
    for btn in ("earn-partner-key-btn", "earn-partner-find-btn", "earn-partner-deals-btn", "earn-partner-report-btn",
                "earn-partner-draft-btn", "earn-partner-link-btn", "earn-partner-kit-btn"):
        assert btn in src
    assert html is None or "earn-partner-box" in html
