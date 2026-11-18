"""Фаза 2 аудита GLM, NETGUARD-01: подмена DNS между проверкой и соединением (rebinding) не пускает во внутреннюю сеть."""
import http.server
import socket
import threading

import pytest

from padam import net_guard


class _Ok(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        self.send_response(200); self.end_headers(); self.wfile.write(b"internal")

    def log_message(self, *a):
        pass


@pytest.fixture
def local_server(monkeypatch):
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)
    _Ok.hits = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Ok)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown(); srv.server_close()


def test_rebinding_публичный_на_проверке_внутренний_на_соединении(local_server, monkeypatch):
    real = socket.getaddrinfo
    calls = {"n": 0}

    def fake(host, port, *a, **kw):
        if host == "rebind.example.com":
            calls["n"] += 1
            ip = "93.184.216.34" if calls["n"] == 1 else "127.0.0.1"   # проверка видит публичный, соединение — свой
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
        return real(host, port, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(Exception):
        net_guard.safe_urlopen(f"http://rebind.example.com:{local_server}/", require_https=False, timeout=5)
    assert _Ok.hits == 0, "запрос дошёл до внутреннего сервера"


def test_dns_servfail_на_проверке_не_пропускает(local_server, monkeypatch):
    real = socket.getaddrinfo
    calls = {"n": 0}

    def fake(host, port, *a, **kw):
        if host == "servfail.example.com":
            calls["n"] += 1
            if calls["n"] == 1:
                raise socket.gaierror("SERVFAIL")
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return real(host, port, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(Exception):
        net_guard.safe_urlopen(f"http://servfail.example.com:{local_server}/", require_https=False, timeout=5)
    assert _Ok.hits == 0


def test_разрешённый_localhost_работает(local_server):
    r = net_guard.safe_urlopen(f"http://127.0.0.1:{local_server}/", allow_localhost=True, require_https=False, timeout=5)
    assert r.status == 200 and r.read() == b"internal"
