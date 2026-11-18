"""Studio на случайном порте не берёт порт, запрещённый браузером (18.11: 1723 → net::ERR_UNSAFE_PORT)."""
import socket

from padam import api


def test_порт_из_запретного_списка_перевыбирается(monkeypatch):
    выданные = iter([1723, 6000, 51234])
    настоящий = api.ThreadingHTTPServer

    class Подставной(настоящий):
        def __init__(self, addr, handler):
            super().__init__((addr[0], 0), handler)
            if addr[1] == 0:
                self.server_address = ("127.0.0.1", next(выданные))

    monkeypatch.setattr(api, "ThreadingHTTPServer", Подставной)
    srv = api._bind_browser_safe(0, api.BaseHTTPRequestHandler)
    try:
        assert srv.server_address[1] == 51234
    finally:
        srv.server_close()


def test_явный_порт_не_меняется():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); свободный = s.getsockname()[1]; s.close()
    srv = api._bind_browser_safe(свободный, api.BaseHTTPRequestHandler)
    try:
        assert srv.server_address[1] == свободный
    finally:
        srv.server_close()
