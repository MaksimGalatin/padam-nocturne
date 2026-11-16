"""HTTP-сервер PADAM без обратного поиска имени в DNS при запуске.

16.11.2026. Стандартный `http.server.HTTPServer.server_bind` вызывает `socket.getfqdn(host)` —
обратный поиск имени компьютера в DNS. На macOS он висит десятки секунд (замер в CI GitHub на всех
четырёх версиях Python: процесс жив, но за 30 с так и не начал слушать; трассировка faulthandler
указала на `socket.getfqdn`). Из-за этого на Маке медленно стартовали `padam api`, PADAM Studio,
MCP по HTTP и общий демон `--auto-daemon`.

Имя сервера PADAM нигде не использует: обработчики не читают `server_name`, а слушаем мы на
адресе, который нам дали. Поэтому имя — это просто сам адрес, без похода в DNS.
"""
from __future__ import annotations

import socketserver
from http.server import ThreadingHTTPServer as _StdThreadingHTTPServer


class ThreadingHTTPServer(_StdThreadingHTTPServer):
    """Тот же `ThreadingHTTPServer`, но `server_bind` не обращается к DNS."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)
