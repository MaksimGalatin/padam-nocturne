#!/usr/bin/env python3
"""REST API для PADAM.

Для тех, кто не на Python. Написан на стандартной библиотеке: своей
цепочки зависимостей у сервера памяти быть не должно.

Запуск:
    python -m padam.api                      # 127.0.0.1:8077
    python -m padam.api --host 0.0.0.0 --port 9000 --token СЕКРЕТ

По умолчанию слушает только локальный интерфейс и работает без токена.
Как только указан --host, отличный от 127.0.0.1, токен становится
обязательным: память не должна оказаться открытой в сеть по недосмотру.

Маршруты:
    GET  /health
    GET  /stats
    POST /search     {"query": "...", "kind": "...", "limit": 5}
    POST /write      {"content": "...", "kind": "...", "importance": 0.5}
    POST /confirm    {"id": "..."}
    POST /refute     {"id": "...", "drop": 0.3}
    POST /forget     {"id": "..."}
    GET  /timeline/<id>
    GET  /export
    POST /sleep      {"batch": 256, "dry_run": false}
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .i18n import t
from .memory import Memory
from .nocturne import Nocturne
from .store import Store

_state: dict = {"memory": None, "token": None, "local": True}
MAX_BODY = 10 * 1024 * 1024  # 10 МБ: больше импорт памяти не бывает, а больший запрос — это атака


def mem() -> Memory:
    if _state["memory"] is None:
        _state["memory"] = Memory(
            user_id=os.environ.get("PADAM_USER", "default"),
            store=Store(os.environ.get("PADAM_DB") or None))
    return _state["memory"]


class Handler(BaseHTTPRequestHandler):
    server_version = f"padam/{__version__}"

    # -- служебное -----------------------------------------------------

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def _send(self, code: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        # 16.10.2026: размер тела не ограничивался — один запрос мог занять всю память процесса.
        if length > MAX_BODY:
            raise ValueError("payload too large")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError("body is not valid JSON")
        # Массив, число или null вместо объекта роняли маршруты на data.get(...) с ошибкой 500.
        if not isinstance(data, dict):
            raise ValueError("body must be a JSON object")
        return data

    def _authorized(self) -> bool:
        token = _state["token"]
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        # Сравнение за постоянное время: обычное == выдаёт длину совпавшего начала по времени ответа.
        return hmac.compare_digest(header.encode("utf-8"), f"Bearer {token}".encode("utf-8"))

    def _trusted(self) -> bool:
        """Запрос пришёл не из чужой веб-страницы в браузере владельца.

        16.10.2026. Локальный сервер без токена доступен любой странице, открытой в браузере на
        этом же компьютере: (1) DNS rebinding — чужой домен начинает указывать на 127.0.0.1 и
        читает /export; (2) подделка запроса — fetch(..., {mode: "no-cors"}) с телом text/plain
        вызывает /forget. Защита: заголовок Host только локальный, Origin — только локальный или
        отсутствует (так ходят curl и CLI), POST — только application/json (браузер не пошлёт его
        чужому адресу без предварительного запроса, на который мы не отвечаем разрешением).
        """
        if _state.get("local"):
            host = (self.headers.get("Host") or "").strip().lower()
            имя = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
            if имя not in ("127.0.0.1", "localhost", "[::1]") and not имя.startswith("127."):
                return False
        origin = (self.headers.get("Origin") or "").strip().lower()
        if origin and not re.match(r"^https?://(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:\d+)?$", origin):
            return False
        return True

    # -- маршруты ------------------------------------------------------

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok", "version": __version__})
        if not self._trusted():
            return self._send(403, {"error": "forbidden origin or host"})
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        try:
            if self.path == "/stats":
                return self._send(200, mem().stats())
            if self.path == "/export":
                return self._send(200, mem().export())
            if self.path.startswith("/timeline/"):
                rid = self.path.split("/timeline/", 1)[1]
                chain = mem().timeline(rid)
                if not chain:
                    return self._send(404, {"error": "not found"})
                return self._send(200, {"versions": chain})
            return self._send(404, {"error": "unknown route"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        if not self._trusted():
            return self._send(403, {"error": "forbidden origin or host"})
        ctype = (self.headers.get("Content-Type") or "").lower()
        if int(self.headers.get("Content-Length") or 0) and "application/json" not in ctype:
            return self._send(415, {"error": "Content-Type must be application/json"})
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        try:
            try:
                data = self._body()
            except ValueError as e:
                return self._send(413 if "too large" in str(e) else 400, {"error": str(e)})
            m = mem()

            if self.path == "/search":
                if "query" not in data:
                    return self._send(400, {"error": "query is required"})
                found = m.recall(data["query"], scope=data.get("scope", "global"),
                                 kind=data.get("kind"),
                                 limit=int(data.get("limit", 5)))
                return self._send(200, {"results": [
                    {"id": r.id, "kind": r.kind, "content": r.content,
                     "score": round(r.score, 5),
                     "importance": r.importance, "confidence": r.confidence,
                     "expired": r.expired,
                     "found_by": list(r.strategies)} for r in found]})

            if self.path == "/write":
                if "content" not in data:
                    return self._send(400, {"error": "content is required"})
                outcome, mid = m.remember(
                    data["content"], kind=data.get("kind"),
                    importance=float(data.get("importance", 0.5)),
                    scope=data.get("scope", "global"))
                return self._send(200, {"outcome": outcome, "id": mid})

            if self.path == "/confirm":
                return self._send(200, {"ok": m.confirm(data["id"])})

            if self.path == "/refute":
                m.refute(data["id"], drop=float(data.get("drop", 0.3)))
                return self._send(200, {"ok": True})

            if self.path == "/forget":
                return self._send(200, {"ok": m.revoke(data["id"])})

            if self.path == "/sleep":
                report = Nocturne(m, batch_size=int(data.get("batch", 256)),
                                  dry_run=bool(data.get("dry_run", False))).run()
                report.pop("checks", None)
                return self._send(200, report)

            if self.path == "/import":
                added = m.import_(data, overwrite=bool(data.get("overwrite")))
                return self._send(200, {"imported": added})

            return self._send(404, {"error": "unknown route"})
        except KeyError as e:
            return self._send(400, {"error": f"missing field: {e}"})
        except Exception as e:
            return self._send(500, {"error": str(e)})


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="padam.api")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8077)
    p.add_argument("--token", default=os.environ.get("PADAM_API_TOKEN"))
    a = p.parse_args(argv)

    local = a.host in ("127.0.0.1", "localhost", "::1") or a.host.startswith("127.")
    if not local and not a.token:
        print(t("Отказ: при выходе за пределы localhost нужен --token.",
                "Refused: --token is required beyond localhost."), file=sys.stderr)
        print(t("Память не должна оказаться открытой в сеть по недосмотру.",
                "Memory must not end up open to the network by accident."), file=sys.stderr)
        return 2

    _state["token"] = a.token
    _state["local"] = local
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    # 12.10.2026: раньше «локально» считалось только для 127.*, и localhost / ::1 печатались как «ВНЕШНИЙ ДОСТУП».
    scope = t("локально", "local only") if local else t("ВНЕШНИЙ ДОСТУП", "EXTERNAL ACCESS")
    token = (t("включён", "required") if a.token else t("не требуется", "not required"))
    print(t(f"PADAM API на http://{a.host}:{a.port}  ({scope}, токен {token})",
            f"PADAM API at http://{a.host}:{a.port}  ({scope}, token {token})"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(t("\nОстановлен.", "\nStopped."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
