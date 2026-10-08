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
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .memory import Memory
from .nocturne import Nocturne
from .store import Store

_state: dict = {"memory": None, "token": None}


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
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError("body is not valid JSON")

    def _authorized(self) -> bool:
        token = _state["token"]
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        return header == f"Bearer {token}"

    # -- маршруты ------------------------------------------------------

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok", "version": __version__})
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
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        try:
            data = self._body()
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

    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.token:
        print("Отказ: при выходе за пределы localhost нужен --token.",
              file=sys.stderr)
        print("Память не должна оказаться открытой в сеть по недосмотру.",
              file=sys.stderr)
        return 2

    _state["token"] = a.token
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    scope = "локально" if a.host.startswith("127.") else "ВНЕШНИЙ ДОСТУП"
    print(f"PADAM API на http://{a.host}:{a.port}  ({scope}, "
          f"токен {'включён' if a.token else 'не требуется'})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлен.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
