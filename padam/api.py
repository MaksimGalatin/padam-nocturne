#!/usr/bin/env python3
"""REST API для PADAM.

Для тех, кто не на Python. Написан на стандартной библиотеке: своей
цепочки зависимостей у сервера памяти быть не должно.

Запуск:
    python -m padam.api                      # 127.0.0.1:8077
    python -m padam.api --host 0.0.0.0 --port 9000 --token СЕКРЕТ

По умолчанию слушает только локальный интерфейс. С 0.4.2 токен есть всегда: не задан
(--token или PADAM_API_TOKEN) — сервер создаёт случайный при запуске и печатает его.
Без токена (--no-token, только локально) запись идёт как запись агента, с проверкой
владельцем, а действия владельца (approve, reject, restore, forget, import, export,
очередь проверки) запрещены. Повод — внешний разбор 09.11.2026: до порта 127.0.0.1
дотягивается и тот, кому файл базы недоступен (агент в песочнице с сетью, другая
учётная запись на том же компьютере), и без токена он мог одобрить свою же задержанную
запись. Как только указан --host, отличный от 127.0.0.1, токен обязателен.

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
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import __version__, config, safety, viewer
from .i18n import t
from .memory import Memory
from .nocturne import Nocturne
from .store import Store

_state: dict = {"memory": None, "token": None, "local": True}
# Действия владельца: без токена недоступны. Тот, кто дотянулся до порта, владельцем не считается.
OWNER_POST = {"/forget", "/approve", "/reject", "/restore", "/import"}
NEEDS_TOKEN = {"error": "this action is the owner's: start the API with --token or PADAM_API_TOKEN"}
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

    def _send_page(self, страница: tuple[str, str]) -> None:
        html, nonce = страница
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Текст памяти — чужие слова: страница выводит его только как текст, а CSP запрещает всё внешнее.
        self.send_header("Content-Security-Policy",
                         f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                         "connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; "
                         "frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
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
        путь = urlsplit(self.path)
        if путь.path == "/" and _state.get("ui"):
            self.send_response(302)
            self.send_header("Location", "/ui")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        if путь.path == "/ui" and _state.get("ui"):
            # Сама страница данных не содержит: записи она берёт через API с токеном из ссылки.
            return self._send_page(viewer.page())
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if not _state["token"]:
            q0 = parse_qs(путь.query)
            if путь.path == "/export" or (путь.path == "/records" and q0.get("view", ["active"])[0] != "active"):
                return self._send(403, NEEDS_TOKEN)
        try:
            if путь.path == "/records":
                q = parse_qs(путь.query)
                return self._send(200, mem().list_records(
                    view=q.get("view", ["active"])[0], text=q.get("q", [None])[0],
                    limit=int(q.get("limit", ["100"])[0]), offset=int(q.get("offset", ["0"])[0]),
                    as_of=q.get("as_of", [None])[0]))
            if self.path == "/stats":
                return self._send(200, mem().stats())
            if self.path == "/export":
                return self._send(200, mem().export())
            if self.path.startswith("/timeline/"):
                rid = self.path.split("/timeline/", 1)[1]
                chain = mem().timeline(rid)
                if not chain:
                    return self._send(404, {"error": "not found"})
                if not _state["token"]:
                    # 0.4.9: без токена запрос не от владельца — текст на проверке и отклонённый
                    # не показывается, так же как в MCP padam_timeline и в /export.
                    for row in chain:
                        if row.get("status") in ("quarantined", "rejected"):
                            row["content"] = None
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
        if not _state["token"] and self.path in OWNER_POST:
            return self._send(403, NEEDS_TOKEN)
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
                                 limit=max(1, min(int(data.get("limit", 5)), config.MAX_RECALL_LIMIT)),
                                 as_of=data.get("as_of") or None)
                return self._send(200, {"results": [
                    {"id": r.id, "kind": r.kind, "content": r.content,
                     "score": round(r.score, 5),
                     "importance": r.importance, "confidence": r.confidence,
                     "origin": r.origin, "created_at": r.created_at,
                     "expired": r.expired, "status": r.status,
                     "suspicious": safety.looks_like_instruction(r.content),
                     "found_by": list(r.strategies)} for r in found]})

            if self.path == "/write":
                if "content" not in data:
                    return self._send(400, {"error": "content is required"})
                if len(str(data["content"])) > config.MAX_CONTENT_CHARS:
                    return self._send(413, {"error": "content too large"})
                # Без поля origin запись считается словами владельца, как и раньше. Клиент, указавший
                # agent или external, проходит те же проверки, что и агент через MCP.
                origin = data.get("origin", "user")
                if origin not in config.ORIGINS:
                    return self._send(400, {"error": f"origin must be one of {list(config.ORIGINS)}"})
                outcome, mid = m.remember(
                    data["content"], kind=data.get("kind"),
                    importance=float(data.get("importance", 0.5)),
                    scope=data.get("scope", "global"),
                    # Без токена владельца не отличить от любого процесса, дотянувшегося до порта.
                    origin=origin, guarded=origin != "user" or not _state["token"])
                return self._send(200, {"outcome": outcome, "id": mid})

            if self.path == "/confirm":
                return self._send(200, {"ok": m.confirm(data["id"])})

            if self.path == "/refute":
                return self._send(200, {"ok": m.refute(data["id"], drop=float(data.get("drop", 0.3)))})

            if self.path == "/forget":
                return self._send(200, {"ok": m.revoke(data["id"])})

            # Решения владельца по записям агента. У MCP этих действий нет; здесь они под токеном.
            if self.path == "/approve":
                return self._send(200, {"ok": m.approve(data["id"])})
            if self.path == "/reject":
                return self._send(200, {"ok": m.reject(data["id"])})
            if self.path == "/restore":
                return self._send(200, {"ok": m.restore(data["id"])})

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


def make_viewer_server(memory: Memory | None = None, port: int = 8078) -> tuple[ThreadingHTTPServer, str]:
    """Сервер просмотра памяти: только 127.0.0.1, токен создаётся на каждый запуск. Возвращает (сервер, ссылка)."""
    _state["token"] = secrets.token_urlsafe(24)
    _state["local"] = True
    _state["ui"] = True
    if memory is not None:
        _state["memory"] = memory
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/ui#t={_state['token']}"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="padam.api")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8077)
    p.add_argument("--token", default=os.environ.get("PADAM_API_TOKEN"))
    p.add_argument("--no-token", action="store_true",
                   help=t("без токена (только локально): запись с проверкой, действия владельца запрещены",
                          "no token (local only): writes are reviewed, owner actions are refused"))
    a = p.parse_args(argv)

    local = a.host in ("127.0.0.1", "localhost", "::1") or a.host.startswith("127.")
    if not local and not a.token:
        print(t("Отказ: при выходе за пределы localhost нужен --token.",
                "Refused: --token is required beyond localhost."), file=sys.stderr)
        print(t("Память не должна оказаться открытой в сеть по недосмотру.",
                "Memory must not end up open to the network by accident."), file=sys.stderr)
        return 2

    # 0.4.3: заглушка из примера службы (REPLACE_WITH_…) или слишком короткий токен — это известная всем
    # строка, хуже, чем никакого. Отказ с объяснением, а не тихий запуск.
    if a.token and (a.token.upper().startswith("REPLACE") or len(a.token) < 16):
        print(t("Отказ: токен — заглушка или короче 16 знаков. Новый: python -c \"import secrets; "
                "print(secrets.token_urlsafe(24))\"",
                "Refused: the token is a placeholder or shorter than 16 characters. A new one: python -c \"import "
                "secrets; print(secrets.token_urlsafe(24))\""), file=sys.stderr)
        return 2
    # 0.4.5: строгий профиль не запускает REST без токена — у такого сервера нет владельца.
    if a.no_token and config.STRICT:
        print(t("Отказ: PADAM_STRICT=1 не допускает --no-token.", "Refused: PADAM_STRICT=1 does not allow --no-token."),
              file=sys.stderr)
        return 2
    создан = False
    if not a.token and not a.no_token:
        a.token, создан = secrets.token_urlsafe(24), True
    _state["token"] = a.token
    _state["local"] = local
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    # 12.10.2026: раньше «локально» считалось только для 127.*, и localhost / ::1 печатались как «ВНЕШНИЙ ДОСТУП».
    scope = t("локально", "local only") if local else t("ВНЕШНИЙ ДОСТУП", "EXTERNAL ACCESS")
    token = (t("включён", "required") if a.token else t("не требуется", "not required"))
    print(t(f"PADAM API на http://{a.host}:{a.port}  ({scope}, токен {token})",
            f"PADAM API at http://{a.host}:{a.port}  ({scope}, token {token})"), flush=True)
    # 0.4.3: flush — без него при выводе в файл или журнал службы токен застревал в буфере и не был виден
    # (замер: 0 байт в журнале через 8 с), а сервер уже ждал запросы с этим токеном.
    if создан:
        print(t(f"Токен этого запуска: {a.token}", f"Token for this run: {a.token}"), flush=True)
        print(t("Заголовок: Authorization: Bearer <токен>. Постоянный — PADAM_API_TOKEN.",
                "Header: Authorization: Bearer <token>. A fixed one: PADAM_API_TOKEN."), flush=True)
    elif a.no_token:
        print(t("Без токена: любая запись ждёт проверки владельцем, действия владельца (approve, forget, export…) "
                "запрещены.", "No token: every write waits for the owner's review; owner actions (approve, forget, "
                "export…) are refused."), file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(t("\nОстановлен.", "\nStopped."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
