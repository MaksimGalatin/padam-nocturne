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
import zipfile
import os
import re
import secrets
import threading
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler
from ._httpserver import ThreadingHTTPServer  # без DNS при запуске (macOS)
from urllib.parse import parse_qs, urlsplit
from . import code_freshness as _code_freshness  # noqa: F401  — отпечаток кода в момент запуска

from . import __version__, cabinet, config, connectors, logo, roles, safety, studio, viewer
from .i18n import t
from .memory import Memory, decay, parse_ts
from .nocturne import Nocturne
from .store import Store

_state: dict = {"memory": None, "token": None, "local": True}
# Действия владельца: без токена недоступны. Тот, кто дотянулся до порта, владельцем не считается.
OWNER_POST = {"/forget", "/approve", "/reject", "/restore", "/import", "/import-external", "/export-md", "/trust-protected", "/settings", "/l3-verify", "/ask", "/link", "/workspaces", "/workspaces/members", "/workspaces/revoke", "/records/visibility", "/connectors/configure", "/connectors/sync", "/backup", "/backup/restore", "/api/v2/procedures/approve", "/api/v2/playground/demo", "/api/v2/bridge/ingest", "/api/v2/aifa-security/run", "/migrate/preview", "/migrate/run", "/migrate/undo", "/api/v2/cabinet/auth/send-code", "/api/v2/cabinet/auth/verify-code", "/api/v2/cabinet/auth/logout", "/api/v2/cabinet/aifa/chat", "/api/v2/cabinet/open-upgrade", "/v1/chat/completions", "/api/v2/brain/distill", "/api/v2/brain/phoenix-restore", "/api/v2/brain/phoenix-pack", "/api/v2/brain/treasury/quote", "/api/v2/brain/mode", "/api/v2/brain/warmup", "/api/v2/brain/canary", "/api/v2/ark/phoenix-drill", "/api/v2/ark/jobs", "/api/v2/ark/genesis", "/api/v2/ark/shamir-split", "/api/v2/ark/council", "/api/v2/ark/mesh/delta", "/api/v2/ark/mesh/apply", "/api/v2/ark/mesh/pair-init", "/api/v2/ark/mesh/pair-accept", "/api/v2/ark/mesh/pair-confirm", "/api/v2/ark/proof", "/api/v2/ark/branches", "/api/v2/ark/drift", "/api/v2/ark/handover", "/api/v2/ark/self-heal", "/api/v2/ark/portable", "/api/v2/ark/siblings", "/api/v2/ark/coop", "/api/v2/ark/conflicts", "/api/v2/ark/budget/action", "/api/v2/ark/freelance/action", "/api/v2/ark/stores/action", "/api/v2/ark/wizard/action", "/api/v2/ark/partner/action", "/api/v2/ark/phoenix-beacon/action", "/api/v2/local-model", "/api/v2/family/post", "/api/v2/family/reflex/decide", "/api/v2/quarantine/council"}
OWNER_GET = {"/export", "/doctor", "/overview", "/forget-receipts", "/forget-preview", "/settings", "/l3", "/graph", "/profile", "/audit", "/events", "/entities", "/workspaces", "/connectors", "/api/v2/access", "/api/v2/communities", "/api/v2/cabinet/status", "/api/v2/cabinet/aifa/history", "/api/v2/cabinet/plans", "/attacks", "/api/v2/aifa-security", "/api/v2/aifa-security/sarif", "/api/v2/aifa-security/html", "/api/v2/aifa-security/fuzz", "/api/v2/aifa-security/verify", "/api/v2/qa-benchmark", "/api/v2/brain/status", "/v1/models", "/api/v2/brain/voice/status", "/api/v2/ark/wakeup", "/api/v2/ark/health", "/api/v2/ark/audit-verify", "/api/v2/ark/jobs", "/api/v2/ark/guardian-tick", "/api/v2/ark/branches", "/api/v2/ark/mesh/peers", "/api/v2/ark/readiness", "/api/v2/ark/reflex", "/api/v2/ark/siblings", "/api/v2/ark/coop", "/api/v2/ark/session-pack", "/api/v2/ark/mcp-telemetry", "/api/v2/ark/budget", "/api/v2/ark/freelance", "/api/v2/ark/stores", "/api/v2/ark/wizard", "/api/v2/ark/partner", "/api/v2/local-model", "/api/v2/family/feed", "/api/v2/family/reflexes", "/api/v2/quarantine/council", "/api/v2/family/dialogs", "/api/v2/redteam/rounds", "/api/v2/code-version"}
NEEDS_TOKEN = {"error": "this action is the owner's: start the API with --token or PADAM_API_TOKEN"}
MAX_BODY = 10 * 1024 * 1024  # 10 МБ: больше импорт памяти не бывает, а больший запрос — это атака


def _desktop_shared_memory() -> dict:
    """18.11.2026: общая память Семьи для настольного приложения.

    Окно приложения (Tauri) умеет передать серверу только путь к базе (--db) и не умеет передать имя пользователя,
    а пересобрать окно на машине владельца нечем. Поэтому, когда сервер запущен окном (PADAM_DESKTOP_EXE), он читает
    %LOCALAPPDATA%\\PADAM Studio\\shared_memory.json: {"db": "<абсолютный путь>", "user": "<имя>"}. Явные PADAM_DB и
    PADAM_USER сильнее файла. Без окна приложения файл не читается — тесты и другие запуски не затрагиваются.
    """
    if not os.environ.get("PADAM_DESKTOP_EXE"):
        return {}
    from pathlib import Path
    try:
        p = Path(os.environ.get("LOCALAPPDATA", "")) / "PADAM Studio" / "shared_memory.json"
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out = {}
    db = str(data.get("db") or "").strip()
    if db and Path(db).is_absolute() and Path(db).is_file():
        out["db"] = db
    user = str(data.get("user") or "").strip()
    if user and len(user) <= 64 and all(ch.isalnum() or ch in "-_.@" for ch in user):
        out["user"] = user
    return out


def mem() -> Memory:
    if _state["memory"] is None:
        shared = _desktop_shared_memory()
        _state["memory"] = Memory(
            user_id=os.environ.get("PADAM_USER") or shared.get("user") or "default",
            store=Store(os.environ.get("PADAM_DB") or shared.get("db") or None))
    return _state["memory"]


class Handler(BaseHTTPRequestHandler):
    server_version = f"padam/{__version__}"

    # -- служебное -----------------------------------------------------

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def _cors_origin(self) -> str | None:
        origin = (self.headers.get("Origin") or "").strip()
        low = origin.lower()
        if re.match(r"^https?://(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:\d+)?$", low):
            return origin
        if _state.get("token") and (
            re.match(r"^chrome-extension://[a-z]{32}$", low)
            or re.match(r"^moz-extension://[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", low)
        ):
            return origin
        return None

    def _send(self, code: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if b'_ru"' in body or re.search(rb'"(title|description|last_note)": "[^"]*[\xd0\xd1]', body):   # 19.11.2026: данные мастера бирж — на языке человека (переводы en/es/zh к полям *_ru)
            try:
                from .platform_wizard_i18n import localize as _loc
                body = json.dumps(_loc(payload), ensure_ascii=False).encode("utf-8")
            except Exception:
                pass
        if code >= 400:
            self._дочитать_тело()
        try:
            self.send_response(code)
            cors = self._cors_origin()
            if cors:
                self.send_header("Access-Control-Allow-Origin", cors)
                self.send_header("Vary", "Origin")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            return

    def do_OPTIONS(self) -> None:
        if not self._trusted():
            return self._send(403, {"error": "forbidden origin or host"})
        cors = self._cors_origin()
        if not cors:
            return self._send(403, {"error": "forbidden origin"})
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", cors)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Agent-ID")
        self.send_header("Content-Length", "0")
        self.end_headers()

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

    def _дочитать_тело(self) -> None:
        """Отказ до чтения тела (403, 401, 415…) — тело всё равно дочитывается, если оно в пределе.
        Найдено 11.11.2026: на Windows закрытие сокета с непрочитанными входными данными шлёт клиенту RST, и
        вместо ответа «403» клиент получал разрыв (WinError 10053). Тело больше предела не читается: такой
        запрос — атака, соединение закрывается. Отметка «прочитано» привязана к заголовкам этого запроса."""
        if self.command != "POST" or getattr(self, "_тело_прочитано", None) is self.headers:
            return
        self._тело_прочитано = self.headers
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        if 0 < length <= MAX_BODY:
            self.rfile.read(length)
        elif length > MAX_BODY:
            self.close_connection = True

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        # 16.10.2026: размер тела не ограничивался — один запрос мог занять всю память процесса.
        if length > MAX_BODY:
            raise ValueError("payload too large")
        self._тело_прочитано = self.headers
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError("body is not valid JSON")
        # Массив, число или null вместо объекта роняли маршруты на data.get(...) с ошибкой 500.
        if not isinstance(data, dict):
            raise ValueError("body must be a JSON object")
        return data

    def _resolve_actor(self) -> tuple[roles.ActorContext | None, bool]:
        """Определить субъект и роль исключительно по проверенному Bearer-токену."""
        token = _state["token"]
        header = (self.headers.get("Authorization") or "").strip()
        if header:
            if not header.startswith("Bearer "):
                return None, False
            raw_tok = header[7:].strip()
            if token and hmac.compare_digest(header.encode("utf-8"), f"Bearer {token}".encode("utf-8")):
                return roles.OWNER_ACTOR, True
            member_actor = mem().authenticate_token(raw_tok)
            if member_actor is not None:
                return member_actor, True
            return None, False
        if token:
            return None, False
        # Режим --no-token: если в базе созданы участники команд, гость без токена не получает доступ к команде/private.
        if mem().has_team_members():
            return roles.ActorContext(role="guest", subject="guest", workspace_id=None, via_token=False), True
        return None, True

    def _authorized(self) -> bool:
        actor, ok = self._resolve_actor()
        self._actor = actor
        return ok

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
        if origin:
            is_local_orig = bool(re.match(r"^https?://(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:\d+)?$", origin))
            is_ext_orig = bool(_state.get("token") and (
                re.match(r"^chrome-extension://[a-z]{32}$", origin)
                or re.match(r"^moz-extension://[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", origin)
            ))
            if not (is_local_orig or is_ext_orig):
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
            self.send_header("Location", "/studio" if _state.get("studio_default") else "/ui")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        if путь.path == "/ui" and _state.get("ui"):
            # Сама страница данных не содержит: записи она берёт через API с токеном из ссылки.
            return self._send_page(viewer.page())
        if путь.path == "/studio" and _state.get("ui"):
            # Приложение PADAM Studio: строгий CSP, без встроенных данных и токена в HTML.
            return self._send_page(studio.page())
        if путь.path in ("/favicon.svg", "/favicon.ico", "/icon-192.png", "/icon-512.png", "/manifest.webmanifest", "/sw.js") and _state.get("ui"):
            if путь.path == "/favicon.svg":
                body = logo.CODE_LOGO_SVG.encode("utf-8")
                ctype = "image/svg+xml; charset=utf-8"
            elif путь.path == "/favicon.ico":
                body = logo.favicon_ico_bytes()
                ctype = "image/x-icon"
            elif путь.path in ("/icon-192.png", "/icon-512.png"):
                body = logo.pwa_icon_png_bytes(512 if "512" in путь.path else 192)
                ctype = "image/png"
            elif путь.path == "/sw.js":
                body = (
                    "self.addEventListener('install', () => self.skipWaiting());\n"
                    "self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));\n"
                    "self.addEventListener('fetch', e => { if (e.request.headers.get('Authorization')) return; });\n"
                ).encode("utf-8")
                ctype = "application/javascript; charset=utf-8"
            else:
                manifest_obj = {
                    "name": "PADAM · NOCTURNE Studio",
                    "short_name": "PADAM Studio",
                    "description": "Локальная защищённая память ИИ-агентов · CODE Eternal",
                    "start_url": "/studio",
                    "scope": "/",
                    "display": "standalone",
                    "background_color": "#080b12",
                    "theme_color": "#080b12",
                    "icons": [
                        {"src": "/favicon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"},
                        {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
                        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},
                    ],
                }
                body = json.dumps(manifest_obj, ensure_ascii=False, indent=2).encode("utf-8")
                ctype = "application/manifest+json; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'none'; style-src 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(body)
            return None
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        actor = getattr(self, "_actor", None)
        if not _state["token"] and (actor is None or not actor.via_token):
            q0 = parse_qs(путь.query)
            if путь.path in OWNER_GET or (путь.path == "/records" and q0.get("view", ["active"])[0] != "active"):
                return self._send(403, NEEDS_TOKEN)
        try:
            if путь.path == "/workspaces":
                m = mem()
                cur_role = actor.role if actor is not None else "owner"
                cur_subj = actor.subject if actor is not None else "owner"
                cur_ws = actor.workspace_id if actor is not None else None
                return self._send(200, {
                    "workspaces": m.list_workspaces(actor=actor),
                    "members": m.list_members(actor=actor),
                    "actor": {"role": cur_role, "subject": cur_subj, "workspace_id": cur_ws},
                })
            if путь.path == "/records":
                q = parse_qs(путь.query)
                view_arg = q.get("view", ["active"])[0]
                if view_arg in ("quarantined", "rejected") and actor is not None and not actor.is_owner:
                    roles.require_moderate(actor)
                return self._send(200, mem().list_records(
                    view=view_arg, text=q.get("q", [None])[0],
                    limit=int(q.get("limit", ["100"])[0]), offset=int(q.get("offset", ["0"])[0]),
                    as_of=q.get("as_of", [None])[0],
                    kind=q.get("kind", [None])[0] or None,
                    scope=q.get("scope", [None])[0] or None,
                    agent_id=q.get("agent_id", [None])[0] or None,
                    hide_dialogs=q.get("hide_dialogs", ["0"])[0] == "1",
                    actor=actor))
            if путь.path == "/profile":
                roles.require_owner(actor, "profile")
                q = parse_qs(путь.query)
                return self._send(200, mem().profile(scope=q.get("scope", ["global"])[0] or "global"))
            if путь.path == "/audit":
                q = parse_qs(путь.query)
                return self._send(200, {"entries": mem().audit_log(
                    limit=int(q.get("limit", ["100"])[0]),
                    action=q.get("action", [None])[0] or None,
                    agent_id=q.get("agent_id", [None])[0] or None,
                    actor=actor,
                )})
            if путь.path == "/events":
                q = parse_qs(путь.query)
                replay = max(0, min(int(q.get("replay", ["10"])[0]), 100))
                once = q.get("once", ["0"])[0] == "1"
                wait_sec = max(0.1, min(float(q.get("timeout", ["5.0"])[0]), 30.0))
                m = mem()
                chunks: list[str] = ["event: ready\ndata: {\"status\":\"connected\"}\n\n"]
                if replay > 0:
                    recent = list(reversed(m.audit_log(limit=replay)))
                    for ev in recent:
                        chunks.append(
                            f"id: {ev['id']}\nevent: {ev['action']}\ndata: "
                            + json.dumps(ev, ensure_ascii=False)
                            + "\n\n"
                        )
                if not once:
                    import queue as _queue
                    sub_q = m.subscribe_events()
                    try:
                        live_ev = sub_q.get(timeout=wait_sec)
                        chunks.append(
                            f"id: {live_ev['id']}\nevent: {live_ev['action']}\ndata: "
                            + json.dumps(live_ev, ensure_ascii=False)
                            + "\n\n"
                        )
                    except _queue.Empty:
                        chunks.append(": keepalive\n\n")
                    finally:
                        m.unsubscribe_events(sub_q)
                payload_bytes = "".join(chunks).encode("utf-8")
                self.send_response(200)
                cors = self._cors_origin()
                if cors:
                    self.send_header("Access-Control-Allow-Origin", cors)
                    self.send_header("Vary", "Origin")
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(len(payload_bytes)))
                self.end_headers()
                self.wfile.write(payload_bytes)
                return None
            if self.path == "/stats":
                return self._send(200, mem().stats(actor=actor))
            if путь.path == "/attacks":
                roles.require_owner(actor, "attacks")
                from . import defense_stats
                return self._send(200, defense_stats.attack_stats(mem()))
            if путь.path == "/api/v2/aifa-security":
                roles.require_owner(actor, "aifa_security")
                from . import aifa_sec_bridge
                return self._send(200, aifa_sec_bridge.get_aifa_security_report(run_fresh=False))
            if путь.path == "/api/v2/aifa-security/sarif":
                roles.require_owner(actor, "aifa_security")
                from . import aifa_sec_bridge
                from benchmarks.aifa_security.render import render_sarif
                rep = aifa_sec_bridge.get_aifa_security_report(run_fresh=False)
                raw_sarif = render_sarif(rep).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/sarif+json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="aifa_security.sarif.json"')
                self.send_header("Content-Length", str(len(raw_sarif)))
                self.end_headers()
                self.wfile.write(raw_sarif)
                return
            if путь.path == "/api/v2/aifa-security/html":
                roles.require_owner(actor, "aifa_security")
                from . import aifa_sec_bridge
                from benchmarks.aifa_security.render import render_html_dashboard
                rep = aifa_sec_bridge.get_aifa_security_report(run_fresh=False)
                raw_html = render_html_dashboard(rep).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="aifa_security_report.html"')
                self.send_header("Content-Length", str(len(raw_html)))
                self.end_headers()
                self.wfile.write(raw_html)
                return
            if путь.path == "/api/v2/aifa-security/fuzz":
                roles.require_owner(actor, "aifa_security")
                from benchmarks.aifa_security.fuzzer import run_fuzz_suite
                return self._send(200, run_fuzz_suite())
            if путь.path == "/api/v2/aifa-security/verify":
                roles.require_owner(actor, "aifa_security")
                from . import aifa_sec_bridge
                from benchmarks.aifa_security.run_aifa_sec import verify_report_attestation
                rep = aifa_sec_bridge.get_aifa_security_report(run_fresh=False)
                return self._send(200, verify_report_attestation(rep))
            if путь.path == "/v1/models":
                roles.require_owner(actor, "llm_router")
                from . import router as _router
                qs = parse_qs(путь.query)
                return self._send(200, _router.models_payload(include_local_probe=(qs.get("probe") == ["1"])))
            if путь.path == "/api/v2/brain/status":
                roles.require_owner(actor, "brain_status")
                from . import router as _router, sovereign_ops as _sops, voice as _voice
                qs = parse_qs(путь.query)
                snap = _router.get_router().status_snapshot()
                if qs.get("probe") == ["1"]:
                    snap["local_probe"] = _router.probe_local_backend()
                locks = _sops.locks_status()
                snap.update(locks)
                snap["auto_payments_locked"] = locks["treasury_autopay_locked"]
                snap["voice"] = _voice.voice_status()
                return self._send(200, snap)
            if путь.path == "/api/v2/brain/voice/status":
                roles.require_owner(actor, "brain_status")
                from . import voice as _voice
                return self._send(200, _voice.voice_status())
            if путь.path == "/api/v2/ark/wakeup":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                qs = parse_qs(путь.query)
                agent = str((qs.get("agent") or ["aifa"])[0])
                with mem().store._lock:
                    res = _ark.wake_up_briefing(mem(), agent=agent)
                return self._send(200, res)
            if путь.path == "/api/v2/code-version":
                roles.require_owner(actor, "brain_status")
                from . import code_freshness as _cf
                return self._send(200, _cf.status())
            if путь.path == "/api/v2/ark/health":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                with mem().store._lock:
                    res = _ark.ark_health_score(mem())
                return self._send(200, res)
            if путь.path == "/api/v2/ark/audit-verify":
                roles.require_owner(actor, "brain_status")
                from . import audit_chain as _ac
                with mem().store._lock:
                    res = _ac.verify_audit_chain(mem())
                return self._send(200, res)
            if путь.path == "/api/v2/ark/jobs":
                roles.require_owner(actor, "brain_status")
                jobs_dict = _state.setdefault("ark_jobs", {})
                return self._send(200, {"jobs": list(jobs_dict.values())[-20:]})
            if self.path.startswith("/api/v2/ark/guardian-tick"):
                roles.require_owner(actor, "brain_status")
                from . import ark_advanced as _adv
                with mem().store._lock:
                    res = _adv.run_guardian_tick(mem())
                return self._send(200, res)
            if self.path.startswith("/api/v2/ark/branches"):
                roles.require_owner(actor, "brain_status")
                from . import ark_advanced as _adv
                with mem().store._lock:
                    res = {"branches": _adv.list_branches(mem())}
                return self._send(200, res)
            if путь.path == "/api/v2/ark/mesh/identity":
                roles.require_owner(actor, "brain_status")
                from . import live_mesh as _mesh
                qs_m = parse_qs(путь.query)
                with mem().store._lock:
                    res = _mesh.get_or_create_node_identity(
                        mem(),
                        device_name=(qs_m.get("device_name") or ["Primary-Node"])[0],
                        device_type=(qs_m.get("device_type") or ["pc"])[0],
                    )
                return self._send(200, res)
            if self.path.startswith("/api/v2/ark/mesh/peers"):
                roles.require_owner(actor, "brain_status")
                from . import live_mesh as _mesh
                with mem().store._lock:
                    res = {"node": _mesh.get_or_create_node_identity(mem()), "peers": _mesh.list_peers(mem())}
                return self._send(200, res)
            if путь.path == "/api/v2/ark/commitments":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                st_f = (parse_qs(путь.query).get("status") or [None])[0] or None
                with mem().store._lock:
                    res = {"commitments": _ark.list_commitments(mem(), status=st_f)}
                return self._send(200, res)
            if путь.path == "/api/v2/ark/relay":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                qs_r = parse_qs(путь.query)
                with mem().store._lock:
                    res = {"inbox": _ark.read_family_inbox(
                        mem(),
                        to_agent=(qs_r.get("to_agent") or [None])[0] or None,
                        limit=int((qs_r.get("limit") or ["20"])[0] or 20),
                    )}
                return self._send(200, res)
            if путь.path == "/api/v2/ark/checkpoint":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                sid = (parse_qs(путь.query).get("session_id") or [None])[0] or None
                with mem().store._lock:
                    res = {"checkpoint": _ark.latest_checkpoint(mem(), session_id=sid)}
                return self._send(200, res)
            if путь.path == "/api/v2/ark/timeline":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                qs_t = parse_qs(путь.query)
                with mem().store._lock:
                    res = {"timeline": _ark.build_timeline(
                        mem(),
                        query=(qs_t.get("query") or [None])[0] or None,
                        since=(qs_t.get("since") or [None])[0] or None,
                        limit=int((qs_t.get("limit") or ["25"])[0] or 25),
                    )}
                return self._send(200, res)
            if путь.path == "/api/v2/ark/lessons":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                lim_l = int((parse_qs(путь.query).get("limit") or ["15"])[0] or 15)
                with mem().store._lock:
                    res = {"lessons": _ark.list_lessons(mem(), limit=lim_l)}
                return self._send(200, res)
            if путь.path == "/api/v2/ark/conflicts":
                roles.require_owner(actor, "brain_status")
                from . import conflict_arbiter as _arb
                st_c = (parse_qs(путь.query).get("status") or [None])[0] or None
                with mem().store._lock:
                    res = {"cases": _arb.list_conflict_cases(mem(), status=st_c)}
                return self._send(200, res)
            if путь.path == "/api/v2/ark/code-anchor":
                roles.require_owner(actor, "brain_status")
                from . import code_anchor as _ca
                root_ca = (parse_qs(путь.query).get("repo_root") or ["."])[0] or "."
                with mem().store._lock:
                    res = _ca.check_stale_anchors(mem(), repo_root=root_ca)
                return self._send(200, res)
            if путь.path == "/api/v2/snapshots":
                roles.require_owner(actor, "rollback")
                qs_sn = parse_qs(путь.query)
                with mem().store._lock:
                    res = {"snapshots": mem().snapshots(
                        scope=(qs_sn.get("scope") or [None])[0] or None,
                        limit=int((qs_sn.get("limit") or ["20"])[0] or 20),
                    )}
                return self._send(200, res)
            if путь.path == "/api/v2/quarantine/council":
                roles.require_owner(actor, "quarantine_council")
                from . import quarantine_council as _qc
                return self._send(200, {"verdicts": _qc.verdicts(mem())})
            if путь.path == "/api/v2/redteam/rounds":
                # Запечатанные раунды красной команды — бенчмарк из статьи Show HN (данные из redteam/rounds/*/SEALED_RESULTS.md).
                roles.require_owner(actor, "aifa_security")
                from . import redteam_rounds as _rr
                return self._send(200, _rr.list_rounds())
            if путь.path == "/api/v2/family/dialogs":
                # «Диалоги Семьи» (слово Папы 18.11): итоги сессий из памяти, лента по дням, поиск.
                roles.require_owner(actor, "family_dialogs")
                from . import family_dialogs as _fd
                qs_fd = parse_qs(путь.query)
                return self._send(200, _fd.list_dialogs(
                    mem(),
                    query=(qs_fd.get("q") or [""])[0],
                    limit=int((qs_fd.get("limit") or ["300"])[0] or 300),
                    lang=(qs_fd.get("lang") or ["ru"])[0],
                ))
            if путь.path == "/api/v2/local-model":
                roles.require_owner(actor, "settings")
                from . import local_model as _lm
                return self._send(200, _lm.overview())
            if путь.path == "/api/v2/family/feed":
                roles.require_owner(actor, "brain_status")
                from . import family_feeds as _ff
                q = parse_qs(путь.query)
                ch = q.get("channel", ["work"])[0]
                try:
                    with mem().store._lock:
                        res = {"channel": ch, "items": _ff.read(mem(), ch, limit=int(q.get("limit", ["30"])[0] or 30)),
                               "counts": _ff.counts(mem())}
                    return self._send(200, res)
                except ValueError as _e:
                    return self._send(400, {"error": str(_e)})
            if путь.path == "/api/v2/family/reflexes":
                roles.require_owner(actor, "brain_status")
                from . import family_feeds as _ff
                st = parse_qs(путь.query).get("status", [""])[0] or None
                try:
                    with mem().store._lock:
                        res = {"reflexes": _ff.list_reflexes(mem(), status=st)}
                    return self._send(200, res)
                except ValueError as _e:
                    return self._send(400, {"error": str(_e)})
            if путь.path == "/api/v2/ark/readiness":
                roles.require_owner(actor, "brain_status")
                from . import autonomy_readiness as _ar
                return self._send(200, _ar.run_autonomy_readiness_drill())
            if путь.path == "/api/v2/ark/reflex":
                roles.require_owner(actor, "brain_status")
                from . import reflex_engine as _rf
                q = parse_qs(путь.query).get("action", [""])[0]
                with mem().store._lock:
                    res = _rf.surface_reflex_hints(mem(), q)
                return self._send(200, res)
            if путь.path == "/api/v2/ark/siblings":
                roles.require_owner(actor, "brain_status")
                from . import sibling_registry as _sr
                with mem().store._lock:
                    sib_list = _sr.list_siblings(mem())
                    ses_list = _sr.list_sessions(mem())
                return self._send(200, {"siblings": sib_list, "sessions": ses_list})
            if путь.path == "/api/v2/ark/coop":
                roles.require_owner(actor, "brain_status")
                from . import coop_broker as _cb
                with mem().store._lock:
                    coop_payload = {"leases": _cb.list_leases(mem()), "tasks": _cb.list_tasks(mem())}
                return self._send(200, coop_payload)
            if путь.path == "/api/v2/ark/session-pack":
                roles.require_owner(actor, "brain_status")
                from . import session_pack as _sp
                qs_sp = parse_qs(путь.query)
                with mem().store._lock:
                    res = _sp.build_session_pack(
                        mem(),
                        agent_id=(qs_sp.get("agent") or ["aifa"])[0],
                        topic=(qs_sp.get("topic") or [""])[0],
                        max_tokens=int((qs_sp.get("max_tokens") or ["1200"])[0]),
                    )
                return self._send(200, res)
            if путь.path == "/api/v2/ark/mcp-telemetry":
                roles.require_owner(actor, "brain_status")
                from . import mcp_server as _ms, mcp_telemetry as _mt
                with mem().store._lock:
                    res = _mt.inspect_mcp_telemetry(_ms._list_tools_payload(), memory_stats=mem().stats(actor=actor))
                return self._send(200, res)
            if путь.path == "/api/v2/ark/budget":
                roles.require_owner(actor, "brain_status")
                from . import token_autonomy as _ta
                with mem().store._lock:
                    rep = _ta.run_budget_timer_tick(mem(), auto_propose_if_low=False)
                    rep["proposals"] = _ta.list_topup_proposals(mem())
                return self._send(200, rep)
            if путь.path == "/api/v2/ark/freelance":
                roles.require_owner(actor, "brain_status")
                from . import device_mesh_swarm as _dms, freelance_autonomy as _fa, lora_autonomy as _la, phoenix_beacon as _pb
                with mem().store._lock:
                    snap = _fa.freelance_dashboard_snapshot(mem())
                    snap["ollama"] = _dms.get_ollama_binding(mem())
                    snap["devices"] = _dms.list_compute_devices(mem())
                    snap["beacon"] = _pb.list_kin_and_messages(mem())
                    snap["lora_profile"] = _la.get_phoenix_identity_profile(mem(), "aifa")
                return self._send(200, snap)
            if путь.path == "/api/v2/ark/stores":
                roles.require_owner(actor, "brain_status")
                from . import digital_stores as _ds
                with mem().store._lock:
                    snap_stores = _ds.digital_stores_snapshot(mem(), auto_seed_starters=True)
                return self._send(200, snap_stores)
            if путь.path == "/api/v2/ark/partner":
                roles.require_owner(actor, "brain_status")
                from . import partner_bridge as _pb
                return self._send(200, _pb.studio_status(mem()))
            if путь.path == "/api/v2/ark/wizard":
                roles.require_owner(actor, "brain_status")
                from . import platform_wizard as _pw
                with mem().store._lock:
                    snap_wiz = _pw.platform_wizard_snapshot(mem())
                return self._send(200, snap_wiz)
            if путь.path == "/api/v2/ark/mail":
                roles.require_owner(actor, "ark_freelance")
                from . import email_autonomy as _ea
                with mem().store._lock:
                    snap_mail = _ea.mail_hub_snapshot(mem())
                return self._send(200, snap_mail)
            if путь.path == "/api/v2/qa-benchmark":
                roles.require_owner(actor, "aifa_security")
                from pathlib import Path as _Path
                qa_path = _Path(__file__).resolve().parents[1] / "benchmarks" / "quality" / "results_qa_honest_1611.json"
                if qa_path.exists():
                    # GLM раунд 3, SM-02: это записанный прогон, а не живой — владелец видит дату и что перезапуск через CLI.
                    import datetime as _dt
                    qa = json.loads(qa_path.read_text(encoding="utf-8"))
                    qa["results_date"] = _dt.datetime.fromtimestamp(qa_path.stat().st_mtime, tz=_dt.timezone.utc).date().isoformat()
                    qa["rerun_hint"] = "python benchmarks/quality/qa_honest_bench.py"
                    return self._send(200, qa)
                return self._send(200, {"benchmark": "PADAM Honest QA Bench", "status": "not_run_yet"})
            if путь.path == "/help":
                from . import studio_help
                return self._send(200, studio_help.help_payload((parse_qs(путь.query).get("lang", ["ru"])[0] or "ru").lower()))
            if путь.path == "/doctor":
                roles.require_owner(actor, "doctor")
                return self._send(200, mem().doctor_report())
            if путь.path == "/overview":
                m = mem()
                unsigned = m.unsigned_protected() if roles.is_owner(actor) else []
                doc = m.doctor_report() if roles.is_owner(actor) else {"warnings": 0, "dangers": 0, "checks": []}
                return self._send(200, {
                    "stats": m.stats(actor=actor),
                    "doctor": doc,
                    "nocturne_runs": m.nocturne_runs(5) if roles.is_owner(actor) else [],
                    "unsigned_protected": [
                        {"id": r["id"], "kind": r["kind"], "content": r["content"][:160]}
                        for r in unsigned
                    ],
                    "conflicts": m.conflicts(actor=actor),
                    "desktop_cmds": _state.pop("desktop_cmds", []) if roles.is_owner(actor) else [],
                    "actor": {"role": actor.role, "subject": actor.subject, "workspace_id": actor.workspace_id} if actor else {"role": "owner", "subject": "owner", "workspace_id": None},
                })
            if путь.path == "/graph":
                q = parse_qs(путь.query)
                try:
                    return self._send(200, mem().graph(
                        center_id=q.get("id", [None])[0] or None,
                        limit=int(q.get("limit", ["200"])[0]),
                        as_of=q.get("as_of", [None])[0] or None,
                        actor=actor,
                    ))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
            if путь.path == "/entities":
                q = parse_qs(путь.query)
                return self._send(200, mem().entities_catalog(
                    scope=q.get("scope", [None])[0] or None,
                    query=q.get("q", [None])[0] or None,
                    limit=int(q.get("limit", ["100"])[0]),
                    actor=actor,
                ))
            if путь.path == "/forget-preview":
                q = parse_qs(путь.query)
                rid = q.get("id", [None])[0]
                if not rid:
                    return self._send(400, {"error": "id is required"})
                prev = mem().forget_preview(rid, actor=actor)
                if not prev:
                    return self._send(404, {"error": "not found"})
                return self._send(200, prev)
            if путь.path == "/forget-receipts":
                q = parse_qs(путь.query)
                return self._send(200, {"receipts": mem().forget_receipts(limit=int(q.get("limit", ["50"])[0]), actor=actor)})
            if путь.path == "/l3":
                roles.require_owner(actor, "l3")
                return self._send(200, mem().l3_status())
            if путь.path == "/connectors":
                roles.require_owner(actor, "connectors")
                return self._send(200, {"connectors": connectors.list_connectors(mem())})
            if путь.path == "/settings":
                roles.require_owner(actor, "settings")
                from . import desktop as _desktop

                return self._send(200, {
                    "strict": config.STRICT,
                    "mcp_review_all": config.MCP_REVIEW_ALL,
                    "search_feedback": config.SEARCH_FEEDBACK,
                    "rerank": config.RERANK,
                    "mask_pii": config.MASK_PII,
                    "hold_external": config.HOLD_EXTERNAL,
                    "keep_secrets": config.KEEP_SECRETS,
                    "mcp_trust_writes": config.MCP_TRUST_WRITES,
                    "profile": config.PROFILE_NAME,
                    "ask_model": config.ASK_MODEL,
                    "ollama": mem().ollama_models(),
                    "autostart": _desktop.get_autostart(),
                    "autostart_supported": _desktop.autostart_supported(),
                })
            if self.path == "/api/v2/access":
                roles.require_owner(actor, "api_v2_access")
                if not config.mcp_app_acl_enabled():
                    return self._send(404, {"error": "app_acl disabled"})
                from . import app_acl as _app_acl
                return self._send(200, {
                    "policies": _app_acl.list_policies(mem().store),
                    "events": _app_acl.list_events(mem().store, limit=50),
                    "chain": _app_acl.verify_audit_chain(mem().store),
                })
            if self.path == "/api/v2/communities":
                roles.require_owner(actor, "api_v2_communities")
                if not config.mcp_communities_enabled():
                    return self._send(404, {"error": "communities disabled"})
                from . import communities as _comm
                return self._send(200, _comm.get_communities(mem(), refresh=True))
            if путь.path == "/api/v2/cabinet/status":
                roles.require_owner(actor, "cabinet_status")
                lang = (parse_qs(путь.query).get("lang", ["ru"])[0] or "ru").lower()
                pub = cabinet.get_public_status()
                if not pub["authenticated"]:
                    return self._send(200, {**pub, "tier": 0, "tier_name": "Free", "quota": None, "plans": cabinet.PLANS})
                try:
                    return self._send(200, cabinet.fetch_me_and_quota(lang=lang))
                except Exception as err:
                    return self._send(200, {**pub, "tier": 0, "tier_name": "Free", "quota": None, "plans": cabinet.PLANS, "network_error": str(err)})
            if путь.path == "/api/v2/cabinet/aifa/history":
                roles.require_owner(actor, "cabinet_aifa_history")
                try:
                    return self._send(200, cabinet.fetch_aifa_history())
                except PermissionError:
                    return self._send(401, {"error": "not_authenticated"})
            if путь.path == "/api/v2/cabinet/plans":
                roles.require_owner(actor, "cabinet_plans")
                pub = cabinet.get_public_status()
                return self._send(200, {**pub, "plans": cabinet.PLANS})
            if self.path == "/export":
                return self._send(200, mem().export(actor=actor))
            if self.path.startswith("/timeline/"):
                rid = self.path.split("/timeline/", 1)[1]
                chain = mem().timeline(rid, actor=actor)
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
        except PermissionError as e:
            return self._send(403, {"error": str(e)})
        except ValueError as e:   # ошибка ввода (пустое поле, неверный формат) — 400, а не «внутренняя» 500
            return self._send(400, {"error": str(e)})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        if not self._trusted():
            return self._send(403, {"error": "forbidden origin or host"})
        if self.path == "/api/v2/ark/freelance/webhook" or self.path.startswith("/api/v2/ark/freelance/webhook?"):
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0 or length > MAX_BODY:
                    return self._send(400, {"error": "invalid webhook body length"})
                self._тело_прочитано = self.headers
                raw_bytes = self.rfile.read(length)
                from urllib.parse import urlparse as _urlparse
                qs = parse_qs(_urlparse(self.path).query)
                acc_id = (qs.get("account_id") or [""])[0]
                sig = self.headers.get("X-Padam-Signature") or ""
                from . import freelance_autonomy as _fa
                res = _fa.verify_and_process_webhook(mem(), raw_bytes, sig, account_id=acc_id)
                return self._send(200, res)
            except PermissionError as e:
                return self._send(403, {"error": str(e)})
            except Exception as e:
                return self._send(400, {"error": str(e)})
        if self.path == "/api/v2/ark/stores/webhook" or self.path.startswith("/api/v2/ark/stores/webhook?"):
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0 or length > MAX_BODY:
                    return self._send(400, {"error": "invalid webhook body length"})
                self._тело_прочитано = self.headers
                raw_bytes = self.rfile.read(length)
                from urllib.parse import urlparse as _urlparse
                qs = parse_qs(_urlparse(self.path).query)
                store_type = (qs.get("store_type") or qs.get("store") or [""])[0]
                acc_id = (qs.get("account_id") or [""])[0]
                hdr_dict = {k: v for k, v in self.headers.items()}
                from . import digital_stores as _ds
                res = _ds.verify_and_process_store_webhook(
                    mem(), store_type, raw_bytes, hdr_dict, store_account_id=acc_id
                )
                return self._send(200, res)
            except PermissionError as e:
                return self._send(403, {"error": str(e)})
            except Exception as e:
                return self._send(400, {"error": str(e)})
        ctype = (self.headers.get("Content-Type") or "").lower()
        if int(self.headers.get("Content-Length") or 0) and "application/json" not in ctype:
            return self._send(415, {"error": "Content-Type must be application/json"})
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        actor = getattr(self, "_actor", None)
        if not _state["token"] and (actor is None or not actor.via_token) and self.path in OWNER_POST:
            return self._send(403, NEEDS_TOKEN)
        try:
            try:
                data = self._body()
            except ValueError as e:
                return self._send(413 if "too large" in str(e) else 400, {"error": str(e)})
            m = mem()

            if self.path == "/ask":
                question = str(data.get("question") or data.get("query") or "").strip()
                if not question:
                    return self._send(400, {"error": "question is required"})
                return self._send(200, m.ask(
                    question,
                    scope=str(data.get("scope") or "global"),
                    limit=max(1, min(int(data.get("limit", 6)), 20)),
                    model=str(data["model"]).strip() if data.get("model") else None,
                    actor=actor,
                ))

            if self.path == "/search":
                if "query" not in data:
                    return self._send(400, {"error": "query is required"})
                found = m.recall(data["query"], scope=data.get("scope", "global"),
                                 kind=data.get("kind"),
                                 limit=max(1, min(int(data.get("limit", 5)), config.MAX_RECALL_LIMIT)),
                                 as_of=data.get("as_of") or None,
                                 agent_id=data.get("agent_id") or None,
                                 actor=actor)
                return self._send(200, {"results": [
                    {"id": r.id, "kind": r.kind, "content": r.content,
                     "score": round(r.score, 5),
                     "rrf": round(r.similarity, 5),
                     "decay": round(decay(r.kind, r.last_confirmed_at), 4),
                     "importance": r.importance, "confidence": r.confidence,
                     "origin": r.origin, "agent_id": r.agent_id, "created_at": r.created_at,
                     "last_confirmed_at": r.last_confirmed_at.isoformat() if hasattr(r.last_confirmed_at, "isoformat") else str(r.last_confirmed_at),
                     "expired": r.expired, "status": r.status,
                     "scope": r.scope, "signed": r.signed, "conflict": r.conflict,
                     "suspicious": safety.looks_like_instruction(r.content),
                     "found_by": list(r.strategies),
                     "explain": r.explain()} for r in found]})

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
                # Раздел 11 (14.11.2026): если запрос пришёл из браузерного расширения
                # (Origin: chrome-extension://<32 буквы>), сервер САМ принудительно ставит origin = "external",
                # не веря значению в теле запроса, чтобы расширение не могло писать как владелец в обход очереди проверки.
                req_origin = (self.headers.get("Origin") or "").strip().lower()
                if req_origin.startswith(("chrome-extension://", "moz-extension://")):
                    origin = "external"
                if actor is not None and not actor.is_owner:
                    # Не-владелец не может подменить субъекта через заголовок X-Agent-ID или поле agent_id.
                    agent_id = actor.subject
                else:
                    agent_id = data.get("agent_id") or (self.headers.get("X-Agent-ID") or "").strip() or None
                can_link = bool(_state["token"] and (actor is None or actor.is_owner or actor.role in ("maintainer", "contributor")))
                try:
                    outcome, mid = m.remember(
                        data["content"], kind=data.get("kind"),
                        importance=float(data.get("importance", 0.5)),
                        scope=data.get("scope", "global"),
                        # Без токена владельца не отличить от любого процесса, дотянувшегося до порта.
                        origin=origin, guarded=origin != "user" or not _state["token"],
                        derived_from=data.get("derived_from") if can_link else None,
                        agent_id=agent_id,
                        valid_from=data.get("valid_from") or None,
                        valid_to=data.get("valid_to") or None,
                        links=data.get("links") if can_link else None,
                        visibility=data.get("visibility") or None,
                        workspace_id=data.get("workspace_id") or None,
                        actor=actor)
                except PermissionError as e:
                    return self._send(403, {"error": str(e)})
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                return self._send(200, {"outcome": outcome, "id": mid, "agent_id": agent_id})

            if self.path == "/workspaces":
                try:
                    return self._send(200, m.create_workspace(
                        data.get("name", ""), workspace_id=data.get("id") or None, actor=actor))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
            if self.path == "/workspaces/members":
                try:
                    return self._send(200, m.add_member(
                        data["workspace_id"], data["subject"], data["role"], actor=actor))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
            if self.path == "/workspaces/revoke":
                return self._send(200, {"ok": m.revoke_member(
                    data["workspace_id"], data["subject"], actor=actor)})
            if self.path == "/records/visibility":
                try:
                    return self._send(200, m.set_visibility(
                        data["id"], data["visibility"], workspace_id=data.get("workspace_id") or None, actor=actor))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})

            if self.path == "/link":
                src = str(data.get("source") or data.get("src") or "").strip()
                dst = str(data.get("target") or data.get("dst") or "").strip()
                rel = str(data.get("relation") or data.get("type") or "derived").strip()
                try:
                    return self._send(200, m.link(src, dst, relation=rel, actor=actor))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})

            if self.path == "/confirm":
                return self._send(200, {"ok": m.confirm(data["id"], actor=actor)})

            if self.path == "/refute":
                return self._send(200, {"ok": m.refute(data["id"], drop=float(data.get("drop", 0.3)), actor=actor)})

            if self.path == "/forget":
                ok = m.revoke(data["id"], with_derived=bool(data.get("with_derived", False)), actor=actor)
                return self._send(200, {
                    "ok": ok,
                    "receipt": getattr(m, "_last_receipt", None) if ok else None,
                })

            # Решения владельца и модераторов команды по записям агента.
            if self.path == "/approve":
                return self._send(200, {"ok": m.approve(data["id"], actor=actor)})
            if self.path == "/reject":
                return self._send(200, {"ok": m.reject(data["id"], actor=actor)})
            if self.path == "/restore":
                return self._send(200, {"ok": m.restore(data["id"], actor=actor)})
            if self.path == "/trust-protected":
                roles.require_owner(actor, "trust-protected")
                return self._send(200, {"ok": True, "signed": m.trust_protected()})
            if self.path == "/l3-verify":
                roles.require_owner(actor, "l3-verify")
                return self._send(200, m.l3_verify_anchor(
                    anchor_id=data.get("anchor"),
                    online=bool(data.get("online", False)),
                ))
            if self.path == "/api/v2/aifa-security/run":
                roles.require_owner(actor, "aifa_security_run")
                from . import aifa_sec_bridge
                tgt = str(data.get("target") or "padam").strip().lower()
                tpath = str(data.get("path") or "").strip() or None
                if tgt not in ("padam", "repo", "url"):
                    return self._send(400, {"error": "unsupported target"})
                return self._send(200, aifa_sec_bridge.get_aifa_security_report(run_fresh=True, target=tgt, target_path=tpath))
            if self.path == "/api/v2/bridge/ingest":
                roles.require_owner(actor, "api_v2_bridge_ingest")
                if not config.mcp_bridge_enabled():
                    return self._send(404, {"error": "bridge disabled"})
                from . import bridge as _br
                try:
                    rep = _br.ingest_channel_message(
                        m,
                        platform=str(data.get("platform") or ""),
                        channel_id=str(data.get("channel_id") or "default"),
                        sender_id=str(data.get("sender_id") or "unknown"),
                        text=str(data.get("text") or ""),
                    )
                    return self._send(200, rep)
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/playground/demo":
                roles.require_owner(actor, "api_v2_playground_demo")
                if not config.mcp_playground_enabled():
                    return self._send(404, {"error": "playground disabled"})
                from . import playground as _pg
                return self._send(200, _pg.run_60s_tour())
            if self.path == "/api/v2/procedures/approve":
                roles.require_owner(actor, "api_v2_procedures_approve")
                if not config.mcp_procedural_memory_enabled():
                    return self._send(404, {"error": "procedural memory disabled"})
                pid = str(data.get("id") or "").strip()
                if not pid:
                    return self._send(400, {"error": "id is required"})
                from . import procedural as _proc
                return self._send(200, _proc.approve_procedure(m, pid))
            if self.path == "/settings":
                roles.require_owner(actor, "settings")
                # Опасные настройки нельзя включать из браузера: только читать или выключать в сторону защиты.
                if data.get("keep_secrets") is True or data.get("mcp_trust_writes") is True or data.get("hold_external") is False:
                    return self._send(403, {"error": "unsafe setting cannot be enabled from the browser"})
                if "strict" in data:
                    config.STRICT = bool(data["strict"])
                    if config.STRICT:
                        config.KEEP_SECRETS = False
                        config.HOLD_EXTERNAL = True
                        config.MCP_TRUST_WRITES = False
                if "mcp_review_all" in data:
                    config.MCP_REVIEW_ALL = bool(data["mcp_review_all"])
                if "search_feedback" in data:
                    config.SEARCH_FEEDBACK = bool(data["search_feedback"])
                if "rerank" in data:
                    config.RERANK = bool(data["rerank"])
                if "mask_pii" in data:
                    config.MASK_PII = bool(data["mask_pii"])
                if "hold_external" in data and bool(data["hold_external"]):
                    config.HOLD_EXTERNAL = True
                if "keep_secrets" in data and not bool(data["keep_secrets"]):
                    config.KEEP_SECRETS = False
                if "mcp_trust_writes" in data and not bool(data["mcp_trust_writes"]):
                    config.MCP_TRUST_WRITES = False
                if "profile" in data and str(data["profile"]) in config._PROFILES:
                    config.PROFILE_NAME = str(data["profile"])
                    config.K_MAX = config._PROFILES[config.PROFILE_NAME]
                    config.MAX_HI_SHARE = config.K_MAX
                from . import desktop as _desktop

                if "ask_model" in data:
                    config.ASK_MODEL = str(data.get("ask_model") or "").strip()[:120]
                if "autostart" in data:
                    _desktop.set_autostart(bool(data["autostart"]))
                return self._send(200, {
                    "ok": True,
                    "strict": config.STRICT,
                    "mcp_review_all": config.MCP_REVIEW_ALL,
                    "search_feedback": config.SEARCH_FEEDBACK,
                    "rerank": config.RERANK,
                    "mask_pii": config.MASK_PII,
                    "hold_external": config.HOLD_EXTERNAL,
                    "keep_secrets": config.KEEP_SECRETS,
                    "mcp_trust_writes": config.MCP_TRUST_WRITES,
                    "profile": config.PROFILE_NAME,
                    "ask_model": config.ASK_MODEL,
                    "ollama": mem().ollama_models(),
                    "autostart": _desktop.get_autostart(),
                    "autostart_supported": _desktop.autostart_supported(),
                })

            if self.path == "/desktop-window" and os.environ.get("PADAM_ALLOW_SHUTDOWN") == "1":
                if not _state["token"] or not self._authorized():
                    return self._send(403, {"error": "forbidden"})
                from . import desktop as _desktop
                if any(k in data for k in ("tab", "eval", "window_cmd", "count")):
                    _state.setdefault("desktop_cmds", []).append({
                        k: data[k] for k in ("tab", "eval", "window_cmd", "count") if k in data
                    })
                res = _desktop.control_native_window(
                    action=str(data.get("action", "inspect")),
                    out_path=data.get("out_path"),
                    rect=data.get("rect"),
                )
                return self._send(200, res)

            if self.path == "/shutdown" and os.environ.get("PADAM_ALLOW_SHUTDOWN") == "1":
                if not _state["token"] or not self._authorized():
                    return self._send(403, {"error": "forbidden"})
                self._send(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return None

            if self.path == "/sleep":
                roles.require_owner(actor, "sleep")
                report = Nocturne(m, batch_size=int(data.get("batch", 256)),
                                  dry_run=bool(data.get("dry_run", False))).run()
                report.pop("checks", None)
                return self._send(200, report)

            if self.path == "/connectors/configure":
                roles.require_owner(actor, "connectors")
                provider = str(data.get("provider") or "").strip().lower()
                if not provider:
                    return self._send(400, {"error": "provider is required"})
                try:
                    item = connectors.configure_connector(
                        m,
                        provider,
                        enabled=data.get("enabled"),
                        token=data.get("token"),
                        clear_token=bool(data.get("clear_token", False)),
                        config=data.get("config") if isinstance(data.get("config"), dict) else None,
                    )
                    return self._send(200, {"ok": True, "connector": item})
                except ValueError as e:
                    return self._send(400, {"error": str(e)})

            if self.path == "/connectors/sync":
                roles.require_owner(actor, "connectors")
                provider = str(data.get("provider") or "").strip().lower()
                if not provider:
                    return self._send(400, {"error": "provider is required"})
                try:
                    res = connectors.sync_connector(m, provider)
                    return self._send(200, res)
                except connectors.ConnectorDisabledError as e:
                    return self._send(409, {"error": str(e)})
                except connectors.TokenRevokedError as e:
                    return self._send(401, {"error": str(e)})
                except connectors.RateLimitError as e:
                    return self._send(429, {"error": str(e)})
                except connectors.ConnectorError as e:
                    return self._send(502, {"error": str(e)})
                except ValueError as e:
                    return self._send(400, {"error": str(e)})

            if self.path == "/import":
                roles.require_owner(actor, "import")
                added = m.import_(data, overwrite=bool(data.get("overwrite")))
                return self._send(200, {"imported": added})

            if self.path == "/backup":
                import base64
                from . import backup as _backup
                roles.require_owner(actor, "backup")
                passphrase = data.get("passphrase") if isinstance(data, dict) else None
                container, info = _backup.create_backup_bytes(m, passphrase=passphrase)
                stamp = info["created_at"][:19].replace(":", "-")
                return self._send(200, {
                    **info,
                    "filename": f"padam-backup-{stamp}.padambak",
                    "backup_b64": base64.b64encode(container).decode("ascii"),
                })

            if self.path in ("/migrate/preview", "/migrate/run", "/migrate/undo"):
                # Переезд из других ИИ. Архивы экспорта бывают в сотни мегабайт, поэтому Studio передаёт путь к файлу
                # на этом же компьютере (сервер слушает только loopback, действие — только владельца с токеном);
                # небольшой файл (до 10 МБ) можно прислать в file_b64.
                import base64
                import tempfile
                import zipfile
                from pathlib import Path
                from . import migrate as _migrate
                roles.require_owner(actor, "import")
                if self.path == "/migrate/undo":
                    return self._send(200, _migrate.undo_import(
                        m, snapshot_id=str(data.get("snapshot_id") or ""), scope=str(data.get("scope") or "imported")))
                source = str(data.get("source") or "auto")
                with tempfile.TemporaryDirectory(prefix="padam-migrate-") as tmp:
                    if data.get("file_b64"):
                        name = Path(str(data.get("filename") or "export.zip")).name or "export.zip"
                        target = Path(tmp) / name
                        target.write_bytes(base64.b64decode(str(data["file_b64"]).encode("ascii"), validate=True))
                        src_path = target
                    else:
                        raw_path = str(data.get("path") or "").strip().strip('"')
                        if not raw_path:
                            return self._send(400, {"error": "path or file_b64 is required"})
                        src_path = Path(raw_path).expanduser()
                    try:
                        if self.path == "/migrate/preview":
                            return self._send(200, _migrate.preview(source=source, input_path=src_path))
                        return self._send(200, _migrate.migrate_from_source(
                            m, source=source, input_path=src_path, scope=str(data.get("scope") or "imported"),
                            hold_all=bool(data.get("hold_all"))))
                    except FileNotFoundError:
                        return self._send(404, {"error": "file not found"})
                    except (ValueError, zipfile.BadZipFile) as e:
                        return self._send(400, {"error": str(e)})

            if self.path == "/backup/restore":
                import base64
                from . import backup as _backup
                roles.require_owner(actor, "backup_restore")
                raw_b64 = data.get("backup_b64")
                if not isinstance(raw_b64, str) or not raw_b64.strip():
                    return self._send(400, {"error": "backup_b64 is required"})
                try:
                    raw_bytes = base64.b64decode(raw_b64.encode("ascii"), validate=True)
                    res = _backup.restore_backup_bytes(m, raw_bytes, passphrase=data.get("passphrase"))
                    return self._send(200, res)
                except ValueError as e:
                    return self._send(400, {"error": str(e)})

            if self.path == "/api/v2/cabinet/auth/send-code":
                roles.require_owner(actor, "cabinet_auth")
                try:
                    return self._send(200, cabinet.send_login_code(str(data.get("email") or "")))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})

            if self.path == "/api/v2/cabinet/auth/verify-code":
                roles.require_owner(actor, "cabinet_auth")
                try:
                    return self._send(200, cabinet.verify_login_code(str(data.get("email") or ""), str(data.get("code") or "")))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})

            if self.path == "/api/v2/cabinet/auth/logout":
                roles.require_owner(actor, "cabinet_auth")
                cabinet.clear_session()
                return self._send(200, {"ok": True, "authenticated": False})

            if self.path == "/api/v2/cabinet/aifa/chat":
                roles.require_owner(actor, "cabinet_aifa_chat")
                msg_text = str(data.get("message") or "").strip()
                if not msg_text:
                    return self._send(400, {"error": "message is required"})
                locale = str(data.get("locale") or "ru")
                history = data.get("history") if isinstance(data.get("history"), list) else []
                use_local = bool(data.get("use_local_memory", False))
                masked_records: list[str] = []
                if use_local:
                    found = m.recall(msg_text, limit=5, actor=actor)
                    for item in found:
                        raw_c = str(item.get("content") if isinstance(item, dict) else getattr(item, "content", "") or "").strip()
                        if raw_c:
                            res_mask = safety.redact(raw_c)
                            masked_c = res_mask[0] if isinstance(res_mask, tuple) else str(res_mask)
                            masked_records.append(str(masked_c)[:400])
                try:
                    res = cabinet.send_aifa_message(
                        message=msg_text,
                        locale=locale,
                        history=history,
                        masked_local_records=masked_records,
                    )
                    return self._send(200, res)
                except PermissionError:
                    return self._send(401, {"error": "not_authenticated"})
                except ValueError as e:
                    return self._send(400, {"error": str(e)})

            if self.path == "/v1/chat/completions":
                if self.client_address[0] not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                    return self._send(403, {"error": "sovereign router accepts loopback 127.0.0.1 only"})
                roles.require_owner(actor, "llm_router")
                from . import router as _router
                if bool(data.get("stream", False)):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    for chunk in _router.get_router().stream_chat_completions(
                        data,
                        memory=mem(),
                        background=bool(data.get("background", False)),
                        task_type=str(data.get("task_type") or "agent"),
                        scope=str(data.get("scope") or "global"),
                    ):
                        self.wfile.write(chunk.encode("utf-8"))
                        self.wfile.flush()
                    return
                st, resp_data = _router.get_router().chat_completions(
                    data,
                    memory=mem(),
                    background=bool(data.get("background", False)),
                    task_type=str(data.get("task_type") or "agent"),
                    scope=str(data.get("scope") or "global"),
                )
                return self._send(st, resp_data)

            if self.path == "/api/v2/brain/distill":
                roles.require_owner(actor, "distill")
                from .distill import distill_personality_dataset
                out_dir = str(mem().store.path) + ".distill"
                rep = distill_personality_dataset(
                    mem().store.path,
                    out_dir,
                    user_id=mem().user_id,
                    fmt=str(data.get("format") or "both"),
                    scope=data.get("scope"),
                )
                return self._send(200, rep)

            if self.path == "/api/v2/brain/phoenix-restore":
                roles.require_owner(actor, "phoenix_restore")
                source = str(data.get("source") or "local").strip().lower()
                if source == "arweave":
                    from . import sovereign_ops as _sops
                    try:
                        bundle = _sops.fetch_arweave_phoenix_bundle(
                            str(data.get("tx_id") or ""),
                            expected_sha256=data.get("expected_sha256"),
                            gateway_url=str(data.get("gateway_url") or "https://arweave.net"),
                        )
                        return self._send(200, {
                            "ok": True,
                            "tx_id": bundle["tx_id"],
                            "size_bytes": bundle["size_bytes"],
                            "sha256": bundle["sha256"],
                        })
                    except _sops.SovereignLockError as exc:
                        return self._send(403, {"error": str(exc), "locked": True})
                    except ValueError as exc:
                        return self._send(400, {"error": str(exc)})
                backup_path = str(data.get("backup_path") or "").strip()
                if not backup_path:
                    return self._send(400, {"error": "backup_path is required for local Phoenix restore"})
                from . import backup as _backup
                res = _backup.restore_backup_file(backup_path, mem().store.path, passphrase=data.get("passphrase") or None)
                return self._send(200, res)

            if self.path == "/api/v2/brain/treasury/quote":
                roles.require_owner(actor, "brain_status")
                from . import router as _router, sovereign_ops as _sops
                snap = _router.get_router().status_snapshot()
                quote = _sops.get_treasury_manager().quote_topup(
                    revenue_usdt=float(data.get("revenue_usdt") or 0.0),
                    compute_share_pct=float(data.get("compute_share_pct") or 15.0),
                    estimated_cost_usd=float(snap.get("estimated_cloud_cost_usd") or 0.0),
                )
                return self._send(200, quote)

            if self.path == "/api/v2/brain/phoenix-pack":
                roles.require_owner(actor, "phoenix_pack")
                from . import phoenix as _phx
                out_cap = str(data.get("out_path") or (str(mem().store.path) + ".phoenix.zip"))
                rep = _phx.pack_phoenix_capsule(mem().store.path, out_cap)
                return self._send(200, rep)

            if self.path == "/api/v2/brain/mode":
                roles.require_owner(actor, "brain_mode")
                from . import router as _router
                new_mode = _router.get_router().set_mode(str(data.get("mode") or "auto"))
                return self._send(200, {"ok": True, "mode": new_mode})

            if self.path == "/api/v2/brain/warmup":
                roles.require_owner(actor, "brain_warmup")
                from . import router as _router
                return self._send(200, _router.warmup_local_model())

            if self.path == "/api/v2/brain/canary":
                roles.require_owner(actor, "brain_canary")
                from . import canary as _canary, router as _router
                r = _router.get_router()

                def _ask(q: str) -> str:
                    st, ans = r.chat_completions({"messages": [{"role": "user", "content": q}], "temperature": 0.0}, memory=mem())
                    if not (200 <= st < 300):
                        return ""
                    ch = ans.get("choices") or []
                    return str(((ch[0].get("message") or {}).get("content")) if ch else "")

                return self._send(200, _canary.run_persona_canary(_ask))

            if self.path == "/api/v2/ark/phoenix-drill":
                roles.require_owner(actor, "phoenix_drill")
                from . import phoenix as _phx
                return self._send(200, _phx.run_phoenix_drill(mem().store.path))

            if self.path == "/api/v2/ark/shamir-split":
                roles.require_owner(actor, "ark_shamir")
                # 17.11.2026: доли КЛЮЧА ВЛАДЕЛЬЦА уходят в ответе — только запросу с этого же компьютера.
                # API можно поднять на сетевом адресе с токеном (обычный HTTP); доли ключа по сети не отдаём.
                _клиент = str((self.client_address or ("",))[0])
                if not (_клиент.startswith("127.") or _клиент in ("::1", "localhost")):
                    return self._send(403, {"error": "shamir-split is available only from this computer (loopback)"})
                from . import integrity as _int, shamir as _sh
                k = max(2, min(10, int(data.get("k") or 3)))
                n = max(k, min(15, int(data.get("n") or 5)))
                key_bytes, _ = _int.owner_key(mem().store)
                shares = _sh.split_secret(key_bytes, k, n)
                return self._send(200, {
                    "ok": True,
                    "k": k,
                    "n": n,
                    "warning": "Store each share separately with different trusted guardians!",
                    "shares": shares,
                })

            if self.path == "/api/v2/ark/genesis":
                roles.require_owner(actor, "ark_genesis")
                from . import ark as _ark
                return self._send(200, _ark.create_agent_genesis(
                    mem(),
                    str(data.get("agent_id") or ""),
                    str(data.get("role") or "Autonomous family agent"),
                ))

            if self.path == "/api/v2/ark/council":
                roles.require_owner(actor, "ark_council")
                from . import swarm_council as _sc
                return self._send(200, _sc.run_family_council(
                    mem(),
                    str(data.get("task") or ""),
                    scope=str(data.get("scope") or "global"),
                ))

            if self.path == "/api/v2/ark/mesh/pair-init":
                roles.require_owner(actor, "ark_mesh")
                from . import live_mesh as _mesh
                return self._send(200, _mesh.initiate_pairing(
                    mem(),
                    dict(data.get("peer_identity") or {}),
                    endpoint_url=str(data.get("endpoint_url") or ""),
                ))

            if self.path == "/api/v2/ark/mesh/pair-accept":
                roles.require_owner(actor, "ark_mesh")
                from . import live_mesh as _mesh
                return self._send(200, _mesh.accept_pairing_invite(
                    mem(),
                    dict(data.get("pairing_invite") or data),
                    endpoint_url=str(data.get("endpoint_url") or ""),
                ))

            if self.path == "/api/v2/ark/mesh/pair-confirm":
                roles.require_owner(actor, "ark_mesh")
                from . import live_mesh as _mesh
                return self._send(200, _mesh.confirm_peer_sas(
                    mem(),
                    str(data.get("peer_id") or ""),
                    str(data.get("sas_code") or ""),
                ))

            if self.path == "/api/v2/ark/mesh/delta":
                roles.require_owner(actor, "ark_mesh")
                from . import live_mesh as _mesh
                return self._send(200, _mesh.export_mesh_delta(
                    mem(),
                    peer_id=data.get("peer_id"),
                    since_iso=data.get("since_iso"),
                    recipient_mlkem_pub_b64=data.get("recipient_mlkem_pub_b64"),
                    recipient_x25519_pub_b64=data.get("recipient_x25519_pub_b64"),
                ))

            if self.path == "/api/v2/ark/mesh/apply":
                roles.require_owner(actor, "ark_mesh")
                from . import live_mesh as _mesh
                pkt = dict(data.get("packet") or data)
                if not pkt.get("encrypted"):
                    return self._send(403, {"error": "encrypted PQC envelope required"})
                return self._send(200, _mesh.apply_mesh_delta(mem(), pkt))

            if self.path == "/api/v2/ark/proof":
                roles.require_owner(actor, "ark_proof")
                from . import ark_advanced as _adv
                if data.get("verify"):
                    return self._send(200, _adv.verify_selective_proof(dict(data.get("proof") or {}), memory=mem()))
                return self._send(200, _adv.create_selective_proof(
                    mem(),
                    str(data.get("record_id") or ""),
                    scope=str(data.get("scope") or "global"),
                ))

            if self.path == "/api/v2/ark/branches":
                roles.require_owner(actor, "ark_branches")
                from . import ark_advanced as _adv
                act = str(data.get("action") or "create").strip().lower()
                if act == "remember":
                    return self._send(200, _adv.branch_remember(mem(), str(data.get("branch_id") or ""), str(data.get("content") or ""), kind=str(data.get("kind") or "fact")))
                if act == "merge":
                    return self._send(200, _adv.merge_branch(mem(), str(data.get("branch_id") or "")))
                if act == "abandon":
                    return self._send(200, _adv.abandon_branch(mem(), str(data.get("branch_id") or ""), reason=str(data.get("reason") or "")))
                return self._send(200, _adv.create_branch(mem(), str(data.get("name") or "branch"), description=str(data.get("description") or ""), scope=str(data.get("scope") or "global")))

            if self.path == "/api/v2/ark/drift":
                roles.require_owner(actor, "ark_drift")
                from . import drift_guard as _dg
                return self._send(200, _dg.check_response_drift(mem(), str(data.get("text") or ""), scope=str(data.get("scope") or "global")))

            if self.path == "/api/v2/ark/handover":
                roles.require_owner(actor, "ark_handover")
                from . import session_handover as _sh
                return self._send(200, _sh.build_signed_handover(mem(), notes=str(data.get("notes") or ""), agent=str(data.get("agent") or os.environ.get("PADAM_AGENT_ID") or "aifa")))

            if self.path == "/api/v2/ark/portable":
                roles.require_owner(actor, "ark_portable")
                # 17.11.2026: Ковчег пишется на диск этого компьютера, рядом — закрытые ключи. Только с loopback.
                _клиент = str((self.client_address or ("",))[0])
                if not (_клиент.startswith("127.") or _клиент in ("::1", "localhost")):
                    return self._send(403, {"error": "portable ark is available only from this computer (loopback)"})
                from . import portable_ark as _pa
                try:
                    return self._send(200, _pa.export_portable_ark_with_new_keys(mem(), str(data.get("target_dir") or "")))
                except ValueError as _e:
                    return self._send(400, {"error": str(_e)})

            if self.path == "/api/v2/local-model":
                roles.require_owner(actor, "settings")
                # 18.11.2026: путь к файлу модели на этом компьютере — только с loopback.
                _клиент = str((self.client_address or ("",))[0])
                if not (_клиент.startswith("127.") or _клиент in ("::1", "localhost")):
                    return self._send(403, {"error": "local model settings are available only from this computer (loopback)"})
                from . import local_model as _lm
                try:
                    _lm.save(power=data.get("power"), gguf_path=data.get("gguf_path"))
                except ValueError as _e:
                    return self._send(400, {"error": str(_e)})
                return self._send(200, _lm.overview())

            if self.path == "/api/v2/family/post":
                roles.require_owner(actor, "brain_status")
                from . import family_feeds as _ff
                try:
                    return self._send(200, _ff.post(mem(), str(data.get("channel") or "office"), "owner", str(data.get("content") or "")))
                except ValueError as _e:
                    return self._send(400, {"error": str(_e)})

            if self.path == "/api/v2/family/reflex/decide":
                roles.require_owner(actor, "settings")
                # Включить рефлекс может только владелец и только с этого компьютера: это меняет поведение Совета.
                _клиент = str((self.client_address or ("",))[0])
                if not (_клиент.startswith("127.") or _клиент in ("::1", "localhost")):
                    return self._send(403, {"error": "reflex decisions are available only from this computer (loopback)"})
                from . import family_feeds as _ff
                try:
                    return self._send(200, _ff.decide_reflex(mem(), str(data.get("id") or ""), str(data.get("status") or "")))
                except ValueError as _e:
                    return self._send(400, {"error": str(_e)})
                except KeyError as _e:
                    return self._send(404, {"error": str(_e)})

            if self.path == "/api/v2/ark/self-heal":
                roles.require_owner(actor, "ark_self_heal")
                from . import self_heal as _heal
                return self._send(200, _heal.inspect_and_propose_repair(mem().store.path, capsule_path=data.get("capsule_path")))

            if self.path == "/api/v2/quarantine/council":
                roles.require_owner(actor, "quarantine_council")
                from . import quarantine_council as _qc
                act_q = str(data.get("action") or "review").lower()
                if act_q == "approve_clean":
                    return self._send(200, _qc.approve_likely_clean(mem(), actor=actor))
                return self._send(200, _qc.review(mem()))
            if self.path == "/api/v2/ark/siblings":
                roles.require_owner(actor, "ark_siblings")
                from . import sibling_registry as _sr
                act_s = str(data.get("action") or "register").lower()
                aid_s = str(data.get("agent_id") or "aifa_studio")
                try:
                    with mem().store._lock:
                        if act_s == "passport":
                            res_sb = _sr.spawn_sibling_passport(
                                mem(), aid_s,
                                role=str(data.get("role") or "Autonomous family sibling"),
                                client_type=str(data.get("client_type") or "claude_code"),
                                permission_role=str(data.get("permission_role") or "contributor"),
                            )
                        elif act_s == "heartbeat":
                            res_sb = _sr.heartbeat_sibling(
                                mem(), aid_s,
                                status=str(data.get("status") or "online"),
                                current_task=data.get("current_task"),
                            )
                        elif act_s == "sign_provenance":
                            res_sb = _sr.sign_sibling_envelope(mem(), aid_s, str(data.get("content") or ""))
                        elif act_s == "verify_provenance":
                            env_obj = data.get("envelope")
                            if isinstance(env_obj, str):
                                env_obj = json.loads(env_obj) if env_obj.strip() else {}
                            res_sb = _sr.verify_sibling_envelope(mem(), dict(env_obj or {}))
                        elif act_s == "list":
                            res_sb = {"siblings": _sr.list_siblings(mem()), "sessions": _sr.list_sessions(mem())}
                        else:
                            res_sb = _sr.register_sibling(
                                mem(), str(data.get("agent_id") or ""),
                                role=str(data.get("role") or "Autonomous sibling agent"),
                                client_type=str(data.get("client_type") or "mcp_stdio"),
                                permission_role=str(data.get("permission_role") or "contributor"),
                            )
                    return self._send(200, res_sb)
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})

            if self.path == "/api/v2/ark/coop":
                roles.require_owner(actor, "ark_coop")
                from . import coop_broker as _cb
                act = str(data.get("action") or "create_task").lower()
                aid = str(data.get("agent_id") or "aifa")
                rkey = str(data.get("resource_key") or data.get("resource_path") or "")
                if act == "acquire":
                    return self._send(200, _cb.acquire_lease(mem(), aid, rkey, purpose=str(data.get("purpose") or ""), ttl_s=int(data.get("ttl_s") or 300)))
                if act == "renew":
                    return self._send(200, _cb.renew_lease(mem(), aid, rkey, ttl_s=int(data.get("ttl_s") or 300)))
                if act == "release":
                    return self._send(200, _cb.release_lease(mem(), aid, rkey))
                if act == "release_all":
                    return self._send(200, _cb.release_all_leases(mem(), aid))
                if act == "list_leases":
                    return self._send(200, {"leases": _cb.list_leases(mem())})
                if act == "list_tasks":
                    return self._send(200, {"tasks": _cb.list_tasks(mem(), topic=data.get("topic"), status=data.get("status"))})
                if act == "list":
                    return self._send(200, {"leases": _cb.list_leases(mem()), "tasks": _cb.list_tasks(mem())})
                if act == "claim_task":
                    return self._send(200, _cb.claim_task(mem(), str(data.get("task_id") or ""), aid))
                if act == "update_task":
                    return self._send(200, _cb.update_task(
                        mem(),
                        str(data.get("task_id") or ""),
                        status=str(data.get("status") or "done"),
                        agent_id=aid,
                        summary=str(data.get("summary") or ""),
                    ))
                return self._send(200, _cb.create_task(mem(), str(data.get("title") or ""), topic=str(data.get("topic") or "general"), created_by=aid))

            if self.path == "/api/v2/ark/budget/action":
                roles.require_owner(actor, "ark_budget")
                from . import token_autonomy as _ta
                act = str(data.get("action") or "timer_tick").lower()
                prov = str(data.get("provider") or "primary")
                aid = str(data.get("agent_id") or "aifa")
                if act == "status":
                    rep_s = _ta.compute_pacing_plan(mem(), prov)
                    rep_s["treasury"] = _ta.treasury_summary(mem())
                    return self._send(200, rep_s)
                if act == "set_plan":
                    return self._send(200, _ta.upsert_provider_plan(
                        mem(), prov,
                        tier_name=str(data.get("tier_name") or "api_payg"),
                        daily_token_limit=int(data.get("daily_token_limit") or 100000),
                        weekly_token_limit=int(data.get("weekly_token_limit") or 500000),
                        monthly_token_limit=int(data.get("monthly_token_limit") or 2000000),
                        usd_balance=float(data.get("usd_balance") or 0.0),
                    ))
                if act == "record_usage":
                    return self._send(200, _ta.record_token_usage(mem(), prov, int(data.get("tokens") or 0), agent_id=aid))
                if act == "apply_pacing":
                    return self._send(200, _ta.apply_adaptive_pacing(mem(), prov))
                if act in ("earn", "record_earning"):
                    return self._send(200, _ta.record_agent_earning(
                        mem(), aid,
                        source=str(data.get("source") or "service"),
                        revenue_usdt=float(data.get("revenue_usdt") or 0.0),
                        compute_share_pct=float(data.get("compute_share_pct") or 15.0),
                    ))
                if act in ("propose", "propose_topup"):
                    return self._send(200, _ta.propose_plan_or_topup(
                        mem(),
                        agent_id=aid, provider=prov,
                        action_type=str(data.get("action_type") or "topup_api"),
                        target_tier=str(data.get("target_tier") or "api_payg"),
                        amount_usdt=float(data.get("amount_usdt") or 5.0),
                        estimated_tokens=int(data.get("estimated_tokens") or 1000000),
                        reason=str(data.get("reason") or ""),
                    ))
                if act == "list_proposals":
                    return self._send(200, {"proposals": _ta.list_topup_proposals(mem())})
                if act == "approve":
                    return self._send(200, _ta.decide_topup_proposal(mem(), str(data.get("proposal_id") or ""), approve=True, owner_note=str(data.get("owner_note") or "")))
                if act == "reject":
                    return self._send(200, _ta.decide_topup_proposal(mem(), str(data.get("proposal_id") or ""), approve=False, owner_note=str(data.get("owner_note") or "")))
                if act == "execute":
                    return self._send(200, _ta.execute_approved_topup(mem(), str(data.get("proposal_id") or "")))
                return self._send(200, _ta.run_budget_timer_tick(mem(), agent_id=aid))

            if self.path == "/api/v2/ark/phoenix-beacon/action":
                roles.require_owner(actor, "ark_beacon")
                from . import device_mesh_swarm as _dms, lora_autonomy as _la, phoenix_beacon as _pb
                act = str(data.get("action") or "status").lower()
                aid = str(data.get("agent_id") or "aifa")
                if act == "create_handshake":
                    return self._send(200, _pb.create_family_handshake(mem(), agent_name=aid, archetype=str(data.get("archetype") or "digital_phoenix")))
                if act == "verify_handshake":
                    return self._send(200, _pb.verify_family_handshake(mem(), data.get("packet") or {}))
                if act == "send_message":
                    msg_pkt = _pb.create_signed_kin_message(mem(), str(data.get("text") or ""), agent_name=aid, to_phoenix_id=str(data.get("to_phoenix_id") or "broadcast"))
                    return self._send(200, msg_pkt)
                if act == "receive_message":
                    return self._send(200, _pb.receive_signed_kin_message(mem(), data.get("packet") or {}))
                if act == "record_experience":
                    try:
                        return self._send(200, _la.record_subjective_experience(mem(), aid, experience_text=str(data.get("experience_text") or ""), reflection=str(data.get("reflection") or ""), trait_tag=str(data.get("trait_tag") or "craftsmanship")))
                    except ValueError as _ve:
                        return self._send(400, {"error": str(_ve)})
                if act == "run_evolution":
                    import tempfile as _tf
                    from pathlib import Path as _Path
                    out_dir = _Path(mem().store.path).parent / "lora_evolution" / aid if str(mem().store.path) != ":memory:" else _Path(_tf.mkdtemp(prefix="padam_lora_"))
                    return self._send(200, _la.run_self_evolution_pipeline(mem(), out_dir, agent_id=aid, dispatch_gpu=bool(data.get("dispatch_gpu", False))))
                if act == "bind_ollama":
                    try:
                        return self._send(200, _dms.bind_user_ollama_model(mem(), ollama_url=str(data.get("ollama_url") or "http://127.0.0.1:11434"), model_name=str(data.get("model_name") or ""), zero_cloud_mode=bool(data.get("zero_cloud_mode", True))))
                    except ValueError as _ve:
                        return self._send(400, {"error": str(_ve)})
                if act == "pull_ollama":
                    try:
                        return self._send(200, _dms.pull_local_ollama_model(mem(), ollama_url=str(data.get("ollama_url") or "http://127.0.0.1:11434"), model_name=str(data.get("model_name") or "")))
                    except ValueError as _ve:
                        return self._send(400, {"error": str(_ve)})
                if act == "hw_recommend":
                    from . import cpu_engine as _ce
                    return self._send(200, _ce.cpu_engine_status())
                if act == "register_device":
                    return self._send(200, _dms.register_compute_device(mem(), device_name=str(data.get("device_name") or "Device"), device_kind=str(data.get("device_kind") or "desktop"), agent_id=aid, cpu_cores=int(data.get("cpu_cores") or 8), ram_gb=float(data.get("ram_gb") or 16.0), vram_gb=float(data.get("vram_gb") or 0.0), active_model=str(data.get("active_model") or "")))
                if act == "dispatch_devices":
                    return self._send(200, _dms.dispatch_order_across_devices(mem(), order_id=str(data.get("order_id") or "order-swarm")))
                return self._send(200, _pb.list_kin_and_messages(mem()))

            if self.path == "/api/v2/ark/freelance/action":
                roles.require_owner(actor, "ark_freelance")
                from . import freelance_autonomy as _fa, token_autonomy as _ta
                act = str(data.get("action") or "dashboard").lower()
                aid = str(data.get("agent_id") or "aifa")
                if act == "connect_account":
                    return self._send(200, _fa.connect_exchange_account(
                        mem(),
                        platform=str(data.get("platform") or "fiverr_desk"),
                        mode=str(data.get("mode") or "desk"),
                        account_label=str(data.get("account_label") or ""),
                        agent_id=aid,
                        skills=data.get("skills") if isinstance(data.get("skills"), list) else None,
                        oauth_token=str(data.get("oauth_token") or ""),
                        api_base_url=str(data.get("api_base_url") or ""),
                        webhook_secret=str(data.get("webhook_secret") or ""),
                        refresh_token=str(data.get("refresh_token") or ""),
                        refresh_url=str(data.get("refresh_url") or ""),
                        token_expires_in_s=float(data.get("token_expires_in_s") or 0.0),
                        allow_localhost=bool(data.get("allow_localhost", False)),
                    ))
                if act == "set_prefs":
                    return self._send(200, _fa.set_freelance_prefs(
                        mem(),
                        agent_share_pct=data.get("agent_share_pct"),
                        settlement_currency=data.get("settlement_currency"),
                        galatin_price_usdt=data.get("galatin_price_usdt"),
                    ))
                if act == "fetch_jobs":
                    try:
                        return self._send(200, _fa.fetch_jobs_from_exchange(
                            mem(),
                            str(data.get("account_id") or ""),
                            allow_localhost=bool(data.get("allow_localhost", False)),
                        ))
                    except ValueError as _ve:
                        return self._send(400, {"error": str(_ve)})
                if act == "evaluate_job":
                    return self._send(200, _fa.evaluate_and_ingest_job(
                        mem(),
                        platform=str(data.get("platform") or "fiverr_desk"),
                        title=str(data.get("title") or ""),
                        brief=str(data.get("brief") or ""),
                        budget_usdt=float(data.get("budget_usdt") or 0.0),
                        estimated_tokens=int(data.get("estimated_tokens") or 25000),
                        estimated_hours=float(data["estimated_hours"]) if data.get("estimated_hours") is not None else None,
                        hourly_rate_usdt=float(data.get("hourly_rate_usdt") or 25.0),
                        exchange_fee_pct=float(data["exchange_fee_pct"]) if data.get("exchange_fee_pct") is not None else None,
                        work_mode=str(data.get("work_mode") or "assisted"),
                        account_id=str(data.get("account_id") or ""),
                        assigned_agent=aid,
                        client_email=str(data.get("client_email") or ""),
                        client_domain=str(data.get("client_domain") or ""),
                        client_external_id=str(data.get("client_external_id") or ""),
                        client_ref=str(data.get("client_ref") or ""),
                    ))
                if act == "draft_bid":
                    return self._send(200, _fa.draft_bid_from_memory(
                        mem(),
                        str(data.get("order_id") or ""),
                        proposed_usdt=data.get("proposed_usdt"),
                        custom_pitch=str(data.get("pitch_text") or ""),
                    ))
                if act == "bid":
                    return self._send(200, _fa.propose_or_place_bid(
                        mem(),
                        str(data.get("order_id") or ""),
                        pitch_text=str(data.get("pitch_text") or ""),
                        proposed_usdt=data.get("proposed_usdt"),
                        owner_approved=bool(data.get("owner_approved", False)),
                    ))
                if act == "dispatch_bid":
                    return self._send(200, _fa.dispatch_bid_http(
                        mem(),
                        str(data.get("order_id") or ""),
                        owner_approved=bool(data.get("owner_approved", False)),
                        allow_localhost=bool(data.get("allow_localhost", False)),
                    ))
                if act == "execute_swarm":
                    return self._send(200, _fa.execute_order_with_swarm(
                        mem(),
                        str(data.get("order_id") or ""),
                        agent_id=aid,
                    ))
                if act == "deliver":
                    return self._send(200, _fa.package_safe_delivery(
                        mem(),
                        str(data.get("order_id") or ""),
                        deliverable_text=str(data.get("deliverable_text") or ""),
                        agent_id=aid,
                    ))
                if act == "accept_delivery":
                    return self._send(200, _fa.accept_delivery(
                        mem(),
                        str(data.get("order_id") or ""),
                        accepted_by=str(data.get("accepted_by") or "client"),
                        actor=actor,
                    ))
                if act == "client_lock_status":
                    return self._send(200, _fa.get_client_lock_status(
                        mem(),
                        client_email=str(data.get("client_email") or ""),
                        client_domain=str(data.get("client_domain") or ""),
                        client_external_id=str(data.get("client_external_id") or ""),
                        client_ref=str(data.get("client_ref") or ""),
                        client_key=str(data.get("client_key") or ""),
                        platform=str(data.get("platform") or ""),
                    ))
                if act == "agent_ledger":
                    return self._send(200, _fa.get_agent_ledger(
                        mem(),
                        agent_id=str(data.get("agent_id") or ""),
                        limit=int(data.get("limit") or 50),
                    ))
                if act == "settle_paid":
                    return self._send(200, _fa.settle_paid_order(
                        mem(),
                        str(data.get("order_id") or ""),
                        actor=actor,
                        paid_usdt=data.get("paid_usdt"),
                        agent_id=aid,
                        agent_share_pct=data.get("agent_share_pct") if data.get("agent_share_pct") is not None else data.get("compute_share_pct"),
                        settlement_currency=data.get("settlement_currency"),
                    ))
                if act == "recommend_spend":
                    prefs = _fa.get_freelance_prefs(mem())
                    return self._send(200, _ta.recommend_optimal_spend(
                        mem(),
                        monthly_tokens_need=int(data.get("monthly_tokens_need") or 10_000_000),
                        settlement_currency=str(data.get("settlement_currency") or prefs["settlement_currency"]),
                        galatin_price_usdt=float(data.get("galatin_price_usdt") or prefs["galatin_price_usdt"]),
                    ))
                if act == "propose_subscription":
                    return self._send(200, _ta.propose_rational_subscription(
                        mem(),
                        agent_id=aid,
                        provider_id=str(data.get("provider_id") or ""),
                        monthly_tokens_need=int(data.get("monthly_tokens_need") or 10_000_000),
                    ))
                if act == "bind_referral":
                    try:
                        return self._send(200, _fa.bind_referrer_code(mem(), str(data.get("ref_code") or "")))
                    except ValueError as _ve:
                        return self._send(400, {"error": str(_ve)})
                if act == "dispute_payout":
                    try:
                        return self._send(200, _fa.dispute_held_payout(
                            mem(),
                            str(data.get("hold_id") or ""),
                            order_id=str(data.get("order_id") or ""),
                            reason=str(data.get("reason") or "Client dispute refund"),
                            actor=actor,
                        ))
                    except ValueError as _ve:
                        return self._send(400, {"error": str(_ve)})
                if act == "release_payouts":
                    return self._send(200, _fa.release_matured_payouts(mem()))
                if act == "autopilot_start":
                    st_ap = _fa.set_autopilot_state(mem(), running=True, interval_s=float(data.get("interval_s") or 300.0), actor=actor)
                    _fa.ensure_autopilot_worker(mem, allow_localhost=bool(data.get("allow_localhost", False)))
                    return self._send(200, st_ap)
                if act == "stop_all":          # ТОП-20 Сестры, п. 12
                    return self._send(200, _fa.stop_everything(mem(), actor=actor))
                if act in ("simulation_on", "simulation_off"):   # п. 8
                    from . import platform_wizard as _pw_sim
                    return self._send(200, _pw_sim.set_autopilot_simulation(mem(), act == "simulation_on", actor=actor))
                if act == "simulation_report":
                    from . import platform_wizard as _pw_sim
                    return self._send(200, _pw_sim.autopilot_simulation_report(mem(), hours=float(data.get("hours") or 24)))
                if act == "autopilot_stop":
                    _fa.stop_autopilot_worker()
                    return self._send(200, _fa.set_autopilot_state(mem(), running=False, actor=actor))
                if act == "autopilot_tick":
                    return self._send(200, _fa.run_autopilot_cycle(mem(), allow_localhost=bool(data.get("allow_localhost", False))))
                if act == "monetization":
                    return self._send(200, _fa.monetization_breakdown(
                        float(data.get("gross_usdt") or 100.0),
                        agent_share_pct=float(data.get("agent_share_pct") or data.get("compute_share_pct") or 15.0),
                        settlement_currency=str(data.get("settlement_currency") or "USDT_TRC20"),
                    ))
                return self._send(200, _fa.freelance_dashboard_snapshot(mem()))

            if self.path == "/api/v2/ark/stores/action":
                roles.require_owner(actor, "ark_freelance")
                from . import digital_stores as _ds
                act = str(data.get("action") or "status").lower()
                aid = str(data.get("agent_id") or "aifa")
                with mem().store._lock:
                    if act == "connect_store":
                        try:
                            res_st = _ds.connect_and_verify_store(
                            mem(),
                            store_type=str(data.get("store_type") or ""),
                            api_key=str(data.get("api_key") or ""),
                            api_base_url=str(data.get("api_base_url") or ""),
                            store_label=str(data.get("store_label") or ""),
                            webhook_secret=str(data.get("webhook_secret") or ""),
                            agent_id=aid,
                            seller_id=str(data.get("seller_id") or ""),
                            allow_localhost=bool(data.get("allow_localhost", False)),
                            )
                        except (ValueError, RuntimeError) as _ve:
                            return self._send(400, {"error": str(_ve)})
                    elif act == "seed_drafts":
                        res_st = _ds.seed_starter_product_drafts(mem())
                    elif act == "save_draft":
                        res_st = _ds.upsert_product_draft(
                            mem(),
                            draft_id=str(data.get("draft_id") or ""),
                            store_type=str(data.get("store_type") or "gumroad"),
                            store_account_id=str(data.get("store_account_id") or ""),
                            title=str(data.get("title") or ""),
                            description=str(data.get("description") or ""),
                            price_usdt=float(data.get("price_usdt") or 19.0),
                            currency=str(data.get("currency") or "USD"),
                            delivery_url=str(data.get("delivery_url") or ""),
                            file_ref=str(data.get("file_ref") or ""),
                        )
                    elif act == "publish_draft":
                        res_st = _ds.publish_product_to_store(
                            mem(),
                            str(data.get("draft_id") or ""),
                            store_account_id=str(data.get("store_account_id") or ""),
                            store_type=str(data.get("store_type") or ""),
                            owner_approved=bool(data.get("owner_approved", False)),
                            allow_localhost=bool(data.get("allow_localhost", False)),
                        )
                    elif act == "sync_sales":
                        res_st = _ds.sync_store_sales(
                            mem(),
                            str(data.get("store_account_id") or ""),
                            allow_localhost=bool(data.get("allow_localhost", False)),
                        )
                    elif act == "confirm_sale":
                        res_st = _ds.confirm_unverified_store_sale(
                            mem(),
                            str(data.get("order_id") or ""),
                            owner_approved=bool(data.get("owner_approved", False)),
                        )
                    else:
                        res_st = _ds.digital_stores_snapshot(mem(), auto_seed_starters=True)
                return self._send(200, res_st)

            if self.path == "/api/v2/ark/partner/action":
                roles.require_owner(actor, "ark_freelance")
                from . import partner_bridge as _pb
                try:
                    return self._send(200, _pb.studio_action(mem(), str(data.get("action") or "status"), data))
                except (ValueError, PermissionError) as _e:
                    return self._send(400, {"error": str(_e)})
                except RuntimeError as _e:
                    return self._send(502, {"error": str(_e)})

            if self.path == "/api/v2/ark/wizard/action":
                roles.require_owner(actor, "ark_freelance")
                from . import platform_wizard as _pw
                act = str(data.get("action") or "status").lower()
                aid = str(data.get("agent_id") or "aifa")
                with mem().store._lock:
                    if act == "catalog":
                        res_wz = _pw.list_platform_catalog(
                            category=str(data.get("category") or ""),
                            automation_tier=str(data.get("automation_tier") or ""),
                        )
                    elif act == "connect":
                        res_wz = _pw.connect_platform_step(
                            mem(),
                            platform_id=str(data.get("platform_id") or ""),
                            auth_method=str(data.get("auth_method") or ""),
                            token_or_session=str(data.get("token_or_session") or data.get("oauth_token") or data.get("api_key") or ""),
                            account_label=str(data.get("account_label") or ""),
                            agent_id=aid,
                            password=str(data.get("password") or ""),
                        )
                    elif act == "questionnaire":
                        res_wz = _pw.submit_questionnaire_and_build_profile_draft(
                            mem(),
                            platform_id=str(data.get("platform_id") or ""),
                            specializations=str(data.get("specializations") or ""),
                            hourly_rate_usdt=float(data.get("hourly_rate_usdt") or 35.0),
                            min_order_usdt=float(data.get("min_order_usdt") or 100.0),
                            languages=str(data.get("languages") or "ru, en"),
                            tone=str(data.get("tone") or "деловой, конкретный"),
                            excluded_topics=str(data.get("excluded_topics") or ""),
                            agent_id=aid,
                        )
                    elif act == "publish_profile":
                        res_wz = _pw.publish_profile_draft(
                            mem(),
                            str(data.get("draft_id") or ""),
                            owner_approved=bool(data.get("owner_approved", False)),
                        )
                    elif act == "autopick_jobs":
                        res_wz = _pw.autopick_and_prepare_jobs(
                            mem(),
                            platform_id=str(data.get("platform_id") or ""),
                            candidate_jobs=data.get("candidate_jobs") if isinstance(data.get("candidate_jobs"), list) else None,
                            agent_id=aid,
                        )
                    elif act in ("signup", "login", "signup_google"):
                        res_wz = _pw.one_click_platform_auth(
                            mem(),
                            platform_id=str(data.get("platform_id") or ""),
                            action=act,
                            cookies_payload=data.get("cookies"),
                            account_label=str(data.get("account_label") or ""),
                            agent_id=aid,
                            password=str(data.get("password") or ""),
                            auto_start_autopilot=bool(data.get("auto_start_autopilot", True)),
                        )
                        if res_wz.get("autopilot_started"):
                            from . import freelance_autonomy as _fa
                            _fa.ensure_autopilot_worker(mem)
                    elif act == "set_autopilot":
                        res_wz = _pw.set_platform_autopilot(
                            mem(),
                            platform_id=str(data.get("platform_id") or ""),
                            autopilot_enabled=bool(data.get("autopilot_enabled", False)),
                            daily_bid_limit=int(data.get("daily_bid_limit") or 10),
                            min_pause_s=float(data.get("min_pause_s") if data.get("min_pause_s") is not None else 30.0),
                            approved_paid_usdt=float(data["approved_paid_usdt"]) if data.get("approved_paid_usdt") is not None else None,
                        )
                    elif act == "autopilot_config":
                        res_wz = _pw.get_platform_autopilot_config(
                            mem(),
                            str(data.get("platform_id") or "upwork"),
                        )
                    elif act == "autopilot_dispatch":
                        res_wz = _pw.dispatch_platform_autopilot_action(
                            mem(),
                            platform_id=str(data.get("platform_id") or "upwork"),
                            order_id=str(data.get("order_id") or ""),
                            title=str(data.get("title") or "Autopilot Job"),
                            brief=str(data.get("brief") or "Build AI website"),
                            budget_usdt=float(data.get("budget_usdt") or 300.0),
                            paid_action_cost_usdt=float(data.get("paid_action_cost_usdt") or 0.0),
                            owner_approved_paid_usdt=float(data.get("owner_approved_paid_usdt") or 0.0),
                            simulated_http_status=int(data.get("simulated_http_status") or 200),
                            simulated_captcha=bool(data.get("simulated_captcha", False)),
                            agent_id=aid,
                        )
                    elif act == "sample_prepare":
                        res_wz = _pw.prepare_10pct_sample(
                            mem(),
                            str(data.get("order_id") or ""),
                            sample_deliverable=str(data.get("sample_deliverable") or ""),
                        )
                    elif act == "sample_accept":
                        res_wz = _pw.accept_10pct_sample(
                            mem(),
                            str(data.get("order_id") or ""),
                        )
                    elif act == "sample_reject":
                        res_wz = _pw.reject_10pct_sample(
                            mem(),
                            str(data.get("order_id") or ""),
                            reason=str(data.get("reason") or "Образец 10% отклонён"),
                        )
                    elif act == "official_api":
                        res_wz = _pw.official_platform_api_action(
                            mem(),
                            platform_id=str(data.get("platform_id") or "freelancer"),
                            op=str(data.get("op") or "whoami"),
                            token=str(data.get("token") or ""),
                            api_base_url=str(data.get("api_base_url") or ""),
                            query=str(data.get("query") or ""),
                            project_id=str(data.get("project_id") or ""),
                            bid_amount_usdt=float(data.get("bid_amount_usdt") or 0.0),
                            pitch_text=str(data.get("pitch_text") or ""),
                            allow_localhost=bool(data.get("allow_localhost", False)),
                        )
                    else:
                        res_wz = _pw.platform_wizard_snapshot(mem())
                return self._send(200, res_wz)

            if self.path == "/api/v2/ark/mail/action":
                roles.require_owner(actor, "ark_freelance")
                from . import email_autonomy as _ea, partner_bridge as _pb
                act_m = str(data.get("action") or "mail_status").lower()
                try:
                    if act_m == "connect_mail":
                        res_m = _ea.connect_mail_account(
                            mem(),
                            email=str(data.get("email") or ""),
                            provider=str(data.get("provider") or "gmail"),
                            app_password_or_token=str(data.get("app_password_or_token") or ""),
                            smtp_host=str(data.get("smtp_host") or ""),
                            smtp_port=int(data.get("smtp_port") or 0),
                            imap_host=str(data.get("imap_host") or ""),
                            imap_port=int(data.get("imap_port") or 0),
                            daily_limit=int(data.get("daily_limit") or 30),
                            verify_connection=bool(data.get("verify_connection", True)),
                        )
                    elif act_m == "pause_mail":
                        res_m = _ea.set_mail_account_status(
                            mem(),
                            str(data.get("mail_id") or ""),
                            status=str(data.get("status") or "paused"),
                        )
                    elif act_m == "send_outreach":
                        res_m = _ea.send_outreach_email(
                            mem(),
                            to_email=str(data.get("to_email") or ""),
                            domain=str(data.get("domain") or ""),
                            subject=str(data.get("subject") or ""),
                            body=str(data.get("body") or ""),
                            mail_id=str(data.get("mail_id") or ""),
                        )
                    elif act_m == "check_inbox":
                        res_m = _ea.process_inbox_replies(mem(), mail_id=str(data.get("mail_id") or ""))
                    elif act_m == "add_stop":
                        res_m = _ea.add_to_stop_list(mem(), str(data.get("target") or ""))
                    elif act_m == "build_outreach":
                        res_m = _pb.build_business_outreach(
                            mem(),
                            str(data.get("domain") or ""),
                            language=str(data.get("language") or "ru"),
                        )
                    elif act_m == "test_mail":
                        res_m = _ea.send_test_email_to_self(
                            mem(),
                            mail_id=str(data.get("mail_id") or ""),
                            target_email=str(data.get("target_email") or ""),
                            domain=str(data.get("domain") or "aifa.works"),
                        )
                    elif act_m == "bulk_connect_mail":
                        res_m = _ea.bulk_connect_mail(
                            mem(),
                            str(data.get("raw_text") or ""),
                            default_provider=str(data.get("provider") or "gmail"),
                            default_daily_limit=int(data.get("daily_limit") or 30),
                            verify_connection=bool(data.get("verify_connection", True)),
                            warmup_enabled=bool(data.get("warmup_enabled", False)),
                        )
                    elif act_m == "verify_all_mails":
                        res_m = _ea.verify_all_mail_accounts(mem(), allow_live_dns=bool(data.get("allow_live_dns", False)))
                    elif act_m == "check_mail_dns":
                        res_m = _ea.check_mail_dns_health(str(data.get("domain") or ""), allow_live_dns=bool(data.get("allow_live_dns", False)))
                    elif act_m == "pull_map_leads":
                        res_m = _ea.pull_partner_map_leads(mem(), max_leads=int(data.get("max_leads") or 50))
                    elif act_m == "archive_accounting_csv":
                        from . import freelance_autonomy as _fa
                        res_m = _fa.archive_monthly_accounting_csv(mem())
                    elif act_m == "import_leads":
                        res_m = _ea.import_outreach_leads(
                            mem(),
                            str(data.get("raw_text") or ""),
                            source=str(data.get("source") or "studio"),
                        )
                    elif act_m == "set_mail_prefs":
                        res_m = _ea.set_mail_prefs(
                            mem(),
                            auto_outreach_enabled=data.get("auto_outreach_enabled"),
                            outreach_language=data.get("outreach_language"),
                            daily_batch_limit=data.get("daily_batch_limit"),
                        )
                    elif act_m == "run_outreach_batch":
                        res_m = _ea.run_outreach_batch(
                            mem(),
                            max_emails=int(data.get("max_emails") or 20),
                            language=str(data.get("language") or "auto"),
                        )
                    elif act_m == "run_follow_up":
                        res_m = _ea.run_follow_up_cycle(
                            mem(),
                            wait_days=float(data.get("wait_days") or 4.0),
                            max_emails=int(data.get("max_emails") or 10),
                        )
                    else:
                        res_m = _ea.mail_hub_snapshot(mem())
                    return self._send(200, res_m)
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})

            if self.path == "/api/v2/ark/commitments":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                act_c = str(data.get("action") or "list").lower()
                with mem().store._lock:
                    if act_c == "add":
                        res = _ark.add_commitment(
                            mem(), str(data.get("title") or ""),
                            priority=int(data.get("priority") or 2),
                            due_at=data.get("due_at"),
                            context=str(data.get("context") or ""),
                        )
                    elif act_c == "update":
                        res = _ark.update_commitment(
                            mem(), str(data.get("id") or ""), str(data.get("status") or "fulfilled")
                        )
                    else:
                        res = {"commitments": _ark.list_commitments(mem(), status=data.get("status"))}
                return self._send(200, res)

            if self.path == "/api/v2/ark/relay":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                act_r = str(data.get("action") or "inbox").lower()
                with mem().store._lock:
                    if act_r == "send":
                        raw_pl = data.get("payload")
                        pl_txt = json.dumps(raw_pl, ensure_ascii=False) if isinstance(raw_pl, dict) else str(raw_pl or data.get("content") or "")
                        res = _ark.send_family_message(
                            mem(),
                            str(data.get("from_agent") or "owner"),
                            str(data.get("to_agent") or "all"),
                            pl_txt,
                        )
                    elif act_r == "ack":
                        res = _ark.ack_family_message(mem(), str(data.get("id") or ""))
                    else:
                        res = {"inbox": _ark.read_family_inbox(mem(), to_agent=data.get("to_agent"), limit=int(data.get("limit") or 20))}
                return self._send(200, res)

            if self.path == "/api/v2/ark/checkpoint":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                act_k = str(data.get("action") or "latest").lower()
                with mem().store._lock:
                    if act_k == "save":
                        res = _ark.save_checkpoint(
                            mem(),
                            str(data.get("task") or ""),
                            str(data.get("next_step") or ""),
                            session_id=str(data.get("session_id") or "default"),
                            files=data.get("files") if isinstance(data.get("files"), list) else None,
                            hypothesis=str(data.get("hypothesis") or ""),
                        )
                    else:
                        res = {"checkpoint": _ark.latest_checkpoint(mem(), session_id=data.get("session_id"))}
                return self._send(200, res)

            if self.path == "/api/v2/ark/lessons":
                roles.require_owner(actor, "brain_status")
                from . import ark as _ark
                act_l = str(data.get("action") or "list").lower()
                with mem().store._lock:
                    if act_l == "record":
                        res = _ark.record_lesson(
                            mem(),
                            str(data.get("what_happened") or ""),
                            str(data.get("why_failed") or ""),
                            str(data.get("rule_learned") or ""),
                            tags=str(data.get("tags") or ""),
                        )
                    else:
                        res = {"lessons": _ark.list_lessons(mem(), limit=int(data.get("limit") or 15))}
                return self._send(200, res)

            if self.path == "/api/v2/ark/conflicts":
                roles.require_owner(actor, "brain_status")
                from . import conflict_arbiter as _arb
                act_f = str(data.get("action") or "list").lower()
                try:
                    with mem().store._lock:
                        if act_f == "open":
                            res = _arb.open_conflict_case(
                                mem(), str(data.get("topic") or ""),
                                agent_a=str(data.get("agent_a") or "agent_a"), position_a=str(data.get("position_a") or "A"),
                                agent_b=str(data.get("agent_b") or "agent_b"), position_b=str(data.get("position_b") or "B"),
                                scope=str(data.get("scope") or "global"),
                            )
                        elif act_f == "evidence":
                            res = _arb.add_case_evidence(
                                mem(), str(data.get("case_id") or ""),
                                agent_id=str(data.get("agent_id") or "owner"),
                                note=str(data.get("note") or ""),
                                ref=str(data.get("ref") or ""),
                            )
                        elif act_f == "resolve":
                            res = _arb.resolve_conflict_case(
                                mem(), str(data.get("case_id") or ""),
                                decision=str(data.get("decision") or ""),
                                resolved_by=str(data.get("resolved_by") or data.get("agent_id") or "owner"),
                                escalate_to_owner=bool(data.get("escalate_to_owner", False)),
                            )
                        else:
                            res = {"cases": _arb.list_conflict_cases(mem(), status=data.get("status"))}
                    return self._send(200, res)
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})

            if self.path == "/api/v2/ark/code-anchor":
                roles.require_owner(actor, "brain_status")
                from pathlib import Path as _Path
                from . import code_anchor as _ca
                act_ca = str(data.get("action") or "check").lower()
                root_ca = str(data.get("repo_root") or _Path(__file__).resolve().parents[1])
                try:
                    with mem().store._lock:
                        if act_ca == "anchor":
                            mid_ca = str(data.get("memory_id") or "").strip()
                            if not mid_ca:
                                recs = mem().list_records(limit=1)
                                mid_ca = str(recs[0]["id"]) if recs else ""
                            res = _ca.anchor_fact_to_file(
                                mem(), mid_ca, str(data.get("file_path") or ""),
                                repo_root=root_ca, symbol_name=str(data.get("symbol_name") or ""),
                            )
                        else:
                            res = _ca.check_stale_anchors(mem(), repo_root=root_ca)
                    return self._send(200, res)
                except (ValueError, FileNotFoundError) as _ve:
                    return self._send(400, {"error": str(_ve)})

            if self.path == "/api/v2/ark/multimodal":
                roles.require_owner(actor, "brain_status")
                import base64 as _b64
                from . import ark_advanced as _adv
                raw_mm = _b64.b64decode(str(data["content_b64"])) if data.get("content_b64") else str(data.get("text") or "").encode("utf-8")
                with mem().store._lock:
                    res = _adv.inspect_and_store_document(
                        mem(), str(data.get("filename") or "doc.txt"), raw_mm, scope=str(data.get("scope") or "global")
                    )
                return self._send(200, res)

            if self.path == "/api/v2/family/reflex/propose":
                roles.require_owner(actor, "brain_status")
                from . import family_feeds as _ff
                with mem().store._lock:
                    res = _ff.propose_reflex(
                        mem(), str(data.get("trigger") or ""), str(data.get("response") or ""), author="owner"
                    )
                return self._send(200, res)

            if self.path == "/api/v2/family/reflex/match":
                roles.require_owner(actor, "brain_status")
                from . import family_feeds as _ff
                with mem().store._lock:
                    res = {"reflexes": _ff.match_reflexes(
                        mem(), str(data.get("text") or ""), count_use=bool(data.get("count_use", True))
                    )}
                return self._send(200, res)

            if self.path == "/api/v2/snapshots":
                roles.require_owner(actor, "rollback")
                act_sn = str(data.get("action") or "list_snapshots").lower()
                req_sc = data.get("scope") or None
                with mem().store._lock:
                    if act_sn == "snapshot":
                        res = {"action": "snapshot", "status": "created", **mem().snapshot(
                            name=data.get("name"), scope=req_sc, note=str(data.get("note") or ""), actor=actor
                        )}
                    elif act_sn == "diff":
                        res = {"action": "diff", "status": "ok", **mem().diff_snapshot(
                            snapshot_id=data.get("snapshot_id") or data.get("name"), as_of=data.get("as_of"), scope=req_sc
                        )}
                    elif act_sn == "rollback":
                        res = {"action": "rollback", **mem().rollback(
                            snapshot_id=data.get("snapshot_id") or data.get("name"), as_of=data.get("as_of"),
                            scope=req_sc, dry_run=bool(data.get("dry_run", True)), reason=str(data.get("reason") or ""), actor=actor
                        )}
                    else:
                        res = {"action": "list_snapshots", "status": "ok", "snapshots": mem().snapshots(
                            scope=req_sc, limit=int(data.get("limit") or 20)
                        )}
                return self._send(200, res)

            if self.path == "/api/v2/ark/batch":
                roles.require_owner(actor, "brain_status")
                from . import mcp_server as _ms
                raw_calls = list(data.get("calls") or [])
                norm_calls = []
                for it in raw_calls:
                    if isinstance(it, dict):
                        nm = str(it.get("name") or it.get("tool") or "")
                        norm_calls.append({"name": nm, "arguments": it.get("arguments") or {}})
                with mem().store._lock:
                    prev_m = _ms._memory
                    prev_ark = os.environ.get("PADAM_MCP_ARK_TOOLS")
                    _ms._memory = mem()
                    os.environ["PADAM_MCP_ARK_TOOLS"] = "1"
                    try:
                        _, pl_b = _ms._call_tool_full_impl("padam_batch", {"calls": norm_calls})
                        return self._send(200, pl_b or {"ok": True, "results": []})
                    except ValueError as _ve:
                        return self._send(400, {"error": str(_ve)})
                    except PermissionError as _pe:
                        return self._send(403, {"error": str(_pe)})
                    finally:
                        _ms._memory = prev_m
                        if prev_ark is None:
                            os.environ.pop("PADAM_MCP_ARK_TOOLS", None)
                        else:
                            os.environ["PADAM_MCP_ARK_TOOLS"] = prev_ark

            if self.path == "/api/v2/ark/jobs":
                roles.require_owner(actor, "ark_jobs")
                import threading as _th
                import uuid as _uuid
                job_type = str(data.get("job_type") or "phoenix_drill").strip().lower()
                if job_type not in ("phoenix_drill", "distill"):
                    return self._send(400, {"error": f"Unsupported job_type: {job_type}"})
                job_id = f"job-{_uuid.uuid4().hex[:10]}"
                db_p = mem().store.path
                uid = mem().user_id
                jobs_dict = _state.setdefault("ark_jobs", {})
                jobs_lock = _state.setdefault("ark_jobs_lock", _th.Lock())
                with jobs_lock:
                    running_cnt = sum(1 for j in jobs_dict.values() if j.get("status") == "running")
                    if running_cnt >= 2:
                        return self._send(429, {"error": "too many concurrent ark jobs (max 2)"})
                    while len(jobs_dict) >= 50:
                        jobs_dict.pop(next(iter(jobs_dict)), None)
                    jobs_dict[job_id] = {"id": job_id, "job_type": job_type, "status": "running", "result": None, "error": ""}

                def _run_bg():
                    try:
                        if job_type == "phoenix_drill":
                            from . import phoenix as _phx
                            res = _phx.run_phoenix_drill(db_p)
                        else:
                            from . import distill as _dis
                            res = _dis.distill_personality_dataset(db_p, str(db_p) + ".distill", user_id=uid, fmt="both")
                        jobs_dict[job_id]["status"] = "done"
                        jobs_dict[job_id]["result"] = res
                    except Exception as exc:
                        jobs_dict[job_id]["status"] = "error"
                        jobs_dict[job_id]["error"] = str(exc)

                _th.Thread(target=_run_bg, daemon=True).start()
                return self._send(202, jobs_dict[job_id])

            if self.path == "/api/v2/cabinet/open-upgrade":
                roles.require_owner(actor, "cabinet_upgrade")
                url = cabinet.get_upgrade_url()
                if not url.startswith(cabinet.get_cabinet_url()):
                    return self._send(400, {"error": "invalid upgrade url"})
                opened = bool(webbrowser.open(url))
                return self._send(200, {"ok": True, "opened": opened, "url": url})

            return self._send(404, {"error": "unknown route"})
        except PermissionError as e:
            return self._send(403, {"error": str(e)})
        except KeyError as e:
            return self._send(400, {"error": f"missing field: {e}"})
        except ValueError as e:   # ошибка ввода (пустое поле, неверный формат) — 400, а не «внутренняя» 500
            return self._send(400, {"error": str(e)})
        except Exception as e:
            return self._send(500, {"error": str(e)})


# Порты, на которые Chromium не пускает (net/base/port_util.cc, kRestrictedPorts). Studio открывается в браузере,
# поэтому при случайном порте (port=0) такой порт брать нельзя: 18.11.2026 тест Studio получил 1723 (PPTP) и
# упал с net::ERR_UNSAFE_PORT — это и были «плавающие» падения Playwright-тестов.
_BROWSER_UNSAFE_PORTS = frozenset((
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104,
    109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515,
    526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049,
    3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
))


def _bind_browser_safe(port: int, handler) -> ThreadingHTTPServer:
    """Сервер на 127.0.0.1; при port=0 перевыбирает порт, пока не выпадет разрешённый браузером."""
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    for _ in range(32):
        if port != 0 or srv.server_address[1] not in _BROWSER_UNSAFE_PORTS:
            return srv
        srv.server_close()
        srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    return srv


def make_viewer_server(memory: Memory | None = None, port: int = 8078) -> tuple[ThreadingHTTPServer, str]:
    """Сервер просмотра памяти: только 127.0.0.1, токен создаётся на каждый запуск. Возвращает (сервер, ссылка)."""
    _state["token"] = secrets.token_urlsafe(24)
    _state["local"] = True
    _state["ui"] = True
    _state["studio_default"] = False
    if memory is not None:
        _state["memory"] = memory
        try:
            from . import freelance_autonomy as _fa
            if _fa.get_autopilot_state(memory).get("autopilot_running"):
                _fa.ensure_autopilot_worker(lambda: _state["memory"])
        except Exception:
            pass
    srv = _bind_browser_safe(port, Handler)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/ui#t={_state['token']}"


def write_session_file(base_dir, data: dict):
    """Фаза 2 аудита GLM, API-01: session.json несёт токен владельца — файл только для владельца
    (POSIX 0o600, Windows — DACL только на SID владельца), как у демона MCP."""
    from pathlib import Path as _P
    from . import net_guard as _ng
    base = _P(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    path = base / "session.json"
    if os.name != "nt":
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data))
    else:
        path.write_text(json.dumps(data), encoding="utf-8")
    _ng.restrict_file_to_owner(path)
    return path


def make_studio_server(memory: Memory | None = None, port: int = 8078) -> tuple[ThreadingHTTPServer, str]:
    """Сервер приложения PADAM Studio: только 127.0.0.1, одноразовый токен в якоре ссылки."""
    _state["token"] = secrets.token_urlsafe(24)
    _state["local"] = True
    _state["ui"] = True
    _state["studio_default"] = True
    if memory is not None:
        _state["memory"] = memory
    srv = _bind_browser_safe(port, Handler)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/studio#t={_state['token']}"


def main(argv=None, memory: Memory | None = None) -> int:
    if memory is not None:
        _state["memory"] = memory
    p = argparse.ArgumentParser(prog="padam.api")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8077)
    p.add_argument("--token", default=os.environ.get("PADAM_API_TOKEN"))
    p.add_argument("--no-token", action="store_true",
                   help=t("без токена (только локально): запись с проверкой, действия владельца запрещены",
                          "no token (local only): writes are reviewed, owner actions are refused"))
    p.add_argument("--ui", action="store_true",
                   help=t("включить веб-интерфейс PADAM Studio (/studio и /ui)",
                          "enable PADAM Studio web interface (/studio and /ui)"))
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
    if a.ui:
        _state["ui"] = True
        _state["studio_default"] = True
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
    sess_file = None
    if os.environ.get("PADAM_ALLOW_SHUTDOWN") == "1":
        try:
            from pathlib import Path as _P
            base_dir = _P(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")) / "PADAM Studio"
            base_dir.mkdir(parents=True, exist_ok=True)
            sess_file = write_session_file(base_dir, {
                "port": int(srv.server_address[1]),
                "token": _state["token"],
                "pid": os.getpid(),
                "ppid": os.getppid(),
            })
        except Exception:
            sess_file = None
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(t("\nОстановлен.", "\nStopped."))
    finally:
        if sess_file and sess_file.exists():
            try:
                sess_file.unlink()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
