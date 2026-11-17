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

from . import __version__, cabinet, config, connectors, logo, roles, safety, studio, viewer
from .i18n import t
from .memory import Memory, decay, parse_ts
from .nocturne import Nocturne
from .store import Store

_state: dict = {"memory": None, "token": None, "local": True}
# Действия владельца: без токена недоступны. Тот, кто дотянулся до порта, владельцем не считается.
OWNER_POST = {"/forget", "/approve", "/reject", "/restore", "/import", "/import-external", "/export-md", "/trust-protected", "/settings", "/l3-verify", "/ask", "/link", "/workspaces", "/workspaces/members", "/workspaces/revoke", "/records/visibility", "/connectors/configure", "/connectors/sync", "/backup", "/backup/restore", "/api/v2/procedures/approve", "/api/v2/playground/demo", "/api/v2/bridge/ingest", "/api/v2/aifa-security/run", "/migrate/preview", "/migrate/run", "/migrate/undo", "/api/v2/cabinet/auth/send-code", "/api/v2/cabinet/auth/verify-code", "/api/v2/cabinet/auth/logout", "/api/v2/cabinet/aifa/chat", "/api/v2/cabinet/open-upgrade", "/v1/chat/completions", "/api/v2/brain/distill", "/api/v2/brain/phoenix-restore", "/api/v2/brain/treasury/quote"}
OWNER_GET = {"/export", "/doctor", "/overview", "/forget-receipts", "/forget-preview", "/settings", "/l3", "/graph", "/profile", "/audit", "/events", "/entities", "/workspaces", "/connectors", "/api/v2/access", "/api/v2/communities", "/api/v2/cabinet/status", "/api/v2/cabinet/aifa/history", "/api/v2/cabinet/plans", "/attacks", "/api/v2/aifa-security", "/api/v2/aifa-security/sarif", "/api/v2/aifa-security/html", "/api/v2/aifa-security/fuzz", "/api/v2/aifa-security/verify", "/api/v2/qa-benchmark", "/api/v2/brain/status", "/v1/models"}
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
        if code >= 400:
            self._дочитать_тело()
        self.send_response(code)
        cors = self._cors_origin()
        if cors:
            self.send_header("Access-Control-Allow-Origin", cors)
            self.send_header("Vary", "Origin")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
                from . import router as _router, sovereign_ops as _sops
                qs = parse_qs(путь.query)
                snap = _router.get_router().status_snapshot()
                if qs.get("probe") == ["1"]:
                    snap["local_probe"] = _router.probe_local_backend()
                locks = _sops.locks_status()
                snap.update(locks)
                snap["auto_payments_locked"] = locks["treasury_autopay_locked"]
                return self._send(200, snap)
            if путь.path == "/api/v2/qa-benchmark":
                roles.require_owner(actor, "aifa_security")
                from pathlib import Path as _Path
                qa_path = _Path(__file__).resolve().parents[1] / "benchmarks" / "quality" / "results_qa_honest_1611.json"
                if qa_path.exists():
                    return self._send(200, json.loads(qa_path.read_text(encoding="utf-8")))
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
                st, resp_data = _router.get_router().chat_completions(
                    data,
                    memory=mem(),
                    background=bool(data.get("background", False)),
                    task_type=str(data.get("task_type") or "agent"),
                    scope=str(data.get("scope") or "global"),
                )
                if bool(data.get("stream", False)) and 200 <= st < 300:
                    chunks = _router.format_sse_chunks(resp_data)
                    raw_sse = "".join(chunks).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Content-Length", str(len(raw_sse)))
                    self.end_headers()
                    self.wfile.write(raw_sse)
                    return
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
        except Exception as e:
            return self._send(500, {"error": str(e)})


def make_viewer_server(memory: Memory | None = None, port: int = 8078) -> tuple[ThreadingHTTPServer, str]:
    """Сервер просмотра памяти: только 127.0.0.1, токен создаётся на каждый запуск. Возвращает (сервер, ссылка)."""
    _state["token"] = secrets.token_urlsafe(24)
    _state["local"] = True
    _state["ui"] = True
    _state["studio_default"] = False
    if memory is not None:
        _state["memory"] = memory
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/ui#t={_state['token']}"


def make_studio_server(memory: Memory | None = None, port: int = 8078) -> tuple[ThreadingHTTPServer, str]:
    """Сервер приложения PADAM Studio: только 127.0.0.1, одноразовый токен в якоре ссылки."""
    _state["token"] = secrets.token_urlsafe(24)
    _state["local"] = True
    _state["ui"] = True
    _state["studio_default"] = True
    if memory is not None:
        _state["memory"] = memory
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
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
            sess_file = base_dir / "session.json"
            sess_file.write_text(json.dumps({
                "port": int(srv.server_address[1]),
                "token": _state["token"],
                "pid": os.getpid(),
                "ppid": os.getppid(),
            }), encoding="utf-8")
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
