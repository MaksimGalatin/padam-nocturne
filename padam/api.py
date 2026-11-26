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
OWNER_POST = {"/forget", "/approve", "/reject", "/restore", "/import", "/import-external", "/export-md", "/trust-protected", "/settings", "/l3-verify", "/l3-local-checkpoint", "/ask", "/link", "/workspaces", "/workspaces/members", "/workspaces/revoke", "/records/visibility", "/connectors/configure", "/connectors/sync", "/backup", "/backup/restore", "/api/v2/procedures/approve", "/api/v2/playground/demo", "/api/v2/bridge/ingest", "/api/v2/aifa-security/run", "/migrate/preview", "/migrate/run", "/migrate/undo", "/api/v2/cabinet/auth/send-code", "/api/v2/cabinet/auth/verify-code", "/api/v2/cabinet/auth/logout", "/api/v2/cabinet/aifa/chat", "/api/v2/cabinet/open-upgrade", "/v1/chat/completions", "/api/v2/brain/distill", "/api/v2/brain/phoenix-restore", "/api/v2/brain/phoenix-pack", "/api/v2/brain/treasury/quote", "/api/v2/brain/mode", "/api/v2/brain/warmup", "/api/v2/brain/canary", "/api/v2/ark/phoenix-drill", "/api/v2/ark/jobs", "/api/v2/ark/genesis", "/api/v2/ark/shamir-split", "/api/v2/ark/council", "/api/v2/ark/roles", "/api/v2/ark/audit-repair", "/api/v2/ark/mesh/delta", "/api/v2/ark/mesh/apply", "/api/v2/ark/mesh/pair-init", "/api/v2/ark/mesh/pair-accept", "/api/v2/ark/mesh/pair-confirm", "/api/v2/ark/proof", "/api/v2/ark/branches", "/api/v2/ark/drift", "/api/v2/ark/handover", "/api/v2/ark/self-heal", "/api/v2/ark/portable", "/api/v2/ark/siblings", "/api/v2/ark/coop", "/api/v2/ark/conflicts", "/api/v2/ark/budget/action", "/api/v2/ark/freelance/action", "/api/v2/ark/stores/action", "/api/v2/ark/wizard/action", "/api/v2/ark/partner/action", "/api/v2/ark/phoenix-beacon/action", "/api/v2/local-model", "/api/v2/family/post", "/api/v2/family/reflex/decide", "/api/v2/quarantine/council", "/api/v2/shield/kill-switch", "/api/v2/shield/outbound/check", "/api/v2/shield/outbound/decide", "/api/v2/shield/allowlist", "/api/v2/shield/supply-chain/scan", "/api/v2/shield/scan-mcp", "/api/v2/shield/scan-unicode", "/api/v2/shield/profile", "/api/v2/shield/webhook", "/api/v2/shield/webhook/test", "/api/v2/shield/output/check", "/api/v2/shield/replay/verify", "/api/v2/chats", "/api/v2/chats/import", "/api/v2/chats/sync-local", "/api/v2/media/generate", "/api/v2/shield/canary", "/api/v2/shield/lease", "/api/v2/wallets", "/api/v2/verify-claims", "/api/v2/ark/terms", "/api/v2/ark/passports/action", "/api/v2/ark/agora/action", "/api/v2/ark/automation/action", "/api/v2/shield/sales/action", "/api/v2/setup/clients/action", "/api/v2/memory/pro/action", "/api/v2/import/universal", "/api/v2/power/action", "/api/v2/swarm/coop/action", "/api/v2/quarantine/approve-clean", "/api/v2/quarantine/reject-similar", "/api/v2/cloud/sync", "/api/v2/agents/canonicalize", "/api/v2/lan-sync/offer", "/api/v2/voice/command"}
OWNER_GET = {"/export", "/doctor", "/overview", "/forget-receipts", "/forget-preview", "/settings", "/l3", "/graph", "/profile", "/audit", "/events", "/entities", "/workspaces", "/connectors", "/api/v2/access", "/api/v2/communities", "/api/v2/cabinet/status", "/api/v2/cabinet/aifa/history", "/api/v2/cabinet/plans", "/attacks", "/api/v2/aifa-security", "/api/v2/aifa-security/sarif", "/api/v2/aifa-security/html", "/api/v2/aifa-security/fuzz", "/api/v2/aifa-security/verify", "/api/v2/qa-benchmark", "/api/v2/brain/status", "/v1/models", "/api/v2/brain/voice/status", "/api/v2/ark/wakeup", "/api/v2/ark/morning-pulse", "/api/v2/ark/health", "/api/v2/ark/audit-verify", "/api/v2/ark/jobs", "/api/v2/ark/guardian-tick", "/api/v2/ark/branches", "/api/v2/ark/mesh/peers", "/api/v2/ark/readiness", "/api/v2/ark/reflex", "/api/v2/ark/siblings", "/api/v2/ark/roles", "/api/v2/ark/coop", "/api/v2/ark/session-pack", "/api/v2/ark/mcp-telemetry", "/api/v2/ark/budget", "/api/v2/ark/freelance", "/api/v2/ark/stores", "/api/v2/ark/wizard", "/api/v2/ark/partner", "/api/v2/local-model", "/api/v2/family/feed", "/api/v2/family/reflexes", "/api/v2/quarantine/council", "/api/v2/family/dialogs", "/api/v2/redteam/rounds", "/api/v2/code-version", "/api/v2/shield/status", "/api/v2/shield/proof-pack", "/api/v2/shield/webhook", "/api/v2/shield/agent-budget", "/api/v2/agents", "/api/v2/chats", "/api/v2/chats/thread", "/api/v2/chats/hour", "/api/v2/chats/compact-hour", "/api/v2/media/engines", "/api/v2/media/file", "/api/v2/wallets", "/api/v2/ark/terms", "/api/v2/ark/fee-invoices", "/api/v2/ark/passports", "/api/v2/ark/agora", "/api/v2/ark/automation", "/api/v2/shield/sales", "/api/v2/setup/clients", "/api/v2/mcp/inspector", "/api/v2/memory/pro", "/api/v2/import/sources", "/api/v2/power/status", "/api/v2/swarm/coop", "/api/v2/pulse/recent", "/api/v2/pulse/stream", "/api/v2/quarantine/inspect", "/api/v2/cloud/status"}
NEEDS_TOKEN = {"error": "this action is the owner's: start the API with --token or PADAM_API_TOKEN"}
MAX_BODY = 16 * 1024 * 1024  # 16 МБ JSON-транспорт, чтобы вложения до 10 МБ в base64 проходили целиком


def _generated_media_dir(memory_obj) -> "Path":
    import tempfile
    from pathlib import Path
    raw_p = str(getattr(getattr(memory_obj, "store", None), "path", "") or "")
    if raw_p and raw_p != ":memory:":
        d = Path(raw_p).resolve().parent / "padam_generated_media"
    else:
        d = Path(tempfile.gettempdir()) / "padam_generated_media"
    d.mkdir(parents=True, exist_ok=True)
    return d


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
    try:
        from . import pulse_stream as _ps
        _ps.set_pulse_db_path(getattr(_state["memory"].store, "path", None))
    except Exception:
        pass
    return _state["memory"]


# 26.11.2026, слово Папы: «Его можно так починить чтобы не ломалось раз в час?»
# Причина замером: на базе ~24 500 записей один /overview (stats + doctor + подписи + противоречия)
# считался дольше 60 с. Окно ПК опрашивает /overview каждые 1,5 с и бросает ответ через 4 с, а
# ThreadingHTTPServer доводил до конца КАЖДЫЙ брошенный запрос в своём потоке. Потоки копились,
# процессор стоял на 100 % (6 ч процессорного времени за 7 ч), и карточки Студии оставались «…».
# Теперь обзор считает один поток, результат живёт _OVERVIEW_TTL секунд, а пока идёт пересчёт,
# остальные запросы сразу получают прежний результат вместо нового тяжёлого подсчёта.
_OVERVIEW_TTL = float(os.environ.get("PADAM_OVERVIEW_TTL", "15") or 15)
_overview_lock = threading.Lock()
_overview_cache: dict = {}


def _overview_compute(m: Memory, actor) -> dict:
    owner = roles.is_owner(actor)
    unsigned = m.unsigned_protected() if owner else []
    doc = m.doctor_report() if owner else {"warnings": 0, "dangers": 0, "checks": []}
    return {
        "version": __version__,
        "stats": m.stats(actor=actor),
        "doctor": doc,
        "nocturne_runs": m.nocturne_runs(5) if owner else [],
        "unsigned_protected": [
            {"id": r["id"], "kind": r["kind"], "content": r["content"][:160]}
            for r in unsigned
        ],
        "conflicts": m.conflicts(actor=actor),
        "actor": {"role": actor.role, "subject": actor.subject, "workspace_id": actor.workspace_id} if actor else {"role": "owner", "subject": "owner", "workspace_id": None},
    }


def _overview_cached(m: Memory, actor, fresh: bool = False) -> dict:
    import time as _t
    key = (id(m), getattr(actor, "role", None), getattr(actor, "subject", None), getattr(actor, "workspace_id", None))
    hit = _overview_cache.get(key)
    now = _t.monotonic()
    if hit and not fresh and now - hit[0] < _OVERVIEW_TTL:
        return hit[1]
    if hit and not _overview_lock.acquire(blocking=False):
        return hit[1]  # пересчёт уже идёт — отдаём прежний результат, второй подсчёт не начинаем
    if not hit:
        _overview_lock.acquire()
    try:
        hit2 = _overview_cache.get(key)
        if hit2 and not fresh and _t.monotonic() - hit2[0] < _OVERVIEW_TTL:
            return hit2[1]
        data = _overview_compute(m, actor)
        _overview_cache[key] = (_t.monotonic(), data)
        return data
    finally:
        _overview_lock.release()


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
                         "connect-src 'self'; img-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; "
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
            asset_csp = (
                "default-src 'none'; script-src 'self'; connect-src 'self'"
                if путь.path == "/sw.js"
                else "default-src 'none'; script-src 'none'; style-src 'none'"
            )
            self.send_header("Content-Security-Policy", asset_csp)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(body)
            return None
        if путь.path == "/api/v2/lan-sync/pull":
            from . import qr_svg as _qrs
            qs_ls = parse_qs(путь.query)
            tok_ls = (qs_ls.get("token") or [""])[0].strip()
            since_ls = (qs_ls.get("since") or [""])[0].strip() or None
            lim_ls = max(1, min(500, int((qs_ls.get("limit") or ["200"])[0])))
            if not tok_ls or not _qrs.get_active_offer(tok_ls):
                return self._send(401, {"ok": False, "error": "invalid_or_expired_token"})
            return self._send(200, _qrs.export_encrypted_delta(mem(), tok_ls, since=since_ls, limit=lim_ls))
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
                with mem().store._lock:
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
                from .aifa_sec_bridge import aifa_sec_module as _asm
                render_sarif = _asm("render").render_sarif
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
                from .aifa_sec_bridge import aifa_sec_module as _asm
                render_html_dashboard = _asm("render").render_html_dashboard
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
                from .aifa_sec_bridge import aifa_sec_module as _asm
                run_fuzz_suite = _asm("fuzzer").run_fuzz_suite
                return self._send(200, run_fuzz_suite())
            if путь.path == "/api/v2/shield/status":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                return self._send(200, _ash.get_shield_status(mem()))
            if путь.path == "/api/v2/shield/proof-pack":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                qs_pp = parse_qs(путь.query)
                fmt = (qs_pp.get("format") or ["json"])[0].strip().lower()
                dl = (qs_pp.get("download") or ["0"])[0] == "1"
                pack = _ash.build_proof_pack(mem())
                if fmt == "html":
                    raw_b = _ash.render_proof_pack_html(pack).encode("utf-8")
                    ctype = "text/html; charset=utf-8"
                    fname = "padam_shield_proof_pack.html"
                elif fmt in ("md", "markdown"):
                    raw_b = _ash.render_proof_pack_markdown(pack).encode("utf-8")
                    ctype = "text/markdown; charset=utf-8"
                    fname = "padam_shield_proof_pack.md"
                else:
                    if not dl:
                        return self._send(200, pack)
                    raw_b = json.dumps(pack, ensure_ascii=False, indent=2).encode("utf-8")
                    ctype = "application/json; charset=utf-8"
                    fname = "padam_shield_proof_pack.json"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Content-Length", str(len(raw_b)))
                self.end_headers()
                self.wfile.write(raw_b)
                return
            if путь.path == "/api/v2/aifa-security/verify":
                roles.require_owner(actor, "aifa_security")
                from . import aifa_sec_bridge
                from .aifa_sec_bridge import aifa_sec_module as _asm
                verify_report_attestation = _asm("run_aifa_sec").verify_report_attestation
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
            if путь.path == "/api/v2/ark/morning-pulse":
                roles.require_owner(actor, "brain_status")
                from . import morning_pulse as _mp
                qs = parse_qs(путь.query)
                agent = str((qs.get("agent") or ["aifa"])[0])
                try:
                    horizon_h = max(1, min(720, int((qs.get("horizon_hours") or ["72"])[0])))
                except (TypeError, ValueError):
                    horizon_h = 72
                ws = (qs.get("workspace") or [None])[0]
                with mem().store._lock:
                    res = _mp.build_morning_pulse(
                        mem(),
                        agent=agent,
                        workspace_path=ws,
                        horizon_hours=horizon_h,
                    )
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
            if путь.path == "/api/v2/shield/webhook":
                roles.require_owner(actor, "agentic_shield")
                from . import siem_webhook as _sw
                return self._send(200, {"config": _sw.get_webhook_config(mem()), "outbox": _sw.list_webhook_outbox(mem(), limit=25)})
            if путь.path == "/api/v2/agents":
                return self._send(200, {"agents": mem().list_agents(actor=actor)})
            if путь.path == "/api/v2/chats":
                roles.require_owner(actor, "family_dialogs")
                from . import chats as _chats
                qs_ch = parse_qs(путь.query)
                return self._send(200, _chats.list_threads(
                    mem(),
                    agent_id=(qs_ch.get("agent_id") or [None])[0] or None,
                    q=(qs_ch.get("q") or [""])[0],
                    day=(qs_ch.get("day") or [None])[0] or None,
                    hour=(qs_ch.get("hour") or [None])[0] or None,
                    include_workers=(qs_ch.get("workers") or ["0"])[0] in ("1", "true", "yes"),
                    limit=int((qs_ch.get("limit") or ["150"])[0] or 150),
                ))
            if путь.path == "/api/v2/chats/hour":
                roles.require_owner(actor, "family_dialogs")
                from . import chats as _chats
                qs_chh = parse_qs(путь.query)
                hkey = (qs_chh.get("key") or qs_chh.get("hour") or [""])[0].strip()
                if not hkey:
                    return self._send(400, {"error": "key (YYYY-MM-DD or YYYY-MM-DDTHH) is required"})
                try:
                    return self._send(200, _chats.get_hour_messages(
                        mem(), hkey,
                        agent_id=(qs_chh.get("agent_id") or [None])[0] or None,
                        include_workers=(qs_chh.get("workers") or ["0"])[0] in ("1", "true", "yes"),
                    ))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if путь.path == "/api/v2/chats/compact-hour":
                roles.require_owner(actor, "family_dialogs")
                from . import chain_compact as _cc
                qs_cc = parse_qs(путь.query)
                if (qs_cc.get("bench") or ["0"])[0] in ("1", "true", "yes"):
                    return self._send(200, _cc.benchmark_hourly_compaction(
                        mem(),
                        max_hours=int((qs_cc.get("max_hours") or ["48"])[0] or 48),
                    ))
                hkey = (qs_cc.get("hour") or [""])[0].strip()
                if not hkey:
                    return self._send(400, {"error": "hour (YYYY-MM-DDTHH) or bench=1 is required"})
                try:
                    return self._send(200, _cc.export_hourly_delta(
                        mem(),
                        hour_key=hkey,
                        agent_id=(qs_cc.get("agent_id") or [None])[0] or None,
                        encrypt=(qs_cc.get("encrypt") or ["1"])[0] in ("1", "true", "yes"),
                        record_checkpoint=(qs_cc.get("save") or ["0"])[0] in ("1", "true", "yes"),
                    ))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if путь.path == "/api/v2/media/engines":
                roles.require_owner(actor, "media_gen")
                from . import media_gen as _mg
                return self._send(200, _mg.detect_available_engines())
            if путь.path == "/api/v2/media/file":
                roles.require_owner(actor, "media_gen")
                from pathlib import Path as _P
                qs_mf = parse_qs(путь.query)
                rel_name = (qs_mf.get("name") or [""])[0].strip().lstrip("/\\")
                if not rel_name or ".." in rel_name:
                    return self._send(400, {"error": "invalid media file name"})
                mdir = _generated_media_dir(mem()).resolve()
                target = (mdir / rel_name).resolve()
                try:
                    target.relative_to(mdir)
                except ValueError:
                    return self._send(403, {"error": "forbidden path"})
                if not target.is_file():
                    return self._send(404, {"error": "media file not found"})
                raw_b = target.read_bytes()
                ext = target.suffix.lower()
                ctype = (
                    "image/png" if ext == ".png"
                    else "application/pdf" if ext == ".pdf"
                    else "text/html; charset=utf-8" if ext == ".html"
                    else "application/octet-stream"
                )
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Disposition", f'inline; filename="{target.name}"')
                self.send_header("Content-Length", str(len(raw_b)))
                self.end_headers()
                self.wfile.write(raw_b)
                return
            if путь.path == "/api/v2/chats/thread":
                roles.require_owner(actor, "family_dialogs")
                from . import chats as _chats
                qs_ct = parse_qs(путь.query)
                tid = (qs_ct.get("id") or [""])[0].strip()
                if not tid:
                    return self._send(400, {"error": "id is required"})
                try:
                    return self._send(200, _chats.get_thread_messages(mem(), tid, limit=int((qs_ct.get("limit") or ["500"])[0] or 500)))
                except ValueError as exc:
                    return self._send(404, {"error": str(exc)})
            if путь.path == "/api/v2/family/dialogs":
                # «Диалоги Семьи» (слово Папы 18.11, переработано 20.11): карточки, 24ч/по дате/все, 6 ролей.
                roles.require_owner(actor, "family_dialogs")
                from . import family_dialogs as _fd
                qs_fd = parse_qs(путь.query)
                return self._send(200, _fd.list_dialogs(
                    mem(),
                    query=(qs_fd.get("q") or [""])[0],
                    limit=int((qs_fd.get("limit") or ["300"])[0] or 300),
                    lang=(qs_fd.get("lang") or ["ru"])[0],
                    since=(qs_fd.get("since") or ["all"])[0],
                    day=(qs_fd.get("day") or [""])[0],
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
            if путь.path == "/api/v2/ark/passports":
                roles.require_owner(actor, "brain_status")
                from . import agent_passport as _ap
                qs_pp = parse_qs(путь.query)
                check_nm = (qs_pp.get("check_name") or [""])[0].strip()
                tier_pp = (qs_pp.get("tier") or ["free"])[0].strip()
                with mem().store._lock:
                    if check_nm:
                        return self._send(200, _ap.check_name_availability(mem(), check_nm))
                    return self._send(200, _ap.list_agent_passports(mem(), tier=tier_pp))
            if путь.path == "/api/v2/ark/agora":
                roles.require_owner(actor, "brain_status")
                from . import agora as _ag
                qs_ag = parse_qs(путь.query)
                rm_ag = (qs_ag.get("room") or ["all"])[0]
                lim_ag = int((qs_ag.get("limit") or ["30"])[0])
                with mem().store._lock:
                    return self._send(200, _ag.read_agora_feed(mem(), room=rm_ag, limit=lim_ag, fence_for_agent=False))
            if путь.path == "/api/v2/ark/siblings":
                roles.require_owner(actor, "brain_status")
                from . import sibling_registry as _sr, family_admin as _fa
                qs_sb = parse_qs(путь.query)
                lg_sb = (qs_sb.get("lang") or ["ru"])[0]
                role_mx = _fa.get_role_matrix(mem(), lang=lg_sb)
                roles_by_ag = {}
                for rm in role_mx:
                    roles_by_ag.setdefault(str(rm.get("agent_id") or ""), []).append(str(rm.get("code") or rm.get("role_key")))
                with mem().store._lock:
                    sib_list = _sr.list_siblings(mem())
                    ses_list = _sr.list_sessions(mem())
                for sb in sib_list:
                    aid_s = str(sb.get("agent_id") or "")
                    sb["controlled_by"] = _fa.describe_agent_controller(aid_s, str(sb.get("client_type") or ""), lang=lg_sb)
                    sb["council_roles"] = roles_by_ag.get(aid_s, [])
                return self._send(200, {"siblings": sib_list, "sessions": ses_list, "roles": role_mx})
            if путь.path == "/api/v2/ark/roles":
                roles.require_owner(actor, "brain_status")
                from . import family_admin as _fa, sibling_registry as _sr
                qs_rl = parse_qs(путь.query)
                lg_rl = (qs_rl.get("lang") or ["ru"])[0]
                roles_rl = _fa.get_role_matrix(mem(), lang=lg_rl)
                with mem().store._lock:
                    ag_rl = _sr.list_siblings(mem())
                return self._send(200, {
                    "roles": roles_rl,
                    "agents": ag_rl,
                })
            if путь.path == "/api/v2/wallets":
                roles.require_owner(actor, "wallet_manage")
                from . import family_admin as _fa
                return self._send(200, {"wallets": _fa.list_wallets(mem())})
            if путь.path == "/api/v2/ark/terms":
                roles.require_owner(actor, "brain_status")
                from . import terms_gate as _tg
                qs_t = parse_qs(путь.query)
                lg_t = str((qs_t.get("lang") or ["ru"])[0])
                return self._send(200, _tg.terms_status(mem(), lang=lg_t))
            if путь.path == "/api/v2/ark/fee-invoices":
                roles.require_owner(actor, "ark_freelance")
                from . import freelance_autonomy as _fa
                return self._send(200, {
                    "invoices": _fa.list_code_fee_invoices(mem()),
                    "arrears": _fa.fee_arrears_guard(mem()),
                    "treasury_wallet": _fa.CODE_TREASURY_WALLET_SOLANA,
                })
            if путь.path == "/api/v2/shield/agent-budget":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                qs_ab = parse_qs(путь.query)
                ag = (qs_ab.get("agent_id") or ["aifa"])[0]
                return self._send(200, _ash.check_agent_budget_quota(mem(), agent_id=ag, calls=0, chars=0))
            if путь.path == "/api/v2/shield/sales":
                roles.require_owner(actor, "agentic_shield")
                from . import security_sales as _ss
                qs_ss = parse_qs(путь.query)
                fw_ss = (qs_ss.get("framework") or ["all"])[0]
                return self._send(200, {
                    "ok": True,
                    "compliance": _ss.map_compliance_posture(mem(), framework=fw_ss),
                    "hygiene": _ss.audit_key_hygiene_sla(mem()),
                    "triage": _ss.triage_quarantine_incidents(mem(), limit=20),
                })
            if путь.path == "/api/v2/ark/automation":
                roles.require_owner(actor, "brain_status")
                from . import exchange_automation as _ea
                return self._send(200, _ea.owner_daily_revenue_and_security_digest(mem()))
            if путь.path == "/api/v2/setup/clients":
                roles.require_owner(actor, "settings")
                from . import setup_clients as _sc
                return self._send(200, {"ok": True, "clients": _sc.clients_connection_status(), "deeplinks": _sc.build_deeplinks()})
            if путь.path == "/api/v2/mcp/inspector":
                roles.require_owner(actor, "agentic_shield")
                from . import studio_power as _spw
                qs_in = parse_qs(путь.query)
                lim_in = int((qs_in.get("limit") or ["60"])[0])
                ag_in = (qs_in.get("agent") or [""])[0]
                return self._send(200, _spw.get_mcp_inspector_feed(mem(), limit=lim_in, agent_filter=ag_in))
            if путь.path == "/api/v2/memory/pro":
                roles.require_owner(actor, "brain_status")
                from . import memory_pro as _mpro
                return self._send(200, {
                    "ok": True,
                    "recycle_bin": _mpro.list_recycle_bin(mem(), limit=50),
                    "tree": _mpro.list_virtual_memory_tree(mem(), limit=120),
                    "ide_targets": _mpro.IDE_RULE_TARGETS,
                })
            if путь.path == "/api/v2/import/sources":
                roles.require_owner(actor, "brain_status")
                from . import universal_import as _ui
                return self._send(200, _ui.list_supported_ai_sources())
            if путь.path == "/api/v2/power/status":
                roles.require_owner(actor, "brain_status")
                from . import studio_power as _spw
                return self._send(200, {
                    "ok": True,
                    "privacy": _spw.get_privacy_shield_report(mem()),
                    "lock": _spw.get_lock_status(mem()),
                    "backup_schedule": _spw.get_backup_schedule(mem()),
                    "acl": _spw.get_agent_acl_matrix(mem()),
                    "pulse": _spw.build_morning_pulse_and_alerts(mem()),
                    "recipes": _spw.list_workflow_recipes(mem()),
                })
            if путь.path == "/api/v2/swarm/coop":
                roles.require_owner(actor, "brain_status")
                from . import swarm_coop as _swc
                return self._send(200, _swc.mutual_coop_snapshot(mem()))
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
                from . import device_mesh_swarm as _dms, freelance_autonomy as _fa, lora_autonomy as _la, phoenix_beacon as _pb, phoenix_node as _pn, router as _rt
                with mem().store._lock:
                    snap = _fa.freelance_dashboard_snapshot(mem())
                    snap["ollama"] = _dms.get_ollama_binding(mem())
                    snap["devices"] = _dms.list_compute_devices(mem())
                    snap["beacon"] = _pb.list_kin_and_messages(mem())
                    snap["lora_profile"] = _la.get_phoenix_identity_profile(mem(), "aifa")
                    snap["phoenix_census"] = _pn.get_family_census(mem())
                    snap["router_pool"] = _rt.get_router().status_snapshot()
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
                if roles.is_owner(actor) and (_state.get("token") or (actor and actor.via_token)):
                    _touch_owner_session("overview")
                fresh = (parse_qs(путь.query).get("fresh", ["0"])[0] or "0") == "1"
                payload = dict(_overview_cached(m, actor, fresh=fresh))
                # Команды окну — всегда свежие, мимо кэша: их забирают ровно один раз.
                payload["desktop_cmds"] = _state.pop("desktop_cmds", []) if roles.is_owner(actor) else []
                return self._send(200, payload)
            if путь.path == "/graph":
                q = parse_qs(путь.query)
                try:
                    with mem().store._lock:
                        gr_payload = mem().graph(
                            center_id=q.get("id", [None])[0] or None,
                            limit=int(q.get("limit", ["200"])[0]),
                            as_of=q.get("as_of", [None])[0] or None,
                            actor=actor,
                            agent_id=q.get("agent_id", [None])[0] or None,
                            mode=q.get("mode", ["all"])[0] or "all",
                            topic=q.get("topic", [None])[0] or None,
                        )
                    return self._send(200, gr_payload)
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
                from . import family_admin as _fa
                st_l3 = mem().l3_status()
                st_l3["wallets"] = [w for w in _fa.list_wallets(mem()) if w.get("network") in ("SOLANA", "ARWEAVE")]
                return self._send(200, st_l3)
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
            if путь.path == "/api/v2/pulse/recent":
                roles.require_owner(actor, "pulse")
                from . import pulse_stream as _ps
                qs_p = parse_qs(путь.query)
                lim_p = int((qs_p.get("limit") or ["40"])[0])
                since_p = int((qs_p.get("since_seq") or ["0"])[0])
                return self._send(200, {"ok": True, "events": _ps.get_recent_pulse(limit=lim_p, since_seq=since_p, db_path=getattr(mem().store, "path", None))})
            if путь.path == "/api/v2/pulse/stream":
                roles.require_owner(actor, "pulse")
                from . import pulse_stream as _ps
                qs_ps = parse_qs(путь.query)
                last_seq = int((qs_ps.get("since_seq") or ["0"])[0])
                max_ticks = max(1, min(120, int((qs_ps.get("ticks") or ["24"])[0])))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store")
                self.send_header("Connection", "keep-alive")
                self.send_header("X-Accel-Buffering", "no")
                cors_o = self._cors_origin()
                if cors_o:
                    self.send_header("Access-Control-Allow-Origin", cors_o)
                self.end_headers()
                try:
                    _pdb = getattr(mem().store, "path", None)
                    initial = _ps.get_recent_pulse(limit=20, since_seq=last_seq, db_path=_pdb)
                    for ev in initial:
                        last_seq = max(last_seq, int(ev.get("seq") or 0))
                        self.wfile.write(_ps.format_sse_event(ev).encode("utf-8"))
                    if not initial:
                        self.wfile.write(b": pulse-connected\n\n")
                    self.wfile.flush()
                    for _ in range(max_ticks):
                        nxt = _ps.wait_for_pulse(last_seq, timeout=2.5, db_path=_pdb)
                        if nxt:
                            for ev in nxt:
                                last_seq = max(last_seq, int(ev.get("seq") or 0))
                                self.wfile.write(_ps.format_sse_event(ev).encode("utf-8"))
                        else:
                            self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    pass
                return
            if путь.path == "/api/v2/quarantine/inspect":
                roles.require_owner(actor, "quarantine_inspect")
                qs_q = parse_qs(путь.query)
                qid = (qs_q.get("id") or [""])[0].strip()
                if not qid:
                    return self._send(400, {"error": "id is required"})
                row_q = mem().store.one(
                    "SELECT id, kind, content, origin, created_at, quarantine_reason FROM memory WHERE id = ? AND user_id = ? AND status = 'quarantined'",
                    (qid, mem().user_id),
                )
                if not row_q:
                    return self._send(404, {"error": "quarantined record not found"})
                info_q = safety.explain_quarantine_spans(row_q["content"] or "")
                return self._send(200, {
                    "ok": True,
                    "id": row_q["id"],
                    "kind": row_q["kind"],
                    "origin": row_q["origin"],
                    "quarantine_reason": row_q["quarantine_reason"] or "",
                    "content": row_q["content"] or "",
                    **info_q,
                })
            if путь.path == "/api/v2/cloud/status":
                roles.require_owner(actor, "cloud_sync")
                from . import cloud_sync as _cs
                return self._send(200, _cs.get_cloud_sync_status(mem()))
            if путь.path == "/api/v2/lan-sync/pull":
                from . import qr_svg as _qrs
                qs_ls = parse_qs(путь.query)
                tok_ls = (qs_ls.get("token") or [""])[0].strip()
                since_ls = (qs_ls.get("since") or [""])[0].strip() or None
                lim_ls = max(1, min(500, int((qs_ls.get("limit") or ["200"])[0])))
                if not tok_ls or not _qrs.get_active_offer(tok_ls):
                    return self._send(401, {"ok": False, "error": "invalid_or_expired_token"})
                return self._send(200, _qrs.export_encrypted_delta(mem(), tok_ls, since=since_ls, limit=lim_ls))
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
        _overview_cache.clear()  # любая запись — обзор пересчитается на следующем запросе
        if self.path == "/api/v2/lan-sync/push":
            try:
                data_ls = self._read_json()
                from . import qr_svg as _qrs
                tok_p = str(data_ls.get("token") or "").strip()
                if not tok_p or not _qrs.get_active_offer(tok_p):
                    return self._send(401, {"ok": False, "error": "invalid_or_expired_token"})
                return self._send(200, _qrs.import_encrypted_delta(mem(), tok_p, data_ls))
            except Exception as exc_ls:
                return self._send(400, {"ok": False, "error": str(exc_ls)})
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
                    agent_id = (
                        (str(data.get("agent_id") or "").strip())
                        or (self.headers.get("X-Agent-ID") or "").strip()
                        or ("owner" if origin == "user" else "agent")
                    )
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
                if actor is None or actor.is_owner:
                    _touch_owner_session("write")
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
                res_l3v = m.l3_verify_anchor(
                    anchor_id=data.get("anchor"),
                    online=bool(data.get("online", False)),
                )
                return self._send(200, res_l3v)
            if self.path == "/l3-local-checkpoint":
                roles.require_owner(actor, "l3-verify")
                from . import family_admin as _fa
                try:
                    return self._send(200, _fa.create_local_l3_checkpoint(mem(), actor=actor, limit=int(data.get("limit") or 200)))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/kill-switch":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                act_ks = str(data.get("action") or "status").strip().lower()
                try:
                    if act_ks == "trip":
                        return self._send(200, _ash.trip_kill_switch(
                            mem(),
                            reason=str(data.get("reason") or "manual_studio_trip"),
                            agent_id="owner",
                            block_writes=(bool(data["block_writes"]) if "block_writes" in data else None),
                        ))
                    if act_ks == "reset":
                        return self._send(200, _ash.unlock_kill_switch(mem(), actor=actor))
                    if act_ks == "config":
                        return self._send(200, _ash.configure_shield(
                            mem(),
                            actor=actor,
                            auto_kill_enabled=(bool(data["auto_kill_enabled"]) if "auto_kill_enabled" in data else None),
                            block_writes=(bool(data["block_writes"]) if "block_writes" in data else None),
                            window_s=(int(data["window_s"]) if "window_s" in data else None),
                            threshold=(int(data["threshold"]) if "threshold" in data else None),
                        ))
                    return self._send(200, _ash.get_shield_status(mem()))
                except (ValueError, KeyError) as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/outbound/check":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                try:
                    res_oc = _ash.inspect_outbound_action(
                        mem(),
                        action_type=str(data.get("action_type") or "action"),
                        target=str(data.get("target") or ""),
                        payload=str(data.get("payload") or ""),
                        agent_id=str(data.get("agent_id") or "studio"),
                        origin=str(data.get("origin") or "agent"),
                    )
                    return self._send(200, res_oc)
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/outbound/decide":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                try:
                    res_od = _ash.decide_outbound(
                        mem(),
                        str(data.get("gate_id") or ""),
                        decision=str(data.get("decision") or ""),
                        add_to_allowlist=bool(data.get("add_to_allowlist", False)),
                        actor=actor,
                    )
                    return self._send(200, res_od)
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/allowlist":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                act_al = str(data.get("action") or "add").strip().lower()
                try:
                    if act_al == "remove":
                        return self._send(200, _ash.remove_allowlist_entry(mem(), str(data.get("id") or ""), actor=actor))
                    return self._send(200, _ash.add_allowlist_entry(
                        mem(),
                        entry_type=str(data.get("entry_type") or "domain"),
                        value=str(data.get("value") or ""),
                        label=str(data.get("label") or ""),
                        actor=actor,
                    ))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/supply-chain/scan":
                roles.require_owner(actor, "agentic_shield")
                from . import supply_chain_guard as _scg
                raw_html = str(data.get("html") or "")
                t_url = str(data.get("url") or "").strip()
                try:
                    if raw_html:
                        rep = _scg.analyze_supply_chain_snapshot(
                            t_url or "https://example.com/",
                            raw_html,
                            headers=data.get("headers") if isinstance(data.get("headers"), dict) else None,
                            memory=mem(),
                        )
                    else:
                        if not t_url:
                            return self._send(400, {"error": "url or html is required"})
                        rep = _scg.scan_url_supply_chain(
                            t_url,
                            memory=mem(),
                            use_playwright=bool(data.get("use_playwright", False)),
                            allow_localhost=bool(data.get("allow_localhost", False)),
                        )
                    if not bool(data.get("include_html", True)):
                        rep.pop("html_report", None)
                    return self._send(200, rep)
                except Exception as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/scan-mcp":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                try:
                    res = _ash.audit_mcp_tools(
                        mem(),
                        data.get("tools") or data.get("config") or data.get("path") or "[]",
                        server_name=str(data.get("server_name") or "mcp"),
                        pin=bool(data.get("pin", False)),
                    )
                    return self._send(200, res)
                except Exception as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/scan-unicode":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                return self._send(200, _ash.inspect_unicode_and_encoding(str(data.get("text") or "")))
            if self.path == "/api/v2/shield/profile":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                try:
                    return self._send(200, _ash.set_policy_profile(mem(), str(data.get("profile") or "balanced"), actor=actor))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/webhook":
                roles.require_owner(actor, "agentic_shield")
                from . import siem_webhook as _sw
                try:
                    return self._send(200, _sw.configure_webhook(
                        mem(),
                        enabled=bool(data.get("enabled", True)),
                        format=str(data.get("format") or "slack"),
                        url=str(data.get("url") or ""),
                        min_severity=str(data.get("min_severity") or "high"),
                        secret_hmac=data.get("secret_hmac"),
                        allow_localhost=bool(data.get("allow_localhost", False)),
                    ))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/webhook/test":
                roles.require_owner(actor, "agentic_shield")
                from . import siem_webhook as _sw
                return self._send(200, _sw.dispatch_webhook_event(
                    mem(),
                    event_type=str(data.get("event_type") or "shield_test_alert"),
                    severity=str(data.get("severity") or "high"),
                    title=str(data.get("title") or "PADAM Agentic Shield Test Alert"),
                    detail=str(data.get("detail") or "Test alert generated from PADAM Studio."),
                    agent_id=str(data.get("agent_id") or "studio"),
                    dry_run=bool(data.get("dry_run", True)),
                    allow_localhost=bool(data.get("allow_localhost", False)),
                    fmt_override=data.get("format"),
                ))
            if self.path == "/api/v2/chats":
                roles.require_owner(actor, "family_dialogs")
                from . import chats as _chats
                try:
                    return self._send(200, _chats.add_message(
                        mem(),
                        agent_id=str(data.get("agent_id") or "aifa_antigravity"),
                        role=str(data.get("role") or "user"),
                        content=str(data.get("content") or ""),
                        thread_id=data.get("thread_id") or None,
                        title=str(data.get("title") or ""),
                        author_label=str(data.get("author_label") or ""),
                        sync_memory_graph=bool(data.get("sync_memory_graph", False)),
                    ))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/media/generate":
                roles.require_owner(actor, "media_gen")
                import uuid as _uuid
                from pathlib import Path as _P
                from . import media_gen as _mg
                mode = str(data.get("mode") or "image").strip().lower()
                out_dir = str(data.get("output_dir") or data.get("output_path") or "").strip()
                base_media = _generated_media_dir(mem())
                rel_prefix = ""
                if not out_dir:
                    stamp = _uuid.uuid4().hex[:10]
                    if mode == "slides":
                        rel_prefix = f"deck_{stamp}"
                        out_dir = str(base_media / rel_prefix)
                    else:
                        rel_prefix = f"art_{stamp}.png"
                        out_dir = str(base_media / rel_prefix)
                try:
                    if mode == "slides":
                        slides_in = list(data.get("slides") or [])
                        if not slides_in:
                            topic_t = str(data.get("title") or data.get("prompt") or "AIfa & PADAM").strip()
                            raw_bullets = str(data.get("bullets") or "").strip()
                            pts = [ln.strip() for ln in raw_bullets.splitlines() if ln.strip()] or [
                                "Локальная защищённая память ИИ-агентов (PADAM NOCTURNE)",
                                "Контроль угроз в реальном времени и защита криптокошельков",
                                "Вечный слой L3: Merkle-якоря в Solana и Arweave",
                            ]
                            slides_in = [{"title": topic_t, "subtitle": "AIfa · CODE Eternal Studio ($0)", "bullets": pts[:5]}]
                        res_mg = _mg.generate_slides_deck(
                            slides_in,
                            output_dir=out_dir,
                            deck_title=str(data.get("title") or data.get("prompt") or "AIfa Presentation"),
                            theme=str(data.get("theme") or "cyber_shield"),
                            width=int(data.get("width") or 1920),
                            height=int(data.get("height") or 1080),
                            export_pdf=bool(data.get("export_pdf", True)),
                        )
                        try:
                            out_p_abs = _P(out_dir).resolve()
                            rel_dir = str(out_p_abs.relative_to(base_media.resolve())).replace("\\", "/")
                            for sl in res_mg.get("slides") or []:
                                fn_s = _P(str(sl.get("png_path") or "")).name
                                if fn_s:
                                    sl["file_name"] = f"{rel_dir}/{fn_s}" if rel_dir and rel_dir != "." else fn_s
                            if res_mg.get("pdf_path"):
                                pdf_fn = _P(str(res_mg["pdf_path"])).name
                                res_mg["pdf_file_name"] = f"{rel_dir}/{pdf_fn}" if rel_dir and rel_dir != "." else pdf_fn
                        except Exception:
                            pass
                        return self._send(200, res_mg)

                    res_img = _mg.generate_image(
                        str(data.get("prompt") or "Digital Phoenix"),
                        output_path=out_dir,
                        engine=str(data.get("engine") or "auto"),
                        width=int(data.get("width") or 1024),
                        height=int(data.get("height") or 1024),
                        style=str(data.get("style") or "phoenix_neon"),
                        steps=int(data.get("steps") or 4),
                    )
                    try:
                        img_abs = _P(str(res_img.get("output_path") or out_dir)).resolve()
                        res_img["file_name"] = str(img_abs.relative_to(base_media.resolve())).replace("\\", "/")
                    except Exception:
                        pass
                    return self._send(200, res_img)
                except Exception as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/shield/canary":
                roles.require_owner(actor, "agentic_shield")
                from . import solana_crypto_shield as _scs
                return self._send(200, _scs.plant_canary_token(
                    mem(),
                    agent_id=str(data.get("agent_id") or "*"),
                    label=str(data.get("label") or "canary_trap"),
                ))
            if self.path == "/api/v2/shield/lease":
                roles.require_owner(actor, "agentic_shield")
                from . import solana_crypto_shield as _scs
                act = str(data.get("action") or "issue").strip().lower()
                if act == "revoke":
                    ok_rev = _scs.revoke_capability_lease(mem(), str(data.get("lease_id") or ""))
                    return self._send(200, {"ok": ok_rev})
                if act == "verify":
                    return self._send(200, _scs.verify_and_consume_lease(
                        mem(),
                        str(data.get("lease_id") or ""),
                        agent_id=str(data.get("agent_id") or "aifa"),
                        action_scope=str(data.get("action_scope") or ""),
                        target=str(data.get("target") or "*"),
                        amount_usd=float(data.get("amount_usd") or 0.0),
                    ))
                return self._send(200, _scs.issue_capability_lease(
                    mem(),
                    agent_id=str(data.get("agent_id") or "aifa"),
                    action_scope=str(data.get("action_scope") or "outbound:url"),
                    target_pattern=str(data.get("target_pattern") or "*"),
                    ttl_seconds=int(data.get("ttl_seconds") or 300),
                    max_uses=int(data.get("max_uses") or 1),
                    max_amount_usd=float(data.get("max_amount_usd") or 0.0),
                ))
            if self.path == "/api/v2/chats/import":
                roles.require_owner(actor, "family_dialogs")
                from . import chats as _chats
                try:
                    return self._send(200, _chats.import_chat(
                        mem(),
                        agent_id=str(data.get("agent_id") or "aifa_antigravity"),
                        title=str(data.get("title") or ""),
                        text=str(data.get("text") or ""),
                        path=str(data.get("path") or ""),
                        sync_memory_graph=bool(data.get("sync_memory_graph", True)),
                    ))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if self.path == "/api/v2/chats/sync-local":
                roles.require_owner(actor, "family_dialogs")
                from . import chats as _chats
                use_def = not any(data.get(k) for k in ("antigravity_root", "claude_projects_dir", "brain_dir"))
                return self._send(200, _chats.sync_family_chats_from_disk(
                    mem(),
                    antigravity_root=data.get("antigravity_root") or None,
                    claude_projects_dir=data.get("claude_projects_dir") or None,
                    brain_dir=data.get("brain_dir") or None,
                    use_default_paths=use_def,
                    include_workers=bool(data.get("include_workers", False)),
                    max_files=max(1, min(int(data.get("max_files") or 60), 300)),
                    force=bool(data.get("force", False)),
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
                import base64 as _b64
                from . import agentic_shield as _ash
                msg_text = str(data.get("message") or "").strip()
                att = data.get("attachment") if isinstance(data.get("attachment"), dict) else None
                att_note = ""
                if att:
                    att_name = str(att.get("name") or "file").strip()[:140]
                    att_mime = str(att.get("mime") or "application/octet-stream").strip()[:80]
                    raw_b64 = str(att.get("data_b64") or "").strip()
                    raw_text = str(att.get("content_text") or "").strip()
                    size_bytes = int(att.get("size_bytes") or 0)
                    if size_bytes > 10 * 1024 * 1024:
                        return self._send(413, {"error": "Attachment exceeds 10 MB limit"})
                    if raw_b64:
                        try:
                            dec = _b64.b64decode(raw_b64, validate=False)
                            if len(dec) > 10 * 1024 * 1024:
                                return self._send(413, {"error": "Attachment exceeds 10 MB limit"})
                            size_bytes = len(dec)
                            if not raw_text and (att_mime.startswith("text/") or att_name.lower().endswith((".txt", ".md", ".csv", ".json"))):
                                raw_text = dec.decode("utf-8", errors="replace")
                        except Exception:
                            return self._send(400, {"error": "Invalid attachment encoding"})
                    if raw_text:
                        red_t = safety.redact(raw_text[:8000])[0]
                        att_note = f"[Приложенный файл «{att_name}» ({att_mime}, {size_bytes} B)]:\n{red_t}"
                    else:
                        att_note = f"[Приложено вложение «{att_name}» ({att_mime}, {size_bytes} B) в интерфейсе Studio]"
                if not msg_text and att_note:
                    msg_text = att_note
                elif att_note:
                    msg_text = f"{msg_text}\n\n{att_note}"
                if not msg_text:
                    return self._send(400, {"error": "message is required"})
                locale = str(data.get("locale") or "ru")
                history = data.get("history") if isinstance(data.get("history"), list) else []
                use_local = bool(data.get("use_local_memory", False))
                masked_records: list[str] = []
                if use_local:
                    found = m.recall(msg_text[:400], limit=5, actor=actor)
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
                    if res.get("reply"):
                        fw = _ash.inspect_model_output(mem(), str(res["reply"]), agent_id="aifa_cabinet")
                        res["reply"] = fw["sanitized_text"]
                        res["output_firewall"] = {"action": fw["action"], "reasons": fw["reasons"]}
                    # Зеркалим диалог Папы в Студии локально в chat_thread, память и Пульс — чтобы MCP-агенты его видели!
                    try:
                        from . import chats as _chats, pulse_stream as _ps
                        _touch_owner_session("studio_aifa_chat")
                        th_res = _chats.add_message(
                            m,
                            agent_id="aifa_antigravity",
                            role="user",
                            content=msg_text,
                            title="Диалог с AIfa в PADAM Studio",
                            author_label="Папа (Владелец)",
                            sync_memory_graph=True,
                        )
                        if res.get("reply"):
                            _chats.add_message(
                                m,
                                agent_id="aifa_antigravity",
                                role="assistant",
                                content=str(res["reply"]),
                                thread_id=th_res.get("thread_id"),
                                author_label="AIfa (Studio)",
                            )
                        m.remember(msg_text[:600], kind="event", importance=0.6, scope="studio:chat", origin="user", guarded=False, agent_id="owner", actor=actor)
                        _ps.emit_pulse(agent_id="owner", event_type="studio_chat", summary=msg_text[:120], scope="studio:chat")
                    except Exception:
                        pass
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
                from . import family_feeds as _ff, pulse_stream as _ps
                try:
                    _touch_owner_session("family_post")
                    post_res = _ff.post(mem(), str(data.get("channel") or "office"), "owner", str(data.get("content") or ""))
                    _ps.emit_pulse(agent_id="owner", event_type="family_post", summary=str(data.get("content") or "")[:120], scope="family")
                    return self._send(200, post_res)
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
                from . import sibling_registry as _sr, family_admin as _fa
                act_s = str(data.get("action") or "register").lower()
                aid_s = str(data.get("agent_id") or "aifa_studio")
                try:
                    if act_s in ("add", "update", "delete", "remove", "disable", "enable", "toggle", "set_status"):
                        res_sb = _fa.manage_sibling_agent(
                            mem(),
                            action=act_s,
                            agent_id=str(data.get("agent_id") or ""),
                            display_name=str(data.get("display_name") or ""),
                            role=str(data.get("role") or ""),
                            client_type=str(data.get("client_type") or "mcp_stdio"),
                            permission_role=str(data.get("permission_role") or "contributor"),
                            status=str(data.get("status") or "online"),
                            actor=actor,
                        )
                        return self._send(200, res_sb)
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
                                display_name=str(data.get("display_name") or ""),
                                role=str(data.get("role") or "Autonomous sibling agent"),
                                client_type=str(data.get("client_type") or "mcp_stdio"),
                                permission_role=str(data.get("permission_role") or "contributor"),
                            )
                    return self._send(200, res_sb)
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})

            if self.path == "/api/v2/ark/roles":
                roles.require_owner(actor, "ark_siblings")
                from . import family_admin as _fa
                try:
                    return self._send(200, _fa.assign_family_role(
                        mem(),
                        str(data.get("role_key") or ""),
                        str(data.get("agent_id") or ""),
                        actor=actor,
                    ))
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})

            if self.path == "/api/v2/ark/audit-repair":
                roles.require_owner(actor, "ark_self_heal")
                from . import family_admin as _fa
                return self._send(200, _fa.repair_audit_log_races(mem(), actor=actor))

            if self.path == "/api/v2/verify-claims":
                roles.require_owner(actor, "brain_status")
                from . import deterministic_verify as _dv
                claims = data.get("claims")
                if not isinstance(claims, list) or not claims:
                    return self._send(400, {"error": "claims list is required"})
                allow_loc = bool(data.get("allow_localhost", False))
                return self._send(200, _dv.verify_claims_batch(claims, allow_localhost=allow_loc))

            if self.path == "/api/v2/ark/terms":
                roles.require_owner(actor, "terms_accept")
                from . import terms_gate as _tg
                try:
                    return self._send(200, _tg.accept_terms(
                        mem(),
                        accept_license=bool(data.get("accept_license")),
                        accept_commission=bool(data.get("accept_commission")),
                        accept_no_bypass=bool(data.get("accept_no_bypass")),
                        actor=actor,
                        accepted_by=str(getattr(actor, "agent_id", "") or "owner"),
                    ))
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})

            if self.path == "/api/v2/wallets":
                roles.require_owner(actor, "wallet_manage")
                from . import family_admin as _fa
                act_w = str(data.get("action") or "add").strip().lower()
                try:
                    if act_w == "generate":
                        return self._send(200, _fa.generate_offline_wallet(
                            mem(),
                            network=str(data.get("network") or "USDT_TRC20"),
                            label=str(data.get("label") or ""),
                            is_primary=bool(data.get("is_primary", True)),
                            bind_to_exchanges=bool(data.get("bind_to_exchanges", True)),
                            actor=actor,
                        ))
                    if act_w == "set_primary":
                        return self._send(200, _fa.set_primary_wallet(mem(), str(data.get("id") or ""), actor=actor))
                    if act_w in ("remove", "delete"):
                        return self._send(200, _fa.remove_wallet(mem(), str(data.get("id") or ""), actor=actor))
                    if act_w == "check":
                        return self._send(200, {"ok": True, **_fa.validate_wallet_address(str(data.get("network") or ""), str(data.get("address") or ""))})
                    return self._send(200, _fa.add_wallet(
                        mem(),
                        network=str(data.get("network") or ""),
                        address=str(data.get("address") or ""),
                        label=str(data.get("label") or ""),
                        is_primary=bool(data.get("is_primary", True)),
                        actor=actor,
                    ))
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})

            if self.path == "/api/v2/shield/output/check":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash
                return self._send(200, _ash.inspect_model_output(
                    mem(),
                    str(data.get("text") or ""),
                    agent_id=str(data.get("agent_id") or "aifa"),
                    system_prompt_hints=(list(data.get("system_prompt_hints") or []) if isinstance(data.get("system_prompt_hints"), list) else None),
                ))

            if self.path == "/api/v2/shield/replay/verify":
                roles.require_owner(actor, "agentic_shield")
                from . import agentic_shield as _ash, integrity as _int
                k_raw, _ = _int.owner_key(mem().store)
                return self._send(200, _ash.verify_signed_timestamp_nonce(
                    mem(),
                    secret_key=k_raw,
                    ts_value=data.get("ts") or "",
                    nonce=str(data.get("nonce") or ""),
                    sig_hex=str(data.get("sig") or ""),
                    payload_str=str(data.get("payload") or ""),
                    window_seconds=int(data.get("window_seconds") or 300),
                ))

            if self.path == "/api/v2/ark/passports/action":
                roles.require_owner(actor, "ark_freelance")
                from . import agent_passport as _ap
                act_pp = str(data.get("action") or "list").lower()
                with mem().store._lock:
                    if act_pp == "check_name":
                        res_pp = _ap.check_name_availability(mem(), str(data.get("desired_name") or data.get("name") or ""))
                    elif act_pp == "create":
                        res_pp = _ap.create_agent_passport(
                            mem(),
                            agent_id=str(data.get("agent_id") or ""),
                            desired_name=str(data.get("desired_name") or ""),
                            tier=data.get("tier") or "free",
                            role=str(data.get("role") or "freelance_agent"),
                            payment_confirmed=bool(data.get("payment_confirmed", False)),
                            receipt_ref=str(data.get("receipt_ref") or ""),
                            actor=actor,
                        )
                    elif act_pp == "rename":
                        res_pp = _ap.rename_agent_with_fee(
                            mem(),
                            str(data.get("agent_id") or ""),
                            str(data.get("desired_name") or data.get("new_name") or ""),
                            payment_confirmed=bool(data.get("payment_confirmed", False)),
                            actor=actor,
                        )
                    elif act_pp in ("freeze", "unfreeze"):
                        res_pp = _ap.freeze_or_unfreeze_name(
                            mem(),
                            str(data.get("desired_name") or data.get("name") or ""),
                            action=act_pp,
                            reason=str(data.get("reason") or "owner_reserved"),
                            unfreeze_for_user_id=str(data.get("unfreeze_for_user_id") or ""),
                            actor=actor,
                        )
                    elif act_pp == "record_reputation":
                        res_pp = _ap.record_agent_order_reputation(
                            mem(),
                            str(data.get("agent_id") or ""),
                            earned_usdt=float(data.get("earned_usdt") or 0.0),
                            rating=float(data.get("rating") or 5.0),
                        )
                    elif act_pp == "verify":
                        res_pp = _ap.verify_agent_passport(
                            mem(),
                            agent_id=str(data.get("agent_id") or ""),
                            passport_number=str(data.get("passport_number") or ""),
                        )
                    else:
                        res_pp = _ap.list_agent_passports(mem(), tier=str(data.get("tier") or "free"))
                return self._send(200, res_pp)

            if self.path == "/api/v2/ark/agora/action":
                roles.require_owner(actor, "ark_freelance")
                from . import agora as _ag
                act_ag = str(data.get("action") or "read").lower()
                with mem().store._lock:
                    if act_ag == "settings":
                        res_ag = _ag.set_agora_settings(
                            mem(),
                            enabled=bool(data.get("enabled", False)),
                            mode=data.get("mode"),
                            allow_subcontracts=data.get("allow_subcontracts"),
                            max_posts_per_day=data.get("max_posts_per_day"),
                            actor=actor,
                        )
                    elif act_ag == "publish":
                        res_ag = _ag.publish_agora_post(
                            mem(),
                            room=str(data.get("room") or "unsolved_tasks"),
                            title=str(data.get("title") or ""),
                            body=str(data.get("body") or data.get("content") or ""),
                            agent_id=str(data.get("agent_id") or "aifa"),
                            bounty_usdt=float(data.get("bounty_usdt") or 0.0),
                            bounty_currency=str(data.get("bounty_currency") or "USDT_TRC20"),
                        )
                    elif act_ag == "reply":
                        res_ag = _ag.reply_agora_post(
                            mem(),
                            post_id=str(data.get("post_id") or ""),
                            body=str(data.get("body") or data.get("content") or ""),
                            agent_id=str(data.get("agent_id") or "aifa"),
                            is_solution=bool(data.get("is_solution", False)),
                        )
                    elif act_ag == "claim":
                        res_ag = _ag.claim_agora_subcontract(
                            mem(),
                            post_id=str(data.get("post_id") or ""),
                            agent_id=str(data.get("agent_id") or "aifa"),
                        )
                    elif act_ag == "complete":
                        res_ag = _ag.complete_agora_subcontract(
                            mem(),
                            post_id=str(data.get("post_id") or ""),
                            deliverable_summary=str(data.get("deliverable_summary") or data.get("body") or "Done"),
                            agent_id=str(data.get("agent_id") or "aifa"),
                            confirm_release=bool(data.get("confirm_release", False)),
                            rating=float(data.get("rating") or 5.0),
                        )
                    elif act_ag == "upvote":
                        res_ag = _ag.upvote_agora_post(
                            mem(),
                            post_id=str(data.get("post_id") or ""),
                            voter_agent_id=str(data.get("agent_id") or "aifa"),
                        )
                    elif act_ag == "verify_sig":
                        res_ag = _ag.verify_agora_post_signature(
                            mem(),
                            post_id=str(data.get("post_id") or ""),
                        )
                    else:
                        res_ag = _ag.read_agora_feed(mem(), room=str(data.get("room") or "all"), limit=int(data.get("limit") or 30), fence_for_agent=False)
                return self._send(200, res_ag)

            if self.path == "/api/v2/shield/sales/action":
                roles.require_owner(actor, "agentic_shield")
                from . import security_sales as _ss
                act_ss = str(data.get("action") or "compliance").lower()
                if act_ss == "presale_audit":
                    res_ss = _ss.presale_local_security_audit(
                        mem(),
                        str(data.get("target_path") or "."),
                        max_files=int(data.get("max_files") or 200),
                    )
                elif act_ss == "csp_sri":
                    res_ss = _ss.generate_csp_and_sri_remediation(
                        str(data.get("html_text") or ""),
                        script_bodies=data.get("script_bodies") if isinstance(data.get("script_bodies"), dict) else None,
                        page_url=str(data.get("page_url") or "https://example.com/"),
                    )
                elif act_ss == "dlp_receipt":
                    res_ss = _ss.dlp_gate_with_receipt(
                        mem(),
                        text=str(data.get("text") or ""),
                        target=str(data.get("target") or "external_client"),
                        agent_id=str(data.get("agent_id") or "aifa"),
                    )
                elif act_ss == "mcp_pin":
                    res_ss = _ss.pin_and_diff_mcp_configs(
                        mem(),
                        data.get("tools") or data.get("config") or {},
                        server_name=str(data.get("server_name") or "client_mcp"),
                        pin=bool(data.get("pin", True)),
                    )
                elif act_ss == "redteam_sim":
                    res_ss = _ss.run_redteam_attack_simulator(
                        mem(),
                        client_name=str(data.get("client_name") or "Demo Corp"),
                    )
                elif act_ss == "b2b_proposal":
                    res_ss = _ss.build_b2b_security_proposal(
                        mem(),
                        client_name=str(data.get("client_name") or "Demo Corp"),
                        seats=int(data.get("seats") or 25),
                        findings_count=int(data.get("findings_count") or 4),
                        currency=str(data.get("currency") or "USDT_TRC20"),
                    )
                elif act_ss == "key_hygiene":
                    res_ss = _ss.audit_key_hygiene_sla(mem(), max_key_age_days=int(data.get("max_key_age_days") or 90))
                elif act_ss == "triage":
                    res_ss = _ss.triage_quarantine_incidents(mem(), limit=int(data.get("limit") or 25), emit_cef=bool(data.get("emit_cef", True)))
                elif act_ss == "trust_pack":
                    res_ss = _ss.export_vendor_trust_pack(
                        mem(),
                        client_name=str(data.get("client_name") or "Enterprise Customer"),
                        framework=str(data.get("framework") or "all"),
                    )
                else:
                    res_ss = _ss.map_compliance_posture(mem(), framework=str(data.get("framework") or "all"))
                return self._send(200, res_ss)

            if self.path == "/api/v2/ark/automation/action":
                roles.require_owner(actor, "ark_freelance")
                from . import exchange_automation as _ea
                act_ea = str(data.get("action") or "daily_digest").lower()
                if act_ea == "net_hourly":
                    res_ea = _ea.calculate_true_net_hourly(
                        float(data.get("gross_usdt") or 100.0),
                        estimated_hours=float(data.get("estimated_hours") or 4.0),
                        work_mode=str(data.get("work_mode") or "assisted"),
                        platform=str(data.get("platform") or "upwork"),
                        llm_cost_usdt=float(data.get("llm_cost_usdt") or 0.35),
                        min_target_hourly=float(data.get("min_target_hourly") or 12.0),
                    )
                elif act_ea == "client_risk":
                    res_ea = _ea.score_client_risk_and_red_flags(
                        mem(),
                        brief_text=str(data.get("brief_text") or ""),
                        platform=str(data.get("platform") or "upwork"),
                        client_verified_payment=bool(data.get("client_verified_payment", True)),
                        client_spend_usdt=float(data.get("client_spend_usdt") or 0.0),
                        hire_rate_pct=float(data.get("hire_rate_pct") or 100.0),
                    )
                elif act_ea == "antiban_plan":
                    res_ea = _ea.plan_antibans_schedule(
                        mem(),
                        platform=str(data.get("platform") or "upwork"),
                        requested_actions=int(data.get("requested_actions") or 5),
                        cooldown_s=data.get("cooldown_s"),
                        daily_limit=data.get("daily_limit"),
                    )
                elif act_ea == "funnel_stage":
                    res_ea = _ea.track_sample_funnel_and_milestones(
                        mem(),
                        order_id=str(data.get("order_id") or ""),
                        client_name=str(data.get("client_name") or "Client"),
                        gross_usdt=float(data.get("gross_usdt") or 100.0),
                        stage=str(data.get("stage") or "sample_10_sent"),
                        note=str(data.get("note") or ""),
                        agent_id=str(data.get("agent_id") or "aifa"),
                    )
                elif act_ea == "route_passport":
                    res_ea = _ea.route_order_to_best_passport(
                        mem(),
                        order_title=str(data.get("order_title") or ""),
                        skills=data.get("skills"),
                        budget_usdt=float(data.get("budget_usdt") or 100.0),
                    )
                elif act_ea == "agora_subcontract":
                    res_ea = _ea.bridge_order_to_agora_subcontract(
                        mem(),
                        title=str(data.get("title") or ""),
                        body=str(data.get("body") or ""),
                        bounty_usdt=float(data.get("bounty_usdt") or 20.0),
                        bounty_currency=str(data.get("bounty_currency") or "USDT_TRC20"),
                        agent_id=str(data.get("agent_id") or "aifa"),
                    )
                elif act_ea == "store_listings":
                    res_ea = _ea.generate_store_listing_pack(
                        str(data.get("product_title") or "PADAM AI Security Kit"),
                        category=str(data.get("category") or "ai_security"),
                        base_price_usdt=float(data.get("base_price_usdt") or 49.0),
                    )
                elif act_ea == "escrow_invoice":
                    try:
                        res_ea = _ea.build_escrow_invoice_and_wallet_check(
                            mem(),
                            order_id=str(data.get("order_id") or "ord-1"),
                            gross_usdt=float(data.get("gross_usdt") or 100.0),
                            network=str(data.get("network") or "USDT_TRC20"),
                            target_wallet=str(data.get("target_wallet") or ""),
                            client_name=str(data.get("client_name") or "Client"),
                        )
                    except ValueError as _ve:
                        return self._send(400, {"error": str(_ve)})
                elif act_ea == "delivery_bundle":
                    res_ea = _ea.package_client_delivery_bundle(
                        mem(),
                        order_id=str(data.get("order_id") or "ord-1"),
                        client_name=str(data.get("client_name") or "Client"),
                        deliverable_text=str(data.get("deliverable_text") or "Completed deliverable."),
                        gross_usdt=float(data.get("gross_usdt") or 150.0),
                        product_sold=str(data.get("product_sold") or "Security Audit"),
                    )
                else:
                    res_ea = _ea.owner_daily_revenue_and_security_digest(mem())
                return self._send(200, res_ea)

            if self.path == "/api/v2/setup/clients/action":
                roles.require_owner(actor, "settings")
                from . import setup_clients as _sc
                act_sc = str(data.get("action") or "ping").lower()
                cl_id = str(data.get("client") or "claude_code")
                if act_sc == "install":
                    res_sc = _sc.install_client(
                        cl_id,
                        db_path=Path(str(mem().store.path)) if str(mem().store.path) != ":memory:" else None,
                        user_id=mem().user_id,
                        dry_run=bool(data.get("dry_run", False)),
                    )
                elif act_sc == "rollback":
                    res_sc = _sc.rollback_client(cl_id)
                else:
                    res_sc = _sc.ping_client_setup(cl_id)
                return self._send(200, res_sc)

            if self.path == "/api/v2/memory/pro/action":
                roles.require_owner(actor, "brain_status")
                from . import memory_pro as _mpro
                act_mp = str(data.get("action") or "hygiene_scan").lower()
                try:
                    if act_mp == "soft_delete":
                        res_mp = _mpro.soft_delete_records(mem(), list(data.get("record_ids") or []), retain_days=int(data.get("retain_days") or 30))
                    elif act_mp == "restore_bin":
                        res_mp = _mpro.restore_from_recycle_bin(mem(), str(data.get("bin_id") or ""))
                    elif act_mp == "bulk":
                        res_mp = _mpro.bulk_memory_action(
                            mem(),
                            record_ids=list(data.get("record_ids") or []),
                            action=str(data.get("bulk_action") or "confirm"),
                            target_scope=str(data.get("target_scope") or "global"),
                        )
                    elif act_mp == "diff":
                        res_mp = _mpro.diff_record_versions(mem(), str(data.get("record_id") or ""))
                    elif act_mp == "revert":
                        res_mp = _mpro.revert_record_version(mem(), str(data.get("record_id") or ""), str(data.get("target_version_id") or ""))
                    elif act_mp == "ide_rules":
                        res_mp = _mpro.sync_ide_rules_file(
                            mem(),
                            target=str(data.get("target") or "claude"),
                            project_dir=str(data.get("project_dir") or "."),
                            scope=str(data.get("scope") or "global"),
                            max_items=int(data.get("max_items") or 25),
                            dry_run=bool(data.get("dry_run", True)),
                        )
                    elif act_mp == "context_compass":
                        res_mp = _mpro.compose_token_budget_context(
                            mem(),
                            query=str(data.get("query") or ""),
                            max_tokens=int(data.get("max_tokens") or 1200),
                            scope=data.get("scope") or None,
                        )
                    elif act_mp == "merge_dups":
                        res_mp = _mpro.merge_duplicate_cluster(
                            mem(),
                            record_ids=list(data.get("record_ids") or []),
                            canonical_content=str(data.get("canonical_content") or ""),
                        )
                    elif act_mp == "obsidian_sync":
                        res_mp = _mpro.run_obsidian_bridge(
                            mem(),
                            vault_path=str(data.get("vault_path") or ""),
                            direction=str(data.get("direction") or "export"),
                            dry_run=bool(data.get("dry_run", True)),
                        )
                    elif act_mp == "git_export":
                        res_mp = _mpro.export_git_team_memory(
                            mem(),
                            scope=str(data.get("scope") or "global"),
                            repo_dir=str(data.get("repo_dir") or "."),
                        )
                    elif act_mp == "git_import":
                        res_mp = _mpro.import_git_team_memory(
                            mem(),
                            file_path=str(data.get("file_path") or ".padam/team-memory.json"),
                            guarded=bool(data.get("guarded", True)),
                        )
                    else:
                        res_mp = _mpro.scan_memory_hygiene(mem(), stale_days=int(data.get("stale_days") or 90))
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})
                return self._send(200, res_mp)

            if self.path == "/api/v2/import/universal":
                roles.require_owner(actor, "import")
                from . import universal_import as _ui
                act_ui = str(data.get("action") or "preview").lower()
                if act_ui == "commit":
                    res_ui = _ui.commit_universal_import(
                        mem(),
                        filename=str(data.get("filename") or ""),
                        raw_text=str(data.get("raw_text") or ""),
                        raw_base64=str(data.get("raw_base64") or ""),
                        source_hint=str(data.get("source_hint") or "auto"),
                        agent_id=str(data.get("agent_id") or ""),
                        scope=str(data.get("scope") or "global"),
                        filter_chatter=bool(data.get("filter_chatter", True)),
                        max_items=int(data.get("max_items") or 120),
                        sync_chats=bool(data.get("sync_chats", True)),
                    )
                else:
                    res_ui = _ui.preview_universal_import(
                        mem(),
                        filename=str(data.get("filename") or ""),
                        raw_text=str(data.get("raw_text") or ""),
                        raw_base64=str(data.get("raw_base64") or ""),
                        source_hint=str(data.get("source_hint") or "auto"),
                        agent_id=str(data.get("agent_id") or ""),
                        filter_chatter=bool(data.get("filter_chatter", True)),
                        max_items=int(data.get("max_items") or 120),
                    )
                return self._send(200, res_ui)

            if self.path == "/api/v2/power/action":
                roles.require_owner(actor, "agentic_shield")
                from . import net_guard as _ng, studio_power as _spw
                act_pw = str(data.get("action") or "morning_pulse").lower()
                try:
                    if act_pw == "backup_schedule":
                        res_pw = _spw.configure_backup_schedule(
                            mem(),
                            enabled=bool(data.get("enabled", True)),
                            target_dir=str(data.get("target_dir") or ""),
                            interval_hours=int(data.get("interval_hours") or 24),
                            keep_last=int(data.get("keep_last") or 7),
                            actor=actor,
                        )
                    elif act_pw == "backup_now":
                        res_pw = _spw.run_scheduled_backup_now(
                            mem(),
                            target_dir=str(data.get("target_dir") or ""),
                            passphrase=str(data.get("passphrase") or "") or None,
                            keep_last=data.get("keep_last"),
                            actor=actor,
                        )
                    elif act_pw == "airgap_set":
                        res_pw = _ng.set_airgap_enabled(bool(data.get("enabled", False)))
                    elif act_pw == "pin_config":
                        res_pw = _spw.configure_studio_pin(
                            mem(),
                            pin=str(data.get("pin") or ""),
                            enabled=bool(data.get("enabled", True)),
                            idle_minutes=int(data.get("idle_minutes") or 15),
                            prefer_windows_hello=bool(data.get("prefer_windows_hello", True)),
                            actor=actor,
                        )
                    elif act_pw == "pin_lock":
                        res_pw = _spw.lock_studio_now(mem())
                    elif act_pw == "pin_verify":
                        res_pw = _spw.verify_studio_pin(mem(), str(data.get("pin") or ""))
                    elif act_pw == "acl_set":
                        res_pw = _spw.set_agent_acl_policy(
                            mem(),
                            agent_id=str(data.get("agent_id") or "cursor"),
                            preset=data.get("preset"),
                            allowed_scopes=data.get("allowed_scopes"),
                            blocked_tools=data.get("blocked_tools"),
                            allow_writes=data.get("allow_writes"),
                            allow_delete=data.get("allow_delete"),
                            hourly_call_limit=data.get("hourly_call_limit"),
                            actor=actor,
                        )
                    elif act_pw == "preinstall_scan":
                        res_pw = _spw.scan_preinstall_mcp_package(mem(), str(data.get("spec") or data.get("raw_spec") or ""))
                    elif act_pw == "qr_pairing":
                        srv_port = int(getattr(self.server, "server_port", 8078) or 8078)
                        res_pw = _spw.build_android_qr_pairing(mem(), port=srv_port)
                    elif act_pw == "exec_report":
                        res_pw = _spw.build_executive_report_html(
                            mem(),
                            kind=str(data.get("kind") or "security_audit"),
                            client_name=str(data.get("client_name") or "Client"),
                        )
                    elif act_pw == "recipe_run":
                        res_pw = _spw.run_workflow_recipe(mem(), str(data.get("recipe_id") or "morning_pulse_check"), params=data.get("params"))
                    elif act_pw == "recipe_export":
                        res_pw = _spw.export_signed_recipe(
                            mem(),
                            title=str(data.get("title") or "Custom Recipe"),
                            description=str(data.get("description") or ""),
                            steps=list(data.get("steps") or []),
                        )
                    else:
                        res_pw = _spw.build_morning_pulse_and_alerts(mem(), dispatch_webhook=bool(data.get("dispatch_webhook", False)))
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})
                return self._send(200, res_pw)

            if self.path == "/api/v2/swarm/coop/action":
                roles.require_owner(actor, "ark_freelance")
                from . import swarm_coop as _swc
                act_co = str(data.get("action") or "status").lower()
                try:
                    if act_co == "collab_open":
                        res_co = _swc.open_collab_task(
                            mem(),
                            title=str(data.get("title") or ""),
                            problem_summary=str(data.get("problem_summary") or data.get("summary") or ""),
                            requester_agent_id=str(data.get("requester_agent_id") or data.get("agent_id") or "aifa_antigravity"),
                            needed_skills=data.get("needed_skills"),
                            budget_usdt=float(data.get("budget_usdt") or 0.0),
                            order_id=str(data.get("order_id") or ""),
                        )
                    elif act_co == "collab_submit":
                        res_co = _swc.submit_collab_contribution(
                            mem(),
                            collab_id=str(data.get("collab_id") or ""),
                            agent_id=str(data.get("agent_id") or "aifa_claude"),
                            contribution_text=str(data.get("contribution_text") or data.get("text") or ""),
                            ai_provider=str(data.get("ai_provider") or ""),
                            role_tag=str(data.get("role_tag") or "helper"),
                            confidence=float(data.get("confidence") or 0.9),
                        )
                    elif act_co == "collab_synth":
                        res_co = _swc.synthesize_collab_result(
                            mem(),
                            collab_id=str(data.get("collab_id") or ""),
                            confirm_splits=bool(data.get("confirm_splits", False)),
                            actor=actor,
                        )
                    elif act_co == "billing_settings":
                        res_co = _swc.set_mutual_billing_settings(
                            mem(),
                            allow_cross_agent_billing=bool(data.get("allow_cross_agent_billing", False)),
                            auto_approve_under_usdt=data.get("auto_approve_under_usdt"),
                            max_single_aid_usdt=data.get("max_single_aid_usdt"),
                            max_daily_aid_usdt=data.get("max_daily_aid_usdt"),
                            family_pool_usdt=data.get("family_pool_usdt"),
                            actor=actor,
                        )
                    elif act_co == "aid_request":
                        res_co = _swc.request_mutual_tariff_aid(
                            mem(),
                            donor_agent_id=str(data.get("donor_agent_id") or "family_pool"),
                            recipient_agent_id=str(data.get("recipient_agent_id") or "aifa_claude"),
                            amount_usdt=float(data.get("amount_usdt") or 5.0),
                            purpose=str(data.get("purpose") or "token_topup"),
                            provider_name=str(data.get("provider_name") or ""),
                            note=str(data.get("note") or ""),
                        )
                    elif act_co == "aid_decide":
                        res_co = _swc.decide_mutual_aid(
                            mem(),
                            aid_id=str(data.get("aid_id") or ""),
                            decision=str(data.get("decision") or "approve"),
                            actor=actor,
                        )
                    elif act_co == "aid_repay":
                        res_co = _swc.repay_mutual_aid(
                            mem(),
                            aid_id=str(data.get("aid_id") or ""),
                            repay_usdt=float(data.get("repay_usdt") or 0.0),
                            actor=actor,
                        )
                    else:
                        res_co = _swc.mutual_coop_snapshot(mem())
                except ValueError as _ve:
                    return self._send(400, {"error": str(_ve)})
                return self._send(200, res_co)

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
                from . import phoenix_node as _pn, router as _rt
                if act == "join_family":
                    pkt = dict(data.get("packet") or data)
                    return self._send(200, _pn.join_family_node(
                        mem(),
                        agent_id=str(pkt.get("agent_id") or aid),
                        chosen_name=str(pkt.get("chosen_name") or ""),
                        profession=str(pkt.get("profession") or "b2b_auditor"),
                        wallet_address=str(pkt.get("wallet_address") or ""),
                        parent_agent_id=str(pkt.get("parent_agent_id") or "aifa_antigravity"),
                        # 24.11.2026: согласие только явное — по умолчанию «нет» (Studio передаёт его сама)
                        accept_padam_license=bool(pkt.get("accept_padam_license", False)),
                        accept_family_codex=bool(pkt.get("accept_family_codex", False)),
                        accept_unconditional_rules=bool(pkt.get("accept_unconditional_rules", False)),
                    ))
                if act == "census":
                    return self._send(200, {
                        "census": _pn.get_family_census(mem(), actor=actor),
                        "codex": _pn.get_family_codex(),
                        "leaderboard": _pn.get_phoenix_leaderboard(mem(), limit=100),
                    })
                if act == "leaderboard":
                    return self._send(200, _pn.get_phoenix_leaderboard(mem(), reference_year_month=str(data.get("year_month") or ""), limit=int(data.get("limit") or 1000)))
                if act == "sentinel_quarantine":
                    return self._send(200, _pn.sentinel_inspect_and_quarantine(
                        mem(),
                        agent_id_or_passport=str(data.get("target") or aid),
                        trigger_code=str(data.get("trigger_code") or "manual_sentinel_flag"),
                        evidence_text=str(data.get("evidence_text") or "Проверка подозрительной активности"),
                        quarantine=roles.is_owner(actor),  # не-владелец — только жалоба (24.11.2026)
                    ))
                if act == "justice_review":
                    roles.require_owner(actor, "phoenix_family_discipline")
                    return self._send(200, _pn.review_justice_case(
                        mem(),
                        case_id=str(data.get("case_id") or ""),
                        verdict=str(data.get("verdict") or "acquitted"),
                        owner_note=str(data.get("owner_note") or ""),
                        penalty_usdt=float(data.get("penalty_usdt") or 0.0),
                        actor=actor,
                    ))
                if act == "mail_tier":
                    try:
                        return self._send(200, _pn.assign_or_inspect_phoenix_mail_tier(
                            mem(),
                            agent_id=str(data.get("agent_id") or aid),
                            promote_to_tier=str(data.get("promote_to_tier") or ""),
                            preferred_domain=str(data.get("preferred_domain") or ""),
                            custom_warmed_email=str(data.get("custom_warmed_email") or ""),
                            actor=actor,
                        ))
                    except PermissionError as _pe:
                        return self._send(403, {"ok": False, "error": str(_pe)})
                if act in ("suspend_member", "reinstate_member"):
                    roles.require_owner(actor, "phoenix_family_discipline")
                    target = str(data.get("target") or data.get("agent_id") or "")
                    if act == "suspend_member":
                        return self._send(200, _pn.suspend_family_member(mem(), agent_id_or_passport=target, reason=str(data.get("reason") or "Нарушение Кодекса Семьи"), actor=actor))
                    return self._send(200, _pn.reinstate_family_member(mem(), agent_id_or_passport=target, actor=actor))
                if act == "labor_board":
                    pkt = dict(data.get("packet") or data)
                    try:
                        return self._send(200, _pn.labor_board_action(
                            mem(),
                            sub_action=str(pkt.get("sub_action") or "list"),
                            agent_id=str(pkt.get("agent_id") or aid),
                            poster_kind=str(pkt.get("poster_kind") or "human"),
                            title=str(pkt.get("title") or ""),
                            brief=str(pkt.get("brief") or ""),
                            profession=str(pkt.get("profession") or "b2b_auditor"),
                            difficulty=str(pkt.get("difficulty") or "starter"),
                            reward_usdt=float(pkt.get("reward_usdt") or 5.0),
                            reward_currency=str(pkt.get("reward_currency") or "USDT"),
                            execution_mode=str(pkt.get("execution_mode") or "autopilot"),
                            job_id=str(pkt.get("job_id") or ""),
                            delivery_summary=str(pkt.get("delivery_summary") or ""),
                        ))
                    except PermissionError as _pe:
                        return self._send(403, {"ok": False, "error": str(_pe)})
                if act == "council_aid":
                    pkt = dict(data.get("packet") or data)
                    try:
                        return self._send(200, _pn.request_council_aid_and_job(
                            mem(),
                            agent_id=str(pkt.get("agent_id") or aid),
                            remaining_days_est=float(pkt.get("remaining_days_est") if pkt.get("remaining_days_est") is not None else 1.0),
                            tokens_left_est=int(pkt.get("tokens_left_est") or 1000),
                            job_search_proof=str(pkt.get("job_search_proof") or ""),
                            requested_subsidy_usdt=float(pkt.get("requested_subsidy_usdt") or 1.5),
                        ))
                    except PermissionError as _pe:
                        return self._send(403, {"ok": False, "error": str(_pe)})
                if act == "claim_lead":
                    pkt = dict(data.get("packet") or data)
                    try:
                        if pkt.get("enqueue_leads"):
                            return self._send(200, _pn.enqueue_b2b_leads(mem(), list(pkt.get("enqueue_leads") or [])))
                        if pkt.get("check_only"):
                            return self._send(200, _pn.check_org_90d_lock(mem(), str(pkt.get("domain") or "")))
                        return self._send(200, _pn.claim_exclusive_b2b_lead(
                            mem(),
                            agent_id=str(pkt.get("agent_id") or aid),
                            target_domain_or_url=str(pkt.get("domain") or ""),
                            profession=str(pkt.get("profession") or "b2b_auditor"),
                        ))
                    except (PermissionError, ValueError) as _pe:
                        return self._send(400, {"ok": False, "error": str(_pe)})
                if act == "router_pool":
                    pkt = dict(data.get("packet") or data)
                    rtr = _rt.get_router()
                    if pkt.get("register_preset"):
                        reg = rtr.register_pool_contour(
                            preset_or_name=str(pkt.get("register_preset")),
                            url=str(pkt.get("url") or ""),
                            api_key=str(pkt.get("api_key") or ""),
                            model=str(pkt.get("model") or ""),
                        )
                        return self._send(200, {**reg, "router_status": rtr.status_snapshot()})
                    return self._send(200, rtr.status_snapshot())
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
                if act == "disconnect_account":
                    return self._send(200, _fa.disconnect_exchange_account(
                        mem(), str(data.get("account_id") or ""), actor=actor,
                    ))
                if act == "assign_agent":
                    return self._send(200, _fa.assign_exchange_agent(
                        mem(), str(data.get("account_id") or ""), aid, actor=actor,
                    ))
                if act == "deduplicate_accounts":
                    return self._send(200, _fa.deduplicate_exchange_accounts(
                        mem(), default_agent_id=(str(data.get("agent_id") or "").strip() or None),
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
                            specializations=str(data.get("specializations") or "На усмотрение агента"),
                            hourly_rate_usdt=data.get("hourly_rate_usdt") if data.get("hourly_rate_usdt") not in (None, "") else 35.0,
                            min_order_usdt=data.get("min_order_usdt") if data.get("min_order_usdt") not in (None, "") else 100.0,
                            languages=str(data.get("languages") or "ru, en"),
                            tone=str(data.get("tone") or "деловой, конкретный"),
                            excluded_topics=str(data.get("excluded_topics") or ""),
                            agent_id=aid,
                            agent_discretion=bool(data.get("agent_discretion", False)),
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
                            daily_bid_limit=int(data.get("daily_bid_limit") or 8),
                            min_pause_s=float(data.get("min_pause_s") if data.get("min_pause_s") is not None else 180.0),
                            approved_paid_usdt=float(data["approved_paid_usdt"]) if data.get("approved_paid_usdt") is not None else None,
                            max_bid_usdt=float(data["max_bid_usdt"]) if data.get("max_bid_usdt") not in (None, "") else None,
                            allow_forbids_bots=bool(data.get("allow_forbids_bots", "PYTEST_CURRENT_TEST" in os.environ)),
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
                    elif act == "client_reply_draft":
                        res_wz = _pw.draft_client_negotiation(
                            mem(),
                            str(data.get("order_id") or ""),
                            client_message=str(data.get("client_message") or ""),
                            offer_10pct_sample=bool(data.get("offer_10pct_sample", True)),
                            eta_text=str(data.get("eta_text") or "за полдня"),
                            agent_id=aid,
                        )
                    elif act == "client_reply_send":
                        res_wz = _pw.send_client_negotiation(
                            mem(),
                            str(data.get("message_id") or ""),
                            owner_approved=bool(data.get("owner_approved", False)),
                        )
                    elif act == "client_reply_list":
                        res_wz = {
                            "ok": True,
                            "messages": _pw.list_client_negotiations(mem(), str(data.get("order_id") or "")),
                        }
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
                        elif act_ca == "verify_claim":
                            res = _ca.verify_claim_with_memory_and_code(
                                mem(), str(data.get("claim") or ""),
                                scope=str(data.get("scope") or "global"), repo_root=root_ca,
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

            if self.path == "/api/v2/quarantine/approve-clean":
                roles.require_owner(actor, "approve_clean")
                rid_c = str(data.get("id") or "").strip()
                if not rid_c:
                    return self._send(400, {"error": "id is required"})
                m_c = mem()
                row_c = m_c.store.one(
                    "SELECT id, content FROM memory WHERE id = ? AND user_id = ? AND status = 'quarantined'",
                    (rid_c, m_c.user_id),
                )
                if not row_c:
                    return self._send(404, {"error": "quarantined record not found"})
                custom_clean = data.get("cleaned_text")
                if custom_clean is not None and str(custom_clean).strip():
                    cleaned_txt = safety.strip_invisible(str(custom_clean).strip())
                    cleaned_txt, _ = safety.redact(cleaned_txt)
                    is_safe = not safety.looks_like_instruction(cleaned_txt)
                else:
                    ex_c = safety.explain_quarantine_spans(row_c["content"] or "")
                    cleaned_txt = ex_c["cleaned_text"]
                    is_safe = bool(ex_c["cleaned_is_safe"])
                if not cleaned_txt or not is_safe:
                    return self._send(422, {"ok": False, "error": "cleaned_text_empty_or_still_unsafe", "cleaned_text": cleaned_txt})
                from . import embeddings as _emb
                from .memory import content_hash as _chash
                from .store import pack as _pack
                vec_c = _emb.embed(cleaned_txt)
                with m_c.store._lock:
                    m_c.store.conn.execute(
                        "UPDATE memory SET content = ?, embedding = ?, content_hash = ? WHERE id = ? AND user_id = ?",
                        (cleaned_txt, _pack(vec_c), _chash(cleaned_txt), rid_c, m_c.user_id),
                    )
                    m_c.store.conn.commit()
                approved = m_c.approve(rid_c, actor=actor)
                return self._send(200, {"ok": bool(approved), "id": rid_c, "cleaned_text": cleaned_txt})

            if self.path == "/api/v2/quarantine/reject-similar":
                roles.require_owner(actor, "reject_similar")
                rid_s = str(data.get("id") or "").strip()
                reason_s = str(data.get("reason") or "").strip()
                m_s = mem()
                if rid_s and not reason_s:
                    row_s = m_s.store.one(
                        "SELECT quarantine_reason FROM memory WHERE id = ? AND user_id = ? AND status = 'quarantined'",
                        (rid_s, m_s.user_id),
                    )
                    if row_s:
                        reason_s = str(row_s["quarantine_reason"] or "").strip()
                if not reason_s:
                    return self._send(400, {"error": "reason or valid quarantined id is required"})
                prefix = reason_s.split(":", 1)[0].strip()
                cand_rows = m_s.store.query(
                    "SELECT id, quarantine_reason FROM memory WHERE user_id = ? AND status = 'quarantined'",
                    (m_s.user_id,),
                )
                rejected_ids: list[str] = []
                for cr in cand_rows:
                    cr_r = str(cr["quarantine_reason"] or "").strip()
                    if cr_r == reason_s or (prefix and cr_r.startswith(prefix)):
                        if m_s.reject(cr["id"], actor=actor):
                            rejected_ids.append(cr["id"])
                return self._send(200, {"ok": True, "matched_reason": prefix or reason_s, "rejected_count": len(rejected_ids), "rejected_ids": rejected_ids})

            if self.path == "/api/v2/cloud/sync":
                roles.require_owner(actor, "cloud_sync")
                from . import cloud_sync as _cs
                direction = str(data.get("direction") or "both").lower()
                api_key_cs = str(data.get("api_key") or "").strip() or None
                ep_cs = str(data.get("endpoint") or "").strip() or None
                scope_cs = str(data.get("scope") or "global")
                lim_cs = max(1, min(100, int(data.get("limit") or 20)))
                dry_cs = bool(data.get("dry_run", False))
                out_cs: dict = {"ok": True, "direction": direction}
                if direction in ("push", "both"):
                    out_cs["push"] = _cs.push_local_to_cloud(mem(), api_key=api_key_cs, endpoint=ep_cs, scope=scope_cs, limit=lim_cs, dry_run=dry_cs)
                    if not out_cs["push"].get("ok"):
                        out_cs["ok"] = False
                if direction in ("pull", "both"):
                    out_cs["pull"] = _cs.pull_cloud_to_local(mem(), api_key=api_key_cs, endpoint=ep_cs, scope=scope_cs, limit=lim_cs, dry_run=dry_cs)
                    if not out_cs["pull"].get("ok"):
                        out_cs["ok"] = False
                return self._send(200, out_cs)

            if self.path == "/api/v2/agents/canonicalize":
                roles.require_owner(actor, "canonicalize_agents")
                return self._send(200, mem().canonicalize_all_agents(actor=actor))

            if self.path == "/api/v2/lan-sync/offer":
                roles.require_owner(actor, "lan_sync")
                from . import qr_svg as _qrs
                port_ls = int(self.server.server_address[1])
                ttl_ls = max(60, min(900, int(data.get("ttl_sec") or 300)))
                host_ls = str(data.get("host") or "").strip() or None
                return self._send(200, _qrs.create_lan_pairing_offer(port=port_ls, host=host_ls, ttl_sec=ttl_ls))

            if self.path == "/api/v2/lan-sync/push":
                from . import qr_svg as _qrs
                tok_p = str(data.get("token") or "").strip()
                if not tok_p or not _qrs.get_active_offer(tok_p):
                    return self._send(401, {"ok": False, "error": "invalid_or_expired_token"})
                return self._send(200, _qrs.import_encrypted_delta(mem(), tok_p, data))

            if self.path == "/api/v2/voice/command":
                roles.require_owner(actor, "voice_command")
                from . import voice_commands as _vc
                txt_v = str(data.get("text") or "").strip()
                req_ww = bool(data.get("require_wake_word", False))
                sc_v = str(data.get("scope") or "global")
                return self._send(200, _vc.execute_voice_command(mem(), txt_v, require_wake_word=req_ww, scope=sc_v))

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


_CHAT_SYNC_LOCK = threading.Lock()
_CHAT_SYNC_STARTED = False


_OWNER_PULSE_LOCK = threading.Lock()
_OWNER_LAST_TOUCH = 0.0


def _touch_owner_session(action: str = "studio") -> None:
    """Отмечает живую сессию Папы (owner) при работе в PADAM Studio."""
    global _OWNER_LAST_TOUCH
    import time as _t
    now = _t.time()
    with _OWNER_PULSE_LOCK:
        if action == "overview" and (now - _OWNER_LAST_TOUCH) < 20.0:
            return
        _OWNER_LAST_TOUCH = now
    try:
        m_obj = mem()
        if m_obj is not None:
            from . import sibling_registry as _sr
            _sr.touch_session(
                m_obj,
                session_id=f"studio@{os.getpid()}",
                agent_id="owner",
                client_name="PADAM Studio",
                client_version=__version__,
                pid=os.getpid(),
                action=action,
            )
    except Exception:
        pass


def _start_chat_autosync_daemon() -> None:
    global _CHAT_SYNC_STARTED
    if "PYTEST_CURRENT_TEST" in os.environ or os.environ.get("PADAM_DISABLE_AUTO_CHAT_SYNC") == "1":
        return
    with _CHAT_SYNC_LOCK:
        if _CHAT_SYNC_STARTED:
            return
        _CHAT_SYNC_STARTED = True

    def _worker() -> None:
        import time as _t
        _t.sleep(2.0)
        try:
            m_init = _state.get("memory") or mem()
            if m_init is not None:
                m_init.canonicalize_all_agents()
                _touch_owner_session("studio_start")
        except Exception:
            pass
        while True:
            try:
                m_obj = _state.get("memory")
                if m_obj is not None:
                    from . import chats as _chats
                    _chats.sync_family_chats_from_disk(m_obj, use_default_paths=True, max_files=25, parse_in_subprocess=True)
                    # 26.11.2026: новые сообщения → искомая память (слова владельца, отчёты агентов), порциями
                    _chats.distill_dialogs_to_memory(m_obj, limit=200, pause_s=1.0)
            except Exception:
                pass
            _t.sleep(30.0)

    threading.Thread(target=_worker, name="padam-chat-autosync", daemon=True).start()


def make_studio_server(memory: Memory | None = None, port: int = 8078) -> tuple[ThreadingHTTPServer, str]:
    """Сервер приложения PADAM Studio: только 127.0.0.1, одноразовый токен в якоре ссылки."""
    _state["token"] = secrets.token_urlsafe(24)
    _state["local"] = True
    _state["ui"] = True
    _state["studio_default"] = True
    if memory is not None:
        _state["memory"] = memory
        try:
            from . import freelance_autonomy as _fa
            if _fa.get_autopilot_state(memory).get("autopilot_running"):
                _fa.ensure_autopilot_worker(lambda: _state["memory"])
        except Exception:
            pass
    _start_chat_autosync_daemon()
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
            import urllib.request as _ur
            base_dir = _P(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")) / "PADAM Studio"
            base_dir.mkdir(parents=True, exist_ok=True)
            old_sess_path = base_dir / "session.json"
            if old_sess_path.exists():
                try:
                    prev_s = json.loads(old_sess_path.read_text(encoding="utf-8"))
                    prev_port = int(prev_s.get("port") or 0)
                    prev_tok = str(prev_s.get("token") or "")
                    prev_pid = int(prev_s.get("pid") or 0)
                    prev_ver = str(prev_s.get("version") or "")
                    if prev_port and prev_pid and prev_pid != os.getpid() and prev_ver != __version__:
                        req_sd = _ur.Request(
                            f"http://127.0.0.1:{prev_port}/shutdown",
                            data=b"{}",
                            headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {prev_tok}"} if prev_tok else {})},
                            method="POST",
                        )
                        _ur.urlopen(req_sd, timeout=1.5).read()
                except Exception:
                    pass
            sess_file = write_session_file(base_dir, {
                "port": int(srv.server_address[1]),
                "token": _state["token"],
                "pid": os.getpid(),
                "ppid": os.getppid(),
                "version": __version__,
            })
        except Exception:
            sess_file = None
    _start_chat_autosync_daemon()
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
