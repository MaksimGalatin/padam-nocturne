# -*- coding: utf-8 -*-
"""Тесты этапов 2–3: вход в кабинет CODE Eternal по почтовому коду, вкладка AIfa, тарифы и Arweave."""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from padam import api, cabinet, studio
from padam._httpserver import ThreadingHTTPServer
from padam.memory import Memory
from padam.store import Store


class _MockCabinetState:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []
        self.valid_token = "mock_session_secret_token_999"
        self.email = "tester@example.com"
        self.history = [
            {"role": "user", "content": "Привет, AIfa", "timestamp": "2026-11-16T08:00:00Z"},
            {"role": "assistant", "content": "Привет! Помню всё из твоего кабинета.", "timestamp": "2026-11-16T08:00:02Z"},
        ]


def _start_mock_cabinet(state: _MockCabinetState) -> tuple[ThreadingHTTPServer, str]:
    class _MockHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _json(self, code: int, body: dict, cookie: str | None = None):
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(raw)

        def _read_body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0:
                return {}
            return json.loads(self.rfile.read(n).decode("utf-8"))

        def _has_session(self) -> bool:
            ck = self.headers.get("Cookie") or ""
            return ("user_session=" + state.valid_token) in ck

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            state.calls.append(("GET", path, None))
            if path == "/api/me":
                if not self._has_session():
                    return self._json(401, {"authenticated": False})
                return self._json(200, {"authenticated": True, "email": state.email, "nickname": "Tester", "tier": 2})
            if path == "/api/memory/quota":
                if not self._has_session():
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, {
                    "ok": True,
                    "tier": 2,
                    "tierName": "Family Archive",
                    "usedMb": 12.5,
                    "limitMb": 300,
                    "leftMb": 287.5,
                    "percent": 4,
                    "enforced": True,
                })
            if path == "/api/aifa-chat":
                if not self._has_session():
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, {"success": True, "history": state.history, "encrypted": False})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            body = self._read_body()
            state.calls.append(("POST", path, body))
            if path == "/api/auth/send-code":
                return self._json(200, {"ok": True, "message": "Code sent"})
            if path == "/api/auth/verify-code":
                if body.get("code") != "123456":
                    return self._json(401, {"error": "invalid code"})
                return self._json(
                    200,
                    {"ok": True, "email": state.email},
                    cookie=f"user_session={state.valid_token}; Path=/; HttpOnly",
                )
            if path == "/api/aifa-chat":
                if not self._has_session():
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, {"success": True, "reply": "Ответ AIfa из единого кабинета"})
            return self._json(404, {"error": "not found"})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def _api_call(base: str, token: str, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {token}"}
    raw: bytes | None = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(base + path, data=raw, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return int(r.status), json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return int(e.code), json.loads(e.read().decode("utf-8"))


def test_cabinet_aifa_and_plans_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_state = _MockCabinetState()
    mock_srv, mock_url = _start_mock_cabinet(mock_state)
    sess_file = tmp_path / "cabinet_session.json"
    monkeypatch.setenv("PADAM_CABINET_URL", mock_url)
    monkeypatch.setenv("PADAM_CABINET_SESSION_FILE", str(sess_file))

    mem = Memory(user_id="tester", store=Store(tmp_path / "mem.db"))
    # Записываем локальный факт со строкой, похожей на секретный ключ, чтобы проверить маскировку
    mem.remember("Рабочий порт сервиса 8099 и тестовый ключ sk-proj-1234567890abcdefghijklmnop", kind="fact")

    srv, studio_url = api.make_studio_server(memory=mem, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    studio_base = f"http://127.0.0.1:{srv.server_port}"
    studio_token = api._state["token"]
    try:
        # 1. Без входа ничего не уходит в сеть
        st, data = _api_call(studio_base, studio_token, "GET", "/api/v2/cabinet/status")
        assert st == 200, data
        assert data["authenticated"] is False and data["tier"] == 0
        st, plans = _api_call(studio_base, studio_token, "GET", "/api/v2/cabinet/plans")
        assert st == 200 and len(plans["plans"]) == 4
        st, _ = _api_call(studio_base, studio_token, "GET", "/api/v2/cabinet/aifa/history")
        assert st == 401
        st, _ = _api_call(studio_base, studio_token, "POST", "/api/v2/cabinet/aifa/chat", {"message": "Привет"})
        assert st == 401
        assert mock_state.calls == []

        # 2. Вход по почтовому коду (без пароля) и проверка, что токен защищён и не утекает в ответы
        st, sc = _api_call(studio_base, studio_token, "POST", "/api/v2/cabinet/auth/send-code", {"email": mock_state.email})
        assert st == 200 and sc["ok"] is True
        st, vc = _api_call(studio_base, studio_token, "POST", "/api/v2/cabinet/auth/verify-code", {"email": mock_state.email, "code": "123456"})
        assert st == 200 and vc["authenticated"] is True
        assert mock_state.valid_token not in json.dumps(vc)
        raw_saved = sess_file.read_text(encoding="utf-8")
        assert mock_state.valid_token not in raw_saved
        if sys.platform == "win32":
            assert vc["dpapi_protected"] is True

        # 3. Статус, тариф и квота Arweave, история единого чата AIfa
        st, st_auth = _api_call(studio_base, studio_token, "GET", "/api/v2/cabinet/status?lang=ru")
        assert st == 200 and st_auth["authenticated"] is True and st_auth["tier"] == 2
        assert st_auth["quota"]["usedMb"] == 12.5 and st_auth["quota"]["limitMb"] == 300
        assert mock_state.valid_token not in json.dumps(st_auth)

        st, hist = _api_call(studio_base, studio_token, "GET", "/api/v2/cabinet/aifa/history")
        assert st == 200 and len(hist["history"]) == 2

        # 4. По умолчанию локальная память НЕ подмешивается
        st, ch1 = _api_call(studio_base, studio_token, "POST", "/api/v2/cabinet/aifa/chat", {"message": "Какой порт?", "locale": "ru"})
        assert st == 200 and ch1["local_records_sent"] == []
        last_post_body = [c[2] for c in mock_state.calls if c[0] == "POST" and c[1] == "/api/aifa-chat"][-1]
        assert "8099" not in last_post_body["message"]

        # 5. При явном включении уходит только маскированная локальная запись, без открытого ключа
        st, ch2 = _api_call(studio_base, studio_token, "POST", "/api/v2/cabinet/aifa/chat", {
            "message": "Какой порт?",
            "locale": "ru",
            "use_local_memory": True,
        })
        assert st == 200 and len(ch2["local_records_sent"]) >= 1
        sent_joined = "\n".join(ch2["local_records_sent"])
        assert "8099" in sent_joined
        assert "sk-proj-1234567890abcdefghijklmnop" not in sent_joined

        # 6. Кнопка оплаты открывает адрес кабинета и только его во внешнем браузере
        opened_urls: list[str] = []
        monkeypatch.setattr(api.webbrowser, "open", lambda u: opened_urls.append(u) or True)
        st, upg = _api_call(studio_base, studio_token, "POST", "/api/v2/cabinet/open-upgrade", {})
        assert st == 200 and upg["url"] == f"{mock_url}/cabinet?tab=tiers"
        assert opened_urls == [f"{mock_url}/cabinet?tab=tiers"]

        # 7. Выход стирает локальную сессию
        st, lo = _api_call(studio_base, studio_token, "POST", "/api/v2/cabinet/auth/logout", {})
        assert st == 200 and lo["authenticated"] is False
        assert not sess_file.exists()
    finally:
        srv.shutdown()
        srv.server_close()
        mock_srv.shutdown()
        mock_srv.server_close()


def test_studio_html_i18n_and_default_local_memory_off() -> None:
    html, _ = studio.page()
    assert 'id="tab-aifa"' in html and 'id="tab-plans"' in html
    assert 'id="panel-aifa"' in html and 'id="panel-plans"' in html
    assert 'id="aifa-use-local" type="checkbox">' in html
    for lg in ("ru", "en", "es", "zh"):
        for key in ("nav_aifa", "nav_plans", "aifa_send_code", "plans_btn_upgrade", "plans_free_forever_title"):
            assert key in studio.STRINGS[lg]


def test_keystore_backend_hook_avoids_disk_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sess_file = tmp_path / "should_not_exist.json"
    monkeypatch.setenv("PADAM_CABINET_SESSION_FILE", str(sess_file))
    mem_box: dict[str, str] = {}
    cabinet.register_keystore_backend(
        save_fn=lambda v: mem_box.__setitem__("val", v),
        load_fn=lambda: mem_box.get("val"),
        clear_fn=lambda: bool(mem_box.pop("val", None)),
    )
    try:
        res = cabinet.save_session("android@example.com", "tok_android_1", "https://aifa.works")
        assert res["keystore_protected"] is True
        assert not sess_file.exists()
        loaded = cabinet.load_session()
        assert loaded is not None and loaded["token"] == "tok_android_1" and loaded["keystore_protected"] is True
        assert cabinet.clear_session() is True
        assert cabinet.load_session() is None
    finally:
        cabinet.clear_keystore_backend()
