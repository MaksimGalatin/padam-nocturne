# -*- coding: utf-8 -*-
"""Мост запуска настоящего PADAM Studio внутри Android-приложения (Chaquopy)."""

from __future__ import annotations

import os
import threading
import webbrowser

_SERVER = None
_SERVER_URL = None
_LOCK = threading.Lock()


def start_studio(files_dir: str, keystore_bridge, browser_bridge) -> str:
    """Поднимает локальный сервер PADAM Studio на 127.0.0.1 и возвращает URL с токеном."""
    global _SERVER, _SERVER_URL
    with _LOCK:
        if _SERVER_URL:
            return _SERVER_URL

        os.makedirs(files_dir, exist_ok=True)
        os.environ["HOME"] = files_dir
        os.environ["PADAM_DB"] = os.path.join(files_dir, "padam.db")
        os.environ.setdefault("PADAM_NO_OLLAMA", "1")

        from padam import api, cabinet
        from padam.memory import Memory
        from padam.store import Store

        # Привязываем хранение сессии кабинета к аппаратному Android Keystore вместо файла
        cabinet.register_keystore_backend(
            save_fn=lambda payload: keystore_bridge.saveSession(str(payload)),
            load_fn=lambda: keystore_bridge.loadSession(),
            clear_fn=lambda: bool(keystore_bridge.clearSession()),
        )

        # Перенаправляем webbrowser.open во внешний браузер телефона (например, на страницу оплаты)
        def _android_open(url: str, new: int = 0, autoraise: bool = True) -> bool:
            try:
                return bool(browser_bridge.openExternalUrl(str(url)))
            except Exception:
                return False

        webbrowser.open = _android_open

        mem = Memory(user_id="android", store=Store(os.environ["PADAM_DB"]))
        srv, url = api.make_studio_server(memory=mem, port=0)
        th = threading.Thread(target=srv.serve_forever, name="padam-studio-http", daemon=True)
        th.start()
        _SERVER = srv
        _SERVER_URL = url
        return url
