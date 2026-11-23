# -*- coding: utf-8 -*-
"""Мост запуска настоящего PADAM Studio внутри Android-приложения (Chaquopy).

Добавлено в 0.8.0 (Фишки 17, 18, 19, 20):
- ingest_shared_text: приём текста из системного «Поделиться» (ACTION_SEND) через Agentic Shield;
- handle_voice_command: обработка голосовых команд и Wake Word «Айфа…»;
- sync_lan_with_pc: зашифрованная AES-256-GCM синхронизация дельты памяти с ПК по QR;
- get_widget_stats: живые счётчики активной памяти и карантина для виджета.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.parse
import urllib.request
import webbrowser

_SERVER = None
_SERVER_URL = None
_MEMORY = None
_LOCK = threading.Lock()


def start_studio(files_dir: str, keystore_bridge, browser_bridge) -> str:
    """Поднимает локальный сервер PADAM Studio на 127.0.0.1 и возвращает URL с токеном."""
    global _SERVER, _SERVER_URL, _MEMORY
    with _LOCK:
        if _SERVER_URL:
            return _SERVER_URL

        os.makedirs(files_dir, exist_ok=True)
        os.environ["HOME"] = files_dir
        os.environ["PADAM_DB"] = os.path.join(files_dir, "padam.db")
        os.environ.setdefault("PADAM_NO_OLLAMA", "1")
        # У Chaquopy нет отдельного python.exe для подпроцесса: бенчмарк AIFaSecurity идёт внутри процесса.
        os.environ.setdefault("PADAM_BENCH_INPROC", "1")

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
        _MEMORY = mem
        srv, url = api.make_studio_server(memory=mem, port=0)
        th = threading.Thread(target=srv.serve_forever, name="padam-studio-http", daemon=True)
        th.start()
        _SERVER = srv
        _SERVER_URL = url
        return url


def ingest_shared_text(raw_text: str, source_app: str = "android_share") -> str:
    """Принимает текст из системного меню «Поделиться» и прогоняет через Agentic Shield (Фишка 17)."""
    if _MEMORY is None:
        return json.dumps({"ok": False, "error": "memory_not_ready"}, ensure_ascii=False)
    clean = str(raw_text or "").strip()
    if not clean:
        return json.dumps({"ok": False, "error": "empty_text"}, ensure_ascii=False)
    try:
        outcome, mid = _MEMORY.remember(
            clean[:8000],
            kind="fact",
            scope="global",
            origin="external",
            guarded=True,
            agent_id=source_app,
        )
        return json.dumps({"ok": True, "outcome": outcome, "id": mid}, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)


def handle_voice_command(raw_text: str, require_wake_word: bool = False) -> str:
    """Выполняет голосовую команду «Айфа…» и возвращает JSON с текстом для озвучки TTS (Фишка 19)."""
    if _MEMORY is None:
        return json.dumps({"ok": False, "error": "memory_not_ready"}, ensure_ascii=False)
    from padam import voice_commands
    res = voice_commands.execute_voice_command(
        _MEMORY,
        str(raw_text or ""),
        require_wake_word=bool(require_wake_word),
    )
    return json.dumps(res, ensure_ascii=False)


def sync_lan_with_pc(qr_payload_or_uri: str) -> str:
    """Синхронизирует дельту памяти с ПК по LAN QR-коду (AES-256-GCM, Фишка 18)."""
    if _MEMORY is None:
        return json.dumps({"ok": False, "error": "memory_not_ready"}, ensure_ascii=False)
    from padam import qr_svg
    try:
        raw = str(qr_payload_or_uri or "").strip()
        if raw.startswith("padam://lan-sync?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(raw).query)
            base_url = (qs.get("url") or [""])[0].rstrip("/")
            token = (qs.get("token") or [""])[0]
            key_b64 = (qs.get("key") or [""])[0]
        else:
            obj = json.loads(raw)
            base_url = str(obj.get("base_url") or obj.get("url") or "").rstrip("/")
            token = str(obj.get("token") or "")
            key_b64 = str(obj.get("key_b64") or obj.get("key") or "")
        if not base_url or not token or not key_b64:
            return json.dumps({"ok": False, "error": "invalid_qr_payload"}, ensure_ascii=False)

        pull_url = f"{base_url}/api/v2/lan-sync/pull?token={urllib.parse.quote(token)}&limit=100"
        with urllib.request.urlopen(pull_url, timeout=8) as resp:
            envelope = json.loads(resp.read().decode("utf-8"))
        if not envelope.get("ok"):
            return json.dumps({"ok": False, "error": envelope.get("error") or "pull_failed"}, ensure_ascii=False)

        import base64
        key = base64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
        items = qr_svg.decrypt_lan_payload(key, envelope["nonce_b64"], envelope["ciphertext_b64"])
        imported = 0
        quarantined = 0
        for it in items:
            txt = str(it.get("content") or "").strip()
            if not txt:
                continue
            outcome, _ = _MEMORY.remember(
                txt,
                kind=str(it.get("kind") or "fact"),
                scope=str(it.get("scope") or "global"),
                origin="agent",
                guarded=True,
                agent_id="pc_lan_sync",
            )
            if outcome == "quarantined":
                quarantined += 1
            elif outcome != "duplicate":
                imported += 1
        return json.dumps({"ok": True, "imported": imported, "quarantined": quarantined, "received": len(items)}, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)


def get_widget_stats() -> str:
    """Возвращает JSON со счётчиками активной памяти и карантина для виджета (Фишка 20)."""
    if _MEMORY is None:
        return json.dumps({"active": 0, "quarantined": 0})
    st = _MEMORY.stats()
    return json.dumps({"active": int(st.get("active") or 0), "quarantined": int(st.get("quarantined") or 0)})
