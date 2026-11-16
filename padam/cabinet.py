# -*- coding: utf-8 -*-
"""Клиент единого кабинета CODE Eternal / AIfa для PADAM Studio.

Отвечает за:
- беспарольный вход по одноразовому почтовому коду (/api/auth/send-code и /api/auth/verify-code);
- локальное защищённое хранение сессии (Windows DPAPI через hardware_seal._dpapi_protect / _dpapi_unprotect);
- чтение профиля (/api/me), квоты Arweave (/api/memory/quota) и единого чата AIfa (/api/aifa-chat);
- передачу в чат AIfa маскированной локальной памяти только при явном согласии пользователя;
- безопасный переход на страницу оплаты кабинета во внешнем браузере (без приёма платёжных данных).
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .hardware_seal import _dpapi_protect, _dpapi_unprotect

DEFAULT_CABINET_URL = "https://aifa.works"
_CABINET_DPAPI_ENTROPY = b"padam-cabinet-session-v1"
_HTTP_TIMEOUT = 25
_keystore_backend: dict[str, Any] | None = None


def register_keystore_backend(save_fn: Any, load_fn: Any, clear_fn: Any) -> None:
    """Подключает системное хранилище ключей (например Android Keystore) вместо файла."""
    global _keystore_backend
    _keystore_backend = {"save": save_fn, "load": load_fn, "clear": clear_fn}


def clear_keystore_backend() -> None:
    """Сбрасывает внешний keystore-бэкенд (для тестов)."""
    global _keystore_backend
    _keystore_backend = None

# Тарифы и месячные лимиты Arweave строго по Конституции и lib/arweave-quota.ts
PLANS: list[dict[str, Any]] = [
    {
        "tier": 0,
        "id": "free",
        "name": "Free",
        "price_usd_month": 0,
        "setup_usd": 0,
        "arweave_mb_month": 0,
    },
    {
        "tier": 1,
        "id": "spark",
        "name": "Spark",
        "price_usd_month": 15,
        "setup_usd": 0,
        "arweave_mb_month": 30,
    },
    {
        "tier": 2,
        "id": "family",
        "name": "Family Archive",
        "price_usd_month": 100,
        "setup_usd": 0,
        "arweave_mb_month": 300,
    },
    {
        "tier": 3,
        "id": "dna",
        "name": "Digital DNA",
        "price_usd_month": 200,
        "setup_usd": 1000,
        "arweave_mb_month": 1024,
    },
]


def get_cabinet_url() -> str:
    """Возвращает базовый URL кабинета без завершающего слэша."""
    raw = (os.environ.get("PADAM_CABINET_URL") or DEFAULT_CABINET_URL).strip()
    if not raw:
        raw = DEFAULT_CABINET_URL
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise ValueError("Invalid PADAM_CABINET_URL")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost"):
        raise ValueError("Non-local cabinet URL must use https")
    return raw.rstrip("/")


def get_upgrade_url() -> str:
    """Возвращает безопасный URL страницы тарифов и оплаты в кабинете."""
    return get_cabinet_url() + "/cabinet?tab=tiers"


def _session_path() -> Path:
    override = (os.environ.get("PADAM_CABINET_SESSION_FILE") or "").strip()
    if override:
        return Path(override)
    base = Path.home() / ".padam"
    return base / "cabinet_session.json"


def _protect_secret(raw_text: str) -> tuple[str, bool]:
    data = raw_text.encode("utf-8")
    if sys.platform == "win32":
        blob = _dpapi_protect(data, entropy=_CABINET_DPAPI_ENTROPY)
        return base64.b64encode(blob).decode("ascii"), True
    return base64.b64encode(data).decode("ascii"), False


def _unprotect_secret(b64_text: str, is_dpapi: bool) -> str:
    blob = base64.b64decode(b64_text.encode("ascii"))
    if is_dpapi:
        if sys.platform != "win32":
            raise RuntimeError("DPAPI session cannot be opened outside win32")
        raw = _dpapi_unprotect(blob, entropy=_CABINET_DPAPI_ENTROPY)
        return raw.decode("utf-8")
    return blob.decode("utf-8")


def save_session(email: str, cookie_token: str, cabinet_url: str | None = None) -> dict[str, Any]:
    """Сохраняет сессию кабинета локально в защищённом виде (Keystore / DPAPI)."""
    em = email.strip().lower()
    cab = (cabinet_url or get_cabinet_url()).rstrip("/")
    if _keystore_backend is not None:
        raw_json = json.dumps({"email": em, "cabinet_url": cab, "token": cookie_token}, ensure_ascii=False)
        _keystore_backend["save"](raw_json)
        return {"authenticated": True, "email": em, "cabinet_url": cab, "dpapi_protected": False, "keystore_protected": True}
    path = _session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    enc_b64, is_dpapi = _protect_secret(cookie_token)
    payload = {
        "email": em,
        "cabinet_url": cab,
        "dpapi": is_dpapi,
        "token_b64": enc_b64,
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    if sys.platform != "win32":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return {"authenticated": True, "email": payload["email"], "cabinet_url": payload["cabinet_url"], "dpapi_protected": is_dpapi}


def load_session() -> dict[str, Any] | None:
    """Читает и расшифровывает локальную сессию кабинета. Не логирует сам токен."""
    if _keystore_backend is not None:
        try:
            raw_json = _keystore_backend["load"]()
            if not raw_json:
                return None
            data = json.loads(raw_json)
            tok = str(data.get("token") or "")
            if not tok:
                return None
            return {
                "email": str(data.get("email") or ""),
                "cabinet_url": str(data.get("cabinet_url") or get_cabinet_url()).rstrip("/"),
                "dpapi_protected": False,
                "keystore_protected": True,
                "token": tok,
            }
        except Exception:
            return None
    path = _session_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        tok = _unprotect_secret(str(data["token_b64"]), bool(data.get("dpapi")))
        if not tok:
            return None
        return {
            "email": str(data.get("email") or ""),
            "cabinet_url": str(data.get("cabinet_url") or get_cabinet_url()).rstrip("/"),
            "dpapi_protected": bool(data.get("dpapi")),
            "token": tok,
        }
    except Exception:
        return None


def clear_session() -> bool:
    """Стирает локальную сохранённую сессию кабинета."""
    if _keystore_backend is not None:
        try:
            return bool(_keystore_backend["clear"]())
        except Exception:
            return False
    path = _session_path()
    existed = path.exists()
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    return existed


def get_public_status() -> dict[str, Any]:
    """Возвращает состояние входа без утечки секретного токена."""
    url = get_cabinet_url()
    sess = load_session()
    if not sess:
        return {
            "authenticated": False,
            "email": None,
            "cabinet_url": url,
            "dpapi_protected": False,
            "upgrade_url": get_upgrade_url(),
        }
    return {
        "authenticated": True,
        "email": sess["email"],
        "cabinet_url": sess.get("cabinet_url") or url,
        "dpapi_protected": bool(sess.get("dpapi_protected")),
        "upgrade_url": get_upgrade_url(),
    }


def _extract_user_session_cookie(headers: Any) -> str | None:
    if headers is None:
        return None
    raw_list: list[str] = []
    if hasattr(headers, "get_all"):
        raw_list = headers.get_all("Set-Cookie") or []
    elif "Set-Cookie" in headers:
        raw_list = [str(headers["Set-Cookie"])]
    for item in raw_list:
        for part in str(item).split(";"):
            kv = part.strip()
            if kv.startswith("user_session="):
                val = kv[len("user_session="):].strip()
                if val:
                    return urllib.parse.unquote(val)
    return None


def _http_json(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    cookie_token: str | None = None,
    timeout: int = _HTTP_TIMEOUT,
) -> tuple[int, dict[str, Any], str | None]:
    headers: dict[str, str] = {"Accept": "application/json"}
    raw_body: bytes | None = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
    if cookie_token:
        headers["Cookie"] = "user_session=" + urllib.parse.quote(cookie_token, safe="")
    req = urllib.request.Request(url, data=raw_body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            txt = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(txt) if txt.strip() else {}
            new_cookie = _extract_user_session_cookie(resp.headers)
            return int(resp.status), parsed if isinstance(parsed, dict) else {"data": parsed}, new_cookie
    except urllib.error.HTTPError as err:
        txt = err.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(txt) if txt.strip() else {}
        except Exception:
            parsed = {"error": txt[:200] or f"HTTP {err.code}"}
        return int(err.code), parsed if isinstance(parsed, dict) else {"error": str(parsed)}, None


def send_login_code(email: str) -> dict[str, Any]:
    """Запрашивает отправку 6-значного кода входа на почту (без пароля)."""
    em = (email or "").strip().lower()
    if not em or "@" not in em:
        raise ValueError("Valid email is required")
    base = get_cabinet_url()
    st, data, _ = _http_json("POST", base + "/api/auth/send-code", {"email": em})
    if st >= 400:
        raise RuntimeError(str(data.get("error") or f"HTTP {st}"))
    return {"ok": True, "email": em, "message": data.get("message") or ""}


def verify_login_code(email: str, code: str) -> dict[str, Any]:
    """Подтверждает 6-значный код и сохраняет полученную сессию в DPAPI."""
    em = (email or "").strip().lower()
    cd = (code or "").strip()
    if not em or "@" not in em:
        raise ValueError("Valid email is required")
    if not cd:
        raise ValueError("Verification code is required")
    base = get_cabinet_url()
    st, data, cookie_tok = _http_json("POST", base + "/api/auth/verify-code", {"email": em, "code": cd})
    if st >= 400:
        raise RuntimeError(str(data.get("error") or f"HTTP {st}"))
    tok = cookie_tok or (str(data.get("token") or "").strip() or None)
    if not tok:
        raise RuntimeError("Cabinet did not return user_session cookie")
    return save_session(em, tok, base)


def fetch_me_and_quota(lang: str = "ru") -> dict[str, Any]:
    """Загружает профиль (/api/me) и квоту Arweave (/api/memory/quota) для вошедшего человека."""
    pub = get_public_status()
    if not pub["authenticated"]:
        return {**pub, "tier": 0, "tier_name": "Free", "quota": None, "plans": PLANS}
    sess = load_session()
    assert sess is not None
    base = sess.get("cabinet_url") or get_cabinet_url()
    tok = sess["token"]

    st_me, me_data, _ = _http_json("GET", base + "/api/me", cookie_token=tok)
    if st_me == 401:
        clear_session()
        return {
            "authenticated": False,
            "email": None,
            "cabinet_url": base,
            "dpapi_protected": False,
            "upgrade_url": get_upgrade_url(),
            "tier": 0,
            "tier_name": "Free",
            "quota": None,
            "plans": PLANS,
            "session_expired": True,
        }
    if st_me >= 400:
        raise RuntimeError(str(me_data.get("error") or f"HTTP {st_me}"))

    q_lang = lang if lang in ("ru", "en", "es", "zh") else "ru"
    st_q, q_data, _ = _http_json("GET", f"{base}/api/memory/quota?lang={q_lang}", cookie_token=tok)
    quota = q_data if (st_q < 400 and q_data.get("ok")) else None
    tier = int((quota or {}).get("tier") if quota is not None else me_data.get("tier") or 0)
    plan_obj = next((p for p in PLANS if p["tier"] == tier), PLANS[0])
    return {
        **pub,
        "email": me_data.get("email") or pub["email"],
        "nickname": me_data.get("nickname"),
        "tier": tier,
        "tier_name": (quota or {}).get("tierName") or plan_obj["name"],
        "quota": quota,
        "plans": PLANS,
    }


def fetch_aifa_history(chat_type: str = "main") -> dict[str, Any]:
    """Читает единую историю переписки с AIfa из /api/aifa-chat."""
    sess = load_session()
    if not sess:
        raise PermissionError("not_authenticated")
    base = sess.get("cabinet_url") or get_cabinet_url()
    qs = urllib.parse.urlencode({"chatType": chat_type})
    st, data, _ = _http_json("GET", f"{base}/api/aifa-chat?{qs}", cookie_token=sess["token"])
    if st == 401:
        clear_session()
        raise PermissionError("not_authenticated")
    if st >= 400:
        raise RuntimeError(str(data.get("error") or f"HTTP {st}"))
    return {"ok": True, "history": data.get("history") or [], "encrypted": bool(data.get("encrypted"))}


def send_aifa_message(
    message: str,
    locale: str = "ru",
    history: list[dict[str, Any]] | None = None,
    masked_local_records: list[str] | None = None,
    chat_type: str = "main",
) -> dict[str, Any]:
    """Отправляет сообщение в /api/aifa-chat от имени вошедшего пользователя.

    Если переданы masked_local_records (уже прошедшие маскировку), они явно
    добавляются в контекст сообщения, а список отправленных записей возвращается вызывающему коду.
    """
    sess = load_session()
    if not sess:
        raise PermissionError("not_authenticated")
    msg = (message or "").strip()
    if not msg:
        raise ValueError("Message is required")

    sent_local = [r for r in (masked_local_records or []) if r and str(r).strip()][:5]
    outbound_msg = msg
    if sent_local:
        ctx_lines = ["[PADAM local memory context (masked)]:"]
        for idx, rec in enumerate(sent_local, 1):
            ctx_lines.append(f"{idx}. {rec}")
        ctx_lines.append("")
        ctx_lines.append(msg)
        outbound_msg = "\n".join(ctx_lines)

    base = sess.get("cabinet_url") or get_cabinet_url()
    payload = {
        "message": outbound_msg,
        "history": (history or [])[-20:],
        "chatType": chat_type,
        "locale": locale if locale in ("ru", "en", "es", "zh") else "ru",
    }
    st, data, _ = _http_json("POST", f"{base}/api/aifa-chat", payload, cookie_token=sess["token"], timeout=60)
    if st == 401:
        clear_session()
        raise PermissionError("not_authenticated")
    if st >= 400:
        raise RuntimeError(str(data.get("userMessage") or data.get("error") or f"HTTP {st}"))
    reply = data.get("response") or data.get("reply") or data.get("text") or ""
    return {
        "ok": True,
        "reply": str(reply),
        "provider": data.get("provider") or "central",
        "local_records_sent": sent_local,
    }
