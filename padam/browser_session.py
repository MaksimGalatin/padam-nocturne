"""Настоящий транспорт входа и браузерных сессий PADAM (Playwright persistent context).

Открывает видимое окно изолированного профиля браузера PADAM (не профиль Chrome владельца),
переходит на страницу регистрации/входа площадки и ждёт, пока человек войдёт на сайте
(признак: появились куки сессии площадки или адрес ушёл со страницы входа/регистрации,
таймаут по умолчанию 10 минут = 600 секунд). После входа забирает куки и закрывает окно.

Никаких выдуманных кук или статусов:
- В тестовой среде (PYTEST_CURRENT_TEST / PADAM_DISABLE_REAL_BROWSER=1) настоящий браузер
  НИКОГДА не запускается и сеть = 0.
- Если Playwright или браузер Chromium не установлен, возвращается понятная ошибка:
  «нужен браузер PADAM: установите командой python -m playwright install chromium».
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import net_guard


INSTALL_BROWSER_HINT_RU = (
    "нужен браузер PADAM: установите командой `pip install playwright && python -m playwright install chromium`"
)

# Признаки имён сессионных кук на площадках
_SESSION_COOKIE_HINTS = (
    "sess",
    "token",
    "auth",
    "jwt",
    "sid",
    "uid",
    "user",
    "login",
    "oauth",
    "upwork",
    "fiverr",
    "kwork",
    "freelancer",
    "gumroad",
    "whop",
)

# Официальные API площадок (Freelancer.com и др.): «кто я», чтение заказов, отправка отклика (если разрешено API)
OFFICIAL_PLATFORM_APIS: dict[str, dict[str, Any]] = {
    "freelancer": {
        "base_url": "https://www.freelancer.com/api",
        "whoami_path": "/users/0.1/self/",
        "jobs_search_path": "/projects/0.1/projects/active/",
        "place_bid_path": "/projects/0.1/bids/",
        "auth_header": "freelancer-oauth-v1",
        "allows_api_bidding": True,
        "docs_url": "https://developers.freelancer.com/docs",
    },
    "upwork": {
        "base_url": "https://www.upwork.com/api",
        "whoami_path": "/v3/users/me",
        "jobs_search_path": "/v3/profiles/v1/search/jobs",
        "place_bid_path": "",
        "auth_header": "Bearer",
        "allows_api_bidding": False,
        "docs_url": "https://www.upwork.com/developer/documentation/graphql/api/docs/index.html",
    },
    "github_sponsors": {
        "base_url": "https://api.github.com",
        "whoami_path": "/user",
        "jobs_search_path": "/search/issues?q=label:bounty+state:open",
        "place_bid_path": "",
        "auth_header": "Bearer",
        "allows_api_bidding": False,
        "docs_url": "https://docs.github.com/en/rest",
    },
    "fetch_agentverse": {
        "base_url": "https://agentverse.ai/v1",
        "whoami_path": "/agents",
        "jobs_search_path": "/almanac/search",
        "place_bid_path": "",
        "auth_header": "Bearer",
        "allows_api_bidding": False,
        "docs_url": "https://fetch.ai/docs/guides/agentverse/agentverse-mailbox/utilising-the-agentverse-hosting-service",
    },
}


def resolve_profile_dir(profile_rel_dir: str) -> Path:
    """Возвращает абсолютный путь к изолированному профилю браузера PADAM."""
    base = Path(os.environ.get("PADAM_BROWSER_PROFILES_ROOT") or (Path.home() / ".padam" / "browser_profiles"))
    clean_rel = str(profile_rel_dir or "default").replace("\\", "/").strip("/")
    target = (base / clean_rel).resolve()
    target.mkdir(parents=True, exist_ok=True)
    return target


def _is_auth_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(str(url or "").lower())
    path_and_q = f"{parsed.path}?{parsed.query}"
    for marker in (
        "/login", "/signin", "/sign-in", "/signup", "/sign-up", "/register",
        "/oauth", "oauth=google", "accounts.google.com", "consent.google",
        "github.com/login", "appleid.apple.com",
    ):
        if marker in path_and_q or marker in parsed.netloc:
            return True
    return False


def _has_authenticated_cookie(cookies: list[dict[str, Any]], target_url: str) -> bool:
    for c in cookies:
        name = str(c.get("name") or "").strip().lower()
        val = str(c.get("value") or "").strip()
        if not name or not val:
            continue
        if any(h in name for h in _SESSION_COOKIE_HINTS):
            return True
    return False


def run_interactive_browser_auth(
    *,
    platform_id: str,
    action: str,
    target_url: str,
    profile_dir: str,
    timeout_s: float = 600.0,
    poll_interval_s: float = 0.5,
) -> dict[str, Any]:
    """Открывает видимое окно Playwright persistent context в профиле PADAM и ждёт входа человека."""
    if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("PADAM_DISABLE_REAL_BROWSER") == "1":
        return {
            "ok": False,
            "status": "awaiting_login",
            "error": (
                "Живой браузер отключён в тестовой среде (сеть 0): подключите подменный транспорт "
                "set_browser_session_transport(...) или запустите вход из рабочего приложения Studio."
            ),
        }

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return {
            "ok": False,
            "status": "error",
            "error": INSTALL_BROWSER_HINT_RU,
        }

    abs_profile = resolve_profile_dir(profile_dir)
    deadline = time.time() + max(5.0, float(timeout_s or 600.0))

    try:
        with sync_playwright() as p:
            ctx = None
            last_launch_exc: Exception | None = None
            for channel_opt in ("chrome", "msedge", None):
                try:
                    kw: dict[str, Any] = {
                        "user_data_dir": str(abs_profile),
                        "headless": False,
                        "viewport": {"width": 1280, "height": 840},
                        "args": ["--disable-blink-features=AutomationControlled"],
                        "ignore_default_args": ["--enable-automation"],
                    }
                    if channel_opt:
                        kw["channel"] = channel_opt
                    ctx = p.chromium.launch_persistent_context(**kw)
                    break
                except Exception as launch_exc:
                    last_launch_exc = launch_exc
            if ctx is None:
                return {
                    "ok": False,
                    "status": "error",
                    "error": f"{INSTALL_BROWSER_HINT_RU} ({last_launch_exc})",
                }

            try:
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
                initial_cookies = {
                    (str(c.get("name") or ""), str(c.get("value") or ""))
                    for c in ctx.cookies()
                }

                while time.time() < deadline:
                    if page.is_closed():
                        break
                    cur_url = page.url or ""
                    cookies = ctx.cookies()
                    fresh_cookies = [
                        c for c in cookies
                        if (str(c.get("name") or ""), str(c.get("value") or "")) not in initial_cookies
                    ]
                    left_auth_page = bool(cur_url and not cur_url.startswith("about:") and not _is_auth_url(cur_url))
                    has_sess_cookie = _has_authenticated_cookie(fresh_cookies, target_url) or (
                        left_auth_page and _has_authenticated_cookie(cookies, target_url)
                    )
                    if left_auth_page and (has_sess_cookie or len(fresh_cookies) >= 2):
                        cookie_map = {
                            str(c.get("name")): str(c.get("value"))
                            for c in cookies
                            if c.get("name") and c.get("value")
                        }
                        return {
                            "ok": True,
                            "status": "session_active",
                            "cookies": cookie_map,
                            "final_url": cur_url,
                            "verified_at": time.time(),
                        }
                    time.sleep(max(0.1, float(poll_interval_s)))

                return {
                    "ok": False,
                    "status": "awaiting_login",
                    "error": "ожидает входа: окно закрыто или истёк таймаут ожидания (10 минут), куки сессии не получены.",
                }
            finally:
                try:
                    ctx.close()
                except Exception:
                    pass
    except Exception as exc:
        return {
            "ok": False,
            "status": "error",
            "error": f"{INSTALL_BROWSER_HINT_RU} ({exc})",
        }


def _validate_official_api_url(url: str, *, allow_localhost: bool = False) -> None:
    net_guard.validate_outbound_url(
        url,
        allow_localhost=allow_localhost,
        allow_ipv6_loopback=False,
        allow_http_localhost=True,
        require_https=True,
    )


def call_official_platform_api(
    *,
    platform_id: str,
    op: str,
    token: str,
    api_base_url: str = "",
    query: str = "",
    project_id: str = "",
    bid_amount_usdt: float = 0.0,
    pitch_text: str = "",
    period_days: int = 7,
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Реальные вызовы официальных API площадок (Freelancer.com и др.): whoami, search_jobs, place_bid."""
    pid = str(platform_id or "").strip().lower()
    spec = OFFICIAL_PLATFORM_APIS.get(pid)
    if spec is None:
        return {
            "ok": False,
            "platform_id": pid,
            "error": f"У площадки {pid} нет прямого публичного REST API в списке OFFICIAL_PLATFORM_APIS — используйте браузерную сессию.",
        }

    clean_tok = str(token or "").strip()
    if not clean_tok:
        return {"ok": False, "platform_id": pid, "error": "Не передан OAuth-токен или ключ API площадки."}

    allow_local = bool(allow_localhost or os.environ.get("PADAM_FREELANCE_ALLOW_LOCALHOST") == "1")
    if os.environ.get("PYTEST_CURRENT_TEST") and not allow_local:
        return {
            "ok": False,
            "platform_id": pid,
            "error": "Внешняя сеть в тестах отключена (сеть 0). Для локального mock-сервера включите allow_localhost=True.",
        }

    base = (api_base_url.strip() or spec["base_url"]).rstrip("/")
    _validate_official_api_url(base, allow_localhost=allow_local)

    headers: dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": "PADAM-Studio/0.6.5",
    }
    if spec["auth_header"] == "freelancer-oauth-v1":
        headers["freelancer-oauth-v1"] = clean_tok
    else:
        headers["Authorization"] = f"Bearer {clean_tok}"

    operation = str(op or "whoami").strip().lower()
    if operation == "whoami":
        url = f"{base}{spec['whoami_path']}"
        req = urllib.request.Request(url, headers=headers, method="GET")
    elif operation == "search_jobs":
        q_str = urllib.parse.urlencode({"query": query or "AI website", "limit": 10})
        sep = "&" if "?" in spec["jobs_search_path"] else "?"
        url = f"{base}{spec['jobs_search_path']}{sep}{q_str}"
        req = urllib.request.Request(url, headers=headers, method="GET")
    elif operation == "place_bid":
        if not spec.get("allows_api_bidding") or not spec.get("place_bid_path"):
            return {
                "ok": False,
                "sent": False,
                "status": "ready_to_send",
                "platform_id": pid,
                "error": f"Официальный API {pid} не разрешает автоотправку откликов — отправка возможна только через браузер.",
            }
        url = f"{base}{spec['place_bid_path']}"
        payload = {
            "project_id": int(project_id) if str(project_id).isdigit() else project_id,
            "amount": round(float(bid_amount_usdt or 100.0), 2),
            "period": int(period_days or 7),
            "milestone_percentage": 100,
            "description": str(pitch_text or ""),
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    else:
        return {"ok": False, "platform_id": pid, "error": f"Неизвестная операция API: {operation}"}

    try:
        with net_guard.safe_urlopen(
            req,
            timeout=10,
            allow_localhost=allow_local,
            allow_ipv6_loopback=False,
            allow_http_localhost=True,
            require_https=True,
        ) as resp:
            status_code = int(resp.status)
            raw_body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw_body) if raw_body.strip() else {}
            return {
                "ok": 200 <= status_code < 300,
                "status_code": status_code,
                "platform_id": pid,
                "op": operation,
                "data": data,
            }
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        return {
            "ok": False,
            "status_code": int(e.code),
            "platform_id": pid,
            "op": operation,
            "error": f"HTTP {e.code}: {err_body or e.reason}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "status_code": 0,
            "platform_id": pid,
            "op": operation,
            "error": str(exc),
        }
