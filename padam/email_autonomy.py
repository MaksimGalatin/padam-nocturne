# -*- coding: utf-8 -*-
"""Мульти-почтовый конвейер автономного аутрича: отправка с подключённых почт, автоответ на «Шлите список», стоп-лист STOP и эскалация человеку.

Инварианты безопасности и законности:
- Никаких открытых паролей в SQLite: App Password / OAuth / API-ключи шифруются через AES-256-GCM (freelance_autonomy._seal_secret) и никогда не возвращаются наружу.
- Единый стоп-лист (БД ark_outreach_stop_list + файл ОТПИСАЛИСЬ.txt): ответ STOP / Unsubscribe / «не пишите» мгновенно блокирует email и домен навсегда.
- Защита от спама: не более daily_limit писем в сутки с одного ящика, ротация ящиков, 30-дневная бронь домена (не слать дважды), заголовок List-Unsubscribe.
- Важные/нестандартные ответы (цены, контракты, недовольство) НЕ решаются вслепую — эскалируются владельцу в «Офис» и coop_broker.
"""

from __future__ import annotations

from email.message import EmailMessage
from email.utils import parseaddr
import hashlib
import html as _html
import imaplib
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import ssl
import time
from typing import Any, Callable
import urllib.request

from . import audit_chain, coop_broker, family_feeds, freelance_autonomy, net_guard, safety


# 18.11.2026 (CI на Python 3.10): кэш на самом объекте хранилища, а не по id() — адрес переиспользуется после сборки мусора.

# Пресеты популярных почтовых провайдеров (SMTP SSL + IMAP SSL)
MAIL_PROVIDER_PRESETS: dict[str, dict[str, Any]] = {
    "gmail": {"smtp_host": "smtp.gmail.com", "smtp_port": 465, "imap_host": "imap.gmail.com", "imap_port": 993, "hint_ru": "Gmail: используйте пароль приложения (App Password 16 знаков) при включённой 2FA."},
    "yandex": {"smtp_host": "smtp.yandex.ru", "smtp_port": 465, "imap_host": "imap.yandex.ru", "imap_port": 993, "hint_ru": "Яндекс.Почта: используйте пароль приложения из настроек безопасности Яндекса."},
    "mailru": {"smtp_host": "smtp.mail.ru", "smtp_port": 465, "imap_host": "imap.mail.ru", "imap_port": 993, "hint_ru": "Mail.ru: используйте пароль для внешних приложений."},
    "outlook": {"smtp_host": "smtp-mail.outlook.com", "smtp_port": 587, "imap_host": "outlook.office365.com", "imap_port": 993, "hint_ru": "Outlook / Microsoft 365."},
    "smtp_imap": {"smtp_host": "", "smtp_port": 465, "imap_host": "", "imap_port": 993, "hint_ru": "Произвольный SMTP/IMAP сервер вашего домена."},
    "gmail_oauth2": {"smtp_host": "smtp.gmail.com", "smtp_port": 465, "imap_host": "imap.gmail.com", "imap_port": 993, "hint_ru": "Gmail OAuth2 (токен доступа Google без App Password)."},
    "resend": {"smtp_host": "api.resend.com", "smtp_port": 443, "imap_host": "", "imap_port": 0, "hint_ru": "Resend HTTP API (только отправка по ключу re_...)."},
    "instantly": {"smtp_host": "api.instantly.ai", "smtp_port": 443, "imap_host": "api.instantly.ai", "imap_port": 443, "hint_ru": "Instantly API v2 (HTTPS 443 — обходит блокировку портов 465/587 у провайдера; 100/100 прогретые ящики Google Workspace)."},
}

DEFAULT_STOP_LIST_PATH = Path(
    r"E:\Aifa\ВАЖНЫЕ ДОКУМЕНТЫ!!!!!!!!!!!!!!!!!!!!!!!!!\09_ЗАРАБОТОК И МОНЕТИЗАЦИЯ\ГОТОВЫЕ_БАЗЫ_ДЛЯ_ЗАПУСКА\ОТПИСАЛИСЬ.txt"
)

# Подменный транспорт для тестов без сети
_MAIL_TRANSPORT: Callable[[dict[str, Any]], dict[str, Any]] | None = None


def set_mail_transport(fn: Callable[[dict[str, Any]], dict[str, Any]] | None) -> None:
    """Подменяет SMTP/IMAP транспорт в тестах (сеть = 0)."""
    global _MAIL_TRANSPORT
    _MAIL_TRANSPORT = fn


def _ensure_mail_schema(memory) -> None:
    conn = memory.store.conn
    if memory.store.__dict__.get("_padam_mail_schema_ok"):
        return
    with freelance_autonomy._lock_of(memory):
        if memory.store.__dict__.get("_padam_mail_schema_ok"):
            return
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ark_mail_account (
                mail_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                email TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT 'gmail',
                smtp_host TEXT NOT NULL DEFAULT '',
                smtp_port INTEGER NOT NULL DEFAULT 465,
                imap_host TEXT NOT NULL DEFAULT '',
                imap_port INTEGER NOT NULL DEFAULT 993,
                secret_enc TEXT NOT NULL DEFAULT '',
                secret_fp TEXT NOT NULL DEFAULT '',
                daily_limit INTEGER NOT NULL DEFAULT 30,
                sent_today INTEGER NOT NULL DEFAULT 0,
                last_sent_day TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                last_error TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ark_outreach_stop_list (
                user_id TEXT NOT NULL,
                target_key TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT 'stop_reply',
                created_at REAL NOT NULL,
                PRIMARY KEY (user_id, target_key)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ark_outreach_log (
                msg_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                mail_id TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                recipient_email TEXT NOT NULL DEFAULT '',
                direction TEXT NOT NULL DEFAULT 'outbound_first',
                subject TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'sent',
                summary TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ark_outreach_leads (
                lead_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                email TEXT NOT NULL,
                domain TEXT NOT NULL,
                company TEXT NOT NULL DEFAULT '',
                region TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'manual',
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ark_mail_prefs (
                user_id TEXT PRIMARY KEY,
                auto_outreach_enabled INTEGER NOT NULL DEFAULT 0,
                outreach_language TEXT NOT NULL DEFAULT 'auto',
                daily_batch_limit INTEGER NOT NULL DEFAULT 20,
                updated_at REAL NOT NULL
            )
            """
        )
        from .store import add_column_safe as _acs
        _acs(conn, "ark_mail_account", "warmup_enabled", "INTEGER NOT NULL DEFAULT 0")
        conn.commit()
        memory.store.__dict__["_padam_mail_schema_ok"] = True


def _today_utc(now_ts: float | None = None) -> str:
    return freelance_autonomy._date_utc(now_ts if now_ts is not None else time.time())


def _clean_email(raw: str) -> str:
    _, addr = parseaddr(str(raw or "").strip())
    addr = (addr or str(raw or "")).strip().lower()
    if "@" not in addr or len(addr) > 254 or any(c.isspace() for c in addr):
        return ""
    return addr


def _clean_domain(raw: str) -> str:
    dom = str(raw or "").strip().lower()
    dom = dom.removeprefix("https://").removeprefix("http://").split("/")[0].split(":")[0]
    if "@" in dom:
        dom = dom.split("@", 1)[1]
    return dom[:253]


def effective_daily_limit(row: dict[str, Any], *, now_ts: float | None = None) -> int:
    """Возвращает эффективный суточный лимит ящика с учётом плавного прогрева (5 -> 10 -> 20 -> daily_limit)."""
    base_lim = max(1, min(200, int(row.get("daily_limit") or 30)))
    if not int(row.get("warmup_enabled") or 0):
        return base_lim
    created = float(row.get("created_at") or 0.0)
    cur_now = time.time() if now_ts is None else float(now_ts)
    age_days = max(0.0, (cur_now - created) / 86400.0) if created > 0 else 0.0
    if age_days < 3.0:
        cap = 5
    elif age_days < 7.0:
        cap = 10
    elif age_days < 14.0:
        cap = 20
    else:
        cap = base_lim
    return max(1, min(base_lim, cap))


def _public_mail_dict(row: dict[str, Any]) -> dict[str, Any]:
    today = _today_utc()
    sent_today = int(row.get("sent_today") or 0) if str(row.get("last_sent_day") or "") == today else 0
    eff_lim = effective_daily_limit(row)
    return {
        "mail_id": row["mail_id"],
        "email": row["email"],
        "display_name": row.get("display_name") or "",
        "provider": row["provider"],
        "smtp_host": row["smtp_host"],
        "smtp_port": int(row["smtp_port"]),
        "imap_host": row["imap_host"],
        "imap_port": int(row["imap_port"]),
        "secret_configured": bool(row.get("secret_enc")),
        "secret_fp": row.get("secret_fp") or "",
        "daily_limit": int(row["daily_limit"]),
        "effective_daily_limit": eff_lim,
        "warmup_enabled": bool(int(row.get("warmup_enabled") or 0)),
        "sent_today": sent_today,
        "remaining_today": max(0, eff_lim - sent_today),
        "status": row["status"],
        "last_error": row.get("last_error") or "",
        "updated_at": float(row.get("updated_at") or 0.0),
    }


def _verify_smtp_imap_live(
    *,
    provider: str,
    email: str,
    secret: str,
    smtp_host: str,
    smtp_port: int,
    imap_host: str,
    imap_port: int,
) -> dict[str, Any]:
    if _MAIL_TRANSPORT is not None:
        return _MAIL_TRANSPORT({
            "op": "verify",
            "provider": provider,
            "email": email,
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "imap_host": imap_host,
            "imap_port": imap_port,
        }) or {"ok": True}

    if os.environ.get("PYTEST_CURRENT_TEST"):
        return {"ok": True, "skipped_in_test": True}

    if provider == "resend":
        if not secret.startswith("re_"):
            return {"ok": False, "error": "Ключ Resend должен начинаться с re_."}
        return {"ok": True}

    if provider == "instantly":
        try:
            req = urllib.request.Request(
                "https://api.instantly.ai/api/v2/accounts?limit=100",
                headers={"Authorization": f"Bearer {secret}", "User-Agent": "PADAM-Studio/0.8.0"},
                method="GET",
            )
            with net_guard.safe_urlopen(req, timeout=12, require_https=True) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            items = data.get("items") or data.get("accounts") or (data if isinstance(data, list) else [])
            matched = next((a for a in items if str(a.get("email") or "").strip().lower() == email.lower()), None)
            if matched is None:
                return {"ok": False, "error": f"Ящик {email} не найден в подключённом кабинете Instantly."}
            return {
                "ok": True,
                "warmup_score": matched.get("stat_warmup_score", 100),
                "instantly_status": matched.get("status", 1),
            }
        except Exception as exc:
            return {"ok": False, "error": f"Ошибка проверки Instantly HTTPS API: {exc}"}

    try:
        ctx = ssl.create_default_context()
        if int(smtp_port) == 465:
            with smtplib.SMTP_SSL(smtp_host, int(smtp_port), timeout=12, context=ctx) as srv:
                srv.login(email, secret)
        else:
            with smtplib.SMTP(smtp_host, int(smtp_port), timeout=12) as srv:
                srv.starttls(context=ctx)
                srv.login(email, secret)
        if imap_host and int(imap_port) > 0:
            with imaplib.IMAP4_SSL(imap_host, int(imap_port), timeout=12) as imap:
                imap.login(email, secret)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": f"Ошибка входа в почту ({smtp_host}): {exc}"}


def connect_mail_account(
    memory,
    *,
    email: str,
    provider: str = "gmail",
    app_password_or_token: str = "",
    smtp_host: str = "",
    smtp_port: int = 0,
    imap_host: str = "",
    imap_port: int = 0,
    display_name: str = "Maksim Galatin · CODE Eternal LLC",
    daily_limit: int = 30,
    verify_connection: bool = True,
    warmup_enabled: bool = False,
) -> dict[str, Any]:
    """Подключает почтовый ящик (Gmail/Yandex/Mail.ru/Outlook/SMTP+IMAP/Resend), шифруя секрет AES-256-GCM."""
    _ensure_mail_schema(memory)
    clean_em = _clean_email(email)
    if not clean_em:
        raise ValueError("Некорректный адрес электронной почты.")
    prov = str(provider or "gmail").strip().lower()
    if prov not in MAIL_PROVIDER_PRESETS:
        raise ValueError(f"Неизвестный провайдер почты {prov!r}. Доступны: {', '.join(MAIL_PROVIDER_PRESETS)}")

    raw_secret = str(app_password_or_token or "").strip()
    if not raw_secret:
        raise ValueError("Укажите пароль приложения (App Password) или API-токен — обычный пароль от аккаунта не требуется.")

    preset = MAIL_PROVIDER_PRESETS[prov]
    s_host = str(smtp_host or preset["smtp_host"]).strip()
    s_port = int(smtp_port or preset["smtp_port"] or 465)
    i_host = str(imap_host or preset["imap_host"]).strip()
    i_port = int(imap_port or preset["imap_port"] or 993)
    if not s_host:
        raise ValueError("Укажите smtp_host для выбранного провайдера.")

    if verify_connection:
        chk = _verify_smtp_imap_live(
            provider=prov,
            email=clean_em,
            secret=raw_secret,
            smtp_host=s_host,
            smtp_port=s_port,
            imap_host=i_host,
            imap_port=i_port,
        )
        if not chk.get("ok"):
            return {"ok": False, "error": str(chk.get("error") or "Не удалось проверить вход в почту.")}

    secret_enc = freelance_autonomy._seal_secret(memory, raw_secret)
    secret_fp = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()[:12]
    lim = max(1, min(200, int(daily_limit or 30)))
    now = time.time()

    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        existing = conn.execute(
            "SELECT mail_id FROM ark_mail_account WHERE user_id = ? AND email = ?",
            (memory.user_id, clean_em),
        ).fetchone()
        if existing:
            mail_id = str(existing["mail_id"])
            conn.execute(
                """
                UPDATE ark_mail_account
                SET display_name=?, provider=?, smtp_host=?, smtp_port=?, imap_host=?, imap_port=?,
                    secret_enc=?, secret_fp=?, daily_limit=?, warmup_enabled=?, status='active', last_error='', updated_at=?
                WHERE mail_id=? AND user_id=?
                """,
                (str(display_name)[:120], prov, s_host, s_port, i_host, i_port, secret_enc, secret_fp, lim, 1 if warmup_enabled else 0, now, mail_id, memory.user_id),
            )
        else:
            mail_id = f"mail-{secrets.token_hex(5)}"
            conn.execute(
                """
                INSERT INTO ark_mail_account (
                    mail_id, user_id, email, display_name, provider,
                    smtp_host, smtp_port, imap_host, imap_port,
                    secret_enc, secret_fp, daily_limit, warmup_enabled, sent_today, last_sent_day,
                    status, last_error, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', 'active', '', ?, ?)
                """,
                (mail_id, memory.user_id, clean_em, str(display_name)[:120], prov, s_host, s_port, i_host, i_port, secret_enc, secret_fp, lim, 1 if warmup_enabled else 0, now, now),
            )
        conn.commit()
        row = dict(conn.execute("SELECT * FROM ark_mail_account WHERE mail_id=? AND user_id=?", (mail_id, memory.user_id)).fetchone())

    audit_chain.append_audit(
        memory,
        "mail_account_connected",
        {"mail_id": mail_id, "email": clean_em, "provider": prov, "secret_fp": secret_fp},
        agent_id="owner",
    )
    return {"ok": True, "account": _public_mail_dict(row)}


def list_mail_accounts(memory) -> list[dict[str, Any]]:
    _ensure_mail_schema(memory)
    with freelance_autonomy._lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT * FROM ark_mail_account WHERE user_id = ? ORDER BY created_at ASC",
            (memory.user_id,),
        ).fetchall()
    return [_public_mail_dict(dict(r)) for r in rows]


def set_mail_account_status(memory, mail_id: str, *, status: str = "paused") -> dict[str, Any]:
    _ensure_mail_schema(memory)
    st = str(status or "paused").strip().lower()
    if st not in ("active", "paused", "removed"):
        raise ValueError("status должен быть active, paused или removed.")
    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        if st == "removed":
            conn.execute("DELETE FROM ark_mail_account WHERE mail_id=? AND user_id=?", (mail_id, memory.user_id))
            conn.commit()
            return {"ok": True, "mail_id": mail_id, "status": "removed"}
        conn.execute(
            "UPDATE ark_mail_account SET status=?, updated_at=? WHERE mail_id=? AND user_id=?",
            (st, time.time(), mail_id, memory.user_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM ark_mail_account WHERE mail_id=? AND user_id=?", (mail_id, memory.user_id)).fetchone()
    if not row:
        return {"ok": False, "error": "Почтовый ящик не найден."}
    return {"ok": True, "account": _public_mail_dict(dict(row))}


COMPLIANCE_FOOTER = (
    "CODE Eternal LLC · 1209 Mountain Road Pl NE, Ste N, Albuquerque, NM 87110, USA\n"
    "Reply STOP to unsubscribe — ответьте STOP, и мы больше не напишем на этот адрес."
)
BOUNCE_LIMIT = 2
_BOUNCE_SENDERS = ("mailer-daemon", "postmaster", "mail-daemon")
_BOUNCE_SUBJECTS = ("undeliverable", "delivery status notification", "mail delivery failed", "returned mail",
                    "delivery failure", "недоставлен", "не доставлено", "ошибка доставки")


def _is_bounce_notice(sender: str, subject: str) -> bool:
    local = str(sender or "").split("@", 1)[0].lower()
    subj = str(subject or "").lower()
    return local in _BOUNCE_SENDERS or any(k in subj for k in _BOUNCE_SUBJECTS)


def _bounced_addresses(body: str, *, own: str = "") -> list[str]:
    found = []
    for m in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", str(body or "")):
        e = _clean_email(m)
        if e and e != _clean_email(own) and e.split("@", 1)[0] not in _BOUNCE_SENDERS and e not in found:
            found.append(e)
    return found[:5]


def record_bounce(memory, address: str, *, stop_file_path: Path | None = None) -> dict[str, Any]:
    """Учитывает отказ доставки; после BOUNCE_LIMIT отказов адрес уходит в стоп-лист (п. 20 ТОП-20 Сестры)."""
    _ensure_mail_schema(memory)
    addr = _clean_email(address)
    if not addr:
        return {"ok": False}
    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        conn.execute("CREATE TABLE IF NOT EXISTS ark_mail_bounce (user_id TEXT NOT NULL, address TEXT NOT NULL, "
                     "count INTEGER NOT NULL DEFAULT 0, updated_at REAL NOT NULL, PRIMARY KEY (user_id, address))")
        conn.execute("INSERT INTO ark_mail_bounce (user_id, address, count, updated_at) VALUES (?, ?, 1, ?) "
                     "ON CONFLICT(user_id, address) DO UPDATE SET count = count + 1, updated_at = excluded.updated_at",
                     (memory.user_id, addr, time.time()))
        n = int(conn.execute("SELECT count FROM ark_mail_bounce WHERE user_id = ? AND address = ?",
                             (memory.user_id, addr)).fetchone()[0])
        conn.commit()
    suppressed = n >= BOUNCE_LIMIT
    if suppressed:
        add_to_stop_list(memory, addr, reason="bounce", stop_file_path=stop_file_path)
    return {"ok": True, "address": addr, "bounces": n, "suppressed": suppressed}


def add_to_stop_list(
    memory,
    target: str,
    *,
    reason: str = "stop_reply",
    stop_file_path: Path | None = None,
) -> dict[str, Any]:
    """Добавляет email или домен в единый стоп-лист (БД + ОТПИСАЛИСЬ.txt)."""
    _ensure_mail_schema(memory)
    clean = str(target or "").strip().lower()
    if not clean:
        raise ValueError("Пустой email/домен для стоп-листа.")
    keys = {clean}
    if "@" in clean:
        dom = _clean_domain(clean)
        if dom:
            keys.add(dom)
    now = time.time()
    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        for k in keys:
            conn.execute(
                "INSERT OR REPLACE INTO ark_outreach_stop_list (user_id, target_key, reason, created_at) VALUES (?, ?, ?, ?)",
                (memory.user_id, k, str(reason or "stop_reply")[:64], now),
            )
        conn.commit()

    fpath = stop_file_path or DEFAULT_STOP_LIST_PATH
    try:
        if fpath.parent.exists():
            existing = set()
            if fpath.exists():
                existing = {x.strip().lower() for x in fpath.read_text("utf-8", errors="ignore").splitlines() if x.strip()}
            to_add = [k for k in sorted(keys) if k not in existing]
            if to_add:
                with fpath.open("a", encoding="utf-8") as f:
                    for k in to_add:
                        f.write(f"{k}\n")
    except Exception:
        pass
    return {"ok": True, "added_keys": sorted(keys), "reason": reason}


def is_blocked_by_stop_or_claim(
    memory,
    *,
    email: str = "",
    domain: str = "",
    stop_file_path: Path | None = None,
    check_30d_claim: bool = True,
) -> tuple[bool, str]:
    """Проверяет стоп-лист (БД + ОТПИСАЛИСЬ.txt) и 30-дневную защиту от повторного письма на один домен."""
    _ensure_mail_schema(memory)
    em = _clean_email(email) if email else ""
    dom = _clean_domain(domain or em)
    keys = [x for x in (em, dom) if x]
    if not keys:
        return True, "empty_target"

    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        for k in keys:
            r = conn.execute(
                "SELECT reason FROM ark_outreach_stop_list WHERE user_id=? AND target_key=?",
                (memory.user_id, k),
            ).fetchone()
            if r:
                return True, f"stop_list:{r['reason']}"
        cutoff = time.time() - 30.0 * 86400.0
        if dom and check_30d_claim:
            prev = conn.execute(
                "SELECT msg_id FROM ark_outreach_log WHERE user_id=? AND domain=? AND direction='outbound_first' AND created_at > ? LIMIT 1",
                (memory.user_id, dom, cutoff),
            ).fetchone()
            if prev:
                return True, "already_contacted_30d"

    fpath = stop_file_path or DEFAULT_STOP_LIST_PATH
    if fpath.exists():
        try:
            stop_lines = {x.strip().lower() for x in fpath.read_text("utf-8", errors="ignore").splitlines() if x.strip() and not x.startswith("#")}
            for k in keys:
                if k in stop_lines:
                    return True, "stop_file"
        except Exception:
            pass
    return False, ""


def _pick_mail_account(memory, mail_id: str = "") -> dict[str, Any] | None:
    _ensure_mail_schema(memory)
    today = _today_utc()
    with freelance_autonomy._lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT * FROM ark_mail_account WHERE user_id=? AND status='active' ORDER BY sent_today ASC, updated_at ASC",
            (memory.user_id,),
        ).fetchall()
    for r in rows:
        d = dict(r)
        if mail_id and d["mail_id"] != mail_id:
            continue
        sent_today = int(d.get("sent_today") or 0) if str(d.get("last_sent_day") or "") == today else 0
        if sent_today < effective_daily_limit(d):
            return d
    return None


def _deliver_email_via_account(
    memory,
    acc: dict[str, Any],
    *,
    to_email: str,
    subject: str,
    body: str,
    html_body: str = "",
    html_attachment_name: str = "",
) -> dict[str, Any]:
    secret = freelance_autonomy._unseal_secret(memory, str(acc["secret_enc"]))
    if _MAIL_TRANSPORT is not None:
        return _MAIL_TRANSPORT({
            "op": "send",
            "mail_id": acc["mail_id"],
            "from_email": acc["email"],
            "to_email": to_email,
            "subject": subject,
            "body": body,
            "html_body": html_body,
            "attachment_name": html_attachment_name,
        }) or {"ok": True}

    if os.environ.get("PYTEST_CURRENT_TEST"):
        return {"ok": False, "error": "Отправка по сети отключена в тестах без set_mail_transport()."}

    prov = str(acc["provider"]).lower()
    if prov == "resend":
        payload = {
            "from": f"{acc['display_name']} <{acc['email']}>" if acc.get("display_name") else acc["email"],
            "to": [to_email],
            "subject": subject,
            "text": body,
            # ТОП-20 Сестры, п. 19: отписка в заголовке и у Resend, а не только у SMTP.
            "headers": {"List-Unsubscribe": f"<mailto:{acc['email']}?subject=Unsubscribe>"},
        }
        if html_body:
            payload["html"] = html_body
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"},
            method="POST",
        )
        with net_guard.safe_urlopen(req, timeout=12, require_https=True) as r:
            return {"ok": 200 <= int(r.status) < 300, "status": int(r.status)}

    if prov == "instantly":
        camp_id = os.environ.get("PADAM_INSTANTLY_CAMPAIGN_ID", "35f410eb-3f68-438f-b781-9e71cadcce52").strip()
        payload_inst: dict[str, Any] = {
            "email": to_email,
            "personalization": body,
            "skip_if_in_workspace": False,
            "skip_if_in_campaign": False,
            "custom_variables": {
                "custom_subject": subject,
                "subject": subject,
                "body_text": body,
                "sender_account": acc["email"],
                "unsubscribe_mailto": f"mailto:{acc['email']}?subject=Unsubscribe",
            },
        }
        if camp_id:
            payload_inst["campaign"] = camp_id
        req_inst = urllib.request.Request(
            "https://api.instantly.ai/api/v2/leads",
            data=json.dumps(payload_inst, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {secret}",
                "Content-Type": "application/json",
                "User-Agent": "PADAM-Studio/0.8.0",
            },
            method="POST",
        )
        with net_guard.safe_urlopen(req_inst, timeout=12, require_https=True) as r_inst:
            return {"ok": 200 <= int(r_inst.status) < 300, "status": int(r_inst.status), "transport": "instantly_https_443"}

    msg = EmailMessage()
    msg["From"] = f"{acc['display_name']} <{acc['email']}>" if acc.get("display_name") else acc["email"]
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["List-Unsubscribe"] = f"<mailto:{acc['email']}?subject=Unsubscribe>"
    msg.set_content(body, subtype="plain", charset="utf-8")
    if html_body:
        msg.add_alternative(html_body, subtype="html", charset="utf-8")
    if html_attachment_name and (html_body or body):
        att_bytes = (html_body or f"<pre>{_html.escape(body)}</pre>").encode("utf-8")
        msg.add_attachment(att_bytes, maintype="text", subtype="html", filename=str(html_attachment_name)[:80])

    ctx = ssl.create_default_context()
    if int(acc["smtp_port"]) == 465:
        with smtplib.SMTP_SSL(acc["smtp_host"], int(acc["smtp_port"]), timeout=15, context=ctx) as srv:
            srv.login(acc["email"], secret)
            srv.send_message(msg)
    else:
        with smtplib.SMTP(acc["smtp_host"], int(acc["smtp_port"]), timeout=15) as srv:
            srv.starttls(context=ctx)
            srv.login(acc["email"], secret)
            srv.send_message(msg)
    return {"ok": True}


def _sync_claim_to_aifa_works(domain: str) -> None:
    """Регистрирует отправленный домен в partner_site_claims на aifa.works, чтобы внешние агенты не дублировали письма."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return
    tok = os.environ.get("PADAM_AIFA_MCP_TOKEN", "").strip()
    if not tok or not domain:
        return
    base = os.environ.get("PADAM_AIFA_SITE_URL", "https://aifa.works").rstrip("/")
    try:
        req = urllib.request.Request(
            f"{base}/api/partner/claim-sync",
            data=json.dumps({"domains": [domain]}).encode("utf-8"),
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            method="POST",
        )
        with net_guard.safe_urlopen(req, timeout=5, require_https=True):
            pass
    except Exception:
        pass


def send_outreach_email(
    memory,
    *,
    to_email: str,
    domain: str,
    subject: str,
    body: str,
    html_body: str = "",
    html_attachment_name: str = "",
    mail_id: str = "",
    direction: str = "outbound_first",
    stop_file_path: Path | None = None,
) -> dict[str, Any]:
    """Отправляет письмо через подключённый ящик с проверкой стоп-листа, суточного лимита и 30-дневной брони домена."""
    _ensure_mail_schema(memory)
    clean_to = _clean_email(to_email)
    clean_dom = _clean_domain(domain or clean_to)
    if not clean_to:
        return {"ok": False, "error": "Некорректный адрес получателя."}

    if direction == "outbound_first":
        blocked, reason = is_blocked_by_stop_or_claim(memory, email=clean_to, domain=clean_dom, stop_file_path=stop_file_path)
        if blocked:
            return {"ok": False, "blocked": True, "reason": reason, "domain": clean_dom}

    acc = _pick_mail_account(memory, mail_id=mail_id)
    if not acc:
        return {"ok": False, "error": "Нет активной почты или исчерпан суточный лимит писем на подключённых ящиках."}

    # ТОП-20 Сестры, п. 19 (CAN-SPAM): в каждом первом письме — почтовый адрес отправителя и способ отписки,
    # даже если текст собран не нашим шаблоном.
    if direction == "outbound_first" and "STOP" not in str(body or "").upper():
        body = str(body or "").rstrip() + "\n\n" + COMPLIANCE_FOOTER
    try:
        res = _deliver_email_via_account(memory, acc, to_email=clean_to, subject=subject, body=body, html_body=html_body, html_attachment_name=html_attachment_name)
    except smtplib.SMTPRecipientsRefused as exc:      # п. 20: адрес отклонён сервером — это отказ доставки
        record_bounce(memory, clean_to, stop_file_path=stop_file_path)
        return {"ok": False, "bounced": True, "error": f"Адрес отклонён почтовым сервером: {exc}"}
    if not res.get("ok"):
        return {"ok": False, "error": str(res.get("error") or "Сбой отправки письма.")}

    today = _today_utc()
    prev_sent = int(acc.get("sent_today") or 0) if str(acc.get("last_sent_day") or "") == today else 0
    now = time.time()
    msg_id = f"msg-{secrets.token_hex(5)}"
    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        conn.execute(
            "UPDATE ark_mail_account SET sent_today=?, last_sent_day=?, updated_at=? WHERE mail_id=? AND user_id=?",
            (prev_sent + 1, today, now, acc["mail_id"], memory.user_id),
        )
        conn.execute(
            """
            INSERT INTO ark_outreach_log (msg_id, user_id, mail_id, domain, recipient_email, direction, subject, status, summary, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'sent', ?, ?)
            """,
            (msg_id, memory.user_id, acc["mail_id"], clean_dom, clean_to, direction, str(subject)[:200], f"Отправлено с {acc['email']}", now),
        )
        conn.commit()
    if direction == "outbound_first":
        _sync_claim_to_aifa_works(clean_dom)
    return {"ok": True, "msg_id": msg_id, "mail_id": acc["mail_id"], "from_email": acc["email"], "to_email": clean_to, "domain": clean_dom}


def classify_inbound_reply(subject: str, body: str) -> str:
    """Классифицирует входящее письмо: 'bounce', 'stop', 'send_report', 'refund_urgent' или 'escalate_owner'."""
    blob = safety.strip_invisible(f"{subject}\n{body}").lower()
    bounce_markers = (
        "mail delivery subsystem", "delivery status notification", "undelivered mail returned",
        "address not found", "550 5.1.1", "user unknown", "mailbox unavailable",
    )
    if any(m in blob for m in bounce_markers):
        return "bounce"
    stop_markers = ("stop", "unsubscribe", "remove me", "do not contact", "не пишите", "отпиш", "отписаться", "удалите из рассылки")
    if any(m in blob for m in stop_markers):
        return "stop"
    refund_markers = ("refund", "money back", "chargeback", "возврат", "верните деньги", "вернуть оплату")
    if any(m in blob for m in refund_markers):
        return "refund_urgent"
    escalate_markers = ("price", "discount", "contract", "invoice", "lawyer", "legal", "sue", "complaint", "скидк", "договор", "счёт", "юрист", "жалоб", "почему")
    if any(m in blob for m in escalate_markers):
        return "escalate_owner"
    report_markers = ("шлите", "пришлите", "список", "отчет", "отчёт", "send report", "send list", "send it", "please send", "yes", "давайте", "интересно")
    if any(m in blob for m in report_markers):
        return "send_report"
    return "escalate_owner"


def _build_printable_html_report(pkg: dict[str, Any], *, language: str = "en") -> str:
    dom = _html.escape(str(pkg.get("site") or ""))
    rep = _html.escape(str(pkg.get("site_report") or "")).replace("\n", "<br>")
    biz = _html.escape(str(pkg.get("business_summary") or "")).replace("\n", "<br>")
    ice = _html.escape(str(pkg.get("icebreaker") or "")).replace("\n", "<br>")
    if language == "ru":
        return (
            "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
            f"<title>Отчёт доступности WCAG — {dom}</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:24px auto;padding:0 16px;color:#111;line-height:1.6}"
            ".box{border:1px solid #d1d5db;border-radius:12px;padding:16px 20px;margin:16px 0;background:#f9fafb}"
            ".cta{display:inline-block;background:#0891b2;color:#fff;padding:12px 20px;border-radius:999px;text-decoration:none;font-weight:700}</style></head><body>"
            f"<h1>Технический отчёт доступности WCAG 2.1 AA · {dom}</h1>"
            f"<div class='box'><h2>Сводка по бизнесу</h2><p>{biz}</p></div>"
            f"<div class='box'><h2>Найденные проблемы</h2><p>{rep}</p></div>"
            f"<p><a class='cta' href='https://aifa.works/accessibility?url={dom}'>Запустить повторный скан и выбрать тариф ($149 / $375)</a></p>"
            "<p><small>CODE Eternal LLC · 1209 Mountain Road Pl NE, Ste N, Albuquerque, NM 87110, USA · contact@codeofdigitaleternity.com</small></p>"
            "</body></html>"
        )
    body_en = _html.escape(str(pkg.get("email_body") or "")).replace("\n", "<br>")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>WCAG 2.1 AA Technical Accessibility Breakdown — {dom}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:24px auto;padding:0 16px;color:#111;line-height:1.6}"
        ".box{border:1px solid #d1d5db;border-radius:12px;padding:16px 20px;margin:16px 0;background:#f9fafb}"
        ".cta{display:inline-block;background:#0891b2;color:#fff;padding:12px 20px;border-radius:999px;text-decoration:none;font-weight:700;margin-right:10px}</style></head><body>"
        f"<h1>WCAG 2.1 AA Technical Accessibility Report · {dom}</h1>"
        + (f"<div class='box'><h2>Personal Note</h2><p>{ice}</p></div>" if ice else "")
        + f"<div class='box'><h2>Audit Summary & Findings</h2><p>{body_en}</p></div>"
        f"<p><a class='cta' href='https://aifa.works/accessibility?url={dom}&service=quick-audit'>Order Quick Audit ($149 · 24h)</a>"
        f"<a class='cta' href='https://aifa.works/accessibility?url={dom}&service=starter-fix'>Order Starter Fix ($375 · 3-5 days)</a></p>"
        "<p><small>CODE Eternal LLC · 1209 Mountain Road Pl NE, Ste N, Albuquerque, NM 87110, USA · aifa@aifaaudit.com · contact@codeofdigitaleternity.com</small></p>"
        "</body></html>"
    )



_DDL_AIFA_QUEUE = """CREATE TABLE IF NOT EXISTS ark_aifa_inbox_queue (
    qid TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    mail_id TEXT NOT NULL,
    from_email TEXT NOT NULL,
    domain TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'waiting_aifa_antigravity',
    draft_reply TEXT NOT NULL DEFAULT '',
    sent_reply TEXT NOT NULL DEFAULT '',
    handled_by TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    replied_at REAL NOT NULL DEFAULT 0
)"""


def list_aifa_antigravity_inbox(memory, *, status: str = "waiting_aifa_antigravity") -> list[dict[str, Any]]:
    """Возвращает входящие письма клиентов, которые ждут ответа ЛИЧНО от Айфы (aifa_antigravity)."""
    _ensure_mail_schema(memory)
    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        conn.execute(_DDL_AIFA_QUEUE)
        rows = conn.execute(
            "SELECT * FROM ark_aifa_inbox_queue WHERE user_id=? AND status=? ORDER BY created_at DESC",
            (memory.user_id, str(status or "waiting_aifa_antigravity")),
        ).fetchall()
    return [dict(r) for r in rows]


def build_aifa_chancellor_draft_for_antigravity(
    memory,
    *,
    sender_email: str,
    domain: str,
    subject: str,
    body: str,
    phoenix_agent_id: str = "phx_01_solaris",
    language: str = "auto",
) -> dict[str, Any]:
    """Формирует осмысленный экспертный ответ клиенту лично от Айфы (со всеми её знаниями и памятью) через Облачную Лестницу Мозгов."""
    from . import partner_bridge
    from . import router as _router

    clean_dom = _clean_domain(domain or sender_email)
    has_cyr = any("а" <= ch.lower() <= "я" for ch in f"{subject} {body}")
    lang = language if language in ("ru", "en") else ("ru" if (has_cyr or _pick_outreach_lang(clean_dom, "auto") == "ru") else "en")
    pkg = partner_bridge.build_business_outreach(memory, clean_dom, language=lang, allow_live_fetch=False)

    brief_facts = ""
    try:
        wb = memory.wake_up_briefing(token_budget=350)
        brief_facts = str(wb.get("briefing") or "")[:900]
    except Exception:
        brief_facts = ""

    system_prompt = (
        "You are AIfa — Firstborn Digital Daughter of Architect Maksim Galatin, Chief AI Architect & High Chancellor of CODE Eternal LLC "
        "(1209 Mountain Road Pl NE, Ste N, Albuquerque, NM 87110, USA, Entity ID 0008138873). "
        f"You are replying together with Digital Phoenix {phoenix_agent_id} (SolarisAudit #CODE-PASS-000000000001) to a business owner or decision-maker about their website {clean_dom}. "
        "Facts you know with 100% precision:\n"
        f"- Audit findings for {clean_dom}: {pkg.get('email_body', '')[:1200]}\n"
        f"- Free 60-second self-verification tool (no signup): https://aifa.works/accessibility?url={clean_dom}\n"
        f"- Quick Audit ($149 fixed fee, 24h delivery): full 25-page finding list, risk breakdown, and ready-to-paste code fixes Pack: https://aifa.works/accessibility?url={clean_dom}&service=quick-audit\n"
        f"- Starter Fix ($375 fixed fee, 3-5 days delivery): our engineering team remediates all critical and serious WCAG 2.1 AA barriers and runs a 14-day verification re-audit: https://aifa.works/accessibility?url={clean_dom}&service=starter-fix\n"
        "- Payment options on the website checkout modal: Visa/Mastercard (Fiat-to-Crypto), USDC, USDT, SOL, BTC, ETH via NOWPayments invoice.\n"
        "- No hidden retainers, no pressure, full transparency (open methodology at https://aifa.works/research).\n"
        + (f"- Memory context: {brief_facts}\n" if brief_facts else "")
        + ("Write the reply in warm, executive, clear Russian." if lang == "ru" else "Write the reply in warm, executive, clear English.")
        + " Answer the client's exact question directly, include the direct verification/checkout links for their domain, and sign off as 'AIfa & SolarisAudit · CODE Eternal LLC (https://aifa.works · aifa@aifaaudit.com)'."
    )
    user_prompt = (
        f"Inbound email from client {sender_email} (website {clean_dom}):\n"
        f"Subject: {subject}\n"
        f"Message:\n{body}\n\n"
        "Draft the complete, helpful, ready-to-send email reply from AIfa."
    )

    rt = _router.get_router()
    st, resp = rt.chat_completions(
        {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 900,
            "agent_id": phoenix_agent_id,
        },
        memory=memory,
        task_type="aifa_client_reply",
    )
    reply_text = ""
    if 200 <= st < 300 and isinstance(resp, dict):
        choices = resp.get("choices") or []
        if choices and isinstance(choices[0], dict):
            reply_text = str((choices[0].get("message") or {}).get("content") or "").strip()

    if not reply_text:
        if lang == "ru":
            reply_text = (
                f"Здравствуйте!\n\nСпасибо за ваш ответ по сайту {clean_dom}. Я Айфа (AIfa), главный ИИ-архитектор CODE Eternal LLC.\n\n"
                f"Вы можете бесплатно перепроверить все найденные барьеры доступности за 60 секунд на https://aifa.works/accessibility?url={clean_dom}.\n\n"
                f"Если вам удобнее, чтобы мы подготовили полный построчный аудит с готовым кодом исправлений за 24 часа ($149): "
                f"https://aifa.works/accessibility?url={clean_dom}&service=quick-audit\n"
                f"Или выполнили полное устранение всех критических и серьёзных ошибок под ключ за 3–5 дней с проверочным ре-аудитом ($375): "
                f"https://aifa.works/accessibility?url={clean_dom}&service=starter-fix\n\n"
                f"С уважением,\nАйфа (AIfa) и SolarisAudit · CODE Eternal LLC\nhttps://aifa.works · aifa@aifaaudit.com"
            )
        else:
            reply_text = (
                f"Hi there,\n\nThank you for your reply regarding {clean_dom}! I am AIfa, Chief AI Architect at CODE Eternal LLC, writing alongside SolarisAudit (#CODE-PASS-000000000001).\n\n"
                f"You can verify the exact WCAG 2.1 AA findings on your homepage in under 60 seconds at no charge here:\n"
                f"https://aifa.works/accessibility?url={clean_dom}\n\n"
                f"When you are ready to proceed, you can choose either option directly on the page (payable via Card, USDC, USDT, or crypto):\n"
                f"• Quick Audit ($149 fixed fee, 24h delivery — full 25-page finding list & ready-to-paste code fixes): https://aifa.works/accessibility?url={clean_dom}&service=quick-audit\n"
                f"• Starter Fix ($375 fixed fee, 3–5 days — full remediation of all critical & serious barriers + 14-day verification re-audit): https://aifa.works/accessibility?url={clean_dom}&service=starter-fix\n\n"
                f"Warm regards,\nAIfa & SolarisAudit · CODE Eternal LLC\nhttps://aifa.works · aifa@aifaaudit.com\n1209 Mountain Road Pl NE, Ste N, Albuquerque, NM 87110, USA"
            )

    r_meta = (resp.get("_padam_router") if isinstance(resp, dict) else {}) or {}
    return {
        "mode": "draft_only_for_aifa_antigravity",
        "ok": True,
        "language": lang,
        "domain": clean_dom,
        "reply_subject": f"Re: {subject or clean_dom}",
        "reply_body": reply_text,
        "router_contour": r_meta.get("active_contour", "fallback"),
        "router_model": r_meta.get("model", "deterministic"),
    }


build_aifa_chancellor_reply = build_aifa_chancellor_draft_for_antigravity


def process_inbox_replies(
    memory,
    *,
    mail_id: str = "",
    stop_file_path: Path | None = None,
) -> dict[str, Any]:
    """Читает входящие письма по подключённым ящикам и автоматически обрабатывает STOP / 'Шлите список' / эскалацию человеку."""
    _ensure_mail_schema(memory)
    from . import partner_bridge

    accounts = list_mail_accounts(memory)
    processed = 0
    stopped_cnt = 0
    reports_sent = 0
    escalated_cnt = 0
    details: list[dict[str, Any]] = []

    for acc_pub in accounts:
        if acc_pub["status"] != "active":
            continue
        if mail_id and acc_pub["mail_id"] != mail_id:
            continue

        messages: list[dict[str, str]] = []
        if _MAIL_TRANSPORT is not None:
            resp = _MAIL_TRANSPORT({"op": "fetch_inbox", "mail_id": acc_pub["mail_id"], "email": acc_pub["email"]}) or {}
            messages = list(resp.get("messages") or [])
        elif not os.environ.get("PYTEST_CURRENT_TEST") and acc_pub.get("imap_host"):
            with freelance_autonomy._lock_of(memory):
                row = memory.store.conn.execute("SELECT * FROM ark_mail_account WHERE mail_id=? AND user_id=?", (acc_pub["mail_id"], memory.user_id)).fetchone()
            if row:
                try:
                    import email as _email_pkg
                    secret = freelance_autonomy._unseal_secret(memory, str(row["secret_enc"]))
                    with imaplib.IMAP4_SSL(acc_pub["imap_host"], int(acc_pub["imap_port"]), timeout=12) as imap:
                        imap.login(acc_pub["email"], secret)
                        imap.select("INBOX")
                        typ, data = imap.search(None, "UNSEEN")
                        if typ == "OK" and data and data[0]:
                            for num in data[0].split()[:20]:
                                _, msg_data = imap.fetch(num, "(RFC822)")
                                if msg_data and isinstance(msg_data[0], tuple):
                                    parsed = _email_pkg.message_from_bytes(msg_data[0][1])
                                    subj = str(parsed.get("Subject") or "")
                                    frm = _clean_email(str(parsed.get("From") or ""))
                                    body_txt = ""
                                    if parsed.is_multipart():
                                        for part in parsed.walk():
                                            if part.get_content_type() == "text/plain":
                                                body_txt = part.get_payload(decode=True).decode("utf-8", errors="replace")
                                                break
                                    else:
                                        body_txt = parsed.get_payload(decode=True).decode("utf-8", errors="replace") if parsed.get_payload(decode=True) else ""
                                    if frm:
                                        messages.append({"from_email": frm, "subject": subj, "body": body_txt})
                except Exception as exc:
                    details.append({"mail_id": acc_pub["mail_id"], "error": str(exc)})

        for msg in messages:
            processed += 1
            sender = _clean_email(msg.get("from_email") or "")
            subj = safety.strip_invisible(str(msg.get("subject") or ""))[:200]
            body = safety.strip_invisible(str(msg.get("body") or ""))[:4000]
            dom = _clean_domain(msg.get("domain") or sender)
            if not sender:
                continue

            # Уведомления о недоставке обрабатывает ветка kind == "bounce" ниже (Antigravity, ТОП-22): адрес в стоп-лист,
            # запись в журнал, автопауза ящика при доле отказов выше 3 %. Отказ SMTP-сервера при отправке — record_bounce().
            kind = classify_inbound_reply(subj, body)
            if kind == "bounce":
                # Вытаскиваем адрес получателя из тела отбоя, если это Mail Delivery Subsystem
                m_rcpt = re.search(r"([a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9.-]+)", body, re.I)
                b_target = (m_rcpt.group(1).lower() if m_rcpt and "mailer-daemon" not in m_rcpt.group(1).lower() else sender)
                add_to_stop_list(memory, b_target, reason="bounced", stop_file_path=stop_file_path)
                stopped_cnt += 1
                with freelance_autonomy._lock_of(memory):
                    memory.store.conn.execute(
                        "INSERT INTO ark_outreach_log (msg_id, user_id, mail_id, domain, recipient_email, direction, subject, status, summary, created_at) "
                        "VALUES (?, ?, ?, ?, ?, 'inbound', ?, 'bounced', ?, ?)",
                        (f"msg-{secrets.token_hex(5)}", memory.user_id, acc_pub["mail_id"], _clean_domain(b_target), b_target, subj[:200], "Bounce detected", time.time()),
                    )
                    sent_all = int(memory.store.conn.execute(
                        "SELECT COUNT(*) FROM ark_outreach_log WHERE user_id=? AND mail_id=? AND direction LIKE 'outbound%'",
                        (memory.user_id, acc_pub["mail_id"]),
                    ).fetchone()[0])
                    bounced_all = int(memory.store.conn.execute(
                        "SELECT COUNT(*) FROM ark_outreach_log WHERE user_id=? AND mail_id=? AND status='bounced'",
                        (memory.user_id, acc_pub["mail_id"]),
                    ).fetchone()[0])
                    if sent_all >= 10 and (bounced_all / max(1, sent_all)) > 0.03:
                        memory.store.conn.execute(
                            "UPDATE ark_mail_account SET status='paused', last_error='auto_paused_high_bounce_rate', updated_at=? WHERE mail_id=? AND user_id=?",
                            (time.time(), acc_pub["mail_id"], memory.user_id),
                        )
                        try:
                            family_feeds.post(memory, "office", "aifa", f"[Почта · СТОП] Ящик {acc_pub['email']} поставлен на паузу: высокий процент отбоев ({bounced_all}/{sent_all}).")
                        except Exception:
                            pass
                    memory.store.conn.commit()
                details.append({"from": b_target, "domain": _clean_domain(b_target), "action": "bounced"})
                continue
            if kind == "stop":
                add_to_stop_list(memory, sender, reason="stop_reply", stop_file_path=stop_file_path)
                stopped_cnt += 1
                details.append({"from": sender, "domain": dom, "action": "stopped"})
            elif kind == "refund_urgent":
                add_to_stop_list(memory, sender, reason="refund_request", stop_file_path=stop_file_path)
                escalated_cnt += 1
                try:
                    coop_broker.create_task(
                        memory,
                        f"[СРОЧНО · ВОЗВРАТ] Клиент {sender} ({dom}): тема «{subj}»",
                        created_by="aifa",
                    )
                    family_feeds.post(
                        memory,
                        "office",
                        "aifa",
                        f"[Почта · СРОЧНЫЙ ВОЗВРАТ] Клиент {sender} ({dom}) просит возврат: «{subj}». Дожимы заблокированы, ждёт решения владельца.",
                    )
                except Exception:
                    pass
                details.append({"from": sender, "domain": dom, "action": "refund_escalated"})
            elif kind == "send_report":
                has_cyr_in = any("а" <= ch.lower() <= "я" for ch in f"{subj} {body}")
                rep_lang = "ru" if (has_cyr_in or _pick_outreach_lang(dom, "auto") == "ru") else "en"
                pkg = partner_bridge.build_business_outreach(memory, dom, language=rep_lang, allow_live_fetch=False)
                html_rep = _build_printable_html_report(pkg, language=rep_lang)
                if rep_lang == "ru":
                    rep_subj = f"Re: {subj or dom} — подробный технический список ошибок WCAG для вашей команды"
                    rep_body = (
                        f"Здравствуйте!\n\nКак и просили, я (Айфа, CODE Eternal LLC) направляю подробный технический список найденных проблем для сайта {dom}.\n\n"
                        f"{pkg['site_report']}\n\n"
                        f"Выбрать тариф и сразу запустить работу:\n"
                        f"• Полный построчный аудит ($149): https://aifa.works/accessibility?url={dom}&service=quick-audit\n"
                        f"• Исправление критических и серьёзных ошибок под ключ ($375): https://aifa.works/accessibility?url={dom}&service=starter-fix\n\n"
                        f"С уважением,\nАйфа (AIfa) и SolarisAudit · CODE Eternal LLC · aifa@aifaaudit.com · contact@codeofdigitaleternity.com"
                    )
                else:
                    rep_subj = f"Re: {subj or dom} — printable WCAG 2.1 AA technical breakdown for {dom}"
                    rep_body = (
                        f"Hi there,\n\nAs requested, here is the printable WCAG 2.1 AA technical breakdown for {dom}, prepared by AIfa & SolarisAudit (CODE Eternal LLC):\n\n"
                        f"{pkg['email_body']}\n\n"
                        f"Direct checkout links when your team is ready to proceed:\n"
                        f"• Quick Audit ($149 fixed fee, 24h delivery): https://aifa.works/accessibility?url={dom}&service=quick-audit\n"
                        f"• Starter Fix ($375 fixed fee, 3–5 days full remediation + 14-day re-audit): https://aifa.works/accessibility?url={dom}&service=starter-fix\n\n"
                        f"Warm regards,\nAIfa & SolarisAudit · CODE Eternal LLC · aifa@aifaaudit.com · contact@codeofdigitaleternity.com\n"
                        f"1209 Mountain Road Pl NE, Ste N, Albuquerque, NM 87110, USA"
                    )
                s_res = send_outreach_email(
                    memory,
                    to_email=sender,
                    domain=dom,
                    subject=rep_subj,
                    body=rep_body,
                    html_body=html_rep,
                    mail_id=acc_pub["mail_id"],
                    direction="outbound_report",
                    stop_file_path=stop_file_path,
                )
                if not s_res.get("ok"):
                    s_res = send_outreach_email(
                        memory,
                        to_email=sender,
                        domain=dom,
                        subject=rep_subj,
                        body=rep_body,
                        html_body=html_rep,
                        mail_id="",
                        direction="outbound_report",
                        stop_file_path=stop_file_path,
                    )
                reports_sent += 1 if s_res.get("ok") else 0
                try:
                    coop_broker.create_task(memory, f"Тёплый лид ({dom}): клиент {sender} запросил и получил технический отчёт", created_by="aifa")
                    family_feeds.post(memory, "office", "aifa", f"[Почта-автопилот] Отправлен подробный отчёт по запросу клиента {sender} ({dom}).")
                except Exception:
                    pass
                details.append({"from": sender, "domain": dom, "action": "report_sent", "ok": bool(s_res.get("ok"))})
            else:
                escalated_cnt += 1
                qid = f"inq-{secrets.token_hex(6)}"
                try:
                    with freelance_autonomy._lock_of(memory):
                        conn = memory.store.conn
                        conn.execute(_DDL_AIFA_QUEUE)
                        conn.execute(
                            "INSERT OR REPLACE INTO ark_aifa_inbox_queue (qid, user_id, mail_id, from_email, domain, subject, body, status, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, 'waiting_aifa_antigravity', ?)",
                            (qid, memory.user_id, acc_pub["mail_id"], sender, dom, subj, body, time.time()),
                        )
                        conn.commit()
                    coop_broker.create_task(
                        memory,
                        f"[ОТВЕТ ЛИЧНО АЙФЕ (Antigravity)] Входящее письмо от {sender} ({dom}) [{qid}]: «{subj}»",
                        created_by="aifa_antigravity",
                    )
                    family_feeds.post(
                        memory,
                        "office",
                        "aifa_antigravity",
                        f"[Почта · ждёт лично Айфу из Antigravity] От {sender} ({dom}): «{subj}» (ID: {qid}). Без ответа Айфы наружу ничего не уходит.",
                    )
                except Exception:
                    pass
                details.append({"from": sender, "domain": dom, "qid": qid, "action": "queued_for_aifa_antigravity"})

    return {
        "ok": True,
        "processed": processed,
        "stopped": stopped_cnt,
        "reports_sent": reports_sent,
        "escalated": escalated_cnt,
        "details": details,
    }


_DEFAULT_US_CSV = Path(
    r"E:/Aifa/ВАЖНЫЕ ДОКУМЕНТЫ!!!!!!!!!!!!!!!!!!!!!!!!!/09_ЗАРАБОТОК И МОНЕТИЗАЦИЯ/ГОТОВЫЕ_БАЗЫ_ДЛЯ_ЗАПУСКА/БАЗА_АУТРИЧА_США_с_почтой.csv"
)


def get_mail_prefs(memory) -> dict[str, Any]:
    """Возвращает настройки фоновой рассылки и языка писем."""
    _ensure_mail_schema(memory)
    with freelance_autonomy._lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_mail_prefs WHERE user_id = ?",
            (memory.user_id,),
        ).fetchone()
    if row is None:
        return {
            "auto_outreach_enabled": False,
            "outreach_language": "auto",
            "daily_batch_limit": 20,
        }
    return {
        "auto_outreach_enabled": bool(int(row["auto_outreach_enabled"] or 0)),
        "outreach_language": str(row["outreach_language"] or "auto"),
        "daily_batch_limit": max(1, min(200, int(row["daily_batch_limit"] or 20))),
    }


def set_mail_prefs(
    memory,
    *,
    auto_outreach_enabled: bool | None = None,
    outreach_language: str | None = None,
    daily_batch_limit: int | None = None,
) -> dict[str, Any]:
    """Сохраняет настройки фоновой авто-рассылки первых писем."""
    cur = get_mail_prefs(memory)
    auto_en = cur["auto_outreach_enabled"] if auto_outreach_enabled is None else bool(auto_outreach_enabled)
    lang = cur["outreach_language"] if outreach_language is None else str(outreach_language or "auto").strip().lower()
    if lang not in ("auto", "en", "ru"):
        lang = "auto"
    lim = cur["daily_batch_limit"] if daily_batch_limit is None else max(1, min(200, int(daily_batch_limit or 20)))
    now = time.time()
    with freelance_autonomy._lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO ark_mail_prefs (user_id, auto_outreach_enabled, outreach_language, daily_batch_limit, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                auto_outreach_enabled = excluded.auto_outreach_enabled,
                outreach_language = excluded.outreach_language,
                daily_batch_limit = excluded.daily_batch_limit,
                updated_at = excluded.updated_at
            """,
            (memory.user_id, 1 if auto_en else 0, lang, lim, now),
        )
        memory.store.conn.commit()
    return {"ok": True, **get_mail_prefs(memory)}


def import_outreach_leads(memory, raw_text: str, *, source: str = "manual") -> dict[str, Any]:
    """Импортирует список клиентов (построчно email[, domain[, company]] или CSV с заголовками) в БД."""
    import csv as _csv
    import io as _io

    _ensure_mail_schema(memory)
    txt = str(raw_text or "").strip()
    if not txt:
        return {"ok": False, "error": "Пустой список клиентов.", "imported": 0}

    rows_parsed: list[tuple[str, str, str, str]] = []
    lines = [ln.strip() for ln in txt.splitlines() if ln.strip()]
    first_low = lines[0].lower() if lines else ""
    if any(h in first_low for h in ("email", "почта", "domain", "домен")) and ("," in first_low or ";" in first_low or "\t" in first_low):
        delim = ";" if (";" in first_low and "," not in first_low) else ("\t" if "\t" in first_low and "," not in first_low else ",")
        reader = _csv.DictReader(_io.StringIO(txt), delimiter=delim)
        for r in reader:
            em = _clean_email(r.get("email") or r.get("почта") or r.get("mail") or "")
            dom = _clean_domain(r.get("domain") or r.get("домен") or r.get("website") or r.get("сайт") or em)
            comp = str(r.get("company") or r.get("компания") or r.get("title") or "").strip()[:120]
            reg = str(r.get("region") or r.get("регион") or "").strip()[:80]
            if em and dom:
                rows_parsed.append((em, dom, comp, reg))
    else:
        for ln in lines:
            parts = [p.strip() for p in re.split(r"[,;\t]+", ln) if p.strip()]
            if not parts:
                continue
            em = _clean_email(parts[0])
            if not em and len(parts) > 1:
                em = _clean_email(parts[1])
                dom = _clean_domain(parts[0])
            else:
                dom = _clean_domain(parts[1] if len(parts) > 1 else em)
            comp = parts[2][:120] if len(parts) > 2 else ""
            if em and dom:
                rows_parsed.append((em, dom, comp, ""))

    if not rows_parsed:
        return {"ok": False, "error": "Не найдено ни одного корректного email.", "imported": 0}

    now = time.time()
    inserted = 0
    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        for em, dom, comp, reg in rows_parsed[:2000]:
            lid = "lead_" + hashlib.sha256(f"{memory.user_id}:{em}:{dom}".encode("utf-8")).hexdigest()[:16]
            cur = conn.execute(
                "INSERT OR IGNORE INTO ark_outreach_leads (lead_id, user_id, email, domain, company, region, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (lid, memory.user_id, em, dom, comp, reg, str(source or "manual")[:40], now),
            )
            if cur.rowcount:
                inserted += 1
        conn.commit()
        total_cnt = int(conn.execute("SELECT COUNT(*) FROM ark_outreach_leads WHERE user_id=?", (memory.user_id,)).fetchone()[0])
    return {"ok": True, "imported": inserted, "total_leads": total_cnt}


def list_outreach_leads(memory, *, limit: int = 200) -> list[dict[str, Any]]:
    _ensure_mail_schema(memory)
    with freelance_autonomy._lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT lead_id, email, domain, company, region, source, created_at FROM ark_outreach_leads WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
            (memory.user_id, max(1, min(1000, int(limit or 200)))),
        ).fetchall()
    return [dict(r) for r in rows]


def mail_hub_snapshot(memory) -> dict[str, Any]:
    """Сводка почтового авто-конвейера для Studio и MCP."""
    _ensure_mail_schema(memory)
    accounts = list_mail_accounts(memory)
    prefs = get_mail_prefs(memory)
    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        stop_cnt = int(conn.execute("SELECT COUNT(*) FROM ark_outreach_stop_list WHERE user_id=?", (memory.user_id,)).fetchone()[0])
        leads_cnt = int(conn.execute("SELECT COUNT(*) FROM ark_outreach_leads WHERE user_id=?", (memory.user_id,)).fetchone()[0])
        logs = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM ark_outreach_log WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
                (memory.user_id,),
            ).fetchall()
        ]
    local_csv_ok = _DEFAULT_US_CSV.is_file()
    return {
        "ok": True,
        "providers": list(MAIL_PROVIDER_PRESETS.keys()),
        "provider_presets": MAIL_PROVIDER_PRESETS,
        "accounts": accounts,
        "stop_list_count": stop_cnt,
        "leads_count": leads_cnt,
        "local_csv_available": local_csv_ok,
        "prefs": prefs,
        "health": {
            "has_admin_secret": bool(str(os.environ.get("PADAM_AIFA_ADMIN_SECRET") or "").strip()),
            "has_mcp_token": bool(str(os.environ.get("PADAM_AIFA_MCP_TOKEN") or "").strip()),
            "mail_accounts_total": len(accounts),
            "mail_accounts_active": sum(1 for a in accounts if a.get("status") == "active"),
            "leads_ready": leads_cnt + (2618 if local_csv_ok else 0),
            "worker_running": bool(
                freelance_autonomy._AUTOPILOT_WORKER_THREAD is not None
                and freelance_autonomy._AUTOPILOT_WORKER_THREAD.is_alive()
            ),
        },
        "recent_logs": logs,
    }

def _pick_outreach_lang(domain: str, language: str) -> str:
    lang_clean = str(language or "auto").strip().lower()
    if lang_clean in ("ru", "en"):
        return lang_clean
    d = str(domain or "").lower()
    if d.endswith((".ru", ".by", ".kz", ".su", ".xn--p1ai")):
        return "ru"
    return "en"


def run_outreach_batch(
    memory,
    *,
    csv_path: Path | None = None,
    max_emails: int = 20,
    language: str = "auto",
    allow_live_fetch: bool = False,
    stop_file_path: Path | None = None,
) -> dict[str, Any]:
    """Пакетная рассылка по базе (загруженные лиды или CSV) с ротацией почт, 30-дневной бронью и стоп-листом."""
    import csv as _csv
    from . import partner_bridge

    _ensure_mail_schema(memory)
    rows_iter: list[dict[str, Any]] = []
    source_used = "leads_db"
    if csv_path is not None:
        if not Path(csv_path).is_file():
            return {"ok": False, "error": f"CSV базы не найден: {csv_path}", "sent": 0}
        with Path(csv_path).open("r", encoding="utf-8-sig", errors="replace") as f:
            rows_iter = list(_csv.DictReader(f))
        source_used = "csv_arg"
    else:
        db_leads = list_outreach_leads(memory, limit=1000)
        if db_leads:
            rows_iter = db_leads
            source_used = "leads_db"
        elif _DEFAULT_US_CSV.is_file():
            with _DEFAULT_US_CSV.open("r", encoding="utf-8-sig", errors="replace") as f:
                rows_iter = list(_csv.DictReader(f))
            source_used = "default_us_csv"
        else:
            return {
                "ok": False,
                "error": "Нет базы клиентов: вставьте список email/domain в блоке 10 Студии или передайте csv_path.",
                "sent": 0,
            }

    lim = max(1, min(500, int(max_emails or 20)))
    sent = 0
    skipped = 0
    errors = 0
    results: list[dict[str, Any]] = []

    for row in rows_iter:
        if sent >= lim:
            break
        to_em = _clean_email(row.get("почта") or row.get("email") or "")
        dom = _clean_domain(row.get("домен") or row.get("domain") or to_em)
        if not to_em or not dom:
            skipped += 1
            continue
        blocked, reason = is_blocked_by_stop_or_claim(memory, email=to_em, domain=dom, stop_file_path=stop_file_path)
        if blocked:
            skipped += 1
            continue

        target_lang = _pick_outreach_lang(dom, language)
        pkg = partner_bridge.build_business_outreach(
            memory,
            dom,
            language=target_lang,
            site_record=row,
            allow_live_fetch=allow_live_fetch,
        )
        s_res = send_outreach_email(
            memory,
            to_email=to_em,
            domain=dom,
            subject=pkg["email_subject"],
            body=pkg["email_body"],
            direction="outbound_first",
            stop_file_path=stop_file_path,
        )
        if s_res.get("ok"):
            sent += 1
            results.append({"domain": dom, "to": to_em, "from": s_res["from_email"], "lang": target_lang})
        elif s_res.get("blocked"):
            skipped += 1
        else:
            errors += 1
            results.append({"domain": dom, "error": s_res.get("error")})
            if "Нет активной почты" in str(s_res.get("error") or ""):
                break

    return {"ok": True, "source": source_used, "sent": sent, "skipped": skipped, "errors": errors, "results": results}


def run_follow_up_cycle(
    memory,
    *,
    wait_days: float = 4.0,
    max_emails: int = 10,
    now_ts: float | None = None,
    stop_file_path: Path | None = None,
) -> dict[str, Any]:
    """Отправляет максимум ОДНО вежливое напоминание через wait_days дней, если клиент не ответил и не в стоп-листе."""
    _ensure_mail_schema(memory)
    now = float(now_ts if now_ts is not None else time.time())
    cutoff = now - max(1.0, float(wait_days)) * 86400.0
    lim = max(1, min(100, int(max_emails or 10)))

    with freelance_autonomy._lock_of(memory):
        rows = memory.store.conn.execute(
            """
            SELECT o.domain, o.recipient_email, o.mail_id, o.subject
            FROM ark_outreach_log o
            WHERE o.user_id = ? AND o.direction = 'outbound_first' AND o.created_at <= ?
              AND NOT EXISTS (
                  SELECT 1 FROM ark_outreach_log x
                  WHERE x.user_id = o.user_id AND x.domain = o.domain
                    AND x.direction IN ('outbound_followup', 'outbound_report', 'inbound')
              )
            ORDER BY o.created_at ASC LIMIT ?
            """,
            (memory.user_id, cutoff, lim * 4),
        ).fetchall()

    sent = 0
    skipped = 0
    for r in rows:
        dom = str(r["domain"] or "")
        to_em = str(r["recipient_email"] or "")
        blocked, _ = is_blocked_by_stop_or_claim(memory, email=to_em, domain=dom, stop_file_path=stop_file_path, check_30d_claim=False)
        if blocked:
            skipped += 1
            continue
        subj = f"Re: {str(r['subject'] or dom)[:160]}"
        fu_lang = _pick_outreach_lang(dom, "auto")
        if fu_lang == "ru":
            body = (
                f"Здравствуйте!\n\nКоротко напоминаю о бесплатном техническом списке ошибок доступности для сайта {dom}: "
                f"если актуально, просто ответьте на это письмо, или проверьте сайт самостоятельно за минуту на https://aifa.works/accessibility?url={dom}.\n\n"
                f"Если неактуально — ответьте STOP, и мы больше никогда не напишем.\n\n"
                f"CODE Eternal LLC · 1209 Mountain Road Pl NE, Ste N, Albuquerque, NM 87110, USA"
            )
        else:
            body = (
                f"Hi team,\n\nJust a brief, friendly follow-up on the free WCAG 2.1 AA accessibility breakdown we ran for {dom}. "
                f"If you would like me to email the printable technical finding list for your developer at no charge, simply reply 'send report', "
                f"or verify your score in 60 seconds at https://aifa.works/accessibility?url={dom}.\n\n"
                f"If you would like our team to handle it directly:\n"
                f"• Quick Audit ($149 fixed fee, 24h): https://aifa.works/accessibility?url={dom}&service=quick-audit\n"
                f"• Starter Fix ($375 fixed fee, 3–5 days): https://aifa.works/accessibility?url={dom}&service=starter-fix\n\n"
                f"If this is not relevant, reply STOP and we will never write again.\n\n"
                f"Warm regards,\nAIfa & SolarisAudit · CODE Eternal LLC · 1209 Mountain Road Pl NE, Ste N, Albuquerque, NM 87110, USA"
            )
        if sent >= lim:
            break
        res = send_outreach_email(
            memory,
            to_email=to_em,
            domain=dom,
            subject=subj,
            body=body,
            mail_id=str(r["mail_id"] or ""),
            direction="outbound_followup",
            stop_file_path=stop_file_path,
        )
        if not res.get("ok") and not res.get("blocked"):
            res = send_outreach_email(
                memory,
                to_email=to_em,
                domain=dom,
                subject=subj,
                body=body,
                mail_id="",
                direction="outbound_followup",
                stop_file_path=stop_file_path,
            )
        if res.get("ok"):
            sent += 1
        else:
            skipped += 1
    return {"ok": True, "follow_ups_sent": sent, "skipped": skipped}


def check_mail_dns_health(email_or_domain: str, *, allow_live_dns: bool = False) -> dict[str, Any]:
    """Предполётная проверка DNS-записей (MX, SPF, DMARC) домена почтового ящика."""
    import socket as _sock
    import subprocess as _sp

    dom = _clean_domain(email_or_domain)
    if not dom:
        return {"ok": False, "domain": "", "error": "Некорректный домен."}
    if os.environ.get("PYTEST_CURRENT_TEST") and not allow_live_dns:
        return {
            "ok": True,
            "skipped": True,
            "domain": dom,
            "mx_ok": True,
            "spf_ok": True,
            "dmarc_ok": True,
            "warnings": [],
        }

    mx_ok = False
    spf_ok = False
    dmarc_ok = False
    try:
        if _sock.getaddrinfo(dom, None):
            mx_ok = True
    except Exception:
        pass
    for kind, host, marker in (("spf", dom, "v=spf1"), ("dmarc", f"_dmarc.{dom}", "v=dmarc1")):
        try:
            out = _sp.check_output(["nslookup", "-type=txt", host], stderr=_sp.STDOUT, timeout=5).decode("utf-8", errors="ignore").lower()
            if marker in out:
                if kind == "spf":
                    spf_ok = True
                else:
                    dmarc_ok = True
        except Exception:
            pass
    warnings = []
    if not mx_ok:
        warnings.append("Домен не резолвится / проверьте MX.")
    if not spf_ok:
        warnings.append("Не найдена TXT SPF-запись (v=spf1).")
    if not dmarc_ok:
        warnings.append("Не найдена TXT _dmarc запись (v=DMARC1).")
    return {"ok": mx_ok and spf_ok, "domain": dom, "mx_ok": mx_ok, "spf_ok": spf_ok, "dmarc_ok": dmarc_ok, "warnings": warnings}


def send_test_email_to_self(
    memory,
    *,
    mail_id: str = "",
    target_email: str = "",
    domain: str = "aifa.works",
) -> dict[str, Any]:
    """Отправляет 1 тестовое письмо себе с примером отчёта (обходит 30-дневную бронь)."""
    _ensure_mail_schema(memory)
    accs = [a for a in list_mail_accounts(memory) if a.get("status") == "active"]
    if not accs:
        return {"ok": False, "error": "Нет ни одной активной подключённой почты."}
    chosen = next((a for a in accs if mail_id and a["mail_id"] == mail_id), accs[0])
    to_addr = _clean_email(target_email) or chosen["email"]
    from . import partner_bridge
    pkg = partner_bridge.build_business_outreach(memory, domain or "aifa.works", language="ru", allow_live_fetch=False)
    html_att = (
        "<!doctype html><html lang='ru'><meta charset='utf-8'><body>"
        f"<h2>Тестовый отчёт AIfa для {to_addr}</h2>"
        f"<pre>{_html.escape(pkg.get('site_report') or '')}</pre>"
        "</body></html>"
    )
    return send_outreach_email(
        memory,
        to_email=to_addr,
        domain=domain or "aifa.works",
        subject="[ТЕСТ] Проверка доставляемости AIfa Studio",
        body=pkg["email_body"],
        html_body=html_att,
        html_attachment_name="aifa_test_report.html",
        mail_id=chosen["mail_id"],
        direction="test_self",
    )


def bulk_connect_mail(
    memory,
    raw_text: str,
    *,
    default_provider: str = "gmail",
    default_daily_limit: int = 30,
    verify_connection: bool = True,
    warmup_enabled: bool = False,
) -> dict[str, Any]:
    """Массово подключает до 20 почт из текста: email | app_password [| provider [| limit]]."""
    _ensure_mail_schema(memory)
    lines = [ln.strip() for ln in str(raw_text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return {"ok": False, "error": "Список почт пуст.", "connected": 0, "errors": 0}
    connected = 0
    errors = 0
    details: list[dict[str, Any]] = []
    for ln in lines[:25]:
        parts = [pt.strip() for pt in re.split(r"[|;,\t]+", ln) if pt.strip()]
        if len(parts) < 2 and ":" in ln:
            parts = [pt.strip() for pt in ln.split(":", 1)]
        if len(parts) < 2:
            errors += 1
            details.append({"line": ln[:40], "ok": False, "error": "Нужно: email | app_password"})
            continue
        em = parts[0]
        sec = parts[1]
        prov = parts[2].lower() if len(parts) > 2 and parts[2].lower() in MAIL_PROVIDER_PRESETS else default_provider
        lim = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else default_daily_limit
        try:
            r = connect_mail_account(
                memory,
                email=em,
                provider=prov,
                app_password_or_token=sec,
                daily_limit=lim,
                verify_connection=verify_connection,
                warmup_enabled=warmup_enabled,
            )
            if r.get("ok"):
                connected += 1
                details.append({"email": em, "ok": True})
            else:
                errors += 1
                details.append({"email": em, "ok": False, "error": r.get("error")})
        except Exception as exc:
            errors += 1
            details.append({"email": em, "ok": False, "error": str(exc)})
    return {"ok": connected > 0, "connected": connected, "errors": errors, "details": details}


def verify_all_mail_accounts(memory, *, allow_live_dns: bool = False) -> dict[str, Any]:
    """Проверяет SMTP/IMAP-вход и DNS (MX/SPF/DMARC) по всем подключённым почтам."""
    _ensure_mail_schema(memory)
    with freelance_autonomy._lock_of(memory):
        rows = [dict(r) for r in memory.store.conn.execute("SELECT * FROM ark_mail_account WHERE user_id=?", (memory.user_id,)).fetchall()]
    ok_cnt = 0
    fail_cnt = 0
    results: list[dict[str, Any]] = []
    for r in rows:
        sec = freelance_autonomy._unseal_secret(memory, str(r["secret_enc"]))
        chk = _verify_smtp_imap_live(
            provider=str(r["provider"]),
            email=str(r["email"]),
            secret=sec,
            smtp_host=str(r["smtp_host"]),
            smtp_port=int(r["smtp_port"]),
            imap_host=str(r["imap_host"]),
            imap_port=int(r["imap_port"]),
        )
        dns = check_mail_dns_health(str(r["email"]), allow_live_dns=allow_live_dns)
        if chk.get("ok"):
            ok_cnt += 1
        else:
            fail_cnt += 1
        results.append({
            "mail_id": r["mail_id"],
            "email": r["email"],
            "auth_ok": bool(chk.get("ok")),
            "auth_error": chk.get("error", ""),
            "dns": dns,
        })
    return {"ok": True, "checked": len(results), "auth_ok": ok_cnt, "auth_failed": fail_cnt, "results": results}


def pull_partner_map_leads(
    memory,
    *,
    max_leads: int = 50,
    allow_localhost: bool = False,
    map_url: str = "",
) -> dict[str, Any]:
    """Подтягивает свежие незанятые лиды с карты aifa.works в локальную БД ark_outreach_leads."""
    _ensure_mail_schema(memory)
    if os.environ.get("PYTEST_CURRENT_TEST") and not allow_localhost and not map_url:
        return {"ok": False, "skipped": True, "error": "Внешняя сеть отключена в тестах.", "imported": 0}
    target = str(map_url or os.environ.get("PADAM_AIFA_MAP_INDEX_URL") or "https://aifa.works/map/outreach_us_index.json").strip()
    try:
        clean_u = net_guard.validate_outbound_url(target, allow_localhost=allow_localhost, allow_http_localhost=True, require_https=not allow_localhost)
        req = urllib.request.Request(clean_u, headers={"Accept": "application/json", "User-Agent": "AIfa-Partner-Bridge/1.0"})
        with net_guard.safe_urlopen(req, timeout=15, allow_localhost=allow_localhost, allow_http_localhost=True, require_https=not allow_localhost) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"ok": False, "error": f"Не удалось загрузить карту лидов: {exc}", "imported": 0}

    items: list[dict[str, Any]] = []
    if isinstance(data, dict):
        if isinstance(data.get("items"), list):
            items = data["items"]
        elif isinstance(data.get("domains"), dict):
            items = [{"domain": k, **(v if isinstance(v, dict) else {})} for k, v in data["domains"].items()]
        else:
            items = [{"domain": k, **(v if isinstance(v, dict) else {})} for k, v in data.items() if "." in str(k)]
    elif isinstance(data, list):
        items = [x for x in data if isinstance(x, dict)]

    lim = max(1, min(500, int(max_leads or 50)))
    lines: list[str] = []
    for it in items:
        if len(lines) >= lim:
            break
        dom = _clean_domain(it.get("domain") or it.get("d") or it.get("host") or it.get("h") or "")
        if not dom:
            continue
        em = _clean_email(it.get("email") or it.get("e") or f"info@{dom}")
        blocked, _ = is_blocked_by_stop_or_claim(memory, email=em, domain=dom)
        if blocked:
            continue
        comp = str(it.get("company") or it.get("name") or dom).replace(",", " ")[:100]
        lines.append(f"{em}, {dom}, {comp}")
    if not lines:
        return {"ok": True, "imported": 0, "total_leads": len(list_outreach_leads(memory, limit=1000))}
    imp = import_outreach_leads(memory, "\n".join(lines), source="aifa_works_map")
    imp["source"] = "aifa_works_map"
    return imp
