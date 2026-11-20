# -*- coding: utf-8 -*-
"""Корпоративный коннектор вебхуков PADAM Agentic Shield (Slack, MS Teams, SIEM CEF/Splunk/ECS)."""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from . import __version__, safety
from .store import new_id

WEBHOOK_FORMATS = ("json", "slack", "microsoft_teams", "cef", "splunk_hec", "elastic_ecs")
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_CEF = {"low": 3, "medium": 5, "high": 8, "critical": 10}
_SEV_COLOR = {"low": "#38bdf8", "medium": "#f59e0b", "high": "#f97316", "critical": "#ef4444"}

_DDL_STMTS = (
    """CREATE TABLE IF NOT EXISTS shield_webhook_config (
        user_id      TEXT PRIMARY KEY,
        enabled      INTEGER NOT NULL DEFAULT 0,
        format       TEXT NOT NULL DEFAULT 'json',
        url          TEXT NOT NULL DEFAULT '',
        min_severity TEXT NOT NULL DEFAULT 'high',
        secret_hmac  TEXT NOT NULL DEFAULT '',
        updated_at   TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS shield_webhook_outbox (
        id          TEXT PRIMARY KEY,
        user_id     TEXT NOT NULL,
        format      TEXT NOT NULL,
        event_type  TEXT NOT NULL,
        severity    TEXT NOT NULL,
        target_url  TEXT NOT NULL DEFAULT '',
        payload_json TEXT NOT NULL,
        delivered   INTEGER NOT NULL DEFAULT 0,
        http_status INTEGER NOT NULL DEFAULT 0,
        error_text  TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL
    )""",
    """CREATE INDEX IF NOT EXISTS shield_webhook_outbox_idx
        ON shield_webhook_outbox (user_id, created_at DESC)""",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_tables(memory: Any) -> None:
    if memory is None:
        return
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_webhook_ready", False):
        return
    with store._lock:
        was_in_tx = bool(getattr(store.conn, "in_transaction", False))
        for stmt in _DDL_STMTS:
            store.conn.execute(stmt)
        if not was_in_tx:
            store.conn.commit()
        store._shield_webhook_ready = True


def _is_forbidden_ip(ip_obj: ipaddress._BaseAddress) -> bool:
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


def _resolve_pinned_ips(url: str, *, allow_localhost: bool = False) -> tuple[str, list[str]]:
    """Валидирует URL вебхука и возвращает (clean_url, pinned_public_ips) против SSRF и DNS-rebinding."""
    u = str(url or "").strip()
    if not u:
        return "", []
    parsed = urllib.parse.urlsplit(u)
    if parsed.scheme not in ("https", "http"):
        raise ValueError("webhook URL must start with https:// or http://")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("webhook URL has empty host")
    if parsed.scheme == "http" and host not in ("127.0.0.1", "localhost", "::1") and not allow_localhost:
        raise ValueError("external webhook URL must use https://")

    pinned: list[str] = []
    if allow_localhost and host in ("localhost", "127.0.0.1", "::1"):
        return u, ["127.0.0.1" if host in ("localhost", "127.0.0.1") else "::1"]

    # Сначала проверяем литеральный IP без DNS (защита от 0.0.0.0, 169.254.169.254 и в оффлайне)
    try:
        lit_ip = ipaddress.ip_address(host.strip("[]"))
        if not allow_localhost and _is_forbidden_ip(lit_ip):
            raise ValueError(f"SSRF blocked: private/loopback target {lit_ip}")
        return u, [str(lit_ip)]
    except ValueError as ve:
        if "SSRF blocked" in str(ve):
            raise

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        for info in infos:
            raw_ip = str(info[4][0]).split("%")[0]
            ip_obj = ipaddress.ip_address(raw_ip)
            if not allow_localhost and _is_forbidden_ip(ip_obj):
                raise ValueError(f"SSRF blocked: private/loopback target {ip_obj}")
            if raw_ip not in pinned:
                pinned.append(raw_ip)
    except socket.gaierror:
        # Оффлайн-конфигурация (dry-run / CI): доменные имена без DNS допустимы на этапе configure,
        # но явные локальные адреса блокируются всегда; при реальной отправке DNS обязателен.
        if host.lower() in ("localhost", "localhost.localdomain") or host.lower().endswith(".local"):
            raise ValueError("SSRF blocked: localhost target")
    return u, pinned


def _validate_webhook_url(url: str, *, allow_localhost: bool = False) -> str:
    clean_url, _ = _resolve_pinned_ips(url, allow_localhost=allow_localhost)
    return clean_url


def _post_pinned_webhook(
    target_url: str,
    body_bytes: bytes,
    headers: dict[str, str],
    *,
    allow_localhost: bool = False,
    timeout: float = 5.0,
) -> int:
    """Отправляет POST на заранее проверенный и запиненный IP (без DNS-rebinding и без авто-редиректов)."""
    clean_url, pinned_ips = _resolve_pinned_ips(target_url, allow_localhost=allow_localhost)
    if not pinned_ips:
        raise ValueError("DNS resolution returned no valid external IP for webhook")
    parsed = urllib.parse.urlsplit(clean_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    pinned_ip = pinned_ips[0]

    req_headers = dict(headers)
    req_headers["Host"] = parsed.netloc

    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
            pinned_ip, port=port, sni_host=host, timeout=timeout, context=ctx
        )
    else:
        conn = http.client.HTTPConnection(pinned_ip, port=port, timeout=timeout)
    try:
        conn.request("POST", path, body=body_bytes, headers=req_headers)
        resp = conn.getresponse()
        resp.read()
        return int(resp.status)
    finally:
        conn.close()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS-соединение с пиннингом IP на уровне сокета и корректным TLS SNI исходного хоста."""

    def __init__(self, pinned_ip: str, *, port: int, sni_host: str, timeout: float, context: ssl.SSLContext):
        super().__init__(pinned_ip, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._sni_host = sni_host

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni_host)


def get_webhook_config(memory: Any) -> dict[str, Any]:
    ensure_tables(memory)
    row = memory.store.one(
        "SELECT enabled, format, url, min_severity, secret_hmac, updated_at FROM shield_webhook_config WHERE user_id = ?",
        (memory.user_id,),
    )
    if not row:
        return {
            "enabled": False,
            "format": "slack",
            "url": "",
            "min_severity": "high",
            "has_hmac_secret": False,
            "updated_at": "",
            "supported_formats": list(WEBHOOK_FORMATS),
        }
    return {
        "enabled": bool(row["enabled"]),
        "format": str(row["format"] or "json"),
        "url": str(row["url"] or ""),
        "min_severity": str(row["min_severity"] or "high"),
        "has_hmac_secret": bool(row["secret_hmac"]),
        "updated_at": str(row["updated_at"] or ""),
        "supported_formats": list(WEBHOOK_FORMATS),
    }


def configure_webhook(
    memory: Any,
    *,
    enabled: bool = True,
    format: str = "slack",
    url: str = "",
    min_severity: str = "high",
    secret_hmac: str | None = None,
    allow_localhost: bool = False,
) -> dict[str, Any]:
    ensure_tables(memory)
    fmt = str(format or "json").strip().lower()
    if fmt not in WEBHOOK_FORMATS:
        raise ValueError(f"unsupported webhook format: {fmt}")
    sev = str(min_severity or "high").strip().lower()
    if sev not in _SEV_RANK:
        sev = "high"
    clean_url = _validate_webhook_url(url, allow_localhost=allow_localhost) if str(url or "").strip() else ""
    if enabled and not clean_url:
        raise ValueError("webhook url is required when enabled=True")

    prev = memory.store.one("SELECT secret_hmac FROM shield_webhook_config WHERE user_id = ?", (memory.user_id,))
    sec = str(secret_hmac) if secret_hmac is not None else (str(prev["secret_hmac"]) if prev else "")
    now = _utc_now()
    memory.store.execute(
        """INSERT INTO shield_webhook_config (user_id, enabled, format, url, min_severity, secret_hmac, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(user_id) DO UPDATE SET
           enabled=excluded.enabled, format=excluded.format, url=excluded.url,
           min_severity=excluded.min_severity, secret_hmac=excluded.secret_hmac, updated_at=excluded.updated_at""",
        (memory.user_id, 1 if enabled else 0, fmt, clean_url, sev, sec, now),
    )
    return get_webhook_config(memory)


def build_webhook_payload(
    *,
    fmt: str,
    event_type: str,
    severity: str,
    title: str,
    detail: str,
    agent_id: str = "agent",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Формирует payload под Slack / MS Teams / CEF / Splunk HEC / Elastic ECS / JSON без секретов."""
    f = str(fmt or "json").strip().lower()
    sev = str(severity or "high").strip().lower()
    if sev not in _SEV_RANK:
        sev = "high"
    safe_title, _ = safety.redact(safety.strip_invisible(str(title or event_type))[:160])
    safe_detail, _ = safety.redact(safety.strip_invisible(str(detail or ""))[:600])
    safe_agent = str(agent_id or "agent")[:64]
    ts = _utc_now()
    meta = dict(extra or {})

    if f == "slack":
        color = _SEV_COLOR.get(sev, "#f97316")
        return {
            "text": f"[PADAM Agentic Shield · {sev.upper()}] {safe_title}",
            "attachments": [{
                "color": color,
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": f"PADAM Shield: {safe_title}"[:150]}},
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*Event:*\n`{event_type}`"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n`{sev.upper()}`"},
                        {"type": "mrkdwn", "text": f"*Agent:*\n`{safe_agent}`"},
                        {"type": "mrkdwn", "text": f"*Time (UTC):*\n`{ts}`"},
                    ]},
                    {"type": "section", "text": {"type": "mrkdwn", "text": safe_detail or "—"}},
                ],
            }],
        }

    if f == "microsoft_teams":
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": _SEV_COLOR.get(sev, "#f97316").lstrip("#"),
            "summary": f"PADAM Agentic Shield: {safe_title}",
            "sections": [{
                "activityTitle": f"PADAM Agentic Shield [{sev.upper()}] — {safe_title}",
                "activitySubtitle": f"Agent: {safe_agent} · UTC: {ts}",
                "facts": [
                    {"name": "Event", "value": str(event_type)},
                    {"name": "Severity", "value": sev.upper()},
                    {"name": "Agent", "value": safe_agent},
                ],
                "text": safe_detail or "—",
                "markdown": True,
            }],
        }

    if f == "cef":
        cef_sev = _SEV_CEF.get(sev, 8)
        esc = lambda s: str(s).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")  # noqa: E731
        cef_line = (
            f"CEF:0|CODE Eternal|PADAM Agentic Shield|{__version__}|{esc(event_type)}|{esc(safe_title)}|{cef_sev}|"
            f"rt={esc(ts)} suser={esc(safe_agent)} msg={esc(safe_detail)}"
        )
        return {"cef": cef_line, "severity": sev, "event_type": event_type, "timestamp": ts}

    if f == "splunk_hec":
        return {
            "time": int(datetime.now(timezone.utc).timestamp()),
            "source": "padam-agentic-shield",
            "sourcetype": "padam:agentic_shield",
            "event": {
                "version": __version__,
                "timestamp": ts,
                "event_type": event_type,
                "severity": sev,
                "title": safe_title,
                "agent_id": safe_agent,
                "detail": safe_detail,
                "meta": meta,
            },
        }

    if f == "elastic_ecs":
        return {
            "@timestamp": ts,
            "ecs": {"version": "8.11.0"},
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection", "malware"],
                "action": event_type,
                "severity": _SEV_RANK.get(sev, 3) * 25,
            },
            "service": {"name": "padam-agentic-shield", "version": __version__},
            "agent": {"id": safe_agent},
            "message": f"{safe_title}: {safe_detail}",
            "labels": meta,
        }

    return {
        "schema": "padam.agentic_shield.alert.v1",
        "version": __version__,
        "timestamp": ts,
        "event_type": event_type,
        "severity": sev,
        "title": safe_title,
        "agent_id": safe_agent,
        "detail": safe_detail,
        "meta": meta,
    }


def dispatch_webhook_event(
    memory: Any,
    *,
    event_type: str,
    severity: str = "high",
    title: str = "",
    detail: str = "",
    agent_id: str = "agent",
    extra: dict[str, Any] | None = None,
    dry_run: bool = False,
    allow_localhost: bool = False,
    fmt_override: str | None = None,
) -> dict[str, Any]:
    """Формирует и при включённой настройке отправляет уведомление в Slack/Teams/SIEM + пишет в outbox."""
    ensure_tables(memory)
    cfg = get_webhook_config(memory)
    fmt = (fmt_override or cfg.get("format") or "json").lower()
    if fmt not in WEBHOOK_FORMATS:
        fmt = "json"
    min_rank = _SEV_RANK.get(str(cfg.get("min_severity") or "high").lower(), 3)
    cur_rank = _SEV_RANK.get(str(severity or "high").lower(), 3)

    payload = build_webhook_payload(
        fmt=fmt, event_type=event_type, severity=severity, title=title or event_type,
        detail=detail, agent_id=agent_id, extra=extra,
    )
    body_str = json.dumps(payload, ensure_ascii=False)
    body_bytes = body_str.encode("utf-8")

    headers = {"Content-Type": "application/json; charset=utf-8", "User-Agent": f"PADAM-Shield/{__version__}"}
    row_sec = memory.store.one("SELECT secret_hmac FROM shield_webhook_config WHERE user_id = ?", (memory.user_id,))
    sec_val = str(row_sec["secret_hmac"] or "") if row_sec else ""
    if sec_val:
        sig = hmac.new(sec_val.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        headers["X-PADAM-Signature-256"] = f"sha256={sig}"

    delivered = False
    http_status = 0
    err_txt = ""
    target_url = str(cfg.get("url") or "")

    should_send = (not dry_run) and bool(cfg.get("enabled")) and bool(target_url) and (cur_rank >= min_rank)
    if should_send:
        try:
            http_status = _post_pinned_webhook(
                target_url, body_bytes, headers, allow_localhost=allow_localhost, timeout=5.0
            )
            delivered = 200 <= http_status < 300
        except Exception as exc:
            err_txt = str(exc)[:240]

    oid = new_id()
    memory.store.execute(
        """INSERT INTO shield_webhook_outbox
           (id, user_id, format, event_type, severity, target_url, payload_json, delivered, http_status, error_text, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (oid, memory.user_id, fmt, str(event_type)[:80], str(severity)[:20], target_url[:240],
         body_str, 1 if delivered else 0, http_status, err_txt, _utc_now()),
    )
    return {
        "ok": True,
        "outbox_id": oid,
        "format": fmt,
        "dry_run": dry_run,
        "sent": should_send,
        "delivered": delivered,
        "http_status": http_status,
        "error": err_txt,
        "payload": payload,
        "signature_header": headers.get("X-PADAM-Signature-256", ""),
    }


def list_webhook_outbox(memory: Any, *, limit: int = 30) -> list[dict[str, Any]]:
    ensure_tables(memory)
    rows = memory.store.query(
        """SELECT id, format, event_type, severity, target_url, delivered, http_status, error_text, created_at, payload_json
           FROM shield_webhook_outbox WHERE user_id = ? ORDER BY created_at DESC LIMIT ?""",
        (memory.user_id, max(1, min(int(limit), 100))),
    )
    out = []
    for r in rows:
        item = dict(r)
        item["delivered"] = bool(item.get("delivered"))
        out.append(item)
    return out
