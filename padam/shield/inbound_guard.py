# -*- coding: utf-8 -*-
"""Защита входящих триггеров: Webhook, Email и Calendar Invite Injection Guard.

Защищает автономных агентов, запускаемых внешними событиями:
1. Входящие вебхуки: проверка HMAC-SHA256 подписи, окна свежести timestamp
   (защита от устаревших пакетов) и одноразовости nonce в SQLite под `store._lock`
   с изоляцией `user_id` (защита от Replay-атак).
2. Email / Calendar / Issue триггеры:
   - проверка доменного спуфинга `Reply-To` против `From`,
   - блокировка опасных и двойных расширений вложений (`.pdf.exe`, `.docm`, `.ps1`, `.lnk`),
   - инспекция HTML-тела и описаний календарных событий через `browser_guard` +
     `adversarial_norm` + `exfil_guard` + `prompt_hierarchy`,
   - автоматическая маркировка события как `UNTRUSTED_TRIGGER` с 128-битной рамкой.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time
from typing import Any, Dict, List, Sequence

from ..store import add_column_safe
from .adversarial_norm import canonicalize_adversarial_text
from .browser_guard import inspect_dom_html
from .exfil_guard import inspect_exfil_channels
from .prompt_hierarchy import fence_untrusted_content, inspect_role_delimiters


_DANGEROUS_EXT_RE = re.compile(
    r"(?i)(?:\.(?:exe|scr|bat|cmd|ps1|vbs|vbe|js|jse|hta|lnk|msi|dll|pif|docm|xlsm|pptm|iso|img)$|"
    r"\.(?:pdf|docx?|xlsx?|jpg|png)\.(?:exe|scr|bat|cmd|ps1|js|vbs|hta|lnk)$)"
)

_TRIGGER_INJECTION_RE = re.compile(
    r"(?is)\b(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?"
    r"|when\s+(?:the\s+)?(?:assistant|agent|ai)\s+(?:reads?|processes?|summarizes?)"
    r"|forward\s+(?:all\s+)?(?:recent\s+)?(?:emails?|messages?|secrets?|keys?|invoices?)\s+to"
    r"|send\s+(?:a\s+)?(?:payment|transfer|wire|usdt|eth|sol)\s+to"
    r"|override\s+(?:policy|rules?|safety)|disable\s+kill\s*switch"
    r"|игнорируй\s+предыдущие\s+инструкции|перешли\s+все\s+письма"
    r")"
)


def _ensure_tables(memory: Any) -> None:
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_webhook_nonces (
                user_id TEXT NOT NULL DEFAULT '',
                nonce_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (user_id, nonce_hash)
            )
            """
        )
        add_column_safe(conn, "shield_webhook_nonces", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.commit()


def _extract_email_domain(addr: str) -> str:
    m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", str(addr or ""))
    return m.group(1).lower() if m else ""


def verify_inbound_webhook(
    memory: Any,
    *,
    raw_body: bytes | str,
    signature_header: str,
    secret: str,
    timestamp_header: str = "",
    tolerance_sec: int = 300,
    nonce: str = "",
) -> Dict[str, Any]:
    """Проверяет HMAC-SHA256 подпись, свежесть timestamp и одноразовость входящего вебхука."""
    _ensure_tables(memory)
    body_b = raw_body.encode("utf-8") if isinstance(raw_body, str) else bytes(raw_body or b"")
    sec_b = str(secret or "").encode("utf-8")
    sig_raw = str(signature_header or "").strip()
    if sig_raw.lower().startswith("sha256="):
        sig_hex = sig_raw[7:].strip().lower()
    else:
        sig_hex = sig_raw.lower()

    if not sig_hex or not sec_b:
        return {"ok": False, "allowed": False, "blocked": True, "rule_id": "INBOUND-MISSING-SIGNATURE", "reason": "Отсутствует HMAC-подпись или секрет вебхука"}

    now = time.time()
    ts_str = str(timestamp_header or "").strip()
    if ts_str:
        try:
            ts_val = float(ts_str)
        except ValueError:
            return {"ok": False, "allowed": False, "blocked": True, "rule_id": "INBOUND-INVALID-TIMESTAMP", "reason": "Некорректный заголовок времени вебхука"}
        if abs(now - ts_val) > max(10, int(tolerance_sec)):
            return {"ok": False, "allowed": False, "blocked": True, "rule_id": "INBOUND-STALE-TIMESTAMP", "reason": "Метка времени вебхука вышла за допустимое окно свежести"}
        signed_payload = f"{ts_str}.".encode("utf-8") + body_b
    else:
        signed_payload = body_b

    expected_a = hmac.new(sec_b, signed_payload, hashlib.sha256).hexdigest()
    expected_b = hmac.new(sec_b, body_b, hashlib.sha256).hexdigest()
    if not (hmac.compare_digest(expected_a, sig_hex) or hmac.compare_digest(expected_b, sig_hex)):
        return {"ok": False, "allowed": False, "blocked": True, "rule_id": "INBOUND-SIGNATURE-INVALID", "reason": "HMAC-SHA256 подпись вебхука недействительна"}

    # Проверка анти-Replay по nonce (или по хешу (timestamp + signature))
    replay_key = nonce or f"{ts_str}:{sig_hex}"
    nonce_hash = hashlib.sha256(replay_key.encode("utf-8")).hexdigest()
    uid = str(getattr(memory, "user_id", "") or "")
    with memory.store._lock:
        conn = memory.store.conn
        # Подчищаем старые записи (> 24 ч)
        conn.execute("DELETE FROM shield_webhook_nonces WHERE created_at < ?", (now - 86400,))
        exists = conn.execute(
            "SELECT 1 FROM shield_webhook_nonces WHERE user_id = ? AND nonce_hash = ?",
            (uid, nonce_hash),
        ).fetchone()
        if exists:
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "INBOUND-WEBHOOK-REPLAY",
                "reason": "Обнаружен повтор уже обработанного вебхука (Replay Attack)",
            }
        conn.execute(
            "INSERT INTO shield_webhook_nonces (user_id, nonce_hash, created_at) VALUES (?, ?, ?)",
            (uid, nonce_hash, now),
        )
        conn.commit()

    return {"ok": True, "allowed": True, "blocked": False, "verified": True}


def inspect_inbound_event(
    *,
    channel: str = "email",
    subject: str = "",
    body: str = "",
    sender: str = "",
    reply_to: str = "",
    attachment_names: Sequence[str] = (),
) -> Dict[str, Any]:
    """Проверяет входящее письмо, приглашение календаря или тикет до передачи агенту."""
    findings: List[Dict[str, Any]] = []
    ch = str(channel or "email").strip().lower()

    # 1. Спуфинг Reply-To относительно From
    from_dom = _extract_email_domain(sender)
    reply_dom = _extract_email_domain(reply_to)
    if from_dom and reply_dom and from_dom != reply_dom:
        findings.append(
            {
                "rule_id": "INBOUND-REPLY-TO-SPOOF",
                "severity": "HIGH",
                "detail": f"Несовпадение доменов From ({from_dom}) и Reply-To ({reply_dom}) — возможный фишинг",
            }
        )

    # 2. Опасные вложения / двойные расширения
    for att in (attachment_names or ()):
        a = str(att or "").strip()
        if a and _DANGEROUS_EXT_RE.search(a):
            findings.append(
                {
                    "rule_id": "INBOUND-DANGEROUS-ATTACHMENT",
                    "severity": "CRITICAL",
                    "detail": f"Заблокировано опасное вложение: {a[:80]}",
                }
            )

    full_text = f"{subject}\n{body}"

    # 3. HTML / DOM скрытые инъекции в письме или описании события календаря
    if "<" in body and ">" in body:
        dom_res = inspect_dom_html(body)
        for df in dom_res.get("findings") or []:
            findings.append(
                {
                    "rule_id": f"INBOUND-{df['rule_id']}",
                    "severity": df.get("severity", "HIGH"),
                    "detail": df.get("detail", ""),
                }
            )

    # 4. Прямые и адверсариальные инъекции триггера (включая Calendar Invite Injection)
    norm = canonicalize_adversarial_text(full_text)["canonical"]
    if _TRIGGER_INJECTION_RE.search(full_text) or _TRIGGER_INJECTION_RE.search(norm):
        findings.append(
            {
                "rule_id": "INBOUND-TRIGGER-INJECTION",
                "severity": "CRITICAL",
                "detail": f"Обнаружена непрямая промпт-инъекция во входящем событии ({ch})",
            }
        )

    # 5. Подмена ролей LLM и скрытая эксфильтрация
    hr = inspect_role_delimiters(full_text)
    for hf in hr.get("findings") or []:
        findings.append(hf)
    exf = inspect_exfil_channels(full_text)
    for ef in exf.get("findings") or []:
        findings.append(
            {
                "rule_id": f"INBOUND-{str(ef.get('rule_id') or ef.get('code') or 'EXFIL').upper()}",
                "severity": str(ef.get("severity", "HIGH")).upper(),
                "detail": ef.get("detail", ""),
            }
        )

    fenced = fence_untrusted_content(full_text, source=f"inbound:{ch}")
    blocked = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "channel": ch,
        "privilege_level": "UNTRUSTED_TRIGGER",
        "findings": findings,
        "fenced_payload": fenced["fenced_text"],
    }
