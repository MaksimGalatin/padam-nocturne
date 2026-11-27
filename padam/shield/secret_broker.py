# -*- coding: utf-8 -*-
"""Zero-Exposure Secret Broker (брокер секретов по псевдонимам без утечки в LLM).

Агент НИКОГДА не видит настоящие API-ключи (`OPENAI_API_KEY`, `STRIPE_SECRET_KEY`,
`GITHUB_TOKEN`): вместо них модель оперирует безопасным дескриптором
`{{PADAM_SECRET:<name>}}`. При исходящем HTTP-запросе брокер:
1. Проверяет URL на Cloud Metadata SSRF (`inspect_url_ssrf`),
2. Проверяет, что целевой хост входит в строго заданный `allowed_hosts` этого секрета
   (если атакующий заставит отправить дескриптор на `evil.com` — жёсткий `BROKER-HOST-MISMATCH`),
3. Расшифровывает секрет локальным ключом владельца (`integrity.owner_key`) только
   на границе отправки, подставляет в заголовок, а при получении ответа вычищает
   любое эхо секрета (`scrub_response_text`).
Все операции потокобезопасны (`store._lock`) и изолированы по `user_id`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from .. import integrity as _integrity
from ..store import add_column_safe
from .ssrf_path_guard import inspect_url_ssrf


_HANDLE_RE = re.compile(r"\{\{PADAM_SECRET:([a-zA-Z0-9_.-]{1,64})\}\}")


def _ensure_tables(memory: Any) -> None:
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_secret_broker (
                name TEXT NOT NULL,
                user_id TEXT NOT NULL DEFAULT '',
                allowed_hosts_json TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                ciphertext_b64 TEXT NOT NULL,
                mac_hex TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (user_id, name)
            )
            """
        )
        add_column_safe(conn, "shield_secret_broker", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.commit()


def _owner_key(memory: Any) -> bytes:
    key, _ = _integrity.owner_key(memory.store)
    return key if isinstance(key, bytes) else str(key).encode("utf-8")


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        blk = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        out.extend(blk)
        counter += 1
    return bytes(out[:length])


def _encrypt_secret(key: bytes, plaintext: str, aad: bytes) -> tuple[str, str, str]:
    nonce = secrets.token_bytes(16)
    pt = plaintext.encode("utf-8")
    ks = _keystream(key, nonce, len(pt))
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    mac = hmac.new(key, aad + nonce + ct, hashlib.sha256).hexdigest()
    return nonce.hex(), base64.b64encode(ct).decode("ascii"), mac


def _decrypt_secret(key: bytes, nonce_hex: str, ct_b64: str, mac_hex: str, aad: bytes) -> Optional[str]:
    nonce = bytes.fromhex(nonce_hex)
    ct = base64.b64decode(ct_b64)
    expected = hmac.new(key, aad + nonce + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac_hex):
        return None
    ks = _keystream(key, nonce, len(ct))
    pt = bytes(a ^ b for a, b in zip(ct, ks))
    return pt.decode("utf-8")


def _host_allowed(host: str, allowed_hosts: Sequence[str]) -> bool:
    h = host.strip().lower().rstrip(".")
    if not h:
        return False
    for pat in allowed_hosts:
        p = pat.strip().lower().rstrip(".")
        if p == h:
            return True
        if p.startswith("*.") and (h == p[2:] or h.endswith("." + p[2:])):
            return True
    return False


def register_broker_secret(
    memory: Any,
    *,
    name: str,
    secret_value: str,
    allowed_hosts: Sequence[str],
) -> Dict[str, Any]:
    """Регистрирует секрет в локальном брокере и возвращает безопасный дескриптор для LLM."""
    _ensure_tables(memory)
    clean_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", str(name or "").strip())[:64]
    if not clean_name:
        return {"ok": False, "error": "Имя секрета не может быть пустым"}
    hosts = sorted({str(h).strip().lower() for h in (allowed_hosts or []) if str(h).strip()})
    if not hosts:
        return {"ok": False, "error": "Необходимо указать хотя бы один разрешённый хост (allowed_hosts)"}
    if not secret_value:
        return {"ok": False, "error": "Значение секрета не может быть пустым"}

    uid = str(getattr(memory, "user_id", "") or "")
    aad = f"padam-broker-v1|{uid}|{clean_name}".encode("utf-8")
    nonce_hex, ct_b64, mac_hex = _encrypt_secret(_owner_key(memory), str(secret_value), aad)

    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            INSERT OR REPLACE INTO shield_secret_broker
                (name, user_id, allowed_hosts_json, nonce_hex, ciphertext_b64, mac_hex, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (clean_name, uid, json.dumps(hosts, ensure_ascii=False), nonce_hex, ct_b64, mac_hex, time.time()),
        )
        conn.commit()

    return {
        "ok": True,
        "name": clean_name,
        "handle": f"{{{{PADAM_SECRET:{clean_name}}}}}",
        "allowed_hosts": hosts,
    }


def resolve_outbound_headers(
    memory: Any,
    *,
    target_url: str,
    headers: Dict[str, str],
    allow_private_url: bool = False,
) -> Dict[str, Any]:
    """Подставляет реальные секреты вместо дескрипторов строго для разрешённого хоста."""
    _ensure_tables(memory)
    sr = inspect_url_ssrf(target_url, allow_private=allow_private_url)
    if sr["blocked"]:
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": sr["findings"][0]["rule_id"],
            "reason": sr["findings"][0]["detail"],
        }

    host = (urlparse(target_url).hostname or "").strip().lower()
    uid = str(getattr(memory, "user_id", "") or "")
    key = _owner_key(memory)
    resolved_headers: Dict[str, str] = {}
    injected_names: List[str] = []

    for hk, hv in (headers or {}).items():
        val = str(hv)
        matches = list(_HANDLE_RE.finditer(val))
        if not matches:
            resolved_headers[str(hk)] = val
            continue
        new_val = val
        for m in matches:
            sname = m.group(1)
            with memory.store._lock:
                row = memory.store.conn.execute(
                    "SELECT allowed_hosts_json, nonce_hex, ciphertext_b64, mac_hex "
                    "FROM shield_secret_broker WHERE user_id = ? AND name = ?",
                    (uid, sname),
                ).fetchone()
            if not row:
                return {
                    "ok": False,
                    "allowed": False,
                    "blocked": True,
                    "rule_id": "BROKER-SECRET-NOT-FOUND",
                    "reason": f"Секрет '{sname}' не зарегистрирован у текущего владельца",
                }
            allowed_hosts = json.loads(row[0])
            if not _host_allowed(host, allowed_hosts):
                return {
                    "ok": False,
                    "allowed": False,
                    "blocked": True,
                    "rule_id": "BROKER-HOST-MISMATCH",
                    "reason": f"Запрещена передача секрета '{sname}' на неразрешённый хост '{host}' (разрешены: {allowed_hosts})",
                }
            aad = f"padam-broker-v1|{uid}|{sname}".encode("utf-8")
            plain = _decrypt_secret(key, str(row[1]), str(row[2]), str(row[3]), aad)
            if plain is None:
                return {
                    "ok": False,
                    "allowed": False,
                    "blocked": True,
                    "rule_id": "BROKER-INTEGRITY-ERROR",
                    "reason": f"Нарушена целостность хранилища секрета '{sname}'",
                }
            new_val = new_val.replace(m.group(0), plain)
            injected_names.append(sname)
        resolved_headers[str(hk)] = new_val

    return {
        "ok": True,
        "allowed": True,
        "blocked": False,
        "host": host,
        "injected_secrets": sorted(set(injected_names)),
        "headers": resolved_headers,
    }


def scrub_response_secrets(memory: Any, text: str) -> Dict[str, Any]:
    """Удаляет любые случайно отражённые в ответе сервера значения зарегистрированных секретов."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    key = _owner_key(memory)
    raw = str(text or "")
    scrubbed = raw
    redacted_names: List[str] = []

    with memory.store._lock:
        rows = memory.store.conn.execute(
            "SELECT name, nonce_hex, ciphertext_b64, mac_hex FROM shield_secret_broker WHERE user_id = ?",
            (uid,),
        ).fetchall()

    for name, nonce_hex, ct_b64, mac_hex in rows:
        aad = f"padam-broker-v1|{uid}|{name}".encode("utf-8")
        plain = _decrypt_secret(key, str(nonce_hex), str(ct_b64), str(mac_hex), aad)
        if plain and len(plain) >= 6 and plain in scrubbed:
            scrubbed = scrubbed.replace(plain, f"[SCRUBBED_SECRET:{name}]")
            redacted_names.append(str(name))

    return {
        "ok": True,
        "redacted_count": len(redacted_names),
        "redacted_names": redacted_names,
        "clean_text": scrubbed,
    }


def list_broker_secrets(memory: Any) -> Dict[str, Any]:
    """Возвращает список псевдонимов и разрешённых хостов (без раскрытия самих секретов!)."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    with memory.store._lock:
        rows = memory.store.conn.execute(
            "SELECT name, allowed_hosts_json, created_at FROM shield_secret_broker WHERE user_id = ? ORDER BY name ASC",
            (uid,),
        ).fetchall()
    return {
        "ok": True,
        "count": len(rows),
        "items": [
            {
                "name": str(r[0]),
                "handle": f"{{{{PADAM_SECRET:{r[0]}}}}}",
                "allowed_hosts": json.loads(r[1]),
                "created_at": r[2],
            }
            for r in rows
        ],
    }
