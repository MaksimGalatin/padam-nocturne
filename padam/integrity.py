"""Подпись владельца на записях о личности и предпочтениях.

Зачем: identity и preference не затухают, поэтому подменённая запись живёт вечно. PADAM уже
не даёт агенту менять их через MCP, но запись в файл базы можно сделать и в обход PADAM —
другим процессом, другим MCP-сервером с доступом к SQLite, вручную. Подпись отличает то,
что внёс владелец через PADAM, от вставленного мимо него: в выдаче такая запись помечается.

Ключ — 32 случайных байта в файле рядом с базой (права 0600 на POSIX). Это защита от записи
в обход PADAM, а не от того, кто уже читает ваши файлы: у него будет и ключ. При первом
создании ключа подписываются все действующие записи этих видов: они были внесены до подписи,
и PADAM считает их своими (доверие при первом использовании).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from . import config

_ключи_в_памяти: dict[int, bytes] = {}


def key_path(store) -> Path | None:
    if str(store.path) == ":memory:":
        return None
    return store.path.with_name(store.path.name + ".owner.key")


def owner_key(store) -> tuple[bytes, bool]:
    """(ключ, создан_сейчас)."""
    путь = key_path(store)
    if путь is None:
        if id(store) not in _ключи_в_памяти:
            _ключи_в_памяти[id(store)] = secrets.token_bytes(32)
            return _ключи_в_памяти[id(store)], True
        return _ключи_в_памяти[id(store)], False
    if путь.exists():
        return bytes.fromhex(путь.read_text(encoding="ascii").strip()), False
    ключ = secrets.token_bytes(32)
    путь.write_text(ключ.hex(), encoding="ascii")
    if os.name == "posix":
        try:
            os.chmod(путь, 0o600)
        except OSError:
            pass
    return ключ, True


def _core_hmac(key: bytes, memory_id: str, kind: str, content: str) -> str:
    msg = "\x1f".join((str(memory_id), str(kind), str(content or ""))).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _full_hmac(
    key: bytes,
    memory_id: str,
    kind: str,
    content: str,
    scope: str,
    user_id: str,
    created_at: str,
    status: str,
) -> str:
    msg = "\x1f".join(
        ("v2", str(memory_id), str(kind), str(content or ""), str(scope or "global"), str(user_id or ""), str(created_at or ""), str(status or "active"))
    ).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def sign(
    key: bytes,
    memory_id: str,
    kind: str,
    content: str,
    *,
    scope: str | None = None,
    user_id: str | None = None,
    created_at: str | None = None,
    status: str | None = None,
) -> str:
    core = _core_hmac(key, memory_id, kind, content)
    if scope is None and user_id is None and created_at is None and status is None:
        return core
    full = _full_hmac(
        key,
        memory_id,
        kind,
        content,
        scope if scope is not None else "global",
        user_id if user_id is not None else "",
        created_at if created_at is not None else "",
        status if status is not None else "active",
    )
    return f"v2:{core}:{full}"


def _row_keys(row) -> set[str]:
    if isinstance(row, dict):
        return set(row.keys())
    if hasattr(row, "keys"):
        return set(row.keys())
    return set()


def valid(key: bytes, row, *, require_context: bool = False) -> bool:
    keys = _row_keys(row)
    подпись = str(row["owner_sig"] or "") if "owner_sig" in keys else ""
    if not подпись:
        return False
    rid = row["id"]
    rkind = row["kind"]
    rcontent = row["content"]
    if подпись.startswith("v2:"):
        parts = подпись.split(":", 2)
        if len(parts) != 3:
            return False
        _, core_sig, full_sig = parts
        if not hmac.compare_digest(core_sig, _core_hmac(key, rid, rkind, rcontent)):
            return False
        has_all_ctx = {"scope", "user_id", "created_at", "status"} <= keys
        if not has_all_ctx:
            if require_context:
                return False
            # Для старых SELECT-запросов (4 колонки) при require_context=False проверяем базовый core HMAC,
            # а если хоть часть контекста есть (напр. scope), требуем совпадения хотя бы доступного — нет, полная проверка требует всех 4.
            return True
        expected_full = _full_hmac(
            key,
            rid,
            rkind,
            rcontent,
            row["scope"],
            row["user_id"],
            row["created_at"],
            row["status"],
        )
        return hmac.compare_digest(full_sig, expected_full)

    if require_context:
        # Запись со старой v1-подписью без привязки к scope/user_id/created_at/status
        return hmac.compare_digest(подпись, _core_hmac(key, rid, rkind, rcontent))
    return hmac.compare_digest(подпись, _core_hmac(key, rid, rkind, rcontent))


def protected(kind: str) -> bool:
    return kind in config.PROTECTED_KINDS
