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


def sign(key: bytes, memory_id: str, kind: str, content: str) -> str:
    сообщение = "\x1f".join((memory_id, kind, content or "")).encode("utf-8")
    return hmac.new(key, сообщение, hashlib.sha256).hexdigest()


def valid(key: bytes, row) -> bool:
    подпись = row["owner_sig"]
    return bool(подпись) and hmac.compare_digest(подпись, sign(key, row["id"], row["kind"], row["content"]))


def protected(kind: str) -> bool:
    return kind in config.PROTECTED_KINDS
