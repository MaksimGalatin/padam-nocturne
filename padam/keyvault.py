"""Защита ключей записей паролем.

Ключ каждой записи (anchor_key.key_ref) раньше лежал в базе открытым hex: кто
получил файл базы, тот читал и шифротексты в Arweave. Теперь ключ хранится
завёрнутым:

    key_ref = "w1:" + hex( nonce(12) ‖ AES-256-GCM(KEK, key, aad) )
    KEK     = scrypt(пароль, соль из key_vault, n=2**15, r=8, p=1) → 32 байта
    aad     = b"padam-key|" + memory_id

* Пароль в базу не пишется. Источник — аргумент, переменная окружения
  PADAM_KEY_PASSPHRASE или ввод в консоли.
* aad привязывает обёртку к id записи: ключ одной записи нельзя подложить
  другой — расшифровка упадёт.
* Проверочная запись в key_vault ловит неверный пароль сразу, до того как
  что-либо будет завёрнуто им.
* Уничтожение ключа (право на забвение) не меняется: key_ref = 'destroyed'.
* Старая база (ключи открытым hex) читается как прежде, пока не выполнена
  protect_existing(); после неё открытых ключей не остаётся, а VACUUM и
  сброс WAL убирают их старые копии из файла.
"""

from __future__ import annotations

import os
import secrets
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .store import now_iso

PREFIX = "w1:"
ENV = "PADAM_KEY_PASSPHRASE"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
_CHECK_AAD = b"padam-keyvault-check"
_CHECK_PLAIN = b"padam-nocturne key vault v1"

VAULT_SCHEMA = """
CREATE TABLE IF NOT EXISTS key_vault (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    salt_hex    TEXT NOT NULL,
    kdf         TEXT NOT NULL,
    check_hex   TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
"""


class KeyVaultError(Exception):
    """Общая ошибка хранилища ключей."""


class Locked(KeyVaultError):
    """Ключи защищены паролем, а пароль не дан."""


class WrongPassphrase(KeyVaultError):
    """Пароль не подходит к этой базе."""


def _derive(passphrase: str, salt: bytes, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    if not passphrase:
        raise KeyVaultError("пустой пароль недопустим")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def _aad(memory_id: str) -> bytes:
    return b"padam-key|" + memory_id.encode("utf-8")


def ensure_schema(memory) -> None:
    memory.store.conn.executescript(VAULT_SCHEMA)


def _vault_row(memory):
    ensure_schema(memory)
    return memory.store.one("SELECT * FROM key_vault WHERE id = 1")


def is_enabled(memory) -> bool:
    return _vault_row(memory) is not None


def enable(memory, passphrase: str) -> None:
    """Включить защиту для этой базы: соль, параметры, проверочная запись."""
    if is_enabled(memory):
        raise KeyVaultError("защита уже включена; для смены пароля — rekey()")
    salt = secrets.token_bytes(16)
    kek = _derive(passphrase, salt)
    nonce = secrets.token_bytes(12)
    check = nonce + AESGCM(kek).encrypt(nonce, _CHECK_PLAIN, _CHECK_AAD)
    memory.store.execute(
        "INSERT INTO key_vault (id, salt_hex, kdf, check_hex, created_at) VALUES (1, ?, ?, ?, ?)",
        (salt.hex(), f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}", check.hex(), now_iso()))
    memory._kek = kek


def unlock(memory, passphrase: Optional[str] = None) -> bool:
    """Открыть ключи паролем (аргумент или PADAM_KEY_PASSPHRASE).

    Возвращает False, если защита не включена (открывать нечего).
    Неверный пароль — WrongPassphrase, без пароля — Locked.
    """
    row = _vault_row(memory)
    if row is None:
        return False
    if getattr(memory, "_kek", None):
        return True
    passphrase = passphrase if passphrase is not None else os.environ.get(ENV)
    if not passphrase:
        raise Locked(f"ключи записей защищены паролем: задайте {ENV} или запустите с --ask-passphrase")
    _, n, r, p = row["kdf"].split(":")
    kek = _derive(passphrase, bytes.fromhex(row["salt_hex"]), int(n), int(r), int(p))
    check = bytes.fromhex(row["check_hex"])
    try:
        AESGCM(kek).decrypt(check[:12], check[12:], _CHECK_AAD)
    except InvalidTag:
        raise WrongPassphrase("пароль не подходит к этой базе") from None
    memory._kek = kek
    return True


def lock(memory) -> None:
    """Забыть ключ шифрования ключей в памяти процесса."""
    memory._kek = None


def _kek(memory) -> bytes:
    if not getattr(memory, "_kek", None):
        unlock(memory)          # PADAM_KEY_PASSPHRASE, если задана
    if not getattr(memory, "_kek", None):
        raise Locked(f"ключи записей защищены паролем: задайте {ENV} или запустите с --ask-passphrase")
    return memory._kek


def wrap(memory, memory_id: str, key: bytes) -> str:
    nonce = secrets.token_bytes(12)
    return PREFIX + (nonce + AESGCM(_kek(memory)).encrypt(nonce, key, _aad(memory_id))).hex()


def unwrap(memory, memory_id: str, key_ref: str) -> bytes:
    blob = bytes.fromhex(key_ref[len(PREFIX):])
    try:
        return AESGCM(_kek(memory)).decrypt(blob[:12], blob[12:], _aad(memory_id))
    except InvalidTag:
        raise KeyVaultError(f"обёртка ключа записи {memory_id} не сходится "
                            "(чужая запись или повреждение)") from None


def store_form(memory, memory_id: str, key: bytes) -> str:
    """Как записать новый ключ: завёрнутым, если защита включена, иначе hex."""
    return wrap(memory, memory_id, key) if is_enabled(memory) else key.hex()


def read_form(memory, memory_id: str, key_ref: str) -> bytes:
    """Достать ключ из key_ref любого вида (w1:… или прежний hex)."""
    if key_ref.startswith(PREFIX):
        return unwrap(memory, memory_id, key_ref)
    return bytes.fromhex(key_ref)


def plain_count(memory) -> int:
    """Сколько ключей лежит открытым hex (не завёрнуты и не уничтожены)."""
    r = memory.store.one(
        "SELECT COUNT(*) AS n FROM anchor_key WHERE key_ref != 'destroyed' AND key_ref NOT LIKE 'w1:%'")
    return int(r["n"]) if r else 0


def protect_existing(memory, passphrase: str) -> dict:
    """Включить защиту (если ещё нет) и завернуть все открытые ключи.

    После обёртки — сброс WAL и VACUUM: иначе старые открытые копии ключей
    остаются в свободных страницах файла и в журнале.
    """
    enabled_now = False
    if is_enabled(memory):
        unlock(memory, passphrase)
    else:
        enable(memory, passphrase)
        enabled_now = True
    rows = memory.store.query(
        "SELECT memory_id, key_ref FROM anchor_key WHERE key_ref != 'destroyed' AND key_ref NOT LIKE 'w1:%'")
    conn = memory.store.conn
    with conn:
        for r in rows:
            conn.execute("UPDATE anchor_key SET key_ref = ? WHERE memory_id = ?",
                         (wrap(memory, r["memory_id"], bytes.fromhex(r["key_ref"])), r["memory_id"]))
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("VACUUM")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return {"включена_сейчас": enabled_now, "завёрнуто": len(rows), "открытых_осталось": plain_count(memory)}


def rekey(memory, old_passphrase: str, new_passphrase: str) -> int:
    """Сменить пароль: развернуть старым, завернуть новым — одной транзакцией.

    Новые обёртки готовятся в памяти до записи: сбой посреди смены не оставит
    часть ключей под новым паролем, а проверочную запись — под старым.
    """
    unlock(memory, old_passphrase)
    keys = [(r["memory_id"], unwrap(memory, r["memory_id"], r["key_ref"]))
            for r in memory.store.query("SELECT memory_id, key_ref FROM anchor_key WHERE key_ref LIKE 'w1:%'")]
    salt = secrets.token_bytes(16)
    new_kek = _derive(new_passphrase, salt)
    def обернуть(mid, key):
        nonce = secrets.token_bytes(12)
        return PREFIX + (nonce + AESGCM(new_kek).encrypt(nonce, key, _aad(mid))).hex()
    новые = [(обернуть(mid, key), mid) for mid, key in keys]
    nonce = secrets.token_bytes(12)
    check = nonce + AESGCM(new_kek).encrypt(nonce, _CHECK_PLAIN, _CHECK_AAD)
    conn = memory.store.conn
    with conn:
        conn.executemany("UPDATE anchor_key SET key_ref = ? WHERE memory_id = ?", новые)
        conn.execute("UPDATE key_vault SET salt_hex = ?, kdf = ?, check_hex = ? WHERE id = 1",
                     (salt.hex(), f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}", check.hex()))
    memory._kek = new_kek
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("VACUUM")
    return len(keys)
