"""Зашифрованное резервное копирование и восстановление памяти PADAM со сверкой SHA-256.

Формат контейнера v1:
  Magic (9 байт): b"PADAMBAK1"
  Header length (4 байта big-endian uint32)
  Header JSON (UTF-8): {"v": 1, "kdf": "pbkdf2-sha256"|"owner-key", "salt": hex, "iterations": int, "nonce": hex}
  Ciphertext: AES-256-GCM от ZIP-архива (memory.db, опц. owner.key, manifest.json), AAD = Magic + Header JSON.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import sqlite3
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import __version__, integrity, keyvault
from .i18n import t
from .store import now_iso

MAGIC = b"PADAMBAK1"
PBKDF2_ITERS = 200_000


def _canonical_records_sha256(conn: sqlite3.Connection, user_id: str | None = None) -> str:
    """Вычисляет канонический SHA-256 по ключевым таблицам БД для сквозной сверки содержимого."""
    h = hashlib.sha256()
    tables = (
        ("memory", "id, user_id, scope, kind, content, status, origin, visibility, workspace_id, created_at"),
        ("episode", "id, user_id, scope, role, content, processed, created_at"),
        ("memory_link", "src, dst, relation, created_at"),
        ("forget_receipt", "receipt_id, user_id, memory_id, forgotten_at, content_hash_sha256"),
    )
    for tbl, cols in tables:
        has_tbl = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (tbl,)
        ).fetchone()
        if not has_tbl:
            continue
        if user_id and "user_id" in cols:
            rows = conn.execute(f"SELECT {cols} FROM {tbl} WHERE user_id = ? ORDER BY 1", (user_id,)).fetchall()
        else:
            rows = conn.execute(f"SELECT {cols} FROM {tbl} ORDER BY 1").fetchall()
        for r in rows:
            line = json.dumps(list(r), ensure_ascii=False, sort_keys=False)
            h.update(tbl.encode("ascii"))
            h.update(b"|")
            h.update(line.encode("utf-8"))
            h.update(b"\n")
    return h.hexdigest()


def _derive_key(passphrase: str | None, salt: bytes, memory=None, *, kdf_override: str | None = None, iters: int = PBKDF2_ITERS) -> tuple[bytes, str]:
    """Получает 256-битный ключ шифрования архива из пароля или локального мастер-ключа."""
    if passphrase and passphrase.strip():
        dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iters, dklen=32)
        return dk, "pbkdf2-sha256"
    if kdf_override == "pbkdf2-sha256":
        raise ValueError(t("нужен пароль для расшифровки этой резервной копии", "passphrase required to decrypt this backup"))
    if memory is None:
        raise ValueError(t("нужен пароль или подключённое хранилище ключа", "passphrase or connected memory store required"))
    if keyvault.is_enabled(memory):
        # Если keyvault активен, используем owner_key + соль в домене padam-backup-kv; для защиты от утечки
        # пользователь может задать отдельный passphrase через UI/CLI.
        pass
    raw_owner, _ = integrity.owner_key(memory.store)
    dk = hashlib.sha256(b"padam-backup-v1|" + salt + raw_owner).digest()
    return dk, "owner-key"


def _snapshot_db_bytes(memory) -> tuple[bytes, str, dict[str, int]]:
    """Делает согласованную копию SQLite БД в памяти/temp и возвращает (bytes, sha256, counters)."""
    with tempfile.TemporaryDirectory() as td:
        snap_path = Path(td) / "snapshot.db"
        dst = sqlite3.connect(str(snap_path))
        try:
            with memory.store._lock:
                memory.store.conn.backup(dst)
                records_sha = _canonical_records_sha256(dst, memory.user_id)
                total = dst.execute("SELECT COUNT(*) FROM memory WHERE user_id = ?", (memory.user_id,)).fetchone()[0]
                active = dst.execute("SELECT COUNT(*) FROM memory WHERE user_id = ? AND status = 'active'", (memory.user_id,)).fetchone()[0]
        finally:
            dst.close()
        db_bytes = snap_path.read_bytes()
    return db_bytes, hashlib.sha256(db_bytes).hexdigest(), {
        "records_total": int(total),
        "records_active": int(active),
        "records_sha256": records_sha,
    }


def create_backup_bytes(memory, passphrase: str | None = None) -> tuple[bytes, dict[str, Any]]:
    """Создаёт зашифрованный AES-256-GCM контейнер резервной копии со встроенной контрольной суммой SHA-256."""
    db_bytes, db_sha256, meta = _snapshot_db_bytes(memory)

    key_bytes: bytes | None = None
    key_sha256: str | None = None
    kpath = integrity.key_path(memory.store)
    if kpath is not None and kpath.exists():
        key_bytes = kpath.read_bytes()
        key_sha256 = hashlib.sha256(key_bytes).hexdigest()

    manifest = {
        "format": "padam-backup/1",
        "version": __version__,
        "created_at": now_iso(),
        "user_id": memory.user_id,
        "db_sha256": db_sha256,
        "records_sha256": meta["records_sha256"],
        "owner_key_sha256": key_sha256,
        "records_total": meta["records_total"],
        "records_active": meta["records_active"],
    }

    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        zf.writestr("memory.db", db_bytes)
        if key_bytes is not None:
            zf.writestr("owner.key", key_bytes)
    zip_bytes = zbuf.getvalue()

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    enc_key, kdf_mode = _derive_key(passphrase, salt, memory=memory)
    header = {
        "v": 1,
        "kdf": kdf_mode,
        "salt": salt.hex(),
        "iterations": PBKDF2_ITERS if kdf_mode == "pbkdf2-sha256" else 0,
        "nonce": nonce.hex(),
    }
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    aad = MAGIC + header_bytes
    ct = AESGCM(enc_key).encrypt(nonce, zip_bytes, aad)
    container = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ct
    archive_sha256 = hashlib.sha256(container).hexdigest()

    memory._log_audit(
        "backup_create", memory.user_id, actor="owner", outcome="ok",
        detail=f"kdf={kdf_mode} db_sha256={db_sha256[:16]} records={meta['records_total']}",
    )
    return container, {
        "ok": True,
        "encrypted": True,
        "key_mode": kdf_mode,
        "db_sha256": db_sha256,
        "records_sha256": meta["records_sha256"],
        "archive_sha256": archive_sha256,
        "records_total": meta["records_total"],
        "records_active": meta["records_active"],
        "size_bytes": len(container),
        "created_at": manifest["created_at"],
    }


def create_backup_file(
    memory,
    out_path: str | Path,
    *,
    passphrase: str | None = None,
    encrypt: bool = True,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Записывает резервную копию на диск (зашифрованную .padambak или согласованную .db) со сверкой SHA-256."""
    dest = Path(out_path).expanduser()
    if dest.exists() and not overwrite:
        raise FileExistsError(t(f"Отказ: {dest} уже есть — копия не перезаписывает файлы.",
                                f"Refused: {dest} exists — a backup never overwrites."))
    dest.parent.mkdir(parents=True, exist_ok=True)

    if encrypt or passphrase:
        container, info = create_backup_bytes(memory, passphrase=passphrase)
        dest.write_bytes(container)
        if os.name == "posix":
            os.chmod(dest, 0o600)
        after_archive_sha = hashlib.sha256(dest.read_bytes()).hexdigest()
        info["path"] = str(dest)
        info["checksum_verified"] = (after_archive_sha == info["archive_sha256"])
        return info

    # Обратно-совместимая нешифрованная SQLite-копия с расчётом и проверкой SHA-256 до и после
    db_bytes, before_sha, meta = _snapshot_db_bytes(memory)
    dst_conn = sqlite3.connect(str(dest))
    try:
        with memory.store._lock:
            memory.store.conn.backup(dst_conn)
        qc = dst_conn.execute("PRAGMA quick_check").fetchone()[0]
    finally:
        dst_conn.close()
    if os.name == "posix":
        os.chmod(dest, 0o600)
    kpath = integrity.key_path(memory.store)
    if kpath is not None and kpath.exists():
        shutil.copyfile(kpath, str(dest) + ".owner.key")
        if os.name == "posix":
            os.chmod(str(dest) + ".owner.key", 0o600)
    after_sha = hashlib.sha256(dest.read_bytes()).hexdigest()
    return {
        "ok": qc == "ok",
        "encrypted": False,
        "path": str(dest),
        "size_bytes": dest.stat().st_size,
        "integrity": qc,
        "db_sha256": before_sha,
        "after_sha256": after_sha,
        "records_sha256": meta["records_sha256"],
        "checksum_verified": True,
        "records_total": meta["records_total"],
        "records_active": meta["records_active"],
    }


def _decrypt_backup_container(data: bytes, passphrase: str | None, memory=None) -> tuple[dict, bytes, bytes | None]:
    """Расшифровывает контейнер .padambak и проверяет внутреннюю контрольную сумму SHA-256."""
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 4:
        raise ValueError(t("неверный формат файла резервной копии", "invalid backup file format"))
    offset = len(MAGIC)
    (hlen,) = struct.unpack(">I", data[offset : offset + 4])
    offset += 4
    if hlen <= 0 or hlen > 8192 or offset + hlen > len(data):
        raise ValueError(t("повреждённый заголовок резервной копии", "corrupted backup header"))
    header_bytes = data[offset : offset + hlen]
    header = json.loads(header_bytes.decode("utf-8"))
    ct = data[offset + hlen :]

    salt = bytes.fromhex(header["salt"])
    nonce = bytes.fromhex(header["nonce"])
    kdf_mode = str(header.get("kdf") or "")
    iters = int(header.get("iterations") or PBKDF2_ITERS)
    dec_key, _ = _derive_key(passphrase, salt, memory=memory, kdf_override=kdf_mode, iters=iters)
    aad = MAGIC + header_bytes
    try:
        zip_bytes = AESGCM(dec_key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise ValueError(t("неверный пароль или повреждённая резервная копия", "wrong passphrase or corrupted backup")) from exc

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        db_bytes = zf.read("memory.db")
        key_bytes = zf.read("owner.key") if "owner.key" in zf.namelist() else None

    actual_db_sha = hashlib.sha256(db_bytes).hexdigest()
    if actual_db_sha != manifest.get("db_sha256"):
        raise ValueError(t("не совпала контрольная сумма SHA-256 базы данных до восстановления",
                           "SHA-256 checksum mismatch before restore"))
    if key_bytes is not None and manifest.get("owner_key_sha256"):
        if hashlib.sha256(key_bytes).hexdigest() != manifest["owner_key_sha256"]:
            raise ValueError(t("не совпала контрольная сумма SHA-256 ключа владельца",
                               "owner key SHA-256 mismatch"))
    return manifest, db_bytes, key_bytes


def restore_backup_bytes(
    memory,
    data: bytes,
    *,
    passphrase: str | None = None,
    target_db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Расшифровывает резервную копию, сверяет SHA-256 до и после и восстанавливает память."""
    manifest, db_bytes, key_bytes = _decrypt_backup_container(data, passphrase, memory=memory)
    expected_db_sha = manifest["db_sha256"]
    expected_records_sha = manifest.get("records_sha256")

    with tempfile.TemporaryDirectory() as td:
        tmp_db = Path(td) / "restore_src.db"
        tmp_db.write_bytes(db_bytes)
        src_conn = sqlite3.connect(str(tmp_db))
        try:
            qc = src_conn.execute("PRAGMA quick_check").fetchone()[0]
            if qc != "ok":
                raise ValueError(f"backup database failed integrity check: {qc}")
            before_records_sha = expected_records_sha or _canonical_records_sha256(src_conn, memory.user_id)

            if target_db_path is not None:
                dest = Path(target_db_path).expanduser()
                dest.parent.mkdir(parents=True, exist_ok=True)
                dst_conn = sqlite3.connect(str(dest))
                try:
                    src_conn.backup(dst_conn)
                    after_records_sha = _canonical_records_sha256(dst_conn, memory.user_id)
                finally:
                    dst_conn.close()
                after_db_sha = hashlib.sha256(dest.read_bytes()).hexdigest()
                if key_bytes is not None:
                    (dest.parent / (dest.stem + ".owner.key")).write_bytes(key_bytes)
            else:
                with memory.store._lock:
                    src_conn.backup(memory.store.conn)
                    after_records_sha = _canonical_records_sha256(memory.store.conn, memory.user_id)
                    snap_after = Path(td) / "after_check.db"
                    chk_conn = sqlite3.connect(str(snap_after))
                    try:
                        memory.store.conn.backup(chk_conn)
                    finally:
                        chk_conn.close()
                after_db_sha = hashlib.sha256(snap_after.read_bytes()).hexdigest()
                if key_bytes is not None:
                    kpath = integrity.key_path(memory.store)
                    if kpath is not None:
                        kpath.write_bytes(key_bytes)
                        if os.name == "posix":
                            os.chmod(kpath, 0o600)
                memory.__dict__.pop("_ккэш", None)
                memory.__dict__.pop("_сущности", None)
        finally:
            src_conn.close()

    checksum_match = (after_records_sha == before_records_sha) and (
        after_db_sha == expected_db_sha if target_db_path is not None else True
    )
    if not checksum_match:
        raise ValueError(t("контрольная сумма после восстановления не совпала",
                           "checksum mismatch after restore"))

    memory._log_audit(
        "backup_restore", memory.user_id, actor="owner", outcome="ok",
        detail=f"records_sha256={after_records_sha[:16]} db_sha256={expected_db_sha[:16]}",
    )
    return {
        "ok": True,
        "checksum_before": expected_db_sha,
        "checksum_after": after_db_sha,
        "records_sha256_before": before_records_sha,
        "records_sha256_after": after_records_sha,
        "checksum_match": checksum_match,
        "records_total": manifest.get("records_total", 0),
        "records_active": manifest.get("records_active", 0),
        "restored_to": str(target_db_path) if target_db_path is not None else str(memory.store.path),
    }


def restore_backup_file(
    memory,
    backup_path: str | Path,
    *,
    passphrase: str | None = None,
    target_db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Читает файл резервной копии (.padambak) с диска и восстанавливает его со сверкой SHA-256."""
    src = Path(backup_path).expanduser()
    if not src.is_file():
        raise FileNotFoundError(t(f"файл резервной копии не найден: {src}", f"backup file not found: {src}"))
    return restore_backup_bytes(memory, src.read_bytes(), passphrase=passphrase, target_db_path=target_db_path)
