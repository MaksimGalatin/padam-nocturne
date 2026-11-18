# -*- coding: utf-8 -*-
"""Самоисцеление базы SQLite (Self-Healing Diagnostics & Safe Proposal).

Жёсткое правило безопасности (поправка приёмки 17.11):
1. Модуль НИКОГДА не перезаписывает и не откатывает боевую БД автоматически: автоматический
   откат к старой капсуле Феникса уничтожил бы всё, что было записано после неё.
2. Повреждённый файл всегда сохраняется рядом как `.corrupted.<timestamp>.bak`.
3. Сначала выполняется штатная попытка спасения SQLite в отдельную копию (WAL-чекпоинт,
   `PRAGMA integrity_check`, перенос уцелевших строк / `.recover` в копию).
4. Откат к капсуле Феникса формируется строго как **предложение владельцу** с честным
   подсчётом числа записей, которые будут потеряны после чекпоинта.
"""
from __future__ import annotations

import contextlib
import shutil
import sqlite3
import subprocess
import time
import zipfile
import json
from pathlib import Path
from typing import Any


def _count_records_safe(db_file: Path) -> int | None:
    try:
        with contextlib.closing(sqlite3.connect(str(db_file))) as conn:
            row = conn.execute("SELECT COUNT(*) FROM memory").fetchone()
            return int(row[0]) if row else 0
    except Exception:
        return None


def diagnose_database(db_path: str | Path) -> dict[str, Any]:
    """Проверяет здоровье SQLite через `PRAGMA integrity_check` и наличие WAL."""
    p = Path(db_path).resolve()
    if not p.exists():
        return {"exists": False, "healthy": False, "integrity": "missing", "wal_present": False, "active_records": 0}
    wal_exists = p.with_name(p.name + "-wal").exists()
    try:
        with contextlib.closing(sqlite3.connect(str(p))) as conn:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
            msgs = [str(r[0]) for r in rows]
            healthy = (len(msgs) == 1 and msgs[0].lower() == "ok")
            cnt = _count_records_safe(p)
            return {
                "exists": True,
                "healthy": healthy,
                "integrity": "ok" if healthy else "; ".join(msgs[:5]),
                "wal_present": wal_exists,
                "active_records": cnt,
            }
    except Exception as exc:
        return {
            "exists": True,
            "healthy": False,
            "integrity": f"error: {exc}",
            "wal_present": wal_exists,
            "active_records": None,
        }


def _try_sqlite_recover_to_copy(corrupted_copy: Path, target_copy: Path) -> tuple[bool, str]:
    """Пробует штатное восстановление SQLite: сначала WAL-чекпоинт, потом `.recover` / `iterdump`."""
    # Шаг A: пробуем WAL checkpoint и копирование через SQLite
    try:
        with contextlib.closing(sqlite3.connect(str(corrupted_copy))) as src:
            src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            chk = src.execute("PRAGMA integrity_check").fetchone()
            if chk and str(chk[0]).lower() == "ok":
                with contextlib.closing(sqlite3.connect(str(target_copy))) as dst:
                    src.backup(dst)
                return True, "wal_checkpoint_recovery"
    except Exception:
        pass

    # Шаг B: пробуем системную утилиту sqlite3 .recover, если установлена в PATH
    if shutil.which("sqlite3"):
        try:
            proc = subprocess.run(
                ["sqlite3", str(corrupted_copy), ".recover"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                with contextlib.closing(sqlite3.connect(str(target_copy))) as dst:
                    dst.executescript(proc.stdout)
                    chk = dst.execute("PRAGMA integrity_check").fetchone()
                    if chk and str(chk[0]).lower() == "ok":
                        return True, "sqlite_cli_recover"
        except Exception:
            pass

    # Шаг C: штатный Python SQLite iterdump в новую чистую копию
    try:
        with contextlib.closing(sqlite3.connect(str(corrupted_copy))) as src:
            sql_script = "\n".join(src.iterdump())
        with contextlib.closing(sqlite3.connect(str(target_copy))) as dst:
            dst.executescript(sql_script)
            chk = dst.execute("PRAGMA integrity_check").fetchone()
            if chk and str(chk[0]).lower() == "ok":
                return True, "sqlite_iterdump_copy"
    except Exception:
        pass

    return False, "sqlite_recover_failed"


def _capsule_records_count(capsule_path: str | Path | None) -> int | None:
    if not capsule_path:
        return None
    cp = Path(capsule_path).resolve()
    if not cp.exists():
        return None
    try:
        if cp.suffix == ".zip" or zipfile.is_zipfile(cp):
            import tempfile
            with zipfile.ZipFile(cp, "r") as zf:
                if "memory.db" not in zf.namelist():
                    return None
                with tempfile.TemporaryDirectory(prefix="padam_cap_cnt_") as td:
                    tmp_db = Path(td) / "memory.db"
                    tmp_db.write_bytes(zf.read("memory.db"))
                    return _count_records_safe(tmp_db)
    except Exception:
        return None
    return None


def inspect_and_propose_repair(
    db_path: str | Path,
    *,
    capsule_path: str | Path | None = None,
    known_active_records: int | None = None,
) -> dict[str, Any]:
    """Проверяет БД, при сбое сохраняет битую копию рядом, пробует SQLite `.recover` в копию и выдаёт предложение владельцу."""
    p = Path(db_path).resolve()
    diag = diagnose_database(p)
    if diag.get("healthy"):
        return {
            "ok": True,
            "needed": False,
            "auto_replaced": False,
            "diagnosis": diag,
        }

    if not p.exists():
        return {
            "ok": False,
            "needed": True,
            "auto_replaced": False,
            "diagnosis": diag,
            "proposal": "Database file missing; owner may confirm restore from Phoenix capsule.",
            "owner_confirmation_required": True,
        }

    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    corrupted_bak = p.with_name(f"{p.name}.corrupted.{stamp}.bak")
    shutil.copy2(p, corrupted_bak)
    for ext in ("-wal", "-shm"):
        side = p.with_name(p.name + ext)
        if side.exists():
            shutil.copy2(side, corrupted_bak.with_name(corrupted_bak.name + ext))

    recovered_copy = p.with_name(f"{p.name}.recovered.{stamp}.sqlite")
    sql_ok, sql_method = _try_sqlite_recover_to_copy(corrupted_bak, recovered_copy)
    rec_cnt = _count_records_safe(recovered_copy) if sql_ok else None
    if not sql_ok and recovered_copy.exists():
        recovered_copy.unlink()

    cap_cnt = _capsule_records_count(capsule_path)
    before_cnt = known_active_records if known_active_records is not None else (rec_cnt if rec_cnt is not None else diag.get("active_records"))
    lost_if_rollback = (
        max(0, int(before_cnt) - int(cap_cnt))
        if (before_cnt is not None and cap_cnt is not None)
        else None
    )

    return {
        "ok": True,
        "needed": True,
        "auto_replaced": False,  # НИКОГДА не подменяем боевую базу без явного подтверждения владельца
        "owner_confirmation_required": True,
        "diagnosis": diag,
        "corrupted_backup_path": str(corrupted_bak),
        "sqlite_recover_ok": sql_ok,
        "sqlite_recover_method": sql_method,
        "recovered_copy_path": str(recovered_copy) if sql_ok else None,
        "recovered_records_count": rec_cnt,
        "capsule_path": str(Path(capsule_path).resolve()) if capsule_path else None,
        "capsule_records_count": cap_cnt,
        "records_potentially_lost_on_capsule_rollback": lost_if_rollback,
        "proposal": (
            f"SQLite recovery saved clean copy ({rec_cnt} records) to {recovered_copy.name}; "
            f"rollback to capsule ({cap_cnt} records) would lose {lost_if_rollback} records. Owner confirmation required."
            if sql_ok and cap_cnt is not None
            else (
                f"SQLite recovery saved clean copy to {recovered_copy.name}. Owner confirmation required to swap."
                if sql_ok
                else f"SQLite auto-recover failed ({sql_method}). Rollback to capsule would lose {lost_if_rollback} records; confirm manually."
            )
        ),
    }
