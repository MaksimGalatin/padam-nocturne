"""N6 дорожной карты Сестры (19.11.2026): учение восстановления.

Бэкап, который ни разу не восстанавливали, — надежда, а не бэкап. Учение: зашифрованная копия текущей памяти →
восстановление во ВРЕМЕННЫЙ файл (живая база не трогается) → сверка канонического отпечатка всех записей
до и после. Итог пишется в журнал учений рядом с журналами (logs/restore-drills.jsonl)."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from . import backup


def run_drill(memory) -> dict:
    t0 = time.perf_counter()
    with memory.store._lock:
        src_sha = backup._canonical_records_sha256(memory.store.conn, memory.user_id)
    data, info = backup.create_backup_bytes(memory)
    with tempfile.TemporaryDirectory(prefix="padam_drill_") as td:
        target = Path(td) / "restored.db"
        res = backup.restore_backup_bytes(memory, data, target_db_path=target)
        c = sqlite3.connect(str(target))
        try:
            c.row_factory = sqlite3.Row
            restored_sha = backup._canonical_records_sha256(c, memory.user_id)
            n = c.execute("SELECT COUNT(*) FROM memory WHERE user_id = ?", (memory.user_id,)).fetchone()[0]
        finally:
            c.close()
    out = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "ok": src_sha == restored_sha,
           "records_sha256_source": src_sha[:16], "records_sha256_restored": restored_sha[:16],
           "records_restored": int(n), "backup_bytes": len(data), "elapsed_s": round(time.perf_counter() - t0, 2),
           "live_db_touched": False, "restore_report_ok": bool(res.get("ok", True))}
    try:
        from .observability import _папка
        with (_папка() / "restore-drills.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(out, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return out
