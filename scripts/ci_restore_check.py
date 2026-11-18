#!/usr/bin/env python3
"""Проверка полного восстановления PADAM в CI (пункт 2.6):
демо-база -> JSON-экспорт -> импорт в пустую базу -> поштучная сверка всех записей и связей,
а также зашифрованный бэкап -> восстановление -> сверка SHA-256 и содержимого.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from padam import backup  # noqa: E402
from padam.demo import build_demo_memory  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402

RECORD_COMPARE_FIELDS = (
    "scope",
    "kind",
    "content",
    "status",
    "origin",
    "importance",
    "confidence",
    "supersedes",
    "superseded_by",
    "valid_from",
    "valid_to",
    "content_hash",
    "quarantine_reason",
)


def _snapshot_records(mem: Memory) -> dict[str, dict]:
    """Снимает поштучный словарь всех записей из таблицы memory."""
    rows = mem.store.query(
        "SELECT * FROM memory WHERE user_id = ? ORDER BY id",
        (mem.user_id,),
    )
    out: dict[str, dict] = {}
    for row in rows:
        item = dict(row)
        ch = item.get("content_hash")
        item["content_hash"] = ch.hex() if isinstance(ch, (bytes, bytearray)) else ch
        out[item["id"]] = item
    return out


def _snapshot_links(mem: Memory) -> set[tuple[str, str, str]]:
    """Снимает все направленные рёбра (src, dst, relation) для записей пользователя."""
    rows = mem.store.query(
        """SELECT l.src, l.dst, COALESCE(l.relation, 'derived') AS relation
           FROM memory_link l JOIN memory m ON m.id = l.dst
           WHERE m.user_id = ?""",
        (mem.user_id,),
    )
    return {(r["src"], r["dst"], r["relation"]) for r in rows}


def _assert_equal_memories(src: Memory, dst: Memory, label: str) -> tuple[int, int]:
    """Сравнивает все записи и все связи двух экземпляров Memory."""
    rec_a = _snapshot_records(src)
    rec_b = _snapshot_records(dst)
    assert set(rec_a.keys()) == set(rec_b.keys()), (
        f"[{label}] mismatch in record IDs: "
        f"missing={sorted(set(rec_a) - set(rec_b))}, extra={sorted(set(rec_b) - set(rec_a))}"
    )
    for rec_id, a in rec_a.items():
        b = rec_b[rec_id]
        for field in RECORD_COMPARE_FIELDS:
            assert a.get(field) == b.get(field), (
                f"[{label}] mismatch in record {rec_id}.{field}: {a.get(field)!r} != {b.get(field)!r}"
            )

    links_a = _snapshot_links(src)
    links_b = _snapshot_links(dst)
    assert links_a == links_b, (
        f"[{label}] mismatch in links: "
        f"missing={sorted(links_a - links_b)}, extra={sorted(links_b - links_a)}"
    )
    return len(rec_a), len(links_a)


def run_restore_check() -> dict:
    """Выполняет полный цикл проверки восстановления демо-базы."""
    with tempfile.TemporaryDirectory(prefix="padam-restore-ci-") as td:
        tmp = pathlib.Path(td)
        db1 = tmp / "demo_source.db"
        db2 = tmp / "restored_json.db"
        db3 = tmp / "restored_backup.db"
        bak_file = tmp / "demo.padambak"

        mem_src, _ = build_demo_memory(db1)
        try:
            # 1. Полный JSON-экспорт -> сериализация -> импорт в пустую базу
            payload_text = json.dumps(
                mem_src.export(include_superseded=True, include_held=True),
                ensure_ascii=False,
            )
            payload = json.loads(payload_text)

            # Восстановление своей выгрузки на той же машине: тот же ключ владельца рядом с базой. Тогда подпись
            # записей подтверждается, и защищённые виды не уходят на проверку (аудит GLM MEM-01, 18.11.2026).
            import shutil as _sh
            for _src_key in db1.parent.glob(db1.name + "*.key"):
                _sh.copy(_src_key, db2.parent / _src_key.name.replace(db1.name, db2.name))
            mem_json = Memory(user_id=mem_src.user_id, store=Store(db2))
            try:
                added = mem_json.import_(payload, overwrite=False)
                assert added == len(payload["memory"]), (
                    f"imported count mismatch: {added} != {len(payload['memory'])}"
                )
                n_records, n_links = _assert_equal_memories(mem_src, mem_json, "json-export-import")
            finally:
                mem_json.close()

            # 2. Зашифрованный бэкап -> восстановление в новую базу со сверкой SHA-256
            bak_info = backup.create_backup_file(
                mem_src,
                bak_file,
                passphrase="ci-restore-passphrase",
                encrypt=True,
                overwrite=True,
            )
            assert bak_info.get("ok") is True and bak_info.get("db_sha256")
            mem_bak = Memory(user_id=mem_src.user_id, store=Store(db3))
            try:
                restore_info = backup.restore_backup_file(
                    mem_bak,
                    bak_file,
                    passphrase="ci-restore-passphrase",
                )
                assert restore_info.get("ok") is True
                assert restore_info.get("checksum_match") is True
                assert (
                    restore_info.get("records_sha256_before")
                    and restore_info.get("records_sha256_before") == restore_info.get("records_sha256_after")
                )
                b_records, b_links = _assert_equal_memories(mem_src, mem_bak, "encrypted-backup-restore")
            finally:
                mem_bak.close()

            return {
                "ok": True,
                "records_checked": n_records,
                "links_checked": n_links,
                "backup_records_checked": b_records,
                "backup_links_checked": b_links,
                "db_sha256": restore_info["checksum_after"],
                "records_sha256": restore_info["records_sha256_after"],
            }
        finally:
            mem_src.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="PADAM CI restore verification (demo -> export -> import -> diff)")
    parser.add_argument("--json", action="store_true", help="Print JSON summary")
    args = parser.parse_args()
    res = run_restore_check()
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(
            f"CI restore check PASSED: {res['records_checked']} records, "
            f"{res['links_checked']} links, SHA-256={res['db_sha256'][:16]}..."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
