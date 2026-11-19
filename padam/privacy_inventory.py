"""N8 дорожной карты Сестры (19.11.2026): опись личных данных — единый ответ на запрос «что вы обо мне храните».

Перечисляет таблицы базы, где есть колонка user_id, и сколько в каждой записей этого человека; где лежит файл
базы и ключ; что по умолчанию уходит с компьютера (ничего — заливка в Arweave только при явном включении).
Выгрузка всех данных — существующий `padam export`, удаление навсегда с квитанцией — `padam forget`."""
from __future__ import annotations

import os


def inventory(memory) -> dict:
    st = memory.store
    tables = []
    with st._lock:
        names = [r[0] for r in st.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%_fts%'"
        ).fetchall()]
        for n in sorted(names):
            cols = {r[1] for r in st.conn.execute(f'PRAGMA table_info("{n}")').fetchall()}
            if "user_id" not in cols:
                continue
            cnt = st.conn.execute(f'SELECT COUNT(*) FROM "{n}" WHERE user_id = ?', (memory.user_id,)).fetchone()[0]
            if cnt:
                tables.append({"table": n, "rows": int(cnt)})
    return {
        "user_id": memory.user_id,
        "db_path": str(st.path),
        "tables_with_your_data": tables,
        "total_rows": sum(t["rows"] for t in tables),
        "leaves_this_computer_by_default": [],
        "optional_outbound": {"arweave_mirror": os.environ.get("ARWEAVE_MIRROR") == "1"},
        "how_to_export": "padam export",
        "how_to_erase": "padam forget <id>  (crypto-shredding with receipt)",
    }
