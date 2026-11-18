# -*- coding: utf-8 -*-
"""18.11.2026: GET /l3 и POST /l3-verify одновременно делали ALTER TABLE l3_anchor ADD COLUMN ots — второй падал
«duplicate column name», Studio показывала 500. Класс починен в одном месте: store.add_column_safe."""
import sqlite3
import threading

import pytest

from padam.store import add_column_safe


def test_параллельные_потоки_не_падают():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE t (a TEXT)")
    барьер = threading.Barrier(8)
    итоги, ошибки = [], []

    def работа():
        барьер.wait()
        try:
            итоги.append(add_column_safe(conn, "t", "b", "TEXT"))
        except Exception as e:  # pragma: no cover - это и есть поломка
            ошибки.append(e)

    потоки = [threading.Thread(target=работа) for _ in range(8)]
    for п in потоки:
        п.start()
    for п in потоки:
        п.join()
    assert not ошибки
    assert итоги.count(True) == 1
    assert "b" in {r[1] for r in conn.execute("PRAGMA table_info(t)")}


class _Гонка:
    """Соединение, где столбец «добавил другой процесс» между PRAGMA и ALTER."""

    def __init__(self, ошибка):
        self.ошибка = ошибка

    def execute(self, sql, *a):
        if sql.startswith("PRAGMA"):
            return self
        raise sqlite3.OperationalError(self.ошибка)

    def fetchall(self):
        return []


def test_duplicate_column_от_другого_процесса_не_ошибка():
    assert add_column_safe(_Гонка("duplicate column name: b"), "t", "b", "TEXT") is False


def test_другая_ошибка_не_глотается():
    with pytest.raises(sqlite3.OperationalError):
        add_column_safe(_Гонка("database is locked"), "t", "b", "TEXT")


def test_l3_схема_дважды_и_параллельно(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    from padam import anchor
    from padam.memory import Memory
    from padam.store import Store
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    барьер = threading.Barrier(4)
    ошибки = []

    def работа():
        барьер.wait()
        try:
            anchor.ensure_schema(m)
        except Exception as e:  # pragma: no cover
            ошибки.append(e)

    потоки = [threading.Thread(target=работа) for _ in range(4)]
    for п in потоки:
        п.start()
    for п in потоки:
        п.join()
    assert not ошибки
    assert "ots" in {r[1] for r in m.store.conn.execute("PRAGMA table_info(l3_anchor)")}
