# -*- coding: utf-8 -*-
"""18.11.2026: поиск на 20 000 записях тратил 0,53 из 0,61 с на commit служебных счётчиков после каждого запроса.
Счётчики теперь откладываются — но не теряются и видны при чтении."""
import sqlite3

from padam.memory import Memory
from padam.store import Store


def test_счётчики_отложены_но_видны(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    monkeypatch.setattr("padam.store.time.monotonic", lambda: 1000.0)
    m = Memory(user_id="u", store=Store(tmp_path / "c.db"))
    m.remember("PADAM хранит память в одном файле SQLite", kind="fact")
    for _ in range(5):
        m.recall("где хранится память", limit=5)
    assert m.store._отложенные, "счётчики должны копиться, а не писаться после каждого поиска"
    assert m.self_report()["searches"] == 5          # чтение счётчиков сначала дописывает их
    assert not m.store._отложенные


def test_счётчики_не_теряются_при_закрытии(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    monkeypatch.setattr("padam.store.time.monotonic", lambda: 1000.0)
    путь = tmp_path / "d.db"
    m = Memory(user_id="u", store=Store(путь))
    m.remember("Совет Семьи — шесть ролей", kind="fact")
    for _ in range(3):
        m.recall("сколько ролей в Совете", limit=5)
    m.store.close()
    c = sqlite3.connect(путь)
    assert c.execute("SELECT SUM(searches) FROM search_stats").fetchone()[0] == 3
    assert c.execute("SELECT MAX(access_count) FROM memory").fetchone()[0] >= 3


def test_настоящая_запись_уносит_счётчики_тем_же_коммитом(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    monkeypatch.setattr("padam.store.time.monotonic", lambda: 1000.0)
    путь = tmp_path / "e.db"
    m = Memory(user_id="u", store=Store(путь))
    m.remember("первая запись", kind="fact")
    m.recall("первая", limit=5)
    c = sqlite3.connect(путь)
    assert (c.execute("SELECT COALESCE(SUM(searches),0) FROM search_stats").fetchone()[0]) == 0   # ещё отложено
    m.remember("вторая запись", kind="fact")
    assert c.execute("SELECT SUM(searches) FROM search_stats").fetchone()[0] >= 1             # ушло с записью
