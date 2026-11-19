# -*- coding: utf-8 -*-
"""19.11.2026: CI Windows/3.10 — «cannot commit - no transaction is active» в параллельном совете карантина.
Класс: модули пишут в store.conn напрямую, мимо замка хранилища. Замок встроен в само соединение."""
import threading

from padam.memory import Memory
from padam.store import Store, _ConnUnderLock


def test_соединение_хранилища_под_замком(tmp_path):
    s = Store(tmp_path / "a.db")
    assert isinstance(s.conn, _ConnUnderLock)
    assert s.conn.raw.__class__.__name__ == "Connection"


def test_прямые_записи_и_atomic_параллельно_не_падают(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "b.db"))
    st = m.store
    st.conn.execute("CREATE TABLE IF NOT EXISTS t_race (k INTEGER)")
    st.conn.commit()
    ошибки = []

    def прямо():
        try:
            for i in range(300):
                st.conn.execute("INSERT INTO t_race (k) VALUES (?)", (i,))
                st.conn.commit()
        except Exception as exc:  # pragma: no cover
            ошибки.append(repr(exc))

    def через_atomic():
        try:
            for i in range(300):
                st.atomic([("INSERT INTO t_race (k) VALUES (?)", (-i,))])
        except Exception as exc:  # pragma: no cover
            ошибки.append(repr(exc))

    th = [threading.Thread(target=f) for f in (прямо, через_atomic) * 4]
    [t.start() for t in th]
    [t.join() for t in th]
    assert not ошибки, ошибки[:3]
    assert st.one("SELECT COUNT(*) AS n FROM t_race")["n"] == 300 * 8


def test_резервная_копия_в_соединение_хранилища(tmp_path):
    import sqlite3
    st = Store(tmp_path / "c.db")
    src = sqlite3.connect(":memory:")
    src.execute("CREATE TABLE z (a)")
    src.commit()
    src.backup(st.conn.raw)
    st.conn.backup(sqlite3.connect(":memory:"))   # обёртка разворачивает и цель, и источник
