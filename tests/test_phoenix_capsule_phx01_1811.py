"""Аудит GLM фаза 2, PHX-01 (Critical, 18.11.2026): распаковка «Феникс-капсулы» не заменяет ключ владельца
и не воскрешает забытые записи."""
from __future__ import annotations

import sqlite3

import pytest

from padam import phoenix
from padam.memory import Memory
from padam.store import Store


def _mem(path):
    from padam import integrity
    m = Memory(user_id="u", store=Store(path))
    integrity.owner_key(m.store)  # ключ владельца создаётся лениво — создаём явно, как после первой подписи
    return m


def _id(r):
    return r[1] if isinstance(r, tuple) else r


def test_старая_капсула_не_воскрешает_забытое(tmp_path):
    db = tmp_path / "a.db"
    m = _mem(db)
    mid = _id(m.remember("Секрет, который владелец потом забудет", kind="fact", origin="user"))
    m.close()
    cap = phoenix.pack_phoenix_capsule(db, tmp_path / "cap.phoenix.zip")["capsule_path"]
    m = _mem(db); assert m.revoke(mid); m.close()

    rep = phoenix.unpack_phoenix_capsule(cap, db)
    assert rep["reforgotten"] >= 1 and rep["backup"]
    con = sqlite3.connect(db)
    st, content = con.execute("SELECT status, content FROM memory WHERE id = ?", (mid,)).fetchone()
    n_receipts = con.execute("SELECT COUNT(*) FROM forget_receipt WHERE memory_id = ?", (mid,)).fetchone()[0]
    con.close()
    assert st == "revoked" and content is None and n_receipts == 1
    assert b"\xd0\xa1\xd0\xb5\xd0\xba\xd1\x80\xd0\xb5\xd1\x82" not in db.read_bytes()  # «Секрет» не лежит в файле


def test_чужая_капсула_не_меняет_ключ_владельца(tmp_path):
    мой = tmp_path / "mine.db"; чужой = tmp_path / "evil.db"
    m = _mem(мой); m.remember("моя запись", kind="fact", origin="user"); m.close()
    e = _mem(чужой); e.remember("подброшенное", kind="fact", origin="user"); e.close()
    мой_ключ = (tmp_path / "mine.db.owner.key").read_bytes()
    байты_до = мой.read_bytes()
    cap = phoenix.pack_phoenix_capsule(чужой, tmp_path / "evil.phoenix.zip")["capsule_path"]
    with pytest.raises(ValueError, match="different owner key"):
        phoenix.unpack_phoenix_capsule(cap, мой)
    assert (tmp_path / "mine.db.owner.key").read_bytes() == мой_ключ
    assert мой.read_bytes() == байты_до


def test_своя_капсула_на_чистую_машину_ставит_ключ(tmp_path):
    db = tmp_path / "a.db"
    m = _mem(db); m.remember("запись", kind="fact", origin="user"); m.close()
    cap = phoenix.pack_phoenix_capsule(db, tmp_path / "c.phoenix.zip")["capsule_path"]
    новая = tmp_path / "new" / "a.db"
    rep = phoenix.unpack_phoenix_capsule(cap, новая)
    assert rep["owner_key"] == "installed"
    assert (новая.parent / "a.db.owner.key").read_bytes() == (tmp_path / "a.db.owner.key").read_bytes()
