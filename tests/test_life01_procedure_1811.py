"""Фаза 2 аудита GLM, LIFE-01: новая процедура с тем же именем не превращает забытую (revoked) в superseded."""
from __future__ import annotations

from padam import procedural
from padam.memory import Memory
from padam.store import Store


def test_забытая_процедура_остаётся_забытой(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_PROCEDURAL_MEMORY", "1")
    m = Memory(user_id="u", store=Store(tmp_path / "p.db"))
    a = procedural.save_procedure(m, name="deploy", steps="1. build\n2. push", owner_approved=True, force=True)["id"]
    assert m.revoke(a)
    b = procedural.save_procedure(m, name="deploy", steps="1. test\n2. build\n3. push", owner_approved=True, force=True)["id"]
    st = m.store.one("SELECT status FROM memory WHERE id = ?", (a,))[0]
    links = m.store.one("SELECT COUNT(*) FROM memory_link WHERE src = ? AND dst = ?", (a, b))[0]
    assert st == "revoked" and links == 0
    m.close()


def test_действующая_заменяется_как_раньше(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_PROCEDURAL_MEMORY", "1")
    m = Memory(user_id="u", store=Store(tmp_path / "p2.db"))
    a = procedural.save_procedure(m, name="deploy", steps="1. build", owner_approved=True, force=True)["id"]
    b = procedural.save_procedure(m, name="deploy", steps="1. test\n2. build", owner_approved=True, force=True)["id"]
    assert m.store.one("SELECT status FROM memory WHERE id = ?", (a,))[0] == "superseded"
    m.close()
