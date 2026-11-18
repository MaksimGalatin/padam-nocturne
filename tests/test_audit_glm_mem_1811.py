# Аудит GLM 18.11.2026: MEM-02 (сбой журнала не молчит) и MEM-09 (panic не уничтожает квитанции забвения).
from padam.memory import Memory
from padam.store import Store


def test_сбой_журнала_аудита_виден(tmp_path, capsys):
    m = Memory(user_id="u", store=Store(tmp_path / "a.db"))
    m.store.conn.execute("DROP TABLE audit_log")
    m._log_audit("probe")
    assert m.stats()["audit_failures"] == 1
    assert "audit_log write failed" in capsys.readouterr().err


def test_panic_сохраняет_квитанции_но_не_отпечаток(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "p.db"))
    _, rid = m.remember("Secret plan alpha", kind="fact")
    m.revoke(rid)
    assert m.store.one("SELECT content_hash_sha256 FROM forget_receipt WHERE memory_id = ?", (rid,))[0]
    m.panic(wipe_local=True)
    row = m.store.one("SELECT receipt_id, content_hash_sha256 FROM forget_receipt WHERE memory_id = ?", (rid,))
    assert row is not None and row["receipt_id"]          # доказательство стирания осталось
    assert row["content_hash_sha256"] is None             # проверить догадку по отпечатку нельзя


def test_откат_подписывает_восстановленное_предпочтение(tmp_path):
    from padam import integrity, snapshots
    m = Memory(user_id="u", store=Store(tmp_path / "s.db"))
    _, pid = m.remember("The favourite word of the owner is Amber", kind="preference")
    snap = snapshots.create_snapshot(m, name="before")
    исход, _ = m.remember("The favourite word of the owner is Basalt", kind="preference")  # заменяет старое
    assert исход == "superseded"
    m.store.execute("UPDATE memory SET owner_sig = NULL WHERE id = ?", (pid,))  # подпись должен поставить сам откат
    res = snapshots.rollback(m, snapshot_id=snap.get("snapshot_id") or snap.get("id"), revoke_after=False)
    key, _ = integrity.owner_key(m.store)
    rows = m.store.query("SELECT id, kind, content, owner_sig FROM memory WHERE kind='preference' AND content IS NOT NULL")
    assert rows, res
    assert all(integrity.valid(key, r) for r in rows)
