"""Тесты защиты ключей записей паролем (padam/keyvault.py).

Каждый тест — одно обещание модуля: ключ в базе не лежит открытым, неверный
пароль ловится сразу, обёртку нельзя переставить на чужую запись, старая база
защищается без остатков открытых ключей в файле, смена пароля не теряет ключи,
право на забвение работает как прежде.
"""
import base64
import json

import pytest

from padam import anchor, keyvault
from padam.memory import Memory
from padam.store import Store

ПАРОЛЬ = "долгая ночь перед годовщиной"


@pytest.fixture
def mem(tmp_path):
    m = Memory(user_id="test", store=Store(tmp_path / "t.db"))
    anchor.ensure_schema(m)
    yield m
    m.close()


def _fake(calls):
    def up(payload, tags):
        calls["payload"] = payload
        return "AR_TX_1"

    def anc(memo):
        return "SIG_1", 1
    return up, anc


def _ключи(mem):
    return {r["memory_id"]: r["key_ref"] for r in mem.store.query("SELECT memory_id, key_ref FROM anchor_key")}


def test_new_keys_are_wrapped_and_records_still_decrypt(mem):
    keyvault.enable(mem, ПАРОЛЬ)
    mem.remember("номер дома бабушки — 14")
    calls = {}
    up, anc = _fake(calls)
    anchor.run_l3(mem, uploader=up, anchorer=anc)
    refs = _ключи(mem)
    assert refs and all(v.startswith("w1:") for v in refs.values()), "в базе нет ни одного открытого ключа"
    rec = json.loads(calls["payload"])["records"][0]
    assert anchor.decrypt(base64.b64decode(rec["data"]), anchor.key_for(mem, rec["id"])) == "номер дома бабушки — 14"


def test_locked_without_passphrase_and_env_unlocks(mem, monkeypatch):
    keyvault.enable(mem, ПАРОЛЬ)
    mem.remember("запись")
    anchor.ensure_keys(mem)
    mid = next(iter(_ключи(mem)))
    keyvault.lock(mem)
    monkeypatch.delenv(keyvault.ENV, raising=False)
    with pytest.raises(keyvault.Locked):
        anchor.key_for(mem, mid)
    monkeypatch.setenv(keyvault.ENV, ПАРОЛЬ)
    assert len(anchor.key_for(mem, mid)) == 32


def test_wrong_passphrase_is_caught_before_use(mem):
    keyvault.enable(mem, ПАРОЛЬ)
    keyvault.lock(mem)
    with pytest.raises(keyvault.WrongPassphrase):
        keyvault.unlock(mem, "не тот пароль")
    assert not getattr(mem, "_kek", None), "неверный пароль не оставляет ключа в памяти"


def test_wrapped_key_cannot_be_moved_to_another_record(mem):
    keyvault.enable(mem, ПАРОЛЬ)
    mem.remember("первая запись")
    mem.remember("вторая запись, совсем о другом")
    anchor.ensure_keys(mem)
    (a, ref_a), (b, _) = list(_ключи(mem).items())[:2]
    mem.store.execute("UPDATE anchor_key SET key_ref = ? WHERE memory_id = ?", (ref_a, b))
    with pytest.raises(keyvault.KeyVaultError):
        anchor.key_for(mem, b)
    assert len(anchor.key_for(mem, a)) == 32


def test_protect_existing_leaves_no_plain_key_in_the_file(mem, tmp_path):
    mem.remember("старая запись до защиты")
    mem.remember("ещё одна старая запись")
    anchor.ensure_keys(mem)
    старые = _ключи(mem)
    assert all(not v.startswith("w1:") for v in старые.values()), "до защиты ключи открыты (прежнее поведение)"
    plain_bytes = {mid: bytes.fromhex(v) for mid, v in старые.items()}

    итог = keyvault.protect_existing(mem, ПАРОЛЬ)
    assert итог == {"включена_сейчас": True, "завёрнуто": 2, "открытых_осталось": 0}
    for mid, v in _ключи(mem).items():
        assert v.startswith("w1:")
        assert anchor.key_for(mem, mid) == plain_bytes[mid], "ключ тот же — шифротексты в Arweave читаются"

    mem.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    файлы = [tmp_path / "t.db", tmp_path / "t.db-wal"]
    сырьё = b"".join(f.read_bytes() for f in файлы if f.exists())
    for hex_key in старые.values():
        assert hex_key.encode() not in сырьё, "открытая копия ключа осталась в файле базы"


def test_protect_twice_is_harmless_and_checks_passphrase(mem):
    mem.remember("запись")
    anchor.ensure_keys(mem)
    keyvault.protect_existing(mem, ПАРОЛЬ)
    keyvault.lock(mem)
    assert keyvault.protect_existing(mem, ПАРОЛЬ)["завёрнуто"] == 0
    keyvault.lock(mem)
    with pytest.raises(keyvault.WrongPassphrase):
        keyvault.protect_existing(mem, "чужой пароль")


def test_revoke_still_destroys_wrapped_key(mem):
    keyvault.enable(mem, ПАРОЛЬ)
    mem.remember("то, что человек попросил забыть")
    anchor.ensure_keys(mem)
    mid = next(iter(_ключи(mem)))
    assert mem.revoke(mid)
    assert anchor.key_for(mem, mid) is None
    assert _ключи(mem)[mid] == anchor.DESTROYED


def test_rekey_keeps_keys_and_old_passphrase_stops_working(mem):
    mem.remember("запись один")
    mem.remember("запись два, о другом")
    anchor.ensure_keys(mem)
    keyvault.protect_existing(mem, ПАРОЛЬ)
    до = {mid: anchor.key_for(mem, mid) for mid in _ключи(mem)}
    assert keyvault.rekey(mem, ПАРОЛЬ, "новый пароль") == 2
    keyvault.lock(mem)
    with pytest.raises(keyvault.WrongPassphrase):
        keyvault.unlock(mem, ПАРОЛЬ)
    keyvault.unlock(mem, "новый пароль")
    assert {mid: anchor.key_for(mem, mid) for mid in _ключи(mem)} == до


def test_old_database_without_vault_works_as_before(mem):
    mem.remember("запись в базе без защиты")
    anchor.ensure_keys(mem)
    mid, ref = next(iter(_ключи(mem).items()))
    assert not keyvault.is_enabled(mem)
    assert anchor.key_for(mem, mid) == bytes.fromhex(ref)


def test_empty_passphrase_rejected(mem):
    with pytest.raises(keyvault.KeyVaultError):
        keyvault.enable(mem, "")


def test_protect_existing_400_keys_no_residue_in_free_pages(mem, tmp_path):
    """На двух записях SQLite переписывает страницу целиком, и утечку не видно.
    На 400 ключах без VACUUM в свободных страницах остаётся ~1/6 открытых ключей
    (замер 08.10.2026: 66 из 400) — этот тест падает, если VACUUM убрать."""
    import secrets
    from padam.store import now_iso
    with mem.store.conn:
        for i in range(400):
            mem.store.conn.execute(
                "INSERT INTO anchor_key (memory_id, key_ref, shard_count, threshold, created_at) VALUES (?, ?, 1, 1, ?)",
                (f"id{i}", secrets.token_bytes(32).hex(), now_iso()))
    mem.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    старые = list(_ключи(mem).values())
    assert keyvault.protect_existing(mem, ПАРОЛЬ)["завёрнуто"] == 400
    сырьё = b"".join(p.read_bytes() for p in tmp_path.iterdir() if p.name.startswith("t.db"))
    assert sum(k.encode() in сырьё for k in старые) == 0
