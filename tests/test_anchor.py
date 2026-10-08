"""Тесты L3: ключ на запись, дерево Меркла, пакет для Arweave, корень в Solana.

Сеть здесь не трогается: Arweave и Solana подменены поддельными функциями.
Живой прогон — отдельной командой `padam l3` (см. README).
"""
import base64
import hashlib
import json

import pytest

from padam import anchor
from padam.memory import Memory
from padam.store import Store


@pytest.fixture
def mem(tmp_path):
    m = Memory(user_id="test", store=Store(tmp_path / "t.db"))
    anchor.ensure_schema(m)
    yield m
    m.close()


def _ids(mem):
    return [r["id"] for r in mem.store.query(
        "SELECT id FROM memory WHERE status='active' ORDER BY created_at, id")]


def _fake(calls):
    def up(payload, tags):
        calls["payload"] = payload
        calls["tags"] = tags
        return "AR_TX_" + hashlib.sha256(payload).hexdigest()[:10]

    def anc(memo):
        calls["memo"] = memo
        return "SIG_" + str(len(calls)), 4242
    return up, anc


# --- Меркл ---------------------------------------------------------------

def test_merkle_known_vector():
    a, b, c = (anchor.leaf_record(x) for x in (b"a", b"b", b"c"))
    # три листа: ((a,b), c) — нечётный c поднимается без пары
    assert anchor.merkle_root([a, b, c]) == anchor.node(anchor.node(a, b), c)
    assert anchor.merkle_root([a]) == a


@pytest.mark.parametrize("n", list(range(1, 18)))
def test_proof_every_leaf(n):
    leaves = [anchor.leaf_record(bytes([i])) for i in range(n)]
    root = anchor.merkle_root(leaves)
    for i in range(n):
        assert anchor.verify_proof(leaves[i], anchor.merkle_proof(leaves, i), root)


def test_proof_rejects_foreign_leaf():
    leaves = [anchor.leaf_record(bytes([i])) for i in range(5)]
    root = anchor.merkle_root(leaves)
    fake = anchor.leaf_record(b"\xff")
    assert not anchor.verify_proof(fake, anchor.merkle_proof(leaves, 2), root)


def test_domain_separation():
    # лист записи и лист забвения не подделать друг под друга
    assert anchor.leaf_record(b"AIFA-FORGET|x|t") != anchor.leaf_forget("x", "t")


def test_empty_tree_refused():
    with pytest.raises(ValueError):
        anchor.merkle_root([])


# --- шифрование ----------------------------------------------------------

def test_encrypt_roundtrip_and_wrong_key():
    k1, k2 = bytes(32), bytes([1]) * 32
    blob = anchor.encrypt("секрет", k1)
    assert anchor.decrypt(blob, k1) == "секрет"
    with pytest.raises(Exception):
        anchor.decrypt(blob, k2)


def test_every_record_gets_own_key(mem):
    mem.remember("кофе по утрам без сахара")
    mem.remember("сервер переехал во Франкфурт")
    assert anchor.ensure_keys(mem) == 2
    keys = [r["key_ref"] for r in mem.store.query("SELECT key_ref FROM anchor_key")]
    assert len(set(keys)) == 2 and all(len(k) == 64 for k in keys)
    assert anchor.ensure_keys(mem) == 0, "повторно ключи не выдаются"


# --- прогон L3 -----------------------------------------------------------

def test_run_l3_marks_records_and_bundle_has_no_plaintext(mem):
    mem.remember("пароль от сейфа — 4417")
    mem.remember("любимый цвет — синий")
    calls = {}
    up, anc = _fake(calls)
    rep = anchor.run_l3(mem, uploader=up, anchorer=anc)
    assert rep["status"] == "anchored" and rep["records"] == 2 and rep["forgets"] == 0
    assert "4417" not in calls["payload"].decode() and "синий" not in calls["payload"].decode()
    assert calls["memo"].startswith(anchor.MEMO_PREFIX + " root=" + rep["root"])
    assert all(r["anchor_tx"] == rep["solana_sig"] for r in mem.store.query(
        "SELECT anchor_tx FROM memory WHERE status='active'"))
    # пакет независимо сходится с корнем в заметке
    v = anchor.verify_bundle(calls["payload"], calls["memo"])
    assert v["ok"] and v["records"] == 2


def test_second_run_only_new(mem):
    mem.remember("первый факт про погоду в Манте")
    calls = {}
    up, anc = _fake(calls)
    anchor.run_l3(mem, uploader=up, anchorer=anc)
    assert anchor.run_l3(mem, uploader=up, anchorer=anc)["status"] == "nothing_new"
    mem.remember("второй факт про рыбный рынок")
    rep = anchor.run_l3(mem, uploader=up, anchorer=anc)
    assert rep["records"] == 1


def test_revoke_destroys_key_and_forget_is_anchored(mem):
    mem.remember("адрес, который надо забыть")
    calls = {}
    up, anc = _fake(calls)
    anchor.run_l3(mem, uploader=up, anchorer=anc)
    bundle = json.loads(calls["payload"])
    mid = bundle["records"][0]["id"]
    blob = base64.b64decode(bundle["records"][0]["data"])
    key = anchor.key_for(mem, mid)
    assert anchor.decrypt(blob, key) == "адрес, который надо забыть"

    assert mem.revoke(mid)
    assert anchor.key_for(mem, mid) is None, "ключ затёрт физически"
    row = mem.store.one("SELECT key_ref FROM anchor_key WHERE memory_id=?", (mid,))
    assert row["key_ref"] == anchor.DESTROYED

    rep = anchor.run_l3(mem, uploader=up, anchorer=anc)
    assert rep["forgets"] == 1 and rep["records"] == 0
    v = anchor.verify_bundle(calls["payload"], calls["memo"])
    assert v["ok"] and v["forgets"] == 1
    assert anchor.run_l3(mem, uploader=up, anchorer=anc)["status"] == "nothing_new"


def test_dry_run_touches_nothing(mem):
    mem.remember("проба без отправки")
    rep = anchor.run_l3(mem, dry_run=True)
    assert rep["status"] == "dry_run"
    assert mem.store.one("SELECT COUNT(*) c FROM l3_anchor")["c"] == 0


def test_paid_size_refused(mem, monkeypatch):
    monkeypatch.setattr(anchor, "TURBO_FREE_LIMIT", 10)
    mem.remember("длинная запись, которая превысит маленький порог")
    with pytest.raises(RuntimeError):
        anchor.run_l3(mem, uploader=lambda p, t: "x", anchorer=lambda m: ("s", 1))


def test_mainnet_needs_explicit_name():
    with pytest.raises(ValueError):
        anchor.solana_memo("x", "нет_файла.json", network="main")


def test_no_receipt_for_never_anchored(mem):
    mem.remember("запись, которую забыли до отправки")
    mid = mem.store.one("SELECT id FROM memory")["id"]
    anchor.ensure_keys(mem)
    assert mem.revoke(mid)
    assert anchor.key_for(mem, mid) is None
    # в цепи этой записи нет — ни записи, ни квитанции отправлять нечего
    assert anchor.run_l3(mem, dry_run=True)["status"] == "nothing_new"


def test_superseded_after_anchor_not_resent(mem):
    calls = {}
    up, anc = _fake(calls)
    mem.remember("тариф Spark стоит 15 долларов")
    anchor.run_l3(mem, uploader=up, anchorer=anc)
    mem.remember("тариф Spark теперь стоит 20 долларов")
    rep = anchor.run_l3(mem, uploader=up, anchorer=anc)
    # уходит только новая версия; старая уже закреплена и остаётся в истории
    assert rep["status"] == "anchored" and rep["records"] == 1 and rep["forgets"] == 0
