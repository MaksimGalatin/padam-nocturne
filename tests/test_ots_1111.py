"""0.4.12: второй свидетель вечного слоя — штамп OpenTimestamps (Bitcoin). Без сети: календари подменены."""
import hashlib

import pytest

from padam import anchor
from padam.memory import Memory
from padam.store import Store

ots = pytest.importorskip("padam.ots")
pytest.importorskip("opentimestamps")
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation  # noqa: E402
from opentimestamps.core.timestamp import Timestamp  # noqa: E402


def _календарь(принятые):
    def submit(url, msg, timeout):
        принятые.append(url)
        ts = Timestamp(msg)
        ts.attestations.add(PendingAttestation(url))
        return ts
    return submit


def test_штамп_содержит_отпечаток_и_календари():
    данные = b"bundle bytes"
    принятые = []
    b = ots.stamp(hashlib.sha256(данные).digest(), calendars=("https://c1", "https://c2"), submit=_календарь(принятые))
    assert принятые == ["https://c1", "https://c2"]
    о = ots.info(b)
    assert о["digest"] == hashlib.sha256(данные).hexdigest()
    assert о["pending"] == ["https://c1", "https://c2"] and о["bitcoin_blocks"] == []
    assert ots.matches(b, данные) and not ots.matches(b, b"other")


def test_один_календарь_недоступен_штамп_есть_все_недоступны_ошибка():
    принятые = []
    ok = _календарь(принятые)

    def один_падает(url, msg, t):
        if url == "https://down":
            raise OSError("down")
        return ok(url, msg, t)
    b = ots.stamp(b"\x01" * 32, calendars=("https://down", "https://up"), submit=один_падает)
    assert ots.info(b)["pending"] == ["https://up"]
    with pytest.raises(ots.OtsError):
        ots.stamp(b"\x01" * 32, calendars=("https://down",), submit=один_падает)
    with pytest.raises(ots.OtsError):
        ots.stamp(b"short", submit=ok)


def test_созревание_даёт_номер_блока():
    b = ots.stamp(b"\x02" * 32, calendars=("https://c1",), submit=_календарь([]))

    def get(url, msg, t):
        ts = Timestamp(msg)
        ts.attestations.add(BitcoinBlockHeaderAttestation(965040))
        return ts
    стало, блоки = ots.upgrade(b, get=get)
    assert блоки == [965040] and стало != b
    assert ots.info(стало)["bitcoin_blocks"] == [965040]

    def ещё_нет(url, msg, t):
        raise OSError("pending")
    тот_же, блоков_нет = ots.upgrade(b, get=ещё_нет)
    assert тот_же == b and блоков_нет == []


@pytest.fixture
def mem(tmp_path):
    m = Memory(user_id="test", store=Store(tmp_path / "t.db"))
    anchor.ensure_schema(m)
    yield m
    m.close()


def _закрепление():
    up = lambda payload, tags: "AR_TX_1"           # noqa: E731
    anc = lambda memo: ("SIG_1", 4242)              # noqa: E731
    return up, anc


def test_закрепление_сохраняет_штамп_в_базе_и_рядом_с_пакетом(mem, tmp_path):
    mem.remember("The team chose Postgres for billing", kind="decision", origin="user")
    up, anc = _закрепление()
    увидел = []
    rep = anchor.run_l3(mem, uploader=up, anchorer=anc, save_dir=str(tmp_path / "l3"),
                        stamper=lambda d: (увидел.append(d), ots.stamp(d, calendars=("https://c1",),
                                                                        submit=_календарь([])))[1])
    assert rep["bitcoin_ots"] == "pending" and "ots_error" not in rep
    row = mem.store.one("SELECT id, ots, bundle_sha256 FROM l3_anchor")
    пакет = (tmp_path / "l3" / f"{row['id']}.json").read_bytes()
    assert увидел == [hashlib.sha256(пакет).digest()]               # штампуется ровно пакет из Arweave
    assert row["bundle_sha256"] == hashlib.sha256(пакет).hexdigest()
    assert ots.matches(bytes(row["ots"]), пакет)
    assert (tmp_path / "l3" / f"{row['id']}.json.ots").read_bytes() == bytes(row["ots"])


def test_сбой_штампа_не_отменяет_якорь(mem):
    mem.remember("Billing runs on Postgres", kind="fact", origin="user")
    up, anc = _закрепление()

    def сломан(d):
        raise ots.OtsError("ни один календарь не принял")
    rep = anchor.run_l3(mem, uploader=up, anchorer=anc, stamper=сломан)
    assert rep["status"] == "anchored" and rep["solana_sig"] == "SIG_1"
    assert "ни один календарь" in rep["ots_error"] and rep["bitcoin_ots"] is None
    assert mem.store.one("SELECT ots FROM l3_anchor")["ots"] is None


def test_старая_база_получает_столбец_штампа(tmp_path):
    m = Memory(user_id="test", store=Store(tmp_path / "old.db"))
    try:
        m.store.script(anchor.L3_SCHEMA)                 # как до 0.4.12: столбца ots нет
        assert "ots" not in {r[1] for r in m.store.query("PRAGMA table_info(l3_anchor)")}
        anchor.ensure_schema(m)
        anchor.ensure_schema(m)                          # повторный вызов не падает
        assert "ots" in {r[1] for r in m.store.query("PRAGMA table_info(l3_anchor)")}
    finally:
        m.close()
