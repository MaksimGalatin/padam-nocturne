# -*- coding: utf-8 -*-
"""Дорожная карта Сестры 19.11.2026: B1 (журнал вызовов с trace_id, p95), N6 (учение восстановления),
N9 (учения на сбой: внедрение ошибок — память не теряет записи и не врёт об успехе)."""
import json
import sqlite3
import threading

import pytest

from padam import backup, observability, restore_drill
from padam.memory import Memory
from padam.store import Store


@pytest.fixture
def m(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_HOME", str(tmp_path / "home"))
    return Memory(user_id="u", store=Store(tmp_path / "m.db"))


# ---------- B1
def test_b1_журнал_вызова_без_аргументов_и_сводка_p95(m):
    for i in range(20):
        observability.log_call("padam_search", ok=True, duration_ms=10 + i, action="find")
    observability.log_call("padam_write", ok=False, duration_ms=300)
    s = observability.latency_summary()
    assert s["calls"] == 21 and s["errors"] == 1
    assert s["p95_ms"] >= 29 and s["target_p95_ms"] == 200
    строка = open(s["file"], encoding="utf-8").readline()
    rec = json.loads(строка)
    assert set(rec) >= {"trace_id", "tool", "duration_ms", "ok"} and "args" not in rec


def test_b1_выключатель(m, monkeypatch):
    monkeypatch.setenv("PADAM_OBS_LOG", "0")
    assert observability.log_call("x", ok=True, duration_ms=1) is None


# ---------- N6
def test_n6_учение_проходит_и_живая_база_не_меняется(m):
    for i in range(30):
        m.remember(f"факт номер {i} для учения", kind="fact")
    до = backup._canonical_records_sha256(m.store.conn, m.user_id)
    r = restore_drill.run_drill(m)
    assert r["ok"] is True and r["records_restored"] >= 30
    assert backup._canonical_records_sha256(m.store.conn, m.user_id) == до


def test_n6_порча_копии_ловится(m, monkeypatch):
    m.remember("запись, которую испортим в копии", kind="fact")
    настоящий = backup.restore_backup_bytes

    def испортить(memory, data, **kw):
        res = настоящий(memory, data, **kw)
        c = sqlite3.connect(str(kw["target_db_path"]))
        c.execute("UPDATE memory SET content = 'подмена'")
        c.commit(); c.close()
        return res
    monkeypatch.setattr(backup, "restore_backup_bytes", испортить)
    assert restore_drill.run_drill(m)["ok"] is False


# ---------- N9
def test_n9_сбой_посреди_atomic_не_оставляет_половины(m):
    m.store.conn.execute("CREATE TABLE IF NOT EXISTS t_chaos (k INTEGER NOT NULL)")
    m.store.conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        m.store.atomic([("INSERT INTO t_chaos (k) VALUES (1)", ()), ("INSERT INTO t_chaos (k) VALUES (NULL)", ())])
    assert m.store.one("SELECT COUNT(*) AS n FROM t_chaos")["n"] == 0


def test_n9_рой_потоков_со_сбоями_не_теряет_успешные_записи(m):
    ошибки, успешно = [], []
    замок = threading.Lock()

    def писать(n):
        for i in range(25):
            try:
                if i % 7 == 3:
                    raise RuntimeError("внедрённый сбой")
                rid = m.remember(f"поток {n} запись {i}", kind="fact")
                with замок:
                    успешно.append(rid)
            except RuntimeError:
                pass
            except Exception as exc:  # pragma: no cover
                ошибки.append(repr(exc))
    th = [threading.Thread(target=писать, args=(k,)) for k in range(6)]
    [t.start() for t in th]; [t.join() for t in th]
    assert not ошибки, ошибки[:2]
    есть = {r["id"] for r in m.store.query("SELECT id FROM memory WHERE user_id = ?", ("u",))}
    assert успешно and all(x[1] in есть for x in успешно), (len(успешно), len(есть))


def test_n9_заблокированная_база_даёт_понятную_ошибку_а_не_тихую_потерю(tmp_path):
    p = tmp_path / "lock.db"
    st = Store(p)
    чужой = sqlite3.connect(str(p), timeout=0.1)
    чужой.execute("BEGIN EXCLUSIVE")
    st.conn.execute("PRAGMA busy_timeout = 200")
    with pytest.raises(sqlite3.OperationalError):
        st.execute("INSERT INTO audit_log (user_id, action, created_at) VALUES ('u','x','t')")
    чужой.rollback(); чужой.close()


# ---------- N8
def test_n8_опись_данных_считает_записи_человека(m):
    from padam import privacy_inventory
    for i in range(3):
        m.remember(f"личный факт {i}", kind="fact")
    inv = privacy_inventory.inventory(m)
    mem_row = [t for t in inv["tables_with_your_data"] if t["table"] == "memory"]
    assert mem_row and mem_row[0]["rows"] == 3
    assert inv["leaves_this_computer_by_default"] == []
