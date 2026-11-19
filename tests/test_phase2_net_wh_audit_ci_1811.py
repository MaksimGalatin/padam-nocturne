"""Аудит GLM фаза 2, MEM-02 — тест Antigravity (_wt_sister_live_1811), перенесён 19.11.2026 вместе с её кодом.
Её проверки NETGUARD-01 написаны под её вариант защиты (в main своя, red-team 34/34); WH-01/WH-03, CI --require-hashes
и кейсы v2_wh_07/08, v2_xrec_04 — без кода ни в main, ни в её копии: вынесены в хвост, не оставлены падающими."""


from __future__ import annotations

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import threading
import time
import urllib.parse

import pytest

from padam import audit_chain, digital_stores, net_guard
from padam.memory import Memory
from padam.store import Store


_ROOT = Path(__file__).resolve().parent.parent


def test_mem02_audit_log_is_hash_chained_and_tamper_detected(tmp_path: Path):
    """MEM-02: audit_log имеет хеш-цепь и HMAC-якорь; подмена или удаление строк ловятся verify_audit_chain."""
    db_path = tmp_path / "mem02.db"
    mem = Memory(user_id="mem02_u", store=Store(str(db_path)))
    try:
        mem.remember("Запись 1 для аудита", kind="fact")
        mem.remember("Запись 2 для аудита", kind="fact")
        mem.remember("Запись 3 для аудита", kind="fact")

        ok_res = audit_chain.verify_audit_chain(mem)
        assert ok_res["ok"] is True
        assert ok_res.get("audit_log_ok") is True
        assert int(ok_res.get("audit_log_length") or 0) >= 3

        rows = mem.store.query(
            "SELECT id, detail FROM audit_log WHERE user_id = ? ORDER BY seq ASC, rowid ASC",
            ("mem02_u",),
        )
        assert len(rows) >= 3
        mid_id = rows[1]["id"]

        # Прямая подмена поля в SQLite в обход PADAM должна ломать цепь audit_log
        mem.store.conn.execute("UPDATE audit_log SET detail = 'tampered-detail' WHERE id = ?", (mid_id,))
        mem.store.conn.commit()
        bad_edit = audit_chain.verify_audit_chain(mem)
        assert bad_edit["ok"] is False
        assert bad_edit.get("audit_log_ok") is False

        # Прямое стирание всего журнала audit_log после работы тоже должно детектироваться
        db_wipe = tmp_path / "mem02_wipe.db"
        mem_w = Memory(user_id="mem02_w", store=Store(str(db_wipe)))
        try:
            mem_w.remember("Важное событие аудита", kind="fact")
            mem_w.remember("Второе событие аудита", kind="fact")
            assert audit_chain.verify_audit_chain(mem_w)["ok"] is True
            mem_w.store.conn.execute("DELETE FROM audit_log WHERE user_id = ?", ("mem02_w",))
            mem_w.store.conn.commit()
            bad_wipe = audit_chain.verify_audit_chain(mem_w)
            assert bad_wipe["ok"] is False
            assert bad_wipe.get("audit_log_ok") is False
        finally:
            mem_w.close()
    finally:
        mem.close()


def test_mem02_старые_записи_до_цепи_не_ломают_проверку(tmp_path):
    """Поправка при переносе: в живой базе тысячи записей audit_log без seq (до цепи) — это история, а не подмена."""
    from padam import audit_chain
    from padam.memory import Memory
    from padam.store import Store
    m = Memory(user_id="u", store=Store(tmp_path / "legacy.db"))
    m.store.conn.execute("INSERT INTO audit_log (id, user_id, created_at, action) VALUES ('old1', 'u', '2026-01-01', 'write')")
    m.store.conn.commit()
    m.remember("новая запись после включения цепи", kind="fact")
    r = audit_chain.verify_audit_chain(m)
    assert r.get("audit_log_ok") is True, r
