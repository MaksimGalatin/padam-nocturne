"""26.11.2026: /overview под частым опросом окна ПК не должен считаться заново на каждый запрос.

Поломка: на базе ~24 500 записей один подсчёт шёл дольше 60 с, окно спрашивало каждые 1,5 с,
каждый брошенный запрос доводился до конца в своём потоке — процессор 100 %, карточки «…».
"""
import threading
import time

from padam import api


class _Actor:
    role, subject, workspace_id = "owner", "owner", None


def test_parallel_requests_compute_once(monkeypatch):
    api._overview_cache.clear()
    calls = []

    def slow(m, actor):
        calls.append(1)
        time.sleep(0.3)
        return {"stats": {"active": len(calls)}}

    monkeypatch.setattr(api, "_overview_compute", slow)
    m = object()
    out = []
    ths = [threading.Thread(target=lambda: out.append(api._overview_cached(m, _Actor()))) for _ in range(20)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    assert len(calls) == 1
    assert len(out) == 20 and all(o["stats"]["active"] == 1 for o in out)


def test_stale_served_while_recompute_running(monkeypatch):
    api._overview_cache.clear()
    m = object()
    monkeypatch.setattr(api, "_overview_compute", lambda m, a: {"v": 1})
    assert api._overview_cached(m, _Actor())["v"] == 1
    gate = threading.Event()

    def slow(m, a):
        gate.wait(2)
        return {"v": 2}

    monkeypatch.setattr(api, "_overview_compute", slow)
    t = threading.Thread(target=lambda: api._overview_cached(m, _Actor(), fresh=True))
    t.start()
    time.sleep(0.1)
    t0 = time.monotonic()
    assert api._overview_cached(m, _Actor(), fresh=True)["v"] == 1  # не ждёт, отдаёт прежнее
    assert time.monotonic() - t0 < 0.5
    gate.set()
    t.join()
    assert api._overview_cached(m, _Actor())["v"] == 2


def test_ttl_expiry_recomputes(monkeypatch):
    api._overview_cache.clear()
    n = []
    monkeypatch.setattr(api, "_overview_compute", lambda m, a: (n.append(1), {"n": len(n)})[1])
    monkeypatch.setattr(api, "_OVERVIEW_TTL", 0.05)
    m = object()
    assert api._overview_cached(m, _Actor())["n"] == 1
    assert api._overview_cached(m, _Actor())["n"] == 1
    time.sleep(0.08)
    assert api._overview_cached(m, _Actor())["n"] == 2
