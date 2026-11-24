"""Потолок расходов Vertex (слово Архитектора 24.11.2026): $30 в сутки из гранта и $0 сверх гранта."""
from __future__ import annotations

from padam import router

VX = router.ContourConfig(name="vertex_grant_after_local", url="https://vertex.test/v1", api_key="k",
                          model="m", timeout_s=5.0, enabled=True)
LOCAL = router.ContourConfig(name="local", url="http://127.0.0.1:11434/v1", api_key="",
                             model="llama", timeout_s=5.0, enabled=True)


def _router(calls: list[str], tokens: int):
    def fake_post(url, headers, payload, timeout_s):
        calls.append(url)
        return 200, {"choices": [{"message": {"role": "assistant", "content": "ok"}}],
                     "usage": {"total_tokens": tokens}}

    r = router.SovereignRouter(http_post_fn=fake_post)
    r.effective_contours = lambda **kw: [VX, LOCAL]   # Vertex первым — так видно, кто ответил
    return r


def test_vertex_stops_after_daily_cap(monkeypatch):
    monkeypatch.delenv("PADAM_VERTEX_DAILY_USD_CAP", raising=False)
    monkeypatch.delenv("PADAM_VERTEX_GRANT_ENDS", raising=False)
    monkeypatch.delenv("PADAM_VERTEX_USD_PER_1K", raising=False)
    calls: list[str] = []
    r = _router(calls, tokens=8_000_000)          # 8 млн токенов × $0.004/1K = $32 > $30
    st, d = r.chat_completions({"messages": [{"role": "user", "content": "first question"}]})
    assert st == 200 and d["_padam_router"]["active_contour"] == "vertex_grant_after_local"
    assert r.vertex_cost_today_usd >= 30
    st, d = r.chat_completions({"messages": [{"role": "user", "content": "second different question"}]})
    assert st == 200 and d["_padam_router"]["active_contour"] == "local"
    assert calls[-1].startswith("http://127.0.0.1")
    snap = r.status_snapshot()
    assert snap["vertex_daily_cap_usd"] == "30" and snap["vertex_cost_today_usd"] >= 30


def test_vertex_under_cap_keeps_working(monkeypatch):
    monkeypatch.delenv("PADAM_VERTEX_DAILY_USD_CAP", raising=False)
    monkeypatch.delenv("PADAM_VERTEX_GRANT_ENDS", raising=False)
    calls: list[str] = []
    r = _router(calls, tokens=1000)
    for q in ("one", "two two", "three three three"):
        st, d = r.chat_completions({"messages": [{"role": "user", "content": q}]})
        assert d["_padam_router"]["active_contour"] == "vertex_grant_after_local"


def test_vertex_off_after_grant_end_date(monkeypatch):
    monkeypatch.setenv("PADAM_VERTEX_GRANT_ENDS", "2020-01-01")
    calls: list[str] = []
    r = _router(calls, tokens=10)
    st, d = r.chat_completions({"messages": [{"role": "user", "content": "after grant"}]})
    assert d["_padam_router"]["active_contour"] == "local"
    assert not any("vertex.test" in u for u in calls)


def test_vertex_cap_zero_disables(monkeypatch):
    monkeypatch.setenv("PADAM_VERTEX_DAILY_USD_CAP", "0")
    monkeypatch.delenv("PADAM_VERTEX_GRANT_ENDS", raising=False)
    calls: list[str] = []
    r = _router(calls, tokens=10)
    st, d = r.chat_completions({"messages": [{"role": "user", "content": "cap zero"}]})
    assert d["_padam_router"]["active_contour"] == "local"


def test_new_day_resets_counter(monkeypatch):
    monkeypatch.delenv("PADAM_VERTEX_DAILY_USD_CAP", raising=False)
    monkeypatch.delenv("PADAM_VERTEX_GRANT_ENDS", raising=False)
    r = _router([], tokens=10)
    r._vertex_day = "2000-01-01"
    r.vertex_cost_today_usd = 999.0
    assert r._vertex_blocked() is False          # наступили новые сутки — счётчик обнулён
    assert r.vertex_cost_today_usd == 0.0


def test_stream_counts_vertex_spend(monkeypatch):
    monkeypatch.delenv("PADAM_VERTEX_DAILY_USD_CAP", raising=False)
    monkeypatch.delenv("PADAM_VERTEX_GRANT_ENDS", raising=False)
    monkeypatch.setenv("PADAM_VERTEX_USD_PER_1K", "1000")   # завышенная цена — один поток выбирает весь потолок

    def fake_stream(url, headers, payload, timeout_s):
        yield 'data: {"choices":[{"delta":{"content":"' + "x" * 200 + '"}}]}'
        yield "data: [DONE]"

    r = router.SovereignRouter(http_post_fn=lambda *a: (200, {}), http_stream_fn=fake_stream)
    r.effective_contours = lambda **kw: [VX, LOCAL]
    list(r.stream_chat_completions({"messages": [{"role": "user", "content": "stream"}]}))
    assert r.vertex_cost_today_usd >= 30
    assert r._vertex_blocked() is True
