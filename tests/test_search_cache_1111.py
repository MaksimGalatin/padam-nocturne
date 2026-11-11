"""0.4.10: кэш кандидатов поиска.

Замер 11.11.2026 на 10 000 записях: 68 % времени поиска уходило на SELECT, который при каждом поиске заново
читал и распаковывал все действующие записи. Кэш держит их до изменения базы. Эти тесты проверяют, что
итог поиска не меняется, а любое изменение базы — своё, чужого процесса, забывание — сразу видно.
"""
from padam.memory import Memory
from padam.store import Store


def _ids(recs):
    return [(r.id, round(r.score, 12)) for r in recs]


def _без_кэша(m, query, **kw):
    m.__dict__.pop("_ккэш", None)
    out = m.recall(query, **kw)
    m.__dict__.pop("_ккэш", None)
    return out


def test_итог_с_кэшем_равен_итогу_без_кэша(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    try:
        for i in range(60):
            m.remember(f"Note {i}: the billing service uses Postgres and deploys on Friday {i % 7}", kind="fact")
        for q in ("billing postgres", "deploys on friday", "note 17", "nothing like this here"):
            без = _без_кэша(m, q, limit=10)
            m.recall(q, limit=10)                      # прогрев кэша
            с = m.recall(q, limit=10)
            assert [r.id for r in с] == [r.id for r in без]
            assert m.__dict__.get("_ккэш"), "кэш должен заполниться"
    finally:
        m.close()


def test_счётчики_поиска_не_сбрасывают_кэш(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    try:
        m.remember("The team chose Postgres for billing", kind="decision")
        m.recall("postgres", limit=5)
        отметка = m.store.stamp()
        m.recall("postgres", limit=5)                  # пишет access_count и search_stats
        assert m.store.stamp() == отметка
        n = m.store.one("SELECT access_count FROM memory")[0]
        assert n == 2                                  # счётчики при этом записаны
    finally:
        m.close()


def test_новая_запись_и_правка_видны_сразу(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    try:
        m.remember("The team chose Postgres for billing", kind="decision")
        assert all("Redis" not in r.content for r in m.recall("redis cache layer", limit=5))
        m.remember("We added Redis as the cache layer", kind="decision")
        assert any("Redis" in r.content for r in m.recall("redis cache layer", limit=5))
    finally:
        m.close()


def test_запись_другого_процесса_видна_сразу(tmp_path):
    база = tmp_path / "общая.db"
    a = Memory(user_id="u", store=Store(база))
    b = Memory(user_id="u", store=Store(база))      # второе соединение — как второй процесс
    try:
        a.remember("The team chose Postgres for billing", kind="decision")
        a.recall("postgres", limit=5)                  # кэш у a заполнен
        b.remember("Kubernetes runs the staging cluster", kind="fact")
        assert any("Kubernetes" in r.content for r in a.recall("kubernetes staging", limit=5))
    finally:
        a.close()
        b.close()


def test_забытое_уходит_из_кэша(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    try:
        _, rid = m.remember("Office door code is 4512", kind="fact", origin="user")
        assert any("4512" in r.content for r in m.recall("office door code", limit=5))
        assert m.revoke(rid)                          # то, что делает `padam forget`
        # сразу после забывания, ещё до следующего поиска, текста нет и в памяти процесса
        for запись in m.__dict__.get("_ккэш", {}).values():
            assert all("4512" not in (r["content"] or "") for r in запись[2])
        assert all("4512" not in (r.content or "") for r in m.recall("office door code", limit=5))
    finally:
        m.close()
