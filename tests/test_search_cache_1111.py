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


# --- 0.4.11: кэш векторов переживает «повтор» и «замену» --------------------------------------------------
# Замер 11.11.2026 (3 000 + 500 записей): кэш векторов перестраивался 14 раз — 12 после замены, 2 после повтора,
# каждый раз чтением всех векторов из базы. Теперь он правится на месте. Тест сверяет его с расчётом заново.

def _ближайший(m, вектор, kind, scope):
    return m._nearest_active(вектор, kind, scope)


def _ближайший_заново(m, вектор, kind, scope):
    кэш = m.__dict__.pop("_вкэш", None)
    try:
        return m._nearest_active(вектор, kind, scope)
    finally:
        m.__dict__.pop("_вкэш", None)
        if кэш is not None:
            m.__dict__["_вкэш"] = кэш


def _ключ(x):
    return None if x is None else (x[0], round(x[2], 9))


def test_кэш_векторов_после_повтора_и_замены_равен_расчёту_заново(tmp_path):
    from padam import embeddings
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    try:
        тексты = []
        for i, город in enumerate(["Manta", "Quito", "Cuenca", "Loja", "Ambato", "Ibarra"]):
            тексты += [f"The capital of the project is {город}",                 # замена предыдущей
                       f"Backup job {i} runs at night and keeps 30 copies",      # новая
                       "The team chose Postgres for billing"]                    # повтор после первого раза
        пробы = [embeddings.embed(t) for t in ("capital of the project", "backup job copies",
                                                "postgres billing", "nothing like this")]
        исходы = []
        for t in тексты:
            исход, _ = m.remember(t, kind="fact")
            исходы.append(исход)
            for v in пробы:
                assert _ключ(_ближайший(m, v, "fact", "global")) == _ключ(_ближайший_заново(m, v, "fact", "global"))
        assert исходы.count("superseded") >= 3 and исходы.count("duplicate") >= 3, исходы
        # список записей в кэше — тот же, что при построении с нуля (заменённых в нём нет)
        в_кэше = list(m._векторы("global", "fact", пробы[0].size)[0])
        m.__dict__.pop("_вкэш", None)
        assert в_кэше == list(m._векторы("global", "fact", пробы[0].size)[0])
        # заменённая запись не может быть «ближайшей действующей»
        best = _ближайший(m, пробы[0], "fact", "global")
        assert m.store.one("SELECT status FROM memory WHERE id=?", (best[0],))[0] == "active"
    finally:
        m.close()


def test_замена_не_перестраивает_кэш_векторов(tmp_path):
    from padam import embeddings
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    try:
        for i in range(20):
            m.remember(f"Service {i} listens on port {8000 + i}", kind="fact")
        m.remember("The capital of the project is Manta", kind="fact")
        _ближайший(m, embeddings.embed("capital"), "fact", "global")           # кэш заполнен
        было = id(next(iter(m.__dict__["_вкэш"].values()))[1])     # список id — тот же объект, если не перечитан
        исход, _ = m.remember("The capital of the project is Quito", kind="fact")
        assert исход == "superseded"
        assert id(next(iter(m.__dict__["_вкэш"].values()))[1]) == было, "кэш должен пережить замену"
        исход, _ = m.remember("Service 3 listens on port 8003", kind="fact")
        assert исход == "duplicate"
        assert id(next(iter(m.__dict__["_вкэш"].values()))[1]) == было, "кэш должен пережить повтор"
        assert next(iter(m.__dict__["_вкэш"].values()))[0] == m.store.stamp()
    finally:
        m.close()
