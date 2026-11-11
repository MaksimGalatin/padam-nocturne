"""0.4.6: стратегия «точных идентификаторов» считала сущностью каждое слово от двух букв (re.IGNORECASE на шаблоне
аббревиатур), а встроенный вектор голосовал в слиянии наравне с настоящей моделью. Найдено 09.11.2026 сравнением с
базовой линией BM25 на LongMemEval (benchmarks/longmemeval/baselines/)."""

import pytest

from padam import retrieval
from padam.memory import Memory
from padam.store import Store


def test_function_words_are_not_entities():
    assert retrieval.entities("What is the name of the GTX card I bought in 2026-10-08 for my i7 build?") == {
        "2026-10-08", "gtx", "i7"}


@pytest.mark.parametrize("текст, есть", [
    ("Audit per WCAG and ADA for GALATIN", {"wcag", "ada", "galatin"}),
    ("Ключ задачи 01DAF7-8B0717, почта a.b@example.com", {"01daf7-8b0717", "a.b@example.com"}),
    ("модель llama3 и nomic-embed", {"llama3"}),
])
def test_real_identifiers_are_still_found(текст, есть):
    assert есть <= retrieval.entities(текст)


def test_ordinary_lowercase_words_are_not_entities():
    assert retrieval.entities("we talked about the weather and dinner plans") == set()


@pytest.fixture
def память(tmp_path, monkeypatch):
    monkeypatch.setattr("padam.config.EMBEDDER", "builtin")
    m = Memory(user_id="t", store=Store(tmp_path / "m.db"))
    for текст in ("Боевой сервер стоит во Франкфурте, резервный в Хельсинки",
                  "Кошка любит спать на диване после обеда",
                  "Отпуск запланирован на август, едем к морю",
                  "Для биллинга выбрали Postgres, а не MySQL"):
        m.remember(текст, kind="fact", origin="user")
    yield m
    m.close()


def test_russian_inflected_form_still_found_with_builtin(память):
    """Лексический поиск по основам держит падежи: «на каком сервере» находит «сервер»."""
    найдено = память.recall("на каком сервере работает сайт", limit=1)
    assert найдено and "Франкфурте" in найдено[0].content


def test_builtin_vector_does_not_vote_when_words_match(память, monkeypatch):
    увиденные = []
    исходная = retrieval.reciprocal_rank_fusion
    monkeypatch.setattr(retrieval, "reciprocal_rank_fusion",
                        lambda rankings, weights=None: увиденные.append(weights) or исходная(rankings, weights))
    память.recall("биллинг", limit=1)
    assert увиденные and увиденные[0]["semantic"] == retrieval.BUILTIN_SEMANTIC_WEIGHT == 0.0
    assert retrieval.DEFAULT_WEIGHTS["semantic"] == 1.0


def test_builtin_vector_is_the_fallback_when_nothing_matches(память):
    """Ни одного общего слова и идентификатора: поиск не пустой, его ведёт вектор (основы и пары слов)."""
    найдено = память.recall("серверная инфраструктура", limit=1)
    assert найдено, "запасной путь по вектору ничего не вернул"


def test_служебные_слова_не_тянут_поиск_1111(tmp_path):
    """0.4.12: «what / did / the / что / как» совпадают почти с каждой записью; в лексический запрос они не идут."""
    from padam.memory import Memory
    from padam.store import Store
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    try:
        for i in range(30):
            m.remember(f"What did the team do on day {i}? They did the same as always, what else", kind="event")
        m.remember("Billing moved to Postgres in March", kind="decision")
        top = m.recall("What did we decide about Postgres?", limit=3)
        assert top and "Postgres" in top[0].content
        # запрос из одних служебных слов не становится пустым
        assert m.recall("what did the", limit=3)
        # по-русски так же
        m.remember("Оплату перевели на Postgres в марте", kind="decision")
        assert any("Postgres" in r.content for r in m.recall("Что мы решили про Postgres?", limit=3))
    finally:
        m.close()
