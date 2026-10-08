"""Тесты ядра памяти."""

import math
from datetime import datetime, timezone, timedelta

import numpy as np
import pytest

from padam import config, embeddings
from padam.memory import Memory, decay, content_hash
from padam.store import Store, parse_ts


@pytest.fixture
def mem(tmp_path):
    m = Memory(user_id="test", store=Store(tmp_path / "t.db"))
    yield m
    m.close()


# --- эмбеддинги -------------------------------------------------------

def test_embed_deterministic():
    a = embeddings.embed("привет мир")
    b = embeddings.embed("привет мир")
    assert np.allclose(a, b), "одинаковый текст должен давать одинаковый вектор"


def test_embed_normalized():
    v = embeddings.embed("любой текст для проверки нормы")
    assert abs(np.linalg.norm(v) - 1.0) < 1e-5


def test_similar_texts_closer_than_unrelated():
    base = embeddings.embed("сканер доступности проверяет клавиатурный обход")
    close = embeddings.embed("клавиатурный обход проверяет сканер доступности сайта")
    far = embeddings.embed("рецепт борща со сметаной и чесноком")
    assert embeddings.cosine(base, close) > embeddings.cosine(base, far)


def test_empty_text_does_not_crash():
    v = embeddings.embed("")
    assert v.shape[0] == config.EMBED_DIM


# --- затухание --------------------------------------------------------

def test_preference_never_decays():
    long_ago = datetime.now(timezone.utc) - timedelta(days=3650)
    assert decay("preference", long_ago) == 1.0
    assert decay("identity", long_ago) == 1.0


def test_event_decays_faster_than_fact():
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    assert decay("event", week_ago) < decay("fact", week_ago)


def test_half_life_is_exact():
    """Через период полураспада вес должен быть ровно 0.5."""
    hl = config.HALF_LIFE_DAYS["fact"]
    t = datetime.now(timezone.utc) - timedelta(days=hl)
    assert abs(decay("fact", t) - 0.5) < 0.01


# --- запись -----------------------------------------------------------

def test_new_record_created(mem):
    outcome, mid = mem.remember("Сервер стоит в Манте", kind="fact")
    assert outcome == "created"
    assert mid


def test_identical_record_is_duplicate(mem):
    mem.remember("Токен называется GALATIN", kind="decision")
    outcome, _ = mem.remember("Токен называется GALATIN", kind="decision")
    assert outcome == "duplicate"


def test_duplicate_raises_confidence(mem):
    _, mid = mem.remember("Токен называется GALATIN", kind="decision")
    before = mem.store.one("SELECT confidence FROM memory WHERE id=?", (mid,))[0]
    mem.store.execute("UPDATE memory SET confidence=0.5 WHERE id=?", (mid,))
    mem.remember("Токен называется GALATIN", kind="decision")
    after = mem.store.one("SELECT confidence FROM memory WHERE id=?", (mid,))[0]
    assert after > 0.5


def test_contradiction_supersedes_old(mem):
    _, old = mem.remember("Тариф стоит 15 долларов", kind="decision")
    outcome, new = mem.remember(
        "Тариф больше не 15 долларов, теперь 20", kind="decision")
    assert outcome in ("superseded", "merged")

    old_row = mem.store.one("SELECT status, superseded_by FROM memory WHERE id=?",
                            (old,))
    assert old_row["status"] == "superseded"
    assert old_row["superseded_by"] == new

    new_row = mem.store.one("SELECT supersedes FROM memory WHERE id=?", (new,))
    assert new_row["supersedes"] == old


def test_superseded_not_returned_in_recall(mem):
    mem.remember("Тариф стоит 15 долларов", kind="decision")
    mem.remember("Тариф больше не 15 долларов, теперь 20", kind="decision")
    results = mem.recall("сколько стоит тариф", kind="decision")
    contents = " ".join(r.content for r in results)
    assert "теперь 20" in contents
    assert not any(r.content == "Тариф стоит 15 долларов" for r in results)


def test_nothing_is_ever_deleted(mem):
    mem.remember("Тариф стоит 15 долларов", kind="decision")
    mem.remember("Тариф больше не 15 долларов, теперь 20", kind="decision")
    total = mem.store.one("SELECT COUNT(*) FROM memory")[0]
    assert total == 2, "старая версия должна остаться в базе"


# --- поиск ------------------------------------------------------------

def test_recall_ranks_relevant_first(mem):
    mem.remember("Сервер: 16 ядер, 64 гигабайта памяти", kind="fact")
    mem.remember("Каталог радио содержит 530 оригинальных песен", kind="fact")
    top = mem.recall("сколько памяти на сервере", limit=1)
    assert top and "16 ядер" in top[0].content


def test_recall_respects_kind_filter(mem):
    mem.remember("Отвечать по-русски", kind="preference")
    mem.remember("Отвечать по-русски принято в проекте", kind="fact")
    only = mem.recall("язык ответа", kind="preference")
    assert all(r.kind == "preference" for r in only)


def test_recall_empty_store(mem):
    assert mem.recall("что угодно") == []


def test_score_explains_itself(mem):
    mem.remember("Сервер в Манте", kind="fact")
    r = mem.recall("сервер")[0]
    text = r.explain()
    assert "rrf=" in text and "decay=" in text
    assert "[" in text, "должны быть показаны стратегии, которые нашли запись"


# --- гибридный поиск --------------------------------------------------

def test_entity_match_finds_exact_identifier(mem):
    mem.remember("Биллинг-аккаунт 01DAF7-8B0717-3B1694 активен", kind="fact")
    mem.remember("Сервер работает нормально", kind="fact")
    top = mem.recall("01DAF7-8B0717-3B1694", limit=1)
    assert top and "01DAF7" in top[0].content


def test_lexical_finds_rare_word(mem):
    mem.remember("Каталог радио содержит 530 оригинальных песен", kind="fact")
    mem.remember("Сервер в Эквадоре с видеокартой", kind="fact")
    top = mem.recall("оригинальных песен", limit=1)
    assert top and "530" in top[0].content


def test_multiple_strategies_reported(mem):
    mem.remember("Токен GALATIN, эмиссия 10 миллиардов", kind="decision")
    r = mem.recall("GALATIN эмиссия")[0]
    assert len(r.strategies) >= 2, "запись должна найтись несколькими путями"


# --- подтверждение и опровержение -------------------------------------

def test_recall_does_not_confirm(mem):
    """Показ записи не делает её верной — свежесть не должна обновляться."""
    _, mid = mem.remember("Работает в компании X", kind="fact")
    old = mem.store.one(
        "SELECT last_confirmed_at FROM memory WHERE id=?", (mid,))[0]
    mem.store.execute(
        "UPDATE memory SET last_confirmed_at = '2020-01-01T00:00:00+00:00' "
        "WHERE id=?", (mid,))
    mem.recall("где работает")
    after = mem.store.one(
        "SELECT last_confirmed_at FROM memory WHERE id=?", (mid,))[0]
    assert after.startswith("2020"), "recall не должен обновлять подтверждение"


def test_recall_updates_last_seen(mem):
    _, mid = mem.remember("Запись для проверки просмотра", kind="fact")
    mem.store.execute(
        "UPDATE memory SET last_seen_at='2020-01-01T00:00:00+00:00' WHERE id=?",
        (mid,))
    mem.recall("запись проверки")
    seen = mem.store.one("SELECT last_seen_at FROM memory WHERE id=?", (mid,))[0]
    assert not seen.startswith("2020")


def test_confirm_refreshes_and_raises_confidence(mem):
    _, mid = mem.remember("Проверяемый факт", kind="fact")
    mem.store.execute(
        "UPDATE memory SET confidence=0.5, "
        "last_confirmed_at='2020-01-01T00:00:00+00:00' WHERE id=?", (mid,))
    assert mem.confirm(mid) is True
    row = mem.store.one(
        "SELECT confidence, last_confirmed_at FROM memory WHERE id=?", (mid,))
    assert row["confidence"] > 0.5
    assert not row["last_confirmed_at"].startswith("2020")


def test_refute_lowers_confidence_without_refreshing(mem):
    _, mid = mem.remember("Сомнительный факт", kind="fact")
    mem.store.execute(
        "UPDATE memory SET last_confirmed_at='2020-01-01T00:00:00+00:00' "
        "WHERE id=?", (mid,))
    mem.refute(mid)
    row = mem.store.one(
        "SELECT confidence, refuted_count, last_confirmed_at "
        "FROM memory WHERE id=?", (mid,))
    assert row["confidence"] < 1.0
    assert row["refuted_count"] == 1
    assert row["last_confirmed_at"].startswith("2020"), \
        "опровержение не должно освежать запись"


def test_repeated_refutation_archives(mem):
    _, mid = mem.remember("Факт, который опровергнут много раз", kind="fact")
    for _ in range(4):
        mem.refute(mid)
    status = mem.store.one("SELECT status FROM memory WHERE id=?", (mid,))[0]
    assert status == "archived"
    assert mem.recall("факт опровергнут") == []


# --- битемпоральность -------------------------------------------------

def test_supersede_closes_validity_interval(mem):
    _, old = mem.remember("Тариф стоит 15 долларов", kind="decision")
    mem.remember("Тариф больше не 15, теперь 20 долларов", kind="decision")
    row = mem.store.one(
        "SELECT valid_from, valid_to FROM memory WHERE id=?", (old,))
    assert row["valid_from"] is not None
    assert row["valid_to"] is not None, \
        "у замещённой записи должен закрыться период истинности"


# --- отзыв ------------------------------------------------------------

def test_revoke_wipes_content_but_keeps_hash(mem):
    _, mid = mem.remember("Персональные данные клиента", kind="fact")
    original_hash = mem.store.one(
        "SELECT content_hash FROM memory WHERE id=?", (mid,))[0]

    assert mem.revoke(mid) is True

    row = mem.store.one(
        "SELECT content, embedding, status, content_hash FROM memory WHERE id=?",
        (mid,))
    assert row["content"] is None
    assert row["embedding"] is None
    assert row["status"] == "revoked"
    assert row["content_hash"] == original_hash, "хеш должен пережить отзыв"


def test_revoked_not_in_recall(mem):
    _, mid = mem.remember("Секретная строка про кактусы", kind="fact")
    mem.revoke(mid)
    assert mem.recall("кактусы") == []


def test_content_hash_stable():
    assert content_hash("abc") == content_hash("abc")
    assert content_hash("abc") != content_hash("abd")


# --- история версий ---------------------------------------------------

def test_timeline_returns_full_chain(mem):
    mem.remember("Запуск в сентябре", kind="decision")
    mem.remember("Запуск уже не в сентябре, а в октябре", kind="decision")
    _, third = mem.remember(
        "Запуск больше не в октябре, перенесён на ноябрь", kind="decision")

    chain = mem.timeline(third)
    assert len(chain) == 3
    assert "сентябре" in chain[0]["content"]
    assert "ноябрь" in chain[-1]["content"]


# --- сессии -----------------------------------------------------------

def test_same_session_when_continuing(mem):
    s1 = mem.current_session("обсуждаем сканер доступности и обход клавиатурой")
    s2 = mem.current_session("продолжаем про сканер доступности и обход")
    assert s1 == s2


def test_new_session_after_long_gap(mem):
    s1 = mem.current_session("первая тема разговора")
    old = (datetime.now(timezone.utc)
           - timedelta(hours=config.SESSION_GAP_HOURS + 1)).isoformat()
    mem.store.execute("UPDATE session SET last_active_at=? WHERE id=?", (old, s1))
    s2 = mem.current_session("первая тема разговора")
    assert s1 != s2


# --- статистика -------------------------------------------------------

def test_stats_counts_correctly(mem):
    mem.remember("Факт один", kind="fact")
    mem.remember("Правило: отвечать кратко", kind="preference")
    _, mid = mem.remember("Будет отозвано", kind="fact")
    mem.revoke(mid)

    s = mem.stats()
    assert s["active"] == 2
    assert s["revoked"] == 1
    assert s["by_kind"]["fact"] == 1
    assert s["by_kind"]["preference"] == 1

# --- защита размерности вектора ---------------------------------------

def test_empty_text_never_goes_to_ollama(monkeypatch):
    u"""Пустой текст обрабатывается встроенным методом, минуя модель.

    Ollama на пустой строке возвращает пустой список, и такой вектор
    уходил наружу размерности (0,) вместо EMBED_DIM. Ломалось молча:
    падал не embed, а те, кто ждал вектор фиксированной длины.
    """
    ходили = []

    def не_должно_вызываться(text):
        ходили.append(text)
        raise AssertionError("пустой текст не должен уходить в Ollama")

    monkeypatch.setattr(embeddings, "_check_ollama", lambda: True)
    monkeypatch.setattr(embeddings, "_ollama_embed", не_должно_вызываться)

    for пусто in ("", "   ", "\n\t "):
        v = embeddings.embed(пусто)
        assert v.shape[0] == config.EMBED_DIM
    assert ходили == []


def test_empty_vector_from_ollama_falls_back(monkeypatch):
    u"""Если модель вернула вектор нулевой длины — берём встроенный метод."""
    import numpy as _np

    monkeypatch.setattr(embeddings, "_check_ollama", lambda: True)
    monkeypatch.setattr(
        embeddings, "_ollama_embed",
        lambda text: _np.asarray([], dtype=_np.float32))

    v = embeddings.embed("непустой текст")
    assert v.shape[0] == config.EMBED_DIM
