"""0.4.4: поиск ближайшей записи при сохранении — матрицей вместо цикла, тот же результат.

Замер 09.11.2026 (benchmarks/scale): каждая запись сравнивалась со всеми сохранёнными по одной в цикле Python,
и запись 10 000 реплик шла дольше 25 минут. Новый способ обязан выбирать ту же запись с той же близостью.
"""

import random

import numpy as np

from padam import embeddings
from padam.memory import Memory
from padam.store import Store, pack, unpack

СЛОВА = ("billing deploy invoice postgres sprint release tea garden lisbon sister meeting budget server "
         "memory backup report contract design album song radio map audit school river city train").split()


def _как_прежде(m, vec, kind, scope):
    rows = m.store.query("""SELECT id, content, embedding FROM memory WHERE user_id = ? AND scope = ? AND kind = ?
                            AND status = 'active' AND embedding IS NOT NULL""", (m.user_id, scope, kind))
    best = None
    for r in rows:
        sim = embeddings.cosine(vec, unpack(r["embedding"]))
        if best is None or sim > best[2]:
            best = (r["id"], r["content"], sim)
    return best


def test_matrix_search_matches_the_old_loop(tmp_path):
    rnd = random.Random(7)
    m = Memory(user_id="n", store=Store(tmp_path / "m.db"))
    for i in range(400):
        m.remember(f"note {i}: " + " ".join(rnd.choice(СЛОВА) for _ in range(rnd.randint(5, 25))), kind="event")
    # Записи с вектором другой модели (другая размерность) — у них близость 0, как и прежде.
    чужие = [r["id"] for r in m.store.query("SELECT id FROM memory WHERE kind='event' LIMIT 5")]
    for rid in чужие:
        m.store.execute("UPDATE memory SET embedding = ? WHERE id = ?", (pack(np.ones(256, dtype=np.float32) / 16), rid))
    for _ in range(300):
        vec = embeddings.embed(" ".join(rnd.choice(СЛОВА) for _ in range(rnd.randint(2, 10))))
        старый, новый = _как_прежде(m, vec, "event", "global"), m._nearest_active(vec, "event", "global")
        assert новый[0] == старый[0] and новый[1] == старый[1]
        assert abs(новый[2] - старый[2]) < 1e-6
    assert m._nearest_active(embeddings.embed("x"), "identity", "global") is None
    m.close()


def test_entity_cache_keeps_results_and_forgets_with_the_record(tmp_path, monkeypatch):
    """0.4.4: сущности записей разбираются один раз — выдача та же, а забытая запись уходит и из кэша."""
    from padam import retrieval
    rnd = random.Random(5)
    m = Memory(user_id="e", store=Store(tmp_path / "m.db"))
    for i in range(300):
        m.remember(f"ticket INV-{1000 + i} " + " ".join(rnd.choice(СЛОВА) for _ in range(10)), kind="event")
    вопросы = [f"INV-{1000 + rnd.randint(0, 299)} " + rnd.choice(СЛОВА) for _ in range(40)]
    с_кэшем = [[(r.id, round(r.score, 12)) for r in m.recall(в, limit=10)] for в in вопросы]
    monkeypatch.setattr(Memory, "_сущности_записи", lambda self, rid, content: retrieval.entities(content or ""))
    без_кэша = [[(r.id, round(r.score, 12)) for r in m.recall(в, limit=10)] for в in вопросы]
    assert [[i for i, _ in x] for x in с_кэшем] == [[i for i, _ in x] for x in без_кэша]
    monkeypatch.undo()
    жертва = m.recall(вопросы[0], limit=1)[0].id
    assert жертва in m._сущности
    m.revoke(жертва)
    assert жертва not in m._сущности
    m.close()


def test_vector_cache_never_drifts_from_the_database(tmp_path):
    """Кэш векторов сверяется с базой после любых изменений: своих вставок, смены статуса, отзыва,
    и записи из ДРУГОГО соединения (так одновременно работают CLI и MCP-сервер)."""
    rnd = random.Random(11)
    путь = tmp_path / "m.db"
    m = Memory(user_id="n", store=Store(путь))
    другой = Memory(user_id="n", store=Store(путь))

    def сверить():
        for _ in range(20):
            vec = embeddings.embed(" ".join(rnd.choice(СЛОВА) for _ in range(rnd.randint(2, 8))))
            старый, новый = _как_прежде(m, vec, "event", "global"), m._nearest_active(vec, "event", "global")
            assert (старый is None) == (новый is None)
            if старый:
                # Из почти равных (разница в последнем знаке float32) любая — верный ответ: близость выбранной
                # записи, посчитанная прежней функцией, обязана быть максимальной.
                её = m.store.one("SELECT embedding FROM memory WHERE id=?", (новый[0],))["embedding"]
                assert abs(embeddings.cosine(vec, unpack(её)) - старый[2]) < 1e-6
                assert abs(новый[2] - старый[2]) < 1e-6

    for i in range(150):
        m.remember(f"item {i} " + " ".join(rnd.choice(СЛОВА) for _ in range(12)), kind="event")
    сверить()                                                     # кэш построен
    for i in range(30):                                           # свои вставки дописываются в кэш
        m.remember(f"more {i} " + " ".join(rnd.choice(СЛОВА) for _ in range(12)), kind="event")
        if i % 10 == 0:
            сверить()
    жертва = m.store.one("SELECT id FROM memory WHERE kind='event' AND status='active' LIMIT 1")["id"]
    m.store.execute("UPDATE memory SET status='superseded' WHERE id=?", (жертва,))
    сверить()                                                     # смена статуса — кэш перечитан
    другой.remember("from the other connection " + " ".join(rnd.choice(СЛОВА) for _ in range(12)), kind="event")
    сверить()                                                     # чужой коммит виден через data_version
    m.revoke(m.store.one("SELECT id FROM memory WHERE kind='event' AND status='active' LIMIT 1")["id"])
    сверить()
    другой.close()
    m.close()
