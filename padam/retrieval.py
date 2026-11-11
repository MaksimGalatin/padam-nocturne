"""Гибридное извлечение.

Одна стратегия поиска всегда что-то упускает. Векторная не находит точных
совпадений — номер счёта, модель процессора, дату. Лексическая не понимает
переформулировок. Точное совпадение сущностей ловит идентификаторы, но
слепо к смыслу.

Здесь три стратегии работают параллельно, их результаты объединяются
методом обратного ранга (RRF): запись, попавшая в верх нескольких списков,
поднимается выше той, что заняла первое место в одном.
"""

from __future__ import annotations

import re
from collections import defaultdict

import numpy as np

from . import embeddings

# --- сущности: то, что нужно находить точно ---------------------------

_ENTITY_PATTERNS = [
    r"\b[A-Z]{2,}[A-Z0-9\-]*\b",          # GALATIN, GTX, ADA, WCAG
    r"\b[a-z]+\d[\w\-]*\b",                # i7, llama3, nomic-embed
    r"\b\d{4}-\d{2}-\d{2}\b",              # 2026-10-08
    r"\b\d[\d\s.,]*\d\b",                  # 14700, 10 000, 44,919
    r"\b[\w.\-]+@[\w.\-]+\b",              # почта
    r"https?://\S+",                       # ссылки
    r"\b[0-9A-F]{4,}-[0-9A-F\-]+\b",       # идентификаторы вроде 01DAF7-8B0717
]
# 0.4.6: аббревиатуры (первый шаблон) — только заглавными. С общим re.IGNORECASE «[A-Z]{2,}» совпадал с любым
# словом от двух букв, и «точные идентификаторы» считали совпадение всех слов подряд, служебных тоже (the, is,
# what) — с весом 1,5. Найдено 09.11.2026 сравнением с базовой линией BM25 на LongMemEval: поиск проигрывал ей
# 91,7 % против 96,0 %. Остальные шаблоны регистр по-прежнему не различают.
_ENTITY_RE = re.compile("(?-i:" + _ENTITY_PATTERNS[0] + ")|" + "|".join(_ENTITY_PATTERNS[1:]), re.IGNORECASE)


def entities(text: str) -> set[str]:
    """Идентификаторы, которые должны совпадать буквально."""
    found = {m.group(0).strip(" .,").lower() for m in _ENTITY_RE.finditer(text)}
    return {e for e in found if len(e) >= 2}


# --- второй проход: слова обратной связи --------------------------------

_СЛОВО_RE = re.compile(r"[^\W\d_][\w'-]{3,}")
_СТОП_СЛОВА = frozenset("""
about above after again against also among another anything because been before being between both could does
doing done down during each either else even ever every from further have having here hers herself himself into
itself just like made make many might more most much must myself never only other ours ourselves over same should
some such than that their theirs them themselves then there these they this those through under until upon very
want were what when where which while whom whose will with within without would your yours yourself yourselves
assistant user really thing things think know going sure help great good well need
этот этого этой этом эти этих того тому чтобы только когда тоже также потому более менее очень можно нужно было
были была будет будут есть если который которая которое которые которых свой своя своё свои своих себя тебя меня
него неё ними всех весь вся всё ещё уже даже между после перед через здесь тогда теперь просто ассистент
пользователь""".split())


def feedback_terms(query: str, contents: list[str], need: int = 2, most: int = 8) -> list[str]:
    """Слова, общие хотя бы для `need` из найденных записей и которых нет в запросе, — не больше `most`.

    Псевдо-обратная связь: первые найденные записи подсказывают, как ещё в памяти говорят о том же, и второй
    поиск с этими словами добирает беседы, где нет слов вопроса. Слово считается один раз на запись;
    из равных по частоте раньше идёт то, что встретилось раньше (итог воспроизводим)."""
    вопрос = {w.lower() for w in _СЛОВО_RE.findall(query or "")}
    счёт: dict[str, int] = {}
    for text in contents:
        for w in dict.fromkeys(w.lower() for w in _СЛОВО_RE.findall(text or "")):
            if w not in _СТОП_СЛОВА and w not in вопрос:
                счёт[w] = счёт.get(w, 0) + 1
    частые = sorted(((c, i, w) for i, (w, c) in enumerate(счёт.items()) if c >= need), key=lambda x: (-x[0], x[1]))
    return [w for _, _, w in частые[:most]]


# --- обратный ранг ----------------------------------------------------

RRF_K = 60          # сглаживание: чем больше, тем меньше вес первых мест


def reciprocal_rank_fusion(rankings: dict[str, list[str]],
                           weights: dict[str, float] | None = None
                           ) -> dict[str, float]:
    """rankings: {имя стратегии: [id по убыванию релевантности]}

    Возвращает {id: суммарный балл}. Формула: сумма по стратегиям от
    weight / (K + позиция). Запись, устойчиво попадающая в верх разных
    списков, обгоняет ту, что лидирует в одном.
    """
    weights = weights or {}
    scores: dict[str, float] = defaultdict(float)
    for strategy, ids in rankings.items():
        w = weights.get(strategy, 1.0)
        for pos, rid in enumerate(ids):
            scores[rid] += w / (RRF_K + pos + 1)
    return dict(scores)


# --- стратегии --------------------------------------------------------

def rank_semantic(query_vec: np.ndarray, rows: list, limit: int) -> list[str]:
    """Векторная близость. Понимает переформулировки, слепа к цифрам."""
    # 0.4.4: одно матричное умножение вместо cosine() на каждую запись (285 тысяч вызовов на 30 запросов при
    # 10 000 записях). Тот же итог: близость = clip(a·b, -1, 1), векторы другой размерности не участвуют
    # (cosine давал им 0, а 0 сюда не проходил), порядок при равенстве — по номеру записи, как прежде.
    if query_vec is None or not query_vec.size:
        return []
    q = np.asarray(query_vec, dtype=np.float32)
    # 0.4.13: Memory отдаёт кандидатов с уже собранной матрицей (Кандидаты.матрица) — один раз на состояние базы.
    # Замер 11.11.2026 на 10 000 записях: np.stack на каждом поиске — 0,88 из 2,70 с на 30 поисков (со вторым
    # проходом — дважды на поиск). Те же векторы, тот же порядок записей — итог тот же.
    матрица = getattr(rows, "матрица", None)
    if матрица is not None and матрица[0] == q.shape[0]:
        _, M, ids = матрица
        if not ids:
            return []
        sims = np.clip(M @ q, -1.0, 1.0)
    else:
        годные = [r for r in rows if r["_vec"] is not None and r["_vec"].shape == q.shape]
        if not годные:
            return []
        sims = np.clip(np.stack([r["_vec"] for r in годные]) @ q, -1.0, 1.0)
        ids = [r["id"] for r in годные]
    # 0.4.4: при равной близости — порядок сохранения записей, а не случайный UUID: иначе два прогона одного кода
    # давали разные числа LongMemEval (каждый пятый вопрос: 92,6 % против 91,5 %, найдено 09.11.2026).
    # 0.4.13: устойчивая сортировка numpy вместо sort по списку кортежей — тот же порядок, равные в исходном порядке.
    положительные = np.nonzero(sims > 0)[0]
    порядок = положительные[np.argsort(-sims[положительные], kind="stable")][:limit]
    return [ids[i] for i in порядок]


class Кандидаты(list):
    """Список кандидатов поиска с матрицей векторов: (размерность, матрица, id в порядке строк)."""
    матрица = None


_СЛУЖЕБНЫЕ = frozenset("""
a an the and or but if of to in on at by for from with about into over as is are was were be been being am do does
did done have has had having i me my mine we us our you your he him his she her it its they them their this that
these those what which who whom whose when where why how many much there here can could would should will shall may
might must not no yes so than then too very just also any some all each other such own same only
что как где когда это этот эта эти мой моя моё мои мне меня мы нас наш ты тебя твой вы вас ваш он она оно они его её
их был была было были быть есть для на в во по из от до за под над при про о об и или но а же ли не ни да нет так
то тот та те уже ещё сколько какой какая какие который которая которые
""".split())


def rank_lexical(store, user_id: str, scope: str, query: str,
                 limit: int, statuses: tuple[str, ...] = ("active",)) -> list[str]:
    """BM25 через FTS5. Промышленный лексический поиск, встроен в SQLite."""
    terms = [t for t in re.findall(r"\w+", query.lower()) if len(t) > 1]
    if not terms:
        return []
    # 0.4.12: служебные слова (what, did, the, my, что, как…) в OR-запросе совпадают почти с каждой записью, и BM25
    # считался для всей базы. Опыт 11.11.2026, LongMemEval-S, 470 вопросов с ответом: без них «нужная беседа в
    # пятёрке» 96,8 → 97,2 %, «все нужные в пятёрке» 83,0 → 84,0 %, на 376 ненастроенных вопросах лучше по всем
    # четырём мерам; поиск на 10 000 записей 46,4 → 24,6 мс (медиана). Запрос из одних служебных слов — как есть.
    значимые = [t for t in terms if t not in _СЛУЖЕБНЫЕ]
    if значимые:
        terms = значимые
    # 0.4.6: слово длиннее пяти букв ищется по основе — без двух последних букв, не короче пяти. Префикс «сервере»*
    # не находил «сервер», «серверы» — «сервере», и русский запрос в косвенном падеже проигрывал заметке со словом
    # «на» (найдено 09.11.2026 тестом tests/test_retrieval_0911.py). Окончания русских падежей и английских форм
    # (servers, planned) — одна-две буквы.
    terms = list(dict.fromkeys(t[:max(5, len(t) - 2)] if len(t) > 5 else t for t in terms))
    # OR по терминам: пусть BM25 сам взвесит редкие выше частых
    match = " OR ".join(f'"{t}"*' for t in terms)
    try:
        rows = store.query(
            f"""SELECT m.id FROM memory_fts f
               JOIN memory m ON m.rowid = f.rowid
               WHERE memory_fts MATCH ? AND m.user_id = ? AND m.scope = ?
                 AND m.status IN ({",".join("?" * len(statuses))})
               ORDER BY bm25(memory_fts) LIMIT ?""",
            (match, user_id, scope, *statuses, limit))
        return [r["id"] for r in rows]
    except Exception:
        return []


def rank_entity(query: str, rows: list, limit: int) -> list[str]:
    """Точное совпадение идентификаторов. Ловит то, что теряют оба выше."""
    q_ent = entities(query)
    if not q_ent:
        return []
    scored = []
    for r in rows:
        # 0.4.4: Memory передаёт уже разобранные сущности записи (_ents) — разбирать заново на каждый поиск дорого.
        ents = r["_ents"] if "_ents" in r else entities(r["content"] or "")
        overlap = q_ent & ents
        if overlap:
            scored.append((len(overlap), r["id"]))
    scored.sort(key=lambda x: x[0], reverse=True)       # ничьи — в порядке сохранения, см. rank_semantic
    return [rid for _, rid in scored[:limit]]


# --- компактная выдача ------------------------------------------------

COMPACT_HEAD = 700      # реплика человека / начало записи — целиком до этого предела
COMPACT_TAIL = 150      # ответ ассистента в записи-раунде — только начало


def compact_text(text: str, head: int = COMPACT_HEAD, tail: int = COMPACT_TAIL) -> str:
    """Короткий вид записи для выдачи «много записей сразу».

    Вопрос «сколько всего…» требует фактов из многих разговоров, а длинные
    записи-раунды («user: … assistant: …») съедают место: в тот же объём
    влезает втрое меньше записей. Факт обычно сидит в реплике человека,
    поэтому она остаётся целиком (до head), а ответ ассистента — начало.
    Замер 13.10.2026, LongMemEval-S, 15 вопросов-подсчётов, одна и та же
    модель-ответчик: 10 полных записей — 3 из 15, 30 сжатых — 8 из 15.
    Сама запись в базе не меняется — это только вид выдачи.
    """
    text = text or ""
    marker = "\nassistant:"
    if marker in text:
        person, assistant = text.split(marker, 1)
        out = person[:head] + ("…" if len(person) > head else "")
        if assistant.strip():
            out += marker + assistant[:tail] + ("…" if len(assistant) > tail else "")
        return out
    return text[:head] + ("…" if len(text) > head else "")


# --- объединение ------------------------------------------------------

DEFAULT_WEIGHTS = {
    "semantic": 1.0,
    "lexical": 1.0,
    "entity": 1.5,      # точное совпадение идентификатора — сильный сигнал
}
# 0.4.6: встроенный «вектор» — это слова, их пятибуквенные основы и пары слов без учёта редкости, то есть шумный
# двойник лексического поиска, а не смысл. В слиянии он не голосует: LongMemEval-S, все 500 вопросов — с ним
# (вес 1,0) 91,7 % «доказательство в первой пятёрке», с весом 0,5 — 93,2 %, без него — 96,8 % (BM25 без PADAM — 96,0 %);
# на 400 вопросах, на которых веса не подбирались, — 96,5 %. Падежи («сервер» / «сервере») держит лексический поиск
# по основам. Вектор остаётся запасным путём: если ни слова, ни идентификаторы не совпали, поиск идёт по нему.
# С настоящей моделью (model2vec, fastembed, Ollama) вес прежний.
BUILTIN_SEMANTIC_WEIGHT = 0.0


def hybrid_rank(store, user_id: str, scope: str, query: str,
                rows: list, pool: int = 50,
                weights: dict[str, float] | None = None,
                statuses: tuple[str, ...] = ("active",)
                ) -> tuple[dict[str, float], dict[str, list[str]]]:
    """Возвращает (баллы RRF, вклад каждой стратегии) — второе для --explain."""
    qvec = embeddings.embed(query)
    rankings = {
        "semantic": rank_semantic(qvec, rows, pool),
        "lexical": rank_lexical(store, user_id, scope, query, pool, statuses),
        "entity": rank_entity(query, rows, pool),
    }
    rankings = {k: v for k, v in rankings.items() if v}
    if weights is None:
        weights = dict(DEFAULT_WEIGHTS)
        if embeddings.метка_модели().startswith("builtin"):
            # запасной путь: нет ни лексических, ни точных совпадений — ищем по вектору, иначе вернули бы пустоту
            запасной = not rankings.get("lexical") and not rankings.get("entity")
            weights["semantic"] = 1.0 if запасной else BUILTIN_SEMANTIC_WEIGHT
    scores = reciprocal_rank_fusion(rankings, weights)
    return scores, rankings
