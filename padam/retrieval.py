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
    вопрос = {embeddings.fold_diacritics(w).lower() for w in _СЛОВО_RE.findall(query or "")}
    счёт: dict[str, int] = {}
    for text in contents:
        for w in dict.fromkeys(embeddings.fold_diacritics(w).lower() for w in _СЛОВО_RE.findall(text or "")):
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
        if w <= 0.0:
            continue
        for pos, rid in enumerate(ids):
            scores[rid] += w / (RRF_K + pos + 1)
    return dict(scores)


# --- стратегии --------------------------------------------------------

MIN_NEURAL_SIM = 0.15


def _query_terms_and_stems(query: str) -> tuple[list[str], list[str]]:
    """Значимые термины запроса (с нормализацией диакритики) и их основы для охвата и BM25."""
    q_norm = embeddings.fold_diacritics((query or "").lower())
    raw = [t for t in re.findall(r"\w+", q_norm) if len(t) > 1]
    if not raw:
        return [], []
    sig = [t for t in raw if t not in _СЛУЖЕБНЫЕ]
    terms = sig if sig else raw
    terms = list(dict.fromkeys(terms))
    stems = [t[:max(5, len(t) - 2)] if len(t) > 5 else t for t in terms]
    return terms, stems


def query_term_coverage(query: str, content: str) -> tuple[float, float]:
    """Возвращает (доля совпавших значимых терминов/основ, доля точных целых слов) в [0.0, 1.0]."""
    terms, stems = _query_terms_and_stems(query)
    if not terms or not content:
        return 0.0, 0.0
    doc_norm = embeddings.fold_diacritics(content.lower())
    doc_words = set(re.findall(r"\w+", doc_norm))
    if not doc_words:
        return 0.0, 0.0
    doc_prefixes_5 = {w[:5] for w in doc_words if len(w) >= 5}
    stem_hits = 0
    exact_hits = 0
    for term, stem in zip(terms, stems):
        if term in doc_words:
            exact_hits += 1
            stem_hits += 1
            continue
        # Префиксное совпадение по основе (русские падежи и окончания вроде сервер/сервере, cedul/cedula)
        if any(w.startswith(stem) for w in doc_words) or (len(term) >= 5 and term[:5] in doc_prefixes_5):
            stem_hits += 1
    n = len(terms)
    return stem_hits / n, exact_hits / n


def _builtin_query_features(query: str) -> set[str]:
    """Набор токенов и 5-буквенных основ запроса для отсечения случайных хеш-коллизий builtin."""
    toks = embeddings._tokens(query or "")
    feats = set(toks)
    for t in toks:
        if len(t) > 5:
            feats.add(t[:5])
    return feats


def _text_has_any_builtin_feature(content: str, q_feats: set[str]) -> bool:
    if not q_feats:
        return True
    if not content:
        return True
    toks = embeddings._tokens(content)
    for t in toks:
        if t in q_feats or (len(t) > 5 and t[:5] in q_feats):
            return True
    return False


def rank_semantic(query_vec: np.ndarray, rows: list, limit: int,
                  query_model: str | None = None,
                  query_text: str = "") -> list[str]:
    """Векторная близость. Понимает переформулировки, слепа к цифрам.

    0.7.2:
    - Строго изолирует несовместимые пространства `embedding_model` (не смешивает `ollama:nomic-embed-text`
      с `builtin:768`, даже если размерность обоих 768).
    - Для `builtin` отсеивает случайные хеш-коллизии `blake2b % 768`, если в тексте записи нет ни одного
      общего токена/основы с запросом.
    - Для нейросетевых моделей отсекает нулевой шум ниже `MIN_NEURAL_SIM`.
    """
    if query_vec is None or not query_vec.size or limit <= 0:
        return []
    q = np.asarray(query_vec, dtype=np.float32)
    is_builtin = bool(query_model and query_model.startswith("builtin"))
    min_sim = 0.0 if (not query_model or is_builtin) else MIN_NEURAL_SIM

    # Выбираем матрицу строго совместимой модели эмбеддингов (плюс legacy-записи с пустой моделью)
    матрицы_мод = getattr(rows, "матрицы_по_модели", None)
    M = None
    ids = None
    if query_model and isinstance(матрицы_мод, dict):
        parts_M = []
        parts_ids = []
        for mk in (query_model, ""):
            entry = матрицы_мод.get(mk)
            if entry is not None and entry[0] == q.shape[0] and entry[2]:
                parts_M.append(entry[1])
                parts_ids.extend(entry[2])
        if not parts_ids:
            return []
        if len(parts_M) == 1:
            M, ids = parts_M[0], parts_ids
        else:
            M, ids = np.concatenate(parts_M, axis=0), parts_ids
        if len(ids) > 400 and min_sim == 0.0 and not is_builtin:
            from . import config as _cfg
            if _cfg.mcp_quant_index_enabled():
                qkey = f"qi:{query_model}"
                qmap = getattr(rows, "_quant_by_model", None)
                if qmap is None:
                    qmap = {}
                    try:
                        rows._quant_by_model = qmap
                    except Exception:
                        pass
                qi = qmap.get(qkey)
                if qi is None:
                    from .quant_index import QuantizedIndex
                    qi = QuantizedIndex(M, ids)
                    qmap[qkey] = qi
                return qi.search(q, limit)
        sims = np.clip(M @ q, -1.0, 1.0)
    else:
        матрица = getattr(rows, "матрица", None)
        if not query_model and матрица is not None and матрица[0] == q.shape[0]:
            _, M, ids = матрица
            if not ids:
                return []
            if len(ids) > 400:
                from . import config as _cfg
                if _cfg.mcp_quant_index_enabled():
                    qi = getattr(rows, "quant_index", None)
                    if qi is None:
                        from .quant_index import QuantizedIndex
                        qi = QuantizedIndex(M, ids)
                        try:
                            rows.quant_index = qi
                        except Exception:
                            pass
                    return qi.search(q, limit)
            sims = np.clip(M @ q, -1.0, 1.0)
        else:
            годные = [
                r for r in rows
                if r["_vec"] is not None
                and r["_vec"].shape == q.shape
                and (not query_model or not r.get("embedding_model") or r.get("embedding_model") == query_model)
            ]
            if not годные:
                return []
            sims = np.clip(np.stack([r["_vec"] for r in годные]) @ q, -1.0, 1.0)
            ids = [r["id"] for r in годные]

    положительные = np.nonzero(sims > min_sim)[0]
    if not положительные.size:
        return []

    fetch_limit = min(положительные.size, limit * 4) if (is_builtin and query_text) else limit
    if положительные.size > fetch_limit * 2:
        pos_sims = sims[положительные]
        part = np.argpartition(-pos_sims, fetch_limit - 1)[:fetch_limit]
        threshold = pos_sims[part].min()
        tied = положительные[pos_sims >= threshold]
        if tied.size <= fetch_limit * 4:
            порядок = tied[np.argsort(-sims[tied], kind="stable")][:fetch_limit]
        else:
            порядок = положительные[np.argsort(-sims[положительные], kind="stable")][:fetch_limit]
    else:
        порядок = положительные[np.argsort(-sims[положительные], kind="stable")][:fetch_limit]

    cand_pairs = [(ids[i], float(sims[i])) for i in порядок]
    if is_builtin and query_text:
        q_feats = _builtin_query_features(query_text)
        if q_feats:
            by_id = getattr(rows, "_by_id", None)
            if by_id is None:
                by_id = {r["id"]: r for r in rows}
                try:
                    rows._by_id = by_id
                except Exception:
                    pass
            filtered: list[str] = []
            for rid, sim_v in cand_pairs:
                # Высокий косинус (>= 0.25) пропускаем даже без совпадения текста (защита AS-025: подмена content при старом векторе).
                if sim_v >= 0.25:
                    filtered.append(rid)
                else:
                    rec_d = by_id.get(rid)
                    if rec_d is None or _text_has_any_builtin_feature(rec_d.get("content") or "", q_feats):
                        filtered.append(rid)
                if len(filtered) >= limit:
                    break
            return filtered
    return [rid for rid, _ in cand_pairs[:limit]]


class Кандидаты(list):
    """Список кандидатов поиска с матрицей векторов: (размерность, матрица, id в порядке строк)."""
    матрица = None
    матрицы_по_модели = None


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
    """BM25 через FTS5 с нормализацией диакритики и учётом охвата терминов запроса (0.7.2)."""
    orig_terms, stems = _query_terms_and_stems(query)
    if not stems:
        return []
    terms = list(dict.fromkeys(stems))
    # OR по терминам: пусть BM25 сам взвесит редкие выше частых, а затем поднимем записи с полным охватом терминов
    match = " OR ".join(f'"{t}"*' for t in terms)
    st_placeholders = ",".join("?" * len(statuses))
    try:
        # 0.5.2: сначала отбираем верхние rowid из FTS5 без чтения BLOB-страниц большой таблицы memory;
        # по rowid IN (...) проверяем user_id/scope/status, и только если верхушку заняли чужие записи — полный JOIN.
        pre_limit = min(max(limit * 4, 200), 800) if limit > 0 else 200
        fts_rows = store.query(
            "SELECT rowid, bm25(memory_fts) AS r FROM memory_fts WHERE memory_fts MATCH ? ORDER BY r, rowid LIMIT ?",
            (match, pre_limit),
        )
        if not fts_rows:
            return []
        rank_map = {int(fr["rowid"]): (float(fr["r"]), idx) for idx, fr in enumerate(fts_rows)}
        rowid_ph = ",".join("?" * len(rank_map))
        m_rows = store.query(
            f"""SELECT rowid, id, content FROM memory
               WHERE rowid IN ({rowid_ph}) AND user_id = ? AND scope = ?
                 AND status IN ({st_placeholders})""",
            (*rank_map.keys(), user_id, scope, *statuses),
        )
        if len(m_rows) < limit and len(fts_rows) >= pre_limit:
            m_rows = store.query(
                f"""SELECT m.rowid, m.id, m.content, bm25(memory_fts) AS r FROM memory_fts f
                   JOIN memory m ON m.rowid = f.rowid
                   WHERE memory_fts MATCH ? AND m.user_id = ? AND m.scope = ?
                     AND m.status IN ({st_placeholders})
                   ORDER BY r, m.rowid LIMIT ?""",
                (match, user_id, scope, *statuses, max(limit * 2, limit)),
            )
            rank_map = {int(mr["rowid"]): (float(mr["r"]), idx) for idx, mr in enumerate(m_rows)}

        if len(orig_terms) >= 2:
            # Многословный запрос: записи с большим числом совпавших значимых терминов (и точным словом) выше.
            def _lex_key(mr):
                bm, pos = rank_map[int(mr["rowid"])]
                cov, ex = query_term_coverage(query, mr["content"] or "")
                return (-round(cov, 4), -round(ex, 4), bm, pos)
            m_sorted = sorted(m_rows, key=_lex_key)
        else:
            # Однословный запрос: точное целое слово выше случайного префикса, внутри — порядок BM25.
            def _lex_key_one(mr):
                bm, pos = rank_map[int(mr["rowid"])]
                _, ex = query_term_coverage(query, mr["content"] or "")
                return (-round(ex, 4), bm, pos)
            m_sorted = sorted(m_rows, key=_lex_key_one)
        return [r["id"] for r in m_sorted[:limit]]
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
    qvec, qmodel = embeddings.embed_with_model(query)
    sem_ids = rank_semantic(qvec, rows, pool, query_model=qmodel, query_text=query)
    lex_ids = rank_lexical(store, user_id, scope, query, pool, statuses)
    ent_ids = rank_entity(query, rows, pool)
    # 0.7.2: если активна нейросеть, но база в основном старая (builtin) и ничего не нашлось — запасной путь builtin
    if not sem_ids and not lex_ids and not ent_ids and not qmodel.startswith("builtin"):
        bdim = getattr(embeddings.config, "EMBED_DIM", 768)
        btag = f"builtin:{bdim}"
        bvec = embeddings._builtin_embed(query, dim=bdim)
        sem_ids = rank_semantic(bvec, rows, pool, query_model=btag, query_text=query)
        if sem_ids:
            qmodel = btag
    rankings = {
        "semantic": sem_ids,
        "lexical": lex_ids,
        "entity": ent_ids,
    }
    rankings = {k: v for k, v in rankings.items() if v}
    if weights is None:
        weights = dict(DEFAULT_WEIGHTS)
        if qmodel.startswith("builtin"):
            # запасной путь: нет ни лексических, ни точных совпадений — ищем по вектору, иначе вернули бы пустоту
            запасной = not rankings.get("lexical") and not rankings.get("entity")
            weights["semantic"] = 1.0 if запасной else BUILTIN_SEMANTIC_WEIGHT
        else:
            # Для настоящей нейросетевой модели эмбеддингов смысл перевешивает шумные частичные совпадения слов
            weights["semantic"] = 1.4
            weights["lexical"] = 0.8
    scores = reciprocal_rank_fusion(rankings, weights)
    # 0.7.2: стратегия с нулевым весом не голосовала — не загрязняем ею `found_by`
    active_rankings = {k: v for k, v in rankings.items() if weights.get(k, 1.0) > 0.0}
    return scores, active_rankings


# --- Б13: переранжирование верхних кандидатов по переключателю PADAM_RERANK=1 ---

_RERANK_STOP = _СТОП_СЛОВА | frozenset(
    "is are was were am be do did does has had have can could would should may might will shall "
    "the a an in on at to of for from by with as into than that this it its he she they we you my your our their "
    "на по за из от до не да но и в во со с к ко у о об про при без для как что где кто".split()
)
_RERANK_TOK_RE = re.compile(r"[^\W_]{2,}", re.UNICODE)
_RERANK_MODELS: dict[str, object] = {}


def _rerank_tokens(text: str) -> list[str]:
    out: list[str] = []
    for raw in _RERANK_TOK_RE.findall(embeddings.fold_diacritics(text or "").lower()):
        if raw in _RERANK_STOP:
            continue
        out.append(raw[:5] if len(raw) > 4 and not raw.isdigit() else raw)
    return out


def _min_span_score(q_set: set[str], doc_tokens: list[str]) -> float:
    """Минимальное окно в документе, содержащее максимальное число уникальных терминов вопроса."""
    if len(q_set) < 2 or not doc_tokens:
        return 0.0
    hits = [(i, tok) for i, tok in enumerate(doc_tokens) if tok in q_set]
    present = {tok for _, tok in hits}
    if len(present) < 2:
        return 0.0
    need = len(present)
    counts: dict[str, int] = {}
    have = 0
    left = 0
    best_span = len(doc_tokens) + 1
    for right in range(len(hits)):
        _, rtok = hits[right]
        counts[rtok] = counts.get(rtok, 0) + 1
        if counts[rtok] == 1:
            have += 1
        while have == need and left <= right:
            span = hits[right][0] - hits[left][0] + 1
            if span < best_span:
                best_span = span
            _, ltok = hits[left]
            counts[ltok] -= 1
            if counts[ltok] == 0:
                have -= 1
            left += 1
    if best_span <= 0 or best_span > len(doc_tokens):
        return 0.0
    density = len(present) / best_span
    coverage = len(present) / len(q_set)
    return min(1.0, density) * coverage


def _get_onnx_reranker(model_dir: str):
    if not model_dir:
        return None
    if model_dir in _RERANK_MODELS:
        return _RERANK_MODELS[model_dir]
    import glob
    import math
    import os
    try:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
    except Exception:
        _RERANK_MODELS[model_dir] = None
        return None
    tok_path = os.path.join(model_dir, "tokenizer.json")
    onnx_files = sorted(glob.glob(os.path.join(model_dir, "**", "*.onnx"), recursive=True))
    if not os.path.exists(tok_path) or not onnx_files:
        _RERANK_MODELS[model_dir] = None
        return None

    class _OnnxCross:
        def __init__(self):
            self.tok = Tokenizer.from_file(tok_path)
            self.tok.enable_truncation(max_length=512)
            self.tok.no_padding()
            so = ort.SessionOptions()
            so.intra_op_num_threads = 2
            so.inter_op_num_threads = 1
            self.sess = ort.InferenceSession(onnx_files[0], so, providers=["CPUExecutionProvider"])
            self.inputs = [i.name for i in self.sess.get_inputs()]

        def score_pairs(self, query: str, docs: list[str]) -> list[float]:
            out: list[float] = []
            for d in docs:
                enc = self.tok.encode(query, d)
                type_ids = getattr(enc, "type_ids", None) or [0] * len(enc.ids)
                feed = {
                    "input_ids": np.array([enc.ids], dtype=np.int64),
                    "attention_mask": np.array([enc.attention_mask], dtype=np.int64),
                    "token_type_ids": np.array([type_ids], dtype=np.int64),
                }
                logits = self.sess.run(None, {k: v for k, v in feed.items() if k in self.inputs})[0]
                val = float(logits.reshape(-1)[0])
                out.append(1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, val)))))
            return out

    try:
        inst = _OnnxCross()
    except Exception:
        inst = None
    _RERANK_MODELS[model_dir] = inst
    return inst


def _pair_relevance(query: str, doc: str, q_tokens: list[str], q_bigrams: list[tuple[str, str]],
                    q_ents: set[str]) -> float:
    if not q_tokens:
        return 0.0
    d_tokens = _rerank_tokens(doc)
    if not d_tokens:
        return 0.0
    q_set = set(q_tokens)
    d_set = set(d_tokens)
    cov = len(q_set & d_set) / len(q_set)
    prox = _min_span_score(q_set, d_tokens)

    bg = 0.0
    if q_bigrams:
        d_pairs = {(d_tokens[i], d_tokens[j]) for i in range(len(d_tokens))
                   for j in (i + 1, i + 2) if j < len(d_tokens)}
        bg = sum(1 for p in q_bigrams if p in d_pairs) / len(q_bigrams)

    if q_ents:
        d_ents = entities(doc)
        ent_cov = len(q_ents & d_ents) / len(q_ents)
        return 0.45 * cov + 0.25 * prox + 0.15 * bg + 0.15 * ent_cov
    return 0.50 * cov + 0.30 * prox + 0.20 * bg


def rerank_records(query: str, records: list, *, top_k: int = 30, model_dir: str = "") -> list:
    """Переранжирует верхние `top_k` записей по парной релевантности (query, content).

    По умолчанию в PADAM выключено (`PADAM_RERANK=0`). Работает детерминированно без сети:
    при указании локальной папки ONNX-модели использует кросс-энкодер, иначе — встроенный
    кросс-парный анализатор (охват терминов, компактность окна, биграммы, точные сущности).
    """
    if len(records) <= 1 or top_k <= 1:
        return list(records)
    head = list(records[:top_k])
    tail = list(records[top_k:])

    max_base = max((getattr(r, "score", 0.0) for r in head), default=0.0)
    if max_base <= 0.0:
        max_base = 1.0

    onnx = _get_onnx_reranker(model_dir)
    if onnx is not None:
        pair_scores = onnx.score_pairs(query, [getattr(r, "content", "") for r in head])
    else:
        q_tokens = _rerank_tokens(query)
        q_bigrams = [(q_tokens[i], q_tokens[i + 1]) for i in range(len(q_tokens) - 1)]
        q_ents = entities(query)
        pair_scores = [_pair_relevance(query, getattr(r, "content", ""), q_tokens, q_bigrams, q_ents) for r in head]

    w_pair = 0.45 if onnx is not None else 0.30
    w_base = 1.0 - w_pair
    rescored = []
    for idx, (rec, pscore) in enumerate(zip(head, pair_scores)):
        base_norm = getattr(rec, "score", 0.0) / max_base
        combined = (w_base * base_norm + w_pair * pscore) * max_base
        rec.score = combined
        strats = getattr(rec, "strategies", ()) or ()
        if "rerank" not in strats:
            rec.strategies = tuple(strats) + ("rerank",)
        rescored.append((combined, -idx, rec))

    rescored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    reordered_head = [x[2] for x in rescored]
    if tail and reordered_head:
        floor = min(getattr(r, "score", 0.0) for r in reordered_head)
        for r in tail:
            if getattr(r, "score", 0.0) >= floor:
                r.score = floor * 0.999
    return reordered_head + tail
