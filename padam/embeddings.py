"""Эмбеддинги.

Порядок: пробуем Ollama (качественно, локально, бесплатно). Если её нет —
встроенный детерминированный метод, чтобы система работала сразу, без
установки чего-либо.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import threading
import time

import numpy as np

from . import config

_probe_lock = threading.Lock()
_ollama_available: bool | None = None
_ollama_checked_at: float = 0.0

# Как часто перепроверять доступность. 60 секунд — достаточно редко, чтобы не
# дёргать сеть на каждой записи, и достаточно часто, чтобы падение Ollama не
# успело незаметно испортить много записей.
_ПЕРЕПРОВЕРКА_СЕК = 60.0


def _check_ollama() -> bool:
    """Доступна ли Ollama. Ответ живёт минуту, а не вечно.

    🔴 ПОЧЕМУ ЭТО ВАЖНО (найдено 05.09.2026). Раньше ответ запоминался на весь
    процесс: `if _ollama_available is not None: return`. Если Ollama падала
    посреди работы, все последующие записи МОЛЧА уходили на встроенный метод —
    и ложились в ту же базу рядом с нейросетевыми векторами.

    Косинус между встроенным и нейросетевым вектором одного и того же текста —
    около нуля: пространства несовместимы. Значит поиск потом не находит такие
    записи вовсе — не «хуже находит», а не находит. Отказ при этом бесшумный:
    ни ошибки, ни предупреждения, просто память перестаёт помнить часть себя.

    Обратный случай так же важен: Ollama подняли — надо это заметить, а не
    работать встроенным методом до перезапуска процесса.
    """
    global _ollama_available, _ollama_checked_at
    with _probe_lock:
        сейчас = time.monotonic()
        if (_ollama_available is not None
                and сейчас - _ollama_checked_at < _ПЕРЕПРОВЕРКА_СЕК):
            return _ollama_available
        прежнее = _ollama_available
        try:
            import requests
            r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=3)
            _ollama_available = r.status_code == 200
        except Exception:
            _ollama_available = False
        _ollama_checked_at = сейчас
        if прежнее is not None and прежнее != _ollama_available:
            # Смена способа — событие, о котором нельзя молчать: с этого
            # мгновения новые записи считаются в другом пространстве.
            sys.stderr.write(
                "[padam] способ векторизации сменился: %s -> %s\n"
                % ("ollama" if прежнее else "builtin",
                   "ollama" if _ollama_available else "builtin"))
        return _ollama_available


# ---------------------------------------------------------------------
# Локальная модель в самом процессе (0.4.0): без службы и без сети после первой загрузки.
# Ставится дополнением `pip install "padam-nocturne[embed]"` (model2vec, ~30 МБ модели). Замер на LongMemEval-S,
# каждый пятый вопрос (94 без отказных): все нужные сессии в десятке 87,2 % против 83,0 % у встроенного метода,
# хоть одна в десятке 97,9 % против 94,7 %, скорость та же. Выбор — PADAM_EMBEDDER: auto | builtin | ollama |
# model2vec | fastembed. auto: Ollama, если отвечает; иначе установленная локальная модель; иначе встроенный.
# ---------------------------------------------------------------------
_local_lock = threading.Lock()
_local = None            # (вид, имя, функция текст -> вектор)
_local_failed = False


def _local_model():
    """Загружает локальную модель один раз. Не установлена или не загрузилась — None (тогда встроенный метод)."""
    global _local, _local_failed
    if _local is not None or _local_failed:
        return _local
    with _local_lock:
        if _local is not None or _local_failed:
            return _local
        виды = [config.EMBEDDER] if config.EMBEDDER in ("model2vec", "fastembed") else ["model2vec", "fastembed"]
        for вид in виды:
            try:
                if вид == "model2vec":
                    from model2vec import StaticModel
                    имя = config.LOCAL_EMBED_MODEL or "minishlab/potion-base-8M"
                    # Сеть — только при первой загрузке. Сама model2vec ходит в huggingface.co при КАЖДОМ запуске:
                    # force_download по умолчанию True, а на Windows и с False — её проверка кэша получает имя
                    # с обратной косой чертой («minishlab\\potion-base-8M») и не находит модель. Замер 09.11.2026:
                    # CONNECT huggingface.co:443 при полном кэше. Поэтому папку уже скачанной модели находим сами
                    # (try_to_load_from_cache только смотрит в кэш, в сеть не ходит) и отдаём model2vec папку, а не
                    # имя. snapshot_download(local_files_only=True) не годится: он требует ВСЕ файлы репозитория,
                    # а model2vec скачивает только три нужных.
                    путь = имя
                    if not os.path.isdir(имя):
                        try:
                            from huggingface_hub import try_to_load_from_cache
                            файл = try_to_load_from_cache(имя, "config.json")
                            if isinstance(файл, str):
                                папка = os.path.dirname(файл)
                                if all(os.path.isfile(os.path.join(папка, n))
                                       for n in ("model.safetensors", "tokenizer.json")):
                                    путь = папка
                        except Exception:              # нет в кэше — первая загрузка из сети, один раз
                            путь = имя
                    м = StaticModel.from_pretrained(путь, force_download=False)
                    _local = ("model2vec", имя, lambda t, м=м: м.encode([t])[0])
                else:
                    from fastembed import TextEmbedding
                    имя = config.LOCAL_EMBED_MODEL or "BAAI/bge-small-en-v1.5"
                    м = TextEmbedding(имя)
                    _local = ("fastembed", имя, lambda t, м=м: next(iter(м.embed([t]))))
                return _local
            except Exception as e:                     # не установлена, нет сети при первой загрузке и т.п.
                if config.EMBEDDER == вид:
                    from .i18n import t        # язык как у остальных служебных сообщений; stdout не трогаем — там MCP
                    print("[padam] " + t("локальная модель %s не загрузилась (%s): встроенный метод",
                                         "local model %s did not load (%s): using built-in search") % (вид, e),
                          file=sys.stderr)
        _local_failed = True
        return None


def backend() -> str:
    if config.EMBEDDER == "builtin":
        return "builtin"
    if config.EMBEDDER in ("auto", "ollama") and _check_ollama():
        return "ollama"
    if config.EMBEDDER in ("auto", "model2vec", "fastembed") and _local_model() is not None:
        return _local[0]
    return "builtin"


def метка_модели() -> str:
    """Чем считается вектор прямо сейчас — записывается в каждую запись.

    Встроенный метод помечается вместе с размерностью: она задаётся настройкой
    и при её смене прежние векторы становятся несравнимыми так же, как при
    смене нейросетевой модели.
    """
    b = backend()
    if b == "ollama":
        return "ollama:%s" % config.EMBED_MODEL
    if b in ("model2vec", "fastembed"):
        return "%s:%s" % (_local[0], _local[1])
    return "builtin:%d" % config.EMBED_DIM


# ---------------------------------------------------------------------
# Встроенный метод: хеширование словных n-грамм в фиксированный вектор.
# Детерминирован, не требует зависимостей, даёт осмысленную косинусную
# близость для текстов с общей лексикой.
# ---------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)

# Служебные слова дают ложные совпадения: две записи без общего смысла
# «пересекаются» по предлогам. Для встроенного метода это критично,
# потому что он считает именно пересечение лексики.
_STOP = frozenset("""
и в во не что он на я с со как а то все она так его но да ты к у же вы за бы
по только ее мне было вот от меня еще нет о из ему теперь когда даже ну вдруг
ли если уже или ни быть был него до вас нибудь опять уж вам ведь там потом себя
ничего ей может они тут где есть надо ней для мы тебя их чем была сам чтоб без
будто чего раз тоже себе под будет ж кто этот того потому этого какой совсем
ним здесь этом один почти мой тем чтобы нее сейчас были куда зачем всех никогда
можно при наконец два об другой хоть после над больше тот через эти нас про
всего них какая много разве три эту моя впрочем хорошо свою этой перед иногда
лучше чуть том нельзя такой им более всегда конечно всю между
the a an and or but in on at to for of with from by is are was were be been
being it this that these those as if then than so such not no yes do does did
have has had will would can could should may might must i you he she we they
""".split())

_MIN_TOKEN_LEN = 2


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower())
            if len(t) >= _MIN_TOKEN_LEN and t not in _STOP]


_STEM_LEN = 5


def _stem(token: str) -> str | None:
    """Грубая основа: первые пять букв.

    Русский язык флективный, и «сервер» с «сервере» — это одно слово в
    разных падежах. Без нормализации лексический поиск на русском просто
    не работает. Полноценный стеммер здесь избыточен: префикс закрывает
    подавляющее большинство падежных и числовых форм.
    """
    return token[:_STEM_LEN] if len(token) > _STEM_LEN else None


def _builtin_embed(text: str, dim: int = config.EMBED_DIM) -> np.ndarray:
    vec = np.zeros(dim, dtype=np.float32)
    toks = _tokens(text)
    if not toks:
        return vec

    features: list[str] = list(toks)
    features += [s for s in (_stem(t) for t in toks) if s]
    features += [f"{a}_{b}" for a, b in zip(toks, toks[1:])]

    for feat in features:
        h = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
        idx = int.from_bytes(h[:4], "big") % dim
        sign = 1.0 if h[4] & 1 else -1.0
        vec[idx] += sign

    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


def _ollama_embed(text: str) -> np.ndarray:
    import requests
    # 🔴 20.10.2026: прежний вызов `/api/embeddings` на тексте длиннее окна модели получает от Ollama 500
    # «the input length exceeds the context length», а не обрезку. Замер на открытом наборе LongMemEval:
    # 539 из 1 000 случайных разговоров не получали вектора, и при включённом запасном методе ложились в базу
    # со встроенным вектором из несовместимого пространства — поиск их потом не находил. Теперь `/api/embed`
    # с явной обрезкой по окну модели и окном EMBED_CTX: длинная запись получает вектор своего начала.
    r = requests.post(
        f"{config.OLLAMA_URL}/api/embed",
        json={"model": config.EMBED_MODEL, "input": text, "truncate": True,
              "options": {"num_ctx": config.EMBED_CTX}},
        timeout=120,
    )
    r.raise_for_status()
    данные = r.json()
    v = np.asarray((данные.get("embeddings") or [[]])[0], dtype=np.float32)
    # Ollama на пустой строке возвращает пустой список, и такой вектор
    # уходил наружу как есть — размерности (0,) вместо EMBED_DIM.
    # Молчаливо ломались все, кто ждёт вектор фиксированной длины.
    if v.size == 0:
        raise ValueError("Ollama вернула пустой вектор")
    norm = np.linalg.norm(v)
    return v / norm if norm > 0 else v


def embed(text: str) -> np.ndarray:
    """Возвращает нормированный вектор. Никогда не падает."""
    # Пустой текст не о чем спрашивать модель: у него нет признаков.
    # Встроенный метод отдаёт нули нужной размерности — это и есть
    # честный ответ «признаков нет», в отличие от вектора нулевой длины.
    if not text or not text.strip():
        return _builtin_embed(text)
    b = backend()
    if b in ("model2vec", "fastembed"):
        try:
            v = np.asarray(_local[2](text[: config.MAX_CONTENT_CHARS]), dtype=np.float32)
            n = float(np.linalg.norm(v))
            if v.size and n > 0:
                return v / n
        except Exception:
            if not config.ALLOW_FALLBACK:
                raise
        return _builtin_embed(text)
    if b == "ollama":
        try:
            v = _ollama_embed(text)
            # Проверяем размерность ЗДЕСЬ, а не внутри _ollama_embed:
            # так защита переживает любую замену транспорта — другую
            # модель, другой сервер, подменённую функцию в тестах.
            if v.size == config.EMBED_DIM:
                return v
            if not config.ALLOW_FALLBACK:
                raise ValueError(
                    "модель вернула вектор длины %d вместо %d"
                    % (v.size, config.EMBED_DIM))
        except Exception:
            if not config.ALLOW_FALLBACK:
                raise
    return _builtin_embed(text)


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    """Оба вектора уже нормированы, поэтому это просто скалярное произведение."""
    if a is None or b is None or a.size == 0 or b.size == 0:
        return 0.0
    if a.shape != b.shape:
        return 0.0
    return float(np.clip(np.dot(a, b), -1.0, 1.0))
