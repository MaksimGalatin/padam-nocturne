"""Классификация записей.

Две задачи:
  1. Определить тип записи (kind) — от него зависит скорость забывания.
  2. Решить, что делать с похожей записью: дубликат, уточнение,
     противоречие или сосуществование.

Если Ollama доступна — спрашиваем малую модель. Если нет — работают
правила. Правила проще, но предсказуемы и не молчат.
"""

from __future__ import annotations

import json
import re

from . import config, embeddings

VERDICTS = ("duplicate", "refinement", "contradiction", "coexist")

# --- правила для типа записи -----------------------------------------

_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("preference", (
        "всегда отвечай", "предпочит", "не пиши", "не надо", "мне нравится когда",
        "обращайся", "prefer", "always answer", "don't write", "please use",
    )),
    ("identity", (
        "меня зовут", "я работаю", "я живу", "мой проект", "я основатель",
        "my name is", "i work", "i live", "i am the founder",
    )),
    ("correction", (
        "не так", "исправ", "на самом деле", "ошибка", "неверно", "поправ",
        "actually", "correction", "that's wrong", "not correct",
    )),
    ("decision", (
        "решил", "выбрал", "остановились на", "берём", "утвердил", "договорились",
        "decided", "we'll go with", "chose", "approved",
    )),
    ("event", (
        "дедлайн", "сегодня", "завтра", "в пятницу", "к сроку", "успеть до",
        "deadline", "today", "tomorrow", "due by", "by friday",
    )),
    ("state", (
        "сейчас работаю", "в процессе", "пока не", "на этой неделе", "идёт",
        "currently", "in progress", "working on", "this week",
    )),
]


def infer_kind_rules(text: str) -> str:
    t = text.lower()
    for kind, markers in _RULES:
        if any(m in t for m in markers):
            return kind
    return "fact"


# --- Ollama ----------------------------------------------------------

_KIND_PROMPT = """Classify the memory record into exactly one category.

Categories:
- preference: how the person wants to be worked with
- identity: who the person is, what they do
- decision: a choice that was made
- correction: fixing something said earlier
- fact: a stable fact
- state: current status of ongoing work
- event: something tied to a specific date

Record: {text}

Answer with one word from the list, nothing else."""

_VERDICT_PROMPT = """Two memory records are semantically close. Decide the relation.

Options:
- duplicate: same meaning, no new information
- refinement: the new one adds detail to the old one
- contradiction: the new one replaces the old one, they cannot both be true
- coexist: both can be true at the same time

OLD: {old}
NEW: {new}

Answer with one word from the list, nothing else."""


def _ask_ollama(prompt: str, allowed: tuple[str, ...]) -> str | None:
    if embeddings.backend() != "ollama":
        return None
    try:
        import requests
        r = requests.post(
            f"{config.OLLAMA_URL}/api/generate",
            json={
                "model": config.CLASSIFY_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0},
            },
            timeout=45,
        )
        r.raise_for_status()
        answer = r.json().get("response", "").strip().lower()
        answer = re.sub(r"[^a-z]", "", answer.split()[0]) if answer.split() else ""
        return answer if answer in allowed else None
    except Exception:
        return None


def infer_kind(text: str) -> str:
    """Тип записи. Ollama если есть, иначе правила."""
    got = _ask_ollama(_KIND_PROMPT.format(text=text[:1500]), config.KINDS)
    return got or infer_kind_rules(text)


# --- разрешение противоречий -----------------------------------------

_NEGATION = ("не ", "больше не", "уже не", "вместо", "no longer",
             "not ", "instead of", "changed to", "теперь")


def verdict_rules(new: str, old: str) -> str:
    """Запасные правила, когда модель недоступна.

    🔴 УМОЛЧАНИЕ ИЗМЕНЕНО 05.09.2026: было `refinement`, стало `coexist`.

    Прежнее умолчание замещало старую запись всякий раз, когда правила не
    нашли признаков — то есть ПРИ СОМНЕНИИ память забывала. Отказ при этом
    не виден: система отчитывается «уточнено, прежняя версия сохранена», а
    из выдачи запись пропадает.

    Правильное умолчание — сосуществование: две записи живут рядом, и ни
    одна не исчезает. Замещаем только при явном признаке — отрицании,
    структурном конфликте или уверенном вердикте модели.
    """
    n, o = new.strip().lower(), old.strip().lower()
    if n == o:
        return "duplicate"
    if any(m in n for m in _NEGATION):
        return "contradiction"
    # новая заметно длиннее и содержит старую — уточнение
    if len(n) > len(o) * 1.3 and o[:40] in n:
        return "refinement"
    return "coexist"


# --- структурный вердикт ---------------------------------------------
#
# Два утверждения спорят друг с другом только когда говорят РАЗНОЕ ОБ ОДНОМ И
# ТОМ ЖЕ свойстве одного объекта. «Где родился X» и «кем работает X» не спорят,
# как бы похоже ни звучали; «столица X — Париж» и «столица X — Рим» спорят.
#
# Это общее свойство памяти, а не приём под конкретный набор данных: без него
# похожесть текста подменяет собой смысл. Замер 05.09.2026 на mh_6k показал
# цену подмены — 203 замещения при 142 настоящих конфликтах, то есть не менее
# 61 верного факта исчезло из выдачи и оборвало цепочки рассуждения.

_СВЯЗКИ = (
    # места
    " was born in the city of ", " died in the city of ",
    " worked in the city of ", " was founded in the city of ",
    " was created in the country of ", " is located in the ",
    # люди и роли
    " plays the position of ", " was founded by ", " was performed by ",
    " was created by ", " was written by ", " was directed by ",
    " is married to ", " is a citizen of ", " is affiliated with the ",
    # свойства
    " speaks the language of ", " is the religion of ",
    " works in the field of ", " plays the sport of ",
    # русские
    " родился в ", " работает ", " женат на ", " живёт в ",
    " стоит ", " равен ", " равна ",
    # самые общие — последними, иначе съедят частные
    " is ", " — ", " это ",
)

# Предлоги, после которых в утверждении стоит ЗНАЧЕНИЕ. Нужны для общего
# разбора: «was developed by Microsoft», «was written in the language of
# English» и тысячи других оборотов разбираются одним правилом, без
# перечисления каждого глагола.
_ПРЕДЛОГИ = (" of ", " by ", " to ", " in ", " at ", " from ", " with ")

# Глагольные признаки утверждения о свойстве. Без них правило зацепило бы
# любую фразу с предлогом, включая обычное повествование.
_ПРИЗНАКИ = (" is ", " was ", " are ", " were ", " has ", " have ",
             " plays ", " speaks ", " works ", " lives ", " died ",
             " born ", " founded ", " created ", " developed ", " written ")


def дочистить(ключ: str, значение: str):
    """Переносит из значения в ключ то, что осталось от связки.

    🔴 ЗАЧЕМ (найдено замером 05.09.2026). Факт «John Harkes is associated
    with the sport of association football» разбирался общей связкой ` is `,
    и значением выходило `associated with the sport of association football`.

    Дальше это подставлялось как СУЩНОСТЬ в следующий шаг обхода — и,
    разумеется, не находило ничего. Цепочка обрывалась на первом же звене,
    хотя факт был найден верно.

    Цена ошибки в числах: вопросы про столицу (а они трёх- и
    четырёхзвенные) давали 1 верный ответ из 15 — 7 %, четверть всех потерь
    прогона. При этом сама память работала безупречно: «capital of Italy is
    Rome» была замещена на «is Duluth», как и положено.

    Починка общая, а не для одного оборота: если значение начинается со
    служебных слов и внутри него есть предлог, значением становится хвост
    после ПОСЛЕДНЕГО предлога, а всё до него уходит в ключ. Так
    `associated with the sport of association football` превращается в
    `association football`, а ключ дорастает до
    `john harkes is associated with the sport of`.
    """
    зн = (значение or "").strip()
    низ = " " + зн.lower() + " "
    # Признак «значение на самом деле — продолжение связки»: оно начинается
    # с причастия или предлога, а не с имени.
    начала = ("associated ", "known ", "located ", "written ", "performed ",
              "created ", "developed ", "born ", "married ", "educated ",
              "the ", "a ", "an ")
    if not зн.lower().startswith(начала):
        return ключ, зн
    лучший, длина = -1, 0
    for предлог in _ПРЕДЛОГИ:
        i = зн.lower().rfind(предлог)
        if i > лучший:
            лучший, длина = i, len(предлог)
    if лучший <= 0:
        return ключ, зн
    хвост = зн[лучший + длина:].strip()
    if not хвост:
        return ключ, зн
    return (ключ + " " + зн[:лучший + длина].strip()).strip(), хвост.lower()


def разобрать_факт(текст: str):
    """«The author of X is Y» → («the author of x is», «y»).

    Возвращает (ключ, значение) либо (None, None), если текст не похож на
    утверждение «свойство объекта = значение». Берётся ПОСЛЕДНЕЕ вхождение
    самой длинной подходящей связки: левая часть сама может её содержать
    («The city that is the capital of …»).
    """
    т = (текст or "").strip().rstrip(".")
    if not т:
        return None, None

    # Проход первый — точные связки. Надёжнее и дают осмысленный ключ.
    for связка in _СВЯЗКИ:
        i = т.rfind(связка)
        if i > 0:
            ключ = (т[:i] + связка).strip().lower()
            значение = т[i + len(связка):].strip().lower().rstrip(".")
            if ключ and значение:
                return дочистить(ключ, значение)

    # Проход второй — общий приём: хвост после ПОСЛЕДНЕГО предлога, если во
    # фразе есть глагольный признак утверждения. Именно он делает разбор
    # масштабируемым: перечислять каждый глагол под конкретный набор данных
    # было бы подгонкой, а это правило работает на любом тексте.
    низ = " " + т.lower() + " "
    if not any(п in низ for п in _ПРИЗНАКИ):
        return None, None
    лучший, длина = -1, 0
    for предлог in _ПРЕДЛОГИ:
        i = т.rfind(предлог)
        if i > лучший:
            лучший, длина = i, len(предлог)
    if лучший <= 0:
        return None, None
    ключ = т[:лучший + длина].strip().lower()
    значение = т[лучший + длина:].strip().lower().rstrip(".")
    # значение — это имя, место или число, а не продолжение повествования
    if not ключ or not значение or len(значение.split()) > 8:
        return None, None
    return ключ, значение


def структурный_вердикт(new: str, old: str):
    """Вердикт по структуре факта или None, если структура не разобрана.

    None означает «решай как раньше» — моделью, затем правилами.
    """
    кн, зн = разобрать_факт(new)
    ко, зо = разобрать_факт(old)
    if not кн or not ко:
        return None
    if кн != ко:
        # разные свойства — спорить не о чем, обе записи нужны
        return "coexist"
    if зн == зо:
        return "duplicate"
    return "contradiction"


def resolve(new: str, old: str) -> str:
    структурный = структурный_вердикт(new, old)
    if структурный is not None:
        return структурный
    got = _ask_ollama(
        _VERDICT_PROMPT.format(new=new[:1000], old=old[:1000]), VERDICTS)
    return got or verdict_rules(new, old)
