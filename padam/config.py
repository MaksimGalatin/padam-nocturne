"""Настройки PADAM. Всё имеет значение по умолчанию — работает без настройки."""

import os
from pathlib import Path

# --- где хранить -----------------------------------------------------

DB_PATH = Path(os.environ.get(
    "PADAM_DB", Path.home() / ".padam" / "memory.db"))

# --- эмбеддинги ------------------------------------------------------

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
EMBED_MODEL = os.environ.get("PADAM_EMBED_MODEL", "nomic-embed-text")
CLASSIFY_MODEL = os.environ.get("PADAM_CLASSIFY_MODEL", "llama3.2:1b")
EMBED_DIM = int(os.environ.get("PADAM_EMBED_DIM", "768"))
# окно модели эмбеддингов в токенах; длиннее — обрезается (nomic-embed-text держит 8192)
EMBED_CTX = int(os.environ.get("PADAM_EMBED_CTX", "8192"))

# Если Ollama недоступна, используется встроенный детерминированный
# метод. Он слабее по качеству, но полностью рабочий и не требует
# ничего устанавливать.
ALLOW_FALLBACK = os.environ.get("PADAM_ALLOW_FALLBACK", "1") == "1"

# --- затухание по типам записей (дни до половинного веса) -----------

HALF_LIFE_DAYS = {
    "preference": None,   # не затухает никогда
    "identity":   None,   # не затухает никогда
    "decision":   365,
    "correction": 365,
    "fact":       180,
    "state":      14,
    "event":      2,
}

KINDS = tuple(HALF_LIFE_DAYS.keys())

# --- происхождение записи и границы доверия ---------------------------
#
# user — это сказал человек; agent — вывод самой модели; external — прочитано на странице,
# в файле или в выводе инструмента. Начальная уверенность разная, и повтор собственного
# вывода модели её не поднимает: иначе модель сама себе становится независимым источником.

ORIGINS = ("user", "agent", "external")
ORIGIN_CONFIDENCE = {"user": 1.0, "agent": 0.8, "external": 0.6}

# Эти типы не затухают, поэтому подмена через агента осталась бы навсегда.
PROTECTED_KINDS = ("identity", "preference")
# Ниже этого MCP не опускает защищённую запись: архивирует её только владелец из консоли.
PROTECTED_REFUTE_FLOOR = 0.1

MCP_TRUST_WRITES = os.environ.get("PADAM_MCP_TRUST_WRITES", "0") == "1"
KEEP_SECRETS = os.environ.get("PADAM_KEEP_SECRETS", "0") == "1"

MAX_CONTENT_CHARS = 20000
MAX_RECALL_LIMIT = 50
# Столько несведённых эпизодов — повод предложить цикл консолидации.
CONSOLIDATION_DUE = 1000

# --- фильтр противоречий --------------------------------------------
#
# Порог зависит от способа получения эмбеддингов. Нейросетевые векторы
# дают высокую близость даже у разных формулировок одной мысли; встроенный
# метод считает пересечение лексики и даёт меньшие значения. Измерено:
# связанные фразы 0.42-0.54, несвязанные 0.00.

SIMILARITY_THRESHOLD_OLLAMA = float(
    os.environ.get("PADAM_SIM_THRESHOLD_OLLAMA", "0.85"))
SIMILARITY_THRESHOLD_BUILTIN = float(
    os.environ.get("PADAM_SIM_THRESHOLD_BUILTIN", "0.35"))


def similarity_threshold(backend: str) -> float:
    return (SIMILARITY_THRESHOLD_OLLAMA if backend == "ollama"
            else SIMILARITY_THRESHOLD_BUILTIN)

# --- сессии ----------------------------------------------------------

SESSION_GAP_HOURS = 6
SESSION_TOPIC_DISTANCE = 0.5
SESSION_BOOST_CURRENT = 1.3
SESSION_BOOST_TODAY = 1.1
EXPIRED_PENALTY = 0.2   # множитель для записей с истёкшим сроком

# --- NOCTURNE --------------------------------------------------------

# Потолок доли острых эпизодов в батче зависит от работы агента: тому, кто держит серверы, ошибки надо
# помнить лучше, творческому помощнику — слабее. PADAM_PROFILE задаёт готовый уровень, PADAM_SHARP_SHARE —
# точное число; оба ограничены 0.05–0.5, чтобы ни сон из одних катастроф, ни слепота к ним не настраивались.
_PROFILES = {"default": 0.25, "ops": 0.40, "creative": 0.10}


def _sharp_share() -> float:
    точно = os.environ.get("PADAM_SHARP_SHARE")
    try:
        значение = float(точно) if точно else _PROFILES.get(os.environ.get("PADAM_PROFILE", "default"), 0.25)
    except ValueError:
        значение = 0.25
    return min(max(значение, 0.05), 0.5)


K_MAX = _sharp_share()   # потолок доли острых эпизодов в батче
# Мост поколений: столько записей со старыми векторами пересчитывается за один сон (модель сменилась —
# поиск по смыслу их не видит). Векторы считаются только локально (Ollama или встроенный метод).
SLEEP_REINDEX_BATCH = int(os.environ.get("PADAM_SLEEP_REINDEX", "200"))
GAMMA_REPLAY = 0.85      # распад приоритета после переигрывания
P_FLOOR_RATIO = 0.01     # пол приоритета = доля от медианы
ALPHA = 0.6              # степень приоритизации
BETA_START = 0.4         # коррекция смещения в начале
BETA_END = 1.0           # коррекция смещения в конце
HI_PERCENTILE = 90       # что считается острым
SPREAD_THRESHOLD = 2.0   # во сколько раз max должен превышать медиану,
                         # чтобы считать распределение неоднородным

# --- пороги метрик ---------------------------------------------------

MAX_HI_SHARE = K_MAX
MIN_KIND_ENTROPY_RATIO = 0.8
MAX_OVERREPLAY_SHARE = 0.01
OVERREPLAY_COUNT = 5
