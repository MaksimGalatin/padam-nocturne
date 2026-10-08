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

K_MAX = 0.25             # потолок доли острых эпизодов в батче
GAMMA_REPLAY = 0.85      # распад приоритета после переигрывания
P_FLOOR_RATIO = 0.01     # пол приоритета = доля от медианы
ALPHA = 0.6              # степень приоритизации
BETA_START = 0.4         # коррекция смещения в начале
BETA_END = 1.0           # коррекция смещения в конце
HI_PERCENTILE = 90       # что считается острым
SPREAD_THRESHOLD = 2.0   # во сколько раз max должен превышать медиану,
                         # чтобы считать распределение неоднородным

# --- пороги метрик ---------------------------------------------------

MAX_HI_SHARE = 0.25
MIN_KIND_ENTROPY_RATIO = 0.8
MAX_OVERREPLAY_SHARE = 0.01
OVERREPLAY_COUNT = 5
