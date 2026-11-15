"""Настройки PADAM. Всё имеет значение по умолчанию — работает без настройки."""

import os
from pathlib import Path

# --- где хранить -----------------------------------------------------

DB_PATH = Path(os.environ.get(
    "PADAM_DB", Path.home() / ".padam" / "memory.db"))

# --- эмбеддинги ------------------------------------------------------

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
EMBED_MODEL = os.environ.get("PADAM_EMBED_MODEL", "nomic-embed-text")
# 0.4.0: способ векторов — auto | builtin | ollama | model2vec | fastembed (см. embeddings._local_model).
EMBEDDER = os.environ.get("PADAM_EMBEDDER", "auto").strip().lower()
LOCAL_EMBED_MODEL = os.environ.get("PADAM_LOCAL_EMBED_MODEL", "")
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
# Строгий режим: всё, что агент пометил как прочитанное снаружи (origin=external), ждёт владельца целиком,
# а не только похожее на команду. По умолчанию выключен: пометку ставит сам агент, и тот же текст он может
# записать как agent, поэтому настоящая защита — ограда выдачи, а этот режим — дополнительная строгость.
# 0.4.0: по умолчанию ВКЛЮЧЕНО — словарь команд подгоняется под виденные атаки (третий набор: 6 из 14),
# поэтому прочитанное агентом снаружи ждёт владельца всегда. PADAM_HOLD_EXTERNAL=0 выключает.
HOLD_EXTERNAL = os.environ.get("PADAM_HOLD_EXTERNAL", "1") != "0"
# 0.4.1: каждая запись агента через MCP ждёт владельца, какую бы пометку источника агент ни поставил (её сервер
# проверить не может — в MCP нет удостоверения источника). Выключено по умолчанию: без владельца память не растёт.
MCP_REVIEW_ALL = os.environ.get("PADAM_MCP_REVIEW_ALL", "0") == "1"


def unsafe_settings() -> list[tuple[str, str]]:
    """0.4.2: настройки, которые выключают защиту, и что именно они открывают (внешний разбор 09.11.2026:
    неверный выключатель равен утечке, поэтому о каждом говорится при запуске, а не только в README)."""
    out = []
    if KEEP_SECRETS:
        out.append(("PADAM_KEEP_SECRETS=1", "keys, passwords and seed phrases are stored as written, in clear"))
    if MCP_TRUST_WRITES:
        out.append(("PADAM_MCP_TRUST_WRITES=1", "an agent can store commands and rewrite who you are without your review"))
    if not HOLD_EXTERNAL:
        out.append(("PADAM_HOLD_EXTERNAL=0", "text an agent read on a web page or in a file is stored without your review"))
    return out
KEEP_SECRETS = os.environ.get("PADAM_KEEP_SECRETS", "0") == "1"
# Б4 (14.11.2026): маскировка телефонов и почты переключателем PADAM_MASK_PII=1.
# По умолчанию выключена: в личной памяти человеку часто нужны свои номера и адреса.
MASK_PII = os.environ.get("PADAM_MASK_PII", "0") == "1"
# Б10 (14.11.2026): исходящий вебхук событий памяти (write, approve, reject, forget).
# Отправляется только при явно заданном PADAM_WEBHOOK_URL и подписывается HMAC-SHA256 (PADAM_WEBHOOK_SECRET).
WEBHOOK_URL = os.environ.get("PADAM_WEBHOOK_URL", "").strip()
WEBHOOK_SECRET = os.environ.get("PADAM_WEBHOOK_SECRET", "").strip()

# Второй проход поиска (псевдо-обратная связь): слова, общие для нескольких первых найденных записей, дописываются
# к запросу, и два списка сливаются обратным рангом. Опыт 11.11.2026 на LongMemEval-S (470 вопросов с ответом):
# «все нужные беседы в первой пятёрке» 83,0 % → 85,3 %, по нескольким беседам 64,5 % → 70,3 %. Цена — второй поиск.
# 0.4.13: включён по умолчанию (решение владельца проекта 11.11.2026). Поверх 0.4.12 на тех же 470 вопросах: all@5
# 84,0 → 86,6 %, all@10 91,1 → 93,0 %, any@10 98,7 → 99,1 %, any@5 97,2 → 97,0 %. Денег не тратит — это второй
# локальный поиск; время поиска примерно вдвое. Выключить: PADAM_SEARCH_FEEDBACK=0.
SEARCH_FEEDBACK = os.environ.get("PADAM_SEARCH_FEEDBACK", "1") != "0"

# Б13 (14.11.2026): переранжирование верхних кандидатов поиска по переключателю (выключено по умолчанию).
# Без внешней модели использует встроенный кросс-парный реранкер (охват терминов, близость окна, биграммы и сущности);
# при указании PADAM_RERANK_MODEL (папка с tokenizer.json + .onnx) применяет локальный ONNX cross-encoder.
RERANK = os.environ.get("PADAM_RERANK", "0") == "1"
RERANK_TOP_K = int(os.environ.get("PADAM_RERANK_TOP", "30"))
RERANK_MODEL = os.environ.get("PADAM_RERANK_MODEL", "").strip()
# Г10 (14.11.2026): локальная модель Ollama для экрана «Спроси свою память» (выбирается человеком в настройках).
ASK_MODEL = os.environ.get("PADAM_ASK_MODEL", "").strip()

# 0.4.5: строгий профиль одним выключателем вместо россыпи флагов (внешний разбор 09.11.2026: «каждый флаг
# охраняется, но единого --strict нет»). PADAM_STRICT=1: каждая запись агента ждёт владельца, внешний текст тоже;
# ослабляющие переменные игнорируются (и об этом говорится при запуске); закрепление в Arweave без защищённых
# ключей и REST без токена отказываются запускаться даже с явным флагом.
STRICT = os.environ.get("PADAM_STRICT", "0") == "1"
_STRICT_IGNORED: list[str] = []
if STRICT:
    if KEEP_SECRETS:
        _STRICT_IGNORED.append("PADAM_KEEP_SECRETS=1")
    if MCP_TRUST_WRITES:
        _STRICT_IGNORED.append("PADAM_MCP_TRUST_WRITES=1")
    if not HOLD_EXTERNAL:
        _STRICT_IGNORED.append("PADAM_HOLD_EXTERNAL=0")
    KEEP_SECRETS, MCP_TRUST_WRITES, HOLD_EXTERNAL, MCP_REVIEW_ALL = False, False, True, True


def strict_ignored() -> list[str]:
    """Ослабляющие переменные, которые строгий профиль отменил."""
    return list(_STRICT_IGNORED)

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
    # Локальные нейросетевые модели дают близость того же порядка, что и Ollama (замер LongMemEval 09.11.2026).
    return (SIMILARITY_THRESHOLD_OLLAMA if backend in ("ollama", "model2vec", "fastembed")
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
PROFILES = _PROFILES
PROFILE_NAME = os.environ.get("PADAM_PROFILE", "default") if os.environ.get("PADAM_PROFILE", "default") in _PROFILES else "default"


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

# --- Пункт 1.3: MCP tasks (2025-11-25) и sampling для сжатия кластеров ---
# По умолчанию выключены: включаются явным флагом и согласием клиента.
MCP_TASKS_ENABLED = os.environ.get("PADAM_MCP_TASKS", "0") == "1"
MCP_SAMPLING_ENABLED = os.environ.get("PADAM_MCP_SAMPLING", "0") == "1"

# --- Пункт 1.2: OAuth 2.1 + RFC 9728 для локального MCP HTTP-сервера ---
MCP_OAUTH_ENABLED = os.environ.get("PADAM_MCP_OAUTH", "0") == "1"


def mcp_oauth_enabled() -> bool:
    """Включается только явно через PADAM_MCP_OAUTH=1; по умолчанию выключено."""
    return os.environ.get("PADAM_MCP_OAUTH", "0") == "1"

# --- Пункт 4.2: Пределы входа MCP (размер, глубина JSON, число записей за вызов) ---
MAX_EXPORT_LIMIT = int(os.environ.get("PADAM_MAX_EXPORT_LIMIT", "5000"))
MAX_EXPORT_OFFSET = int(os.environ.get("PADAM_MAX_EXPORT_OFFSET", "1000000"))
MAX_JSON_DEPTH = int(os.environ.get("PADAM_MAX_JSON_DEPTH", "32"))
MAX_JSON_NODES = int(os.environ.get("PADAM_MAX_JSON_NODES", "4096"))
MAX_MCP_MESSAGE_BYTES = int(os.environ.get("PADAM_MAX_MCP_BYTES", str(512 * 1024)))

# --- Пункт 4.3: Ограничение частоты вызовов на сессию в HTTP-режиме ---
# По умолчанию 0 (выключено); включается через PADAM_MCP_RATE_LIMIT=<N> запросов за окно.
MCP_RATE_LIMIT = int(os.environ.get("PADAM_MCP_RATE_LIMIT", "0"))
MCP_RATE_WINDOW_S = float(os.environ.get("PADAM_MCP_RATE_WINDOW_S", "60.0"))


def mcp_rate_limit() -> int:
    raw = os.environ.get("PADAM_MCP_RATE_LIMIT")
    if raw is not None and raw.strip():
        try:
            return max(0, int(raw))
        except ValueError:
            return 0
    return max(0, int(MCP_RATE_LIMIT))


# --- ТОП-10 Пункт 1: Multi-hop графовое расширение поиска (выключено по умолчанию) ---
def mcp_graph_hops_default() -> int:
    """Глубина обхода графа по умолчанию в padam_search (0 = выключено)."""
    raw = os.environ.get("PADAM_MCP_GRAPH_HOPS", "0").strip()
    try:
        return min(2, max(0, int(raw)))
    except ValueError:
        return 0


# --- ТОП-10 Пункт 2: Асинхронный stdio-мультиплексор (выключено по умолчанию) ---
def mcp_async_stdio_enabled() -> bool:
    """Включает пул воркеров и живую отмену/batch/sampling по stdio (PADAM_MCP_ASYNC_STDIO=1 или --async-stdio)."""
    return os.environ.get("PADAM_MCP_ASYNC_STDIO", "0").strip() == "1"


# --- ТОП-10 Пункт 3: MCP Roots + предиктивный когнитивный кэш (выключено по умолчанию) ---
def mcp_roots_enabled() -> bool:
    """Авто-выбор scope проекта по roots/list клиента (PADAM_MCP_ROOTS=1)."""
    return os.environ.get("PADAM_MCP_ROOTS", "0").strip() == "1"


def mcp_predictive_cache_enabled() -> bool:
    """Предиктивный прогрев ядра графа проекта в RAM при смене roots (включается вместе с PADAM_MCP_ROOTS=1 или PADAM_MCP_PREDICTIVE_CACHE=1)."""
    raw = os.environ.get("PADAM_MCP_PREDICTIVE_CACHE", "").strip()
    if raw == "0":
        return False
    if raw == "1":
        return True
    return mcp_roots_enabled()


# --- ТОП-10 Пункт 4: Бюджет токенов и атомарное слияние (выключено по умолчанию) ---
def mcp_default_max_tokens() -> int:
    """Бюджет токенов по умолчанию для padam_search (0 = не ограничен)."""
    raw = os.environ.get("PADAM_MCP_MAX_TOKENS", "0").strip()
    try:
        val = int(raw)
        return val if val >= 50 else 0
    except ValueError:
        return 0


def mcp_atomic_merge_default() -> bool:
    """Режим dedup_mode='atomic_merge' по умолчанию в padam_write (выключен по умолчанию)."""
    return os.environ.get("PADAM_MCP_ATOMIC_MERGE", "0").strip() == "1"

# --- ТОП-10 Пункт 5: Настоящий Streamable HTTP v2 (выключено по умолчанию) ---
def mcp_http_sse_post_enabled() -> bool:
    """SSE-стриминг POST /mcp и возобновление GET /mcp по Last-Event-ID (PADAM_MCP_HTTP_SSE_POST=1)."""
    return os.environ.get("PADAM_MCP_HTTP_SSE_POST", "0").strip() == "1"

# --- ТОП-10 Пункт 6: MCP Apps интерактивные HTML-интерфейсы (выключено по умолчанию) ---
def mcp_apps_enabled() -> bool:
    """Включает ресурсы ui://padam/* с MIME text/html;profile=mcp-app (PADAM_MCP_APPS=1)."""
    return os.environ.get("PADAM_MCP_APPS", "0").strip() == "1"

# --- ТОП-10 Пункт 7: Иконки SEP-973 и карточка /.well-known/mcp/server-card.json (выключено по умолчанию) ---
def mcp_icons_enabled() -> bool:
    """Добавляет SEP-973 icons в serverInfo, tools, resources, prompts (PADAM_MCP_ICONS=1)."""
    return os.environ.get("PADAM_MCP_ICONS", "0").strip() == "1"


def mcp_server_card_enabled() -> bool:
    """Открывает GET /.well-known/mcp/server-card.json (PADAM_MCP_SERVER_CARD=1)."""
    return os.environ.get("PADAM_MCP_SERVER_CARD", "0").strip() == "1"

# --- ТОП-10 Пункт 8: Курсорная пагинация */list (выключено по умолчанию) ---
def mcp_page_size() -> int:
    """Размер страницы для tools/resources/prompts/tasks/list (PADAM_MCP_PAGE_SIZE=0 — без разбивки)."""
    raw = os.environ.get("PADAM_MCP_PAGE_SIZE", "0").strip()
    try:
        return max(0, min(1000, int(raw)))
    except ValueError:
        return 0

# --- ТОП-10 Пункт 9: Общий локальный пул-сервер (--auto-daemon) и жёсткая изоляция сессий (выключено по умолчанию) ---
def mcp_auto_daemon_enabled() -> bool:
    """Авто-подключение к общему локальному пулу вместо изолированных SQLite-инстансов (PADAM_MCP_AUTO_DAEMON=1)."""
    return os.environ.get("PADAM_MCP_AUTO_DAEMON", "0").strip() == "1"


def mcp_session_isolation_enabled() -> bool:
    """Жёсткая песочная изоляция проектов на уровне MCP-сессий в общем пуле (PADAM_MCP_SESSION_ISOLATION=1)."""
    return os.environ.get("PADAM_MCP_SESSION_ISOLATION", "0").strip() == "1" or mcp_auto_daemon_enabled()


# --- Легенда Шаг 1: Автономный Движок Сновидений Active REM Sleep (выключено по умолчанию) ---
def mcp_rem_sleep_enabled() -> bool:
    """Включает фоновый REM-сон в локальном демоне при простое (PADAM_REM_SLEEP=1)."""
    return os.environ.get("PADAM_REM_SLEEP", "0").strip() == "1"


def mcp_rem_idle_seconds() -> float:
    """Порог простоя (сек) перед автозапуском цикла REM-сновидений."""
    raw = os.environ.get("PADAM_REM_IDLE_S", "300").strip()
    try:
        return max(0.05, float(raw))
    except ValueError:
        return 300.0


def mcp_rem_ollama_url() -> str:
    """Адрес локальной Ollama для REM-сна (допускается только localhost/127.0.0.1)."""
    return os.environ.get("PADAM_REM_OLLAMA_URL", "").strip()


def mcp_rem_model() -> str:
    """Модель локальной Ollama для синтеза инсайтов во сне."""
    return (os.environ.get("PADAM_REM_MODEL", "llama3.2:3b") or "llama3.2:3b").strip()


# --- Легенда Шаг 2: Когнитивный Контроль Версий (padam_rollback, выключено по умолчанию) ---
def mcp_rollback_tool_enabled() -> bool:
    """Включает 10-й MCP-инструмент padam_rollback (Машина Времени) и ресурс padam://snapshots."""
    return os.environ.get("PADAM_MCP_ROLLBACK_TOOL", "0").strip() == "1"


# --- Легенда Шаг 3: Превентивный Семантический Фаервол (DLP & Zero-Leak Shield, выключено по умолчанию) ---
def mcp_dlp_shield_enabled() -> bool:
    """Включает токенизацию секретов в [PADAM_SECRET_ID_N] и локальный DLP-прокси-щит."""
    return os.environ.get("PADAM_MCP_DLP_SHIELD", "0").strip() == "1"


def mcp_dlp_upstream_url() -> str:
    """Необязательный upstream URL для локального DLP-прокси-шлюза (пусто по умолчанию)."""
    return os.environ.get("PADAM_DLP_UPSTREAM_URL", "").strip()


# --- Легенда Шаг 4: Локальный Меж-Агентский Синдикат (P2P Swarm Synapse, выключено по умолчанию) ---
def mcp_swarm_enabled() -> bool:
    """Включает локальную синаптическую шину агентов padam://swarm/feed и GET /swarm/feed (PADAM_MCP_SWARM=1)."""
    return os.environ.get("PADAM_MCP_SWARM", "0").strip() == "1"


# --- Легенда Шаг 5: Аппаратная Печать Души (Hardware-Locked Genesis, выключено по умолчанию) ---
def mcp_hw_seal_enabled() -> bool:
    """Включает аппаратное запечатывание БД (PADAMHW1: FIDO2 + OS DPAPI/Keystore, PADAM_HW_SEAL=1)."""
    return os.environ.get("PADAM_HW_SEAL", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 1: Хуки жизненного цикла (выключено по умолчанию) ---
def mcp_hooks_enabled() -> bool:
    """Включает подсистему хуков жизненного цикла Claude/Codex/Gemini (PADAM_HOOKS=1)."""
    return os.environ.get("PADAM_HOOKS", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 2: Панель прав приложений и хешируемый журнал доступа (выключено по умолчанию) ---
def mcp_app_acl_enabled() -> bool:
    """Включает контроль доступа по клиенту/agent_id, паузу/отзыв и ресурс padam://access-control (PADAM_APP_ACL=1)."""
    return os.environ.get("PADAM_APP_ACL", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 3: Двусторонняя синхронизация с Markdown / Obsidian (выключено по умолчанию) ---
def mcp_obsidian_sync_enabled() -> bool:
    """Включает двустороннюю синхронизацию папки Obsidian/Markdown с графом памяти (PADAM_OBSIDIAN_SYNC=1)."""
    return os.environ.get("PADAM_OBSIDIAN_SYNC", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 4: Полная двухвременная модель (Bi-temporal, выключено по умолчанию) ---
def mcp_bitemporal_enabled() -> bool:
    """Включает системное время learned_at/invalidated_at и двойной срез (valid_at, known_at) (PADAM_BITEMPORAL=1)."""
    return os.environ.get("PADAM_BITEMPORAL", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 5: Процедурная память — навыки (kind="procedure", выключено по умолчанию) ---
def mcp_procedural_memory_enabled() -> bool:
    """Включает версионируемые навыки kind='procedure' и экспорт в SKILL.md/CLAUDE.md (PADAM_PROCEDURAL_MEMORY=1)."""
    return os.environ.get("PADAM_PROCEDURAL_MEMORY", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 6: Reflect — разделение фактов, опыта и мнений (выключено по умолчанию) ---
def mcp_reflect_enabled() -> bool:
    """Включает эпистемическое разделение world_fact / agent_experience / opinion и ресурс padam://reflect (PADAM_REFLECT=1)."""
    return os.environ.get("PADAM_REFLECT", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 7: Бэкенд для нативного Memory Tool Claude (/memories, выключено по умолчанию) ---
def mcp_claude_memory_fs_enabled() -> bool:
    """Включает виртуальную ФС /memories (view/create/str_replace/insert/delete/rename) и ресурс padam://memories (PADAM_CLAUDE_MEMORY_FS=1)."""
    return os.environ.get("PADAM_CLAUDE_MEMORY_FS", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 8: Сообщества графа со сводками (Label Propagation, выключено по умолчанию) ---
def mcp_communities_enabled() -> bool:
    """Включает кластеризацию графа label propagation и ресурс padam://communities/{scope} (PADAM_COMMUNITIES=1)."""
    return os.environ.get("PADAM_COMMUNITIES", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 9: Переносимый подписанный пакет памяти MemCube (выключено по умолчанию) ---
def mcp_memcube_enabled() -> bool:
    """Включает экспорт/импорт подписанных шифрованных контейнеров памяти MemCube (PADAM_MEMCUBE=1)."""
    return os.environ.get("PADAM_MEMCUBE", "0").strip() == "1"


# --- ТОП-10 v2 Пункт 10: Автосвязывание прямо при записи (как A-MEM, выключено по умолчанию) ---
def mcp_write_autolink_enabled() -> bool:
    """Включает автоматическое создание связей при записи (без LLM-вызова, PADAM_WRITE_AUTOLINK=1)."""
    return os.environ.get("PADAM_WRITE_AUTOLINK", "0").strip() == "1"
