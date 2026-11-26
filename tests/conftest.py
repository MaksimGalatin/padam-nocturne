"""Тесты не трогают живую Ollama на этой машине.

Найдено 09.11.2026: если на порту 11434 отвечала Ollama, набор звал её сам — она грузила модель
(отдельный процесс llama-server, нагрузка на процессор), а поиск по смыслу находил то, чего встроенный
метод не находит, и два теста падали. Набор зависел от того, что запущено на компьютере, и на GitHub
(где Ollama нет) вёл себя иначе, чем дома. Теперь везде встроенный метод, как на GitHub.

Живая проверка с настоящей Ollama — только явно: PADAM_TEST_LIVE_OLLAMA=1.
Тесты, которым нужна «включённая» Ollama, по-прежнему подменяют её сами (monkeypatch).
"""

import os

import pytest

from padam import config, embeddings

ЖИВАЯ_OLLAMA = os.environ.get("PADAM_TEST_LIVE_OLLAMA") == "1"
_НИКУДА = "http://127.0.0.1:9"   # порт «discard»: соединение отклоняется сразу


@pytest.fixture(autouse=True)
def _без_живой_ollama(monkeypatch):
    if ЖИВАЯ_OLLAMA:
        yield
        return
    monkeypatch.setenv("OLLAMA_URL", _НИКУДА)          # подпроцессы с сервером наследуют окружение
    monkeypatch.setattr(config, "OLLAMA_URL", _НИКУДА)
    # 0.4.0: и локальную модель (дополнение [embed]) тесты не берут сами — только встроенный метод, как на GitHub.
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    monkeypatch.setattr(config, "EMBEDDER", "builtin")
    monkeypatch.setattr(embeddings, "_ollama_available", None)
    monkeypatch.setattr(embeddings, "_check_ollama", lambda: False)
    yield


@pytest.fixture(autouse=True)
def _без_настроек_компьютера(tmp_path_factory, monkeypatch):
    """18.11.2026: тесты не читают ~/.padam/local_model.json этого компьютера.

    Иначе на машине, где владелец выбрал модель GGUF, Совет Семьи и офлайн-движок в тестах грузили настоящую
    Qwen3-14B: прогон тестов лент шёл 292 с вместо 10. Тест, которому нужна своя папка, ставит PADAM_HOME сам.
    """
    home = tmp_path_factory.mktemp("padam_home")
    monkeypatch.setenv("PADAM_HOME", str(home))
    # И база по умолчанию — тоже временная: Memory() без store пишет в config.DB_PATH. 18.11.2026 нашлось,
    # что тесты с Memory(путь) (путь уходил в user_id) писали в ~/.padam/memory.db этого компьютера.
    monkeypatch.setenv("PADAM_DB", str(home / "memory.db"))
    monkeypatch.setattr(config, "DB_PATH", home / "memory.db")
    monkeypatch.delenv("PADAM_CPU_GGUF_PATH", raising=False)
    monkeypatch.delenv("PADAM_CPU_POWER", raising=False)
    yield



# 25.11.2026: настройки роутера моделей, которые живой PADAM берёт из окружения Windows этой машины.
# Найдено при подготовке 0.9.0: на машине стоят настоящие ключи Gemini (PADAM_LLM_GEMINI_KEYS) и файл
# гранта Vertex, роутер по замыслу ставит бесплатный Gemini раньше локальной Ollama, и три теста роутера
# падали дома, хотя на GitHub (где ключей нет) проходили. Хуже: тест без подмены сети мог бы позвать
# настоящий Gemini нашими ключами. Теперь каждый тест начинает с чистого роутера, как на GitHub;
# тест, которому нужна такая настройка, ставит её сам через monkeypatch.setenv.
_РОУТЕР_ИЗ_ОКРУЖЕНИЯ_ПРЕФИКСЫ = ("PADAM_LLM_", "PADAM_VERTEX_", "PADAM_GRANT_")
_РОУТЕР_ИЗ_ОКРУЖЕНИЯ_ИМЕНА = ("PADAM_ALLOW_VERTEX_AFTER_LOCAL", "PADAM_ASK_MODEL", "PADAM_COUNCIL_GUARD_MODEL",
                              "PADAM_ROUTER_COOLDOWN_S", "PADAM_ROUTER_LOOP_LIMIT")


@pytest.fixture(autouse=True)
def _без_ключей_роутера_компьютера(monkeypatch):
    for имя in list(os.environ):
        if имя.startswith(_РОУТЕР_ИЗ_ОКРУЖЕНИЯ_ПРЕФИКСЫ) or имя in _РОУТЕР_ИЗ_ОКРУЖЕНИЯ_ИМЕНА:
            monkeypatch.delenv(имя, raising=False)
    yield


@pytest.fixture(autouse=True)
def _сброс_общей_памяти_api():
    """18.11.2026: тест оставлял закрытую Memory в padam.api._state, следующий подхватывал её
    («Cannot operate on a closed database», зависело от порядка). После каждого теста общее состояние сбрасывается."""
    yield
    try:
        from padam import api as _api
        st = getattr(_api, "_state", None)
        if isinstance(st, dict) and st.get("memory") is not None:
            st["memory"] = None
    except Exception:
        pass
    try:
        from padam import mcp_server as _mcp
        _mcp._memory = None          # то же у MCP-сервера: следующий тест не пишет в базу предыдущего
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _свой_журнал_казны(tmp_path, monkeypatch):
    """18.11.2026, аудит фазы 3 FA-06: окно пополнений казны хранится в файле. Каждому тесту — свой файл,
    чтобы тесты не делили предел и не писали в домашнюю папку пользователя."""
    monkeypatch.setenv("PADAM_TREASURY_LOG", str(tmp_path / "treasury_topup_log.json"))


# 23.11.2026, Лицензия PADAM 1.0: входы в Заработок требуют согласия (terms_gate.require_terms_accepted).
# Тесты Заработка проверяют саму работу бирж и автопилота, а не окно согласия, поэтому для них подменяется
# только terms_gate.earning_gate; сама проверка require_terms_accepted не подменяется нигде.
# Настоящие ворота проверяет файл из _НАСТОЯЩИЕ_ВОРОТА — там подмены нет.
_НАСТОЯЩИЕ_ВОРОТА = {"test_earning_terms_gate_2311.py"}


@pytest.fixture(autouse=True)
def _согласие_для_тестов_заработка(request, monkeypatch):
    if request.node.path.name in _НАСТОЯЩИЕ_ВОРОТА:
        yield
        return
    from padam import terms_gate
    monkeypatch.setattr(terms_gate, "earning_gate", lambda memory: {"accepted": True})
    yield
