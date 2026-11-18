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
