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
