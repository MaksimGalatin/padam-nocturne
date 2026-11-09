"""Локальная модель векторов в процессе (0.4.0, дополнение [embed]): выбирается, помечается и не ломает старые записи."""

import numpy as np
import pytest

from padam import config, embeddings

model2vec = pytest.importorskip("model2vec")


@pytest.fixture
def local(monkeypatch):
    monkeypatch.setattr(config, "EMBEDDER", "model2vec")
    monkeypatch.setattr(embeddings, "_local", None)
    monkeypatch.setattr(embeddings, "_local_failed", False)
    if embeddings._local_model() is None:
        pytest.skip("model2vec установлен, но модель не загрузилась (нет сети при первой загрузке)")
    return embeddings


def test_local_model_is_used_labelled_and_normalised(local):
    assert local.backend() == "model2vec"
    assert local.метка_модели().startswith("model2vec:")
    v = local.embed("Я люблю зелёный чай без сахара")
    assert v.dtype == np.float32 and abs(float(np.linalg.norm(v)) - 1.0) < 1e-5
    assert config.similarity_threshold(local.backend()) == config.SIMILARITY_THRESHOLD_OLLAMA


def test_meaning_beats_shared_words(local):
    q = local.embed("which drink do I prefer")
    tea = local.embed("I like green tea without sugar")
    car = local.embed("my car needs new tyres")
    assert local.cosine(q, tea) > local.cosine(q, car)


def test_vectors_of_another_model_never_crash_search(local):
    старый = embeddings._builtin_embed("старая запись встроенным методом")
    новый = local.embed("новая запись локальной моделью")
    assert старый.shape != новый.shape
    assert local.cosine(старый, новый) == 0.0


def test_cached_model_loads_with_the_network_closed(local, monkeypatch):
    """Регрессия 0.4.0: модель из кэша грузится без единого выхода в сеть.

    Найдено 09.11.2026 счётчиком подключений: сама model2vec при КАЖДОМ запуске сервера ходила в huggingface.co —
    force_download по умолчанию True, а на Windows и с False её проверка кэша не находила модель (имя с обратной
    косой чертой). Для памяти, которая живёт у человека на компьютере, это лишний выход в сеть.
    """
    import socket

    import requests

    monkeypatch.setattr(embeddings, "_local", None)
    monkeypatch.setattr(embeddings, "_local_failed", False)
    попытки = []

    def запрет(self, *a, **k):
        попытки.append(a)
        raise OSError("сеть закрыта в этом тесте")

    # Перехват на трёх уровнях: сокет — новое соединение; HTTP-клиенты — запрос по соединению из пула,
    # открытому первой загрузкой в этом же процессе (на одних сокетах такой запрос не виден, проверено).
    monkeypatch.setattr(socket.socket, "connect", запрет)
    monkeypatch.setattr(socket.socket, "connect_ex", запрет)
    monkeypatch.setattr(requests.Session, "send", запрет)
    try:
        import httpx
        monkeypatch.setattr(httpx.Client, "send", запрет)
    except ImportError:
        pass
    assert embeddings._local_model() is not None
    assert embeddings.backend() == "model2vec"
    assert попытки == []


def test_builtin_stays_when_asked(monkeypatch):
    monkeypatch.setattr(config, "EMBEDDER", "builtin")
    assert embeddings.backend() == "builtin"
    assert embeddings.метка_модели().startswith("builtin:")
