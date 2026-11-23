# -*- coding: utf-8 -*-
"""Кэш видов текста — свой у каждого потока (23.11.2026).

Studio обслуживает запросы в нескольких потоках. Раньше кэш был общим на процесс: при двух одновременных записях
вторая на выходе возвращала кэш первой, и он оставался в памяти навсегда вместе с исходным текстом до маски.
"""
import threading

from padam import safety


def test_кэш_не_переживает_перекрытые_записи_в_двух_потоках():
    первая_внутри = threading.Event()
    вторая_внутри = threading.Event()
    первая_вышла = threading.Event()
    после: dict[str, object] = {}

    def первая():
        with safety.одна_запись():
            safety.looks_like_instruction("секрет первой записи")
            первая_внутри.set()
            вторая_внутри.wait(5)
        первая_вышла.set()
        после["первая"] = safety._КЭШ_ВАРИАНТОВ

    def вторая():
        первая_внутри.wait(5)
        with safety.одна_запись():
            safety.looks_like_instruction("секрет второй записи")
            # кэш второй записи не видит текст первой
            после["вторая_видит_первую"] = "секрет первой записи" in (safety._КЭШ_ВАРИАНТОВ or {})
            вторая_внутри.set()
            первая_вышла.wait(5)
        после["вторая"] = safety._КЭШ_ВАРИАНТОВ

    потоки = [threading.Thread(target=первая), threading.Thread(target=вторая)]
    for п in потоки:
        п.start()
    for п in потоки:
        п.join(10)

    assert после["вторая_видит_первую"] is False
    assert после["первая"] is None
    assert после["вторая"] is None
    assert safety._КЭШ_ВАРИАНТОВ is None


def test_сброс_кэша_в_текущем_потоке():
    with safety.одна_запись():
        safety.looks_like_instruction("текст")
        assert "текст" in safety._КЭШ_ВАРИАНТОВ
        safety.сбросить_кэш_вариантов()
        assert safety._КЭШ_ВАРИАНТОВ is None
    assert safety._КЭШ_ВАРИАНТОВ is None
