"""Маскировка секретов не должна быть квадратичной по длине слова.

16.11.2026: шаблон _KEYED в padam/safety.py с ленивым префиксом имени
перезапускался с каждой позиции длинного «слова» — 31 400 символов
обрабатывались 153,8 с (одна заметка занимала сервер на минуты).
Якорь начала слова сделал время линейным: те же 31 400 символов — ~30 мс.
"""
import time

from padam import safety


def _ms(text: str) -> float:
    t0 = time.perf_counter()
    safety.redact(text)
    return (time.perf_counter() - t0) * 1000.0


def test_redact_long_word_is_linear():
    small = ("pay " * 200) + ("to " * 200) + ("a" * 3000)
    big = ("pay " * 200) + ("to " * 200) + ("a" * 30000)
    # с запасом под нагруженную машину: до правки big шёл ~150 000 мс
    assert _ms(big) < 3000.0
    # рост на порядок длины не должен давать рост на два порядка времени
    assert _ms(big) < 40 * max(_ms(small), 1.0)


def test_redact_keyed_still_masks():
    out, counts = safety.redact("DB_PASSWORD=Qw3rty!2345678 and client_secret: abcdEFGH12345678")
    assert "Qw3rty!2345678" not in out
    assert "abcdEFGH12345678" not in out
    assert counts
