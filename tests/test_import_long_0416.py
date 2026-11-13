"""0.4.16: импорт обрезает запись до маскировки.

Маскировка растёт сверхлинейно на сплошной строке (замер 13.11.2026: 80 000 знаков — 2,2 с, 320 000 — 32 с), а
`padam import` и импорт через REST API (тело до 10 МБ) маскировали запись целиком и только потом резали до
MAX_CONTENT_CHARS. Одна запись в миллионы знаков в файле выгрузки подвешивала импорт на десятки минут.
"""
import json
import random
import string
import time

from padam import config


def _выгрузка(tmp_path):
    from padam.memory import Memory
    from padam.store import Store
    mem = Memory(user_id="test", store=Store(tmp_path / "m.db"))
    mem.remember("Our office is in Albuquerque")
    return json.loads(json.dumps(mem.export()))


def test_длинная_запись_импортируется_быстро_и_обрезается(tmp_path):
    from padam.memory import Memory
    from padam.store import Store
    выгрузка = _выгрузка(tmp_path)
    r = random.Random(13)
    длинная = "".join(r.choice(string.ascii_letters + string.digits + "+/") for _ in range(1_000_000))
    выгрузка["memory"][0]["content"] = длинная
    другая = Memory(user_id="test", store=Store(tmp_path / "n.db"))
    t0 = time.time()
    assert другая.import_(выгрузка) == 1
    assert time.time() - t0 < 30, "импорт одной длинной записи должен идти секунды, а не минуты"
    текст = другая.store.one("SELECT content FROM memory")["content"]
    assert len(текст) <= config.MAX_CONTENT_CHARS


def test_ключ_у_границы_обрезки_замаскирован(tmp_path):
    from padam.memory import Memory
    from padam.store import Store
    выгрузка = _выгрузка(tmp_path)
    ключ = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # выдуманный, нужной формы
    # Ключ начинается за 20 знаков до предела и заходит за него: после обрезки его начало не должно остаться открытым.
    выгрузка["memory"][0]["content"] = "x " * ((config.MAX_CONTENT_CHARS - 20) // 2) + ключ + " хвост" * 50_000
    другая = Memory(user_id="test", store=Store(tmp_path / "n.db"))
    другая.import_(выгрузка)
    текст = другая.store.one("SELECT content FROM memory")["content"]
    assert "ghp_A1b2" not in текст
