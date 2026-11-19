# -*- coding: utf-8 -*-
"""18.11.2026: «плавающий» тест Совета шести голосов оказался настоящей ошибкой.

Водяной знак цепи аудита хранился в словаре по id(store). Python выдаёт тот же id новому объекту после сборки
мусора, и свежая база наследовала знак умершей: проверка цепи говорила «цепь и якорь стёрты», голос PIXEL в
Совете отказывал. Тот же класс был у ключа владельца и секретов узла для баз в памяти и у флагов «схема создана».
"""
import gc

from padam import audit_chain, digital_stores, integrity, live_mesh, platform_wizard
from padam.memory import Memory
from padam.store import Store


def test_свежая_база_не_наследует_знак_умершей():
    for _ in range(60):          # без починки id повторяется почти сразу, и проверка падает
        старая = Memory(user_id="u", store=Store(":memory:"))
        audit_chain.append_audit(старая, "test", {"n": 1})
        del старая
        gc.collect()
        новая = Memory(user_id="u", store=Store(":memory:"))
        итог = audit_chain.verify_audit_chain(новая)
        assert итог["ok"], итог


def test_нет_глобальных_словарей_по_id():
    for модуль, имя in ((audit_chain, "_MEM_AUDIT_WATERMARKS"), (integrity, "_ключи_в_памяти"),
                        (live_mesh, "_NODE_SECRETS_MEM"), (digital_stores, "_INITIALIZED_DBS"),
                        (platform_wizard, "_INITIALIZED_WIZ_DBS")):
        assert not hasattr(модуль, имя), f"{модуль.__name__}.{имя} снова ключуется по id()"


def test_ключ_владельца_в_памяти_свой_у_каждой_базы():
    a, b = Store(":memory:"), Store(":memory:")
    ka, создан_a = integrity.owner_key(a)
    assert создан_a and integrity.owner_key(a) == (ka, False)
    kb, создан_b = integrity.owner_key(b)
    assert создан_b and kb != ka


def test_во_всём_пакете_нет_кэшей_по_id_объекта():
    """CI 19.11 (Python 3.10): почтовый модуль снова завёл кэш по id(conn) — таблица не создавалась в новой базе.
    Тот же класс нашёлся в ключах маяка и сиблингов. Страж ловит любой id(conn|store|memory...) в коде пакета."""
    import pathlib
    import re
    корень = pathlib.Path(__file__).resolve().parents[1] / "padam"
    найдено = []
    for f in корень.glob("*.py"):
        for n, строка in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if строка.lstrip().startswith("#"):
                continue
            if re.search(r"id\((conn|store|self\.store|memory\.store|memory|mem|self\.conn)\)", строка):
                найдено.append(f"{f.name}:{n}")
    assert not найдено, найдено
