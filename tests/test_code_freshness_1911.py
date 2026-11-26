# -*- coding: utf-8 -*-
"""19.11.2026: окно владельца показывало код, запущенный до выкатки. Отпечаток кода при старте vs файлы на диске."""
import os
import time

from padam import code_freshness as cf
from padam import studio


def test_свежий_код_не_устаревший():
    assert cf.status()["stale"] is False


def test_изменение_файла_на_диске_даёт_stale(monkeypatch):
    monkeypatch.setenv("PADAM_CODE_SETTLE_S", "0")
    monkeypatch.setattr(cf, "LOADED", "0" * 16)
    assert cf.status()["stale"] is True


def test_пока_файлы_меняются_перезапуска_нет(monkeypatch):
    """25.11.2026: серия замен файлов давала серию перезапусков Studio (11–22 с ожидания). Ждём тишины."""
    monkeypatch.setattr(cf, "LOADED", "0" * 16)
    monkeypatch.setenv("PADAM_CODE_SETTLE_S", "20")
    monkeypatch.setattr(cf, "_свежайшая_правка", lambda: time.time() - 3)
    st = cf.status()
    assert st["stale"] is False and st["settling"] is True
    monkeypatch.setattr(cf, "_свежайшая_правка", lambda: time.time() - 25)
    st = cf.status()
    assert st["stale"] is True and st["settling"] is False


def test_маршрут_только_владельцу_и_баннер_на_4_языках():
    from padam import api
    assert "/api/v2/code-version" in api.OWNER_GET
    src = open(studio.__file__, encoding="utf-8").read()
    assert src.count('"code_stale":') == 4
    assert "checkCodeFresh" in src and "att-aifasec-seal" in src
