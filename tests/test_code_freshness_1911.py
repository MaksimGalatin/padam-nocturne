# -*- coding: utf-8 -*-
"""19.11.2026: окно владельца показывало код, запущенный до выкатки. Отпечаток кода при старте vs файлы на диске."""
import os
import time

from padam import code_freshness as cf
from padam import studio


def test_свежий_код_не_устаревший():
    assert cf.status()["stale"] is False


def test_изменение_файла_на_диске_даёт_stale(monkeypatch):
    monkeypatch.setattr(cf, "LOADED", "0" * 16)
    assert cf.status()["stale"] is True


def test_маршрут_только_владельцу_и_баннер_на_4_языках():
    from padam import api
    assert "/api/v2/code-version" in api.OWNER_GET
    src = open(studio.__file__, encoding="utf-8").read()
    assert src.count('"code_stale":') == 4
    assert "checkCodeFresh" in src and "att-aifasec-seal" in src
