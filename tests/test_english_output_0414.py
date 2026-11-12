# -*- coding: utf-8 -*-
"""0.4.14: всё, что PADAM показывает человеку, — на его языке; при PADAM_LANG=en в выводе нет кириллицы.

До 0.4.14 сообщения об ошибках (доли наследования, пароль ключей, слой Arweave/Solana, выгрузка) и поле
выгрузки «факт_ключ» оставались русскими при любом языке. Шаблоны распознавания русских атак и имена
колонок базы — не вывод, они остаются русскими.
"""
import json
import re

import pytest

КИР = re.compile(r"[А-Яа-яЁё]")


def _ошибка(f):
    try:
        f()
    except Exception as e:  # noqa: BLE001 — нужен текст любой ошибки
        return str(e)
    raise AssertionError("ожидалась ошибка")


@pytest.mark.parametrize("язык,кириллица", [("en", False), ("ru", True)])
def test_errors_follow_language(monkeypatch, tmp_path, язык, кириллица):
    monkeypatch.setenv("PADAM_LANG", язык)
    from padam import anchor, keyvault, legacy
    from padam.memory import Memory
    from padam.store import Store

    mem = Memory(user_id="test", store=Store(tmp_path / "m.db"))
    тексты = [
        _ошибка(lambda: legacy.split(b"", 2, 3)),
        _ошибка(lambda: legacy.split(b"x", 1, 3)),
        _ошибка(lambda: legacy.combine(["not-a-share"])),
        _ошибка(lambda: keyvault.enable(mem, "")),
        _ошибка(lambda: anchor.merkle_root([])),
        _ошибка(lambda: mem.import_({"format": "nonsense"})),
    ]
    for т in тексты:
        assert bool(КИР.search(т)) is кириллица, т


def test_export_has_no_cyrillic_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("PADAM_LANG", "en")
    from padam.memory import Memory
    from padam.store import Store

    mem = Memory(user_id="test", store=Store(tmp_path / "m.db"))
    mem.remember("Our office is in Albuquerque")
    выгрузка = mem.export()
    for запись in выгрузка["memory"]:
        assert not any(КИР.search(k) for k in запись), sorted(запись)
        assert "fact_key" in запись
    # Обратная загрузка выгрузки нового формата работает.
    другая = Memory(user_id="test", store=Store(tmp_path / "n.db"))
    assert другая.import_(json.loads(json.dumps(выгрузка))) == len(выгрузка["memory"])
