# -*- coding: utf-8 -*-
"""B6 Plugin SDK: загрузка только после одобрения владельца, отпечаток кода, права только memory:read, фасад чтения."""
import json

import pytest

from padam import plugins
from padam.memory import Memory
from padam.store import Store

КОД = '''
def register(api):
    def найти(args):
        return [r["content"] for r in api.search(args.get("q", ""), 3)]
    api.register_tool("find", найти, "поиск по памяти")
'''


@pytest.fixture
def m(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_PLUGINS_DIR", str(tmp_path / "plugins"))
    mem = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    mem.remember("Папа пьёт чай, не кофе", kind="fact")
    return mem


def _плагин(name="tea-finder", caps=("memory:read",), code=КОД):
    d = plugins.plugins_dir() / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.json").write_text(json.dumps({"name": name, "version": "0.1.0", "entry": "plugin.py",
                                               "capabilities": list(caps)}), encoding="utf-8")
    (d / "plugin.py").write_text(code, encoding="utf-8")
    return d


def test_без_одобрения_не_грузится(m):
    _плагин()
    assert plugins.load_approved(m) == {}
    assert plugins.list_plugins()[0]["state"] == "not_approved"


def test_после_одобрения_инструмент_работает_и_читает_память(m):
    _плагин()
    plugins.approve("tea-finder")
    assert plugins.list_plugins()[0]["state"] == "approved"
    out = plugins.run_tool(m, "tea-finder.find", {"q": "чай"})
    assert any("чай" in x for x in out)


def test_изменённый_после_одобрения_код_не_грузится(m):
    d = _плагин()
    plugins.approve("tea-finder")
    (d / "plugin.py").write_text(КОД + "\n# подмена\n", encoding="utf-8")
    assert plugins.list_plugins()[0]["state"] == "changed_since_approval"
    with pytest.raises(KeyError):
        plugins.run_tool(m, "tea-finder.find", {"q": "чай"})


def test_право_записи_отклоняется(m):
    _плагин(name="writer", caps=("memory:read", "memory:write"))
    with pytest.raises(ValueError):
        plugins.approve("writer")
    assert plugins.list_plugins()[0]["state"] == "invalid"


def test_фасад_не_отдаёт_саму_память(m):
    api = plugins.PluginAPI("x", lambda q, n: [])
    assert not hasattr(api, "memory") and not hasattr(api, "__dict__")
    рез = plugins.load_approved(m)
    assert рез == {}


def test_отзыв_одобрения(m):
    _плагин()
    plugins.approve("tea-finder")
    assert plugins.revoke("tea-finder")["was_approved"] is True
    assert plugins.load_approved(m) == {}
