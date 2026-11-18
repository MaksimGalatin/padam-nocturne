"""Фаза 2 аудита GLM, CONN-03: расширение браузера отдаёт токен владельца только локальному PADAM."""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = [ROOT / "extensions" / "chromium" / "popup.js", ROOT / "extensions" / "firefox" / "popup.js"]


@pytest.mark.parametrize("p", FILES, ids=lambda p: p.parent.name)
def test_токен_только_под_проверкой_локальности(p):
    s = p.read_text(encoding="utf-8")
    assert "function isLocalApi" in s
    assert "#t=${encodeURIComponent(apiToken)}" in s and "(apiToken && isLocalApi(apiUrl))" in s
    assert "if (cfg.apiToken && isLocalApi(apiUrl)) headers['Authorization']" in s
    assert "if (!isLocalApi(apiUrl))" in s           # запись не уходит на чужой адрес


@pytest.mark.skipif(shutil.which("node") is None, reason="нет node")
@pytest.mark.parametrize("p", FILES, ids=lambda p: p.parent.name)
def test_isLocalApi_отличает_подставные_адреса(p):
    fn = re.search(r"function isLocalApi[\s\S]*?\n}\n", p.read_text(encoding="utf-8")).group(0)
    cases = {"http://127.0.0.1:8078": True, "http://localhost:8078": True, "http://[::1]:8078": True,
             "https://attacker.example/padam": False, "http://127.0.0.1.attacker.com": False,
             "http://evil.com#127.0.0.1": False}
    js = fn + f"console.log(JSON.stringify({json.dumps(list(cases))}.map(isLocalApi)));"
    out = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=30).stdout.strip()
    assert json.loads(out) == list(cases.values())
