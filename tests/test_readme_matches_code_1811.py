# README обязан совпадать с кодом (18.11.2026, слово Папы: «какого хуя ВСЁ это сразу не пишется и не исправляется?!»).
# Падает, если документация отстала: ОС в CI, адреса прослушивания, устаревшие числа экранов, таблица сети на 4 языках.
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
READMES = {"en": "README.md", "ru": "README.ru.md", "es": "README.es.md", "zh": "README.zh.md"}
NET_HEADING = {"en": "Where PADAM listens on the network", "ru": "Где PADAM слушает сеть",
               "es": "Dónde escucha PADAM en la red", "zh": "PADAM 在网络上监听哪里"}


def _read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_ci_os_в_readme_совпадают_с_workflow():
    wf = _read(".github/workflows/tests.yml")
    oses = set(re.findall(r"(ubuntu|windows|macos)-latest", wf))
    assert oses, "в tests.yml не найдены ОС"
    en = _read("README.md")
    m = re.search(r"CI runs the suite on ([^.]+?) with Python", en)
    assert m, "в README.md нет строки про CI"
    named = {w.lower() for w in re.findall(r"Ubuntu|Windows|macOS", m.group(1))}
    assert named == {"ubuntu" if o == "ubuntu" else o for o in oses}, (named, oses)


def test_нет_зашитого_числа_экранов_studio():
    for lg, f in READMES.items():
        t = _read(f)
        assert not re.search(r"10-screen|10 экран|10 pantallas|10 屏", t), (lg, "устаревшее число экранов")


def test_таблица_сети_на_4_языках_и_адреса_из_кода():
    api = _read("padam/api.py")
    mcp = _read("padam/mcp_server.py")
    # Studio: адрес зашит — с 18.11 сокет создаёт _bind_browser_safe (обходит порты, запрещённые браузером)
    assert 'ThreadingHTTPServer(("127.0.0.1", port), handler)' in api
    assert 'srv = _bind_browser_safe(port, Handler)' in api
    assert 'p.add_argument("--host", default="127.0.0.1")' in api                 # REST API по умолчанию
    assert 'hp.add_argument("--host", default="127.0.0.1")' in mcp                # MCP по HTTP по умолчанию
    for lg, f in READMES.items():
        t = _read(f)
        assert NET_HEADING[lg] in t, (lg, "нет таблицы сети")
        assert "127.0.0.1:8079" in t and "PADAM_LAN_DISCOVERY" in t, lg
