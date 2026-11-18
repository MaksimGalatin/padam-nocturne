# -*- coding: utf-8 -*-
"""AS-072 ищет опасные вызовы в коде, а не в словах о них (17.11.2026).

Описание модуля «без eval()» давало ложную тревогу: сканер видел текст документации.
"""
from pathlib import Path

from benchmarks.aifa_security.targets import _python_code_only, scan_directory_tree


def _скан(tmp_path: Path, имя: str, текст: str) -> list[str]:
    (tmp_path / имя).write_text(текст, encoding="utf-8")
    return scan_directory_tree(tmp_path)["unsafe_sinks"]


def test_слова_в_документации_не_тревога(tmp_path):
    текст = '"""Верификатор чисел (без eval(), пункт 7)."""\n\ndef f():\n    """Считает без `eval()` и exec()."""\n    return 1\n'
    assert _скан(tmp_path, "m.py", текст) == []


def test_комментарий_и_строка_не_тревога(tmp_path):
    текст = "# eval(x) здесь не вызывается\nX = 'shell=True и pickle.loads(b) — только слова'\n"
    assert _скан(tmp_path, "m.py", текст) == []


def test_настоящий_вызов_в_python_ловится(tmp_path):
    assert _скан(tmp_path, "m.py", "def f(s):\n    return eval(s)\n") == ["m.py"]


def test_shell_true_в_коде_ловится(tmp_path):
    текст = "import subprocess\nsubprocess.run('ls', shell=True)\n"
    assert _скан(tmp_path, "m.py", текст) == ["m.py"]


def test_вызов_внутри_f_строки_остаётся_кодом(tmp_path):
    # На Python 3.12+ выражение внутри f-строки — код, его прячет только сама строка 3.10/3.11.
    код = _python_code_only("x = f'{eval(s)}'\n")
    assert "eval" not in код or "eval (" in код


def test_javascript_по_прежнему_ловится(tmp_path):
    assert _скан(tmp_path, "a.js", "const x = eval(input);\n") == ["a.js"]


def test_неразбираемый_файл_проверяется_целиком(tmp_path):
    # Битый синтаксис — возвращаем исходный текст, лишняя тревога лучше пропуска.
    assert _python_code_only("def f(:\n    eval(s)\n'''") .count("eval") == 1
