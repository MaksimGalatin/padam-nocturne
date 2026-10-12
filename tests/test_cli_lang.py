"""Язык командной строки: PADAM_LANG=en|ru и выбор по языку системы (12.10.2026)."""

import os
import subprocess
import sys

from padam import i18n


def run(db, lang, *args):
    env = dict(os.environ, PADAM_LANG=lang, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, "-m", "padam", "--db", str(db), *args],
                       capture_output=True, env=env, timeout=120)
    return r.returncode, r.stdout.decode("utf-8", "replace")


def test_cli_speaks_english(tmp_path):
    db = tmp_path / "en.db"
    code, out = run(db, "en", "remember", "Answer briefly", "--kind", "preference")
    assert code == 0 and "remembered" in out
    code, out = run(db, "en", "stats")
    assert code == 0 and "Active records" in out and "Активных" not in out
    code, out = run(tmp_path / "empty.db", "en", "recall", "anything at all")
    assert code == 0 and "Nothing found." in out
    code, out = run(tmp_path / "empty.db", "en", "sleep")
    assert code == 0 and "episode buffer is empty" in out


def test_cli_speaks_russian(tmp_path):
    db = tmp_path / "ru.db"
    code, out = run(db, "ru", "remember", "Отвечать кратко", "--kind", "preference")
    assert code == 0 and "запомнено" in out
    code, out = run(db, "ru", "stats")
    assert code == 0 and "Активных записей" in out


def test_help_is_english(tmp_path):
    code, out = run(tmp_path / "h.db", "en", "--help")
    assert code == 0 and "store a memory" in out and "PADAM_LANG" in out


def test_language_choice(monkeypatch):
    monkeypatch.setenv("PADAM_LANG", "ru")
    assert i18n.lang() == "ru"
    monkeypatch.setenv("PADAM_LANG", "en")
    assert i18n.lang() == "en"
    monkeypatch.delenv("PADAM_LANG")
    for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LANG", "ru_RU.UTF-8")
    assert i18n.lang() == "ru"
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    assert i18n.lang() == "en"
