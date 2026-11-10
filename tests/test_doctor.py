"""0.4.2: padam doctor и предупреждения о выключенной защите (внешний разбор 09.11.2026)."""

import subprocess
import sys

from padam import cli, config
from padam.memory import Memory
from padam.store import Store


def test_doctor_reports_unprotected_keys_and_unsafe_settings(tmp_path, monkeypatch, capsys):
    путь = tmp_path / "m.db"
    Memory(user_id="default", store=Store(путь)).close()
    monkeypatch.setattr(config, "KEEP_SECRETS", True)
    assert cli.main(["--db", str(путь), "doctor"]) == 1
    out = capsys.readouterr().out
    assert "PADAM_KEEP_SECRETS=1" in out
    assert "protect-keys" in out


def test_doctor_is_clean_when_keys_are_protected(tmp_path, monkeypatch, capsys):
    путь = tmp_path / "m.db"
    Memory(user_id="default", store=Store(путь)).close()
    monkeypatch.setenv("PADAM_KEY_PASSPHRASE", "correct-horse-battery-staple-9")
    assert cli.main(["--db", str(путь), "protect-keys"]) == 0
    capsys.readouterr()
    assert cli.main(["--db", str(путь), "doctor"]) == 0, capsys.readouterr().out


def test_api_token_reaches_a_log_file_at_once(tmp_path):
    """Регрессия 0.4.2 → 0.4.3: при выводе не в терминал (файл, журнал службы) токен застревал в буфере —
    0 байт в журнале через 8 с, а сервер уже ждал запросы с этим токеном."""
    import os
    import re
    import time
    журнал = tmp_path / "api.log"
    окружение = {к: в for к, в in os.environ.items() if not к.startswith("PADAM_")}
    окружение.update({"PADAM_DB": str(tmp_path / "a.db"), "OLLAMA_URL": "http://127.0.0.1:9", "PADAM_LANG": "en"})
    with open(журнал, "w") as f:
        п = subprocess.Popen([sys.executable, "-m", "padam", "api", "--port", "0"], stdout=f, stderr=f, env=окружение)
    try:
        for _ in range(100):
            if re.search(r"Token for this run: \S{24,}", журнал.read_text(errors="replace")):
                break
            time.sleep(0.1)
        assert re.search(r"Token for this run: \S{24,}", журнал.read_text(errors="replace")), журнал.read_text()
    finally:
        п.kill()
        п.wait()


def test_api_refuses_the_placeholder_token(capsys, monkeypatch):
    from padam import api

    def не_поднимать(*a, **k):                 # если отказа нет, тест падает, а не ждёт запросов вечно
        raise AssertionError("сервер начал подниматься с заглушкой вместо токена")

    monkeypatch.setattr(api, "ThreadingHTTPServer", не_поднимать)
    assert api.main(["--port", "0", "--token", "REPLACE_WITH_A_LONG_RANDOM_TOKEN"]) == 2
    assert api.main(["--port", "0", "--token", "short"]) == 2


def test_server_names_switched_off_protection_on_stderr_only(tmp_path):
    import os
    окружение = {к: в for к, в in os.environ.items() if not к.startswith("PADAM_")}
    окружение.update({"PADAM_DB": str(tmp_path / "s.db"), "PADAM_MCP_TRUST_WRITES": "1",
                      "OLLAMA_URL": "http://127.0.0.1:9", "PYTHONIOENCODING": "utf-8"})
    r = subprocess.run([sys.executable, "-m", "padam.mcp_server"], input=b"", capture_output=True, env=окружение,
                       timeout=60)
    assert b"PADAM_MCP_TRUST_WRITES=1" in r.stderr
    assert r.stdout == b""                                      # stdout занят протоколом — туда ни строки
