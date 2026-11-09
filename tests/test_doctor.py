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


def test_server_names_switched_off_protection_on_stderr_only(tmp_path):
    import os
    окружение = {к: в for к, в in os.environ.items() if not к.startswith("PADAM_")}
    окружение.update({"PADAM_DB": str(tmp_path / "s.db"), "PADAM_MCP_TRUST_WRITES": "1",
                      "OLLAMA_URL": "http://127.0.0.1:9", "PYTHONIOENCODING": "utf-8"})
    r = subprocess.run([sys.executable, "-m", "padam.mcp_server"], input=b"", capture_output=True, env=окружение,
                       timeout=60)
    assert b"PADAM_MCP_TRUST_WRITES=1" in r.stderr
    assert r.stdout == b""                                      # stdout занят протоколом — туда ни строки
