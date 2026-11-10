"""0.4.5: строгий профиль PADAM_STRICT=1 — один выключатель вместо россыпи флагов (внешний разбор 09.11.2026)."""

import os
import subprocess
import sys

import pytest

from padam import anchor, api, cli, config
from padam.memory import Memory
from padam.store import Store


def _config_в_процессе(**env):
    """Настройки читаются при импорте, поэтому проверяем их в отдельном процессе с нужным окружением."""
    окружение = {k: v for k, v in os.environ.items() if not k.startswith("PADAM_")}
    окружение.update(env)
    код = ("from padam import config as c; print(c.STRICT, c.KEEP_SECRETS, c.MCP_TRUST_WRITES, c.HOLD_EXTERNAL, "
           "c.MCP_REVIEW_ALL, sorted(c.strict_ignored()), len(c.unsafe_settings()))")
    return subprocess.run([sys.executable, "-c", код], env=окружение, capture_output=True, text=True,
                          check=True).stdout.strip()


def test_strict_overrides_every_weakening_switch():
    вывод = _config_в_процессе(PADAM_STRICT="1", PADAM_KEEP_SECRETS="1", PADAM_MCP_TRUST_WRITES="1",
                               PADAM_HOLD_EXTERNAL="0")
    assert вывод == ("True False False True True ['PADAM_HOLD_EXTERNAL=0', 'PADAM_KEEP_SECRETS=1', "
                     "'PADAM_MCP_TRUST_WRITES=1'] 0")


def test_without_strict_nothing_changes():
    assert _config_в_процессе(PADAM_KEEP_SECRETS="1") == "False True False True False [] 1"


@pytest.fixture
def база(tmp_path, monkeypatch):
    путь = tmp_path / "m.db"
    m = Memory(user_id="default", store=Store(путь))
    m.remember("Для биллинга выбрали Postgres", kind="decision")
    m.close()
    вызовы = []
    monkeypatch.setattr(anchor, "run_l3", lambda *a, **k: вызовы.append(k) or {"status": "подменено"})
    monkeypatch.delenv("PADAM_KEY_PASSPHRASE", raising=False)
    return путь, вызовы


def test_strict_refuses_unprotected_anchoring_even_with_the_flag(база, monkeypatch):
    путь, вызовы = база
    monkeypatch.setattr(config, "STRICT", True)
    assert cli.main(["--db", str(путь), "l3", "--arweave-wallet", "w.json", "--solana-keypair", "k.json",
                     "--allow-unprotected-keys"]) == 2
    assert вызовы == []


def test_strict_refuses_rest_without_token(monkeypatch, capsys):
    monkeypatch.setattr(config, "STRICT", True)
    assert api.main(["--no-token", "--port", "0"]) == 2
    assert "PADAM_STRICT" in capsys.readouterr().err


def test_doctor_names_the_profile(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "STRICT", True)
    cli.main(["--db", str(tmp_path / "d.db"), "doctor"])
    assert "PADAM_STRICT=1" in capsys.readouterr().out
