"""0.4.1: настоящая заливка в Arweave не идёт, пока ключи записей не защищены паролем.

Совет внешнего разбора 09.11.2026: без protect-keys ключи лежат в файле базы открыто, а то, что ушло в Arweave,
остаётся там навсегда — у кого файл базы, тот прочтёт всё. Раньше это было только советом в README.
"""

import pytest

from padam import anchor, cli
from padam.memory import Memory
from padam.store import Store


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


def _l3(путь, *доп):
    return cli.main(["--db", str(путь), "l3", "--arweave-wallet", "w.json", "--solana-keypair", "k.json", *доп])


def test_real_anchoring_is_refused_without_passphrase(база, capsys):
    путь, вызовы = база
    assert _l3(путь) == 2
    assert вызовы == []
    assert "protect-keys" in capsys.readouterr().out


def test_explicit_flag_and_dry_run_still_work(база):
    путь, вызовы = база
    assert _l3(путь, "--allow-unprotected-keys") == 0
    assert _l3(путь, "--dry-run") == 0
    assert len(вызовы) == 2 and вызовы[1]["dry_run"] is True


def test_protected_keys_anchor_without_the_flag(база, monkeypatch):
    путь, вызовы = база
    monkeypatch.setenv("PADAM_KEY_PASSPHRASE", "correct-horse-battery-staple-9")
    assert cli.main(["--db", str(путь), "protect-keys"]) == 0
    assert _l3(путь) == 0
    assert len(вызовы) == 1


def test_stats_shows_the_state_of_record_keys(tmp_path, monkeypatch):
    monkeypatch.delenv("PADAM_KEY_PASSPHRASE", raising=False)
    m = Memory(user_id="default", store=Store(tmp_path / "s.db"))
    m.remember("запись", kind="fact")
    ключи = m.stats()["record_keys"]
    assert ключи == {"passphrase_protected": False, "plain": 0}
    m.close()
