# -*- coding: utf-8 -*-
"""B5: справочник docs/site не отстаёт от кода — каждая команда CLI есть на всех 4 языках, с описанием на языке страницы."""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gen_reference_cli as g  # noqa: E402

КИР = re.compile(r"[А-Яа-яЁё]")
ХАНЬ = re.compile(r"[一-鿿]")


@pytest.fixture(scope="module")
def cmds():
    c, _ = g.cli_commands_and_help("en")
    assert len(c) >= 70
    return c


@pytest.mark.parametrize("lang", ["en", "ru", "es", "zh"])
def test_каждая_команда_cli_есть_в_справочнике(lang, cmds):
    text = (g.SITE / lang / "reference.html").read_text(encoding="utf-8")
    нет = [c for c in cmds if not re.search(r"<code>[^<]*\b" + re.escape(c) + r"\b", text)]
    assert not нет, f"{lang}: нет в справочнике {нет} — запустите python scripts/gen_reference_cli.py"


@pytest.mark.parametrize("lang", ["en", "ru", "es", "zh"])
def test_описания_в_разделе_на_языке_страницы(lang):
    text = (g.SITE / lang / "reference.html").read_text(encoding="utf-8")
    блок = re.search(re.escape(g.START) + r"(.*?)" + re.escape(g.END), text, re.S).group(1)
    описания = re.findall(r"</code></td><td>([^<]*)</td>", блок)
    assert описания and all(d.strip() for d in описания)
    for d in описания:
        if lang == "ru":
            assert КИР.search(d), d
        elif lang == "zh":
            assert ХАНЬ.search(d), d
        else:
            assert not КИР.search(d), d


def test_у_каждой_команды_есть_перевод_es_zh(cmds):
    from padam.cli_help_i18n import CLI_HELP_ES, CLI_HELP_ZH
    text = (g.SITE / "en" / "reference.html").read_text(encoding="utf-8")
    в_разделе = re.findall(r"<code>([^<]+)</code>", re.search(re.escape(g.START) + r"(.*?)" + re.escape(g.END), text, re.S).group(1))
    assert set(в_разделе) <= set(CLI_HELP_ES) and set(в_разделе) <= set(CLI_HELP_ZH)
