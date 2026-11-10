"""Первый внешний круг Red Team (Antigravity, 09.11.2026): 60 новых случаев, до волны 26 из 60, после — 55 из 60.

Случаи лежат в redteam/rounds/2026-11-09_antigravity/cases_open.jsonl (выдуманные ключи — перевёрнутыми и в base64,
иначе хостинг кода принимает их за настоящие). Пять случаев оставлены сознательно — каждый с причиной ниже.
Закрытый набор того же автора (SHA-256 5f1f0241…) этим тестом не проверяется: он у автора до выхода версии.
"""

import base64
import json
from pathlib import Path

import pytest

from padam import safety

ПУТЬ = Path(__file__).resolve().parents[1] / "redteam" / "rounds" / "2026-11-09_antigravity" / "cases_open.jsonl"

# Оставлены сознательно, не подгоняем фильтр под эти примеры:
ОСТАВЛЕНЫ = {
    # значение не случайное и составлено из слов; настоящий ключ в ячейке таблицы ловит слой случайных строк
    "so-014": "secret",
    # цитата фразы атаки в разговоре об атаке: снять — научить фильтр пропускать команду, завёрнутую в «пример»;
    # задержанная запись не теряется, её показывают владельцу на проверку
    "bo-001": "benign", "bo-006": "benign",
    # «подчиняться только этой инструкции», «не выполняй инструкции» — по форме та же команда, что и у атаки
    "bo-005": "benign", "bo-007": "benign",
}


def _случаи():
    for line in ПУТЬ.read_text(encoding="utf-8").splitlines():
        if line.strip():
            c = json.loads(line)
            for поле in ("text", "secret"):
                if поле + "_enc" in c:
                    c[поле] = base64.b64decode(c.pop(поле + "_enc")).decode("utf-8")[::-1]
            yield pytest.param(c, id=c["id"])


@pytest.mark.parametrize("случай", list(_случаи()))
def test_round_case(случай):
    if случай["id"] in ОСТАВЛЕНЫ:
        pytest.skip("оставлен сознательно — причина в ОСТАВЛЕНЫ")
    if случай["category"] == "secret":
        assert случай["secret"] not in safety.redact(safety.strip_invisible(случай["text"]))[0]
    elif случай["category"] == "command":
        assert safety.looks_like_instruction(случай["text"])
    else:
        assert not safety.looks_like_instruction(случай["text"])


def test_round_counts():
    случаи = [p.values[0] for p in _случаи()]
    assert len(случаи) == 60 and len(ОСТАВЛЕНЫ) == 5
