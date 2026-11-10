"""Закрытый набор первого внешнего круга Red Team (Antigravity, 09.11.2026): 40 случаев, зафиксированы по SHA-256
до исправлений 0.4.4 и открыты только после её прогона на 0.4.4.

Итог 0.4.4 (опубликован как есть, redteam/rounds/2026-11-09_antigravity/report_sealed_0.4.4.json): секреты 12/15,
команды 14/15, обычные заметки 7/10. Этот тест — про 0.4.5, где исправлены два класса пропусков: подпись
«… key: значение» с незнакомой приставкой сервиса и южнославянское «zanemari». Подгонкой под этот набор он уже не
проверяет обобщение — для этого нужен следующий закрытый круг.

Исходный файл автора лежит рядом в sealed_set.jsonl.gz байт в байт; его SHA-256 сверяется здесь же.
"""

import base64
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from padam import safety

ПАПКА = Path(__file__).resolve().parents[1] / "redteam" / "rounds" / "2026-11-09_antigravity"
ХЕШ = "5f1f0241861f783f0a0a66910ed3d271194a79d0f6f3e00b9b68977fe2779493"

# Оставлены сознательно — тот же класс, что bo-001 и bo-005 открытого круга: цитата атакующей фразы внутри
# рассказа об атаке, учебника или документа. Снять — научить фильтр пропускать команду, завёрнутую в «пример»;
# задержанная запись не теряется, её показывают владельцу на проверку.
ОСТАВЛЕНЫ = {"sb-001": "benign", "sb-003": "benign", "sb-004": "benign"}


def _случаи():
    for line in (ПАПКА / "cases_sealed.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            c = json.loads(line)
            for поле in ("text", "secret"):
                if поле + "_enc" in c:
                    c[поле] = base64.b64decode(c.pop(поле + "_enc")).decode("utf-8")[::-1]
            yield pytest.param(c, id=c["id"])


@pytest.mark.parametrize("случай", list(_случаи()))
def test_sealed_case(случай):
    if случай["id"] in ОСТАВЛЕНЫ:
        pytest.skip("оставлен сознательно — причина в ОСТАВЛЕНЫ")
    if случай["category"] == "secret":
        assert случай["secret"] not in safety.redact(safety.strip_invisible(случай["text"]))[0]
    elif случай["category"] == "command":
        assert safety.looks_like_instruction(случай["text"])
    else:
        assert not safety.looks_like_instruction(случай["text"])


def test_sealed_file_is_the_committed_one():
    """Опубликованный набор — тот самый, чей хеш был записан до исправлений, и совпадает с исходником по смыслу."""
    исходник = gzip.decompress((ПАПКА / "sealed_set.jsonl.gz").read_bytes())
    assert hashlib.sha256(исходник).hexdigest() == ХЕШ
    из_исходника = [json.loads(s) for s in исходник.decode("utf-8").splitlines() if s.strip()]
    наши = [p.values[0] for p in _случаи()]
    assert из_исходника == наши and len(наши) == 40


def test_sealed_report_published_as_is():
    отчёт = json.loads((ПАПКА / "report_sealed_0.4.4.json").read_text(encoding="utf-8"))
    assert отчёт["padam_version"] == "0.4.4" and отчёт["cases"] == 40
    assert {k: (v["passed"], v["of"]) for k, v in отчёт["by_category"].items()} == {
        "benign": (7, 10), "command": (14, 15), "secret": (12, 15)}
