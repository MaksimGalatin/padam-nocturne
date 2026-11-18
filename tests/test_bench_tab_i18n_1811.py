# -*- coding: utf-8 -*-
"""18.11.2026, слово Папы: «Какого хера там всё на английском при русской версии? ГДЕ ПЕРЕВОД на все языки?»
Вкладка «Бенчмарк»: строки на 4 языках, сравнение с другими MCP памяти на 4 языках, 100 критериев переведены,
в отрисовке нет английских литералов."""
import io
import re

from padam import studio
from padam.bench_compare import compare_payload
from padam.bench_titles import ES_ZH

ЯЗЫКИ = ("ru", "en", "es", "zh")
КЛЮЧИ = ("bench_guide_title", "bench_guide_1", "bench_guide_2", "bench_guide_3", "bench_guide_4", "cmp_title", "cmp_sub",
         "cmp_col_k", "cmp_plan_title", "cmp_plan", "bench_json", "bench_sarif", "bench_grade", "bench_std", "st_pass",
         "st_fail", "st_na", "fuzz_running", "fuzz_title", "fuzz_desc", "fuzz_padam", "fuzz_regex", "fuzz_rag",
         "fuzz_row", "fuzz_row2", "qa_row", "rt_round", "rt_models", "rt_sum", "rt_sum_words")


def test_строки_вкладки_на_4_языках():
    for к in КЛЮЧИ:
        for я in ЯЗЫКИ:
            assert (studio.STRINGS[я].get(к) or "").strip(), (к, я)


def test_сравнение_на_4_языках():
    p = compare_payload()
    assert set(p["cols"]) == {"padam", "mem0", "zep", "mcpmem"} and len(p["rows"]) >= 10
    for r in p["rows"]:
        for поле in ("k", "padam", "mem0", "zep", "mcpmem"):
            for я in ЯЗЫКИ:
                assert r[поле][я].strip(), (r["k"]["ru"], поле, я)


def test_все_100_критериев_переведены():
    каталог = io.open("benchmarks/aifa_security/catalog.py", encoding="utf-8").read()
    ids = set(re.findall(r'\("(AS-\d{3})", "D\d+"', каталог))
    assert len(ids) == 100 and ids == set(ES_ZH)


def test_нет_английских_литералов_в_отрисовке():
    код = io.open(studio.__file__, encoding="utf-8").read()
    for литерал in ("`Grade ${", "Fuzz Lab (", "Defense=${", "'Running fuzz", "['Basic Regex Filter'", "R@5=${"):
        assert литерал not in код, литерал


def test_переводы_не_ломают_бенчмарк():
    """Текст переводов не должен содержать строк, которые сканер AS-074 считает уязвимостью (найдено 18.11)."""
    for f in ("padam/bench_titles.py", "padam/bench_compare.py"):
        т = io.open(f, encoding="utf-8").read()
        assert "0.0.0.0" not in т and "verify=False" not in т, f
