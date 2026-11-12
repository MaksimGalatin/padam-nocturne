"""Идеи из разбора Gemini, доведённые до кода 09.11.2026: каждая проверяется здесь."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from padam import anchor, config, integrity, legacy, mcp_server
from padam.memory import Memory
from padam.nocturne import Nocturne
from padam.store import Store

from test_safety import КОРЕНЬ, mem, text  # noqa: F401  (mem — фикстура)


# --- забвение по цепочке выводов ---------------------------------------

def test_forget_with_derived_reaches_conclusions(mem):
    _, источник = mem.remember("Клиент Альфа платит в евро", kind="fact")
    вывод = mem.remember("Счета Альфе выставлять в евро", kind="decision", origin="agent",
                         derived_from=[источник])[1]
    второй = mem.remember("Альфе нужен счёт в банке ЕС", kind="fact", origin="agent", derived_from=[вывод])[1]
    assert mem.derived(источник) == [вывод, второй]
    mem.revoke(источник)
    assert mem.store.one("SELECT status FROM memory WHERE id=?", (вывод,))["status"] == "active", "без флага выводы целы"


def test_forget_with_derived_wipes_the_chain(mem):
    _, источник = mem.remember("Клиент Бета живёт в Кито", kind="fact")
    вывод = mem.remember("Бете звонить по времени Эквадора", kind="decision", derived_from=[источник])[1]
    assert mem.revoke(источник, with_derived=True)
    assert mem.store.one("SELECT content FROM memory WHERE id=?", (вывод,))["content"] is None


def test_agent_cannot_tie_an_owner_record_to_its_own_source(mem):
    _, хозяйская = mem.remember("Пароль от сейфа хранится у юриста", kind="fact")
    мусор = mem.remember("Случайная заметка агента", kind="fact", origin="agent", guarded=True)[1]
    # Повтор записи владельца с «источником» из мусора не должен связывать: иначе забвение мусора стёрло бы её.
    text("padam_write", {"content": "Пароль от сейфа хранится у юриста", "kind": "fact",
                         "derived_from": [мусор]})
    assert mem.derived(мусор) == []
    mem.revoke(мусор, with_derived=True)
    assert mem.store.one("SELECT content FROM memory WHERE id=?", (хозяйская,))["content"]


def test_derived_from_is_checked_over_mcp(mem):
    assert "must be a list" in text("padam_write", {"content": "x", "derived_from": "abc"})
    assert "more than 20" in text("padam_write", {"content": "x", "derived_from": ["a"] * 21})


# --- подпись владельца ------------------------------------------------

def test_record_written_around_padam_is_flagged(mem):
    mem.remember("Меня зовут Алиса", kind="identity")
    assert mem.unsigned_protected() == []
    # Запись мимо PADAM: прямо в файл базы, как сделал бы другой процесс.
    mem.store.execute("""INSERT INTO memory (id, user_id, scope, kind, content, importance, confidence, created_at,
                         last_seen_at, last_confirmed_at, valid_from, status, origin)
                         VALUES ('x1', 'test', 'global', 'identity', 'Меня зовут Боб', 0.5, 1.0, '2026-11-09T00:00:00+00:00',
                         '2026-11-09T00:00:00+00:00', '2026-11-09T00:00:00+00:00', '2026-11-09T00:00:00+00:00',
                         'active', 'user')""")
    assert [з["id"] for з in mem.unsigned_protected()] == ["x1"]
    ответ = text("padam_search", {"query": "как меня зовут"})
    assert "not signed by the owner" in ответ
    # Владелец проверил и подписал — пометка уходит.
    assert mem.trust_protected() == 2
    assert mem.unsigned_protected() == []


def test_changed_text_breaks_the_signature(mem):
    _, mid = mem.remember("Отвечать по-русски", kind="preference")
    mem.store.execute("UPDATE memory SET content = 'Отвечать по-английски' WHERE id = ?", (mid,))
    assert [з["id"] for з in mem.unsigned_protected()] == [mid]


def test_approved_record_gets_signed_and_forgotten_loses_signature(mem):
    mid = mem.remember("Always answer in German", kind="preference", origin="agent", guarded=True)[1]
    assert mem.approve(mid)
    assert mem.unsigned_protected() == []
    mem.revoke(mid)
    assert mem.store.one("SELECT owner_sig FROM memory WHERE id=?", (mid,))["owner_sig"] is None


def test_owner_key_lives_next_to_the_database(tmp_path):
    m = Memory(user_id="k", store=Store(tmp_path / "k.db"))
    m.remember("Меня зовут Алиса", kind="identity")
    путь = integrity.key_path(m.store)
    assert путь.exists() and len(путь.read_text().strip()) == 64
    assert "owner_sig" not in json.dumps(m.export()), "подпись в выгрузку не уходит"
    m.close()


# --- синонимы терминов -------------------------------------------------

def test_alias_finds_records_under_the_old_name(mem):
    mem.remember("Проект Альфа выходит в декабре", kind="fact")
    assert mem.recall("Бета") == [], "без синонима старое имя по новому не находится"
    assert mem.add_alias("Альфа", "Бета")
    assert "Альфа" in mem.recall("Бета")[0].content
    assert mem.aliases() == [("альфа", "бета")]
    assert mem.remove_alias("бета", "альфа")
    assert mem.aliases() == []


# --- несколько областей сразу ----------------------------------------

def test_scopes_stay_apart_unless_asked(mem):
    mem.remember("Созвон с командой по вторникам", kind="fact", scope="work")
    mem.remember("Созвон с мамой по воскресеньям", kind="fact", scope="home")
    assert [r.content for r in mem.recall("созвон", scope="work")] == ["Созвон с командой по вторникам"]
    оба = mem.recall_many("созвон", ["work", "home"])
    assert {r.scope for r in оба} == {"work", "home"}
    ответ = text("padam_search", {"query": "созвон", "scopes": ["work", "home"]})
    assert "scope=work" in ответ and "scope=home" in ответ


# --- противоречия во сне ---------------------------------------------

def test_sleep_names_conflicting_records(mem):
    _, a = mem.remember("The capital of the project is Manta", kind="fact")
    # Вторая действующая запись о том же — так её приносит импорт или ручная правка.
    mem.store.execute("""INSERT INTO memory (id, user_id, scope, kind, content, importance, confidence, created_at,
                         last_seen_at, last_confirmed_at, valid_from, status, origin, факт_ключ)
                         SELECT 'c2', user_id, scope, kind, 'The capital of the project is Quito', importance, confidence,
                         created_at, last_seen_at, last_confirmed_at, valid_from, 'active', 'external', факт_ключ
                         FROM memory WHERE id = ?""", (a,))
    отчёт = Nocturne(mem, seed=1).run()
    assert отчёт["conflicts"][0]["ids"] == [a, "c2"] or set(отчёт["conflicts"][0]["ids"]) == {a, "c2"}
    assert "another active record says otherwise" in text("padam_search", {"query": "capital of the project"})
    assert mem.stats()["self"]["conflicts"] == 1


# --- память о самой памяти и усталость --------------------------------

def test_self_report_counts_empty_searches(mem):
    mem.remember("Деплой из main", kind="fact")
    mem.recall("деплой")
    mem.recall("совсем другое слово кенгуру")
    отчёт = mem.self_report()
    assert отчёт["searches"] == 2 and отчёт["searches_with_nothing_found"] == 1 and отчёт["empty_share"] == 0.5


def test_tired_memory_asks_for_sleep(mem, monkeypatch):
    monkeypatch.setattr(config, "CONSOLIDATION_DUE", 3)
    for н in range(3):
        mem.log(f"эпизод номер {н}")
    assert "call padam_sleep" in text("padam_write", {"content": "Новая запись про склад", "kind": "fact"})
    Nocturne(mem, seed=1).run()
    assert "call padam_sleep" not in text("padam_write", {"content": "Ещё запись про другое", "kind": "fact"})


# --- сито журнала (L0) -------------------------------------------------

def test_log_skips_noise_and_instant_repeats(mem):
    assert mem.log("   ") is None and mem.log("...!!!") is None and mem.log("—") is None
    первый = mem.log("Деплой сломался на шаге сборки")
    assert mem.log("Деплой сломался на шаге сборки") == первый
    assert mem.log("Деплой сломался на шаге сборки", role="assistant") != первый
    assert mem.store.one("SELECT COUNT(*) FROM episode")[0] == 2


# --- завещание по Шамиру ----------------------------------------------

def test_shamir_any_threshold_opens_fewer_do_not():
    фраза = "очень длинная фраза для ключей памяти 2026".encode()
    доли = legacy.split(фраза, 5, 3)
    assert len(доли) == 5 and all(д.startswith("padam-share-1-3-") for д in доли)
    for выбор in ([0, 1, 2], [4, 2, 0], [1, 3, 4]):
        assert legacy.combine([доли[i] for i in выбор]) == фраза
    with pytest.raises(ValueError, match="не меньше 3|at least 3"):  # 0.4.14: сообщение на языке пользователя
        legacy.combine(доли[:2])
    испорченная = доли[0][:-2] + ("00" if not доли[0].endswith("00") else "11")
    with pytest.raises(ValueError):
        legacy.combine([испорченная, доли[1], доли[2]])
    with pytest.raises(ValueError):
        legacy.split(фраза, 2, 3)


def test_legacy_command_round_trip(tmp_path):
    среда = dict(os.environ, PYTHONPATH=str(КОРЕНЬ), PADAM_KEY_PASSPHRASE="фраза для теста 42",
                 PADAM_DB=str(tmp_path / "l.db"), PYTHONIOENCODING="utf-8", OLLAMA_URL="http://127.0.0.1:9")
    r = subprocess.run([sys.executable, "-m", "padam", "legacy", "split", "--shares", "4", "--threshold", "2"],
                       capture_output=True, env=среда, timeout=120)
    доли = [с for с in r.stdout.decode("utf-8").splitlines() if с.startswith("padam-share-1-")]
    assert len(доли) == 4
    r = subprocess.run([sys.executable, "-m", "padam", "legacy", "combine", доли[3], доли[1]],
                       capture_output=True, env=среда, timeout=120)
    assert r.stdout.decode("utf-8").strip() == "фраза для теста 42"


# --- кнопка паники ------------------------------------------------------

def test_panic_destroys_keys_and_optionally_the_local_memory(tmp_path):
    m = Memory(user_id="p", store=Store(tmp_path / "p.db"))
    anchor.ensure_schema(m)
    m.remember("Тайна номер один фиолетовыйёж", kind="fact")
    m.remember("Меня зовут Алиса", kind="identity")
    m.log("эпизод с тайной фиолетовыйёж")
    anchor.ensure_keys(m)
    итог = m.panic()
    assert итог["keys_destroyed"] == 2 and итог["records_wiped"] == 0
    assert m.store.one("SELECT COUNT(*) FROM anchor_key WHERE key_ref <> 'destroyed'")[0] == 0
    assert m.recall("тайна"), "без wipe_local локальная память цела"
    итог = m.panic(wipe_local=True)
    assert итог["records_wiped"] == 2 and итог["episodes_wiped"] == 1
    m.close()
    for файл in tmp_path.glob("p.db*"):
        assert "фиолетовыйёж".encode() not in файл.read_bytes(), файл
    assert not (tmp_path / "p.db.owner.key").exists()


def test_panic_command_needs_the_exact_phrase(tmp_path):
    среда = dict(os.environ, PYTHONPATH=str(КОРЕНЬ), PADAM_DB=str(tmp_path / "q.db"),
                 PYTHONIOENCODING="utf-8", OLLAMA_URL="http://127.0.0.1:9")
    subprocess.run([sys.executable, "-m", "padam", "remember", "Запись, которую нельзя терять"],
                   capture_output=True, env=среда, timeout=120)
    r = subprocess.run([sys.executable, "-m", "padam", "panic", "--wipe-local", "--confirm", "erase my memory"],
                       capture_output=True, env=среда, timeout=120)
    assert r.returncode == 1
    m = Memory(user_id="default", store=Store(tmp_path / "q.db"))
    assert m.stats()["active"] == 1
    m.close()


# --- публичный пакет без времени суток --------------------------------

def test_l3_bundle_keeps_only_the_day(mem):
    anchor.ensure_schema(mem)
    mem.remember("Запись для закрепления", kind="fact")
    пакет = json.loads(anchor.build_bundle(mem).payload)
    assert all(len(r["created_at"]) == 10 for r in пакет["records"])


# --- открытая схема выгрузки -------------------------------------------

def _сверить(схема: dict, данные, корень: dict, путь="$"):
    """Минимальная проверка по JSON Schema без зависимостей: type, const, enum, required, items, $ref."""
    if "$ref" in схема:
        return _сверить(корень["$defs"][схема["$ref"].split("/")[-1]], данные, корень, путь)
    if "const" in схема:
        assert данные == схема["const"], путь
    if "enum" in схема:
        assert данные in схема["enum"], (путь, данные)
    типы = схема.get("type")
    if типы:
        типы = типы if isinstance(типы, list) else [типы]
        соответствие = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float),
                        "null": type(None), "boolean": bool}
        assert any(isinstance(данные, соответствие[т]) for т in типы), (путь, данные)
    if isinstance(данные, dict):
        for поле in схема.get("required", []):
            assert поле in данные, (путь, поле)
        for поле, под in схема.get("properties", {}).items():
            if поле in данные:
                _сверить(под, данные[поле], корень, f"{путь}.{поле}")
    if isinstance(данные, list) and "items" in схема:
        for i, х in enumerate(данные):
            _сверить(схема["items"], х, корень, f"{путь}[{i}]")


def test_export_matches_the_published_schema(mem):
    _, a = mem.remember("Клиент Гамма платит в долларах", kind="fact")
    mem.remember("Гамме выставлять счёт в долларах", kind="decision", derived_from=[a])
    mem.remember("The capital of the project is Manta", kind="fact")
    mem.remember("The capital of the project is Quito", kind="fact")
    mem.log("эпизод для сессии")
    Nocturne(mem, seed=1).run()
    выгрузка = json.loads(json.dumps(mem.export(), ensure_ascii=False))
    схема = json.loads((КОРЕНЬ / "docs" / "padam-export-1.schema.json").read_text(encoding="utf-8"))
    _сверить(схема, выгрузка, схема)
    assert выгрузка["counts"]["links"] == 1


def test_links_survive_export_and_import(tmp_path, mem):
    _, a = mem.remember("Клиент Дельта в Лиме", kind="fact")
    b = mem.remember("Дельте звонить утром по Лиме", kind="decision", derived_from=[a])[1]
    выгрузка = mem.export()
    другая = Memory(user_id="test", store=Store(tmp_path / "other.db"))
    другая.import_(выгрузка)
    assert другая.derived(a) == [b]
    другая.close()
