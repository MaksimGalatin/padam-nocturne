"""Тесты цикла консолидации.

Главный тест — test_nightmare_is_contained: воспроизводит дефект, ради
которого NOCTURNE и написан, и проверяет, что ограничители его гасят.
"""

import numpy as np
import pytest

from padam import config
from padam.memory import Memory
from padam.nocturne import (Nocturne, apply_floor, beta_for, entropy_ratio,
                            importance_weights, probabilities, stratified)
from padam.store import Store
from collections import Counter


@pytest.fixture
def mem(tmp_path):
    m = Memory(user_id="test", store=Store(tmp_path / "n.db"))
    yield m
    m.close()


# --- ограничитель 4: пол приоритета -----------------------------------

def test_floor_lifts_the_lowest():
    p = np.array([100.0, 100.0, 100.0, 0.0, 0.0])
    lifted = apply_floor(p)
    assert lifted.min() > 0, "нулевой приоритет должен быть поднят до пола"
    assert lifted.max() == 100.0, "верх не должен меняться"


def test_floor_is_relative_to_median():
    p = np.array([10.0, 10.0, 10.0, 0.001])
    lifted = apply_floor(p)
    assert lifted.min() == pytest.approx(config.P_FLOOR_RATIO * 10.0)


# --- ограничитель 1: коррекция смещения -------------------------------

def test_importance_weights_favor_rare():
    """Редко выбираемый эпизод получает больший вес — это и есть коррекция."""
    probs = np.array([0.9, 0.1])
    w = importance_weights(probs, n=2, beta=1.0)
    assert w[1] > w[0]


def test_weights_normalized_to_one():
    probs = np.array([0.5, 0.3, 0.2])
    w = importance_weights(probs, n=3, beta=0.6)
    assert w.max() == pytest.approx(1.0)


def test_beta_grows_over_time():
    assert beta_for(0) == pytest.approx(config.BETA_START)
    assert beta_for(1000) == pytest.approx(config.BETA_END)
    assert beta_for(0) < beta_for(50) < beta_for(1000)


# --- вспомогательное ---------------------------------------------------

def test_probabilities_sum_to_one():
    p = probabilities(np.array([5.0, 3.0, 2.0]))
    assert p.sum() == pytest.approx(1.0)


def test_entropy_ratio_bounds():
    assert entropy_ratio(Counter({"a": 10})) == 0.0
    even = entropy_ratio(Counter({"a": 5, "b": 5, "c": 5}))
    assert even == pytest.approx(1.0)
    skewed = entropy_ratio(Counter({"a": 98, "b": 1, "c": 1}))
    assert skewed < 0.5


def test_stratified_covers_all_kinds():
    kinds = ["fact"] * 50 + ["event"] * 3 + ["decision"] * 2
    pool = np.arange(len(kinds))
    rng = np.random.default_rng(42)
    picked = stratified(kinds, pool, 12, rng)
    chosen_kinds = {kinds[i] for i in picked}
    assert chosen_kinds == {"fact", "event", "decision"}, \
        "редкие типы не должны вымываться"


# --- главный тест: кошмар не должен захватить ночь --------------------

def test_nightmare_is_contained(mem):
    """612 острых эпизодов против 1000 обычных.

    Без ограничителей острые заняли бы почти весь батч. С ограничителями
    их доля не должна превысить K_MAX.
    """
    for i in range(1000):
        mem.log(f"обычный рабочий эпизод номер {i}, ничего особенного",
                priority=1.0)
    for i in range(612):
        mem.log(f"критический сбой номер {i}, всё сломалось", priority=100.0)

    report = Nocturne(mem, batch_size=200, dry_run=True, seed=7).run()

    assert report["high_priority_share"] <= config.MAX_HI_SHARE, \
        "потолок на острые эпизоды пробит"
    assert report["episodes_sampled"] == 200


def test_without_cap_nightmare_would_dominate():
    """Контрольная проверка: показывает, что дефект реален.

    Чистая приоритетная выборка без потолка отдала бы острым эпизодам
    подавляющую долю батча.
    """
    p = np.array([1.0] * 1000 + [100.0] * 612)
    probs = probabilities(p)
    hi_mass = probs[1000:].sum()
    assert hi_mass > 0.9, \
        "без потолка острые эпизоды забирают больше 90% вероятностной массы"


# --- ограничитель 3: распад приоритета --------------------------------

def test_priority_decays_after_replay(mem):
    eid = mem.log("важный эпизод", priority=10.0)
    Nocturne(mem, batch_size=10, seed=1).run()
    row = mem.store.one(
        "SELECT priority, replay_count, processed FROM episode WHERE id=?", (eid,))
    assert row["priority"] == pytest.approx(10.0 * config.GAMMA_REPLAY)
    assert row["replay_count"] == 1
    assert row["processed"] == 1


def test_repeated_replay_decays_geometrically():
    p = 100.0
    for _ in range(10):
        p *= config.GAMMA_REPLAY
    assert p < 20.0, "после десяти переигрываний острота должна заметно упасть"


# --- цикл целиком -----------------------------------------------------

def test_empty_buffer_is_safe(mem):
    report = Nocturne(mem).run()
    assert report["episodes_sampled"] == 0


def test_dry_run_changes_nothing(mem):
    mem.log("эпизод для проверки", priority=1.0)
    before = mem.store.one("SELECT COUNT(*) FROM memory")[0]
    Nocturne(mem, dry_run=True).run()
    after = mem.store.one("SELECT COUNT(*) FROM memory")[0]
    assert before == after
    pending = mem.store.one(
        "SELECT COUNT(*) FROM episode WHERE processed=0")[0]
    assert pending == 1, "dry-run не должен помечать эпизоды обработанными"


def test_run_writes_to_l2(mem):
    for i in range(5):
        mem.log(f"эпизод {i} про инфраструктуру проекта", priority=1.0)
    report = Nocturne(mem, batch_size=10, seed=3).run()
    assert report["episodes_sampled"] == 5
    assert mem.store.one("SELECT COUNT(*) FROM memory")[0] > 0


def test_run_is_journaled(mem):
    mem.log("эпизод", priority=1.0)
    Nocturne(mem, batch_size=5, seed=1).run()
    row = mem.store.one(
        "SELECT episodes_sampled, finished_at FROM nocturne_run LIMIT 1")
    assert row["episodes_sampled"] == 1
    assert row["finished_at"] is not None


def test_processed_episodes_not_reprocessed(mem):
    mem.log("эпизод один", priority=1.0)
    Nocturne(mem, batch_size=5, seed=1).run()
    second = Nocturne(mem, batch_size=5, seed=1).run()
    assert second["episodes_sampled"] == 0


def test_checks_are_reported(mem):
    for i in range(20):
        mem.log(f"рабочий эпизод {i}", priority=1.0)
    report = Nocturne(mem, batch_size=20, seed=5).run()
    assert len(report["checks"]) == 3
    labels = [c[0] for c in report["checks"]]
    assert "Доля острых эпизодов" in labels
