# -*- coding: utf-8 -*-
"""GLM раунд 3, Паттерн 1: замок владельца внутри set_autopilot_state и accept_delivery, а не только у вызывающего.
AS-098: печать отчёта проверяется пересчётом, а не объявляется PASS."""
import pytest

from padam import freelance_autonomy as fa
from padam.memory import Memory
from padam.roles import ActorContext
from padam.store import Store


def _агент():
    return ActorContext(role="member", subject="agent-x", workspace_id="w1")


def test_автопилот_не_включить_не_владельцу(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "a.db"))
    with pytest.raises(PermissionError):
        fa.set_autopilot_state(m, running=True, actor=_агент())
    assert fa.get_autopilot_state(m)["autopilot_running"] in (0, False)
    fa.set_autopilot_state(m, running=True)          # владелец (актёр не передан — локальный вызов владельца)
    assert fa.get_autopilot_state(m)["autopilot_running"] in (1, True)


def test_приёмку_не_оформить_не_владельцу(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "b.db"))
    with pytest.raises(PermissionError):
        fa.accept_delivery(m, "нет-такого", actor=_агент())


def test_as098_проверяет_печать():
    from benchmarks.aifa_security.run_aifa_sec import run_aifa_security
    rep = run_aifa_security()
    c = next(x for x in rep["criteria"] if x["id"] == "AS-098")
    assert c["status"] == "PASS" and c["metric"] == rep["summary"]["report_sha256"][:16]


def test_bh04_эталон_не_отстаёт_от_кода():
    """BH-04: опубликованный results_aifa_security.json не должен расходиться со свежим прогоном по статусам."""
    import json
    from pathlib import Path
    from benchmarks.aifa_security.run_aifa_sec import run_aifa_security, verify_report_attestation
    путь = Path(__file__).resolve().parents[1] / "benchmarks" / "aifa_security" / "results_aifa_security.json"
    эталон = json.loads(путь.read_text(encoding="utf-8"))
    assert verify_report_attestation(эталон)["verified"]
    assert эталон["summary"]["target"] == "padam-nocturne"
    свежий = {c["id"]: c["status"] for c in run_aifa_security()["criteria"]}
    старый = {c["id"]: c["status"] for c in эталон["criteria"]}
    разница = {k: (старый.get(k), v) for k, v in свежий.items() if старый.get(k) != v}
    assert not разница, f"эталон отстал от кода — перевыпустить: python -m benchmarks.aifa_security.run_aifa_sec ({разница})"
