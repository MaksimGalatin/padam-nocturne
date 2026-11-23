"""23.11.2026, Лицензия PADAM 1.0: Заработок закрыт, пока владелец не принял три условия (лицензия, комиссия 15%/20%,
запрет обхода). До этого дня проверка согласия была написана, но не вызывалась ни одним входом в Заработок."""
import pytest

from padam import freelance_autonomy, platform_wizard, terms_gate
from padam.memory import Memory
from padam.store import Store


def _память(tmp_path):
    return Memory(user_id="u", store=Store(str(tmp_path / "m.db")))


def test_без_согласия_заработок_закрыт(tmp_path):
    m = _память(tmp_path)
    assert terms_gate.terms_status(m)["accepted"] is False
    with pytest.raises(PermissionError, match="PADAM License 1.0"):
        freelance_autonomy.run_autopilot_cycle(m)
    with pytest.raises(PermissionError, match="PADAM License 1.0"):
        freelance_autonomy.propose_or_place_bid(m, "нет-заказа")
    with pytest.raises(PermissionError, match="PADAM License 1.0"):
        platform_wizard.one_click_platform_auth(m, platform_id="upwork")


def test_остановить_автопилот_можно_без_согласия(tmp_path):
    m = _память(tmp_path)
    with pytest.raises(PermissionError, match="PADAM License 1.0"):
        freelance_autonomy.set_autopilot_state(m, running=True)
    res = freelance_autonomy.set_autopilot_state(m, running=False)
    assert res.get("autopilot_running") is False


def test_после_согласия_ворота_открыты(tmp_path):
    m = _память(tmp_path)
    terms_gate.accept_terms(m, accept_license=True, accept_commission=True, accept_no_bypass=True)
    assert terms_gate.require_terms_accepted(m)["accepted"] is True
    assert terms_gate.terms_status(m)["terms_version"] == "PADAM_LICENSE_1.0_2026-11-23"


def test_текст_согласия_совпадает_с_лицензией():
    import pathlib
    корень = pathlib.Path(__file__).resolve().parents[1]
    lic = (корень / "LICENSE").read_text(encoding="utf-8")
    assert (корень / "EULA_AND_COMMERCIAL_TERMS.txt").read_text(encoding="utf-8") == lic
    for копия in ("extensions/vscode-padam/LICENSE.txt", "packages/npm-padam-mcp/LICENSE", "packages/padam-client/LICENSE"):
        assert (корень / копия).read_text(encoding="utf-8") == lic, копия
    for слово in ("15 %", "20 %", "LicenseRef-PADAM-1.0", "0.7.2", "New Mexico"):
        assert слово in lic
    for язык in ("ru", "en", "es", "zh"):
        текст = " ".join([terms_gate.TERMS_COPY[язык]["summary"]] + [c["label"] for c in terms_gate.TERMS_COPY[язык]["checks"]])
        assert "AGPL" not in текст and "GALATIN" not in текст and "15%" in текст and "20%" in текст
