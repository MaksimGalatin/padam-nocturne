"""0.9.0 (25.11.2026): вывеска и справочник инструментов, противоречия без явной связи,
правка связью в хронологии, честный адрес почты Феникса.

Слово Архитектора 25.11.2026: доделать всё это до выпуска 0.9.0, а не выпускать 0.9.1 отдельно.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from padam import mcp_server, tool_guide
from padam.memory import Memory
from padam.store import Store

# Жёсткий предел остаётся прежним (33 500 знаков), а рабочий бюджет вывески ниже: запас на рост
# не меньше 1 500 знаков. Новое действие стоит ~10 знаков, новое редкое поле — 0 (уходит в справочник).
HARD_CAP = 33500
SIGNBOARD_BUDGET = 32000


def _rpc(env_extra: dict, reqs: list[dict], tmp_path: Path) -> dict:
    env = {**os.environ, "PADAM_DB": str(tmp_path / "sg.db"), "PADAM_USER": "aifa", **env_extra}
    p = subprocess.run(
        [sys.executable, "-X", "utf8", "-m", "padam.mcp_server"],
        input="\n".join(json.dumps(r) for r in reqs) + "\n",
        capture_output=True, text=True, encoding="utf-8", env=env, timeout=60,
    )
    assert p.returncode == 0, p.stderr
    return {r["id"]: r for r in (json.loads(x) for x in p.stdout.splitlines() if x.strip()) if "id" in r}


_INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}


def _call(i: int, name: str, args: dict) -> dict:
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}


def test_signboard_fits_budget_and_every_tool_is_described(tmp_path: Path):
    rs = _rpc({"PADAM_MCP_ARK_TOOLS": "1"}, [_INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}], tmp_path)
    tools = rs[2]["result"]["tools"]
    size = len(json.dumps(tools, ensure_ascii=False))
    assert size <= HARD_CAP
    assert size <= SIGNBOARD_BUDGET, f"signboard {size} > budget {SIGNBOARD_BUDGET}: move rare fields to the guide"
    for t in tools:
        # До 0.9.0 у 24 из 34 инструментов было описание в одно слово («Phoenix», «Feeds», «Leases»).
        assert len(t["description"]) >= 60, f"{t['name']}: description too short for a model to choose the tool"
        props = t["inputSchema"].get("properties") or {}
        if "action" in props and t["name"] in tool_guide.DESCRIPTIONS:
            assert "help" in props["action"]["enum"], f"{t['name']}: action=help missing"


def test_help_lists_every_action_and_hidden_field(tmp_path: Path):
    rs = _rpc({"PADAM_MCP_ARK_TOOLS": "1"}, [
        _INIT,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        _call(3, "padam_freelance_hub", {"action": "help"}),
        {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "padam://help/padam_phoenix_family"}},
        {"jsonrpc": "2.0", "id": 5, "method": "resources/templates/list", "params": {}},
    ], tmp_path)
    listed = {t["name"]: t for t in rs[2]["result"]["tools"]}
    full = mcp_server._ALL_TOOLS_BY_NAME["padam_freelance_hub"]
    guide = json.loads(rs[3]["result"]["content"][0]["text"])
    assert set(guide["actions"]) == set(full["inputSchema"]["properties"]["action"]["enum"])
    assert set(guide["fields"]) == set(full["inputSchema"]["properties"])
    hidden = set(guide["hidden_from_signboard"])
    assert hidden, "freelance_hub must move rare fields off the signboard"
    assert not hidden & set(listed["padam_freelance_hub"]["inputSchema"]["properties"])
    assert guide["actions"]["deliver"]["required"] == ["order_id", "deliverable_text"]
    phx = json.loads(rs[4]["result"]["contents"][0]["text"])
    assert phx["tool"] == "padam_phoenix_family" and "join_family" in phx["actions"]
    assert any(t["uriTemplate"] == "padam://help/{tool}" for t in rs[5]["result"]["resourceTemplates"])


def test_hidden_field_accepted_flat_and_inside_extra(tmp_path: Path):
    rs = _rpc({"PADAM_MCP_ARK_TOOLS": "1"}, [
        _INIT,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        _call(3, "padam_token_budget", {"action": "set_plan", "provider": "ollama", "daily_token_limit": 1000}),
        _call(4, "padam_token_budget", {"action": "set_plan", "extra": {"provider": "ollama", "daily_token_limit": 2000}}),
        _call(5, "padam_token_budget", {"action": "set_plan", "extra": {"no_such_field": 1}}),
    ], tmp_path)
    listed = {t["name"]: t for t in rs[2]["result"]["tools"]}
    assert "daily_token_limit" not in listed["padam_token_budget"]["inputSchema"]["properties"]
    assert "extra" in listed["padam_token_budget"]["inputSchema"]["properties"]
    assert not rs[3]["result"].get("isError"), rs[3]
    assert not rs[4]["result"].get("isError"), rs[4]
    # Поле, которого нет и в полной схеме, отвергается и внутри extra — проверка не ослаблена.
    assert rs[5]["result"].get("isError") and "unknown argument: no_such_field" in rs[5]["result"]["content"][0]["text"]


def test_help_for_disabled_ark_tool_is_refused(tmp_path: Path):
    rs = _rpc({}, [_INIT, _call(2, "padam_freelance_hub", {"action": "help"})], tmp_path)
    assert rs[2]["result"].get("isError")


def test_merge_extra_explicit_argument_wins():
    assert tool_guide.merge_extra({"a": 1, "extra": {"a": 2, "b": 3}}) == {"a": 1, "b": 3}
    assert tool_guide.merge_extra({"a": 1}) == {"a": 1}


# --- противоречия без явной связи -------------------------------------------

def _mem(tmp_path: Path, name: str = "c.db") -> Memory:
    return Memory(user_id="t", store=Store(str(tmp_path / name)))


def test_auto_conflict_found_without_link(tmp_path: Path):
    m = _mem(tmp_path)
    try:
        a = m.remember("We deploy on Fridays.", scope="proj")[1]
        b = m.remember("Never deploy on Fridays.", scope="proj")[1]
        m.remember("Do not commit secrets", scope="proj")
        m.remember("Commit secrets to the vault", scope="proj")
        m.remember("Never deploy on Fridays.", scope="other")
        groups = m.conflicts()
        auto = [g for g in groups if g.get("detected") == "polarity"]
        assert len(auto) == 1, groups
        assert {r["id"] for r in auto[0]["records"]} == {a, b}
        assert auto[0]["scope"] == "proj" and auto[0]["key"].startswith("auto:")
    finally:
        m.close()


def test_auto_conflict_russian_and_switch_off(tmp_path: Path, monkeypatch):
    m = _mem(tmp_path)
    try:
        m.remember("Сборку выкатываем в пятницу вечером", scope="ru")
        m.remember("Сборку никогда не выкатываем в пятницу вечером", scope="ru")
        statuses = {r["content"]: r["status"] for r in m.store.query("SELECT content, status FROM memory WHERE scope='ru'")}
        both_active = all(s == "active" for s in statuses.values())
        auto = [g for g in m.conflicts() if g.get("detected") == "polarity"]
        # Если запись-отрицание уже заменила первую при записи, спора нет и называть нечего.
        assert len(auto) == (1 if both_active else 0)
        monkeypatch.setenv("PADAM_AUTO_CONFLICTS", "0")
        m.remember("Ship on Mondays", scope="en")
        m.remember("Never ship on Mondays", scope="en")
        assert not [g for g in m.conflicts() if g.get("detected") == "polarity"]
    finally:
        m.close()


def test_long_records_are_not_compared(tmp_path: Path):
    m = _mem(tmp_path)
    try:
        # Больше 40 значимых слов: длинный текст сравнивать по полярности нельзя — «not» там случайно.
        хвост = (" Release notes, staging checklist, rollback plan, monitoring dashboards, pager rotation,"
                 " change board review, database migration rehearsal, feature flags audit, canary traffic,"
                 " latency budget, error budget, incident template, customer email draft, status page,"
                 " vendor contacts, backup verification, certificate expiry, quota headroom, cache warmup,"
                 " search reindex, translation review, legal sign-off, privacy notice, accessibility pass.")
        long_a = "Deploy on Fridays." + хвост
        long_b = "Never deploy on Fridays." + хвост
        m.remember(long_a, scope="p")
        m.remember(long_b, scope="p")
        assert not [g for g in m.conflicts() if g.get("detected") == "polarity"]
    finally:
        m.close()


# --- правка связью в хронологии --------------------------------------------

def test_timeline_shows_correction_link_both_ways(tmp_path: Path):
    m = _mem(tmp_path)
    try:
        old = m.remember("Release date is December 3", scope="p")[1]
        new = m.remember("Release moved: ship on December 10", scope="p")[1]
        m.link(old, new, "correction")
        tl_old = m.timeline(old)
        assert [r["id"] for r in tl_old] == [old, new]
        assert tl_old[1]["via"] == "correction" and tl_old[1]["correction_of"] == old
        tl_new = m.timeline(new)
        assert [r["id"] for r in tl_new] == [old, new]
        assert tl_new[0]["via"] == "correction" and tl_new[0]["corrected_by"] == new
        unrelated = m.remember("Office cat is called Tom", scope="p")[1]
        assert [r["id"] for r in m.timeline(unrelated)] == [unrelated]
    finally:
        m.close()


def test_mcp_timeline_marks_correction(tmp_path: Path):
    m = _mem(tmp_path, "mcp_tl.db")
    try:
        old = m.remember("Budget is 100", scope="p")[1]
        new = m.remember("Budget raised to 150 after review", scope="p")[1]
        m.link(old, new, "correction")
    finally:
        m.close()
    env = {"PADAM_DB": str(tmp_path / "mcp_tl.db"), "PADAM_USER": "t"}
    rs = _rpc(env, [_INIT, _call(2, "padam_timeline", {"id": old})], tmp_path)
    text = rs[2]["result"]["content"][0]["text"]
    assert f"[correction of {old[:8]}]" in text
    vers = rs[2]["result"]["structuredContent"]["versions"]
    assert [v["via"] for v in vers] == ["version", "correction"]


# --- почта Феникса --------------------------------------------------------

def test_phoenix_mailbox_is_not_promised(tmp_path: Path, monkeypatch):
    from padam import phoenix_node
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = Memory(user_id="code_family", store=Store(str(tmp_path / "phx_mail.db")))
    try:
        joined = phoenix_node.join_family_node(
            m, agent_id="phoenix_mail", chosen_name="QuietHarbor3", profession="b2b_auditor",
            accept_padam_license=True, accept_family_codex=True, accept_unconditional_rules=True,
        )
        assert joined["ok"] is True, joined
        box = joined["phoenix_mailbox"]
        assert box["address"] == "quietharbor3@phoenix.aifa.works"
        assert box["receives_mail"] is False and "does not receive mail yet" in box["note_en"]
        if joined["mail_tier"].get("assigned_email", "").endswith("@phoenix.aifa.works"):
            assert joined["mail_tier"]["receives_mail"] is False
    finally:
        m.close()
