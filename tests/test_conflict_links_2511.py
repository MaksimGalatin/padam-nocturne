# -*- coding: utf-8 -*-
"""0.9.0 (25.11.2026): явное ребро «противоречие» видно в conflicts/{scope} и в поиске;
отказ join_family объясняет агенту, какой пакет прислать."""
from __future__ import annotations

from pathlib import Path

from padam import mcp_server, phoenix_node
from padam.memory import Memory
from padam.store import Store


def _mem(tmp_path: Path, name: str = "c.db") -> Memory:
    return Memory(user_id="conflict-user", store=Store(str(tmp_path / name)))


def test_explicit_contradiction_link_is_a_conflict(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    mem = _mem(tmp_path)
    _, fri = mem.remember("We deploy Orion on Fridays only after tests pass", kind="decision", origin="user")
    _, mon = mem.remember("We deploy Orion on Mondays and never on Fridays", kind="decision", origin="user",
                          links=[{"target": fri, "relation": "contradiction"}])
    _, other = mem.remember("Alice leads project Orion", kind="fact", origin="user")
    assert mem.store.one("SELECT status FROM memory WHERE id = ?", (fri,))["status"] == "active"
    assert mem.store.one("SELECT status FROM memory WHERE id = ?", (mon,))["status"] == "active"

    groups = mem.conflicts()
    linked = [g for g in groups if g["key"].startswith("link:")]
    assert len(linked) == 1
    ids = {r["id"] for r in linked[0]["records"]}
    assert ids == {fri, mon}
    assert other not in ids

    old = mcp_server._memory
    mcp_server._memory = mem
    try:
        res = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "resources/read",
                                 "params": {"uri": "padam://conflicts/global"}})
        text = res["result"]["contents"][0]["text"]
        assert "Mondays" in text and "Fridays" in text
        assert "No conflicting active records" not in text
    finally:
        mcp_server._memory = old

    found = mem.recall("when do we deploy Orion", limit=10)
    flags = {r.id: r.conflict for r in found}
    assert flags.get(fri) is True or flags.get(mon) is True
    if other in flags:
        assert flags[other] is False


def test_refuted_side_leaves_conflicts(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    mem = _mem(tmp_path, "r.db")
    _, a = mem.remember("The release owner of Orion is Alice", kind="fact", origin="user")
    _, b = mem.remember("Bob owns the Orion release", kind="fact", origin="user",
                        links=[{"target": a, "relation": "contradiction"}])
    assert any(g["key"].startswith("link:") for g in mem.conflicts())
    mem.store.atomic([("UPDATE memory SET status = 'revoked' WHERE id = ?", (b,))])
    assert not any(g["key"].startswith("link:") for g in mem.conflicts())


def test_join_family_refusal_explains_packet(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    mem = _mem(tmp_path, "j.db")
    refused = phoenix_node.join_family_node(mem, agent_id="phoenix_beta", chosen_name="Beta")
    assert refused["ok"] is False
    assert refused["error"] == "unconditional_acceptance_required"
    pkt = refused["required_packet"]
    for key in ("accept_padam_license", "accept_family_codex", "accept_unconditional_rules"):
        assert pkt[key] is True
    assert "join_family" in refused["message_en"]
