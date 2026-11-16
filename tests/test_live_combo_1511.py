"""Сочетания флагов, которые по отдельности проходили тесты, а вместе ломались (живая проверка 15.11.2026)."""
from __future__ import annotations

import importlib


def _mcp(monkeypatch, tmp_path, **flags):
    monkeypatch.setenv("PADAM_DB", str(tmp_path / "combo.db"))
    for k, v in flags.items():
        monkeypatch.setenv(k, v)
    from padam import mcp_server as ms
    importlib.reload(ms)
    ms.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
    ms.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "padam_write", "arguments": {
        "content": "Staging deploys need the vault env var, key AKIAQWERTYUIOPASDF12", "scope": "p", "kind": "fact"}}})
    return ms


def _call(ms, args, i=10):
    return ms.handle({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "padam_search", "arguments": args}})


def test_reflect_and_known_at_are_accepted_by_strict_schema(monkeypatch, tmp_path):
    ms = _mcp(monkeypatch, tmp_path, PADAM_REFLECT="1", PADAM_BITEMPORAL="1")
    r = _call(ms, {"query": "staging env var", "scope": "p", "reflect": True})
    assert not r["result"].get("isError"), r
    assert "reflect" in r["result"]["structuredContent"]
    r = _call(ms, {"query": "staging env var", "scope": "p", "mode": "reflect"}, 11)
    assert not r["result"].get("isError"), r
    r = _call(ms, {"query": "staging env var", "scope": "p", "known_at": "2030-01-01"}, 12)
    assert not r["result"].get("isError"), r


def test_briefing_with_dlp_shield_does_not_crash_or_leak(monkeypatch, tmp_path):
    ms = _mcp(monkeypatch, tmp_path, PADAM_BRIEFING="1", PADAM_MCP_DLP_SHIELD="1")
    r = ms.handle({"jsonrpc": "2.0", "id": 20, "method": "resources/read", "params": {"uri": "padam://briefing/p"}})
    assert "result" in r, r
    text = r["result"]["contents"][0]["text"]
    assert "AKIAQWERTYUIOPASDF12" not in text
