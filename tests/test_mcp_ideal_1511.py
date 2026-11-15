# -*- coding: utf-8 -*-
"""Тесты этапа «MCP до идеала» (PADAM_MCP_ИДЕАЛ_1511.md)."""
from __future__ import annotations

import pytest

from padam import mcp_server
from padam.memory import Memory
from padam.store import Store


def _check_json_schema_lite(val, schema: dict, path: str = "$") -> None:
    """Минимальный проверяющий валидатор JSON Schema для outputSchema."""
    tp = schema.get("type")
    type_map = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "null": type(None),
    }
    if tp is not None:
        allowed = tp if isinstance(tp, list) else [tp]
        ok = False
        for t in allowed:
            if t == "integer" and isinstance(val, bool):
                continue
            if t == "number" and isinstance(val, bool):
                continue
            if isinstance(val, type_map[t]):
                ok = True
                break
        assert ok, f"{path}: expected type {allowed}, got {type(val).__name__} ({val!r})"
    if isinstance(val, dict):
        for req_k in schema.get("required", []):
            assert req_k in val, f"{path}: missing required key {req_k!r}"
        props = schema.get("properties") or {}
        for k, v in val.items():
            if k in props:
                _check_json_schema_lite(v, props[k], f"{path}.{k}")
    elif isinstance(val, list) and "items" in schema:
        for i, item in enumerate(val):
            _check_json_schema_lite(item, schema["items"], f"{path}[{i}]")


def test_mcp_ideal_2_1_all_tools_output_schema_and_structured_content(tmp_path):
    """Пункт 2.1: каждый из 9 инструментов (+ padam_recent) имеет outputSchema (properties+required) и отдаёт текст + structuredContent."""
    mem = Memory(user_id="ideal-2-1", store=Store(tmp_path / "m.db"))
    old_mem = mcp_server._memory
    mcp_server._memory = mem
    try:
        r_list = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tools = r_list["result"]["tools"]
        assert len(tools) == 9
        tools_by_name = {t["name"]: t for t in tools}

        for tname, tdef in {**tools_by_name, "padam_recent": mcp_server.RECENT_TOOL_DEF}.items():
            oschema = tdef.get("outputSchema")
            assert isinstance(oschema, dict), f"{tname} missing outputSchema"
            assert oschema.get("type") == "object"
            assert oschema.get("properties"), f"{tname} outputSchema has empty properties"
            assert oschema.get("required"), f"{tname} outputSchema has empty required"

        # 1. padam_write
        w = mcp_server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "padam_write", "arguments": {"content": "I prefer dark roast coffee", "origin": "user"}},
        })["result"]
        assert w["isError"] is False and w["content"][0]["type"] == "text"
        _check_json_schema_lite(w["structuredContent"], tools_by_name["padam_write"]["outputSchema"])
        rec_id = w["structuredContent"]["id"]

        # 2. padam_search
        s = mcp_server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "padam_search", "arguments": {"query": "dark roast coffee"}},
        })["result"]
        assert s["isError"] is False and s["content"][0]["type"] == "text"
        _check_json_schema_lite(s["structuredContent"], tools_by_name["padam_search"]["outputSchema"])

        # 3. padam_confirm & 4. padam_refute
        c = mcp_server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "padam_confirm", "arguments": {"id": rec_id}},
        })["result"]
        assert c["isError"] is False and c["content"][0]["type"] == "text"
        _check_json_schema_lite(c["structuredContent"], tools_by_name["padam_confirm"]["outputSchema"])

        rf = mcp_server.handle({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "padam_refute", "arguments": {"id": rec_id, "drop": 0.1}},
        })["result"]
        assert rf["isError"] is False and rf["content"][0]["type"] == "text"
        _check_json_schema_lite(rf["structuredContent"], tools_by_name["padam_refute"]["outputSchema"])

        # 5. padam_timeline
        tl = mcp_server.handle({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": "padam_timeline", "arguments": {"id": rec_id}},
        })["result"]
        assert tl["isError"] is False and tl["content"][0]["type"] == "text"
        _check_json_schema_lite(tl["structuredContent"], tools_by_name["padam_timeline"]["outputSchema"])

        # 6. padam_stats
        st = mcp_server.handle({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "padam_stats", "arguments": {}},
        })["result"]
        assert st["isError"] is False and st["content"][0]["type"] == "text"
        _check_json_schema_lite(st["structuredContent"], tools_by_name["padam_stats"]["outputSchema"])

        # 7. padam_sleep
        sl = mcp_server.handle({
            "jsonrpc": "2.0", "id": 8, "method": "tools/call",
            "params": {"name": "padam_sleep", "arguments": {"dry_run": True}},
        })["result"]
        assert sl["isError"] is False and sl["content"][0]["type"] == "text"
        _check_json_schema_lite(sl["structuredContent"], tools_by_name["padam_sleep"]["outputSchema"])

        # 8. padam_export
        ex = mcp_server.handle({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "padam_export", "arguments": {}},
        })["result"]
        assert ex["isError"] is False and ex["content"][0]["type"] == "text"
        _check_json_schema_lite(ex["structuredContent"], tools_by_name["padam_export"]["outputSchema"])

        # 9. padam_profile
        pr = mcp_server.handle({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "padam_profile", "arguments": {}},
        })["result"]
        assert pr["isError"] is False and pr["content"][0]["type"] == "text"
        _check_json_schema_lite(pr["structuredContent"], tools_by_name["padam_profile"]["outputSchema"])

        # 10. padam_recent
        rc = mcp_server.handle({
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": {"name": "padam_recent", "arguments": {}},
        })["result"]
        assert rc["isError"] is False and rc["content"][0]["type"] == "text"
        _check_json_schema_lite(rc["structuredContent"], mcp_server.RECENT_TOOL_DEF["outputSchema"])

        # Ошибка внутри инструмента (неверное окно дат или неизвестный параметр) даёт isError=True и без structuredContent
        err_res = mcp_server.handle({
            "jsonrpc": "2.0", "id": 12, "method": "tools/call",
            "params": {"name": "padam_write", "arguments": {"content": "bad date window", "valid_from": "2026-12-01", "valid_to": "2026-01-01"}},
        })["result"]
        assert err_res["isError"] is True
        assert "structuredContent" not in err_res
        assert "Invalid write argument" in err_res["content"][0]["text"] or "PADAM error" in err_res["content"][0]["text"]
    finally:
        mcp_server._memory = old_mem
        mem.close()
