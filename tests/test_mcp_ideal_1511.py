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
def test_mcp_ideal_2_2_search_resource_links(tmp_path):
    """Результаты padam_search отдают resource_link без раскрытия текста, а URI читаются через resources/read."""
    mem = Memory(user_id="ideal-2-2", store=Store(tmp_path / "m22.db"))
    old_mem = mcp_server._memory
    mcp_server._memory = mem
    try:
        secret_phrase = "telemetry-routing-check"
        wr = mcp_server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "padam_write", "arguments": {
                "content": f"The gateway service uses {secret_phrase} for health monitoring",
                "kind": "fact",
                "scope": "arch",
                "origin": "user",
            }},
        })["result"]
        assert wr["isError"] is False
        assert wr["structuredContent"]["outcome"] == "created"
        rid = wr["structuredContent"]["id"]

        sr = mcp_server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "padam_search", "arguments": {"query": "gateway service telemetry health", "scope": "arch"}},
        })["result"]
        assert sr["isError"] is False
        content = sr["content"]
        assert len(content) >= 2
        assert content[0]["type"] == "text"
        links = [c for c in content[1:] if c.get("type") == "resource_link"]
        assert len(links) == sr["structuredContent"]["count"] >= 1
        target_link = next(lk for lk in links if lk["uri"] == f"padam://record/{rid}")
        assert target_link["mimeType"] == "text/plain"
        assert secret_phrase not in target_link["name"]
        assert secret_phrase not in target_link["description"]
        assert "health" not in target_link["name"]
        assert "health" not in target_link["description"]
        assert target_link["annotations"]["audience"] == ["assistant"]
        assert 0.0 <= target_link["annotations"]["priority"] <= 1.0

        rr = mcp_server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "resources/read",
            "params": {"uri": target_link["uri"]},
        })["result"]
        assert len(rr["contents"]) == 1
        assert rr["contents"][0]["uri"] == target_link["uri"]
        assert secret_phrase in rr["contents"][0]["text"]
        assert "<memory-data nonce=" in rr["contents"][0]["text"]

        empty = mcp_server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "padam_search", "arguments": {"query": "zzzyyyxxxnonexistent987654", "scope": "arch"}},
        })["result"]
        assert len(empty["content"]) == 1 and empty["content"][0]["type"] == "text"
    finally:
        mcp_server._memory = old_mem
        mem.close()
def test_mcp_ideal_2_5_unified_errors_four_languages(tmp_path, monkeypatch):
    """Пункт 2.5: единые коды JSON-RPC и локализация ошибок на 4 языках (en, ru, es, zh)."""
    mem = Memory(user_id="ideal-2-5", store=Store(tmp_path / "m25.db"))
    old_mem = mcp_server._memory
    mcp_server._memory = mem
    try:
        # По умолчанию (без PADAM_LANG) — обратная совместимость en и отсутствие лишнего data
        monkeypatch.delenv("PADAM_LANG", raising=False)
        parse_en = mcp_server.build_jsonrpc_error(None, -32700, "parse error", key="parse_error")
        assert parse_en == {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}

        for lang, expected_words in (
            ("en", {"method": "method not found", "missing": "resource", "unknown_tool": "unknown tool", "missing_arg": "missing required argument"}),
            ("ru", {"method": "Метод MCP не найден", "missing": "Запрошенный ресурс не найден", "unknown_tool": "Неизвестный инструмент", "missing_arg": "Не переданы обязательные аргументы"}),
            ("es", {"method": "Método MCP no encontrado", "missing": "Recurso solicitado no encontrado", "unknown_tool": "Herramienta PADAM desconocida", "missing_arg": "Faltan argumentos obligatorios"}),
            ("zh", {"method": "未找到 MCP 方法", "missing": "未找到请求的资源", "unknown_tool": "未知的 PADAM 工具", "missing_arg": "缺少必需参数"}),
        ):
            monkeypatch.setenv("PADAM_LANG", lang)

            r_meth = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "no/suchMethod"})
            assert r_meth["error"]["code"] == mcp_server.ERROR_CODES["METHOD_NOT_FOUND"]
            assert expected_words["method"] in r_meth["error"]["message"]
            assert set(r_meth["error"]["data"]["messages"].keys()) == {"en", "ru", "es", "zh"}

            r_res = mcp_server.handle({
                "jsonrpc": "2.0", "id": 2, "method": "resources/read",
                "params": {"uri": "padam://record/nonexistent-999"},
            })
            assert r_res["error"]["code"] == mcp_server.ERROR_CODES["RESOURCE_NOT_FOUND"]
            assert expected_words["missing"].lower() in r_res["error"]["message"].lower()

            r_bad_p = mcp_server.handle({"jsonrpc": "2.0", "id": 3, "method": "prompts/get", "params": {"name": "bad_prompt"}})
            assert r_bad_p["error"]["code"] == mcp_server.ERROR_CODES["INVALID_PARAMS"]
            assert r_bad_p["error"]["data"]["lang"] == lang

            r_ut = mcp_server.handle({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "no_such_tool", "arguments": {}},
            })
            assert r_ut["error"]["code"] == mcp_server.ERROR_CODES["INVALID_PARAMS"]
            assert expected_words["unknown_tool"] in r_ut["error"]["message"]

            r_tool = mcp_server.handle({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "padam_write", "arguments": {}},
            })["result"]
            assert r_tool["isError"] is True
            assert expected_words["missing_arg"] in r_tool["content"][0]["text"]
    finally:
        mcp_server._memory = old_mem
        mem.close()
def test_mcp_ideal_2_4_completions_for_all_arguments(tmp_path):
    """Пункт 2.4: completion/complete для scope, kind, name, uri, id, days, provider, date и учёт ролевой видимости."""
    mem = Memory(user_id="ideal-2-4", store=Store(tmp_path / "m24.db"))
    ws = mem.create_workspace("alpha-team")
    mem.remember("Owner billing scope note", kind="fact", scope="billing-secret", origin="user", visibility="private")
    mid_shared = mem.remember("Shared architecture rule", kind="decision", scope="team-alpha", origin="user", visibility="team_read", workspace_id=ws["id"])[1]
    contrib_tok = mem.add_member(ws["id"], "alice24", "contributor")["token"]
    old_mem = mcp_server._memory
    mcp_server._memory = mem
    try:
        # 1. scope для подсказки (владелец видит billing-secret и team-alpha)
        c_scope = mcp_server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "completion/complete",
            "params": {"ref": {"type": "ref/prompt", "name": "recall_before_task"}, "argument": {"name": "scope", "value": "team"}},
        })["result"]["completion"]["values"]
        assert "team-alpha" in c_scope

        # contributor НЕ видит приватную область billing-secret, но видит team-alpha
        tok_ctx = mcp_server._actor_token_ctx.set(contrib_tok)
        try:
            c_priv = mcp_server.handle({
                "jsonrpc": "2.0", "id": 2, "method": "completion/complete",
                "params": {"ref": {"type": "ref/resource", "uri": "padam://scope/{scope}"}, "argument": {"name": "scope", "value": ""}},
            })["result"]["completion"]["values"]
            assert "team-alpha" in c_priv
            assert "billing-secret" not in c_priv
        finally:
            mcp_server._actor_token_ctx.reset(tok_ctx)

        # 2. kind (допустимые типы с фильтрацией по префиксу)
        c_kind = mcp_server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "completion/complete",
            "params": {"ref": {"type": "ref/prompt", "name": "record_decision"}, "argument": {"name": "kind", "value": "de"}},
        })["result"]["completion"]["values"]
        assert "decision" in c_kind

        # 3. name и uri
        c_name = mcp_server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "completion/complete",
            "params": {"ref": {"type": "ref/prompt", "name": ""}, "argument": {"name": "name", "value": "weekly"}},
        })["result"]["completion"]["values"]
        assert c_name == ["weekly_memory_review"]

        c_uri = mcp_server.handle({
            "jsonrpc": "2.0", "id": 5, "method": "completion/complete",
            "params": {"ref": {"type": "ref/resource", "uri": ""}, "argument": {"name": "uri", "value": "padam://asof"}},
        })["result"]["completion"]["values"]
        assert "padam://asof/{date}" in c_uri and "padam://asof-graph/{date}" in c_uri

        # 4. derived_from с контекстом scope, days, provider, date
        c_df = mcp_server.handle({
            "jsonrpc": "2.0", "id": 6, "method": "completion/complete",
            "params": {
                "ref": {"type": "ref/prompt", "name": "record_decision"},
                "argument": {"name": "derived_from", "value": ""},
                "context": {"arguments": {"scope": "team-alpha"}},
            },
        })["result"]["completion"]["values"]
        assert c_df == [mid_shared]

        c_prov = mcp_server.handle({
            "jsonrpc": "2.0", "id": 7, "method": "completion/complete",
            "params": {"ref": {"type": "ref/resource", "uri": "padam://connectors/{provider}"}, "argument": {"name": "provider", "value": "g"}},
        })["result"]["completion"]["values"]
        assert "github" in c_prov and "gdrive" in c_prov
    finally:
        mcp_server._memory = old_mem
        mem.close()
def test_mcp_ideal_2_3_resource_annotations(tmp_path):
    """Пункт 2.3: у всех ресурсов, шаблонов и ответов resources/read есть audience, priority и ISO lastModified."""
    from datetime import datetime

    mem = Memory(user_id="ideal-2-3", store=Store(tmp_path / "m23.db"))
    mid = mem.remember("Backend service listens on port 8090", kind="fact", scope="infra", origin="user")[1]
    old_mem = mcp_server._memory
    mcp_server._memory = mem
    try:
        def _check_ann(ann):
            assert isinstance(ann, dict)
            assert isinstance(ann.get("audience"), list) and ann["audience"]
            assert set(ann["audience"]).issubset({"user", "assistant"})
            assert isinstance(ann.get("priority"), (int, float)) and 0.0 <= ann["priority"] <= 1.0
            lm = ann.get("lastModified")
            assert isinstance(lm, str) and "T" in lm
            datetime.fromisoformat(lm.replace("Z", "+00:00"))

        rlist = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "resources/list"})["result"]["resources"]
        assert len(rlist) == 3
        for item in rlist:
            _check_ann(item.get("annotations"))

        tlist = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "resources/templates/list"})["result"]["resourceTemplates"]
        assert len(tlist) >= 8
        for tpl in tlist:
            _check_ann(tpl.get("annotations"))

        for uri in (
            "padam://profile",
            "padam://review-queue",
            "padam://stats",
            "padam://recent",
            f"padam://record/{mid}",
            f"padam://timeline/{mid}",
            "padam://scope/infra",
            "padam://asof/2026-11-15",
            "padam://conflicts/all",
            f"padam://graph/{mid}",
            "padam://asof-graph/2026-11-15",
            "padam://connectors/all",
        ):
            res = mcp_server.handle({"jsonrpc": "2.0", "id": 10, "method": "resources/read", "params": {"uri": uri}})["result"]
            assert len(res["contents"]) == 1
            _check_ann(res["contents"][0].get("annotations"))
    finally:
        mcp_server._memory = old_mem
        mem.close()
def test_mcp_ideal_2_6_cancellation_and_progress_notifications(tmp_path):
    """Пункт 2.6: progressToken шлёт notifications/progress, а notifications/cancelled отменяет операцию с кодом -32800."""
    import threading

    mem = Memory(user_id="ideal-2-6", store=Store(tmp_path / "m26.db"))
    for i in range(6):
        mem.remember(f"Deployment step note #{i} for benchmark rollout", kind="fact", scope="ops", origin="user")
    for idx_ep in (1, 2):
        mem.store.execute(
            "INSERT INTO episode (id, user_id, session_id, scope, role, content, priority, replay_count, processed, created_at) "
            "VALUES (?, 'ideal-2-6', 's26', 'ops', 'user', ?, 1.0, 0, 0, '2026-11-15T01:00:00Z')",
            (f"ep_26_{idx_ep}", f"Nocturne episode rollout policy #{idx_ep} stays deterministic"),
        )
    old_mem = mcp_server._memory
    mcp_server._memory = mem
    mcp_server.pop_notifications()
    try:
        # 1. Экспорт с progressToken генерирует notifications/progress
        ex = mcp_server.handle({
            "jsonrpc": "2.0", "id": 101, "method": "tools/call",
            "params": {
                "name": "padam_export",
                "arguments": {"scope": "ops"},
                "_meta": {"progressToken": "exp-prog-1"},
            },
        })
        assert ex["result"]["isError"] is False
        notes = [n for n in mcp_server.pop_notifications() if n.get("method") == "notifications/progress"]
        assert len(notes) >= 2
        assert all(n["params"]["progressToken"] == "exp-prog-1" for n in notes)
        assert notes[-1]["params"]["progress"] == notes[-1]["params"]["total"] >= 1

        # 2. Пред-отменённый requestId сразу возвращает -32800 без запуска операции
        assert mcp_server.handle({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": "pre-cancel-99", "reason": "user aborted"},
        }) is None
        pre_res = mcp_server.handle({
            "jsonrpc": "2.0", "id": "pre-cancel-99", "method": "tools/call",
            "params": {"name": "padam_export", "arguments": {}},
        })
        assert pre_res["error"]["code"] == mcp_server.ERROR_CODES["REQUEST_CANCELLED"] == -32800

        # 3. Живая отмена во время выполнения padam_sleep через параллельный notifications/cancelled
        orig_emit = mcp_server._emit_progress
        started_ev = threading.Event()
        gate_ev = threading.Event()

        def _slow_emit(done, total, msg=""):
            orig_emit(done, total, msg)
            started_ev.set()
            gate_ev.wait(timeout=3.0)

        mcp_server._emit_progress = _slow_emit
        holder = {}
        try:
            def _run_sleep():
                holder["resp"] = mcp_server.handle({
                    "jsonrpc": "2.0", "id": "live-sleep-77", "method": "tools/call",
                    "params": {
                        "name": "padam_sleep",
                        "arguments": {"dry_run": False},
                        "_meta": {"progressToken": 77},
                    },
                })

            th = threading.Thread(target=_run_sleep, daemon=True)
            th.start()
            assert started_ev.wait(timeout=3.0)
            mcp_server.handle({
                "jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": "live-sleep-77", "reason": "timeout"},
            })
            gate_ev.set()
            th.join(timeout=5.0)
        finally:
            mcp_server._emit_progress = orig_emit

        assert "resp" in holder and "error" in holder["resp"]
        assert holder["resp"]["error"]["code"] == -32800
    finally:
        mcp_server._memory = old_mem
        mcp_server.pop_notifications()
        mem.close()
def test_mcp_ideal_2_7_ping_and_logging_set_level(tmp_path):
    """Пункт 2.7: capabilities.logging, ping, logging/setLevel (RFC 5424) и notifications/message без секретов."""
    import json

    mem = Memory(user_id="ideal-2-7", store=Store(tmp_path / "m27.db"))
    old_mem = mcp_server._memory
    old_lvl = mcp_server._mcp_log_level
    mcp_server._memory = mem
    mcp_server.pop_notifications()
    try:
        init = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})["result"]
        assert "logging" in init["capabilities"]
        assert mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"] == {}

        bad_lvl = mcp_server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "logging/setLevel",
            "params": {"level": "verbose_invalid"},
        })
        assert bad_lvl["error"]["code"] == -32602

        ok_lvl = mcp_server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "logging/setLevel",
            "params": {"level": "info"},
        })
        assert ok_lvl["result"] == {}
        notes = [n for n in mcp_server.pop_notifications() if n.get("method") == "notifications/message"]
        assert any(n["params"]["level"] == "info" and n["params"]["data"]["level"] == "info" for n in notes)

        fake_secret = "sk-ant-api03-TESTSECRETVALUE999999999999"
        mcp_server.handle({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "padam_write", "arguments": {
                "content": f"Staging credential token is {fake_secret} for local check",
                "origin": "user",
            }},
        })
        log_notes = [n for n in mcp_server.pop_notifications() if n.get("method") == "notifications/message"]
        assert any(n["params"]["level"] == "warning" and n["params"]["data"]["event"] == "secrets_masked" for n in log_notes)
        serialized = json.dumps(log_notes, ensure_ascii=False)
        assert fake_secret not in serialized
        assert "Staging credential" not in serialized

        # При повышении порога до error info/warning больше не отправляются
        assert mcp_server.handle({
            "jsonrpc": "2.0", "id": 6, "method": "logging/setLevel",
            "params": {"level": "error"},
        })["result"] == {}
        mcp_server.pop_notifications()
        assert mcp_server.emit_mcp_log("warning", "padam.test", {"msg": "ignored"}) is None
        err_note = mcp_server.emit_mcp_log("error", "padam.test", {"msg": f"boom {fake_secret}"})
        assert err_note is not None
        assert fake_secret not in json.dumps(err_note)
    finally:
        mcp_server.set_log_level(old_lvl)
        mcp_server._memory = old_mem
        mcp_server.pop_notifications()
        mem.close()
def test_mcp_ideal_4_2_input_and_record_limits(tmp_path):
    """Пункт 4.2: пределы длины строк, limit/batch, числа элементов и глубины/размера JSON."""
    import json
    import os
    import subprocess
    import sys

    from padam import config

    mem = Memory(user_id="ideal-4-2", store=Store(tmp_path / "m42.db"))
    old_mem = mcp_server._memory
    mcp_server._memory = mem
    try:
        # 1. Длинный текст и длинный поисковый запрос
        r_long = mcp_server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "padam_write", "arguments": {"content": "A" * (config.MAX_CONTENT_CHARS + 1)}},
        })["result"]
        assert r_long["isError"] is True and "longer than" in r_long["content"][0]["text"]

        r_qlong = mcp_server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "padam_search", "arguments": {"query": "q" * 4001}},
        })["result"]
        assert r_qlong["isError"] is True and "longer than" in r_qlong["content"][0]["text"]

        # 2. Огромный limit / batch / offset / списки
        for tname, args in (
            ("padam_search", {"query": "test", "limit": config.MAX_RECALL_LIMIT + 1}),
            ("padam_search", {"query": "test", "scopes": [f"s{i}" for i in range(11)]}),
            ("padam_export", {"limit": config.MAX_EXPORT_LIMIT + 1}),
            ("padam_export", {"offset": -1}),
            ("padam_sleep", {"batch": 4097}),
            ("padam_write", {"content": "ok", "derived_from": [f"id-{i}" for i in range(21)]}),
            ("padam_write", {"content": "ok", "links": [{"target": f"id-{i}", "relation": "cause"} for i in range(21)]}),
        ):
            res = mcp_server.handle({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": tname, "arguments": args},
            })["result"]
            assert res["isError"] is True, f"{tname} should reject {args}"

        # 3. Слишком глубокий JSON (глубина > MAX_JSON_DEPTH=32, без RecursionError даже при 1200 уровнях)
        deep: dict = {"x": 1}
        for _ in range(config.MAX_JSON_DEPTH + 10):
            deep = {"nested": deep}
        r_deep = mcp_server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "padam_search", "arguments": {"query": "test"}},
            "extra": deep,
        })
        assert r_deep["error"]["code"] == -32602

        very_deep: list = [1]
        for _ in range(1200):
            very_deep = [very_deep]
        r_vdeep = mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "ping", "params": very_deep})
        assert r_vdeep["error"]["code"] == -32602

        # 4. Слишком много узлов JSON (> MAX_JSON_NODES)
        wide = {"jsonrpc": "2.0", "id": 6, "method": "ping", "params": list(range(config.MAX_JSON_NODES + 50))}
        assert mcp_server.handle(wide)["error"]["code"] == -32602

        # 5. Гигантское сообщение в stdio (> MAX_MCP_MESSAGE_BYTES) не роняет сервер
        env = dict(os.environ, PADAM_DB=str(tmp_path / "stdio42.db"), PADAM_MAX_MCP_BYTES="2048")
        huge = '{"jsonrpc":"2.0","id":1,"method":"ping","pad":"' + ("x" * 3000) + '"}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
        proc = subprocess.run(
            [sys.executable, "-m", "padam.mcp_server"],
            input=huge, capture_output=True, text=True, encoding="utf-8", env=env, timeout=30,
        )
        lines = [json.loads(ln) for ln in proc.stdout.strip().splitlines() if ln.strip()]
        assert len(lines) == 2
        assert lines[0]["error"]["code"] == -32600
        assert lines[1]["id"] == 2 and lines[1]["result"] == {}
    finally:
        mcp_server._memory = old_mem
        mem.close()
def test_mcp_ideal_4_1_fuzz_stability():
    """Пункт 4.1: fuzz-проверка 400 случайных вызовов (полный 10k прогон — scripts/mcp_fuzz_check.py) без падений."""
    import sys
    from pathlib import Path

    scripts_dir = str(Path(__file__).resolve().parent.parent / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    import mcp_fuzz_check

    # Явная проверка не-dict req и не-dict params (ошибка, найденная fuzz-генератором)
    assert mcp_server.handle("not-an-object")["error"]["code"] == -32600
    assert mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "bad"})["error"]["code"] == -32602

    rep = mcp_fuzz_check.run_fuzz(count=400, seed=41)
    assert rep["exceptions"] == 0
    assert rep["invalid_responses"] == 0
    assert rep["ok_calls"] > 50 and rep["tool_errors"] > 50
def test_mcp_ideal_4_3_http_session_rate_limit(tmp_path):
    """Пункт 4.3: ограничение частоты в HTTP-режиме (выключено по умолчанию; при включении даёт 429 + Retry-After)."""
    import json
    import threading
    import urllib.error
    import urllib.request

    from padam import config

    assert config.mcp_rate_limit() == 0

    mem = Memory(user_id="ideal-4-3", store=Store(tmp_path / "m43.db"))
    srv, url, tok = mcp_server.make_mcp_http_server(
        memory=mem, host="127.0.0.1", port=0, token="rate-limit-test-token-1234",
        rate_limit=3, rate_window_s=30.0,
    )
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        def _post(sess_id: str, rpc_id: int, lang: str | None = None):
            body = json.dumps({"jsonrpc": "2.0", "id": rpc_id, "method": "ping"}).encode("utf-8")
            hdrs = {
                "Authorization": f"Bearer {tok}",
                "Content-Type": "application/json",
                "Mcp-Session-Id": sess_id,
            }
            if lang:
                hdrs["X-Padam-Lang"] = lang
            req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status, dict(resp.headers), json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers), json.loads(e.read().decode("utf-8"))

        # Сессия A: первые 3 запроса проходят, 4-й получает 429 + Retry-After + -32001
        for idx in (1, 2, 3):
            st, _, payload = _post("sess-A", idx)
            assert st == 200 and payload["result"] == {}

        st4, hdr4, payload4 = _post("sess-A", 4, lang="ru")
        assert st4 == 429
        assert int(hdr4.get("Retry-After", "0")) >= 1
        assert payload4["error"]["code"] == mcp_server.ERROR_CODES["RATE_LIMITED"] == -32001
        assert "Превышен лимит" in payload4["error"]["message"]

        # Сессия B имеет независимую квоту и проходит
        st_b, _, payload_b = _post("sess-B", 10)
        assert st_b == 200 and payload_b["result"] == {}
    finally:
        srv.shutdown()
        srv.server_close()
        mem.close()
