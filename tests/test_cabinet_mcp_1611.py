# -*- coding: utf-8 -*-
"""Тесты интеграции ЛК (тарифы, оплата, чат с AIfa) в MCP-сервер padam_cabinet."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from padam import cabinet, mcp_server  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402


def _rpc(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    return mcp_server.handle({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})


def test_padam_cabinet_mcp_tool_and_resource(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    m = Memory(user_id="cab_mcp", store=Store(":memory:"))
    m.remember("My secret token is sk-1234567890abcdef1234567890abcdef", kind="fact", origin="user")
    monkeypatch.setattr(mcp_server, "mem", lambda: m)

    # 1. Список базовых инструментов по умолчанию не меняется (9 штук)
    names_default = {t["name"] for t in _rpc("tools/list")["result"]["tools"]}
    assert "padam_cabinet" not in names_default
    assert len(names_default) == 9

    # 2. При PADAM_MCP_CABINET_TOOL=1 инструмент публикуется в tools/list
    monkeypatch.setenv("PADAM_MCP_CABINET_TOOL", "1")
    names_enabled = {t["name"] for t in _rpc("tools/list")["result"]["tools"]}
    assert "padam_cabinet" in names_enabled

    # 3. plans и upgrade_url работают оффлайн
    r_plans = _rpc("tools/call", {"name": "padam_cabinet", "arguments": {"action": "plans"}})
    assert not r_plans["result"]["isError"]
    sc = r_plans["result"]["structuredContent"]
    assert sc["ok"] is True and len(sc["plans"]) >= 3

    # 4. Ресурс padam://cabinet читается в JSON без секретных токенов
    r_res = _rpc("resources/read", {"uri": "padam://cabinet"})
    body = json.loads(r_res["result"]["contents"][0]["text"])
    assert "authenticated" in body and "plans" in body
    assert "cookie" not in body

    # 5. Вход + чат с AIfa с безопасной передачей замаскированной памяти
    with patch.object(cabinet, "send_login_code", return_value={"ok": True, "sent": True}), \
         patch.object(cabinet, "verify_login_code", return_value={"ok": True, "authenticated": True, "email": "u@example.com"}), \
         patch.object(cabinet, "send_aifa_message", return_value={"ok": True, "reply": "Привет!", "sent_local": ["[masked]"]}) as mock_send:
        r_code = _rpc("tools/call", {"name": "padam_cabinet", "arguments": {"action": "send_code", "email": "u@example.com"}})
        assert r_code["result"]["structuredContent"]["ok"] is True

        r_ver = _rpc("tools/call", {"name": "padam_cabinet", "arguments": {"action": "verify_code", "email": "u@example.com", "code": "123456"}})
        assert r_ver["result"]["structuredContent"]["authenticated"] is True

        r_chat = _rpc(
            "tools/call",
            {
                "name": "padam_cabinet",
                "arguments": {"action": "chat_send", "message": "sk-1234567890abcdef1234567890abcdef", "attach_local_memories": True},
            },
        )
        assert r_chat["result"]["structuredContent"]["reply"] == "Привет!"
        passed_ctx = mock_send.call_args.kwargs.get("masked_local_records") or []
        assert all("sk-1234567890" not in item for item in passed_ctx)

    m.close()
