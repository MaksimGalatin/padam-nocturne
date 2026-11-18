"""Фаза 2 аудита GLM, MCP-09: окно MCP App принимает сообщения только от родителя."""
from padam import mcp_apps


def test_сообщения_только_от_родителя():
    js = mcp_apps._MCP_BRIDGE_JS
    i = js.find('window.addEventListener("message"')
    assert "ev.source !== window.parent" in js[i:i + 400]
