"""Фаза 2 аудита GLM, MCP-07: агент не выбирает корень репозитория для якоря кода."""
import pytest

from padam import mcp_server
from padam.memory import Memory
from padam.store import Store


def test_корень_вне_закреплённого_отклоняется(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    proj = tmp_path / "proj"; proj.mkdir(); (proj / "a.py").write_text("x = 1\n", encoding="utf-8")
    чужой = tmp_path / "pristine_copy"; чужой.mkdir()
    monkeypatch.setenv("PADAM_REPO_ROOT", str(proj))
    m = Memory(user_id="u", store=Store(tmp_path / "c.db"))
    monkeypatch.setattr(mcp_server, "_memory", m)
    with pytest.raises(PermissionError):
        mcp_server.call_tool("padam_code_anchor", {"action": "check", "repo_root": str(чужой)})
    with pytest.raises(PermissionError):
        mcp_server.call_tool("padam_code_anchor", {"action": "check", "repo_root": str(tmp_path.anchor)})  # корень диска
    mcp_server.call_tool("padam_code_anchor", {"action": "check"})          # закреплённый — работает
    mcp_server.call_tool("padam_code_anchor", {"action": "check", "repo_root": str(proj)})
    m.close()
