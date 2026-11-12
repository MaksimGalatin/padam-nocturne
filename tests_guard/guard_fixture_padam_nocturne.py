"""Fixture for the PADAM NOCTURNE MCP contribution (mcp.padam-nocturne).

Keeps the reviewed boundary: read-only tools keep Guard's usual handling, every tool that changes memory or
exports all of it is review-gated, unknown future tools fall back to review, and the entry stays external
and opt-in for the exact `uvx padam-nocturne` launch.
"""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.mcp_server_contribution import validate_mcp_contribution

from .mcp_contribution_client import mcp_tool_state

_PADAM = Path(__file__).resolve().parents[1] / "contributions/mcp-servers/mcp.padam-nocturne.json"

_READ_ONLY = {"padam_search", "padam_timeline", "padam_stats"}
_REVIEW = {"padam_write", "padam_confirm", "padam_refute", "padam_sleep", "padam_export"}


def _payload() -> dict[str, object]:
    payload = json.loads(_PADAM.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_padam_nocturne_contribution_validates() -> None:
    validate_mcp_contribution(_payload())


def test_padam_nocturne_is_external_opt_in() -> None:
    payload = _payload()
    assert payload["trustClass"] == "external"
    assert payload["activation"] == "opt-in"


def test_padam_nocturne_launch_is_the_reviewed_uvx_package() -> None:
    launch = _payload()["launch"]
    assert launch == {"kind": "package-launcher", "command": "uvx", "package": "padam-nocturne"}


def test_padam_nocturne_memory_changing_tools_require_review() -> None:
    payload = _payload()
    for tool_name in _REVIEW:
        assert mcp_tool_state(payload, tool_name) == "review", tool_name


def test_padam_nocturne_read_only_tools_inherit() -> None:
    payload = _payload()
    for tool_name in _READ_ONLY:
        assert mcp_tool_state(payload, tool_name) == "inherit", tool_name


def test_padam_nocturne_unlisted_tools_default_to_review() -> None:
    payload = _payload()
    assert mcp_tool_state(payload, "padam_erase_everything") == "review"
    assert mcp_tool_state(payload, "PADAM_WRITE ") == "review"


def test_padam_nocturne_declares_every_server_tool() -> None:
    declared = {item["name"] for item in _payload()["tools"] if isinstance(item, dict)}
    assert _READ_ONLY | _REVIEW <= declared
