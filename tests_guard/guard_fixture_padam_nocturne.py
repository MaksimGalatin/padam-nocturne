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


# --- Review bar (docs/guard/mcp-server-contributions.md): inert until local-admin enable; a this-device grant wins.
# Same structure as Guard's tests/test_guard_mcp_server_grants.py, applied to mcp.padam-nocturne.

from pathlib import Path as _Path

from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident, native_test_guard_home  # noqa: F401
from .mcp_extension_driver import apply_contributed_mcp_decision, apply_local_mcp_extension_decision
from .mcp_policy_catalog_fixture import admit_mcp_layers

_EXTENSION = "command.mcp-padam-nocturne"


def _padam_identity():
    return build_mcp_server_identity(config_path="", command="uvx", args=("padam-nocturne",), transport="stdio")


def _padam_artifact(tool_name: str):
    return build_tool_call_artifact(
        harness="codex",
        server_name="padam",
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=_padam_identity(),
    )


def _layer(kind: ControlLayerKind) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=kind,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(ExtensionControl(target=ControlTarget(ControlTargetKind.EXTENSION, _EXTENSION), state=ControlState.ENABLED),),
    )


class _AuthorityStore:
    def __init__(self, layers=()) -> None:
        self.layers = tuple(layers)
        self.guard_home = native_test_guard_home()
        self.path = self.guard_home / "guard.db"
        admit_mcp_layers(self, self.layers)

    def has_local_cli_grant_rules(self) -> bool:
        return False

    def read_extension_control_authority_for_registry(self, registry, **_kwargs) -> ExtensionControlAuthorityView:
        digest = getattr(registry, "catalog_digest", "0" * 64)
        return ExtensionControlAuthorityView(health=AuthorityHealth.PROTECTED, revision=1, catalog_digest=digest, layers=self.layers)


def test_padam_nocturne_stays_inert_until_local_admin_enable() -> None:
    assert apply_contributed_mcp_decision(_AuthorityStore(), _padam_artifact("padam_write"), "allow") is None


def test_padam_nocturne_enabled_raises_write_to_review() -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN),))
    decision = apply_contributed_mcp_decision(enabled, _padam_artifact("padam_write"), "allow")
    assert decision is not None and decision[:2] == ("review", "catalog-mcp-extension")


def test_padam_nocturne_signed_cloud_enable_does_not_activate() -> None:
    cloud = _AuthorityStore((_layer(ControlLayerKind.SIGNED_CLOUD),))
    assert apply_contributed_mcp_decision(cloud, _padam_artifact("padam_write"), "allow") is None


def test_padam_nocturne_enabled_search_keeps_guard_handling() -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN),))
    assert apply_contributed_mcp_decision(enabled, _padam_artifact("padam_search"), "allow") is None


def test_padam_nocturne_enabled_unlisted_tool_goes_to_review() -> None:
    enabled = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN),))
    decision = apply_contributed_mcp_decision(enabled, _padam_artifact("padam_erase_everything"), "allow")
    assert decision is not None and decision[:2] == ("review", "catalog-mcp-extension")


def test_padam_nocturne_this_device_grant_wins(tmp_path: _Path) -> None:
    identity = _padam_identity()
    store = GuardStore(tmp_path / "guard-home")
    cli_identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
        name=identity.package_name or "mcp-server",
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label="uvx padam-nocturne",
    )
    store.record_local_cli_observation(
        cli_identity, seen_at=utc_now(), surface="mcp", server_identity_hash=identity.identity_hash,
        server_command=identity.command, server_args_hash=identity.args_hash, help_status="ok",
    )
    store.replace_local_cli_commands(
        cli_identity.cli_id, (LocalCliCommand("padam_write", "padam_write", "padam_write", "Write a memory"),)
    )
    store.upsert_local_cli_grant(
        identity=cli_identity, state="allowed", expected_revision=0, updated_at=utc_now(),
        command_states={"padam_write": "allow"},
    )
    granted = apply_local_mcp_extension_decision(store, _padam_artifact("padam_write"), "review")
    assert granted is not None and granted[:2] == ("allow", "local-mcp-extension")
