"""Тесты финального ТОП-10 v4 (распространение, интеграции и виральный рост)."""
from __future__ import annotations

import json
from pathlib import Path


def test_top10v4_1_setup_clients_and_catalog_manifests(tmp_path):
    from padam import setup_clients

    home = tmp_path / "home"
    proj = tmp_path / "proj"
    home.mkdir()
    proj.mkdir()

    # Создаём существующий .mcp.json с чужим сервером, чтобы проверить бережное слияние и .bak
    mcp_json = proj / ".mcp.json"
    mcp_json.write_text(json.dumps({"mcpServers": {"other": {"command": "echo"}}}), encoding="utf-8")

    # Имитируем наличие директорий Cursor, Cline и Codex
    (home / ".cursor").mkdir(parents=True)
    (home / ".codex").mkdir(parents=True)

    res = setup_clients.setup_clients(
        clients=["claude_code", "cursor", "vscode", "codex", "cline", "jetbrains"],
        home=home,
        project_dir=proj,
        verify=True,
    )
    assert res["installed_count"] == 6
    assert res["verified"]["ok"] is True
    assert res["verified"]["tools_count"] == 9
    assert res["deeplinks"]["cursor"].startswith("cursor://")
    assert res["deeplinks"]["vscode"].startswith("vscode:mcp/install?")

    # Проверяем сохранность чужого сервера и создание .bak
    merged = json.loads(mcp_json.read_text(encoding="utf-8"))
    assert "other" in merged["mcpServers"]
    assert merged["mcpServers"]["padam"]["command"] == "padam-mcp"
    assert (proj / ".mcp.json.bak").exists()

    # Проверяем манифесты каталогов MCP в корне репозитория
    root = Path(__file__).resolve().parents[1]
    assert (root / "smithery.yaml").exists()
    glama = json.loads((root / "glama.json").read_text(encoding="utf-8"))
    assert glama["toolsCount"] == 9


def test_top10v4_2_mcpb_desktop_extension_and_vscode_extension(tmp_path):
    import zipfile
    from padam import pack_extension

    bundle_path = tmp_path / "padam.mcpb"
    rep = pack_extension.build_mcpb_bundle(bundle_path, user_id="arch")
    assert rep["status"] == "packed"
    assert bundle_path.exists() and rep["size_bytes"] > 200

    with zipfile.ZipFile(bundle_path, "r") as zf:
        assert "manifest.json" in zf.namelist()
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest["dxt_version"] == "0.2"
        assert manifest["server"]["mcp_config"]["command"] == "padam-mcp"

    root = Path(__file__).resolve().parents[1]
    vs_pkg = json.loads((root / "extensions" / "vscode-padam" / "package.json").read_text(encoding="utf-8"))
    assert "mcpServerDefinitionProviders" in vs_pkg["contributes"]
    assert (root / "extensions" / "vscode-padam" / "extension.js").exists()
