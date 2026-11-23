"""Сборщик Desktop Extension (.mcpb / .dxt) для установки в Claude Desktop двойным кликом."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from . import __version__


def build_mcpb_manifest(*, user_id: str = "default") -> dict[str, Any]:
    return {
        "dxt_version": "0.2",
        "name": "padam-nocturne",
        "display_name": "PADAM NOCTURNE Memory",
        "version": __version__,
        "description": "Local-first AI memory with prompt-injection quarantine, DLP shield, bi-temporal recall, cognitive rollback, and X-Wing PQC sync.",
        "author": {"name": "Maksim Galatin", "email": "codeofdigitaleternity@gmail.com"},
        "repository": {"type": "git", "url": "https://github.com/MaksimGalatin/padam-nocturne"},
        "license": "LicenseRef-PADAM-1.0",
        "server": {
            "type": "python",
            "entry_point": "padam.mcp_server",
            "mcp_config": {
                "command": "padam-mcp",
                "args": [],
                "env": {
                    "PADAM_DB": "${user_config.db_path}",
                    "PADAM_USER": user_id,
                    "PADAM_STRICT": "${user_config.strict_mode}",
                },
            },
        },
        "user_config": {
            "db_path": {
                "type": "string",
                "title": "SQLite Memory Path",
                "description": "Local path to your PADAM SQLite database",
                "default": "~/.padam/memory.db",
                "required": False,
            },
            "strict_mode": {
                "type": "string",
                "title": "Strict Quarantine Mode (0 or 1)",
                "default": "0",
                "required": False,
            },
        },
        "tools_generated": False,
    }


def build_mcpb_bundle(out_path: Path | str, *, user_id: str = "default") -> dict[str, Any]:
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_mcpb_manifest(user_id=user_id)
    readme_txt = (
        "PADAM NOCTURNE Desktop Extension (.mcpb)\n"
        "Requires padam-nocturne installed locally (pip install padam-nocturne or uvx).\n"
    )
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        zf.writestr("README.txt", readme_txt)
    return {
        "status": "packed",
        "path": str(target),
        "size_bytes": target.stat().st_size,
        "version": __version__,
    }
