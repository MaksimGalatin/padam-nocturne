"""Командная память проекта в Git через подписанный контейнер MemCube (.padam/team.memcube).

Позволяет команде разработчиков синхронизировать архитектурные решения
и правила проекта прямо через Git без облачного сервера, сохраняя Ed25519/X-Wing
подпись и автоматический карантин для недоверенных авторов.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from . import memcube
from .memory import Memory

TEAM_VAULT_REL = Path(".padam") / "team.memcube"


def export_team_vault(
    mem: Memory,
    *,
    project_dir: Path | str,
    scope: str = "project",
    passphrase: str | None = None,
    recipient_pub: dict[str, Any] | str | None = None,
    sender_sk: ed25519.Ed25519PrivateKey | None = None,
) -> dict[str, Any]:
    root = Path(project_dir)
    out_file = root / TEAM_VAULT_REL
    out_file.parent.mkdir(parents=True, exist_ok=True)
    cube = memcube.export_memcube(
        mem,
        scope=scope,
        passphrase=passphrase,
        sender_sk=sender_sk,
        recipient_pub=recipient_pub,
        rights="team-read-only",
        force=True,
    )
    out_file.write_text(json.dumps(cube, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    hdr = cube.get("header") or {}
    return {
        "status": "exported",
        "path": str(out_file),
        "scope": scope,
        "author_pub_hex": hdr.get("author_pub_hex"),
        "records_count": (hdr.get("provenance") or {}).get("records_count", 0),
        "cipher": hdr.get("cipher"),
    }


def sync_team_vault(
    mem: Memory,
    *,
    project_dir: Path | str,
    scope: str | None = None,
    passphrase: str | None = None,
    recipient_identity: Any | None = None,
    trusted_authors: set[str] | list[str] | None = None,
) -> dict[str, Any]:
    root = Path(project_dir)
    vault_file = root / TEAM_VAULT_REL
    if not vault_file.exists():
        raise FileNotFoundError(f"Team vault not found: {vault_file}")
    raw = vault_file.read_text(encoding="utf-8")
    res = memcube.import_memcube(
        mem,
        raw,
        passphrase=passphrase,
        recipient_identity=recipient_identity,
        trusted_authors=trusted_authors,
        target_scope=scope,
        force=True,
    )
    return {"status": "synced", "path": str(vault_file), **res}
