# -*- coding: utf-8 -*-
"""Единая «Феникс-Капсула» (`padam phoenix pack / unpack`) для переноса личности за 10 секунд.

Упаковывает в переносимый ZIP-архив с SHA-256 манифестом:
- базу SQLite (`memory.db`);
- ключ подписи владельца (`memory.db.owner.key`, если присутствует);
- локальные L3-манифесты и `lora_manifest.json` (`<db>.l3/`, без открытых API-ключей).
"""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CAPSULE_SCHEMA = "padam-phoenix-capsule-v1"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pack_phoenix_capsule(
    db_path: str | Path,
    out_capsule: str | Path,
    *,
    lora_path: str | Path | None = None,
) -> dict[str, Any]:
    db_file = Path(db_path).resolve()
    if not db_file.exists():
        raise FileNotFoundError(f"Database not found: {db_file}")

    out_file = Path(out_capsule).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = out_file.with_name(f".{out_file.name}.{os.getpid()}.tmp")

    entries: dict[str, bytes] = {}
    entries["memory.db"] = db_file.read_bytes()

    owner_key = db_file.with_name(db_file.name + ".owner.key")
    if owner_key.exists():
        entries["memory.db.owner.key"] = owner_key.read_bytes()

    l3_dir = Path(str(db_file) + ".l3")
    if l3_dir.is_dir():
        for p in sorted(l3_dir.rglob("*")):
            if p.is_file():
                rel = p.relative_to(l3_dir).as_posix()
                entries[f"l3/{rel}"] = p.read_bytes()

    if lora_path is not None:
        lp = Path(lora_path).resolve()
        if not lp.exists():
            raise FileNotFoundError(f"LoRA adapter not found: {lp}")
        entries[f"lora/{lp.name}"] = lp.read_bytes()

    hashes = {name: _sha256_bytes(raw) for name, raw in entries.items()}
    manifest = {
        "schema": CAPSULE_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": hashes,
        "total_bytes": sum(len(v) for v in entries.values()),
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    with zipfile.ZipFile(tmp_out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, raw in entries.items():
            zf.writestr(name, raw)
        zf.writestr("capsule.manifest.json", manifest_bytes)

    os.replace(tmp_out, out_file)
    capsule_sha = _sha256_bytes(out_file.read_bytes())
    return {
        "ok": True,
        "schema": CAPSULE_SCHEMA,
        "capsule_path": str(out_file),
        "capsule_sha256": capsule_sha,
        "file_count": len(entries),
        "files": list(hashes.keys()),
    }


def unpack_phoenix_capsule(
    capsule_path: str | Path,
    target_db_path: str | Path,
) -> dict[str, Any]:
    cap_file = Path(capsule_path).resolve()
    if not cap_file.exists():
        raise FileNotFoundError(f"Capsule not found: {cap_file}")

    target_db = Path(target_db_path).resolve()
    target_db.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(cap_file, "r") as zf:
        names = set(zf.namelist())
        if "capsule.manifest.json" not in names or "memory.db" not in names:
            raise ValueError("Invalid Phoenix capsule: missing capsule.manifest.json or memory.db")
        manifest = json.loads(zf.read("capsule.manifest.json").decode("utf-8"))
        if manifest.get("schema") != CAPSULE_SCHEMA:
            raise ValueError(f"Unsupported capsule schema: {manifest.get('schema')}")

        expected_files: dict[str, str] = dict(manifest.get("files") or {})
        verified: dict[str, bytes] = {}
        for name, exp_sha in expected_files.items():
            if ".." in Path(name).parts or name.startswith("/"):
                raise ValueError(f"Unsafe path in capsule: {name}")
            if name not in names:
                raise ValueError(f"Missing declared file in capsule: {name}")
            raw = zf.read(name)
            if _sha256_bytes(raw) != exp_sha:
                raise ValueError(f"SHA-256 mismatch for {name}")
            verified[name] = raw

    # Атомарная запись после полной проверки целостности всех файлов
    tmp_db = target_db.with_name(f".{target_db.name}.{os.getpid()}.tmp")
    tmp_db.write_bytes(verified["memory.db"])
    os.replace(tmp_db, target_db)

    if "memory.db.owner.key" in verified:
        key_dst = target_db.with_name(target_db.name + ".owner.key")
        key_dst.write_bytes(verified["memory.db.owner.key"])

    l3_dir = Path(str(target_db) + ".l3")
    restored_files = ["memory.db"]
    for name, raw in verified.items():
        if name.startswith("l3/"):
            rel = name[3:]
            dst = (l3_dir / rel).resolve()
            if not str(dst).startswith(str(l3_dir.resolve())):
                raise ValueError(f"Path traversal blocked: {name}")
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(raw)
            restored_files.append(name)
        elif name.startswith("lora/"):
            lora_dir = target_db.parent / "lora"
            lora_dir.mkdir(parents=True, exist_ok=True)
            dst = (lora_dir / Path(name).name).resolve()
            dst.write_bytes(raw)
            restored_files.append(name)

    return {
        "ok": True,
        "target_db": str(target_db),
        "restored_count": len(restored_files),
        "restored_files": restored_files,
    }
