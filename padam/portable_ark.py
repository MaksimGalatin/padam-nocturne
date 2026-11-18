# -*- coding: utf-8 -*-
"""Переносимый «Суверенный Флеш-Ковчег» (Portable USB/SSD Ark, пункт 9).

Правило безопасности (поправка приёмки 17.11):
1. Экспорт выполняется строго в указанную пользователем папку `target_dir`.
2. Никакие открытые секреты (`owner.key`, `node.key.json`, незашифрованные дампы БД)
   в выходную папку НЕ попадают — на носитель записывается только постквантово
   зашифрованная капсула `capsule.pqc.json` (X-Wing ML-KEM-768 + X25519 + AES-256-GCM),
   офлайн-манифест SHA-256 и статический HTML-паспорт (без секретов и без внешнего JS).
"""
from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import phoenix, pqc_mlkem


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def export_portable_ark(
    memory,
    target_dir: str | Path,
    *,
    mlkem_public: bytes,
    x25519_public: bytes,
    lora_path: str | Path | None = None,
) -> dict[str, Any]:
    """Экспортирует автономный PQC-комплект Ковчега в указанную папку `target_dir` без открытых секретов."""
    out_dir = Path(target_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    cap_path = out_dir / "capsule.pqc.json"
    pqc_info = phoenix.pack_pqc_phoenix_capsule(
        memory.store.path,
        cap_path,
        mlkem_public=mlkem_public,
        x25519_public=x25519_public,
        lora_path=lora_path,
    )

    cap_sha = _sha256_file(cap_path)
    created_at = datetime.now(timezone.utc).isoformat()

    readme_txt = (
        "PADAM NOCTURNE — Portable Sovereign Ark\n"
        f"Created (UTC): {created_at}\n"
        "Contents:\n"
        "  1. capsule.pqc.json  - Post-quantum X-Wing (ML-KEM-768 + X25519 + AES-256-GCM) encrypted capsule.\n"
        "  2. passport.html     - Offline verification passport (zero secrets).\n"
        "  3. manifest.sha256.json - SHA-256 checksums of portable files.\n\n"
        "Recovery requires your private ML-KEM-768 seed (64B) + X25519 key (stored separately via Shamir shares).\n"
    )
    readme_path = out_dir / "README_RECOVERY.txt"
    readme_path.write_text(readme_txt, encoding="utf-8")

    passport_html = (
        "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'none'; script-src 'none'\">"
        "<title>PADAM Portable Ark Passport</title></head><body>"
        "<h1>PADAM NOCTURNE · Portable Sovereign Ark</h1>"
        f"<p>Created: {html.escape(created_at)}</p>"
        f"<p>Scheme: {html.escape(str(pqc_info.get('scheme', '')))}</p>"
        f"<p>Encrypted capsule SHA-256: <code>{html.escape(cap_sha)}</code></p>"
        f"<p>Inner archive SHA-256: <code>{html.escape(str(pqc_info.get('inner_sha256', '')))}</code></p>"
        "<p>Private keys are NOT stored on this media. Recover with owner Shamir shares / PQC private key.</p>"
        "</body></html>\n"
    )
    passport_path = out_dir / "passport.html"
    passport_path.write_text(passport_html, encoding="utf-8")

    manifest = {
        "schema": "padam-portable-ark-v1",
        "created_at": created_at,
        "secrets_included": False,
        "files": {
            "capsule.pqc.json": cap_sha,
            "README_RECOVERY.txt": _sha256_file(readme_path),
            "passport.html": _sha256_file(passport_path),
        },
    }
    manifest_path = out_dir / "manifest.sha256.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return {
        "ok": True,
        "target_dir": str(out_dir),
        "secrets_included": False,
        "capsule_path": str(cap_path),
        "manifest_path": str(manifest_path),
        "passport_path": str(passport_path),
        "capsule_sha256": cap_sha,
    }


def export_portable_ark_with_new_keys(memory, target_dir: str | Path) -> dict[str, Any]:
    """Создаёт переносимый Ковчег с НОВОЙ парой ключей X-Wing; закрытые ключи — отдельным файлом РЯДОМ с папкой.

    Общая точка для команды `padam ark-portable` и Studio (17.11.2026). В саму папку ключи не попадают:
    флешку можно потерять, а файл ключей владелец уносит отдельно (или делит по Шамиру).
    Папка должна быть новой или пустой — чтобы не смешать Ковчег с чужими файлами.
    """
    import base64
    import json

    from . import pqc_mlkem

    out_dir = Path(target_dir).expanduser()
    if not out_dir.is_absolute():
        raise ValueError("target_dir must be an absolute path")
    out_dir = out_dir.resolve()
    if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
        raise ValueError("target_dir must be a new or empty folder")
    kp = pqc_mlkem.generate_xwing_keypair()
    rep = export_portable_ark(
        memory, out_dir,
        mlkem_public=bytes(kp["mlkem_public"]),
        x25519_public=bytes(kp["x25519_public"]),
    )
    key_out = out_dir.parent / (out_dir.name + ".owner_keys.json")
    key_out.write_text(json.dumps({
        "mlkem_seed64_b64": base64.b64encode(bytes(kp["mlkem_private"])).decode("ascii"),
        "x25519_priv_b64": base64.b64encode(bytes(kp["x25519_private"])).decode("ascii"),
    }, indent=2) + "\n", encoding="utf-8")
    return {**rep, "private_keys_saved_separately_to": str(key_out), "backend": kp.get("backend")}
