#!/usr/bin/env python3
"""Сборка и проверка браузерных расширений PADAM Memory Guard (Chromium и Firefox).

Все комментарии и диагностика — на русском. Деньги не тратятся, сеть не требуется.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ICONS = (16, 32, 48, 64, 128)
REQUIRED_LOCALES = ("en", "ru", "es", "zh", "zh_CN")
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def read_padam_version(root: Path = ROOT) -> str:
    """Читает __version__ из padam/__init__.py без обязательного импорта зависимостей."""
    init_text = (root / "padam" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', init_text, re.MULTILINE)
    if not m:
        raise RuntimeError("Не удалось найти __version__ в padam/__init__.py")
    return m.group(1)


def validate_extension_dir(browser: str, ext_dir: Path, expected_version: str, sync_version: bool = False) -> dict:
    """Проверяет manifest.json, CSP, иконки, локали и скрипты расширения."""
    if not ext_dir.is_dir():
        raise FileNotFoundError(f"Каталог расширения не найден: {ext_dir}")

    manifest_path = ext_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("manifest_version") != 3:
        raise ValueError(f"{browser}: manifest_version должен быть 3")
    if manifest.get("default_locale") != "en":
        raise ValueError(f"{browser}: default_locale должен быть 'en'")

    if sync_version and manifest.get("version") != expected_version:
        manifest["version"] = expected_version
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if manifest.get("version") != expected_version:
        raise ValueError(
            f"{browser}: версия в manifest.json ({manifest.get('version')}) "
            f"не совпадает с padam/__init__.py ({expected_version})"
        )

    csp = manifest.get("content_security_policy", {}).get("extension_pages", "")
    if "default-src 'none'" not in csp or "script-src 'self'" not in csp:
        raise ValueError(f"{browser}: ослабленный CSP extension_pages: {csp!r}")

    bg = manifest.get("background", {})
    if browser == "chromium" and not bg.get("service_worker"):
        raise ValueError("chromium: отсутствует background.service_worker")
    if browser == "firefox":
        gecko = manifest.get("browser_specific_settings", {}).get("gecko", {})
        if not gecko.get("id") or not gecko.get("strict_min_version"):
            raise ValueError("firefox: отсутствуют обязательные поля browser_specific_settings.gecko")
        if "scripts" not in bg:
            raise ValueError("firefox: отсутствует background.scripts")

    for req_file in ("background.js", "popup.html", "popup.js", "popup.css"):
        if not (ext_dir / req_file).is_file():
            raise FileNotFoundError(f"{browser}: отсутствует {req_file}")

    for sz in REQUIRED_ICONS:
        icon_path = ext_dir / "icons" / f"icon{sz}.png"
        if not icon_path.is_file():
            raise FileNotFoundError(f"{browser}: отсутствует иконка {icon_path.name}")

    for loc in REQUIRED_LOCALES:
        msg_path = ext_dir / "_locales" / loc / "messages.json"
        if not msg_path.is_file():
            raise FileNotFoundError(f"{browser}: отсутствует локаль {loc}")
        msgs = json.loads(msg_path.read_text(encoding="utf-8"))
        if "extName" not in msgs or "extDescription" not in msgs:
            raise ValueError(f"{browser}: в локали {loc} нет extName/extDescription")

    return manifest


def build_extension_zip(ext_dir: Path, out_zip: Path) -> str:
    """Собирает детерминированный .zip архив расширения и возвращает его SHA-256."""
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(
        (p for p in ext_dir.rglob("*") if p.is_file() and not p.name.startswith(".")),
        key=lambda p: p.relative_to(ext_dir).as_posix(),
    )
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for file_path in files:
            arcname = file_path.relative_to(ext_dir).as_posix()
            info = zipfile.ZipInfo(filename=arcname, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # UNIX-совместимые атрибуты для воспроизводимости
            info.external_attr = 0o644 << 16
            zf.writestr(info, file_path.read_bytes())

    return hashlib.sha256(out_zip.read_bytes()).hexdigest()


def build_all(
    out_dir: Path,
    root: Path = ROOT,
    sync_version: bool = False,
) -> dict[str, dict[str, object]]:
    """Проверяет оба расширения (Chromium, Firefox) и собирает .zip пакеты."""
    version = read_padam_version(root)
    results: dict[str, dict[str, object]] = {}
    for browser in ("chromium", "firefox"):
        ext_dir = root / "extensions" / browser
        validate_extension_dir(browser, ext_dir, expected_version=version, sync_version=sync_version)
        out_zip = out_dir / f"padam-memory-guard-{browser}.zip"
        digest = build_extension_zip(ext_dir, out_zip)
        results[browser] = {
            "version": version,
            "path": str(out_zip),
            "size": out_zip.stat().st_size,
            "sha256": digest,
        }
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Сборка расширений PADAM Memory Guard (.zip)")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "extensions" / "dist",
        help="Каталог вывода .zip архивов (по умолчанию extensions/dist)",
    )
    parser.add_argument(
        "--sync-version",
        action="store_true",
        help="Синхронизировать поле version в manifest.json с padam/__init__.py",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Вывести сводку в формате JSON",
    )
    args = parser.parse_args(argv)

    results = build_all(out_dir=args.out_dir, sync_version=args.sync_version)
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for browser, info in results.items():
            print(
                f"{browser}: v{info['version']} -> {info['path']} "
                f"({info['size']} bytes, sha256={info['sha256']})"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
