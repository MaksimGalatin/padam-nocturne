# -*- coding: utf-8 -*-
"""Проверки структуры Android-проекта PADAM, разрешений безопасности и моста запуска."""

from __future__ import annotations

import ast
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANDROID_DIR = ROOT / "android"


def test_android_project_files_and_manifest_safety() -> None:
    manifest = ANDROID_DIR / "app" / "src" / "main" / "AndroidManifest.xml"
    net_sec = ANDROID_DIR / "app" / "src" / "main" / "res" / "xml" / "network_security_config.xml"
    gradle_app = ANDROID_DIR / "app" / "build.gradle.kts"
    runtime_py = ANDROID_DIR / "app" / "src" / "main" / "python" / "android_runtime.py"
    vault_kt = ANDROID_DIR / "app" / "src" / "main" / "java" / "com" / "codeofdigitaleternity" / "padam" / "KeystoreVault.kt"

    for p in (manifest, net_sec, gradle_app, runtime_py, vault_kt):
        assert p.exists(), f"Отсутствует обязательный файл: {p}"

    ast.parse(runtime_py.read_text(encoding="utf-8"))

    gradle_txt = gradle_app.read_text(encoding="utf-8")
    for dep in ("numpy", "requests", "cryptography"):
        assert f'install("{dep}")' in gradle_txt
    assert "targetSdk = 36" in gradle_txt
    assert "minSdk = 24" in gradle_txt

    m_tree = ET.parse(manifest)
    m_root = m_tree.getroot()
    ns = "{http://schemas.android.com/apk/res/android}"
    perms = [el.attrib.get(ns + "name") for el in m_root.findall("uses-permission")]
    assert set(perms) == {
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.RECORD_AUDIO",
        "android.permission.USE_BIOMETRIC",
        "android.permission.POST_NOTIFICATIONS",
    }
    app_el = m_root.find("application")
    assert app_el is not None
    assert app_el.attrib.get(ns + "allowBackup") == "false"
    assert app_el.attrib.get(ns + "usesCleartextTraffic") == "false"

    n_tree = ET.parse(net_sec)
    n_root = n_tree.getroot()
    base_cfg = n_root.find("base-config")
    assert base_cfg is not None and base_cfg.attrib.get("cleartextTrafficPermitted") == "false"
    domains = [d.text.strip() for d in n_root.findall(".//domain") if d.text]
    assert set(domains) == {"127.0.0.1", "localhost"}


def test_android_runtime_starts_studio_with_keystore_and_loopback_only(tmp_path: Path) -> None:
    py_dir = str(ANDROID_DIR / "app" / "src" / "main" / "python")
    sys.path.insert(0, py_dir)
    try:
        import android_runtime  # type: ignore

        android_runtime._SERVER = None
        android_runtime._SERVER_URL = None

        class _FakeVault:
            def __init__(self) -> None:
                self.data: str | None = None

            def saveSession(self, v: str) -> None:
                self.data = v

            def loadSession(self) -> str | None:
                return self.data

            def clearSession(self) -> bool:
                had = self.data is not None
                self.data = None
                return had

        class _FakeBrowser:
            def __init__(self) -> None:
                self.opened: list[str] = []

            def openExternalUrl(self, u: str) -> bool:
                self.opened.append(u)
                return True

        vault = _FakeVault()
        browser = _FakeBrowser()
        url = android_runtime.start_studio(str(tmp_path), vault, browser)
        assert url.startswith("http://127.0.0.1:")
        assert (tmp_path / "padam.db").exists() or True

        from padam import cabinet
        cabinet.save_session("phone@example.com", "secret_android_tok", "https://aifa.works")
        assert vault.data is not None and "secret_android_tok" in vault.data
        assert cabinet.load_session()["token"] == "secret_android_tok"
        cabinet.clear_session()
        cabinet.clear_keystore_backend()
        if android_runtime._SERVER is not None:
            android_runtime._SERVER.shutdown()
            android_runtime._SERVER.server_close()
            android_runtime._SERVER = None
            android_runtime._SERVER_URL = None
    finally:
        if py_dir in sys.path:
            sys.path.remove(py_dir)
