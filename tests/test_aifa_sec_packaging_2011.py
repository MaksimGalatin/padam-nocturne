"""Бенчмарк AIFaSecurity-100 входит в колесо PyPI и в APK (20.11.2026).

До 0.7.0 в колесо клались только padam и padam.connectors: после `pip install padam-nocturne==0.6.5`
Студия и `padam aifa-sec` отвечали «benchmarks/aifa_security package not found» (замер в чистом venv),
а в APK 0.7.0 кнопка «Запустить 100 проверок» давала ту же ошибку (отчёт Сестры по эмулятору).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib


def test_wheel_maps_benchmark_inside_package():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]
    assert "padam.aifa_security" in cfg["packages"]
    assert cfg["package-dir"]["padam.aifa_security"] == "benchmarks/aifa_security"


def test_android_apk_copies_benchmark():
    gradle = (ROOT / "android" / "app" / "build.gradle.kts").read_text(encoding="utf-8")
    assert '../benchmarks/aifa_security' in gradle and 'into("aifa_security")' in gradle
    runtime = (ROOT / "android" / "app" / "src" / "main" / "python" / "android_runtime.py").read_text(encoding="utf-8")
    assert "PADAM_BENCH_INPROC" in runtime


def test_bridge_loader_finds_benchmark_from_repo():
    from padam.aifa_sec_bridge import aifa_sec_module

    run = aifa_sec_module("run_aifa_sec")
    assert hasattr(run, "run_aifa_security") and run.INSTALLED is False
    assert len(aifa_sec_module("catalog").CATALOG) == 100


def test_scanner_skips_own_benchmark_samples():
    from benchmarks.aifa_security import targets

    rs = targets.scan_directory_tree(ROOT / "benchmarks" / "aifa_security")
    assert rs["secret_hits"] == [] and rs["insecure_net"] == []


def test_padam_source_reads_module_text():
    from benchmarks.aifa_security.targets import padam_source

    assert "Content-Security-Policy" in padam_source("api.py")


def test_loader_scan_matches_disk_scan():
    """APK держит код в архиве: скан исходников от загрузчика должен совпадать со сканом файлов на диске."""
    from benchmarks.aifa_security import run_aifa_sec, targets

    a = run_aifa_sec._scan_padam_from_loader()
    b = targets.scan_directory_tree(ROOT / "padam")
    assert a["files_scanned"] == b["files_scanned"] > 50
    for k in ("secret_hits", "unsafe_sinks", "raw_sqls", "insecure_net", "cors_wildcards"):
        assert a[k] == b[k], k
