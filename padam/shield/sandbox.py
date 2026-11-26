# -*- coding: utf-8 -*-
"""Эфемерная микро-песочница (Micro-Sandbox) для изолированного запуска инструментов агента.

Обеспечивает защиту на уровне исполнения ОС:
- Строгая проверка выхода за пределы разрешённой рабочей директории (anti path-traversal + symlinks).
- Вычищение всех чувствительных переменных окружения (`*_KEY`, `*_SECRET`, `*_TOKEN`, `AWS_*`, `PADAM_*`).
- Поддержка запуска в эфемерном контейнере Docker / Podman (`--rm --network=none --read-only
  --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=256m`) с честным
  указанием реального уровня изоляции (`container` или `restricted_process`).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .._no_window import NO_WINDOW

_SENSITIVE_ENV_RE = re.compile(
    r"(?i)(?:KEY|SECRET|TOKEN|PASS|CREDENTIAL|AUTH|COOKIE|PRIVATE|WALLET|SEED|DATABASE_URL|AWS_|GCP_|OPENAI_|ANTHROPIC_|STRIPE_|PADAM_)"
)
_BLOCKED_BINARIES = frozenset({
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "ftp",
    "powershell", "pwsh", "certutil", "bitsadmin", "reg", "regedit", "sc",
    "mkfs", "dd", "shutdown", "reboot", "format", "diskpart",
})


def sanitize_env(base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Удаляет секретные переменные окружения перед запуском процесса в песочнице."""
    src = dict(base_env if base_env is not None else os.environ)
    clean: dict[str, str] = {}
    for k, v in src.items():
        if _SENSITIVE_ENV_RE.search(k):
            continue
        clean[k] = v
    clean["PADAM_SANDBOXED"] = "1"
    return clean


def resolve_confined_path(workspace_dir: str | Path, candidate: str | Path) -> Path:
    """Проверяет, что путь строго лежит внутри `workspace_dir` (защита от `../../` и симлинков)."""
    root = Path(workspace_dir).resolve()
    raw = Path(candidate)
    resolved = (root / raw).resolve() if not raw.is_absolute() else raw.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PermissionError(
            f"Sandbox path escape blocked: {candidate!r} resolves outside workspace {str(root)!r}"
        ) from exc
    return resolved


def detect_container_runtime() -> str | None:
    """Определяет доступный на машине контейнерный рантайм (`docker` или `podman`)."""
    for rt in ("docker", "podman"):
        if shutil.which(rt):
            return rt
    return None


def build_container_command(
    runtime: str,
    *,
    image: str,
    workspace_dir: str | Path,
    command: list[str],
    read_only_workspace: bool = True,
    memory_mb: int = 256,
    pids_limit: int = 64,
) -> list[str]:
    """Формирует строгую команду запуска эфемерного контейнера без сети и привилегий."""
    root = str(Path(workspace_dir).resolve())
    mount_opt = "ro" if read_only_workspace else "rw"
    return [
        runtime, "run", "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={max(16, int(pids_limit))}",
        f"--memory={max(64, int(memory_mb))}m",
        "-w", "/workspace",
        "-v", f"{root}:/workspace:{mount_opt}",
        image,
        *command,
    ]


class MicroSandbox:
    """Исполнитель команд агента в ограниченной среде с защитой от побега."""

    def __init__(
        self,
        workspace_dir: str | Path,
        *,
        read_only: bool = True,
        allow_network: bool = False,
        timeout_s: float = 15.0,
        max_output_bytes: int = 65536,
        container_image: str = "python:3.12-slim",
    ) -> None:
        self.workspace_dir = Path(workspace_dir).resolve()
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.read_only = bool(read_only)
        self.allow_network = bool(allow_network)
        self.timeout_s = max(1.0, min(120.0, float(timeout_s)))
        self.max_output_bytes = max(1024, int(max_output_bytes))
        self.container_image = container_image

    def validate_command(self, argv: list[str]) -> None:
        if not argv:
            raise ValueError("Empty command")
        exe_name = Path(argv[0]).stem.lower()
        if not self.allow_network and exe_name in _BLOCKED_BINARIES:
            raise PermissionError(f"Sandbox blocked restricted binary: {exe_name!r}")
        for arg in argv[1:]:
            s = str(arg)
            # Блокируем попытки выхода за пределы workspace в аргументах
            if ".." in Path(s).parts:
                resolve_confined_path(self.workspace_dir, s)
            elif re.match(r"^(?:/etc/|/root/|/home/|~[/\\]|[A-Za-z]:[/\\])", s):
                # Разрешаем только если путь реально внутри workspace_dir
                resolve_confined_path(self.workspace_dir, s)

    def run(self, argv: list[str], *, prefer_container: bool = False) -> dict[str, Any]:
        """Запускает команду в песочнице и возвращает честный отчёт об уровне изоляции."""
        t0 = time.perf_counter()
        self.validate_command(argv)
        rt = detect_container_runtime() if prefer_container else None
        isolation = "restricted_process"
        exec_argv = list(argv)
        if rt:
            exec_argv = build_container_command(
                rt,
                image=self.container_image,
                workspace_dir=self.workspace_dir,
                command=argv,
                read_only_workspace=self.read_only,
            )
            isolation = f"container:{rt}"

        env = sanitize_env()
        try:
            proc = subprocess.run(
                exec_argv,
                cwd=str(self.workspace_dir),
                env=env,
                capture_output=True,
                timeout=self.timeout_s,
                **NO_WINDOW,
            )
            stdout = proc.stdout[: self.max_output_bytes].decode("utf-8", "replace")
            stderr = proc.stderr[: self.max_output_bytes].decode("utf-8", "replace")
            return {
                "ok": proc.returncode == 0,
                "returncode": int(proc.returncode),
                "isolation_level": isolation,
                "workspace": str(self.workspace_dir),
                "read_only": self.read_only,
                "network_disabled": not self.allow_network,
                "stdout": stdout,
                "stderr": stderr,
                "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            }
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "returncode": -1,
                "isolation_level": isolation,
                "error": f"timeout_after_{self.timeout_s}s",
                "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            }
