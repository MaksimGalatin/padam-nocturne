"""Проверка совместимости MCP-сервера PADAM через официальный @modelcontextprotocol/inspector CLI."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from padam import mcp_server  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402


def _npx_executable() -> str:
    """Возвращает путь к npx с учётом Windows (.cmd)."""
    for name in ("npx.cmd", "npx"):
        path = shutil.which(name)
        if path:
            return path
    raise FileNotFoundError("Не найден npx в PATH для запуска @modelcontextprotocol/inspector")


def _run_inspector(
    npx_bin: str,
    inspector_pkg: str,
    args: list[str],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Запускает официальный inspector --cli и разбирает JSON-ответ на stdout."""
    cmd = [npx_bin, "--yes", inspector_pkg, "--cli", *args]
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
        env=env or os.environ.copy(),
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"Inspector CLI failed (rc={res.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
    stdout_text = res.stdout.strip()
    if not stdout_text:
        return {}
    return json.loads(stdout_text)


def run_stdio_checks(npx_bin: str, inspector_pkg: str, padam_cmd: str) -> dict[str, Any]:
    """Прогоняет проверки официального MCP Inspector по транспорту stdio."""
    with tempfile.TemporaryDirectory(prefix="padam_insp_stdio_") as tmpdir:
        db_path = Path(tmpdir) / "memory.db"
        env_flags = [
            "-e", f"PADAM_DB={db_path}",
            "-e", "PADAM_USER=inspector",
            "-e", "PADAM_EMBEDDER=builtin",
            "-e", "OLLAMA_URL=http://127.0.0.1:9",
        ]
        target = ["--transport", "stdio", *env_flags]

        tools_res = _run_inspector(
            npx_bin,
            inspector_pkg,
            [*target, "--method", "tools/list", "--strict", "--", padam_cmd],
        )
        tools = tools_res.get("tools") or []
        assert len(tools) == 9, f"stdio tools/list: expected 9 tools, got {len(tools)}"

        resources_res = _run_inspector(
            npx_bin,
            inspector_pkg,
            [*target, "--method", "resources/list", "--", padam_cmd],
        )
        resources = resources_res.get("resources") or []
        assert len(resources) >= 3, f"stdio resources/list: expected >= 3, got {len(resources)}"

        prompts_res = _run_inspector(
            npx_bin,
            inspector_pkg,
            [*target, "--method", "prompts/list", "--", padam_cmd],
        )
        prompts = prompts_res.get("prompts") or []
        assert len(prompts) >= 1, f"stdio prompts/list: expected >= 1, got {len(prompts)}"

        write_res = _run_inspector(
            npx_bin,
            inspector_pkg,
            [
                *target,
                "--method", "tools/call",
                "--tool-name", "padam_write",
                "--tool-args-json",
                json.dumps({
                    "content": "Inspector stdio roundtrip note with WAL mode enabled.",
                    "kind": "fact",
                    "origin": "user",
                }),
                "--", padam_cmd,
            ],
        )
        assert not write_res.get("isError"), write_res
        assert (write_res.get("structuredContent") or {}).get("outcome") == "created", write_res

        search_res = _run_inspector(
            npx_bin,
            inspector_pkg,
            [
                *target,
                "--method", "tools/call",
                "--tool-name", "padam_search",
                "--tool-args-json",
                json.dumps({"query": "Inspector stdio roundtrip WAL mode", "limit": 5}),
                "--", padam_cmd,
            ],
        )
        assert not search_res.get("isError"), search_res
        assert (search_res.get("structuredContent") or {}).get("count", 0) >= 1, search_res
        return {
            "transport": "stdio",
            "tools": len(tools),
            "resources": len(resources),
            "prompts": len(prompts),
            "strict_schema": "passed",
            "write_search": "passed",
        }


def run_http_checks(npx_bin: str, inspector_pkg: str) -> dict[str, Any]:
    """Прогоняет проверки официального MCP Inspector по Streamable HTTP с Bearer-токеном."""
    with tempfile.TemporaryDirectory(prefix="padam_insp_http_") as tmpdir:
        db_path = Path(tmpdir) / "memory.db"
        mem = Memory(user_id="inspector-http", store=Store(db_path))
        tok = secrets.token_hex(16)
        srv, url, token = mcp_server.make_mcp_http_server(
            memory=mem, host="127.0.0.1", port=0, token=tok,
        )
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            target = [
                "--transport", "http",
                "--server-url", url,
                "--header", f"Authorization: Bearer {token}",
                "--stored-auth-only",
            ]
            tools_res = _run_inspector(
                npx_bin, inspector_pkg, [*target, "--method", "tools/list", "--strict"],
            )
            tools = tools_res.get("tools") or []
            assert len(tools) == 9, f"http tools/list: expected 9 tools, got {len(tools)}"

            resources_res = _run_inspector(
                npx_bin, inspector_pkg, [*target, "--method", "resources/list"],
            )
            resources = resources_res.get("resources") or []
            assert len(resources) >= 3, f"http resources/list: expected >= 3, got {len(resources)}"

            write_res = _run_inspector(
                npx_bin,
                inspector_pkg,
                [
                    *target,
                    "--method", "tools/call",
                    "--tool-name", "padam_write",
                    "--tool-args-json",
                    json.dumps({
                        "content": "Inspector streamable-http memory entry verified.",
                        "kind": "fact",
                        "origin": "user",
                    }),
                ],
            )
            assert not write_res.get("isError"), write_res
            assert (write_res.get("structuredContent") or {}).get("outcome") == "created", write_res

            search_res = _run_inspector(
                npx_bin,
                inspector_pkg,
                [
                    *target,
                    "--method", "tools/call",
                    "--tool-name", "padam_search",
                    "--tool-args-json",
                    json.dumps({"query": "streamable-http memory entry", "limit": 5}),
                ],
            )
            assert not search_res.get("isError"), search_res
            assert (search_res.get("structuredContent") or {}).get("count", 0) >= 1, search_res

            stats_res = _run_inspector(
                npx_bin,
                inspector_pkg,
                [*target, "--method", "resources/read", "--uri", "padam://stats"],
            )
            assert len(stats_res.get("contents") or []) == 1, stats_res
            return {
                "transport": "streamable-http",
                "tools": len(tools),
                "resources": len(resources),
                "strict_schema": "passed",
                "write_search": "passed",
                "resources_read": "passed",
            }
        finally:
            srv.shutdown()
            srv.server_close()
            mem.close()


def main(argv: list[str] | None = None) -> int:
    """Точка входа проверки официальным MCP Inspector по stdio и streamable-http."""
    parser = argparse.ArgumentParser(description="Проверка PADAM через @modelcontextprotocol/inspector")
    parser.add_argument("--package", default="@modelcontextprotocol/inspector")
    parser.add_argument("--padam-cmd", default="padam-mcp")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    npx_bin = _npx_executable()
    stdio_res = run_stdio_checks(npx_bin, args.package, args.padam_cmd)
    http_res = run_http_checks(npx_bin, args.package)
    summary = {"status": "passed", "stdio": stdio_res, "http": http_res}
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(
            f"[PASS] MCP Inspector stdio: tools={stdio_res['tools']}, resources={stdio_res['resources']}, "
            f"prompts={stdio_res['prompts']}, strict_schema={stdio_res['strict_schema']}"
        )
        print(
            f"[PASS] MCP Inspector streamable-http: tools={http_res['tools']}, resources={http_res['resources']}, "
            f"strict_schema={http_res['strict_schema']}, resources_read={http_res['resources_read']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
