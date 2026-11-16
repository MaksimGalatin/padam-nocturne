"""Локальный общий пул-демон MCP (--auto-daemon) с жёсткой изоляцией проектных сессий между IDE."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import config


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def scope_matches_pin(candidate_scope: str | None, pinned_scope: str | None) -> bool:
    """Проверяет, что candidate_scope строго внутри изолированной песочницы pinned_scope."""
    if not pinned_scope:
        return True
    pin = str(pinned_scope).strip()
    cand = str(candidate_scope or "").strip()
    if not cand or cand.lower() == "all":
        return False
    if cand == pin:
        return True
    return cand.startswith(f"{pin}:") or cand.startswith(f"{pin}/")


def daemon_state_path(db_path: str | Path | None = None, user_id: str | None = None) -> Path:
    """Вычисляет детерминированный путь файла состояния общего пула для пары (db_path, user_id)."""
    raw_dir = os.environ.get("PADAM_DAEMON_STATE_DIR", "").strip()
    base_dir = Path(raw_dir) if raw_dir else config.PADAM_HOME
    base_dir.mkdir(parents=True, exist_ok=True)
    db_norm = str(Path(db_path or config.DB_PATH).expanduser().resolve(strict=False)).lower()
    uid = str(user_id or os.environ.get("PADAM_USER", "default")).strip() or "default"
    digest = hashlib.sha256(f"{db_norm}|{uid}".encode("utf-8")).hexdigest()[:16]
    return base_dir / f"mcp-daemon-{digest}.json"


def write_daemon_state(state_path: Path, data: dict) -> None:
    """Атомарно записывает JSON-дескриптор пула (0600 на POSIX)."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_name(f".{state_path.name}.{os.getpid()}.tmp")
    raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    tmp.write_bytes(raw)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, state_path)
    try:
        os.chmod(state_path, 0o600)
    except OSError:
        pass


def read_daemon_state(state_path: Path) -> dict | None:
    if not state_path.exists():
        return None
    try:
        obj = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    if not obj.get("url") or not obj.get("token"):
        return None
    return obj


def probe_daemon(state_path: Path, timeout_s: float = 0.6) -> dict | None:
    """Проверяет живость локального пула через GET /health и валидирует дескриптор."""
    info = read_daemon_state(state_path)
    if not info:
        return None
    base = str(info["url"]).rsplit("/mcp", 1)[0]
    req = urllib.request.Request(f"{base}/health", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status != 200:
                return None
            payload = json.loads(resp.read().decode("utf-8"))
            if payload.get("status") == "ok":
                return info
    except Exception:
        return None
    return None


def spawn_or_attach_daemon(
    *,
    db_path: str | Path | None = None,
    user_id: str | None = None,
    state_path: Path | None = None,
    wait_timeout_s: float = 30.0,  # 16.11.2026: холодный старт Python на macOS (CI) не укладывался в 8 с
) -> dict:
    """Подключается к живому локальному пулу или запускает его в фоне и ждёт готовности."""
    sp = state_path or daemon_state_path(db_path=db_path, user_id=user_id)
    alive = probe_daemon(sp)
    if alive is not None:
        return alive

    # Удаляем протухший файл состояния перед запуском нового демона
    try:
        if sp.exists():
            sp.unlink()
    except OSError:
        pass

    fresh_tok = secrets.token_urlsafe(24)
    env = os.environ.copy()
    if db_path is not None:
        env["PADAM_DB"] = str(db_path)
    if user_id is not None:
        env["PADAM_USER"] = str(user_id)
    env["PADAM_API_TOKEN"] = fresh_tok
    env["PADAM_MCP_SESSION_ISOLATION"] = "1"
    env.setdefault("PADAM_MCP_ROOTS", "1")
    env.setdefault("PADAM_MCP_PREDICTIVE_CACHE", "1")

    cmd = [
        sys.executable,
        "-m",
        "padam.mcp_server",
        "--http",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--daemon-state",
        str(sp),
    ]
    popen_kw: dict = {
        "env": env,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        popen_kw["creationflags"] = (
            getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        )
    else:
        popen_kw["start_new_session"] = True

    subprocess.Popen(cmd, **popen_kw)
    deadline = time.monotonic() + max(1.0, float(wait_timeout_s))
    while time.monotonic() < deadline:
        ready = probe_daemon(sp, timeout_s=0.4)
        if ready is not None:
            return ready
        time.sleep(0.08)
    raise TimeoutError(f"PADAM MCP daemon did not start within {wait_timeout_s:.1f}s")


def forward_rpc(
    url: str,
    token: str,
    payload: dict | list,
    *,
    session_id: str,
    session_scope: str | None = None,
    timeout_s: float = 30.0,
) -> tuple[int, dict | list | None]:
    """Отправляет JSON-RPC сообщение в локальный пул-сервер по Streamable HTTP."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Mcp-Session-Id": session_id,
    }
    if session_scope:
        headers["X-Padam-Session-Scope"] = session_scope
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            if resp.status == 202 or not raw:
                return resp.status, None
            return resp.status, json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as he:
        raw_err = he.read()
        try:
            return he.code, json.loads(raw_err.decode("utf-8"))
        except Exception:
            return he.code, {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(he)}}


def run_stdio_proxy(
    stdin_stream,
    stdout_stream,
    *,
    url: str,
    token: str,
    initial_scope: str | None = None,
    derive_scope_fn=None,
) -> int:
    """Проксирует stdin/stdout IDE в общий локальный пул, закрепляя отдельную изолированную сессию."""
    client_sid = f"ide-{secrets.token_hex(12)}"
    pinned_scope = (initial_scope or "").strip() or None
    if not pinned_scope and os.environ.get("PADAM_MCP_SESSION_SCOPE", "").strip():
        pinned_scope = os.environ["PADAM_MCP_SESSION_SCOPE"].strip()
    if not pinned_scope and derive_scope_fn is not None:
        try:
            cwd_uri = Path.cwd().resolve().as_uri()
            pinned_scope = derive_scope_fn([{"uri": cwd_uri}])
        except Exception:
            pinned_scope = None

    try:
        while True:
            line = stdin_stream.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            if len(line.encode("utf-8", "replace")) > config.MAX_MCP_MESSAGE_BYTES:
                err_obj = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": f"request exceeds {config.MAX_MCP_MESSAGE_BYTES} bytes"},
                }
                stdout_stream.write(json.dumps(err_obj, ensure_ascii=False) + "\n")
                stdout_stream.flush()
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                err_obj = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
                stdout_stream.write(json.dumps(err_obj, ensure_ascii=False) + "\n")
                stdout_stream.flush()
                continue

            # При initialize / roots/list_changed определяем изолированный scope этого окна IDE
            if isinstance(msg, dict) and derive_scope_fn is not None:
                meth = msg.get("method")
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                if meth in ("initialize", "notifications/roots/list_changed") and isinstance(params.get("roots"), list):
                    pinned_scope = derive_scope_fn(params["roots"])

            _, resp = forward_rpc(
                url,
                token,
                msg,
                session_id=client_sid,
                session_scope=pinned_scope,
            )
            if resp is not None:
                stdout_stream.write(json.dumps(resp, ensure_ascii=False) + "\n")
                stdout_stream.flush()
    finally:
        try:
            del_req = urllib.request.Request(
                url,
                headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": client_sid},
                method="DELETE",
            )
            with urllib.request.urlopen(del_req, timeout=2.0):
                pass
        except Exception:
            pass
    return 0
