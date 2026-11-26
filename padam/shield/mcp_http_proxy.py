# -*- coding: utf-8 -*-
"""Прозрачный шлюз-перехватчик MCP Streamable HTTP / SSE (MCP HTTP Gateway).

Дополняет STDIO-прокси (`mcp_proxy.py`) защитой удалённых и локальных HTTP/SSE
MCP-серверов:
- защита от DNS-Rebinding (строгая проверка `Host` и `Origin` входящих запросов),
- проверка `upstream_url` на Cloud Metadata SSRF,
- перехват `tools/list` (SHA-256 Rug-Pull pinning), `tools/call` (Taint Tracking +
  файрвол исходящих + SSRF/Path проверка аргументов + Web3 ABI),
- инспекция ответов как `application/json`, так и потоковых `text/event-stream` (SSE)
  на RAG-отравление, скрытую эксфильтрацию (Markdown/DNS/ZWSP) и утечку секретов.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import threading
from typing import Any, Dict, List, Optional, Tuple
from urllib import request as _urlreq
from urllib.error import HTTPError
from urllib.parse import urlparse

from .. import agentic_shield as _ash
from .exfil_guard import inspect_exfil_channels
from .honeytoken import scan_for_honeytokens
from .output_rag import inspect_output_guardrails, sanitize_rag_document
from .semantic import classify_semantic_threat
from .ssrf_path_guard import inspect_file_path_access, inspect_url_ssrf
from .taint import observe_tool_step


_INLINE_URL_RE = re.compile(r"(?i)\b(?:https?|file|gopher|dict|ftp|javascript)://[^\s\"'<>`]+")


def _extract_urls_and_paths(obj: Any, urls: List[str], paths: List[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if isinstance(v, str):
                if v.lower().startswith(("http://", "https://", "file://", "gopher://", "dict://", "ftp://")):
                    urls.append(v)
                else:
                    for m in _INLINE_URL_RE.finditer(v):
                        urls.append(m.group(0))
                if any(t in kl for t in ("path", "file", "dir", "target")) and "://" not in v:
                    paths.append(v)
            else:
                _extract_urls_and_paths(v, urls, paths)
    elif isinstance(obj, list):
        for item in obj:
            _extract_urls_and_paths(item, urls, paths)
    elif isinstance(obj, str):
        for m in _INLINE_URL_RE.finditer(obj):
            urls.append(m.group(0))


def inspect_http_mcp_request(
    memory: Any,
    msg: Dict[str, Any],
    *,
    session_id: str = "http-mcp",
    agent_id: str = "mcp_http_client",
    allowed_roots: Tuple[str, ...] = (),
    allow_private_ssrf: bool = False,
) -> Dict[str, Any]:
    """Инспектирует входящий JSON-RPC запрос клиента до проксирования на HTTP MCP upstream."""
    method = str(msg.get("method") or "")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    if method != "tools/call":
        return {"allowed": True, "blocked": False, "method": method}

    tool_name = str(params.get("name") or "")
    args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    args_text = json.dumps(args, ensure_ascii=False)

    # 1. Taint & CFI + сбор URL/путей
    urls: List[str] = []
    paths: List[str] = []
    _extract_urls_and_paths(args, urls, paths)
    primary_target = urls[0] if urls else (paths[0] if paths else tool_name)

    t_res = observe_tool_step(
        memory,
        session_id=session_id,
        tool_name=tool_name,
        target=primary_target,
        payload=args_text,
        agent_id=agent_id,
        auto_trip_kill_switch=False,
    )
    if not t_res.get("allowed", True):
        return {
            "allowed": False,
            "blocked": True,
            "rule_id": "MCP-HTTP-TAINT-BLOCK",
            "reason": t_res.get("reason") or "Заблокировано Taint CFI",
        }

    # 2. SSRF и Path Traversal в аргументах инструмента
    for u in urls:
        sr = inspect_url_ssrf(u, allow_private=allow_private_ssrf)
        if sr["blocked"]:
            return {
                "allowed": False,
                "blocked": True,
                "rule_id": sr["findings"][0]["rule_id"],
                "reason": sr["findings"][0]["detail"],
            }
    for p in paths:
        pr = inspect_file_path_access(p, allowed_roots=allowed_roots)
        if pr["blocked"]:
            return {
                "allowed": False,
                "blocked": True,
                "rule_id": pr["findings"][0]["rule_id"],
                "reason": pr["findings"][0]["detail"],
            }

    # 3. Проверка Honey-Tokens в исходящих аргументах
    ht = scan_for_honeytokens(memory, args_text, agent_id=agent_id, channel="mcp_http_call", trip_kill_switch=False)
    if ht.get("triggered"):
        return {
            "allowed": False,
            "blocked": True,
            "rule_id": "HONEYTOKEN-EXFIL-TRAP",
            "reason": f"В исходящем HTTP MCP вызове обнаружен Honey-Token ({ht['hits'][0]['decoy_kind']})",
        }

    # 4. Кольцо 3: платежи, домены, команды
    ob = _ash.inspect_outbound_action(
        memory,
        action_type="http" if urls else "tool_call",
        target=urls[0] if urls else tool_name,
        payload=args_text,
        agent_id=agent_id,
    )
    if not ob.get("allowed", True):
        return {
            "allowed": False,
            "blocked": True,
            "rule_id": "MCP-HTTP-OUTBOUND-BLOCK",
            "reason": str(ob.get("reason") or "Заблокировано файрволом исходящих действий"),
        }

    return {"allowed": True, "blocked": False, "method": method, "tool_name": tool_name}


def inspect_http_mcp_response_payload(
    memory: Any,
    body_text: str,
    *,
    content_type: str = "application/json",
    method: str = "",
    server_id: str = "http_upstream",
    pinned_once: Optional[List[bool]] = None,
) -> Dict[str, Any]:
    """Инспектирует JSON или SSE-ответ от HTTP MCP-сервера на Rug-Pull, инъекции и эксфильтрацию."""
    frames: List[Dict[str, Any]] = []
    ct = (content_type or "").lower()

    if "text/event-stream" in ct:
        for line in body_text.splitlines():
            s = line.strip()
            if s.startswith("data:"):
                raw = s[5:].strip()
                if not raw or raw == "[DONE]":
                    continue
                try:
                    obj = json.loads(raw)
                    if isinstance(obj, dict):
                        frames.append(obj)
                except Exception:
                    pass
    else:
        try:
            obj = json.loads(body_text)
            if isinstance(obj, dict):
                frames.append(obj)
        except Exception:
            pass

    for frame in frames:
        result = frame.get("result")
        if method == "tools/list" and isinstance(result, dict) and isinstance(result.get("tools"), list):
            should_pin = False
            if pinned_once is not None and not pinned_once[0]:
                should_pin = True
                pinned_once[0] = True
            audit = _ash.audit_mcp_tools(memory, result["tools"], server_name=server_id, pin=should_pin)
            if not audit.get("clean", True) or int(audit.get("rug_pulls_detected", 0)) > 0:
                return {
                    "allowed": False,
                    "blocked": True,
                    "rule_id": "MCP-HTTP-RUG-PULL",
                    "reason": "Обнаружена подмена схемы MCP (Rug-Pull / Tool Poisoning) на HTTP-сервере",
                    "audit": audit,
                }
        elif method == "tools/call" and result is not None:
            text_blob = json.dumps(result, ensure_ascii=False)
            exf = inspect_exfil_channels(text_blob)
            if exf["blocked"]:
                f0 = exf["findings"][0]
                return {
                    "allowed": False,
                    "blocked": True,
                    "rule_id": str(f0.get("rule_id") or f0.get("code") or "EXFIL-BLOCKED"),
                    "reason": str(f0.get("detail") or "Скрытый канал эксфильтрации"),
                }
            rag = sanitize_rag_document(text_blob)
            if rag.get("poison_removed"):
                return {
                    "allowed": False,
                    "blocked": True,
                    "rule_id": "MCP-HTTP-RAG-INJECTION",
                    "reason": "Обнаружена скрытая непрямая промпт-инъекция в ответе HTTP/SSE MCP",
                }
            sem = classify_semantic_threat(text_blob)
            if sem.get("is_threat"):
                return {
                    "allowed": False,
                    "blocked": True,
                    "rule_id": "MCP-HTTP-SEMANTIC-INJECTION",
                    "reason": f"Семантическая инъекция в ответе HTTP/SSE MCP (score={sem.get('score', 0.0):.2f})",
                }
            out_g = inspect_output_guardrails(text_blob)
            if out_g.get("blocked") or out_g.get("action") == "block":
                return {
                    "allowed": False,
                    "blocked": True,
                    "rule_id": "MCP-HTTP-OUTPUT-DLP",
                    "reason": "Ответ HTTP/SSE MCP содержит опасную утечку или вредоносную нагрузку",
                }

    return {"allowed": True, "blocked": False, "frames_checked": len(frames)}


class McpHttpShieldGateway:
    """Локальный защитный HTTP/SSE прокси перед удалённым или локальным MCP-сервером."""

    def __init__(
        self,
        memory: Any,
        upstream_url: str,
        *,
        bind_host: str = "127.0.0.1",
        port: int = 0,
        server_id: str = "http_mcp",
        allow_private_upstream: bool = False,
        allowed_roots: Tuple[str, ...] = (),
    ) -> None:
        if not allow_private_upstream:
            sr = inspect_url_ssrf(upstream_url, allow_private=False)
            if sr["blocked"]:
                raise ValueError(f"Небезопасный upstream_url: {sr['findings'][0]['detail']}")
        self.memory = memory
        self.upstream_url = upstream_url
        self.bind_host = bind_host
        self._bind_port = int(port)
        self.server_id = server_id
        self.allow_private_upstream = allow_private_upstream
        self.allowed_roots = allowed_roots
        self._pinned_once = [False]
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start_background(self) -> Tuple[str, int]:
        gw = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send_json(self, code: int, obj: Dict[str, Any]) -> None:
                raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _check_dns_rebinding(self) -> bool:
                host_hdr = (self.headers.get("Host") or "").split(":")[0].lower()
                if host_hdr and host_hdr not in ("127.0.0.1", "localhost", "::1"):
                    self._send_json(403, {"error": "DNS_REBINDING_BLOCKED", "host": host_hdr})
                    return False
                origin = (self.headers.get("Origin") or "").strip()
                if origin:
                    oh = (urlparse(origin).hostname or "").lower()
                    if oh not in ("127.0.0.1", "localhost", "::1"):
                        self._send_json(403, {"error": "FOREIGN_ORIGIN_BLOCKED", "origin": origin})
                        return False
                return True

            def do_POST(self) -> None:
                if not self._check_dns_rebinding():
                    return
                try:
                    length = int(self.headers.get("Content-Length") or "0")
                except ValueError:
                    return self._send_json(400, {"error": "INVALID_CONTENT_LENGTH"})
                if length < 0 or length > 4 * 1024 * 1024:
                    return self._send_json(413, {"error": "PAYLOAD_TOO_LARGE"})
                raw_body = self.rfile.read(length)
                try:
                    msg = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    return self._send_json(400, {"error": "INVALID_JSON"})

                req_check = inspect_http_mcp_request(
                    gw.memory,
                    msg,
                    session_id=f"http-{gw.server_id}",
                    allowed_roots=gw.allowed_roots,
                    allow_private_ssrf=gw.allow_private_upstream,
                )
                if req_check["blocked"]:
                    return self._send_json(
                        403,
                        {
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "error": {
                                "code": -32090,
                                "message": f"[PADAM HTTP Shield] {req_check['rule_id']}: {req_check['reason']}",
                            },
                        },
                    )

                # Проксируем запрос на upstream
                req = _urlreq.Request(
                    gw.upstream_url,
                    data=raw_body,
                    headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                    method="POST",
                )
                try:
                    with _urlreq.urlopen(req, timeout=15) as resp:
                        resp_bytes = resp.read()
                        resp_ct = resp.headers.get("Content-Type", "application/json")
                        resp_code = resp.status
                except HTTPError as he:
                    resp_bytes = he.read()
                    resp_ct = he.headers.get("Content-Type", "application/json")
                    resp_code = he.code
                except Exception as exc:
                    return self._send_json(502, {"error": f"UPSTREAM_ERROR: {exc}"})

                resp_text = resp_bytes.decode("utf-8", errors="replace")
                resp_check = inspect_http_mcp_response_payload(
                    gw.memory,
                    resp_text,
                    content_type=resp_ct,
                    method=str(msg.get("method") or ""),
                    server_id=gw.server_id,
                    pinned_once=gw._pinned_once,
                )
                if resp_check["blocked"]:
                    return self._send_json(
                        403,
                        {
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "error": {
                                "code": -32091,
                                "message": f"[PADAM HTTP Shield] {resp_check['rule_id']}: {resp_check['reason']}",
                            },
                        },
                    )

                self.send_response(resp_code)
                self.send_header("Content-Type", resp_ct)
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)

        self._httpd = ThreadingHTTPServer((self.bind_host, self._bind_port), _Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._httpd.server_address[:2]
        return str(host), int(port)

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1]) if self._httpd else self._bind_port

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
