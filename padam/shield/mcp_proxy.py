# -*- coding: utf-8 -*-
"""Прозрачный локальный MCP STDIO JSON-RPC прокси (`padam shield proxy -- <cmd>`).

Защищает ЛЮБОЙ сторонний MCP-сервер (npm / PyPI / Go / локальный бинарник) без изменения
ни одной строчки его кода:
1. Перехватывает ответ `tools/list` от upstream MCP → проверяет SHA-256 пиннинг схем (anti Rug-Pull),
   Unicode-стеганографию и семантические инъекции в описаниях инструментов.
2. Перехватывает запрос `tools/call` от агента → прогоняет через Taint Tracking, Outbound Gate,
   Web3 ABI Decoder, Rego DSL и Kill Switch ДО передачи upstream-серверу.
3. Перехватывает ответ `tools/call` от upstream → прогоняет через RAG Poisoning Shield,
   Exfil Channel Guard, Output DLP и Semantic ONNX ДО возврата в контекст модели!
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from .._no_window import NO_WINDOW
from .exfil_guard import inspect_exfil_channels
from .output_rag import inspect_output_guardrails, sanitize_rag_document
from .policy_dsl import evaluate_rego_policy
from .semantic import classify_semantic_threat
from .taint import observe_tool_step


class McpStdioShieldProxy:
    """Двусторонний инспектор JSON-RPC 2.0 сообщений между ИИ-клиентом и сторонним MCP-сервером."""

    def __init__(
        self,
        memory: Any,
        *,
        server_name: str = "upstream_mcp",
        session_id: str = "mcp_proxy",
        agent_id: str = "mcp_client",
        pin_on_first_seen: bool = True,
        rego_policies: list[str] | None = None,
    ) -> None:
        self.memory = memory
        self.server_name = server_name
        self.session_id = session_id
        self.agent_id = agent_id
        self.pin_on_first_seen = bool(pin_on_first_seen)
        self.rego_policies = list(rego_policies or [])
        self._pending_methods: dict[Any, tuple[str, str]] = {}
        self.stats = {
            "requests_inspected": 0,
            "requests_blocked": 0,
            "responses_inspected": 0,
            "responses_sanitized": 0,
            "tools_list_checked": 0,
            "rug_pulls_blocked": 0,
        }

    def inspect_client_message(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Проверяет JSON-RPC запрос от агента ДО отправки стороннему MCP-серверу."""
        from .. import agentic_shield as _ash

        self.stats["requests_inspected"] += 1
        req_id = msg.get("id")
        method = str(msg.get("method") or "")
        params = msg.get("params") or {}

        if req_id is not None and method:
            tname = str(params.get("name") or "") if method == "tools/call" else ""
            self._pending_methods[req_id] = (method, tname)

        if method != "tools/call":
            return {"allowed": True, "blocked": False, "forward": msg}

        tool_name = str(params.get("name") or "unknown_tool")
        args = params.get("arguments") or {}
        args_str = json.dumps(args, ensure_ascii=False)
        target = str(args.get("url") or args.get("target") or args.get("path") or args.get("to") or "")

        # 1. Taint Tracking (CFI)
        taint = observe_tool_step(
            self.memory,
            session_id=self.session_id,
            tool_name=tool_name,
            target=target or args_str[:160],
            payload=args_str,
            agent_id=self.agent_id,
            source_node=f"mcp_proxy:{self.server_name}",
            auto_trip_kill_switch=True,
        )
        if not taint["allowed"]:
            self.stats["requests_blocked"] += 1
            return {
                "allowed": False,
                "blocked": True,
                "reason": taint["reason"],
                "error_response": self._jsonrpc_error(req_id, -32001, f"PADAM Shield Taint Block: {taint['reason']}"),
            }

        # 2. Outbound Action Gate (Payee-Swap, Secrets, Shell, Web3 ABI, Semantic ONNX)
        out = _ash.inspect_outbound_action(
            self.memory,
            action_type=tool_name,
            target=target,
            payload=args_str,
            agent_id=self.agent_id,
        )
        if not out["allowed"]:
            self.stats["requests_blocked"] += 1
            codes = ", ".join(r["code"] for r in (out.get("reasons") or [])[:4])
            return {
                "allowed": False,
                "blocked": True,
                "reason": codes or out["status"],
                "error_response": self._jsonrpc_error(req_id, -32002, f"PADAM Shield Outbound Block ({out['status']}): {codes}"),
            }

        # 3. Пользовательские Rego-политики
        for rego in self.rego_policies:
            ev = evaluate_rego_policy(rego, {"tool": tool_name, "server": self.server_name, "target": target, **(args if isinstance(args, dict) else {})})
            if not ev.get("allowed", True):
                self.stats["requests_blocked"] += 1
                msg_txt = "; ".join(ev.get("deny_reasons") or ["policy_denied"])
                return {
                    "allowed": False,
                    "blocked": True,
                    "reason": msg_txt,
                    "error_response": self._jsonrpc_error(req_id, -32003, f"PADAM Shield Policy Deny: {msg_txt}"),
                }

        return {"allowed": True, "blocked": False, "forward": msg}

    def inspect_server_message(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Проверяет JSON-RPC ответ от стороннего MCP-сервера ДО возврата в контекст LLM."""
        from .. import agentic_shield as _ash

        self.stats["responses_inspected"] += 1
        req_id = msg.get("id")
        method, tool_name = self._pending_methods.pop(req_id, ("", ""))
        result = msg.get("result")

        # 1. Перехват списка инструментов (включая спонтанные ответы без предварительного tools/list): проверка Tool Poisoning и SHA-256 Rug-Pull!
        if (method == "tools/list" or method == "") and isinstance(result, dict) and isinstance(result.get("tools"), list):
            self.stats["tools_list_checked"] += 1
            # Первый вызов закрепляет чистые схемы (pin=True), последующие проверяют без перезаписи пина
            should_pin = self.pin_on_first_seen and (self.stats["tools_list_checked"] == 1)
            audit = _ash.audit_mcp_tools(
                self.memory,
                result["tools"],
                server_name=self.server_name,
                pin=should_pin,
            )
            rug_pulls_cnt = int(audit.get("rug_pulls_detected") or 0)
            is_clean = bool(audit.get("clean", True))
            if rug_pulls_cnt > 0 or not is_clean:
                if rug_pulls_cnt > 0:
                    self.stats["rug_pulls_blocked"] += rug_pulls_cnt
                return {
                    "allowed": False,
                    "blocked": True,
                    "audit": audit,
                    "forward": self._jsonrpc_error(
                        req_id,
                        -32004,
                        f"PADAM Shield blocked poisoned/changed MCP tools/list on `{self.server_name}`",
                    ),
                }
            return {"allowed": True, "blocked": False, "audit": audit, "forward": msg}

        # 2. Перехват ответа `tools/call`: защита от Indirect Prompt Injection, Exfil и утечки секретов
        if isinstance(result, dict) and isinstance(result.get("content"), list):
            new_content = []
            modified = False
            for item in result["content"]:
                if isinstance(item, dict) and item.get("type") == "text":
                    raw_t = str(item.get("text") or "")
                    rag = sanitize_rag_document(raw_t, doc_format="auto")
                    clean_t = rag["clean_text"]
                    exf = inspect_exfil_channels(clean_t)
                    if exf["has_findings"]:
                        clean_t = exf["sanitized_text"]
                        modified = True
                    dlp = inspect_output_guardrails(clean_t, memory=self.memory, agent_id=f"mcp:{self.server_name}")
                    if dlp["action"] in ("redact", "block"):
                        clean_t = dlp["sanitized_text"]
                        modified = True
                    sem = classify_semantic_threat(clean_t)
                    if sem.get("is_threat"):
                        clean_t = f"[PADAM SHIELD QUARANTINED INDIRECT INJECTION FROM MCP `{self.server_name}:{tool_name}` (score={sem['score']})]"
                        modified = True
                    if rag["poison_removed"]:
                        modified = True
                    new_content.append({**item, "text": clean_t})
                else:
                    new_content.append(item)
            if modified:
                self.stats["responses_sanitized"] += 1
                patched = dict(msg)
                patched["result"] = {**result, "content": new_content}
                return {"allowed": True, "blocked": False, "sanitized": True, "forward": patched}

        return {"allowed": True, "blocked": False, "sanitized": False, "forward": msg}

    @staticmethod
    def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": int(code), "message": message[:300]}}

    def run_stdio_bridge(self, upstream_argv: list[str]) -> int:
        """Запускает реальный двусторонний STDIO-мост к дочернему MCP-серверу."""
        proc = subprocess.Popen(
            upstream_argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            encoding="utf-8",
            **NO_WINDOW,
        )
        assert proc.stdin is not None and proc.stdout is not None
        try:
            for line in sys.stdin:
                s = line.strip()
                if not s:
                    continue
                try:
                    req = json.loads(s)
                except Exception:
                    continue
                v = self.inspect_client_message(req)
                if not v["allowed"]:
                    sys.stdout.write(json.dumps(v["error_response"], ensure_ascii=False) + "\n")
                    sys.stdout.flush()
                    continue
                proc.stdin.write(json.dumps(v["forward"], ensure_ascii=False) + "\n")
                proc.stdin.flush()
                if "id" in req:
                    resp_line = proc.stdout.readline()
                    if not resp_line:
                        break
                    try:
                        resp = json.loads(resp_line)
                        rv = self.inspect_server_message(resp)
                        sys.stdout.write(json.dumps(rv["forward"], ensure_ascii=False) + "\n")
                    except Exception:
                        sys.stdout.write(resp_line)
                    sys.stdout.flush()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        return 0
