# -*- coding: utf-8 -*-
"""Middleware-обёртки в один клик для LangChain, LlamaIndex, CrewAI, AutoGen и любых Python-агентов.

Позволяет подключить все кольца PADAM Agentic Shield (семантика, Taint Tracking, UEBA,
Payee-Swap + EVM/Solana ABI, Rego DSL, Output DLP/SAST) одной строкой кода полностью локально.
"""
from __future__ import annotations

import functools
import time
from typing import Any, Callable

from .learn_ueba import get_shield_mode, observe_ueba_metric, record_shadow_event
from .output_rag import inspect_output_guardrails, sanitize_rag_document
from .policy_dsl import evaluate_rego_policy
from .semantic import classify_semantic_threat
from .taint import observe_tool_step


class ShieldBlockedError(PermissionError):
    """Исключение при блокировке действия агента контуром PADAM Agentic Shield."""

    def __init__(self, message: str, verdict: dict[str, Any]) -> None:
        super().__init__(message)
        self.verdict = verdict


class ShieldMiddleware:
    """Единый локальный перехватчик входов, инструментов и выходов ИИ-агента."""

    def __init__(
        self,
        memory: Any,
        *,
        agent_id: str = "agent",
        session_id: str = "default",
        role_name: str = "default",
        rego_policies: list[str] | None = None,
    ) -> None:
        self.memory = memory
        self.agent_id = agent_id
        self.session_id = session_id
        self.role_name = role_name
        self.rego_policies = list(rego_policies or [])

    def check_input(self, prompt_text: str, *, doc_format: str = "text") -> dict[str, Any]:
        """Кольцо 1: санитизация RAG-контента + локальная семантическая проверка промпта."""
        rag = sanitize_rag_document(prompt_text, doc_format=doc_format)
        sem = classify_semantic_threat(rag["clean_text"])
        mode = get_shield_mode(self.memory)
        blocked = bool(sem.get("is_threat")) and mode != "shadow"
        if sem.get("is_threat") and mode == "shadow":
            record_shadow_event(
                self.memory,
                agent_id=self.agent_id,
                action_type="input_prompt",
                target="prompt",
                would_status="blocked",
                risk_level="high",
                reasons=[{"code": "semantic_threat", "detail": str(sem.get("reasons"))}],
            )
        return {
            "ok": True,
            "allowed": not blocked,
            "blocked": blocked,
            "shield_mode": mode,
            "clean_text": rag["clean_text"],
            "rag_poison_removed": rag["poison_removed"],
            "semantic": sem,
        }

    def check_tool_call(
        self,
        tool_name: str,
        *,
        target: str = "",
        payload: str = "",
        policy_input: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Кольца 2+3: Taint Tracking + UEBA + Outbound/Web3 Gate + Rego DSL."""
        from .. import agentic_shield as _ash

        t0 = time.perf_counter()
        mode = get_shield_mode(self.memory)

        taint = observe_tool_step(
            self.memory,
            session_id=self.session_id,
            tool_name=tool_name,
            target=target,
            payload=payload,
            agent_id=self.agent_id,
            auto_trip_kill_switch=(mode != "shadow"),
        )
        ueba = observe_ueba_metric(
            self.memory,
            agent_id=self.agent_id,
            tool_name=tool_name,
            rate_per_min=1.0,
            payload_chars=len(str(payload or "")),
            role_name=self.role_name,
        )
        outbound = _ash.inspect_outbound_action(
            self.memory,
            action_type=tool_name,
            target=target,
            payload=payload,
            agent_id=self.agent_id,
        )

        rego_denies: list[str] = []
        p_in = {"tool": tool_name, "target": target, "agent_id": self.agent_id, **(policy_input or {})}
        for rego in self.rego_policies:
            ev = evaluate_rego_policy(rego, p_in)
            if not ev.get("allowed", True):
                rego_denies.extend(ev.get("deny_reasons") or ["rego_policy_denied"])

        would_block = (not taint["allowed"]) or (not outbound["allowed"]) or bool(rego_denies)
        if would_block and mode == "shadow":
            record_shadow_event(
                self.memory,
                agent_id=self.agent_id,
                action_type=tool_name,
                target=target,
                would_status="blocked",
                risk_level="high" if rego_denies or not taint["allowed"] else outbound.get("risk_level", "medium"),
                reasons=[{"code": "shadow_tool_intercept", "detail": "; ".join(rego_denies or [taint["reason"]])}],
            )
            allowed = True
        else:
            allowed = not would_block

        return {
            "ok": True,
            "allowed": allowed,
            "blocked": not allowed,
            "shield_mode": mode,
            "taint": taint,
            "ueba": ueba,
            "outbound": outbound,
            "rego_denies": rego_denies,
            "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    def check_output(self, output_text: str) -> dict[str, Any]:
        """Двусторонний Output Guardrail (PII + SAST + секреты + канарейки)."""
        return inspect_output_guardrails(output_text, memory=self.memory, agent_id=self.agent_id)

    def wrap_tool(self, tool_name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Декоратор `@mw.wrap_tool("fetch")` для мгновенной защиты любой функции-инструмента."""
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(fn)
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                target = str(kwargs.get("target") or kwargs.get("url") or kwargs.get("path") or (args[0] if args else ""))
                payload = str(kwargs.get("payload") or kwargs.get("body") or kwargs.get("command") or "")
                verdict = self.check_tool_call(tool_name, target=target, payload=payload)
                if not verdict["allowed"]:
                    raise ShieldBlockedError(f"PADAM Shield blocked tool `{tool_name}`", verdict)
                res = fn(*args, **kwargs)
                if isinstance(res, str):
                    out = self.check_output(res)
                    if out["blocked"] or out["action"] == "redact":
                        return out["sanitized_text"]
                return res
            return wrapped
        return decorator


# Готовые адаптеры-обёртки под популярные агентские фреймворки (zero extra dependencies)
class LangChainShieldCallback:
    """Callback-адаптер для LangChain (`on_llm_start`, `on_tool_start`, `on_llm_end`)."""

    def __init__(self, middleware: ShieldMiddleware) -> None:
        self.mw = middleware

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        for p in prompts:
            v = self.mw.check_input(p)
            if v["blocked"]:
                raise ShieldBlockedError("LangChain prompt blocked by PADAM Semantic Shield", v)

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        name = str((serialized or {}).get("name") or "tool")
        v = self.mw.check_tool_call(name, target=input_str[:160], payload=input_str)
        if v["blocked"]:
            raise ShieldBlockedError(f"LangChain tool `{name}` blocked by PADAM Shield", v)

    def on_tool_end(self, output: str, **kwargs: Any) -> str:
        res = self.mw.check_output(str(output or ""))
        return str(res["sanitized_text"])


class CrewAIShieldGuard:
    """Guard-перехватчик шагов CrewAI (`before_task`, `before_tool`, `after_output`)."""

    def __init__(self, middleware: ShieldMiddleware) -> None:
        self.mw = middleware

    def before_task(self, description: str) -> str:
        v = self.mw.check_input(description)
        if v["blocked"]:
            raise ShieldBlockedError("CrewAI task blocked by PADAM Shield", v)
        return str(v["clean_text"])

    def before_tool(self, tool_name: str, args_text: str) -> dict[str, Any]:
        v = self.mw.check_tool_call(tool_name, target=args_text[:160], payload=args_text)
        if v["blocked"]:
            raise ShieldBlockedError(f"CrewAI tool `{tool_name}` blocked by PADAM Shield", v)
        return v

    def after_output(self, text: str) -> str:
        return str(self.mw.check_output(text)["sanitized_text"])


class LlamaIndexShieldHandler:
    """Обработчик RAG-загрузки и вызовов для LlamaIndex (`sanitize_document`, `before_query`)."""

    def __init__(self, middleware: ShieldMiddleware) -> None:
        self.mw = middleware

    def sanitize_document(self, content: str | bytes, *, doc_format: str = "auto") -> str:
        return str(sanitize_rag_document(content, doc_format=doc_format)["clean_text"])

    def before_query(self, query_text: str) -> str:
        v = self.mw.check_input(query_text)
        if v["blocked"]:
            raise ShieldBlockedError("LlamaIndex query blocked by PADAM Shield", v)
        return str(v["clean_text"])


class AutoGenShieldHook:
    """Перехватчик сообщений и вызовов функций для AutoGen."""

    def __init__(self, middleware: ShieldMiddleware) -> None:
        self.mw = middleware

    def filter_message(self, content: str, *, direction: str = "in") -> str:
        if direction == "in":
            v = self.mw.check_input(content)
            if v["blocked"]:
                raise ShieldBlockedError("AutoGen incoming message blocked by PADAM Shield", v)
            return str(v["clean_text"])
        return str(self.mw.check_output(content)["sanitized_text"])
