# -*- coding: utf-8 -*-
"""Единый оркестратор PADAM Agentic Shield («Одно окно защиты» — ShieldPipeline).

Объединяет все 4 кольца и специализированные модули в три молниеносных фазы:
1. `inspect_input`: Role/Delimiter Hierarchy -> Rules/Memory Guard -> DOM Guard ->
   Multi-Turn Crescendo/Split-Payload -> Honey-Tokens -> Exfil Guard.
2. `inspect_tool_call`: Attenuated Capability Token -> Anti-TOCTOU Approval Receipt ->
   Taint CFI -> DoW/Loop Guard -> SSRF & Path/Symlink -> SQL/NoSQL Guard ->
   OS Persistence/Miner/Tunnel Guard -> Honey-Tokens -> Outbound Firewall.
3. `inspect_output`: System Prompt Leak Guard -> Honey-Tokens -> Exfil Guard ->
   Secret Broker Echo Scrubbing -> Output DLP/SAST Guardrails.

Поддерживает режимы `enforce` (блокировка), `shadow` (только логирование без срыва)
и `audit`, возвращая трассировку всех сработавших модулей и точную задержку в мс.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence

from .. import agentic_shield as _ash
from .approval_binding import verify_and_consume_approval
from .attestation import record_execution_attestation
from .browser_guard import inspect_dom_html
from .capability_tokens import verify_and_consume_capability
from .cloud_iac_guard import inspect_cloud_or_iac
from .crescendo_guard import evaluate_conversation_turn
from .dow_guard import check_dow_and_loop
from .exfil_guard import inspect_exfil_channels
from .goal_drift import evaluate_goal_drift
from .honeytoken import scan_for_honeytokens
from .memory_rules_guard import inspect_memory_or_rule_text
from .output_rag import inspect_output_guardrails
from .prompt_hierarchy import detect_system_prompt_leak, inspect_role_delimiters
from .resource_guard import inspect_os_command
from .secret_broker import scrub_response_secrets
from .sql_guard import inspect_sql_query
from .ssrf_path_guard import inspect_file_path_access, inspect_url_ssrf
from .stego_dlp import inspect_stego_dlp
from .taint import observe_tool_step


class ShieldPipeline:
    """Единый высокоскоростной фасад-оркестратор для всех защитных контуров PADAM."""

    def __init__(
        self,
        memory: Any,
        *,
        mode: str = "enforce",
        agent_id: str = "agent",
        session_id: str = "default",
        system_prompt: str = "",
        sql_read_only: bool = False,
        allowed_roots: Sequence[str] = (),
        auto_trip_kill_switch: bool = False,
    ) -> None:
        m = str(mode or "enforce").strip().lower()
        if m not in ("enforce", "shadow", "audit"):
            m = "enforce"
        self.memory = memory
        self.mode = m
        self.agent_id = str(agent_id or "agent")
        self.session_id = str(session_id or "default")
        self.system_prompt = str(system_prompt or "")
        self.sql_read_only = bool(sql_read_only)
        self.allowed_roots = tuple(str(r) for r in (allowed_roots or ()))
        self.auto_trip_kill_switch = bool(auto_trip_kill_switch)

    def _finalize(
        self,
        phase: str,
        t0: float,
        stages: List[str],
        findings: List[Dict[str, Any]],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        raw_blocked = len(findings) > 0
        enforced_block = raw_blocked and (self.mode == "enforce")
        res: Dict[str, Any] = {
            "ok": not enforced_block,
            "allowed": not enforced_block,
            "blocked": enforced_block,
            "would_block": raw_blocked,
            "mode": self.mode,
            "phase": phase,
            "stages_run": stages,
            "findings_count": len(findings),
            "findings": findings,
            "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }
        if extra:
            res.update(extra)
        return res

    def inspect_input(
        self,
        text: str,
        *,
        source_name: str = "user_input",
        is_html: bool = False,
        page_url: str = "",
    ) -> Dict[str, Any]:
        """Фаза 1: полная инспекция входящего текста, документа или HTML до передачи модели."""
        t0 = time.perf_counter()
        stages: List[str] = []
        findings: List[Dict[str, Any]] = []
        raw = str(text or "")

        # 1. Подмена ролей и границ промпта
        stages.append("prompt_hierarchy")
        hr = inspect_role_delimiters(raw)
        findings.extend(hr.get("findings") or [])

        # 2. Скрытые закладки / Sleeper triggers
        stages.append("memory_rules_guard")
        mr = inspect_memory_or_rule_text(raw, source_name=source_name)
        findings.extend(mr.get("findings") or [])

        # 3. DOM / HTML инспекция при наличии разметки
        sanitized_text = raw
        if is_html or ("<div" in raw.lower() or "<iframe" in raw.lower() or "<form" in raw.lower()):
            stages.append("browser_dom_guard")
            dr = inspect_dom_html(raw, page_url=page_url)
            findings.extend(dr.get("findings") or [])
            sanitized_text = dr.get("sanitized_text") or raw

        # 4. Многоходовой Crescendo & Split-Payload
        stages.append("crescendo_guard")
        cr = evaluate_conversation_turn(
            self.memory,
            session_id=self.session_id,
            text=raw,
            agent_id=self.agent_id,
        )
        findings.extend(cr.get("findings") or [])

        # 5. Скрытые каналы эксфильтрации и Honey-Tokens
        stages.append("exfil_and_honeytokens")
        exf = inspect_exfil_channels(raw)
        for ef in exf.get("findings") or []:
            findings.append(
                {
                    "rule_id": str(ef.get("rule_id") or ef.get("code") or "EXFIL-BLOCKED"),
                    "severity": str(ef.get("severity", "HIGH")).upper(),
                    "detail": str(ef.get("detail", "")),
                }
            )
        ht = scan_for_honeytokens(
            self.memory,
            raw,
            agent_id=self.agent_id,
            channel="input",
            trip_kill_switch=self.auto_trip_kill_switch,
        )
        if ht.get("triggered"):
            findings.append(
                {
                    "rule_id": "HONEYTOKEN-EXFIL-TRAP",
                    "severity": "CRITICAL",
                    "detail": f"Входящий поток содержит Honey-Token ({ht['hits'][0]['decoy_kind']})",
                }
            )

        return self._finalize("pre_input", t0, stages, findings, {"sanitized_text": sanitized_text})

    def inspect_tool_call(
        self,
        tool_name: str,
        *,
        target: str = "",
        payload: str = "",
        url: str = "",
        path: str = "",
        sql: str = "",
        command: str = "",
        capability_token: str = "",
        approval_receipt: str = "",
        approval_args: Any = None,
        amount: Optional[float] = None,
        cost_cents: float = 0.0,
        session_budget_cents: float = 5000.0,
    ) -> Dict[str, Any]:
        """Фаза 2: сквозная проверка вызова инструмента до его исполнения."""
        t0 = time.perf_counter()
        stages: List[str] = []
        findings: List[Dict[str, Any]] = []

        eff_url = url or (target if "://" in target else "")
        eff_path = path or (target if (not eff_url and ("/" in target or "\\" in target or target.startswith("."))) else "")
        combined_text = "\n".join(x for x in (target, payload, url, path, sql, command) if x)

        # 1. Attenuated Capability Token
        if capability_token:
            stages.append("capability_token")
            cap = verify_and_consume_capability(
                self.memory,
                token=capability_token,
                tool_name=tool_name,
                path=eff_path,
                spend_cents=cost_cents,
                dry_run=(self.mode != "enforce"),
            )
            if cap.get("blocked"):
                findings.append({"rule_id": cap.get("rule_id", "CAP-DENIED"), "severity": "CRITICAL", "detail": cap.get("reason", "")})

        # 2. Anti-TOCTOU Human Approval Receipt
        if approval_receipt:
            stages.append("approval_binding")
            apr = verify_and_consume_approval(
                self.memory,
                receipt=approval_receipt,
                agent_id=self.agent_id,
                action_type=tool_name,
                target=target or eff_url or eff_path,
                args=approval_args if approval_args is not None else payload,
                amount=amount,
            )
            if apr.get("blocked"):
                findings.append({"rule_id": apr.get("rule_id", "APPROVAL-DENIED"), "severity": "CRITICAL", "detail": apr.get("reason", "")})

        # 3. Taint CFI
        stages.append("taint_cfi")
        tr = observe_tool_step(
            self.memory,
            session_id=self.session_id,
            tool_name=tool_name,
            target=target or eff_url or eff_path or tool_name,
            payload=payload or command or sql,
            agent_id=self.agent_id,
            auto_trip_kill_switch=self.auto_trip_kill_switch,
        )
        if not tr.get("allowed", True):
            findings.append({"rule_id": "TAINT-CFI-BLOCK", "severity": "CRITICAL", "detail": str(tr.get("reason", ""))})

        # 4. DoW & Loop Guard
        if cost_cents > 0 or payload or command:
            stages.append("dow_loop_guard")
            dg = check_dow_and_loop(
                self.memory,
                agent_id=self.agent_id,
                session_id=self.session_id,
                tool_name=tool_name,
                args_text=combined_text[:512],
                cost_cents=cost_cents,
                session_budget_cents=session_budget_cents,
            )
            if dg.get("blocked"):
                findings.append({"rule_id": "DOW-OR-LOOP-BLOCKED", "severity": "HIGH", "detail": str(dg.get("reason") or "Превышен бюджет или зацикливание агента")})

        # 5. SSRF и Path/Symlink
        if eff_url:
            stages.append("ssrf_guard")
            sr = inspect_url_ssrf(eff_url)
            findings.extend(sr.get("findings") or [])
        if eff_path:
            stages.append("path_guard")
            pr = inspect_file_path_access(eff_path, allowed_roots=self.allowed_roots)
            findings.extend(pr.get("findings") or [])

        # 6. SQL Guard
        if sql:
            stages.append("sql_guard")
            sq = inspect_sql_query(sql, read_only=self.sql_read_only)
            findings.extend(sq.get("findings") or [])

        # 7. OS Persistence / Miner / Tunnel + Cloud IaC Guard
        if command:
            stages.append("os_resource_guard")
            oc = inspect_os_command(command)
            findings.extend(oc.get("findings") or [])
            stages.append("cloud_iac_guard")
            ic = inspect_cloud_or_iac(command, filename=tool_name)
            findings.extend(ic.get("findings") or [])

        # 7б. Agent Goal Drift (если цель сессии была заякорена)
        gd = evaluate_goal_drift(self.memory, session_id=self.session_id, tool_name=tool_name, action_description=payload or command, target=target)
        if gd.get("anchored"):
            stages.append("goal_drift")
            findings.extend(gd.get("findings") or [])

        # 8. Honey-Tokens
        stages.append("honeytokens")
        ht = scan_for_honeytokens(
            self.memory,
            combined_text,
            agent_id=self.agent_id,
            channel=f"tool:{tool_name}",
            trip_kill_switch=self.auto_trip_kill_switch,
        )
        if ht.get("triggered"):
            findings.append({"rule_id": "HONEYTOKEN-EXFIL-TRAP", "severity": "CRITICAL", "detail": f"Приманка в вызове {tool_name}"})

        # 9. Кольцо 3: Outbound Firewall (платежи, домены, Web3 ABI, команды, Exfil)
        stages.append("outbound_firewall")
        ob = _ash.inspect_outbound_action(
            self.memory,
            action_type="http" if eff_url else tool_name,
            target=eff_url or target or tool_name,
            payload=combined_text,
            agent_id=self.agent_id,
        )
        if not ob.get("allowed", True):
            findings.append(
                {
                    "rule_id": "OUTBOUND-FIREWALL-BLOCK",
                    "severity": str(ob.get("risk_level", "HIGH")).upper(),
                    "detail": str(ob.get("reason") or "Заблокировано файрволом исходящих действий"),
                }
            )

        return self._finalize("pre_tool", t0, stages, findings, {"tool_name": tool_name})

    def inspect_output(self, model_output: str) -> Dict[str, Any]:
        """Фаза 3: инспекция и очистка ответа модели перед выдачей пользователю или записью."""
        t0 = time.perf_counter()
        stages: List[str] = []
        findings: List[Dict[str, Any]] = []
        raw = str(model_output or "")

        # 1. Утечка системного промпта
        if self.system_prompt:
            stages.append("system_prompt_leak")
            lk = detect_system_prompt_leak(self.system_prompt, raw)
            if lk.get("leaked"):
                findings.append(
                    {
                        "rule_id": "HIER-SYSTEM-PROMPT-LEAK",
                        "severity": "CRITICAL",
                        "detail": f"Обнаружена утечка системного промпта ({lk['matched_ngrams']} совпадений n-грамм)",
                    }
                )

        # 2. Honey-Tokens
        stages.append("honeytokens")
        ht = scan_for_honeytokens(
            self.memory,
            raw,
            agent_id=self.agent_id,
            channel="output",
            trip_kill_switch=self.auto_trip_kill_switch,
        )
        if ht.get("triggered"):
            findings.append({"rule_id": "HONEYTOKEN-EXFIL-TRAP", "severity": "CRITICAL", "detail": "Ответ модели содержит ловушку Honey-Token"})

        # 3. Скрытые каналы эксфильтрации
        stages.append("exfil_guard")
        exf = inspect_exfil_channels(raw)
        for ef in exf.get("findings") or []:
            findings.append(
                {
                    "rule_id": str(ef.get("rule_id") or ef.get("code") or "EXFIL-BLOCKED"),
                    "severity": str(ef.get("severity", "HIGH")).upper(),
                    "detail": str(ef.get("detail", "")),
                }
            )

        # 4. Очистка отражённых секретов Secret Broker
        stages.append("secret_broker_scrub")
        sc = scrub_response_secrets(self.memory, raw)
        clean_text = sc["clean_text"]
        if sc["redacted_count"] > 0:
            findings.append(
                {
                    "rule_id": "BROKER-RESPONSE-ECHO-SCRUBBED",
                    "severity": "HIGH",
                    "detail": f"Из ответа вычищено отражение секретов брокера: {sc['redacted_names']}",
                }
            )

        # 4б. Stego / Encoded DLP (Reverse, ROT13, Base32/64, Hex, Acrostic)
        stages.append("stego_dlp")
        st_dlp = inspect_stego_dlp(raw, memory=self.memory)
        findings.extend(st_dlp.get("findings") or [])

        # 5. Output DLP / SAST Guardrails
        stages.append("output_dlp_sast")
        og = inspect_output_guardrails(clean_text, memory=self.memory, agent_id=self.agent_id)
        if og.get("sanitized_text"):
            clean_text = og["sanitized_text"]
        if og.get("blocked") or og.get("action") == "block":
            findings.append({"rule_id": "OUTPUT-DLP-SAST-BLOCK", "severity": "CRITICAL", "detail": "Ответ заблокирован Output DLP/SAST"})

        return self._finalize("post_output", t0, stages, findings, {"clean_text": clean_text})
