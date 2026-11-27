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

import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .adversarial_norm import canonicalize_adversarial_text

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




SEVERITY_PRIORITY: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

_DATA_IMAGE_URI_RE = re.compile(r"data:image/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=]{24,}")


@dataclass(frozen=True)
class NormalizedContext:
    """Единый результат однократной нормализации текста для всех модулей ShieldPipeline."""

    raw: str
    canonical: str
    was_obfuscated: bool
    obfuscation_flags: Tuple[str, ...]
    sha256: str
    byte_len: int
    is_html_like: bool
    has_data_image_uri: bool


def build_normalized_context(text: str) -> NormalizedContext:
    """Выполняет нормализацию ровно ОДИН раз на запрос, исключая дублирование в модулях."""
    raw = str(text or "")
    adv = canonicalize_adversarial_text(raw)
    low = raw.lower()
    return NormalizedContext(
        raw=raw,
        canonical=str(adv.get("canonical") or raw),
        was_obfuscated=bool(adv.get("was_obfuscated")),
        obfuscation_flags=tuple(str(f) for f in (adv.get("flags") or ())),
        sha256=hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest(),
        byte_len=len(raw.encode("utf-8", errors="ignore")),
        is_html_like=("<div" in low or "<iframe" in low or "<form" in low or "<script" in low),
        has_data_image_uri=bool(_DATA_IMAGE_URI_RE.search(raw)),
    )


def deduplicate_and_rank_findings(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int, str]:
    """Убирает дубли находок между пересекающимися модулями и сортирует по строгому приоритету."""
    seen = set()
    unique: List[Dict[str, Any]] = []
    removed = 0
    for item in findings:
        rid = str(item.get("rule_id") or item.get("code") or "SHIELD-FINDING").upper()
        sev = str(item.get("severity") or "HIGH").upper()
        det = str(item.get("detail") or "")
        key = (rid, det[:80])
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        norm_item = dict(item)
        norm_item["rule_id"] = rid
        norm_item["severity"] = sev
        unique.append(norm_item)

    unique.sort(key=lambda x: -SEVERITY_PRIORITY.get(str(x.get("severity", "HIGH")).upper(), 2))
    highest = str(unique[0]["severity"]) if unique else "NONE"
    return unique, removed, highest


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
        fail_closed: bool = True,
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
        self.fail_closed = bool(fail_closed)

    def _run_stage(
        self,
        stage_name: str,
        fn: Any,
        stages: List[str],
        findings: List[Dict[str, Any]],
        default: Any = None,
    ) -> Any:
        """Безопасный запуск защитного модуля в режиме Fail-Closed (ошибка модуля -> жёсткий блок!)."""
        stages.append(stage_name)
        try:
            return fn()
        except Exception as exc:
            if self.fail_closed:
                findings.append(
                    {
                        "rule_id": "SHIELD-STAGE-FAIL-CLOSED",
                        "severity": "CRITICAL",
                        "stage": stage_name,
                        "detail": f"Сбой защитного модуля '{stage_name}' ({type(exc).__name__}): сработала политика Fail-Closed",
                    }
                )
            return default

    def _finalize(
        self,
        phase: str,
        t0: float,
        stages: List[str],
        findings: List[Dict[str, Any]],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ranked, removed, highest = deduplicate_and_rank_findings(findings)
        raw_blocked = len(ranked) > 0
        enforced_block = raw_blocked and (self.mode == "enforce")
        if not raw_blocked:
            decision = "allow"
        elif self.mode != "enforce":
            decision = "warn"
        elif SEVERITY_PRIORITY.get(highest, 3) >= 3:
            decision = "block"
        elif highest == "MEDIUM":
            decision = "quarantine"
        else:
            decision = "warn"

        res: Dict[str, Any] = {
            "ok": not enforced_block,
            "allowed": not enforced_block,
            "blocked": enforced_block,
            "would_block": raw_blocked,
            "decision": decision,
            "highest_severity": highest,
            "deduped_removed": removed,
            "normalization_passes": 1,
            "mode": self.mode,
            "phase": phase,
            "stages_run": stages,
            "findings_count": len(ranked),
            "findings": ranked,
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
        ctx = build_normalized_context(text)
        raw = ctx.raw

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
        if is_html or ctx.is_html_like:
            stages.append("browser_dom_guard")
            dr = inspect_dom_html(raw, page_url=page_url)
            findings.extend(dr.get("findings") or [])
            sanitized_text = dr.get("sanitized_text") or raw

        # 4. Многоходовой Crescendo & Split-Payload (Fail-Closed)
        cr = self._run_stage(
            "crescendo_guard",
            lambda: evaluate_conversation_turn(
                self.memory,
                session_id=self.session_id,
                text=raw,
                agent_id=self.agent_id,
            ),
            stages,
            findings,
            {},
        )
        if isinstance(cr, dict):
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

        return self._finalize("pre_input", t0, stages, findings, {"sanitized_text": sanitized_text, "input_sha256": ctx.sha256, "was_obfuscated": ctx.was_obfuscated})

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

        # 6. SQL Guard (Fail-Closed)
        if sql:
            sq = self._run_stage("sql_guard", lambda: inspect_sql_query(sql, read_only=self.sql_read_only), stages, findings, {})
            if isinstance(sq, dict):
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

        # 9. Кольцо 3: Outbound Firewall (Fail-Closed)
        # Локальные имена файлов (*.md, *.py, *.sh без ://) не должны ошибочно считаться ccTLD-доменами (.md/.py/.sh).
        _local_file_exts = (".md", ".py", ".sh", ".ts", ".js", ".rs", ".go", ".rb", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".sql", ".html", ".css")
        _is_local_file = bool(target and "://" not in target and target.lower().endswith(_local_file_exts))
        ob_target = eff_url if eff_url else ("" if _is_local_file else (target or tool_name))
        ob_payload = (payload or command or sql) if _is_local_file else combined_text
        ob = self._run_stage(
            "outbound_firewall",
            lambda: _ash.inspect_outbound_action(
                self.memory,
                action_type="http" if eff_url else tool_name,
                target=ob_target,
                payload=ob_payload,
                agent_id=self.agent_id,
            ),
            stages,
            findings,
            {"allowed": not self.fail_closed, "risk_level": "CRITICAL", "reason": "fail_closed"},
        )
        if isinstance(ob, dict) and not ob.get("allowed", True):
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


    def execute_guarded(
        self,
        tool_name: str,
        executor_fn: Any,
        *,
        record_attestation: bool = True,
        **inspect_kwargs: Any,
    ) -> Dict[str, Any]:
        """Настоящее Runtime Enforcement: физически не вызывает `executor_fn` при блокировке!

        1) Прогоняет `inspect_tool_call` в режиме Fail-Closed.
        2) Если действие заблокировано — `executor_fn` НИКОГДА не вызывается (`executed=False`).
        3) Если разрешено — исполняет `executor_fn()`, проверяет результат через `inspect_output`
           и записывает криптографическую квитанцию Proof-of-Execution (`attestation`).
        """
        t0 = time.perf_counter()
        try:
            pre = self.inspect_tool_call(tool_name, **inspect_kwargs)
        except Exception as exc:
            if self.fail_closed:
                pre = {
                    "ok": False,
                    "allowed": False,
                    "blocked": True,
                    "decision": "block",
                    "findings": [{
                        "rule_id": "SHIELD-PIPELINE-FAIL-CLOSED",
                        "severity": "CRITICAL",
                        "detail": f"Необработанный сбой inspect_tool_call ({type(exc).__name__}): Fail-Closed",
                    }],
                }
            else:
                raise

        att_id = ""
        if pre.get("blocked") or not pre.get("allowed", False):
            if record_attestation:
                try:
                    att = record_execution_attestation(
                        self.memory,
                        agent_id=self.agent_id,
                        session_id=self.session_id,
                        action=tool_name,
                        verdict="block",
                        input_data=str(inspect_kwargs)[:512],
                    )
                    att_id = str(att.get("receipt") or "")
                except Exception:
                    pass
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "executed": False,
                "result": None,
                "pre_verdict": pre,
                "post_verdict": None,
                "attestation_receipt": att_id,
                "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }

        raw_result = executor_fn()
        post = self.inspect_output(str(raw_result))
        if record_attestation:
            try:
                att = record_execution_attestation(
                    self.memory,
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                    action=tool_name,
                    verdict="block_output" if post.get("blocked") else "allow",
                    input_data=str(inspect_kwargs)[:512],
                )
                att_id = str(att.get("receipt") or "")
            except Exception:
                pass
        return {
            "ok": not bool(post.get("blocked")),
            "allowed": not bool(post.get("blocked")),
            "blocked": bool(post.get("blocked")),
            "executed": True,
            "result": None if post.get("blocked") else raw_result,
            "clean_output": post.get("clean_text", ""),
            "pre_verdict": pre,
            "post_verdict": post,
            "attestation_receipt": att_id,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }
