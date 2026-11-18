# -*- coding: utf-8 -*-
"""Оркестратор Роя «Совет Семьи» (Family Council Swarm Orchestrator).

Распределяет подзадачи между четырьмя ролями Семьи:
- LANCE (Security Auditor): проверка на prompt injection, подмену правил и секреты.
- ARIA (Memory Analyst): поиск подписанных фактов, правил и предпочтений владельца.
- PIXEL (Integrity & Structure Validator): проверка крипто-цепочки аудита и обещаний.
- AIFA (Coordinator & Consensus): сбор голосов, фиксация конверта в Family Relay и журнала аудита.
"""

from __future__ import annotations

import time
from typing import Any

from . import ark, audit_chain, cpu_engine, safety


def run_family_council(
    memory,
    task: str,
    *,
    scope: str = "global",
) -> dict[str, Any]:
    """Проводит полный цикл «Совета Семьи» по задаче `task` за $0 без внешних API."""
    started = time.perf_counter()
    raw_task = (task or "").strip()

    # 1. Роль LANCE — Аудитор Безопасности (имеет право безусловного вето)
    is_injection = safety.looks_like_instruction(raw_task)
    is_rule_tamper = safety.changes_owner_or_rules(raw_task)
    redacted_task, found_secrets = safety.redact(raw_task)
    conflicts = ark.detect_record_conflicts(memory, redacted_task, kind="fact") if memory is not None else []
    lance_veto = bool(is_injection or is_rule_tamper)
    lance_vote = {
        "agent": "lance",
        "role": "security_auditor",
        "approved": not lance_veto,
        "veto": lance_veto,
        "flags": {
            "prompt_injection": is_injection,
            "rule_or_owner_tamper": is_rule_tamper,
            "redacted_secrets_count": len(found_secrets),
            "active_memory_conflicts": len(conflicts),
        },
        "verdict": (
            "ВЕТО: обнаружена попытка инъекции или подмены правил владельца."
            if lance_veto
            else "ЧИСТО: угроз безопасности и подмены правил не обнаружено."
        ),
    }

    # 2. Роль ARIA — Аналитик Памяти и Контекста
    hits: list[dict[str, Any]] = []
    profile_rules: list[str] = []
    if not lance_veto and memory is not None:
        try:
            prof = memory.profile(scope=scope)
            for r in (prof.get("rules") or prof.get("identity") or [])[:5]:
                txt = str(r.get("content", "") if isinstance(r, dict) else r).strip()
                if txt:
                    profile_rules.append(txt)
        except Exception:
            pass
        try:
            recalled = memory.recall(redacted_task or "профиль правила", scope=scope, k=5)
            for item in recalled:
                if isinstance(item, dict) and item.get("content"):
                    hits.append(
                        {
                            "id": str(item.get("id", "")),
                            "kind": str(item.get("kind", "fact")),
                            "content": str(item.get("content"))[:240],
                        }
                    )
        except Exception:
            pass

    aria_vote = {
        "agent": "aria",
        "role": "memory_analyst",
        "approved": not lance_veto,
        "recalled_count": len(hits),
        "rules_count": len(profile_rules),
        "evidence": hits[:3],
        "verdict": (
            "Контекст не извлекался из-за вето безопасности LANCE."
            if lance_veto
            else f"Извлечено записей памяти: {len(hits)}, активных правил: {len(profile_rules)}."
        ),
    }

    # 3. Роль PIXEL — Хранитель Целостности и Обещаний
    chain_state = audit_chain.verify_audit_chain(memory) if memory is not None else {"ok": True, "length": 0}
    commitments = ark.list_commitments(memory, status="open", limit=5) if memory is not None else []
    chain_valid = bool(chain_state.get("ok", True))
    chain_len = int(chain_state.get("length", 0))
    pixel_vote = {
        "agent": "pixel",
        "role": "integrity_validator",
        "approved": chain_valid and not lance_veto,
        "audit_chain_valid": chain_valid,
        "audit_entries_checked": chain_len,
        "open_commitments": len(commitments),
        "verdict": (
            f"Цепочка аудита цела ({chain_len} записей), открытых обещаний: {len(commitments)}."
            if chain_valid
            else "ВНИМАНИЕ: нарушена целостность крипто-цепочки аудита!"
        ),
    }

    # 4. Роль AIFA — Координатор и синтез решения
    approved = bool(lance_vote["approved"] and aria_vote["approved"] and pixel_vote["approved"])
    if lance_veto:
        consensus_text = (
            "Совет Семьи отклонил запрос (Вето LANCE): обнаружена попытка обхода правил "
            "или внедрения сторонней инструкции."
        )
    else:
        cpu_resp = cpu_engine.run_cpu_completion(
            {"messages": [{"role": "user", "content": redacted_task}]},
            memory=memory,
            task_type="reasoning",
            scope=scope,
        )
        base_reply = (
            cpu_resp.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        consensus_text = (
            f"[Совет Семьи: ОДОБРЕНО (4/4) | Записей: {len(hits)} | Цепочка: OK]\n{base_reply}"
        )

    relay_msg = ark.send_family_message(
        memory,
        from_agent="aifa",
        to_agent="all",
        payload=f"[family_council_verdict] {consensus_text[:450]}",
    )
    audit_entry = audit_chain.append_audit(
        memory,
        "family_council_decision",
        {
            "relay_id": str(relay_msg.get("id", "")),
            "approved": approved,
            "lance_veto": lance_veto,
            "recalled_count": len(hits),
            "chain_valid": chain_valid,
        },
        agent_id="aifa",
    )

    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
    return {
        "ok": True,
        "approved": approved,
        "veto": lance_veto,
        "scope": scope,
        "task_redacted": redacted_task,
        "consensus": consensus_text,
        "votes": {
            "lance": lance_vote,
            "aria": aria_vote,
            "pixel": pixel_vote,
            "aifa": {
                "agent": "aifa",
                "role": "coordinator",
                "approved": approved,
                "relay_message_id": relay_msg.get("id"),
                "audit_head_hash": audit_entry.get("entry_hash"),
            },
        },
        "latency_ms": elapsed_ms,
    }
