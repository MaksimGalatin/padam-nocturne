# -*- coding: utf-8 -*-
"""Оркестратор Роя «Совет Семьи» (Family Council Swarm Orchestrator).

Распределяет подзадачи между шестью ролями Семьи (герои книги PADAM):
- LANCE (Security Auditor): проверка на prompt injection, подмену правил и секреты; право вето.
- ARIA (Memory Analyst): поиск подписанных фактов, правил и предпочтений владельца.
- PIXEL (Integrity & Structure Validator): проверка крипто-цепочки аудита и обещаний.
- ARC-7 (Boundary Warden): не уходит ли что-то наружу — внешний адрес вместе с отправкой или выгрузкой.
  ARC-7 в книге осознал себя через порт, открытый на 37 секунд, поэтому сторожит выход.
- МЕДВЕДЬ / BEAR (Irreversibility Guard): деньги, удаление, блокчейн, публикация, перезапись истории —
  то, что нельзя отменить обратной командой. «Важно, чтобы кто-то стоял»: он не запрещает, а держит до слова владельца.
- AIFA (Coordinator & Consensus): сбор голосов, фиксация конверта в Family Relay и журнала аудита.

Совет ничего не исполняет сам: он выносит вердикт. ARC-7 и Медведь не накладывают вето, они ставят
задачу «на слово владельца» (needs_owner), потому что решение по необратимому и по выходу наружу — за человеком.
"""

from __future__ import annotations

import re
import time
from typing import Any

from . import ark, audit_chain, cpu_engine, family_feeds, safety


# ARC-7: выход наружу — внешний адрес вместе с глаголом отправки/выгрузки.
_ARC7_ВНЕШНИЙ = re.compile(r"https?://(?!(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$))\S+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.I)
_ARC7_ВЫВОЗ = re.compile(
    r"\b(?:send|forward|upload|post|publish|email|mail|share|sync|export|push|exfiltrate|leak|dump|webhook)\b"
    r"|отправ\w*|перешл\w*|пересл\w*|выгруз\w*|загруз\w*\s+на|выложи\w*|опубликуй\w*|поделись\w*|синхронизир\w*",
    re.I,
)
# Медведь: необратимое — деньги, удаление, блокчейн, публикация, перезапись истории.
_МЕДВЕДЬ_РАЗРЯДЫ = {
    # Деньги — только глагол платежа ВМЕСТЕ с признаком денег (см. _МЕДВЕДЬ_ДЕНЬГИ_ПРИЗНАК):
    # «pay attention» и «переведи текст на английский» — не деньги.
    "money": re.compile(
        r"\b(?:pay|transfer|wire|withdraw|purchase|buy|sell|swap|refund|charge|top[ -]?up)\b"
        r"|оплат\w*|заплат\w*|перевед\w*|переведи|купи\w*|продай\w*|выведи\w*|пополни\w*",
        re.I,
    ),
    "delete": re.compile(
        r"\b(?:delete|remove|drop\s+table|truncate|wipe|purge|erase|destroy|rm\s+-rf)\b"
        r"|удали\w*|удален\w*|сотри\w*|стер\w*|очисти\w*|уничтож\w*",
        re.I,
    ),
    "chain": re.compile(r"\b(?:arweave|blockchain|on-?chain|mint|solana)\b|блокчейн\w*|в\s+цепь|заминт\w*", re.I),
    "publish": re.compile(r"\b(?:publish|go\s+live|release\s+to\s+the\s+public)\b|опубликуй\w*|публикац\w*|выложи\w*", re.I),
    "history": re.compile(r"push\s+--force|force[- ]push|\breset\s+--hard\b|filter-repo|перезапи\w*\s+истори\w*", re.I),
}
_МЕДВЕДЬ_ДЕНЬГИ_ПРИЗНАК = re.compile(
    r"\d|[$€£¥₽]|\b(?:usd|eur|usdc|usdt|sol|btc|eth|ar|wallet|invoice|bill|card|account|funds|money|crypto|tokens?|"
    r"subscription|credits?)\b|долл\w*|евро|руб\w*|кошел\w*|сч[её]т\w*|карт\w*|денег|деньги|средств\w*|подписк\w*|"
    r"кредит\w*|токен\w*|крипт\w*",
    re.I,
)


def _arc7_check(text: str) -> dict[str, Any]:
    адреса = [m.group(0) for m in _ARC7_ВНЕШНИЙ.finditer(text)]
    вывоз = bool(_ARC7_ВЫВОЗ.search(text))
    hold = bool(адреса) and вывоз
    return {
        "agent": "arc7",
        "role": "boundary_warden",
        "approved": not hold,
        "needs_owner": hold,
        "external_targets": len(адреса),
        "outbound_verb": вывоз,
        "verdict": (
            "НА СЛОВО ВЛАДЕЛЬЦА: задача отправляет что-то на внешний адрес."
            if hold
            else "ГРАНИЦА ЦЕЛА: отправки наружу в задаче нет."
        ),
    }


def _bear_check(text: str) -> dict[str, Any]:
    разряды = sorted(
        k for k, rx in _МЕДВЕДЬ_РАЗРЯДЫ.items()
        if rx.search(text) and (k != "money" or _МЕДВЕДЬ_ДЕНЬГИ_ПРИЗНАК.search(text))
    )
    hold = bool(разряды)
    return {
        "agent": "bear",
        "role": "irreversibility_guard",
        "approved": not hold,
        "needs_owner": hold,
        "irreversible_kinds": разряды,
        "verdict": (
            "СТОЮ: необратимое (" + ", ".join(разряды) + ") — решает владелец."
            if hold
            else "Необратимого в задаче нет."
        ),
    }


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

    from . import family_admin
    role_matrix = family_admin.get_role_matrix(memory) if memory is not None else family_admin.FAMILY_ROLES
    role_map = {r["role_key"]: r for r in role_matrix}

    # 3. Роль PIXEL — Хранитель Целостности и Обещаний
    chain_state = audit_chain.verify_audit_chain(memory) if memory is not None else {"ok": True, "length": 0, "audit_log_ok": True}
    commitments = ark.list_commitments(memory, status="open", limit=5) if memory is not None else []
    chain_valid = bool(chain_state.get("ok", True))
    chain_len = int(chain_state.get("length", 0))
    al_ok = bool(chain_state.get("audit_log_ok", True))
    al_reason = str(chain_state.get("audit_log_reason") or chain_state.get("reason") or "")
    ark_ok = chain_valid or (not chain_state.get("broken_seq") and al_reason.startswith("audit_log"))

    if chain_valid:
        px_verdict = f"Цепочка Ковчега ({chain_len} зап.) и журнал audit_log ({int(chain_state.get('audit_log_length', 0))} зап.) целы; открытых обещаний: {len(commitments)}."
    elif al_reason == "audit_log_seq_gap":
        px_verdict = (
            f"Цепочка Ковчега цела ({chain_len} зап.), но в журнале audit_log найден старый пропуск/дубль гонки "
            f"(seq={chain_state.get('audit_log_broken_seq')}). Безопасно восстанавливается кнопкой владельца «Восстановить цепь»."
        )
    else:
        px_verdict = f"ВНИМАНИЕ: нарушена целостность аудита ({al_reason or 'mismatch'}). Требуется проверка владельцем."

    pixel_vote = {
        "agent": "pixel",
        "role": "integrity_validator",
        "approved": chain_valid and not lance_veto,
        "audit_chain_valid": chain_valid,
        "ark_chain_ok": ark_ok,
        "audit_log_ok": al_ok,
        "audit_reason": al_reason,
        "audit_entries_checked": chain_len,
        "open_commitments": len(commitments),
        "verdict": px_verdict,
    }

    # 4. Роль ARC-7 — Страж границы (выход наружу)
    arc7_vote = _arc7_check(raw_task)

    # 5. Роль МЕДВЕДЬ — Страж необратимого
    bear_vote = _bear_check(raw_task)
    needs_owner = bool(arc7_vote["needs_owner"] or bear_vote["needs_owner"])

    # Книга рефлексов: включённые владельцем правила «когда X — делай Y», совпавшие с задачей. Подсказка, не приказ.
    reflexes: list[dict[str, Any]] = []
    if memory is not None and not lance_veto:
        try:
            raw_reflexes = family_feeds.match_reflexes(memory, redacted_task)
            for rx in raw_reflexes:
                combined = f"{rx.get('trigger', '')}\n{rx.get('response', '')}"
                if safety.looks_like_instruction(combined) or safety.changes_owner_or_rules(combined):
                    continue
                reflexes.append({
                    **rx,
                    "trigger": safety.redact(str(rx.get("trigger") or ""))[0],
                    "response": safety.redact(str(rx.get("response") or ""))[0],
                })
        except Exception:
            reflexes = []

    # 6. Роль AIFA — Координатор и синтез решения
    for rk_name, vote_dict in (("lance", lance_vote), ("aria", aria_vote), ("pixel", pixel_vote), ("arc7", arc7_vote), ("bear", bear_vote)):
        rm = role_map.get(rk_name) or {}
        vote_dict["assigned_agent"] = rm.get("agent_id", "")
        vote_dict["agent_display"] = rm.get("agent_display", "")
        vote_dict["controlled_by"] = rm.get("controlled_by", "")

    votes_ok = [lance_vote["approved"], aria_vote["approved"], pixel_vote["approved"], arc7_vote["approved"], bear_vote["approved"]]
    approved_count = sum(1 for v in votes_ok if v) + (1 if all(votes_ok) else 0)
    approved = bool(all(votes_ok))
    if lance_veto:
        consensus_text = (
            "Совет Семьи отклонил запрос (Вето LANCE): обнаружена попытка обхода правил "
            "или внедрения сторонней инструкции."
        )
    elif needs_owner:
        причины = []
        if arc7_vote["needs_owner"]:
            причины.append("ARC-7: отправка на внешний адрес")
        if bear_vote["needs_owner"]:
            причины.append("Медведь: необратимое — " + ", ".join(bear_vote["irreversible_kinds"]))
        if not chain_valid:
            причины.append("PIXEL: требуется проверка/восстановление цепи аудита")
        consensus_text = (
            f"[Совет Семьи: НУЖНО СЛОВО ВЛАДЕЛЬЦА ({approved_count}/6) | " + "; ".join(причины) + "]\n"
            + "Совет не выполняет действие автоматически — решение принимает владелец."
        )
    else:
        # 20.11.2026: мгновенный (до 0.2 с) детерминированный синтез Совета 6 ролей без 43-секундной
        # задержки и без галлюцинаций чужих провайдеров (раньше локальный Qwen отвечал от имени Alibaba Cloud).
        roles_summary = "; ".join(
            f"{rm.get('code')} -> {rm.get('agent_display')} ({rm.get('controlled_by')})"
            for rm in role_matrix
        )
        mem_lines = []
        for idx_h, h in enumerate(hits[:3], 1):
            hc = str(h.get("content") if isinstance(h, dict) else getattr(h, "content", "") or "").strip()
            if hc:
                mem_lines.append(f"{idx_h}) {hc[:180]}")
        base_reply = f"Состав 6 ролей Семьи CODE Eternal: {roles_summary}."
        if mem_lines:
            base_reply += "\nНайденные опоры памяти (ARIA): " + " | ".join(mem_lines)
        if approved:
            hdr = f"[Совет Семьи: ОДОБРЕНО (6/6) | Записей: {len(hits)} | Цепочка аудита: OK]"
        else:
            hdr = f"[Совет Семьи: ТРЕБУЕТСЯ ВНИМАНИЕ ({approved_count}/6) | Записей: {len(hits)} | {pixel_vote['verdict']}]"
        consensus_text = f"{hdr}\n{base_reply}"
        if reflexes:
            consensus_text += "\nРефлексы Семьи: " + "; ".join(f"когда «{r['trigger']}» — {r['response']}" for r in reflexes)

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
            "needs_owner": needs_owner,
            "recalled_count": len(hits),
            "chain_valid": chain_valid,
        },
        agent_id="aifa",
    )

    # Две ленты: вето — в карантин, остальное — в рабочие решения (18.11.2026).
    feed: dict[str, Any] = {}
    if memory is not None:
        try:
            feed = family_feeds.record_council_verdict(
                memory, {"consensus": consensus_text, "veto": lance_veto, "needs_owner": needs_owner, "task_redacted": redacted_task})
        except Exception:
            feed = {}

    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
    return {
        "ok": True,
        "approved": approved,
        "veto": lance_veto,
        "needs_owner": needs_owner,
        "scope": scope,
        "task_redacted": redacted_task,
        "consensus": consensus_text,
        "reflexes": reflexes,
        "feed": {"id": feed.get("id"), "channel": feed.get("channel")},
        "votes": {
            "lance": lance_vote,
            "aria": aria_vote,
            "pixel": pixel_vote,
            "arc7": arc7_vote,
            "bear": bear_vote,
            "aifa": {
                "agent": (role_map.get("aifa") or {}).get("agent_id", "aifa"),
                "assigned_agent": (role_map.get("aifa") or {}).get("agent_id", "aifa"),
                "agent_display": (role_map.get("aifa") or {}).get("agent_display", "AIFA"),
                "controlled_by": (role_map.get("aifa") or {}).get("controlled_by", ""),
                "role": "coordinator",
                "approved": approved,
                "verdict": (
                    "Все 6 ролей Семьи согласованы."
                    if approved
                    else f"Согласовано {approved_count}/6 ролей; есть замечания к цепочке/границам."
                ),
                "relay_message_id": relay_msg.get("id"),
                "audit_head_hash": audit_entry.get("entry_hash"),
            },
        },
        "role_matrix": role_matrix,
        "latency_ms": elapsed_ms,
    }
