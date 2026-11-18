# -*- coding: utf-8 -*-
"""Подписанный журнал передачи эстафеты между сессиями (Signed Session Handover, пункт 10).

Собирает проверяемый срез состояния памяти (последний чекпоинт, открытые обещания,
входящие эстафеты Family Relay, уроки, статус цепочки аудита), вычисляет канонический
SHA-256 отпечаток и подписывает его ключом владельца (HMAC-SHA256).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import ark, audit_chain, integrity, safety

_SIG_RE = re.compile(r"<!--\s*PADAM-HANDOVER-SIG-V1:\s*(\{.*?\})\s*-->", re.DOTALL)


def build_signed_handover(
    memory,
    *,
    notes: str = "",
    agent: str = "aifa",
    out_path: str | Path | None = None,
) -> dict[str, Any]:
    """Формирует и криптографически подписывает документ передачи контекста."""
    clean_notes, _ = safety.redact(notes)
    chk = ark.latest_checkpoint(memory)
    commitments = ark.list_commitments(memory, status="open", limit=15)
    inbox = ark.read_family_inbox(memory, to_agent=agent, limit=10)
    lessons = ark.list_lessons(memory, limit=10)
    chain = audit_chain.verify_audit_chain(memory)
    created_at = datetime.now(timezone.utc).isoformat()

    body_lines = [
        f"# ПЕРЕДАЧА КОНТЕКСТА ({created_at[:10]})",
        f"- **Агент:** `{agent}`",
        f"- **Цепочка аудита:** `ok={chain.get('ok')}` (длина: {chain.get('length', 0)})",
        f"- **Открытых обещаний:** {len(commitments)}",
        f"- **Уроков (`ark_lesson`):** {len(lessons)}",
    ]
    if chk:
        body_lines.append(f"- **Последний чекпоинт:** `{chk.get('task')}` -> `{chk.get('next_step')}`")
    if commitments:
        body_lines.append("## Активные обещания")
        for c in commitments:
            body_lines.append(f"- [{c.get('status')}] {c.get('title')}")
    if inbox:
        body_lines.append("## Непрочитанная эстафета Семьи")
        for m in inbox:
            if m.get("verified"):
                body_lines.append(f"- От `{m.get('from_agent')}`: {m.get('payload')}")
    if clean_notes.strip():
        body_lines.append("## Заметки сессии")
        body_lines.append(clean_notes.strip())

    body_text = "\n".join(body_lines) + "\n"
    body_sha256 = hashlib.sha256(body_text.encode("utf-8")).hexdigest()

    key, _ = integrity.owner_key(memory.store)
    sig_payload = {
        "schema": "padam-handover-v1",
        "created_at": created_at,
        "agent": agent,
        "body_sha256": body_sha256,
        "audit_head_hash": chain.get("head_hash", ""),
    }
    canon = json.dumps(sig_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    sig_hmac = hmac.new(key, canon, hashlib.sha256).hexdigest()
    sig_block = {**sig_payload, "hmac_sha256": sig_hmac}

    full_markdown = body_text + f"\n<!-- PADAM-HANDOVER-SIG-V1: {json.dumps(sig_block, ensure_ascii=False, sort_keys=True)} -->\n"

    saved_to: str | None = None
    if out_path is not None:
        p = Path(out_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(full_markdown, encoding="utf-8")
        saved_to = str(p)

    audit_chain.append_audit(
        memory,
        "signed_handover_created",
        {"body_sha256": body_sha256, "agent": agent},
        agent_id=agent,
    )
    return {
        "ok": True,
        "body_sha256": body_sha256,
        "hmac_sha256": sig_hmac,
        "saved_to": saved_to,
        "markdown": full_markdown,
    }


def verify_signed_handover(
    markdown_text: str,
    *,
    memory=None,
    owner_key: bytes | None = None,
) -> dict[str, Any]:
    """Проверяет SHA-256 тела передачи контекста и HMAC-SHA256 подпись владельца."""
    m = _SIG_RE.search(markdown_text or "")
    if not m:
        return {"valid": False, "reason": "missing_signature_block"}
    try:
        sig_block = json.loads(m.group(1))
    except Exception as exc:
        return {"valid": False, "reason": f"invalid_signature_json: {exc}"}

    body_text = markdown_text[: m.start()].rstrip("\n") + "\n"
    actual_sha = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
    if actual_sha != str(sig_block.get("body_sha256") or ""):
        return {"valid": False, "reason": "body_sha256_mismatch"}

    key = owner_key or (integrity.owner_key(memory.store)[0] if memory is not None else None)
    if key is None:
        return {"valid": False, "reason": "owner_key_required"}

    payload_no_sig = {k: v for k, v in sig_block.items() if k != "hmac_sha256"}
    canon = json.dumps(payload_no_sig, ensure_ascii=False, sort_keys=True).encode("utf-8")
    expected_hmac = hmac.new(key, canon, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hmac, str(sig_block.get("hmac_sha256") or "")):
        return {"valid": False, "reason": "hmac_signature_mismatch"}

    return {
        "valid": True,
        "body_sha256": actual_sha,
        "created_at": sig_block.get("created_at"),
        "agent": sig_block.get("agent"),
    }
