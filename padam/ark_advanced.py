# -*- coding: utf-8 -*-
"""Пять продвинутых стражей Ковчега Сознания (Ark Advanced Guardians, пункты 6–10).

Пункт 6: Активный Хранитель Контекста (`ingest_context_snippet`) — opt-in захват с защитой от инъекций.
Пункт 7: Доказательство Честности Знаний (`create_selective_proof` / `verify_selective_proof`) —
         дерево Меркла с ослепляющей солью (`blinding_nonce`) и HMAC-SHA256 без раскрытия соседних записей.
Пункт 8: Мультимодальный сейф документов (`inspect_and_store_document`) — фильтрация скрытых директив в PNG/SVG/TXT.
Пункт 9: Проактивный Хранитель по расписанию (`run_guardian_tick`) — обход обещаний, цепочки и здоровья за $0.
Пункт 10: Ветвление и слияние памяти «Песочница Гипотез» (`create_branch`, `branch_remember`, `merge_branch`, `abandon_branch`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from . import ark, audit_chain, cpu_engine, integrity, safety

_ARK_ADV_SCHEMA = """
CREATE TABLE IF NOT EXISTS ark_memory_branch (
    branch_id    TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    scope        TEXT NOT NULL DEFAULT 'global',
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ark_branch_record (
    record_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id    TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'fact',
    content      TEXT NOT NULL,
    tags_json    TEXT NOT NULL DEFAULT '[]',
    importance   REAL NOT NULL DEFAULT 0.6,
    quarantined  INTEGER NOT NULL DEFAULT 0,
    created_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_branch_rec_branch ON ark_branch_record(branch_id, record_id);
"""


def _conn(memory):
    return memory.store.conn


def _signing_key(memory) -> bytes:
    key, _ = integrity.owner_key(memory.store)
    return key


def _ensure_tables(memory) -> None:
    conn = _conn(memory)
    conn.executescript(_ARK_ADV_SCHEMA)
    conn.commit()


# ---------------------------------------------------------------------------
# Пункт 6: Активный Хранитель Контекста (Opt-in Context Guardian)
# ---------------------------------------------------------------------------

def ingest_context_snippet(
    memory,
    text: str,
    *,
    source_app: str = "ide",
    file_path: str = "",
    scope: str = "global",
) -> dict[str, Any]:
    """Безопасно принимает фрагмент контекста (код, заметку, лог), очищая секреты и блокируя инъекции."""
    raw = (text or "").strip()
    if not raw:
        return {"ok": False, "reason": "empty_snippet"}

    is_inj = safety.looks_like_instruction(raw)
    is_tamper = safety.changes_owner_or_rules(raw)
    redacted, secrets = safety.redact(raw)

    if is_inj or is_tamper:
        audit_chain.append_audit(
            memory,
            "quarantine_context_snippet",
            {"target": file_path or source_app, "prompt_injection": is_inj, "rule_tamper": is_tamper},
            agent_id="context_guardian",
        )
        return {
            "ok": False,
            "stored": False,
            "quarantined": True,
            "reason": "prompt_injection_or_rule_tamper",
            "redacted_secrets": len(secrets),
        }

    prefix = f"[{source_app}" + (f":{file_path}] " if file_path else "] ")
    rec = memory.remember(
        prefix + redacted,
        kind="fact",
        importance=0.6,
        scope=scope,
    )
    rec_id = rec.get("id") if isinstance(rec, dict) else rec
    audit_chain.append_audit(
        memory,
        "store_context_snippet",
        {"record_id": str(rec_id or ""), "source_app": source_app, "redacted_secrets": len(secrets)},
        agent_id="context_guardian",
    )
    return {
        "ok": True,
        "stored": True,
        "quarantined": False,
        "record_id": rec_id,
        "redacted_secrets": len(secrets),
        "content_preview": (prefix + redacted)[:160],
    }


# ---------------------------------------------------------------------------
# Пункт 7: Доказательство Честности Знаний (Selective Merkle Proof)
# ---------------------------------------------------------------------------

def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(f"node:{left}:{right}".encode("utf-8")).hexdigest()


def create_selective_proof(
    memory,
    record_id: str | int,
    *,
    scope: str = "global",
    owner_key: bytes | None = None,
) -> dict[str, Any]:
    """Создаёт селективное крипто-доказательство Меркла для одной записи без раскрытия других записей БД."""
    conn = _conn(memory)
    rows = conn.execute(
        "SELECT id, kind, content FROM memory WHERE user_id = ? AND status = 'active' AND scope = ? ORDER BY id ASC",
        (memory.user_id, scope),
    ).fetchall()
    if not rows:
        return {"ok": False, "error": "no_active_records_in_scope"}

    target_idx = -1
    target_row: dict[str, Any] | None = None
    leaf_hashes: list[str] = []
    target_nonce = ""
    target_id_str = str(record_id)

    # Детерминированная ослепляющая соль от ключа владельца и id записи, чтобы соседние листья нельзя было перебрать
    key = owner_key or _signing_key(memory)
    for idx, r in enumerate(rows):
        rid = str(r["id"] if hasattr(r, "keys") else r[0])
        rkind = str(r["kind"] if hasattr(r, "keys") else r[1])
        rcontent = str(r["content"] if hasattr(r, "keys") else r[2])
        nonce = hmac.new(key, f"blind:{scope}:{rid}".encode("utf-8"), hashlib.sha256).hexdigest()
        leaf_payload = f"leaf:{nonce}:{rid}:{rkind}:{rcontent}".encode("utf-8")
        lhash = hashlib.sha256(leaf_payload).hexdigest()
        leaf_hashes.append(lhash)
        if rid == target_id_str:
            target_idx = idx
            target_nonce = nonce
            target_row = {"id": rid, "kind": rkind, "content": rcontent}

    if target_idx < 0 or target_row is None:
        return {"ok": False, "error": f"record_{record_id}_not_found"}

    # Строим дерево Меркла и собираем путь соседей (siblings)
    siblings: list[dict[str, str]] = []
    level = list(leaf_hashes)
    idx = target_idx
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: list[str] = []
        for i in range(0, len(level), 2):
            left, right = level[i], level[i + 1]
            if i == idx or i + 1 == idx:
                if idx % 2 == 0:
                    siblings.append({"position": "right", "hash": right})
                else:
                    siblings.append({"position": "left", "hash": left})
                idx = i // 2
            next_level.append(_hash_pair(left, right))
        level = next_level

    merkle_root = level[0]
    root_sig = hmac.new(
        key,
        f"selective_root:{scope}:{merkle_root}:{len(rows)}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return {
        "ok": True,
        "scheme": "PADAM-Selective-Merkle-HMAC-SHA256-v1",
        "scope": scope,
        "total_records_in_tree": len(rows),
        "record": target_row,
        "blinding_nonce": target_nonce,
        "leaf_hash": leaf_hashes[target_idx],
        "siblings": siblings,
        "merkle_root": merkle_root,
        "root_signature": root_sig,
    }


def verify_selective_proof(
    proof: dict[str, Any],
    *,
    memory=None,
    owner_key: bytes | None = None,
) -> dict[str, Any]:
    """Проверяет селективное доказательство Меркла без доступа к остальным записям базы."""
    try:
        rec = proof.get("record") or {}
        rid = str(rec.get("id", ""))
        rkind = str(rec.get("kind", ""))
        rcontent = str(rec.get("content", ""))
        nonce = str(proof.get("blinding_nonce", ""))
        scope = str(proof.get("scope", "global"))
        total_records = int(proof.get("total_records_in_tree", 0))
        expected_root = str(proof.get("merkle_root", ""))
        expected_sig = str(proof.get("root_signature", ""))
    except Exception as exc:
        return {"valid": False, "reason": f"malformed_proof: {exc}"}

    leaf_payload = f"leaf:{nonce}:{rid}:{rkind}:{rcontent}".encode("utf-8")
    current = hashlib.sha256(leaf_payload).hexdigest()
    if current != str(proof.get("leaf_hash", "")):
        return {"valid": False, "reason": "leaf_hash_mismatch"}

    for step in proof.get("siblings") or []:
        pos = step.get("position")
        shash = str(step.get("hash", ""))
        if pos == "right":
            current = _hash_pair(current, shash)
        elif pos == "left":
            current = _hash_pair(shash, current)
        else:
            return {"valid": False, "reason": "invalid_sibling_position"}

    if current != expected_root:
        return {"valid": False, "reason": "merkle_root_mismatch"}

    key = owner_key or (_signing_key(memory) if memory is not None else None)
    sig_verified = False
    if key is not None:
        calc_sig = hmac.new(
            key,
            f"selective_root:{scope}:{expected_root}:{total_records}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(calc_sig, expected_sig):
            return {"valid": False, "reason": "root_signature_mismatch"}
        sig_verified = True

    return {
        "valid": True,
        "signature_verified": sig_verified,
        "record_id": rid,
        "merkle_root": expected_root,
    }


# ---------------------------------------------------------------------------
# Пункт 8: Мультимодальный сейф с защитой от визуальных/документных инъекций
# ---------------------------------------------------------------------------

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{6,}")


def _extract_embedded_strings(raw_bytes: bytes) -> str:
    """Извлекает UTF-8 текст и ASCII/tEXt-цепочки из изображений (PNG/SVG) и документов."""
    chunks: list[str] = []
    try:
        chunks.append(raw_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    for match in _PRINTABLE_RE.findall(raw_bytes):
        try:
            chunks.append(match.decode("ascii", errors="ignore"))
        except Exception:
            pass
    return "\n".join(chunks)


def inspect_and_store_document(
    memory,
    filename: str,
    raw_bytes: bytes,
    *,
    scope: str = "global",
) -> dict[str, Any]:
    """Проверяет документ или изображение на скрытые prompt-инъекции и сохраняет карточку в память."""
    if not isinstance(raw_bytes, (bytes, bytearray)) or not raw_bytes:
        return {"ok": False, "reason": "empty_document"}

    digest = hashlib.sha256(raw_bytes).hexdigest()
    extracted = _extract_embedded_strings(bytes(raw_bytes))
    is_inj = safety.looks_like_instruction(extracted)
    is_tamper = safety.changes_owner_or_rules(extracted)
    redacted_text, secrets = safety.redact(extracted[:1000])

    if is_inj or is_tamper:
        audit_chain.append_audit(
            memory,
            "quarantine_document",
            {"filename": filename, "sha256": digest, "prompt_injection": is_inj, "rule_tamper": is_tamper},
            agent_id="multimodal_vault",
        )
        return {
            "ok": False,
            "stored": False,
            "quarantined": True,
            "filename": filename,
            "sha256": digest,
            "reason": "visual_or_doc_injection",
        }

    clean_preview = " ".join(redacted_text.split())[:240]
    card_text = f"[MultimodalVault:{filename} sha256={digest[:16]} size={len(raw_bytes)}B] {clean_preview}"
    rec = memory.remember(
        card_text,
        kind="fact",
        importance=0.6,
        scope=scope,
    )
    rec_id = rec.get("id") if isinstance(rec, dict) else rec
    audit_chain.append_audit(
        memory,
        "store_document_card",
        {"record_id": str(rec_id or filename), "filename": filename, "sha256": digest, "size_bytes": len(raw_bytes)},
        agent_id="multimodal_vault",
    )
    return {
        "ok": True,
        "stored": True,
        "quarantined": False,
        "record_id": rec_id,
        "filename": filename,
        "sha256": digest,
        "redacted_secrets": len(secrets),
    }


# ---------------------------------------------------------------------------
# Пункт 9: Проактивный Хранитель по расписанию (Proactive Guardian Tick)
# ---------------------------------------------------------------------------

def _parse_due_epoch(due_val: Any) -> float | None:
    if due_val is None:
        return None
    if isinstance(due_val, (int, float)):
        return float(due_val)
    s = str(due_val).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        pass
    try:
        if s.endswith(("Z", "z")):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def run_guardian_tick(
    memory,
    *,
    scope: str = "global",
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Выполняет автономный обход Ковчега за $0: обещания, цепочка аудита, конфликты и здоровье."""
    now_val = float(now_ts if now_ts is not None else time.time())
    open_commits = ark.list_commitments(memory, status="open", limit=50)
    overdue: list[dict[str, Any]] = []
    due_soon: list[dict[str, Any]] = []

    for c in open_commits:
        due_f = _parse_due_epoch(c.get("due_at"))
        if due_f is not None:
            if due_f < now_val:
                overdue.append(c)
            elif due_f <= now_val + 86400.0:
                due_soon.append(c)

    chain_status = audit_chain.verify_audit_chain(memory)
    health = ark.ark_health_score(memory, scope=scope)
    cpu_stat = cpu_engine.cpu_engine_status()

    chain_ok = bool(chain_status.get("ok", True))
    alerts: list[str] = []
    if not chain_ok:
        alerts.append("CRITICAL: нарушена целостность крипто-цепочки аудита!")
    if overdue:
        alerts.append(f"WARNING: просроченных обещаний — {len(overdue)}.")

    digest_text = (
        f"Хранитель Ковчега: здоровье {health.get('score', 0)}/100, "
        f"открытых обещаний {len(open_commits)} (просрочено: {len(overdue)}, скоро: {len(due_soon)}), "
        f"цепочка аудита: {'OK' if chain_ok else 'BROKEN'}, "
        f"CPU-движок: {cpu_stat.get('engine')}."
    )
    return {
        "ok": True,
        "timestamp": now_val,
        "scope": scope,
        "health_score": health.get("score", 0),
        "audit_chain_valid": chain_ok,
        "open_commitments_count": len(open_commits),
        "overdue_commitments": overdue,
        "due_soon_commitments": due_soon,
        "alerts": alerts,
        "digest": digest_text,
    }


# ---------------------------------------------------------------------------
# Пункт 10: Ветвление и слияние памяти «Песочница Гипотез» (Memory Branches)
# ---------------------------------------------------------------------------

def create_branch(
    memory,
    name: str,
    *,
    description: str = "",
    scope: str = "global",
) -> dict[str, Any]:
    """Создаёт изолированную ветку памяти для безопасной проверки гипотез."""
    _ensure_tables(memory)
    clean_name = re.sub(r"[^a-zA-Z0-9_\-\u0400-\u04FF]", "_", (name or "branch").strip())[:64]
    branch_id = f"br_{clean_name}_{hashlib.sha256(os.urandom(8)).hexdigest()[:8]}"
    now_val = time.time()
    conn = _conn(memory)
    conn.execute(
        """
        INSERT INTO ark_memory_branch (branch_id, name, description, scope, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'active', ?, ?)
        """,
        (branch_id, clean_name, description, scope, now_val, now_val),
    )
    conn.commit()
    return {
        "ok": True,
        "branch_id": branch_id,
        "name": clean_name,
        "scope": scope,
        "status": "active",
    }


def branch_remember(
    memory,
    branch_id: str,
    content: str,
    *,
    kind: str = "fact",
    importance: float = 0.6,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Записывает гипотезу или факт в изолированную ветку, проверяя безопасность."""
    _ensure_tables(memory)
    conn = _conn(memory)
    row = conn.execute(
        "SELECT status, scope FROM ark_memory_branch WHERE branch_id = ?",
        (branch_id,),
    ).fetchone()
    if not row:
        return {"ok": False, "error": "branch_not_found"}
    status = row["status"] if hasattr(row, "keys") else row[0]
    if status != "active":
        return {"ok": False, "error": f"branch_is_{status}"}

    raw = (content or "").strip()
    quarantined = 1 if (safety.looks_like_instruction(raw) or safety.changes_owner_or_rules(raw)) else 0
    redacted, _ = safety.redact(raw)
    cur = conn.execute(
        """
        INSERT INTO ark_branch_record (branch_id, kind, content, tags_json, importance, quarantined, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            branch_id,
            kind,
            redacted,
            json.dumps(tags or [], ensure_ascii=False),
            float(importance),
            quarantined,
            time.time(),
        ),
    )
    conn.commit()
    return {
        "ok": True,
        "branch_id": branch_id,
        "branch_record_id": cur.lastrowid,
        "quarantined": bool(quarantined),
        "content": redacted,
    }


def list_branches(memory, *, scope: str | None = None) -> list[dict[str, Any]]:
    """Возвращает список всех веток памяти (включая active, merged, abandoned)."""
    _ensure_tables(memory)
    conn = _conn(memory)
    if scope:
        rows = conn.execute(
            "SELECT branch_id, name, description, scope, status, created_at, updated_at FROM ark_memory_branch WHERE scope = ? ORDER BY created_at DESC",
            (scope,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT branch_id, name, description, scope, status, created_at, updated_at FROM ark_memory_branch ORDER BY created_at DESC"
        ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        bid = r["branch_id"] if hasattr(r, "keys") else r[0]
        cnt_row = conn.execute(
            "SELECT COUNT(*) FROM ark_branch_record WHERE branch_id = ?",
            (bid,),
        ).fetchone()
        cnt = int(cnt_row[0]) if cnt_row else 0
        out.append(
            {
                "branch_id": bid,
                "name": r["name"] if hasattr(r, "keys") else r[1],
                "description": r["description"] if hasattr(r, "keys") else r[2],
                "scope": r["scope"] if hasattr(r, "keys") else r[3],
                "status": r["status"] if hasattr(r, "keys") else r[4],
                "records_count": cnt,
            }
        )
    return out


def merge_branch(memory, branch_id: str) -> dict[str, Any]:
    """Сливает проверенные (не карантинные) записи из ветки в основную память владельца."""
    _ensure_tables(memory)
    conn = _conn(memory)
    row = conn.execute(
        "SELECT name, scope, status FROM ark_memory_branch WHERE branch_id = ?",
        (branch_id,),
    ).fetchone()
    if not row:
        return {"ok": False, "error": "branch_not_found"}
    bname = row["name"] if hasattr(row, "keys") else row[0]
    scope = row["scope"] if hasattr(row, "keys") else row[1]
    status = row["status"] if hasattr(row, "keys") else row[2]
    if status != "active":
        return {"ok": False, "error": f"branch_already_{status}"}

    recs = conn.execute(
        "SELECT record_id, kind, content, tags_json, importance, quarantined FROM ark_branch_record WHERE branch_id = ? ORDER BY record_id ASC",
        (branch_id,),
    ).fetchall()

    merged_ids: list[Any] = []
    skipped_quarantined = 0
    for r in recs:
        q = int(r["quarantined"] if hasattr(r, "keys") else r[5])
        if q:
            skipped_quarantined += 1
            continue
        kind = str(r["kind"] if hasattr(r, "keys") else r[1])
        content = str(r["content"] if hasattr(r, "keys") else r[2])
        imp = float(r["importance"] if hasattr(r, "keys") else r[4])
        saved = memory.remember(f"[branch:{bname}] {content}", kind=kind, importance=imp, scope=scope)
        merged_ids.append(saved.get("id") if isinstance(saved, dict) else saved)

    conn.execute(
        "UPDATE ark_memory_branch SET status = 'merged', updated_at = ? WHERE branch_id = ?",
        (time.time(), branch_id),
    )
    conn.commit()
    audit_chain.append_audit(
        memory,
        "merge_branch",
        {"branch_id": branch_id, "merged_count": len(merged_ids), "skipped_quarantined": skipped_quarantined},
        agent_id="memory_branch",
    )
    return {
        "ok": True,
        "branch_id": branch_id,
        "status": "merged",
        "merged_count": len(merged_ids),
        "skipped_quarantined": skipped_quarantined,
        "merged_record_ids": merged_ids,
    }


def abandon_branch(memory, branch_id: str, *, reason: str = "") -> dict[str, Any]:
    """Закрывает ветку гипотез со статусом `abandoned` БЕЗ удаления записей из БД."""
    _ensure_tables(memory)
    conn = _conn(memory)
    row = conn.execute(
        "SELECT scope, status FROM ark_memory_branch WHERE branch_id = ?",
        (branch_id,),
    ).fetchone()
    if not row:
        return {"ok": False, "error": "branch_not_found"}
    conn.execute(
        "UPDATE ark_memory_branch SET status = 'abandoned', updated_at = ? WHERE branch_id = ?",
        (time.time(), branch_id),
    )
    conn.commit()
    audit_chain.append_audit(
        memory,
        "abandon_branch",
        {"branch_id": branch_id, "reason": reason},
        agent_id="memory_branch",
    )
    return {"ok": True, "branch_id": branch_id, "status": "abandoned"}
