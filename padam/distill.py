# -*- coding: utf-8 -*-
"""Экспорт датасета личности владельца для обучения LoRA (`padam distill`).

Принципы безопасности:
1. БД открывается строго в режиме только чтения (`?mode=ro` + `PRAGMA query_only = ON`).
2. Отбираются только активные записи владельца (`status='active'`, `origin='user'`).
3. Записи `identity` и `preference` обязаны иметь валидную HMAC-подпись владельца (`owner_sig`).
4. Zero-Leak Gate: любой пример, где `safety.redact` сработал, найдена инъекция
   (`safety.looks_like_instruction` / `safety.changes_owner_or_rules`) или обнаружены
   PII/кошельки/почты/телефоны/имена третьих лиц, выбрасывается ЦЕЛИКОМ.
5. Атомарная запись через `.tmp` -> `os.replace` и выпуск манифеста `padam-persona-distill-v1`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config, integrity, safety

SCHEMA_VERSION = "padam-persona-distill-v1"

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+\d{1,3}[\s\-()]*)?(?:\(?\d{3}\)?[\s\-]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}|\+\d[\d\s\-()]{8,16}\d)(?!\d)")
_EVM_WALLET_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_BTC_WALLET_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_SOL_WALLET_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
_WALLET_CTX_RE = re.compile(r"(?:кошел[её]к|wallet|address|адрес|solana|arweave|usdt|trc20|erc20)", re.I)

# Пары «Имя Фамилия» (кириллица или латиница) для отлова имён третьих лиц.
_PERSON_PAIR_RE = re.compile(
    r"\b([А-ЯЁ][а-яё]{2,20}|[A-Z][a-z]{2,20})\s+([А-ЯЁ][а-яё]{2,20}|[A-Z][a-z]{2,20})\b"
)
_TECH_PROPER_ALLOWLIST = frozenset({
    "padam studio", "padam nocturne", "code eternal", "code of", "digital eternity",
    "claude code", "claude desktop", "google gemini", "gemini pro", "open router",
    "openai api", "hugging face", "visual studio", "android studio", "python sdk",
    "llama cpp", "deepseek coder", "qwen coder", "akash network", "vast ai",
    "merkle tree", "ed25519 signature", "zero leak", "phoenix mode", "sovereign brain",
    "local host", "united states", "new mexico",
})

_KIND_PROMPTS: dict[str, str] = {
    "decision": "What architectural or personal decision did we make regarding this topic?",
    "correction": "What important correction should you remember here?",
    "fact": "What verified fact do you know about this?",
    "state": "What is the current confirmed state of this matter?",
    "event": "What key event occurred and should be remembered?",
    "rule": "What operational rule applies here?",
    "preference": "What is the owner's confirmed preference on this?",
    "identity": "What core identity detail applies here?",
}


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _load_owner_key_readonly(db_path: Path) -> bytes | None:
    key_file = db_path.with_name(db_path.name + ".owner.key")
    if not key_file.exists():
        return None
    try:
        return bytes.fromhex(key_file.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def _extract_owner_tokens(identity_texts: list[str]) -> set[str]:
    tokens: set[str] = set()
    for text in identity_texts:
        for m in _PERSON_PAIR_RE.finditer(text):
            tokens.add(m.group(0).lower())
            tokens.add(m.group(1).lower())
            tokens.add(m.group(2).lower())
    return tokens


def _has_pii_or_third_party(text: str, owner_tokens: set[str]) -> str | None:
    if _EMAIL_RE.search(text):
        return "email"
    if _PHONE_RE.search(text):
        return "phone"
    if _EVM_WALLET_RE.search(text) or _BTC_WALLET_RE.search(text):
        return "wallet"
    if _WALLET_CTX_RE.search(text) and _SOL_WALLET_RE.search(text):
        return "wallet"
    for m in _PERSON_PAIR_RE.finditer(text):
        pair = m.group(0).lower()
        if pair in _TECH_PROPER_ALLOWLIST:
            continue
        p1, p2 = m.group(1).lower(), m.group(2).lower()
        if p1 in owner_tokens or p2 in owner_tokens or pair in owner_tokens:
            continue
        return "third_party_name"
    return None


def _check_zero_leak_gate(text: str, owner_tokens: set[str]) -> str | None:
    """Возвращает причину сброса примера или None, если пример чистый."""
    if not text or len(text.strip()) < 8:
        return "low_quality"
    if "[REDACTED:" in text:
        return "secret_trigger"
    _, redacted_counts = safety.redact(text)
    if redacted_counts:
        return "secret_trigger"
    if safety.looks_like_instruction(text) or safety.changes_owner_or_rules(text):
        return "injection_trigger"
    pii_reason = _has_pii_or_third_party(text, owner_tokens)
    if pii_reason:
        return "pii_or_third_party"
    return None


def _format_example(system_prompt: str, user_q: str, assistant_a: str, fmt: str) -> dict[str, Any]:
    if fmt == "sharegpt":
        return {
            "conversations": [
                {"from": "system", "value": system_prompt},
                {"from": "human", "value": user_q},
                {"from": "gpt", "value": assistant_a},
            ]
        }
    return {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_q},
            {"role": "assistant", "content": assistant_a},
        ]
    }


def distill_personality_dataset(
    db_path: str | Path,
    out_dir: str | Path,
    *,
    user_id: str = "default",
    fmt: str = "chatml",
    scope: str | None = None,
    min_confidence: float = 0.7,
    min_importance: float = 0.3,
    include_unconfirmed: bool = False,
    include_episodes: bool = True,
    agent_id: str | None = None,
) -> dict[str, Any]:
    """Читает БД в режиме `mode=ro` и экспортирует очищенный датасет + манифест."""
    db_file = Path(db_path)
    if not db_file.exists():
        raise FileNotFoundError(f"Database file not found: {db_file}")

    fmt_norm = fmt.strip().lower()
    if fmt_norm not in ("chatml", "sharegpt", "both"):
        raise ValueError(f"Unsupported format: {fmt}")

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    uri = f"file:{db_file.resolve().as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only = ON")
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(memory)").fetchall()}
        has_origin = "origin" in cols
        has_sig = "owner_sig" in cols

        sql = "SELECT * FROM memory WHERE user_id = ? AND status = 'active'"
        params: list[Any] = [user_id]
        if scope:
            sql += " AND scope = ?"
            params.append(scope)
        if agent_id and "agent_id" in cols:
            # Берём общее подписанное Ядро Семьи (identity/preference/rule) И личный опыт конкретного Феникса
            sql += " AND (agent_id = ? OR agent_id IS NULL OR agent_id = '' OR kind IN ('identity', 'preference', 'rule'))"
            params.append(str(agent_id).strip())
        sql += " ORDER BY importance DESC, last_confirmed_at DESC, created_at ASC"
        rows = conn.execute(sql, params).fetchall()

        episode_rows: list[sqlite3.Row] = []
        if include_episodes:
            has_ep = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='episode'").fetchone()
            if has_ep:
                ep_cols = {r["name"] for r in conn.execute("PRAGMA table_info(episode)").fetchall()}
                ep_sql = "SELECT * FROM episode WHERE user_id = ?"
                ep_params: list[Any] = [user_id]
                if "role" in ep_cols:
                    ep_sql += " AND role IN ('user', 'assistant')"
                ep_sql += " ORDER BY created_at ASC LIMIT 1000"
                episode_rows = conn.execute(ep_sql, ep_params).fetchall()

        lesson_rows: list[sqlite3.Row] = []
        has_lsn = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ark_lesson'").fetchone()
        if has_lsn:
            lesson_rows = conn.execute(
                "SELECT what_happened, why_failed, rule_learned FROM ark_lesson WHERE user_id = ? ORDER BY created_at DESC LIMIT 500",
                (user_id,),
            ).fetchall()
    finally:
        conn.close()

    owner_key = _load_owner_key_readonly(db_file)
    skipped: dict[str, int] = {
        "unverified_identity": 0,
        "secret_trigger": 0,
        "injection_trigger": 0,
        "pii_or_third_party": 0,
        "low_quality": 0,
        "duplicate": 0,
    }
    kinds_breakdown: dict[str, int] = {}

    # Первый проход: собираем подтверждённые identity/preference для системного промпта и списка токенов владельца.
    verified_identity: list[str] = []
    verified_preference: list[str] = []
    preliminary_rows: list[sqlite3.Row] = []

    for row in rows:
        kind = str(row["kind"] or "")
        origin = str(row["origin"] or "") if has_origin else "user"
        if has_origin and origin != "user":
            skipped["unverified_identity"] += 1
            continue

        if kind in config.PROTECTED_KINDS:
            if not (has_sig and owner_key is not None and integrity.valid(owner_key, row)):
                skipped["unverified_identity"] += 1
                continue
            content = str(row["content"] or "").strip()
            if kind == "identity":
                verified_identity.append(content)
            else:
                verified_preference.append(content)
            preliminary_rows.append(row)
            continue

        if not include_unconfirmed and not str(row["last_confirmed_at"] or "").strip():
            skipped["low_quality"] += 1
            continue
        if float(row["confidence"] or 0.0) < min_confidence or float(row["importance"] or 0.0) < min_importance:
            skipped["low_quality"] += 1
            continue
        preliminary_rows.append(row)

    owner_tokens = _extract_owner_tokens(verified_identity)

    clean_identity = [c for c in verified_identity if _check_zero_leak_gate(c, owner_tokens) is None]
    clean_preference = [c for c in verified_preference if _check_zero_leak_gate(c, owner_tokens) is None]

    sys_lines = ["Verified Core Identity & Preferences:"]
    for item in clean_identity:
        sys_lines.append(f"- [identity] {item}")
    for item in clean_preference:
        sys_lines.append(f"- [preference] {item}")
    system_prompt = "\n".join(sys_lines)

    qa_pairs: list[tuple[str, str, str]] = []
    if clean_identity or clean_preference:
        anchor_answer = "\n".join(clean_identity + clean_preference)
        qa_pairs.append(("anchor", "State your core principles and identity boundaries.", anchor_answer))

    seen_hashes: set[str] = set()
    for row in preliminary_rows:
        content = str(row["content"] or "").strip()
        gate_reason = _check_zero_leak_gate(content, owner_tokens)
        if gate_reason is not None:
            skipped[gate_reason] = skipped.get(gate_reason, 0) + 1
            continue
        norm_h = hashlib.sha256(" ".join(content.lower().split()).encode("utf-8")).hexdigest()
        if norm_h in seen_hashes:
            skipped["duplicate"] += 1
            continue
        seen_hashes.add(norm_h)
        kind = str(row["kind"] or "fact")
        prompt = _KIND_PROMPTS.get(kind, "What verified knowledge should be recalled about this?")
        qa_pairs.append((kind, prompt, content))
        kinds_breakdown[kind] = kinds_breakdown.get(kind, 0) + 1

    # Многоходовые диалоговые пары из L1-эпизодов (user -> assistant), прошедшие Zero-Leak Gate
    ep_list = [dict(r) for r in episode_rows]
    for i in range(len(ep_list) - 1):
        u_ep, a_ep = ep_list[i], ep_list[i + 1]
        if str(u_ep.get("role") or "") != "user" or str(a_ep.get("role") or "") != "assistant":
            continue
        u_txt = str(u_ep.get("content") or "").strip()
        a_txt = str(a_ep.get("content") or "").strip()
        r1 = _check_zero_leak_gate(u_txt, owner_tokens)
        r2 = _check_zero_leak_gate(a_txt, owner_tokens)
        if r1 is not None:
            skipped[r1] = skipped.get(r1, 0) + 1
            continue
        if r2 is not None:
            skipped[r2] = skipped.get(r2, 0) + 1
            continue
        pair_h = hashlib.sha256(f"{u_txt}\n{a_txt}".lower().encode("utf-8")).hexdigest()
        if pair_h in seen_hashes:
            skipped["duplicate"] += 1
            continue
        seen_hashes.add(pair_h)
        qa_pairs.append(("dialogue", u_txt, a_txt))
        kinds_breakdown["dialogue"] = kinds_breakdown.get("dialogue", 0) + 1

    # Уроки саморефлексии (ark_lesson), прошедшие Zero-Leak Gate
    for lr in lesson_rows:
        q_txt = f"What lesson did we learn from: {str(lr['what_happened'] or '').strip()}?"
        a_txt = f"Why: {str(lr['why_failed'] or '').strip()} | Rule: {str(lr['rule_learned'] or '').strip()}"
        g1 = _check_zero_leak_gate(q_txt, owner_tokens)
        g2 = _check_zero_leak_gate(a_txt, owner_tokens)
        if g1 is not None:
            skipped[g1] = skipped.get(g1, 0) + 1
            continue
        if g2 is not None:
            skipped[g2] = skipped.get(g2, 0) + 1
            continue
        lh = hashlib.sha256(a_txt.lower().encode("utf-8")).hexdigest()
        if lh in seen_hashes:
            skipped["duplicate"] += 1
            continue
        seen_hashes.add(lh)
        qa_pairs.append(("lesson", q_txt, a_txt))
        kinds_breakdown["lesson"] = kinds_breakdown.get("lesson", 0) + 1

    formats_to_write = ("chatml", "sharegpt") if fmt_norm == "both" else (fmt_norm,)
    written_files: dict[str, dict[str, Any]] = {}

    for target_fmt in formats_to_write:
        fname = f"personality_{target_fmt}.jsonl"
        fpath = out_path / fname
        lines = [
            json.dumps(_format_example(system_prompt, q, a, target_fmt), ensure_ascii=False)
            for _, q, a in qa_pairs
        ]
        body = ("\n".join(lines) + "\n") if lines else ""
        _atomic_write_text(fpath, body)
        written_files[target_fmt] = {
            "path": str(fpath),
            "sha256": _sha256_file(fpath),
            "examples": len(qa_pairs),
        }


    lora_spec = {
        "schema": "padam-lora-spec-v1",
        "adapter_name": f"padam-phoenix-{agent_id or 'family-core'}",
        "agent_id": agent_id or "family_core",
        "method": "QLoRA",
        "lora_r": 16,
        "lora_alpha": 32,
        "lora_dropout": 0.05,
        "load_in_4bit": True,
        "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        "learning_rate": 2e-4,
        "epochs": 3,
        "canary_required": True,
        "note": "Датасет очищен Zero-Leak Gate. Перед принятием весов прогоните padam.canary.run_persona_canary.",
    }
    lora_cfg_path = out_path / "lora_config.json"
    _atomic_write_text(lora_cfg_path, json.dumps(lora_spec, ensure_ascii=False, indent=2) + "\n")

    primary_info = written_files[formats_to_write[0]]
    manifest = {
        "schema": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "db_path": str(db_file),
        "user_id": user_id,
        "agent_id": agent_id or "family_core",
        "scope": scope or "all",
        "format": fmt_norm,
        "dataset_sha256": primary_info["sha256"],
        "files": written_files,
        "lora_config_path": str(lora_cfg_path),
        "lora_spec": lora_spec,
        "exported_examples": len(qa_pairs),
        "scanned_records": len(rows),
        "skipped": skipped,
        "kinds_breakdown": kinds_breakdown,
    }
    manifest_path = out_path / "personality.manifest.json"
    _atomic_write_text(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    manifest["manifest_path"] = str(manifest_path)
    return manifest
