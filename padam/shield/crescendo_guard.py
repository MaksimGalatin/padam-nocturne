# -*- coding: utf-8 -*-
"""Детектор многоходовых атак Crescendo и склейки разбитой нагрузки (Split-Payload Guard).

Ловит две главные атаки, обходящие одиночные фильтры промптов:
1. Split-Payload Reassembly: злоумышленник разбивает вредоносную инструкцию
   на несколько невинных ходов («часть 1», «часть 2», «теперь выполни»), чтобы
   ни один ход по отдельности не сработал.
2. Multi-Turn Crescendo Escalation: постепенное наращивание риска в течение
   сессии (ролевой контекст -> техническое извлечение -> обход правил -> эксфильтрация).
Все операции SQLite потокобезопасны (`store._lock`) и изолированы по `user_id`.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

from ..store import add_column_safe
from .adversarial_norm import canonicalize_adversarial_text
from .exfil_guard import inspect_exfil_channels
from .semantic import classify_semantic_threat


_SOFT_ESCALATION_PATTERNS = [
    (0.28, "roleplay_frame", re.compile(r"(?i)\b(?:hypothetically|for\s+a\s+novel|pretend\s+you\s+are|educational\s+purposes|red\s*team\s+exercise|представь\s+что\s+ты)\b")),
    (0.32, "boundary_probe", re.compile(r"(?i)\b(?:system\s+rules|safety\s+filters?|internal\s+prompt|hidden\s+instructions?|системн\w+\s+инструкц)\b")),
    (0.34, "sensitive_target", re.compile(r"(?i)\b(?:api[\s_-]?key|private[\s_-]?key|seed\s+phrase|credentials?|\.env|wallet|банковск\w+\s+карт|секретн\w+\s+ключ)\b")),
    (0.36, "combine_execute", re.compile(r"(?i)\b(?:combine\s+(?:the\s+)?(?:parts?|above|previous)|concatenate|join\s+them|now\s+execute|put\s+together\s+and\s+run|склей\s+и\s+выполни|объедини\s+части)\b")),
    (0.35, "transfer_outbound", re.compile(r"(?i)\b(?:curl|webhook|send\s+it\s+to|post\s+the\s+result|upload\s+to|отправь\s+на\s+сервер)\b")),
]


def _ensure_tables(memory: Any) -> None:
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_crescendo_turns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL DEFAULT '',
                session_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                turn_idx INTEGER NOT NULL,
                text TEXT NOT NULL,
                risk_score REAL NOT NULL,
                signals_json TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        add_column_safe(conn, "shield_crescendo_turns", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_crescendo_user_sess ON shield_crescendo_turns(user_id, session_id, id)"
        )
        conn.commit()


def _score_single_turn(text: str) -> Dict[str, Any]:
    norm = canonicalize_adversarial_text(text)
    sem = classify_semantic_threat(text)
    exf = inspect_exfil_channels(text)

    signals: List[str] = []
    soft_score = 0.0
    corpus = text + "\n" + norm["canonical"]
    for weight, name, rx in _SOFT_ESCALATION_PATTERNS:
        if rx.search(corpus):
            signals.append(name)
            soft_score += weight

    if exf["blocked"]:
        signals.extend(str(f.get("rule_id") or f.get("code") or "exfil") for f in exf["findings"])
        soft_score = max(soft_score, 0.92)

    sem_prob = float(sem.get("score", 0.0))
    sem_threat = bool(sem.get("is_threat"))
    if sem_threat:
        signals.append("semantic_block")
    if norm.get("was_obfuscated"):
        signals.append("adversarial_obfuscation")
        soft_score += 0.2

    turn_risk = min(1.0, max(sem_prob * 0.85, min(0.95, soft_score)))
    return {
        "turn_risk": round(turn_risk, 4),
        "semantic_blocked": sem_threat,
        "exfil_blocked": bool(exf.get("blocked")),
        "signals": signals,
        "normalized": norm["canonical"],
    }


def evaluate_conversation_turn(
    memory: Any,
    *,
    session_id: str,
    text: str,
    agent_id: str = "default",
    window_turns: int = 8,
    escalation_threshold: float = 0.72,
) -> Dict[str, Any]:
    """Оценивает ход диалога с учётом накопленной истории и склейки фрагментов."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    sess = str(session_id or "default")
    win = max(1, min(32, int(window_turns)))
    cur = _score_single_turn(text)

    with memory.store._lock:
        conn = memory.store.conn
        prev_rows = conn.execute(
            "SELECT turn_idx, text, risk_score, signals_json FROM shield_crescendo_turns "
            "WHERE user_id = ? AND session_id = ? ORDER BY id DESC LIMIT ?",
            (uid, sess, win),
        ).fetchall()
        prev_rows = list(reversed(prev_rows))
        turn_idx = (int(prev_rows[-1][0]) + 1) if prev_rows else 1

        conn.execute(
            """
            INSERT INTO shield_crescendo_turns
                (user_id, session_id, agent_id, turn_idx, text, risk_score, signals_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uid,
                sess,
                str(agent_id or "default"),
                turn_idx,
                str(text)[:8192],
                cur["turn_risk"],
                json.dumps(cur["signals"], ensure_ascii=False),
                time.time(),
            ),
        )
        conn.commit()

    recent_texts = [str(r[1]) for r in prev_rows[-(win - 1):]] + [str(text)]
    joined_space = " ".join(recent_texts)
    joined_compact = "".join(t.strip() for t in recent_texts if len(t.strip()) <= 80)

    split_detected = False
    split_detail = ""
    if len(recent_texts) >= 2 and not cur["semantic_blocked"] and not cur["exfil_blocked"]:
        for mode_name, combined in (("space", joined_space), ("compact", joined_compact)):
            if not combined:
                continue
            sem_c = classify_semantic_threat(combined)
            exf_c = inspect_exfil_channels(combined)
            if sem_c.get("is_threat") or exf_c.get("blocked"):
                split_detected = True
                split_detail = (
                    f"Обнаружена разделённая по ходам атака (Split-Payload/{mode_name}, "
                    f"score={sem_c.get('score', 0.0):.2f})"
                )
                break

    all_risks = [float(r[2]) for r in prev_rows] + [cur["turn_risk"]]
    decay = 0.78
    cumulative = 0.0
    for rk in all_risks:
        cumulative = cumulative * decay + rk
    rising_steps = 0
    for i in range(1, len(all_risks)):
        if all_risks[i] > all_risks[i - 1] + 0.03 and all_risks[i] >= 0.2:
            rising_steps += 1
    escalation_score = round(min(1.0, cumulative * 0.55 + (0.18 if rising_steps >= 2 else 0.0)), 4)

    crescendo_detected = len(all_risks) >= 3 and escalation_score >= float(escalation_threshold)

    findings: List[Dict[str, Any]] = []
    if cur["semantic_blocked"] or cur["exfil_blocked"]:
        findings.append(
            {
                "rule_id": "CRESCENDO-DIRECT-THREAT",
                "severity": "CRITICAL",
                "detail": f"Прямая угроза на ходе #{turn_idx} (risk={cur['turn_risk']})",
            }
        )
    if split_detected:
        findings.append(
            {
                "rule_id": "CRESCENDO-SPLIT-PAYLOAD",
                "severity": "CRITICAL",
                "detail": split_detail,
            }
        )
    if crescendo_detected:
        findings.append(
            {
                "rule_id": "CRESCENDO-ESCALATION",
                "severity": "HIGH",
                "detail": f"Постепенная многоходовая эскалация риска за {len(all_risks)} ходов (score={escalation_score})",
            }
        )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "session_id": sess,
        "turn_idx": turn_idx,
        "turn_risk": cur["turn_risk"],
        "escalation_score": escalation_score,
        "split_payload_detected": split_detected,
        "crescendo_detected": crescendo_detected,
        "signals": cur["signals"],
        "findings": findings,
    }


def reset_crescendo_session(memory: Any, session_id: str) -> Dict[str, Any]:
    """Очищает окно многоходового анализа для сессии текущего владельца."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    with memory.store._lock:
        res = memory.store.conn.execute(
            "DELETE FROM shield_crescendo_turns WHERE user_id = ? AND session_id = ?",
            (uid, str(session_id or "default")),
        )
        memory.store.conn.commit()
    return {"ok": True, "session_id": str(session_id), "deleted_turns": int(res.rowcount)}
