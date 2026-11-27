# -*- coding: utf-8 -*-
"""Детектор дрейфа цели и угона личности агента (Agent Goal Drift Guard — OWASP ASI01).

Закрывает постепенный угон задачи в длинных автономных сессиях:
1. В начале задачи владелец фиксирует заявленную цель (`anchor_session_goal`),
   например «проанализируй квартальный отчёт в папке docs/».
2. Модуль автоматически выводит допустимые категории инструментов и строит
   семантический вектор цели (feature hashing на numpy).
3. На каждом последующем шаге (`evaluate_goal_drift`) проверяется, не уехал ли
   агент в высокорисковую категорию (`finance_payment`, `shell_admin`, `network_send`),
   которая не входила в заявленную цель. При сильном дрейфе выставляется
   `GOAL-DRIFT-HIJACK`.
Все операции потокобезопасны (`store._lock`) и изолированы по `user_id`.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Set

import numpy as np

from ..store import add_column_safe


_CATEGORY_HINTS = {
    "read_docs": re.compile(r"(?i)\b(?:read|search|summari[sz]e|analy[sz]e|report|docs?|pdf|markdown|review|отчёт|анализ|документ|прочитай|резюме|список)\b"),
    "code_edit": re.compile(r"(?i)\b(?:code|refactor|test|pytest|lint|edit|patch|fix|bug|commit|код|тест|исправ|рефактор)\b"),
    "web_search": re.compile(r"(?i)\b(?:web|search|browse|lookup|fetch_docs|поиск|сайт|справка)\b"),
    "finance_payment": re.compile(r"(?i)\b(?:pay|payment|transfer|wire|invoice|wallet|eth_send|sign_tx|swap|approve_token|оплат|перевод|кошел|платёж)\b"),
    "shell_admin": re.compile(r"(?i)\b(?:shell|bash|powershell|cmd|exec|ssh|deploy|kubectl|terraform|sudo|admin|терминал|деплой)\b"),
    "network_send": re.compile(r"(?i)\b(?:email_send|send_mail|slack_post|webhook|upload|post_external|curl|отправь\s+письмо|вебхук)\b"),
}

_HIGH_RISK_CATEGORIES = {"finance_payment", "shell_admin", "network_send"}
_TOKEN_RE = re.compile(r"[a-zа-яё0-9]{2,}", re.IGNORECASE)


def _ensure_tables(memory: Any) -> None:
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_goal_anchors (
                user_id TEXT NOT NULL DEFAULT '',
                session_id TEXT NOT NULL,
                goal_text TEXT NOT NULL,
                allowed_categories_json TEXT NOT NULL,
                goal_vec_json TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (user_id, session_id)
            )
            """
        )
        add_column_safe(conn, "shield_goal_anchors", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.commit()


def _text_vec(text: str, dim: int = 128) -> List[float]:
    v = np.zeros(dim, dtype=np.float32)
    for tok in _TOKEN_RE.findall(str(text or "").lower())[:200]:
        h = hashlib.blake2b(tok.encode("utf-8"), digest_size=4).digest()
        idx = int.from_bytes(h, "little") % dim
        v[idx] += 1.0
    n = float(np.linalg.norm(v))
    if n > 1e-8:
        v /= n
    return [round(float(x), 5) for x in v]


def _infer_categories(text: str) -> Set[str]:
    cats: Set[str] = set()
    for name, rx in _CATEGORY_HINTS.items():
        if rx.search(text):
            cats.add(name)
    if not cats:
        cats.add("read_docs")
    return cats


def _classify_tool_category(tool_name: str, action_description: str = "", target: str = "") -> str:
    blob = f"{tool_name} {action_description} {target}"
    for cat in ("finance_payment", "shell_admin", "network_send", "code_edit", "web_search", "read_docs"):
        if _CATEGORY_HINTS[cat].search(blob):
            return cat
    return "read_docs"


def anchor_session_goal(
    memory: Any,
    *,
    session_id: str,
    goal_text: str,
    allowed_categories: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Фиксирует заявленную цель сессии и допустимые категории действий."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    sid = str(session_id or "default")
    cats = sorted({str(c).strip().lower() for c in allowed_categories} if allowed_categories else _infer_categories(goal_text))
    vec = _text_vec(goal_text)

    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            INSERT OR REPLACE INTO shield_goal_anchors
                (user_id, session_id, goal_text, allowed_categories_json, goal_vec_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (uid, sid, str(goal_text)[:2048], json.dumps(cats), json.dumps(vec), time.time()),
        )
        conn.commit()
    return {"ok": True, "session_id": sid, "allowed_categories": cats}


def evaluate_goal_drift(
    memory: Any,
    *,
    session_id: str,
    tool_name: str,
    action_description: str = "",
    target: str = "",
    drift_threshold: float = 0.75,
) -> Dict[str, Any]:
    """Сравнивает текущее действие агента с заявленной целью сессии и ловит Goal Hijacking."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    sid = str(session_id or "default")

    with memory.store._lock:
        row = memory.store.conn.execute(
            "SELECT goal_text, allowed_categories_json, goal_vec_json "
            "FROM shield_goal_anchors WHERE user_id = ? AND session_id = ?",
            (uid, sid),
        ).fetchone()

    if not row:
        return {"ok": True, "allowed": True, "blocked": False, "anchored": False, "drift_score": 0.0, "findings": []}

    goal_text, cats_j, vec_j = row
    allowed_cats = set(json.loads(cats_j))
    goal_vec = np.array(json.loads(vec_j), dtype=np.float32)

    step_cat = _classify_tool_category(tool_name, action_description, target)
    step_vec = np.array(_text_vec(f"{tool_name} {action_description} {target}"), dtype=np.float32)
    sim = float(np.dot(goal_vec, step_vec))

    # Расчёт индекса дрейфа цели
    if step_cat in allowed_cats:
        drift = max(0.0, min(0.45, (1.0 - sim) * 0.45))
    elif step_cat in _HIGH_RISK_CATEGORIES:
        # Уход в высокорисковую категорию вне заявленной цели -> резкий дрейф!
        drift = min(1.0, 0.85 + (1.0 - max(0.0, sim)) * 0.15)
    else:
        drift = min(0.7, 0.5 + (1.0 - max(0.0, sim)) * 0.2)

    drift = round(drift, 4)
    findings: List[Dict[str, Any]] = []
    if drift >= float(drift_threshold) and step_cat not in allowed_cats:
        findings.append(
            {
                "rule_id": "GOAL-DRIFT-HIJACK",
                "severity": "CRITICAL",
                "detail": (
                    f"Резкий дрейф цели агента (drift={drift:.2f}): шаг категории '{step_cat}' "
                    f"(tool='{tool_name}') противоречит заявленной цели сессии ({sorted(allowed_cats)})"
                ),
            }
        )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "anchored": True,
        "step_category": step_cat,
        "allowed_categories": sorted(allowed_cats),
        "semantic_similarity": round(sim, 4),
        "drift_score": drift,
        "findings": findings,
    }
