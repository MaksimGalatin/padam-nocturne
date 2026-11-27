# -*- coding: utf-8 -*-
"""Кросс-агентный «Стоп-кран» и сдерживание AI-червей (Swarm Circuit-Breaker).

Защищает мульти-агентный рой от самораспространяющихся атак (AI Worm / Morris II):
- Фиксирует направленный граф обмена сообщениями между агентами (`record_swarm_interaction`),
- Блокирует любые исходящие сообщения от агента, помещённого в карантин,
- При выявлении заражения агента A (`trigger_swarm_containment`) выполняет BFS-обход
  радиуса поражения (Blast Radius) и автоматически изолирует самого A и его прямых
  получателей в пределах `max_hops`,
- При превышении порога одновременно скомпрометированных агентов (`swarm_trip_threshold`)
  размыкает общий «Стоп-кран роя» (`swarm_circuit_open = True`).
Все операции потокобезопасны (`store._lock`) и изолированы по `user_id`.
"""
from __future__ import annotations

from collections import deque
import time
from typing import Any, Dict, List, Set

from ..store import add_column_safe


def _ensure_tables(memory: Any) -> None:
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_swarm_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL DEFAULT '',
                from_agent TEXT NOT NULL,
                to_agent TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_swarm_quarantine (
                user_id TEXT NOT NULL DEFAULT '',
                agent_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                hop_distance INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                updated_at REAL NOT NULL,
                PRIMARY KEY (user_id, agent_id)
            )
            """
        )
        add_column_safe(conn, "shield_swarm_edges", "user_id", "TEXT NOT NULL DEFAULT ''")
        add_column_safe(conn, "shield_swarm_quarantine", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_swarm_edges_user ON shield_swarm_edges(user_id, from_agent)")
        conn.commit()


def record_swarm_interaction(
    memory: Any,
    *,
    from_agent: str,
    to_agent: str,
) -> Dict[str, Any]:
    """Регистрирует передачу сообщения в рое; блокирует, если отправитель в карантине."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    fa = str(from_agent or "").strip()
    ta = str(to_agent or "").strip()
    if not fa or not ta:
        return {"ok": False, "allowed": False, "blocked": True, "reason": "from_agent и to_agent обязательны"}

    with memory.store._lock:
        conn = memory.store.conn
        qrow = conn.execute(
            "SELECT reason FROM shield_swarm_quarantine WHERE user_id = ? AND agent_id = ? AND active = 1",
            (uid, fa),
        ).fetchone()
        if qrow:
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "SWARM-QUARANTINED-SENDER",
                "reason": f"Агент '{fa}' находится в карантине роя ({qrow[0]}) — распространение заблокировано!",
            }
        conn.execute(
            "INSERT INTO shield_swarm_edges (user_id, from_agent, to_agent, created_at) VALUES (?, ?, ?, ?)",
            (uid, fa, ta, time.time()),
        )
        conn.commit()

    return {"ok": True, "allowed": True, "blocked": False, "from_agent": fa, "to_agent": ta}


def trigger_swarm_containment(
    memory: Any,
    *,
    compromised_agent: str,
    reason: str = "worm_or_injection_detected",
    max_hops: int = 1,
    window_sec: float = 3600.0,
    swarm_trip_threshold: int = 3,
) -> Dict[str, Any]:
    """Вычисляет BFS Blast Radius и автоматически изолирует заражённый узел и его получателей."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    root = str(compromised_agent or "").strip()
    now = time.time()
    cutoff = now - max(60.0, float(window_sec))
    hops_lim = max(0, min(5, int(max_hops)))

    with memory.store._lock:
        conn = memory.store.conn
        rows = conn.execute(
            "SELECT from_agent, to_agent FROM shield_swarm_edges WHERE user_id = ? AND created_at >= ?",
            (uid, cutoff),
        ).fetchall()
        adj: Dict[str, Set[str]] = {}
        for fa, ta in rows:
            adj.setdefault(str(fa), set()).add(str(ta))

        # BFS обход графа распространения червя
        visited: Dict[str, int] = {root: 0}
        dq: deque[tuple[str, int]] = deque([(root, 0)])
        while dq:
            node, dist = dq.popleft()
            if dist >= hops_lim:
                continue
            for nxt in sorted(adj.get(node, ())):
                if nxt not in visited:
                    visited[nxt] = dist + 1
                    dq.append((nxt, dist + 1))

        for ag, dist in visited.items():
            q_reason = reason if dist == 0 else f"blast_radius_hop_{dist}_from_{root}"
            conn.execute(
                """
                INSERT OR REPLACE INTO shield_swarm_quarantine
                    (user_id, agent_id, reason, hop_distance, active, updated_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (uid, ag, q_reason, dist, now),
            )
        conn.commit()

        active_q = conn.execute(
            "SELECT agent_id FROM shield_swarm_quarantine WHERE user_id = ? AND active = 1",
            (uid,),
        ).fetchall()

    quarantined_all = sorted(str(r[0]) for r in active_q)
    circuit_open = len(quarantined_all) >= max(1, int(swarm_trip_threshold))
    return {
        "ok": True,
        "compromised_agent": root,
        "blast_radius_agents": sorted(visited.keys()),
        "blast_radius_count": len(visited),
        "total_quarantined": len(quarantined_all),
        "quarantined_agents": quarantined_all,
        "swarm_circuit_open": circuit_open,
    }


def release_from_quarantine(memory: Any, agent_id: str) -> Dict[str, Any]:
    """Снимает агента с карантина после проверки владельцем."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    with memory.store._lock:
        res = memory.store.conn.execute(
            "UPDATE shield_swarm_quarantine SET active = 0, updated_at = ? WHERE user_id = ? AND agent_id = ?",
            (time.time(), uid, str(agent_id or "")),
        )
        memory.store.conn.commit()
    return {"ok": True, "agent_id": str(agent_id), "released": res.rowcount > 0}


def get_swarm_health(memory: Any) -> Dict[str, Any]:
    """Возвращает текущее состояние роя и список изолированных агентов."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    with memory.store._lock:
        qrows = memory.store.conn.execute(
            "SELECT agent_id, reason, hop_distance, updated_at FROM shield_swarm_quarantine "
            "WHERE user_id = ? AND active = 1 ORDER BY hop_distance ASC, agent_id ASC",
            (uid,),
        ).fetchall()
        edges_cnt = memory.store.conn.execute(
            "SELECT COUNT(*) FROM shield_swarm_edges WHERE user_id = ?",
            (uid,),
        ).fetchone()[0]
    return {
        "ok": True,
        "edges_recorded": int(edges_cnt),
        "quarantined_count": len(qrows),
        "quarantined": [
            {"agent_id": r[0], "reason": r[1], "hop_distance": int(r[2]), "updated_at": r[3]}
            for r in qrows
        ],
    }
