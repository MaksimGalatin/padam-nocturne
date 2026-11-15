"""Локальный Меж-Агентский Синдикат (P2P Swarm Synapse).

Обеспечивает мгновенную синхронизацию контекста и синаптических импульсов
между локальными агентами (IDE, CLI, браузерный агент) поверх общего
локального пула без облака и со строгой песочной изоляцией по project scope.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

from . import mcp_daemon, safety


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_summary(text: str | None, *, quarantined: bool = False) -> str:
    if quarantined:
        return "(quarantined for owner review)"
    raw = safety.strip_invisible(str(text or "")).strip()
    if not raw:
        return ""
    redacted, _ = safety.redact(raw)
    return redacted[:240]


class SwarmSynapseHub:
    """Потокобезопасная локальная шина синаптических событий роя агентов."""

    def __init__(self, max_signals: int = 512) -> None:
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._seq: int = 0
        self._signals: deque[dict[str, Any]] = deque(maxlen=max(32, int(max_signals)))
        self._agents: dict[str, dict[str, Any]] = {}

    def clear(self) -> None:
        with self._lock:
            self._seq = 0
            self._signals.clear()
            self._agents.clear()
            self._cond.notify_all()

    def register_agent(
        self,
        agent_id: str,
        *,
        session_id: str | None = None,
        pinned_scope: str | None = None,
        client_name: str | None = None,
    ) -> dict[str, Any]:
        clean_id = (agent_id or "").strip()[:120]
        if not clean_id:
            clean_id = (session_id or "anonymous-agent").strip()[:120]
        rec = {
            "agent_id": clean_id,
            "session_id": (session_id or "").strip() or None,
            "pinned_scope": (pinned_scope or "").strip() or None,
            "client_name": (client_name or "").strip() or None,
            "last_seen": _utc_now(),
            "last_seen_mono": round(time.monotonic(), 6),
        }
        with self._lock:
            self._agents[clean_id] = rec
            self._cond.notify_all()
            return dict(rec)

    def publish_signal(
        self,
        event_type: str,
        *,
        memory_id: str | None = None,
        kind: str | None = None,
        scope: str | None = None,
        origin: str = "agent",
        agent_id: str | None = None,
        summary: str | None = None,
        outcome: str | None = None,
        quarantined: bool = False,
        owner_only: bool = False,
    ) -> dict[str, Any]:
        clean_scope = (scope or "global").strip() or "global"
        clean_agent = (agent_id or "").strip() or None
        sig_owner_only = bool(owner_only or quarantined)
        safe_summary = _sanitize_summary(summary, quarantined=quarantined)
        with self._lock:
            self._seq += 1
            sig = {
                "seq": self._seq,
                "ts": _utc_now(),
                "event_type": (event_type or "memory_write").strip(),
                "memory_id": memory_id,
                "kind": kind,
                "scope": clean_scope,
                "origin": origin,
                "agent_id": clean_agent,
                "outcome": outcome,
                "quarantined": bool(quarantined),
                "owner_only": sig_owner_only,
                "summary": safe_summary,
            }
            self._signals.append(sig)
            if clean_agent:
                prev = self._agents.get(clean_agent, {})
                self._agents[clean_agent] = {
                    "agent_id": clean_agent,
                    "session_id": prev.get("session_id"),
                    "pinned_scope": prev.get("pinned_scope") or (clean_scope if clean_scope != "global" else None),
                    "client_name": prev.get("client_name"),
                    "last_seen": sig["ts"],
                    "last_seen_mono": round(time.monotonic(), 6),
                }
            self._cond.notify_all()
            return dict(sig)

    def _visible_to_scope(self, item_scope: str | None, pinned_scope: str | None) -> bool:
        if not pinned_scope:
            return True
        return mcp_daemon.scope_matches_pin(item_scope, pinned_scope)

    def poll_signals(
        self,
        *,
        pinned_scope: str | None = None,
        after_seq: int = 0,
        exclude_agent: str | None = None,
        limit: int = 50,
        is_owner: bool = True,
        wait_timeout: float = 0.0,
    ) -> list[dict[str, Any]]:
        ex = (exclude_agent or "").strip() or None
        lim = max(1, min(500, int(limit)))

        def _collect() -> list[dict[str, Any]]:
            matched: list[dict[str, Any]] = []
            for sig in self._signals:
                if sig["seq"] <= after_seq:
                    continue
                if ex and sig.get("agent_id") == ex:
                    continue
                if sig.get("owner_only") and not is_owner:
                    continue
                if not self._visible_to_scope(sig.get("scope"), pinned_scope):
                    continue
                matched.append(dict(sig))
            return matched[-lim:]

        with self._lock:
            out = _collect()
            if out or wait_timeout <= 0:
                return out
            deadline = time.monotonic() + min(5.0, float(wait_timeout))
            while not out:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                self._cond.wait(timeout=rem)
                out = _collect()
            return out

    def active_agents(self, *, pinned_scope: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            out: list[dict[str, Any]] = []
            for rec in self._agents.values():
                ag_scope = rec.get("pinned_scope")
                if pinned_scope and ag_scope and not mcp_daemon.scope_matches_pin(ag_scope, pinned_scope):
                    continue
                out.append(dict(rec))
            return sorted(out, key=lambda r: r.get("last_seen_mono", 0.0), reverse=True)

    def build_feed(
        self,
        *,
        pinned_scope: str | None = None,
        after_seq: int = 0,
        exclude_agent: str | None = None,
        limit: int = 50,
        is_owner: bool = True,
    ) -> dict[str, Any]:
        signals = self.poll_signals(
            pinned_scope=pinned_scope,
            after_seq=after_seq,
            exclude_agent=exclude_agent,
            limit=limit,
            is_owner=is_owner,
        )
        agents = self.active_agents(pinned_scope=pinned_scope)
        lines: list[str] = []
        for s in signals:
            ag = s.get("agent_id") or s.get("origin") or "agent"
            lines.append(
                f"#{s['seq']} [{s['event_type']}] agent={ag} scope={s['scope']} "
                f"id={s.get('memory_id') or '-'} :: {s['summary']}"
            )
        fenced_text = safety.fence("\n".join(lines) if lines else "(no new swarm signals in scope)")
        with self._lock:
            cur_seq = self._seq
        return {
            "scope": pinned_scope or "all",
            "lastSeq": cur_seq,
            "signalCount": len(signals),
            "agentCount": len(agents),
            "agents": agents,
            "signals": signals,
            "fencedFeed": fenced_text,
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": True,
                "lastSeq": self._seq,
                "bufferedSignals": len(self._signals),
                "registeredAgents": len(self._agents),
            }
