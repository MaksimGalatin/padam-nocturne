# -*- coding: utf-8 -*-
"""Автономный пульс Хранителя Ковчега (Ark Heartbeat Daemon, пункт 5).

Особенности:
- По умолчанию ВЫКЛЮЧЕН (`PADAM_ARK_HEARTBEAT=0`).
- Расход $0, без сетевых обращений: выполняет только проактивный обход `run_guardian_tick`,
  проверку здоровья БД (`diagnose_database`) и записывает отметку в крипто-цепочку аудита.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any

from . import ark_advanced, audit_chain, self_heal


def is_heartbeat_enabled() -> bool:
    return os.environ.get("PADAM_ARK_HEARTBEAT", "0").strip() == "1"


def run_heartbeat_pulse(memory, *, scope: str = "global") -> dict[str, Any]:
    """Выполняет один такт пульса Хранителя ($0, без сети, только чтение + запись аудита)."""
    guardian = ark_advanced.run_guardian_tick(memory, scope=scope)
    db_diag = self_heal.diagnose_database(memory.store.path)
    audit_entry = audit_chain.append_audit(
        memory,
        "ark_heartbeat_pulse",
        {
            "health_score": guardian.get("health_score", 0),
            "audit_chain_valid": bool(guardian.get("audit_chain_valid", False)),
            "db_healthy": bool(db_diag.get("healthy", False)),
            "alerts_count": len(guardian.get("alerts") or []),
            "cost_usd": 0.0,
        },
        agent_id="ark_heartbeat",
    )
    return {
        "ok": True,
        "cost_usd": 0.0,
        "network_calls": 0,
        "guardian": guardian,
        "db_diagnosis": db_diag,
        "audit_seq": audit_entry.get("seq"),
    }


class ArkHeartbeatRunner:
    """Управляемый фоновый планировщик пульса Хранителя."""

    def __init__(self, memory_factory, *, interval_s: float = 300.0, scope: str = "global") -> None:
        self._memory_factory = memory_factory
        self._interval_s = max(0.05, float(interval_s))
        self._scope = scope
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.ticks_completed = 0
        self.last_report: dict[str, Any] | None = None

    def start(self, *, force: bool = False) -> bool:
        if not force and not is_heartbeat_enabled():
            return False
        if self._thread and self._thread.is_alive():
            return True

        def _loop():
            while not self._stop.is_set():
                try:
                    m = self._memory_factory()
                    try:
                        self.last_report = run_heartbeat_pulse(m, scope=self._scope)
                        self.ticks_completed += 1
                    finally:
                        m.close()
                except Exception:
                    pass
                self._stop.wait(self._interval_s)

        self._thread = threading.Thread(target=_loop, name="padam-ark-heartbeat", daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout_s: float = 2.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout_s)
