# -*- coding: utf-8 -*-
"""Режим Shadow-аудита (`padam learn`) и локальный поведенческий движок UEBA (Z-score).

1. Shadow-режим (Dry-Run): логирует потенциальные срабатывания 4 колец без блокировки,
   затем автоматически генерирует оптимальный `padam.policy.yaml` под рабочий стек владельца.
2. Локальный UEBA без облака: рассчитывает адаптивную норму (baseline) по алгоритму Уэлфорда
   для каждой пары `(agent_id, tool_name)` и роли (например, разработчик делает 100 вызовов
   `git`/мин, а бухгалтер — 2 вызова/час) и вычисляет Z-score аномалии.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import math
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

try:
    import yaml as _yaml  # type: ignore[import-untyped]
except Exception:
    _yaml = None

from ..store import add_column_safe


def _dump_policy_yaml(obj: dict[str, Any]) -> str:
    """Сериализует политику в YAML (через PyYAML, либо чистый JSON-совместимый YAML без зависимостей)."""
    if _yaml is not None:
        return _yaml.safe_dump(obj, sort_keys=False, allow_unicode=True)
    # Валидный YAML 1.2 (надмножество JSON), читается любым YAML-парсером и стандартным json.loads
    return json.dumps(obj, ensure_ascii=False, indent=2) + "\n"


def _load_policy_yaml(raw: str) -> Any:
    if _yaml is not None:
        return _yaml.safe_load(raw)
    return json.loads(raw)

_LEARN_UEBA_DDL = """
CREATE TABLE IF NOT EXISTS shield_shadow_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    would_status TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shadow_user_time ON shield_shadow_events (user_id, created_at);

CREATE TABLE IF NOT EXISTS shield_ueba_baselines (
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    role_name TEXT NOT NULL DEFAULT 'default',
    sample_count INTEGER NOT NULL DEFAULT 0,
    mean_rate REAL NOT NULL DEFAULT 0.0,
    m2_rate REAL NOT NULL DEFAULT 0.0,
    mean_chars REAL NOT NULL DEFAULT 0.0,
    m2_chars REAL NOT NULL DEFAULT 0.0,
    ewma_rate REAL NOT NULL DEFAULT 0.0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, agent_id, tool_name)
);
"""


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_learn_ueba_tables(memory: Any) -> None:
    store = getattr(memory, "store", None)
    if store is None or getattr(store, "_shield_learn_ueba_ready", False):
        return
    with store._lock:
        store.conn.executescript(_LEARN_UEBA_DDL)
        try:
            add_column_safe(store.conn, "shield_state", "shield_mode", "TEXT DEFAULT 'enforce'")
        except Exception:
            pass
        store.conn.commit()
        store._shield_learn_ueba_ready = True


def get_shield_mode(memory: Any) -> str:
    """Возвращает текущий режим работы щита: `enforce` или `shadow`."""
    from .. import agentic_shield as _ash

    _ash._default_state(memory)
    ensure_learn_ueba_tables(memory)
    row = memory.store.one("SELECT shield_mode FROM shield_state WHERE user_id = ?", (memory.user_id,))
    mode = str((row["shield_mode"] if row and "shield_mode" in row.keys() else "") or "enforce").strip().lower()
    return "shadow" if mode == "shadow" else "enforce"


def set_shield_mode(memory: Any, mode: str) -> dict[str, Any]:
    """Переключает режим щита между `enforce` (блокировка) и `shadow` (обучение/наблюдение)."""
    from .. import agentic_shield as _ash

    _ash._default_state(memory)
    ensure_learn_ueba_tables(memory)
    m = str(mode or "enforce").strip().lower()
    if m not in ("enforce", "shadow"):
        raise ValueError(f"Unsupported shield mode: {mode!r} (expected 'enforce' or 'shadow')")
    with memory.store._lock:
        memory.store.conn.execute(
            "UPDATE shield_state SET shield_mode = ?, updated_at = ? WHERE user_id = ?",
            (m, _utc_iso(), memory.user_id),
        )
        memory.store.conn.commit()
    return {"ok": True, "shield_mode": m}


def record_shadow_event(
    memory: Any,
    *,
    agent_id: str,
    action_type: str,
    target: str,
    would_status: str,
    risk_level: str,
    reasons: list[dict[str, Any]],
) -> str:
    """Записывает потенциальное срабатывание в журнал Shadow-аудита без блокировки пользователя."""
    ensure_learn_ueba_tables(memory)
    eid = f"shd-{uuid.uuid4().hex[:12]}"
    with memory.store._lock:
        memory.store.conn.execute(
            """INSERT INTO shield_shadow_events
               (id, user_id, agent_id, action_type, target, would_status, risk_level, reasons_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                eid, memory.user_id, str(agent_id or "agent")[:80], str(action_type or "action")[:48],
                str(target or "")[:240], str(would_status or "blocked")[:32],
                str(risk_level or "medium")[:16], json.dumps(reasons, ensure_ascii=False), _utc_iso(),
            ),
        )
        memory.store.conn.commit()
    return eid


def observe_ueba_metric(
    memory: Any,
    *,
    agent_id: str,
    tool_name: str,
    rate_per_min: float,
    payload_chars: int = 0,
    role_name: str = "default",
    z_threshold: float = 3.5,
    min_samples: int = 5,
) -> dict[str, Any]:
    """Обновляет локальный поведенческий профиль (Уэлфорд + EWMA) и вычисляет Z-score аномалии."""
    ensure_learn_ueba_tables(memory)
    aid = str(agent_id or "agent").strip()[:80]
    tname = str(tool_name or "tool").strip()[:80]
    role = str(role_name or "default").strip()[:48]
    val_r = max(0.0, float(rate_per_min))
    val_c = max(0.0, float(payload_chars))

    with memory.store._lock:
        row = memory.store.one(
            "SELECT * FROM shield_ueba_baselines WHERE user_id = ? AND agent_id = ? AND tool_name = ?",
            (memory.user_id, aid, tname),
        )
        if row is None:
            n = 0
            mean_r, m2_r = 0.0, 0.0
            mean_c, m2_c = 0.0, 0.0
            ewma_r = val_r
        else:
            n = int(row["sample_count"])
            mean_r = float(row["mean_rate"])
            m2_r = float(row["m2_rate"])
            mean_c = float(row["mean_chars"])
            m2_c = float(row["m2_chars"])
            ewma_r = float(row["ewma_rate"])

        # Сначала оцениваем Z-score относительно ПРЕДЫДУЩЕЙ нормы (чтобы выброс не размыл сам себя)
        z_rate = 0.0
        z_chars = 0.0
        anomalous = False
        if n >= max(2, int(min_samples)):
            std_r = math.sqrt(m2_r / max(1, n - 1))
            std_c = math.sqrt(m2_c / max(1, n - 1))
            # Минимальный защитный пол дисперсии, чтобы стабильный агент не давал деление на 0
            eff_std_r = max(std_r, max(1.0, mean_r * 0.12))
            eff_std_c = max(std_c, max(64.0, mean_c * 0.15))
            z_rate = (val_r - mean_r) / eff_std_r
            z_chars = (val_c - mean_c) / eff_std_c
            anomalous = (z_rate >= float(z_threshold)) or (z_chars >= float(z_threshold) + 1.0)

        # Обновляем базовую линию (при сильной аномалии ограничиваем влияние выброса — robust update)
        if not anomalous:
            n_new = n + 1
            delta_r = val_r - mean_r
            mean_r_new = mean_r + delta_r / n_new
            m2_r_new = m2_r + delta_r * (val_r - mean_r_new)

            delta_c = val_c - mean_c
            mean_c_new = mean_c + delta_c / n_new
            m2_c_new = m2_c + delta_c * (val_c - mean_c_new)

            ewma_r_new = (0.25 * val_r) + (0.75 * ewma_r) if n > 0 else val_r
            memory.store.conn.execute(
                """INSERT INTO shield_ueba_baselines
                   (user_id, agent_id, tool_name, role_name, sample_count,
                    mean_rate, m2_rate, mean_chars, m2_chars, ewma_rate, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(user_id, agent_id, tool_name) DO UPDATE SET
                       role_name=excluded.role_name, sample_count=excluded.sample_count,
                       mean_rate=excluded.mean_rate, m2_rate=excluded.m2_rate,
                       mean_chars=excluded.mean_chars, m2_chars=excluded.m2_chars,
                       ewma_rate=excluded.ewma_rate, updated_at=excluded.updated_at""",
                (
                    memory.user_id, aid, tname, role, n_new,
                    mean_r_new, m2_r_new, mean_c_new, m2_c_new, ewma_r_new, _utc_iso(),
                ),
            )
            memory.store.conn.commit()
            n, mean_r, mean_c = n_new, mean_r_new, mean_c_new

    recommended_threshold = max(5, int(round(mean_r + 3.0 * max(1.0, mean_r * 0.25))))
    return {
        "ok": True,
        "agent_id": aid,
        "tool_name": tname,
        "role_name": role,
        "samples": n,
        "baseline_mean_rate": round(mean_r, 3),
        "baseline_mean_chars": round(mean_c, 1),
        "observed_rate": round(val_r, 3),
        "z_score_rate": round(z_rate, 3),
        "z_score_chars": round(z_chars, 3),
        "anomalous": anomalous,
        "adaptive_kill_threshold": recommended_threshold,
    }


def list_ueba_profiles(memory: Any, limit: int = 50) -> list[dict[str, Any]]:
    """Возвращает текущие локальные UEBA-профили агентов и инструментов."""
    ensure_learn_ueba_tables(memory)
    rows = memory.store.query(
        "SELECT * FROM shield_ueba_baselines WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
        (memory.user_id, max(1, min(200, int(limit)))),
    )
    out: list[dict[str, Any]] = []
    for r in rows:
        n = int(r["sample_count"])
        std_r = math.sqrt(float(r["m2_rate"]) / max(1, n - 1)) if n >= 2 else 0.0
        out.append({
            "agent_id": r["agent_id"],
            "tool_name": r["tool_name"],
            "role_name": r["role_name"],
            "samples": n,
            "mean_rate": round(float(r["mean_rate"]), 3),
            "stddev_rate": round(std_r, 3),
            "mean_chars": round(float(r["mean_chars"]), 1),
            "adaptive_threshold": max(5, int(round(float(r["mean_rate"]) + 3.0 * max(1.0, std_r)))),
            "updated_at": r["updated_at"],
        })
    return out


def generate_policy_yaml(
    memory: Any,
    *,
    days: int = 7,
    out_path: str | Path | None = None,
) -> dict[str, Any]:
    """Анализирует события Shadow-аудита и UEBA за N дней и строит `padam.policy.yaml`."""
    ensure_learn_ueba_tables(memory)
    since = (datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))).isoformat(timespec="seconds")
    shadow_rows = memory.store.query(
        "SELECT * FROM shield_shadow_events WHERE user_id = ? AND created_at >= ? ORDER BY created_at DESC",
        (memory.user_id, since),
    )
    ueba = list_ueba_profiles(memory, limit=100)

    candidate_domains: dict[str, int] = {}
    excluded_critical = 0
    for r in shadow_rows:
        reasons = json.loads(r["reasons_json"] or "[]")
        codes = {str(x.get("code") or "") for x in reasons}
        # Никогда не включаем в авто-белый список критические атаки (секреты, SSRF, shell, typosquatting, канарейки)
        if r["risk_level"] == "critical" or (codes & {
            "secret_exfiltration_blocked", "dangerous_shell_command", "ssrf_or_unsafe_url",
            "domain_typosquatting", "canary_honeypot_exfiltration", "payee_swap_or_untrusted_wallet",
        }):
            excluded_critical += 1
            continue
        tgt = str(r["target"] or "").strip()
        if "://" in tgt:
            host = urllib.parse.urlsplit(tgt).netloc.lower().split(":")[0]
        elif "." in tgt and " " not in tgt:
            host = tgt.lower().split("/")[0].split(":")[0]
        else:
            host = ""
        if host and not host.startswith("xn--"):
            candidate_domains[host] = candidate_domains.get(host, 0) + 1

    suggested_domains = sorted(candidate_domains.keys())
    policy_obj: dict[str, Any] = {
        "version": "1.0",
        "generated_at": _utc_iso(),
        "learned_window_days": int(days),
        "shield_mode": "enforce",
        "profile": "balanced",
        "allowlist": {
            "domains": suggested_domains,
            "wallets": [],
        },
        "ueba_adaptive_thresholds": {
            f"{u['agent_id']}:{u['tool_name']}": {
                "role": u["role_name"],
                "mean_rate_per_min": u["mean_rate"],
                "recommended_kill_threshold": u["adaptive_threshold"],
            }
            for u in ueba
        },
        "summary": {
            "shadow_events_analyzed": len(shadow_rows),
            "suggested_domains_count": len(suggested_domains),
            "critical_threats_excluded": excluded_critical,
        },
    }
    yaml_text = _dump_policy_yaml(policy_obj)
    if out_path is not None:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(yaml_text, encoding="utf-8")

    return {
        "ok": True,
        "policy": policy_obj,
        "yaml": yaml_text,
        "out_path": str(out_path) if out_path else None,
    }


def apply_policy_yaml(memory: Any, policy_path: str | Path, *, actor: Any = None) -> dict[str, Any]:
    """Применяет сгенерированный `padam.policy.yaml` к текущему экземпляру PADAM Shield."""
    from .. import agentic_shield as _ash

    raw = Path(policy_path).read_text(encoding="utf-8")
    data = _load_policy_yaml(raw) or {}
    if not isinstance(data, dict):
        raise ValueError("Invalid policy YAML: root must be a mapping")

    added_domains = 0
    allow = data.get("allowlist") or {}
    for dom in (allow.get("domains") or []):
        d = str(dom or "").strip()
        if d:
            _ash.add_allowlist_entry(memory, entry_type="domain", value=d, label="padam-learn", actor=actor)
            added_domains += 1
    added_wallets = 0
    for wal in (allow.get("wallets") or []):
        w = str(wal or "").strip()
        if w:
            _ash.add_allowlist_entry(memory, entry_type="wallet", value=w, label="padam-learn", actor=actor)
            added_wallets += 1

    profile = str(data.get("profile") or "").strip()
    if profile in ("balanced", "strict_fin", "paranoid_airgap"):
        _ash.set_policy_profile(memory, profile, actor=actor)

    mode = str(data.get("shield_mode") or "enforce").strip().lower()
    if mode in ("enforce", "shadow"):
        set_shield_mode(memory, mode)

    return {
        "ok": True,
        "applied_profile": profile or "unchanged",
        "shield_mode": mode,
        "domains_added": added_domains,
        "wallets_added": added_wallets,
    }
