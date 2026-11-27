# -*- coding: utf-8 -*-
"""On-Premise Control Plane для централизованного управления флотом узлов PADAM Shield.

Решает корпоративную задачу управления сотнями агентских серверов внутри закрытого
периметра клиента (Zero-Telemetry, без облака вендора):
1. Подписанный версионированный Policy Bundle (`.rego` + JSON-метаданные + HMAC-SHA256)
   с жёсткой защитой от отката версии (`anti-rollback`: узел отвергает версию ниже текущей).
2. Централизованный приём и верификация хеш-цепей `Proof-of-Execution` от удалённых узлов
   в единое хранилище SQLite (`store._lock` + строгая изоляция `user_id`).
3. Живая сводка флота (`get_fleet_status`): версия политики, число узлов, целостность цепей.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional

from .. import integrity as _integrity
from ..store import add_column_safe


def _ensure_tables(memory: Any) -> None:
    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_fleet_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL DEFAULT '',
                version INTEGER NOT NULL,
                rego_source TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                bundle_sha256 TEXT NOT NULL,
                signature_hmac TEXT NOT NULL,
                published_at REAL NOT NULL
            )
            """
        )
        add_column_safe(conn, "shield_fleet_policies", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_fleet_pol_user_ver ON shield_fleet_policies(user_id, version DESC)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shield_fleet_attestations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL DEFAULT '',
                node_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL DEFAULT 0,
                entries_count INTEGER NOT NULL DEFAULT 0,
                chain_head_hash TEXT NOT NULL,
                chain_valid INTEGER NOT NULL DEFAULT 1,
                payload_json TEXT NOT NULL,
                received_at REAL NOT NULL
            )
            """
        )
        add_column_safe(conn, "shield_fleet_attestations", "user_id", "TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_fleet_att_user_node ON shield_fleet_attestations(user_id, node_id, id DESC)"
        )
        conn.commit()


def _sign_bundle_payload(memory: Any, payload: Dict[str, Any]) -> str:
    key, _ = _integrity.owner_key(memory.store)
    kb = key if isinstance(key, bytes) else str(key).encode("utf-8")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hmac.new(kb, canonical, hashlib.sha256).hexdigest()


def publish_fleet_policy_bundle(
    memory: Any,
    *,
    rego_source: str,
    version: Optional[int] = None,
    description: str = "",
) -> Dict[str, Any]:
    """Публикует и подписывает новую версию политики .rego для флота (с защитой от отката)."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    src = str(rego_source or "").strip()
    if not src:
        raise ValueError("rego_source must be non-empty")

    with memory.store._lock:
        conn = memory.store.conn
        row = conn.execute(
            "SELECT MAX(version) FROM shield_fleet_policies WHERE user_id = ?",
            (uid,),
        ).fetchone()
        latest_ver = int(row[0] or 0) if row else 0
        next_ver = int(version) if version is not None else (latest_ver + 1)
        if next_ver <= latest_ver:
            return {
                "ok": False,
                "blocked": True,
                "rule_id": "FLEET-POLICY-ROLLBACK-BLOCKED",
                "reason": f"Запрещён откат версии политики: запрошена v{next_ver} <= текущая v{latest_ver}",
            }

        now = time.time()
        b_hash = hashlib.sha256(src.encode("utf-8")).hexdigest()
        core = {
            "version": next_ver,
            "rego_sha256": b_hash,
            "description": str(description or ""),
            "published_at": round(now, 3),
        }
        sig = _sign_bundle_payload(memory, core)
        conn.execute(
            """
            INSERT INTO shield_fleet_policies
                (user_id, version, rego_source, description, bundle_sha256, signature_hmac, published_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (uid, next_ver, src, str(description or ""), b_hash, sig, now),
        )
        conn.commit()

    return {
        "ok": True,
        "blocked": False,
        "bundle": {
            **core,
            "rego_source": src,
            "signature_hmac": sig,
        },
    }


def verify_fleet_policy_bundle(
    memory: Any,
    bundle: Dict[str, Any],
    *,
    min_version: int = 1,
) -> Dict[str, Any]:
    """Проверяет подпись, хеш содержимого и защиту от отката версии на узле агента."""
    if not isinstance(bundle, dict):
        return {"ok": False, "valid": False, "reason": "invalid_bundle"}
    ver = int(bundle.get("version") or 0)
    if ver < int(min_version):
        return {
            "ok": False,
            "valid": False,
            "rule_id": "FLEET-POLICY-ROLLBACK-BLOCKED",
            "reason": f"Версия пакета v{ver} ниже минимально допустимой v{min_version}",
        }
    src = str(bundle.get("rego_source") or "")
    actual_sha = hashlib.sha256(src.encode("utf-8")).hexdigest()
    if actual_sha != str(bundle.get("rego_sha256") or ""):
        return {
            "ok": False,
            "valid": False,
            "rule_id": "FLEET-POLICY-HASH-MISMATCH",
            "reason": "Хеш rego_source не совпадает с подписанным rego_sha256",
        }
    core = {
        "version": ver,
        "rego_sha256": actual_sha,
        "description": str(bundle.get("description") or ""),
        "published_at": bundle.get("published_at"),
    }
    expected_sig = _sign_bundle_payload(memory, core)
    if not hmac.compare_digest(expected_sig, str(bundle.get("signature_hmac") or "")):
        return {
            "ok": False,
            "valid": False,
            "rule_id": "FLEET-POLICY-SIGNATURE-INVALID",
            "reason": "Недействительная криптографическая подпись пакета политик",
        }
    return {"ok": True, "valid": True, "version": ver, "rego_sha256": actual_sha}


def ingest_node_attestation_batch(
    memory: Any,
    *,
    node_id: str,
    entries: List[Dict[str, Any]],
    policy_version: int = 0,
) -> Dict[str, Any]:
    """Принимает и проверяет связность хеш-цепи Proof-of-Execution от удалённого узла."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    nid = str(node_id or "").strip()
    if not nid:
        raise ValueError("node_id must be non-empty")

    chain_valid = True
    broken_index = -1
    prev_h = "0" * 64
    head_h = prev_h
    for idx, item in enumerate(entries or []):
        item_prev = str(item.get("prev_hash") or "")
        item_cur = str(item.get("entry_hash") or "")
        if idx > 0 and item_prev != prev_h:
            chain_valid = False
            broken_index = idx
            break
        if len(item_cur) != 64:
            chain_valid = False
            broken_index = idx
            break
        prev_h = item_cur
        head_h = item_cur

    with memory.store._lock:
        conn = memory.store.conn
        conn.execute(
            """
            INSERT INTO shield_fleet_attestations
                (user_id, node_id, policy_version, entries_count, chain_head_hash, chain_valid, payload_json, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uid,
                nid,
                int(policy_version),
                len(entries or []),
                head_h,
                1 if chain_valid else 0,
                json.dumps(entries[:200], ensure_ascii=False),
                time.time(),
            ),
        )
        conn.commit()

    return {
        "ok": chain_valid,
        "node_id": nid,
        "entries_received": len(entries or []),
        "chain_valid": chain_valid,
        "broken_index": broken_index,
        "chain_head_hash": head_h,
    }


def get_fleet_status(memory: Any) -> Dict[str, Any]:
    """Возвращает живую сводку On-Premise Control Plane: политику и состояние узлов."""
    _ensure_tables(memory)
    uid = str(getattr(memory, "user_id", "") or "")
    with memory.store._lock:
        conn = memory.store.conn
        pol = conn.execute(
            "SELECT version, description, bundle_sha256, published_at FROM shield_fleet_policies "
            "WHERE user_id = ? ORDER BY version DESC LIMIT 1",
            (uid,),
        ).fetchone()
        rows = conn.execute(
            "SELECT node_id, policy_version, entries_count, chain_head_hash, chain_valid, received_at "
            "FROM shield_fleet_attestations WHERE user_id = ? ORDER BY id DESC LIMIT 200",
            (uid,),
        ).fetchall()

    nodes: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        nid = str(r[0])
        if nid not in nodes:
            nodes[nid] = {
                "node_id": nid,
                "policy_version": int(r[1]),
                "entries_count": int(r[2]),
                "chain_head_hash": str(r[3]),
                "chain_valid": bool(r[4]),
                "last_seen": float(r[5]),
            }

    return {
        "ok": True,
        "zero_telemetry": True,
        "active_policy": {
            "version": int(pol[0]),
            "description": str(pol[1]),
            "rego_sha256": str(pol[2]),
            "published_at": float(pol[3]),
        } if pol else None,
        "nodes_count": len(nodes),
        "healthy_nodes": sum(1 for n in nodes.values() if n["chain_valid"]),
        "nodes": list(nodes.values()),
    }
