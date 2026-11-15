"""Когнитивный Контроль Версий (Git для Разума / Temporal Rollback).

Позволяет создавать лёгкие криптографические снапшоты состояния памяти
(без дублирования текста, чтобы не нарушать необратимое право на забвение!),
считать diff и откатывать ложные/галлюцинированные ветки выводов по snapshot_id
или по временной метке as_of с выпуском L3/Solana квитанций забвения (0x02).
"""
from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from . import anchor, integrity, roles
from .store import new_id, now_iso

if TYPE_CHECKING:
    from .memory import Memory


def _normalize_as_of_upper(as_of: str) -> str:
    raw = (as_of or "").strip()
    if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
        return raw + "T23:59:59.999999+00:00"
    return raw


def _compute_state_hashes(rows: list[dict]) -> tuple[str, str | None]:
    """Детерминированно вычисляет SHA-256 состояния и Merkle-корень через anchor.merkle_root."""
    ordered = sorted(rows, key=lambda r: str(r["id"]))
    h = hashlib.sha256()
    leaves: list[bytes] = []
    for r in ordered:
        ch_hex = r["content_hash"].hex() if isinstance(r.get("content_hash"), (bytes, bytearray)) else ""
        item = {
            "id": r["id"],
            "status": r["status"],
            "kind": r["kind"],
            "scope": r["scope"],
            "confidence": round(float(r["confidence"]), 6),
            "superseded_by": r.get("superseded_by"),
            "content_hash": ch_hex,
        }
        encoded = json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")
        h.update(encoded + b"\n")
        leaves.append(anchor.leaf_record(encoded))
    merkle_hex = anchor.merkle_root(leaves).hex() if leaves else None
    return h.hexdigest(), merkle_hex


def _latest_anchor_tx(mem: "Memory") -> str | None:
    try:
        row = mem.store.one(
            "SELECT anchor_tx FROM l3_anchor WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            (mem.user_id,),
        )
        return row["anchor_tx"] if row and row["anchor_tx"] else None
    except Exception:
        return None


def _current_state_rows(mem: "Memory", scope: str | None = None) -> list[dict]:
    sql = (
        "SELECT id, status, kind, scope, importance, confidence, supersedes, superseded_by, "
        "valid_from, valid_to, expires_at, content_hash, created_at, content "
        "FROM memory WHERE user_id = ?"
    )
    params: list = [mem.user_id]
    if scope:
        sql += " AND scope = ?"
        params.append(scope)
    sql += " ORDER BY created_at ASC, id ASC"
    return [dict(r) for r in mem.store.query(sql, tuple(params))]


def create_snapshot(
    mem: "Memory",
    *,
    name: str | None = None,
    scope: str | None = None,
    note: str = "",
    actor: roles.ActorContext | None = None,
) -> dict:
    """Создаёт лёгкий когнитивный снапшот (savepoint) состояния памяти."""
    if actor is not None and not actor.is_owner:
        raise PermissionError("Creating memory snapshots requires owner permissions")
    snap_id = new_id()
    ts = now_iso()
    snap_name = (name or f"snap-{ts[:19].replace(':', '-')}").strip()[:120]
    rows = _current_state_rows(mem, scope=scope)
    state_sha, merkle_hex = _compute_state_hashes(rows)
    anchor_tx = _latest_anchor_tx(mem)

    ops: list[tuple[str, tuple]] = [
        (
            """INSERT INTO cognitive_snapshot
               (id, user_id, name, scope, note, created_at, record_count, state_sha256, merkle_root_hex, anchor_tx, rollback_count)
               VALUES (?,?,?,?,?,?,?,?,?,?,0)""",
            (snap_id, mem.user_id, snap_name, scope, (note or "")[:500], ts, len(rows), state_sha, merkle_hex, anchor_tx),
        )
    ]
    for r in rows:
        ops.append((
            """INSERT INTO cognitive_snapshot_item
               (snapshot_id, memory_id, status, kind, scope, importance, confidence,
                supersedes, superseded_by, valid_from, valid_to, expires_at, content_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                snap_id, r["id"], r["status"], r["kind"], r["scope"],
                float(r["importance"]), float(r["confidence"]),
                r.get("supersedes"), r.get("superseded_by"),
                r.get("valid_from"), r.get("valid_to"), r.get("expires_at"),
                r.get("content_hash"),
            ),
        ))
    mem.store.atomic(ops)
    mem._log_audit(
        "snapshot",
        snap_id,
        actor=actor.role if actor else "owner",
        scope=scope or "all",
        outcome="ok",
        detail=f"name={snap_name} records={len(rows)}",
    )
    return {
        "snapshot_id": snap_id,
        "name": snap_name,
        "scope": scope,
        "note": (note or "")[:500],
        "created_at": ts,
        "record_count": len(rows),
        "state_sha256": state_sha,
        "merkle_root_hex": merkle_hex,
        "anchor_tx": anchor_tx,
    }


def list_snapshots(mem: "Memory", *, scope: str | None = None, limit: int = 20) -> list[dict]:
    sql = "SELECT * FROM cognitive_snapshot WHERE user_id = ?"
    params: list = [mem.user_id]
    if scope:
        sql += " AND (scope = ? OR scope IS NULL)"
        params.append(scope)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, min(200, int(limit))))
    return [dict(r) for r in mem.store.query(sql, tuple(params))]


def resolve_snapshot(mem: "Memory", snapshot_id: str | None = None, *, name: str | None = None, scope: str | None = None) -> dict | None:
    if snapshot_id:
        row = mem.store.one(
            "SELECT * FROM cognitive_snapshot WHERE id = ? AND user_id = ?",
            (snapshot_id.strip(), mem.user_id),
        )
        if row is not None:
            return dict(row)
        row = mem.store.one(
            "SELECT * FROM cognitive_snapshot WHERE name = ? AND user_id = ? ORDER BY created_at DESC LIMIT 1",
            (snapshot_id.strip(), mem.user_id),
        )
        return dict(row) if row is not None else None
    if name:
        row = mem.store.one(
            "SELECT * FROM cognitive_snapshot WHERE name = ? AND user_id = ? ORDER BY created_at DESC LIMIT 1",
            (name.strip(), mem.user_id),
        )
        return dict(row) if row is not None else None
    return None


def _plan_rollback(
    mem: "Memory",
    *,
    snapshot_id: str | None = None,
    as_of: str | None = None,
    scope: str | None = None,
) -> dict:
    snap: dict | None = None
    eff_scope = scope
    cutoff_ts: str | None = None

    if snapshot_id:
        snap = resolve_snapshot(mem, snapshot_id=snapshot_id, scope=scope)
        if snap is None:
            raise ValueError(f"Snapshot not found: {snapshot_id}")
        if snap.get("scope") and scope and snap["scope"] != scope:
            raise PermissionError(f"Snapshot scope mismatch: {snap['scope']} != {scope}")
        eff_scope = eff_scope or snap.get("scope")
        cutoff_ts = snap["created_at"]
    elif as_of:
        cutoff_ts = _normalize_as_of_upper(as_of)
        # Пытаемся подобрать ближайший точный снапшот на момент <= as_of того же scope
        if eff_scope:
            row = mem.store.one(
                "SELECT * FROM cognitive_snapshot WHERE user_id = ? AND scope = ? AND created_at <= ? ORDER BY created_at DESC LIMIT 1",
                (mem.user_id, eff_scope, cutoff_ts),
            )
        else:
            row = mem.store.one(
                "SELECT * FROM cognitive_snapshot WHERE user_id = ? AND scope IS NULL AND created_at <= ? ORDER BY created_at DESC LIMIT 1",
                (mem.user_id, cutoff_ts),
            )
        if row is not None:
            snap = dict(row)
    else:
        raise ValueError("Provide either snapshot_id or as_of for rollback/diff")

    cur_rows = _current_state_rows(mem, scope=eff_scope)
    cur_map = {r["id"]: r for r in cur_rows}
    before_sha, before_merkle = _compute_state_hashes(cur_rows)

    after_candidates: set[str] = set()
    will_restore: list[dict] = []
    unrecoverable: list[str] = []

    if snap is not None:
        items = [
            dict(r) for r in mem.store.query(
                "SELECT * FROM cognitive_snapshot_item WHERE snapshot_id = ?",
                (snap["id"],),
            )
        ]
        snap_ids = {it["memory_id"] for it in items}
        for mid, crow in cur_map.items():
            if mid not in snap_ids and crow["status"] != "revoked":
                after_candidates.add(mid)
        for it in items:
            crow = cur_map.get(it["memory_id"])
            if crow is None:
                unrecoverable.append(it["memory_id"])
                continue
            if crow["status"] == "revoked" and crow["content"] is None:
                if it["status"] != "revoked":
                    unrecoverable.append(it["memory_id"])
                continue
            changed = (
                crow["status"] != it["status"]
                or round(float(crow["confidence"]), 6) != round(float(it["confidence"]), 6)
                or crow.get("superseded_by") != it.get("superseded_by")
            )
            if changed:
                will_restore.append({
                    "id": it["memory_id"],
                    "from_status": crow["status"],
                    "to_status": it["status"],
                    "to_confidence": float(it["confidence"]),
                    "to_importance": float(it["importance"]),
                    "to_superseded_by": it.get("superseded_by"),
                    "to_valid_from": it.get("valid_from"),
                    "to_valid_to": it.get("valid_to"),
                    "to_expires_at": it.get("expires_at"),
                })
    else:
        # Чистый откат по времени as_of: убираем все записи, созданные строго после cutoff_ts
        for mid, crow in cur_map.items():
            if (crow.get("created_at") or "") > cutoff_ts and crow["status"] != "revoked":
                after_candidates.add(mid)
        # Если до cutoff_ts существовала запись, вытесненная записью из будущего, восстанавливаем её как active
        for mid, crow in cur_map.items():
            if mid in after_candidates:
                continue
            if crow["status"] == "superseded" and crow.get("superseded_by") in after_candidates and crow["content"] is not None:
                will_restore.append({
                    "id": mid,
                    "from_status": crow["status"],
                    "to_status": "active",
                    "to_confidence": float(crow["confidence"]),
                    "to_importance": float(crow["importance"]),
                    "to_superseded_by": None,
                    "to_valid_from": crow.get("valid_from"),
                    "to_valid_to": crow.get("valid_to"),
                    "to_expires_at": crow.get("expires_at"),
                })

    # Каскад выводов (derived): если отменяем/забываем запись, все derived-следствия тоже должны быть откатаны
    expanded_after = set(after_candidates)
    for aid in list(after_candidates):
        for did in mem.derived(aid):
            drow = cur_map.get(did)
            if drow is not None and drow["status"] != "revoked":
                expanded_after.add(did)

    # Не восстанавливаем то, что попало в каскад отмены
    will_restore = [r for r in will_restore if r["id"] not in expanded_after]

    return {
        "mode": "snapshot" if snap is not None else "temporal_asof",
        "snapshot": {
            "snapshot_id": snap["id"],
            "name": snap["name"],
            "created_at": snap["created_at"],
            "state_sha256": snap["state_sha256"],
            "merkle_root_hex": snap.get("merkle_root_hex"),
            "anchor_tx": snap.get("anchor_tx"),
        } if snap is not None else None,
        "as_of": cutoff_ts,
        "scope": eff_scope,
        "before_sha256": before_sha,
        "merkle_root_before": before_merkle,
        "will_forget_ids": sorted(expanded_after),
        "will_restore": will_restore,
        "unrecoverable_revoked_ids": sorted(unrecoverable),
    }


def diff_snapshot(
    mem: "Memory",
    *,
    snapshot_id: str | None = None,
    as_of: str | None = None,
    scope: str | None = None,
) -> dict:
    plan = _plan_rollback(mem, snapshot_id=snapshot_id, as_of=as_of, scope=scope)
    return {
        **plan,
        "will_forget_count": len(plan["will_forget_ids"]),
        "will_restore_count": len(plan["will_restore"]),
        "unrecoverable_count": len(plan["unrecoverable_revoked_ids"]),
    }


def rollback(
    mem: "Memory",
    *,
    snapshot_id: str | None = None,
    as_of: str | None = None,
    scope: str | None = None,
    dry_run: bool = False,
    revoke_after: bool = True,
    reason: str = "",
    actor: roles.ActorContext | None = None,
) -> dict:
    """Откатывает память к когнитивному снапшоту или моменту as_of (с криптографическими квитанциями)."""
    if actor is not None and not actor.is_owner:
        raise PermissionError("Cognitive rollback requires owner permissions")

    plan = _plan_rollback(mem, snapshot_id=snapshot_id, as_of=as_of, scope=scope)
    if dry_run:
        return {
            "format": "padam-rollback-receipt/1",
            "status": "dry_run",
            "dry_run": True,
            **plan,
            "forgotten_ids": [],
            "forget_leaves": [],
            "restored_ids": [],
            "after_sha256": plan["before_sha256"],
            "merkle_root_after": plan["merkle_root_before"],
        }

    forgotten_ids: list[str] = []
    forget_leaves: list[str] = []
    restored_ids: list[str] = []

    # 1. Отзываем ложные/галлюцинированные ветки после точки отката.
    # Сначала отсекаем их от прежних версий (чтобы не затронуть честное прошлое),
    # а затем точечно стираем каждую запись из plan['will_forget_ids'] (включая её derived-потомков).
    forget_set = set(plan["will_forget_ids"])
    if forget_set:
        ph = ",".join("?" * len(forget_set))
        mem.store.atomic([
            (f"UPDATE memory SET superseded_by = NULL WHERE user_id = ? AND superseded_by IN ({ph})", (mem.user_id, *forget_set)),
            (f"UPDATE memory SET supersedes = NULL WHERE user_id = ? AND id IN ({ph})", (mem.user_id, *forget_set)),
        ])
    for mid in plan["will_forget_ids"]:
        if revoke_after:
            if mem.revoke(mid, with_derived=False, cascade=False):
                forgotten_ids.append(mid)
                rcpt = getattr(mem, "_last_receipt", None)
                if isinstance(rcpt, dict) and rcpt.get("leaf_forget_hex"):
                    forget_leaves.append(str(rcpt["leaf_forget_hex"]))
        else:
            mem.store.execute(
                "UPDATE memory SET status = 'rejected' WHERE id = ? AND user_id = ? AND status != 'revoked'",
                (mid, mem.user_id),
            )
            forgotten_ids.append(mid)

    # 2. Восстанавливаем записи, бывшие активными на точке отката (никогда не воскрешая забытое!)
    restore_ops: list[tuple[str, tuple]] = []
    for r in plan["will_restore"]:
        restore_ops.append((
            """UPDATE memory
               SET status = ?, confidence = ?, importance = ?, superseded_by = ?,
                   valid_from = ?, valid_to = ?, expires_at = ?
               WHERE id = ? AND user_id = ? AND status != 'revoked' AND content IS NOT NULL""",
            (
                r["to_status"], r["to_confidence"], r["to_importance"], r["to_superseded_by"],
                r["to_valid_from"], r["to_valid_to"], r["to_expires_at"],
                r["id"], mem.user_id,
            ),
        ))
        restored_ids.append(r["id"])
    if restore_ops:
        mem.store.atomic(restore_ops)
        # Переподписываем защищённые записи владельцем, если локальный ключ владельца доступен
        try:
            key = getattr(mem, "_ключ", None)
            if key is not None:
                for rid in restored_ids:
                    row = mem.store.one(
                        "SELECT id, user_id, scope, kind, content, origin, created_at FROM memory WHERE id = ? AND user_id = ? AND content IS NOT NULL",
                        (rid, mem.user_id),
                    )
                    if row is not None and row["kind"] in ("identity", "preference"):
                        sig = integrity.sign(key, row["id"], row["user_id"], row["scope"], row["kind"], row["content"], row["origin"], row["created_at"])
                        mem.store.execute("UPDATE memory SET owner_sig = ? WHERE id = ?", (sig, rid))
        except Exception:
            pass

    if plan.get("snapshot") is not None:
        mem.store.execute(
            "UPDATE cognitive_snapshot SET rollback_count = rollback_count + 1 WHERE id = ? AND user_id = ?",
            (plan["snapshot"]["snapshot_id"], mem.user_id),
        )
    mem.__dict__.pop("_ккэш", None)

    after_rows = _current_state_rows(mem, scope=plan["scope"])
    after_sha, after_merkle = _compute_state_hashes(after_rows)

    receipt = {
        "format": "padam-rollback-receipt/1",
        "status": "rolled_back",
        "dry_run": False,
        "mode": plan["mode"],
        "snapshot": plan["snapshot"],
        "as_of": plan["as_of"],
        "scope": plan["scope"],
        "reason": (reason or "")[:400],
        "before_sha256": plan["before_sha256"],
        "after_sha256": after_sha,
        "merkle_root_before": plan["merkle_root_before"],
        "merkle_root_after": after_merkle,
        "forgotten_ids": forgotten_ids,
        "forget_leaves": forget_leaves,
        "restored_ids": restored_ids,
        "unrecoverable_revoked_ids": plan["unrecoverable_revoked_ids"],
        "rolled_back_at": now_iso(),
    }
    mem._log_audit(
        "rollback",
        plan["snapshot"]["snapshot_id"] if plan["snapshot"] else None,
        actor=actor.role if actor else "owner",
        scope=plan["scope"] or "all",
        outcome="rolled_back",
        detail=f"forgotten={len(forgotten_ids)} restored={len(restored_ids)} unrecoverable={len(plan['unrecoverable_revoked_ids'])}",
    )
    return receipt
