# -*- coding: utf-8 -*-
"""Постквантовый конверт для вечного архива L3 (L3 PQC Archive Envelope, пункт 11).

Гарантии:
- Полностью локальная сборка за $0 поверх `padam/pqc_mlkem.py` (эталон `cryptography` с 64B seed,
  или запасной PurePython ML-KEM-768).
- Ни одна сетевая отправка в Arweave / Solana здесь не выполняется; флаги-замки
  `PADAM_ALLOW_SOVEREIGN_L3=1` и `ARWEAVE_MIRROR=1` остаются закрытыми по умолчанию.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

from . import pqc_mlkem, safety


def seal_l3_pqc_bundle(
    memory,
    mlkem_public: bytes,
    x25519_public: bytes,
    *,
    scope: str | None = None,
) -> dict[str, Any]:
    """Собирает активные записи памяти и запечатывает их в постквантовый конверт для L3."""
    sql = "SELECT id, scope, kind, content, created_at, owner_sig FROM memory WHERE user_id = ? AND status = 'active'"
    params: list[Any] = [memory.user_id]
    if scope:
        sql += " AND scope = ?"
        params.append(scope)
    sql += " ORDER BY created_at ASC, id ASC"
    rows = memory.store.conn.execute(sql, params).fetchall()

    records = []
    leaves: list[str] = []
    for r in rows:
        clean_content, _ = safety.redact(str(r["content"] or ""))
        rec = {
            "id": str(r["id"]),
            "scope": str(r["scope"]),
            "kind": str(r["kind"]),
            "content": clean_content,
            "created_at": str(r["created_at"]),
            "owner_sig": r["owner_sig"],
        }
        records.append(rec)
        leaves.append(hashlib.sha256(json.dumps(rec, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest())

    if leaves:
        lvl = list(leaves)
        while len(lvl) > 1:
            if len(lvl) % 2 == 1:
                lvl.append(lvl[-1])
            lvl = [hashlib.sha256((lvl[i] + ":" + lvl[i + 1]).encode("utf-8")).hexdigest() for i in range(0, len(lvl), 2)]
        merkle_root = lvl[0]
    else:
        merkle_root = hashlib.sha256(b"empty-l3-bundle").hexdigest()

    bundle_plain = {
        "schema": "padam-l3-pqc-bundle-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "merkle_root": merkle_root,
        "records_count": len(records),
        "records": records,
    }
    raw = json.dumps(bundle_plain, ensure_ascii=False, sort_keys=True).encode("utf-8")
    pqc_env = pqc_mlkem.pqc_seal_bytes(raw, mlkem_public, x25519_public)

    return {
        "ok": True,
        "schema": "padam-l3-pqc-envelope-v1",
        "merkle_root": merkle_root,
        "records_count": len(records),
        "network_uploaded": False,
        "locks": {
            "PADAM_ALLOW_SOVEREIGN_L3": os.environ.get("PADAM_ALLOW_SOVEREIGN_L3", "0"),
            "ARWEAVE_MIRROR": os.environ.get("ARWEAVE_MIRROR", "0"),
        },
        "pqc_envelope": pqc_env,
    }


def open_l3_pqc_bundle(
    envelope_bundle: dict[str, Any],
    mlkem_private: bytes,
    x25519_private: bytes,
) -> dict[str, Any]:
    """Расшифровывает и проверяет целостность корня Меркла L3 PQC-конверта."""
    raw = pqc_mlkem.pqc_open_bytes(envelope_bundle["pqc_envelope"], mlkem_private, x25519_private)
    bundle = json.loads(raw.decode("utf-8"))

    leaves = [
        hashlib.sha256(json.dumps(rec, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        for rec in (bundle.get("records") or [])
    ]
    if leaves:
        lvl = list(leaves)
        while len(lvl) > 1:
            if len(lvl) % 2 == 1:
                lvl.append(lvl[-1])
            lvl = [hashlib.sha256((lvl[i] + ":" + lvl[i + 1]).encode("utf-8")).hexdigest() for i in range(0, len(lvl), 2)]
        calc_root = lvl[0]
    else:
        calc_root = hashlib.sha256(b"empty-l3-bundle").hexdigest()

    if calc_root != envelope_bundle.get("merkle_root") or calc_root != bundle.get("merkle_root"):
        raise ValueError("L3 PQC bundle Merkle root mismatch")

    return {
        "ok": True,
        "verified": True,
        "merkle_root": calc_root,
        "records_count": len(bundle.get("records") or []),
        "records": bundle.get("records") or [],
    }
