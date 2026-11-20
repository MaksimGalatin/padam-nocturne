# -*- coding: utf-8 -*-
"""Сверхкомпактная почасовая упаковка переписок для Arweave и Solana Merkle Proof (PA1H v1).

Решает главную проблему прямых выгрузок (JSON/Markdown без сжатия и перезаливки целого 68 КБ
файла при каждой реплике):
1. Берётся только дельта за 1 конкретный час (`YYYY-MM-DDTHH`, UTC), с контролем SHA-256
   в `chat_chain_checkpoint` — неизменённые или уже запечатанные часы повторно не грузятся.
2. Повторяющиеся поля (`agent_id`, `role`, полные 29-байтные ISO timestamps) сжимаются
   в почасовой словарь и относительные сдвиги секунд `0..3599` от начала часа.
3. Поток автоматически жмётся лучшим кодером (`brotli` q=11, `lzma`, `zlib` level=9)
   и опционально шифруется AES-256-GCM с компактным бинарным заголовком `PA1H` (40 байт
   вместо base64+33% JSON-обёртки).
4. Для каждого часа и каждых суток строится дерево Меркла (`SHA-256`) для 1 транзакции Solana Memo.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import zlib
import lzma
from datetime import datetime, timezone
from typing import Any

from . import integrity

try:
    import brotli as _brotli
except Exception:
    _brotli = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except Exception:
    _AESGCM = None

_MAGIC = b"PA1H"
_ALGO_NONE = 0
_ALGO_ZLIB = 1
_ALGO_LZMA = 2
_ALGO_BROTLI = 3
_ALGO_NAMES = {0: "raw", 1: "zlib", 2: "lzma", 3: "brotli"}


def ensure_schema(memory: Any) -> None:
    with memory.store._lock:
        memory.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS chat_chain_checkpoint (
                user_id           TEXT NOT NULL,
                hour_key          TEXT NOT NULL,
                agent_id          TEXT NOT NULL DEFAULT '*',
                msg_count         INTEGER NOT NULL DEFAULT 0,
                first_ts          TEXT NOT NULL DEFAULT '',
                last_ts           TEXT NOT NULL DEFAULT '',
                content_sha256    TEXT NOT NULL,
                merkle_root_hex   TEXT NOT NULL,
                raw_bytes         INTEGER NOT NULL DEFAULT 0,
                packed_bytes      INTEGER NOT NULL DEFAULT 0,
                compression_algo  TEXT NOT NULL DEFAULT 'brotli',
                encrypted         INTEGER NOT NULL DEFAULT 1,
                arweave_tx        TEXT,
                solana_sig        TEXT,
                memo              TEXT NOT NULL DEFAULT '',
                updated_at        TEXT NOT NULL,
                PRIMARY KEY (user_id, hour_key, agent_id)
            );
            CREATE INDEX IF NOT EXISTS idx_chat_chain_user_hour
                ON chat_chain_checkpoint (user_id, hour_key DESC);
            """
        )
        memory.store.conn.commit()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_iso(ts: str) -> datetime:
    s = str(ts or "").strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _norm_hour_key(hour_key: str) -> tuple[str, int]:
    """Приводит YYYY-MM-DDTHH к канону и возвращает число часов с Unix Epoch."""
    clean = str(hour_key or "").strip().replace(" ", "T")[:13]
    if len(clean) == 10:
        clean += "T00"
    dt = datetime.strptime(clean, "%Y-%m-%dT%H").replace(tzinfo=timezone.utc)
    return clean, int(dt.timestamp() // 3600)


def _merkle_root(leaves_hex: list[str]) -> str:
    if not leaves_hex:
        return hashlib.sha256(b"PA1H-EMPTY-MERKLE").hexdigest()
    layer = [bytes.fromhex(h) for h in leaves_hex]
    while len(layer) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        layer = nxt
    return layer[0].hex()


def _compress_best(raw: bytes) -> tuple[int, bytes]:
    candidates: list[tuple[int, bytes]] = [(_ALGO_NONE, raw)]
    try:
        candidates.append((_ALGO_ZLIB, zlib.compress(raw, level=9)))
    except Exception:
        pass
    try:
        candidates.append((_ALGO_LZMA, lzma.compress(raw, preset=9)))
    except Exception:
        pass
    if _brotli is not None:
        try:
            candidates.append((_ALGO_BROTLI, _brotli.compress(raw, quality=11)))
        except Exception:
            pass
    best_algo, best_data = min(candidates, key=lambda x: len(x[1]))
    return best_algo, best_data


def _decompress(algo: int, data: bytes) -> bytes:
    if algo == _ALGO_NONE:
        return data
    if algo == _ALGO_ZLIB:
        return zlib.decompress(data)
    if algo == _ALGO_LZMA:
        return lzma.decompress(data)
    if algo == _ALGO_BROTLI:
        if _brotli is None:
            raise RuntimeError("brotli module is required to unpack brotli PA1H stream")
        return _brotli.decompress(data)
    raise ValueError(f"Unknown PA1H compression algo: {algo}")


def _derive_32b_key(memory: Any, explicit_key: bytes | None = None) -> bytes:
    if explicit_key is not None:
        if len(explicit_key) != 32:
            return hashlib.sha256(explicit_key).digest()
        return explicit_key
    raw_k, _ = integrity.owner_key(memory.store)
    return hashlib.sha256(b"PA1H-CHAT-ENC-V1|" + raw_k).digest()


def pack_messages_binary(
    messages: list[dict[str, Any]],
    *,
    hour_key: str,
    encrypt: bool = True,
    key_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Упаковывает список сообщений за 1 час в сверхкомпактный формат PA1H (+опц. AES-256-GCM)."""
    hk, hour_epoch = _norm_hour_key(hour_key)
    hour_start_sec = hour_epoch * 3600

    agents_dict: list[str] = []
    agent_idx_map: dict[str, int] = {}
    role_map = {"user": 0, "assistant": 1, "system": 2}
    compact_rows: list[list[Any]] = []
    leaf_hashes: list[str] = []
    md_lines: list[str] = []

    sorted_msgs = sorted(messages, key=lambda m: (str(m.get("created_at") or ""), int(m.get("seq") or 0)))
    for m in sorted_msgs:
        aid = str(m.get("agent_id") or "aifa")
        if aid not in agent_idx_map:
            agent_idx_map[aid] = len(agents_dict)
            agents_dict.append(aid)
        aidx = agent_idx_map[aid]
        role = str(m.get("role") or "user").lower()
        ridx = role_map.get(role, 0)
        ts_str = str(m.get("created_at") or (hk + ":00:00+00:00"))
        dt = _parse_iso(ts_str)
        delta_sec = max(0, min(3599, int(dt.timestamp()) - hour_start_sec))
        body = str(m.get("content") or "")
        compact_rows.append([aidx, ridx, delta_sec, body])

        msg_id = str(m.get("id") or "")
        leaf_pre = f"PADAM-CHAT-MSG-V1|{msg_id}|{aid}|{role}|{ts_str}|{body}".encode("utf-8")
        leaf_hashes.append(hashlib.sha256(leaf_pre).hexdigest())
        lbl = str(m.get("author_label") or aid)
        md_lines.append(f"### [{ts_str}] {lbl} ({role})\n{body}\n")

    canonical_struct = {"h": hk, "a": agents_dict, "m": compact_rows}
    compact_json = json.dumps(canonical_struct, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    raw_json_baseline = json.dumps(
        [{"id": m.get("id"), "agent_id": m.get("agent_id"), "role": m.get("role"),
          "author_label": m.get("author_label"), "created_at": m.get("created_at"), "content": m.get("content")}
         for m in sorted_msgs],
        ensure_ascii=False,
    ).encode("utf-8")
    raw_md_baseline = "\n".join(md_lines).encode("utf-8")

    algo, compressed = _compress_best(compact_json)
    content_sha = hashlib.sha256(compact_json).hexdigest()
    merkle_hex = _merkle_root(leaf_hashes)

    flags = 0
    payload_bytes = compressed
    if encrypt:
        if key_bytes is None or len(key_bytes) != 32:
            raise ValueError("32-byte AES-256 key is required when encrypt=True")
        if _AESGCM is None:
            raise RuntimeError("cryptography AESGCM is unavailable")
        flags |= 0x01
        nonce = os.urandom(12)
        aad = struct.pack(">4sBBHI", _MAGIC, flags, algo, len(compact_rows) & 0xFFFF, hour_epoch & 0xFFFFFFFF)
        ct = _AESGCM(key_bytes).encrypt(nonce, compressed, aad)
        payload_bytes = nonce + ct

    header = struct.pack(">4sBBHI", _MAGIC, flags, algo, len(compact_rows) & 0xFFFF, hour_epoch & 0xFFFFFFFF)
    blob = header + payload_bytes

    algo_name = _ALGO_NAMES.get(algo, "raw")
    raw_ref = max(1, len(raw_md_baseline), len(raw_json_baseline))
    ratio_vs_md = round(len(blob) / max(1, len(raw_md_baseline)), 4) if raw_md_baseline else 1.0
    ratio_vs_json = round(len(blob) / max(1, len(raw_json_baseline)), 4) if raw_json_baseline else 1.0

    # Ориентир: Turbo / Irys пускает транзакции до 100 KiB БЕСПЛАТНО ($0)
    free_irys_eligible = len(blob) <= 100 * 1024
    return {
        "format": "PA1H/1",
        "hour_key": hk,
        "msg_count": len(compact_rows),
        "agents": agents_dict,
        "compression_algo": algo_name,
        "encrypted": bool(encrypt),
        "content_sha256": content_sha,
        "merkle_root_hex": merkle_hex,
        "raw_markdown_bytes": len(raw_md_baseline),
        "raw_json_bytes": len(raw_json_baseline),
        "compact_json_bytes": len(compact_json),
        "packed_bytes": len(blob),
        "ratio_vs_markdown": ratio_vs_md,
        "ratio_vs_json": ratio_vs_json,
        "savings_pct_vs_json": round((1.0 - ratio_vs_json) * 100, 1) if raw_json_baseline else 0.0,
        "free_arweave_under_100kb": free_irys_eligible,
        "solana_memo": f"PADAM-CHAT-H1|h={hk}|n={len(compact_rows)}|r={merkle_hex[:32]}|b={len(blob)}",
        "blob_bytes": blob,
        "blob_b64": base64.urlsafe_b64encode(blob).decode("ascii"),
    }


def unpack_messages_binary(blob: bytes, *, key_bytes: bytes | None = None) -> dict[str, Any]:
    """Распаковывает и (при шифровании) расшифровывает бинарный почасовой пакет PA1H."""
    if len(blob) < 12 or blob[:4] != _MAGIC:
        raise ValueError("Invalid PA1H header")
    magic, flags, algo, msg_count, hour_epoch = struct.unpack(">4sBBHI", blob[:12])
    body = blob[12:]
    encrypted = bool(flags & 0x01)
    if encrypted:
        if key_bytes is None or len(key_bytes) != 32:
            raise ValueError("32-byte key_bytes required to decrypt PA1H blob")
        if len(body) < 28:
            raise ValueError("Truncated encrypted PA1H payload")
        nonce, ct = body[:12], body[12:]
        aad = struct.pack(">4sBBHI", magic, flags, algo, msg_count, hour_epoch)
        compressed = _AESGCM(key_bytes).decrypt(nonce, ct, aad)
    else:
        compressed = body
    raw_json = _decompress(algo, compressed)
    struct_obj = json.loads(raw_json.decode("utf-8"))
    agents = list(struct_obj.get("a") or [])
    hk = str(struct_obj.get("h") or "")
    role_rev = {0: "user", 1: "assistant", 2: "system"}
    hour_start_sec = hour_epoch * 3600
    restored: list[dict[str, Any]] = []
    for row in struct_obj.get("m") or []:
        aidx, ridx, dsec, txt = int(row[0]), int(row[1]), int(row[2]), str(row[3])
        aid = agents[aidx] if 0 <= aidx < len(agents) else "aifa"
        ts = datetime.fromtimestamp(hour_start_sec + dsec, tz=timezone.utc).isoformat(timespec="seconds")
        restored.append({"agent_id": aid, "role": role_rev.get(ridx, "user"), "created_at": ts, "content": txt})
    return {
        "hour_key": hk,
        "msg_count": len(restored),
        "compression_algo": _ALGO_NAMES.get(algo, "raw"),
        "encrypted": encrypted,
        "messages": restored,
    }


def export_hourly_delta(
    memory: Any,
    *,
    hour_key: str,
    agent_id: str | None = None,
    include_workers: bool = False,
    encrypt: bool = True,
    record_checkpoint: bool = True,
) -> dict[str, Any]:
    """Выгружает дельту всех сообщений за конкретный час (UTC), проверяя изменение SHA-256."""
    ensure_schema(memory)
    hk, _ = _norm_hour_key(hour_key)
    ag_filter = (str(agent_id or "").strip()) or None
    ag_key = ag_filter or "*"

    sql = (
        "SELECT m.id, m.agent_id, m.seq, m.role, m.author_label, m.content, m.created_at "
        "FROM chat_message m JOIN chat_thread t ON t.id = m.thread_id "
        "WHERE m.user_id = ? AND substr(m.created_at, 1, 13) = ? "
    )
    params: list[Any] = [memory.user_id, hk]
    if not include_workers:
        sql += "AND t.is_worker = 0 "
    if ag_filter:
        sql += "AND m.agent_id = ? "
        params.append(ag_filter)
    sql += "ORDER BY m.created_at ASC, m.seq ASC"
    rows = [dict(r) for r in memory.store.query(sql, tuple(params))]
    if not rows:
        return {"ok": True, "hour_key": hk, "agent_id": ag_key, "empty": True, "unchanged": True, "msg_count": 0}

    key_b = _derive_32b_key(memory) if encrypt else None
    packed = pack_messages_binary(rows, hour_key=hk, encrypt=encrypt, key_bytes=key_b)
    prev = memory.store.one(
        "SELECT content_sha256, arweave_tx, solana_sig FROM chat_chain_checkpoint "
        "WHERE user_id = ? AND hour_key = ? AND agent_id = ?",
        (memory.user_id, hk, ag_key),
    )
    unchanged = bool(prev and prev["content_sha256"] == packed["content_sha256"])

    if record_checkpoint and not unchanged:
        now = _utc_now_iso()
        with memory.store._lock:
            memory.store.conn.execute(
                """INSERT INTO chat_chain_checkpoint
                   (user_id, hour_key, agent_id, msg_count, first_ts, last_ts, content_sha256,
                    merkle_root_hex, raw_bytes, packed_bytes, compression_algo, encrypted, memo, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(user_id, hour_key, agent_id) DO UPDATE SET
                   msg_count=excluded.msg_count, first_ts=excluded.first_ts, last_ts=excluded.last_ts,
                   content_sha256=excluded.content_sha256, merkle_root_hex=excluded.merkle_root_hex,
                   raw_bytes=excluded.raw_bytes, packed_bytes=excluded.packed_bytes,
                   compression_algo=excluded.compression_algo, encrypted=excluded.encrypted,
                   memo=excluded.memo, updated_at=excluded.updated_at""",
                (
                    memory.user_id, hk, ag_key, packed["msg_count"],
                    str(rows[0].get("created_at") or ""), str(rows[-1].get("created_at") or ""),
                    packed["content_sha256"], packed["merkle_root_hex"],
                    packed["raw_json_bytes"], packed["packed_bytes"],
                    packed["compression_algo"], 1 if encrypt else 0,
                    packed["solana_memo"], now,
                ),
            )
            memory.store.conn.commit()

    out = {k: v for k, v in packed.items() if k != "blob_bytes"}
    out.update({
        "ok": True,
        "empty": False,
        "unchanged": unchanged,
        "agent_id": ag_key,
        "already_arweave_tx": prev["arweave_tx"] if prev else None,
        "already_solana_sig": prev["solana_sig"] if prev else None,
    })
    return out


def benchmark_hourly_compaction(memory: Any, *, max_hours: int = 48, include_workers: bool = False) -> dict[str, Any]:
    """Считает честный замер экономии Arweave по живым часовым бакетам БД (без записи в сеть)."""
    sql = (
        "SELECT DISTINCT substr(m.created_at, 1, 13) AS hk "
        "FROM chat_message m JOIN chat_thread t ON t.id = m.thread_id "
        "WHERE m.user_id = ? AND length(m.created_at) >= 13 "
    )
    if not include_workers:
        sql += "AND t.is_worker = 0 "
    sql += "ORDER BY hk DESC LIMIT ?"
    hours = [r["hk"] for r in memory.store.query(sql, (memory.user_id, max(1, min(int(max_hours), 240)))) if r["hk"]]

    tot_msgs = 0
    tot_md = 0
    tot_json = 0
    tot_packed = 0
    free_hours = 0
    samples: list[dict[str, Any]] = []
    key_b = _derive_32b_key(memory)

    for hk in hours:
        try:
            _norm_hour_key(hk)
        except Exception:
            continue
        rows = [
            dict(r) for r in memory.store.query(
                "SELECT m.id, m.agent_id, m.seq, m.role, m.author_label, m.content, m.created_at "
                "FROM chat_message m JOIN chat_thread t ON t.id = m.thread_id "
                "WHERE m.user_id = ? AND substr(m.created_at, 1, 13) = ? "
                + ("" if include_workers else "AND t.is_worker = 0 ")
                + "ORDER BY m.created_at ASC, m.seq ASC",
                (memory.user_id, hk),
            )
        ]
        if not rows:
            continue
        res = pack_messages_binary(rows, hour_key=hk, encrypt=True, key_bytes=key_b)
        tot_msgs += res["msg_count"]
        tot_md += res["raw_markdown_bytes"]
        tot_json += res["raw_json_bytes"]
        tot_packed += res["packed_bytes"]
        if res["free_arweave_under_100kb"]:
            free_hours += 1
        if len(samples) < 12:
            samples.append({
                "hour_key": hk,
                "msg_count": res["msg_count"],
                "raw_json_bytes": res["raw_json_bytes"],
                "raw_markdown_bytes": res["raw_markdown_bytes"],
                "packed_bytes": res["packed_bytes"],
                "compression_algo": res["compression_algo"],
                "savings_pct_vs_json": res["savings_pct_vs_json"],
                "free_arweave_under_100kb": res["free_arweave_under_100kb"],
            })

    avg_ratio = round(tot_packed / max(1, tot_json), 4) if tot_json else 1.0
    return {
        "hours_measured": len(hours),
        "free_hours_under_100kb": free_hours,
        "total_messages": tot_msgs,
        "total_raw_markdown_bytes": tot_md,
        "total_raw_json_bytes": tot_json,
        "total_packed_bytes": tot_packed,
        "overall_savings_pct_vs_json": round((1.0 - avg_ratio) * 100, 1) if tot_json else 0.0,
        "compression_factor": round(tot_json / max(1, tot_packed), 2) if tot_packed else 1.0,
        "samples": samples,
    }
