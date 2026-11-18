"""L3 — вечный слой Nocturne: Arweave + Solana.

Что делает, по шагам:
  1. У каждой новой активной записи памяти появляется СВОЙ ключ AES-256-GCM
     (таблица anchor_key). Содержание шифруется этим ключом.
  2. Шифротексты новых записей и «квитанции забвения» (записи, ключ которых
     уничтожен при revoke) собираются в один пакет.
  3. Из пакета строится дерево Меркла. Схема та же, что у якоря памяти
     центрального сайта (codeofdigitaleternity.com/src/lib/memory-anchor.ts):
         лист записи   = SHA-256( 0x00 ‖ байты записи )
         лист забвения = SHA-256( 0x02 ‖ UTF-8 "AIFA-FORGET|<id>|<время>" )
         узел          = SHA-256( 0x01 ‖ левый ‖ правый )
     Нечётный узел уровня поднимается выше без пары (не дублируется).
     Байты записи = nonce (12 байт) ‖ шифротекст.
  4. Пакет (только шифротекст, без открытого текста и без ключей) уходит
     в Arweave, корень — в Solana заметкой Memo.

Что это даёт человеку:
  * доказательство, что память не подменили задним числом (корень в цепи);
  * право на забвение в неизменяемом хранилище: уничтожили ключ записи —
    её шифротекст в Arweave навсегда шум, остальная память цела;
  * квитанция забвения сама закрепляется в следующем корне.

Деньги: заливка в Arweave до 100 КиБ через Turbo бесплатна; больше — отказ,
пока явно не разрешено (allow_paid_arweave). Заметка Memo в Solana стоит
порядка 0,000005 SOL. Основная сеть Solana — только явным network="mainnet".
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import keyvault
from .memory import Memory
from .store import now_iso
from .i18n import t

# ---------------------------------------------------------------- схема L3

L3_SCHEMA = """
CREATE TABLE IF NOT EXISTS l3_anchor (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    root_hex      TEXT NOT NULL,
    leaf_count    INTEGER NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    bundle_bytes  INTEGER NOT NULL,
    arweave_tx    TEXT,
    solana_sig    TEXT,
    solana_slot   INTEGER,
    network       TEXT,
    memo          TEXT
);
CREATE TABLE IF NOT EXISTS l3_leaf (
    anchor_id  TEXT NOT NULL,
    position   INTEGER NOT NULL,
    kind       TEXT NOT NULL,          -- 'record' | 'forget'
    memory_id  TEXT NOT NULL,
    leaf_hex   TEXT NOT NULL,
    PRIMARY KEY (anchor_id, position)
);
CREATE INDEX IF NOT EXISTS l3_leaf_memory ON l3_leaf (memory_id, kind);
"""

MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
MEMO_PREFIX = "PADAM-NOCTURNE v1"
RPC = {
    "devnet": "https://api.devnet.solana.com",
    "mainnet": "https://api.mainnet-beta.solana.com",
}
TURBO_FREE_LIMIT = 100 * 1024          # байт; больше — платно
DESTROYED = "destroyed"


def ensure_schema(memory: Memory) -> None:
    memory.store.script(L3_SCHEMA)
    # 0.4.12: штамп OpenTimestamps пакета (второй свидетель — Bitcoin). Столбец добавляется к прежним базам.
    столбцы = {r[1] for r in memory.store.query("PRAGMA table_info(l3_anchor)")}
    if "ots" not in столбцы:
        memory.store.execute("ALTER TABLE l3_anchor ADD COLUMN ots BLOB")


# ---------------------------------------------------------------- Меркл

def leaf_record(record_bytes: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + record_bytes).digest()


def leaf_record_bound(memory_id: str, record_bytes: bytes) -> bytes:
    """ARK-03: лист записи Меркла, жёстко привязанный к memory_id (подмена record.id ломает корень)."""
    return hashlib.sha256(b"\x00" + str(memory_id).encode("utf-8") + b"\x1f" + record_bytes).digest()


def leaf_forget(memory_id: str, destroyed_at: str) -> bytes:
    return hashlib.sha256(
        b"\x02" + f"AIFA-FORGET|{memory_id}|{destroyed_at}".encode("utf-8")).digest()


def node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise ValueError(t("пустое дерево: нечего закреплять", "empty tree: nothing to anchor"))
    level = list(leaves)
    while len(level) > 1:
        nxt = [node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])          # нечётный поднимается без пары
        level = nxt
    return level[0]


def merkle_proof(leaves: list[bytes], index: int) -> list[tuple[str, str]]:
    """Путь от листа к корню: список (сторона соседа 'L'|'R', хеш hex)."""
    if not 0 <= index < len(leaves):
        raise IndexError(index)
    path, level, i = [], list(leaves), index
    while len(level) > 1:
        pair = i ^ 1
        if pair < len(level):
            path.append(("L" if pair < i else "R", level[pair].hex()))
        nxt = [node(level[k], level[k + 1]) for k in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level, i = nxt, i // 2
    return path


def verify_proof(leaf: bytes, path: list[tuple[str, str]], root: bytes) -> bool:
    h = leaf
    for side, sib_hex in path:
        sib = bytes.fromhex(sib_hex)
        h = node(sib, h) if side == "L" else node(h, sib)
    return h == root


# ---------------------------------------------------------------- шифрование

def encrypt(content: str, key: bytes) -> bytes:
    """nonce(12) ‖ шифротекст+тег. Ключ — 32 байта, свой у каждой записи."""
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, content.encode("utf-8"), None)


def decrypt(record_bytes: bytes, key: bytes) -> str:
    return AESGCM(key).decrypt(record_bytes[:12], record_bytes[12:], None).decode("utf-8")


def ensure_keys(memory: Memory) -> int:
    """Выдать свой ключ каждой активной записи, у которой его ещё нет."""
    rows = memory.store.query(
        """SELECT m.id FROM memory m LEFT JOIN anchor_key k ON k.memory_id = m.id
           WHERE m.user_id = ? AND m.status = 'active' AND m.content IS NOT NULL
             AND k.memory_id IS NULL""", (memory.user_id,))
    for r in rows:
        # с включённой защитой (keyvault) ключ ложится в базу завёрнутым паролем, иначе — hex, как прежде
        memory.store.execute(
            """INSERT INTO anchor_key (memory_id, key_ref, shard_count, threshold, created_at)
               VALUES (?, ?, 1, 1, ?)""",
            (r["id"], keyvault.store_form(memory, r["id"], secrets.token_bytes(32)), now_iso()))
    return len(rows)


def destroy_key(memory: Memory, memory_id: str) -> None:
    """Затереть сам ключ (а не только поставить отметку): без ключа шифротекст — шум."""
    memory.store.execute(
        """UPDATE anchor_key SET key_ref = ?, destroyed_at = COALESCE(destroyed_at, ?)
           WHERE memory_id = ?""", (DESTROYED, now_iso(), memory_id))


def key_for(memory: Memory, memory_id: str) -> Optional[bytes]:
    r = memory.store.one("SELECT key_ref FROM anchor_key WHERE memory_id = ?", (memory_id,))
    if not r or r["key_ref"] == DESTROYED:
        return None
    return keyvault.read_form(memory, memory_id, r["key_ref"])


# ---------------------------------------------------------------- пакет

@dataclass
class Bundle:
    payload: bytes
    leaves: list[bytes]
    entries: list[tuple[str, str]]          # (kind, memory_id) по порядку листьев
    root: bytes = field(default=b"")


def build_bundle(memory: Memory) -> Optional[Bundle]:
    """Новые активные записи (ещё без якоря) и неотмеченные забвения → пакет."""
    ensure_schema(memory)
    ensure_keys(memory)
    recs = memory.store.query(
        """SELECT m.id, m.content, m.created_at FROM memory m
           JOIN anchor_key k ON k.memory_id = m.id
           WHERE m.user_id = ? AND m.status = 'active' AND m.content IS NOT NULL
             AND m.anchor_tx IS NULL AND k.key_ref <> ?
           ORDER BY m.created_at, m.id""", (memory.user_id, DESTROYED))
    forgets = memory.store.query(
        """SELECT k.memory_id, k.destroyed_at FROM anchor_key k
           JOIN memory m ON m.id = k.memory_id
           WHERE m.user_id = ? AND k.destroyed_at IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM l3_leaf l
                             WHERE l.memory_id = k.memory_id AND l.kind = 'forget')
             -- квитанция нужна только тому, что уже лежит в цепи: забывать
             -- неотправленное в Arweave нечего, а лишний лист — лишний шум
             AND EXISTS (SELECT 1 FROM l3_leaf l
                         WHERE l.memory_id = k.memory_id AND l.kind = 'record')
           ORDER BY k.destroyed_at, k.memory_id""", (memory.user_id,))
    if not recs and not forgets:
        return None
    items, leaves, entries = [], [], []
    for r in recs:
        blob = encrypt(r["content"], key_for(memory, r["id"]))
        # Публичный пакет хранит только день записи: время до микросекунды рассказывало миру,
        # в какие часы человек говорит с памятью. Листья от даты не зависят.
        items.append({"id": r["id"], "created_at": (r["created_at"] or "")[:10],
                      "data": base64.b64encode(blob).decode()})
        leaves.append(leaf_record_bound(r["id"], blob))
        entries.append(("record", r["id"]))
    fitems = []
    for f in forgets:
        fitems.append({"id": f["memory_id"], "destroyed_at": f["destroyed_at"]})
        leaves.append(leaf_forget(f["memory_id"], f["destroyed_at"]))
        entries.append(("forget", f["memory_id"]))
    root = merkle_root(leaves)
    payload = json.dumps({
        "format": "padam-l3/2",
        "content_basis": "redacted_at_ingest",
        "created_at": now_iso(),
        "owner": hashlib.sha256(memory.user_id.encode()).hexdigest(),
        "scheme": "record leaf=SHA256(0x00||id||0x1f||base64decode(data)); forget leaf=SHA256(0x02||'AIFA-FORGET|id|destroyed_at'); "
                  "node=SHA256(0x01||L||R); odd node promoted; leaves: records then forgets, in listed order",
        "records": items,
        "forgets": fitems,
        "root": root.hex(),
    }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return Bundle(payload=payload, leaves=leaves, entries=entries, root=root)


# ---------------------------------------------------------------- Arweave

def turbo_upload(payload: bytes, wallet_path: str, tags: dict[str, str],
                 sdk_dir: Optional[str] = None) -> str:
    """Заливка через Turbo (Node + @ardrive/turbo-sdk). Возвращает id записи."""
    script = Path(__file__).with_name("turbo_upload.mjs")
    sdk = sdk_dir or os.environ.get("PADAM_TURBO_SDK_DIR", "")
    tmp = Path(os.environ.get("TEMP", ".")) / f"padam_l3_{uuid.uuid4().hex}.json"
    tmp.write_bytes(payload)
    try:
        out = subprocess.run(
            ["node", str(script), str(tmp), wallet_path, json.dumps(tags), sdk],
            capture_output=True, text=True, timeout=180)
    finally:
        tmp.unlink(missing_ok=True)
    if out.returncode != 0:
        raise RuntimeError("Turbo: " + (out.stderr or out.stdout).strip()[-400:])
    return json.loads(out.stdout.strip().splitlines()[-1])["id"]


# ---------------------------------------------------------------- Solana

def _rpc(url: str, method: str, params: list):
    req = urllib.request.Request(url, data=json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"})
    resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
    if "error" in resp:
        raise RuntimeError(f"Solana {method}: {resp['error']}")
    return resp["result"]


def solana_memo(memo: str, keypair_path: str, network: str = "devnet") -> tuple[str, int]:
    """Отправить заметку Memo, дождаться подтверждения. Возвращает (подпись, слот)."""
    # имя сети проверяется ДО импорта solders: защита от случайного mainnet не должна зависеть
    # от того, установлен ли extra [l3] (08.10.2026: в установке без [l3] тест падал на импорте)
    if network not in RPC:
        raise ValueError(t(f"сеть {network!r}: допустимо devnet или mainnet", f"network {network!r}: use devnet or mainnet"))
    from solders.hash import Hash
    from solders.instruction import AccountMeta, Instruction
    from solders.keypair import Keypair
    from solders.message import Message
    from solders.pubkey import Pubkey
    from solders.transaction import Transaction

    url = RPC[network]
    kp = Keypair.from_bytes(bytes(json.loads(Path(keypair_path).read_text())))
    ix = Instruction(Pubkey.from_string(MEMO_PROGRAM), memo.encode("utf-8"),
                     [AccountMeta(kp.pubkey(), is_signer=True, is_writable=True)])
    bh = Hash.from_string(_rpc(url, "getLatestBlockhash",
                               [{"commitment": "finalized"}])["value"]["blockhash"])
    tx = Transaction([kp], Message.new_with_blockhash([ix], kp.pubkey(), bh), bh)
    sig = _rpc(url, "sendTransaction", [base64.b64encode(bytes(tx)).decode(),
                                        {"encoding": "base64", "preflightCommitment": "confirmed"}])
    for _ in range(60):
        st = _rpc(url, "getSignatureStatuses", [[sig]])["value"][0]
        if st and st.get("confirmationStatus") in ("confirmed", "finalized"):
            if st.get("err"):
                raise RuntimeError(t(f"транзакция упала: {st['err']}", f"transaction failed: {st['err']}"))
            return sig, int(st["slot"])
        time.sleep(2)
    raise TimeoutError(t(f"не подтверждена за 120 с: {sig}", f"not confirmed within 120 s: {sig}"))


def read_memo(sig: str, network: str = "devnet") -> str:
    """Прочитать заметку из транзакции — для независимой проверки."""
    tx = _rpc(RPC[network], "getTransaction",
              [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0,
                     "commitment": "confirmed"}])
    for line in (tx or {}).get("meta", {}).get("logMessages", []):
        if "Memo" in line and MEMO_PREFIX in line:
            return line.split('"', 1)[1].rsplit('"', 1)[0] if '"' in line else line
    raise LookupError(t("заметка PADAM-NOCTURNE в транзакции не найдена", "no PADAM-NOCTURNE memo found in the transaction"))


# ---------------------------------------------------------------- прогон

Uploader = Callable[[bytes, dict], str]
Anchorer = Callable[[str], tuple[str, int]]


def run_l3(memory: Memory, uploader: Optional[Uploader] = None,
           anchorer: Optional[Anchorer] = None, network: str = "devnet",
           allow_paid_arweave: bool = False, dry_run: bool = False,
           save_dir: Optional[str] = None,
           stamper: Optional[Callable[[bytes], bytes]] = None) -> dict:
    """Закрепить новое: пакет → Arweave → корень в Solana → штамп в Bitcoin → отметки в базе.

    stamper(sha256 пакета) -> байты .ots — второй свидетель (padam.ots.stamp). Его сбой якорь не отменяет:
    Arweave и Solana уже записаны, в отчёте появляется ots_error, штамп можно сделать позже."""
    b = build_bundle(memory)
    if b is None:
        return {"status": "nothing_new"}
    report = {"status": "dry_run" if dry_run else "anchored", "root": b.root.hex(),
              "leaves": len(b.leaves),
              "records": sum(1 for k, _ in b.entries if k == "record"),
              "forgets": sum(1 for k, _ in b.entries if k == "forget"),
              "bundle_bytes": len(b.payload), "network": network}
    if len(b.payload) > TURBO_FREE_LIMIT and not allow_paid_arweave:
        raise RuntimeError(t(f"пакет {len(b.payload)} байт > бесплатного порога Turbo {TURBO_FREE_LIMIT}: заливка платная, нужен allow_paid_arweave=True",
                             f"bundle of {len(b.payload)} bytes > Turbo free limit {TURBO_FREE_LIMIT}: the upload is paid, set allow_paid_arweave=True"))
    if dry_run:
        return report
    if uploader is None or anchorer is None:
        raise ValueError(t("нужны uploader и anchorer (или dry_run=True)", "uploader and anchorer are required (or dry_run=True)"))
    ar_tx = uploader(b.payload, {"Content-Type": "application/json", "App-Name": "PADAM-Nocturne",
                                 "Type": "padam-l3-bundle", "Merkle-Root": b.root.hex()})
    memo = f"{MEMO_PREFIX} root={b.root.hex()} n={len(b.leaves)} ar={ar_tx} d={now_iso()[:10]}"
    sig, slot = anchorer(memo)
    aid = uuid.uuid4().hex
    штамп: Optional[bytes] = None
    if stamper is not None:
        try:
            штамп = stamper(hashlib.sha256(b.payload).digest())
        except Exception as e:
            report["ots_error"] = f"{type(e).__name__}: {e}"
    if save_dir:                       # своя копия пакета у владельца — проверка без шлюза
        Path(save_dir).mkdir(parents=True, exist_ok=True)
        (Path(save_dir) / f"{aid}.json").write_bytes(b.payload)
        if штамп:                      # рядом с пакетом — как ждёт штатный `ots verify <файл>.ots`
            (Path(save_dir) / f"{aid}.json.ots").write_bytes(штамп)
    # 16.10.2026: одной транзакцией — якорь, все листья и пометки записей. Раньше каждый шаг
    # был отдельным коммитом, и сбой посередине оставлял якорь без части листьев.
    ops: list[tuple[str, tuple]] = [(
        """INSERT INTO l3_anchor (id, user_id, created_at, root_hex, leaf_count, bundle_sha256,
           bundle_bytes, arweave_tx, solana_sig, solana_slot, network, memo, ots)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (aid, memory.user_id, now_iso(), b.root.hex(), len(b.leaves),
         hashlib.sha256(b.payload).hexdigest(), len(b.payload), ar_tx, sig, slot, network, memo, штамп))]
    for pos, ((kind, mid), lf) in enumerate(zip(b.entries, b.leaves)):
        ops.append((
            "INSERT INTO l3_leaf (anchor_id, position, kind, memory_id, leaf_hex) VALUES (?,?,?,?,?)",
            (aid, pos, kind, mid, lf.hex())))
        if kind == "record":
            ops.append((
                "UPDATE memory SET anchor_tx = ?, anchor_slot = ? WHERE id = ?", (sig, slot, mid)))
    memory.store.atomic(ops)
    report.update(anchor_id=aid, arweave_tx=ar_tx, solana_sig=sig, solana_slot=slot, memo=memo,
                  bitcoin_ots="pending" if штамп else None)
    return report


GATEWAYS = ("https://arweave.net/", "https://ar-io.net/", "https://permagate.io/")


def fetch_arweave(tx: str, timeout: int = 40) -> Optional[bytes]:
    """Пакет с любого шлюза; None — шлюзы его ещё не разнесли (Turbo отдаёт с задержкой)."""
    for g in GATEWAYS:
        try:
            return urllib.request.urlopen(g + tx, timeout=timeout).read()
        except Exception:
            continue
    return None


def verify_bundle(
    payload: bytes,
    memo: str,
    *,
    attestation: Optional[dict] = None,
    expected_pubkey_hex: Optional[str] = None,
    require_owner_attestation: bool = False,
) -> dict:
    """Проверка пакета L3: пересчёт Меркла (с привязкой id для v2) + опциональная/обязательная Ed25519-аттестация."""
    d = json.loads(payload)
    fmt = d.get("format") or "padam-l3/1"
    if fmt == "padam-l3/2":
        rec_leaves = [leaf_record_bound(str(r.get("id") or ""), base64.b64decode(r["data"])) for r in d["records"]]
    else:
        rec_leaves = [leaf_record(base64.b64decode(r["data"])) for r in d["records"]]
    leaves = rec_leaves + [leaf_forget(f["id"], f["destroyed_at"]) for f in d["forgets"]]
    root = merkle_root(leaves).hex()
    in_memo = memo.split("root=", 1)[1].split()[0] if "root=" in memo else ""
    merkle_ok = (root == d.get("root") == in_memo)

    pinned_pub = (expected_pubkey_hex or os.environ.get("PADAM_ANCHOR_PUBKEY_HEX") or "").strip().lower() or None
    strict = bool(require_owner_attestation or attestation is not None or pinned_pub is not None)
    if strict:
        if attestation is None:
            return {
                "root_recomputed": root,
                "root_in_bundle": d.get("root"),
                "root_in_chain": in_memo,
                "merkle_ok": merkle_ok,
                "signature_ok": False,
                "owner_verified": False,
                "ok": False,
                "error": "owner_attestation_required",
                "records": len(d["records"]),
                "forgets": len(d["forgets"]),
            }
        att_res = verify_anchor_attestation(
            None,
            memo,
            attestation,
            expected_pubkey_hex=pinned_pub,
            require_pinned_pubkey=bool(pinned_pub is not None or require_owner_attestation),
        )
        root_matches_att = (root == attestation.get("root_hex"))
        all_ok = bool(merkle_ok and att_res.get("ok") and root_matches_att)
        return {
            "root_recomputed": root,
            "root_in_bundle": d.get("root"),
            "root_in_chain": in_memo,
            "merkle_ok": merkle_ok,
            "signature_ok": bool(att_res.get("signature_ok") and root_matches_att),
            "owner_verified": bool(all_ok and att_res.get("owner_verified")),
            "ok": all_ok,
            "error": att_res.get("error") or (None if root_matches_att else "attestation root mismatch"),
            "records": len(d["records"]),
            "forgets": len(d["forgets"]),
        }

    return {
        "root_recomputed": root,
        "root_in_bundle": d.get("root"),
        "root_in_chain": in_memo,
        "ok": merkle_ok,
        "owner_verified": False,
        "untrusted_signer": True,
        "warning": "Merkle matches payload/memo only; pass attestation and expected_pubkey_hex for owner provenance proof.",
        "records": len(d["records"]),
        "forgets": len(d["forgets"]),
    }


# ---------------------------------------------------------------- В5: локальная подпись и проверка якоря ($0, devnet)

def _attestation_message(memo: str, root_hex: str, network: str, measurement: str, slot: int) -> bytes:
    canonical = (
        f"PADAM-ANCHOR-SIG-v1|network={network}|root={root_hex}|"
        f"memo={memo}|measurement={measurement}|slot={int(slot)}"
    )
    return canonical.encode("utf-8")


def read_devnet_slot(rpc_fn: Optional[Callable[[str, str, list], object]] = None) -> int:
    """Read-only запрос текущего слота Solana devnet (стоимость $0, без ключей)."""
    caller = rpc_fn or _rpc
    res = caller(RPC["devnet"], "getSlot", [{"commitment": "confirmed"}])
    return int(res)  # type: ignore[arg-type]


def sign_anchor_attestation(
    memo: str,
    root_hex: str,
    signing_key,
    *,
    network: str = "devnet",
    measurement: str = "local-devnet-demo",
    slot: int = 0,
) -> dict:
    """Подписывает корень Меркла и заметку Memo локальным Ed25519-ключом (без сети и mainnet)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if isinstance(signing_key, (bytes, bytearray)):
        sk = Ed25519PrivateKey.from_private_bytes(bytes(signing_key))
    elif isinstance(signing_key, Ed25519PrivateKey):
        sk = signing_key
    else:
        raise TypeError("signing_key must be Ed25519PrivateKey or 32 raw bytes")

    msg = _attestation_message(memo, root_hex, network, measurement, slot)
    sig = sk.sign(msg)
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "version": 1,
        "algorithm": "ed25519",
        "network": network,
        "root_hex": root_hex,
        "memo": memo,
        "measurement": measurement,
        "slot": int(slot),
        "pubkey_hex": pub.hex(),
        "signature_hex": sig.hex(),
    }


def verify_anchor_attestation(
    payload: Optional[bytes],
    memo: str,
    attestation: dict,
    *,
    expected_pubkey_hex: Optional[str] = None,
    expected_measurement: Optional[str] = None,
    reject_mainnet: bool = False,
    require_pinned_pubkey: bool = False,
) -> dict:
    """Локально ($0) проверяет дерево Меркла пакета (если передан) и подпись Ed25519 якоря."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    net = str(attestation.get("network") or "")
    if reject_mainnet and net == "mainnet":
        return {"ok": False, "bundle_ok": None, "signature_ok": False, "error": "mainnet rejected by policy"}

    bundle_ok: Optional[bool] = None
    bundle_info: dict = {}
    if payload is not None:
        try:
            bundle_info = verify_bundle(payload, memo)
            bundle_ok = bool(bundle_info.get("ok"))
        except Exception as exc:
            return {"ok": False, "bundle_ok": False, "signature_ok": False, "error": f"bundle check failed: {exc}"}
        if not bundle_ok:
            return {"ok": False, "bundle_ok": False, "signature_ok": False, "error": "merkle root mismatch", **bundle_info}
        if bundle_info.get("root_recomputed") != attestation.get("root_hex"):
            return {"ok": False, "bundle_ok": True, "signature_ok": False, "error": "attestation root differs from bundle"}

    if attestation.get("memo") != memo:
        return {"ok": False, "bundle_ok": bundle_ok, "signature_ok": False, "error": "memo mismatch"}

    pub_hex = str(attestation.get("pubkey_hex") or "").lower()
    pinned_pub = (expected_pubkey_hex or os.environ.get("PADAM_ANCHOR_PUBKEY_HEX") or "").strip().lower()
    if require_pinned_pubkey and not pinned_pub:
        return {"ok": False, "bundle_ok": bundle_ok, "signature_ok": False, "owner_verified": False, "error": "expected_pubkey_hex_required"}
    if pinned_pub and pub_hex != pinned_pub:
        return {"ok": False, "bundle_ok": bundle_ok, "signature_ok": False, "owner_verified": False, "error": "unexpected pubkey"}

    meas = str(attestation.get("measurement") or "")
    if expected_measurement and meas != expected_measurement:
        return {"ok": False, "bundle_ok": bundle_ok, "signature_ok": False, "error": "unexpected enclave measurement"}

    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        sig = bytes.fromhex(str(attestation.get("signature_hex") or ""))
        msg = _attestation_message(
            str(attestation.get("memo") or ""),
            str(attestation.get("root_hex") or ""),
            net,
            meas,
            int(attestation.get("slot") or 0),
        )
        pk.verify(sig, msg)
        sig_ok = True
        err = None
    except (ValueError, InvalidSignature) as exc:
        sig_ok = False
        err = f"signature verification failed: {exc}"

    ok = bool(sig_ok and (bundle_ok is not False))
    return {
        "ok": ok,
        "bundle_ok": bundle_ok,
        "signature_ok": sig_ok,
        "owner_verified": bool(ok and pinned_pub),
        "signer_pinned": bool(pinned_pub),
        "network": net,
        "slot": int(attestation.get("slot") or 0),
        "error": err,
    }

