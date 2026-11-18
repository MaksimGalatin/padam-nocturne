"""Второй свидетель вечного слоя: отпечаток пакета L3 закрепляется в Bitcoin через OpenTimestamps.

Зачем. Корень Меркла памяти уже лежит в Solana (заметка Memo). Второй, независимый свидетель — блокчейн
Bitcoin: если с одной сетью что-то случится, доказательство «память не переписали задним числом» останется.

Что уходит наружу: только SHA-256 пакета с «солью» (16 случайных байт), как делает официальный клиент `ots` —
календарь не видит даже сам отпечаток пакета, не то что содержимое. Бесплатно, без аккаунта и без кошелька:
календари собирают отпечатки со всего мира в одну транзакцию Bitcoin. Через несколько часов штамп можно
«дозреть» (`upgrade`) — в нём появляется номер блока Bitcoin.

Проверка без нас: пакет скачивается из Arweave, штамп лежит рядом (`<id>.json.ots`), дальше штатный
`ots verify <id>.json.ots` или любой проверяющий OpenTimestamps.

Нужен пакет `opentimestamps` (LGPL-3.0): `pip install padam-nocturne[l3]`.
"""
from __future__ import annotations

import hashlib
import io
import os
from typing import Iterable
from .i18n import t

# Общественные календари — те же, что у официального клиента `ots` по умолчанию.
CALENDARS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
)


class OtsError(RuntimeError):
    pass


def _lib():
    try:
        from opentimestamps.core import notary, op, serialize, timestamp  # noqa: F401
        from opentimestamps import calendar  # noqa: F401
    except ImportError as e:                                    # pragma: no cover — зависит от установки
        raise OtsError(t("нужен пакет opentimestamps: pip install padam-nocturne[l3]",
                          "the opentimestamps package is required: pip install padam-nocturne[l3]")) from e
    return notary, op, serialize, timestamp, calendar


def stamp(digest: bytes, calendars: Iterable[str] = CALENDARS, timeout: int = 15, submit=None) -> bytes:
    """Штамп OpenTimestamps для SHA-256 `digest` (32 байта). Возвращает байты файла .ots.

    submit(url, msg, timeout) -> Timestamp — для тестов без сети; по умолчанию RemoteCalendar(url).submit."""
    if len(digest) != 32:
        raise OtsError(t("нужен SHA-256: 32 байта", "a SHA-256 digest is required: 32 bytes"))
    notary, op, serialize, timestamp, calendar = _lib()
    файл = timestamp.DetachedTimestampFile(op.OpSHA256(), timestamp.Timestamp(digest))
    вершина = файл.timestamp.ops.add(op.OpAppend(os.urandom(16))).ops.add(op.OpSHA256())
    отправить = submit or (lambda url, msg, t: calendar.RemoteCalendar(url).submit(msg, timeout=t))
    принято, ошибки = 0, []
    for url in calendars:
        try:
            вершина.merge(отправить(url, вершина.msg, timeout))
            принято += 1
        except Exception as e:                                  # календарь недоступен — пробуем следующий
            ошибки.append(f"{url}: {type(e).__name__}")
    if not принято:
        raise OtsError(t("ни один календарь OpenTimestamps не принял отпечаток: ",
                      "no OpenTimestamps calendar accepted the digest: ") + "; ".join(ошибки))
    buf = io.BytesIO()
    файл.serialize(serialize.StreamSerializationContext(buf))
    return buf.getvalue()


def _read(ots_bytes: bytes):
    notary, op, serialize, timestamp, calendar = _lib()
    return timestamp.DetachedTimestampFile.deserialize(serialize.StreamDeserializationContext(io.BytesIO(ots_bytes)))


def info(ots_bytes: bytes) -> dict:
    """Неверифицированные локальные метаданные .ots (НЕ является доказательством против цепи Bitcoin; используйте verify())."""
    notary = _lib()[0]
    d = _read(ots_bytes)
    ждут = sorted({a.uri for _, a in d.timestamp.all_attestations() if isinstance(a, notary.PendingAttestation)})
    блоки = sorted({a.height for _, a in d.timestamp.all_attestations()
                    if isinstance(a, notary.BitcoinBlockHeaderAttestation)})
    return {
        "digest": d.file_digest.hex(),
        "pending": ждут,
        "bitcoin_blocks": блоки,
        "unverified_metadata": True,
        "bitcoin_proof_verified": False,
    }


def matches(ots_bytes: bytes, payload: bytes) -> bool:
    """Проверяет только заголовок file_digest против SHA-256 (не проверяет дерево и Bitcoin header)."""
    return _read(ots_bytes).file_digest == hashlib.sha256(payload).digest()


def verify(ots_bytes: bytes, payload: bytes, *, block_header_fn=None) -> dict:
    """OTS-01: криптографически обходит дерево операций OpenTimestamps и сверяет BitcoinBlockHeaderAttestation с заголовком блока."""
    notary = _lib()[0]
    try:
        d = _read(ots_bytes)
    except Exception as exc:
        return {"verified": False, "error": f"invalid_ots: {exc}", "untrusted_claim_blocks": []}

    expected_digest = hashlib.sha256(payload).digest()
    if d.file_digest != expected_digest or d.timestamp.msg != expected_digest:
        return {"verified": False, "error": "file_digest_mismatch", "untrusted_claim_blocks": []}

    # Обходим дерево операций вручную, пересчитывая msg каждого узла через op_edge(cur_msg)
    btc_claims: list[tuple[int, bytes, object]] = []
    tree_valid = True

    def _walk(ts, cur_msg: bytes) -> None:
        nonlocal tree_valid
        if ts.msg != cur_msg:
            tree_valid = False
            return
        for att in ts.attestations:
            if isinstance(att, notary.BitcoinBlockHeaderAttestation):
                btc_claims.append((int(att.height), cur_msg, att))
        for op_edge, sub in ts.ops.items():
            nxt_msg = op_edge(cur_msg)
            _walk(sub, nxt_msg)

    _walk(d.timestamp, expected_digest)
    claim_heights = sorted({h for h, _, _ in btc_claims})
    if not tree_valid:
        return {"verified": False, "error": "timestamp_tree_op_mismatch", "untrusted_claim_blocks": claim_heights}
    if not btc_claims:
        return {"verified": False, "error": "no_bitcoin_attestations", "untrusted_claim_blocks": []}
    if block_header_fn is None:
        return {
            "verified": False,
            "error": "no_verified_bitcoin_header_source",
            "untrusted_claim_blocks": claim_heights,
        }

    verified_blocks: list[dict[str, int]] = []
    for height, commitment_msg, att in btc_claims:
        try:
            bh = block_header_fn(height)
            if bh is None:
                continue
            if isinstance(bh, dict):
                mr_raw = bh.get("merkleroot") or bh.get("hashMerkleRoot")
                mr_bytes = bytes.fromhex(mr_raw) if isinstance(mr_raw, str) else bytes(mr_raw or b"")
                ntime = int(bh.get("time") or bh.get("nTime") or 0)
                class _HdrObj:
                    hashMerkleRoot = mr_bytes
                    nTime = ntime
                bh_obj = _HdrObj()
            else:
                bh_obj = bh
            block_time = att.verify_against_blockheader(commitment_msg, bh_obj)
            verified_blocks.append({"height": height, "time": int(block_time)})
        except Exception:
            continue

    if not verified_blocks:
        return {
            "verified": False,
            "error": "bitcoin_block_header_verification_failed",
            "untrusted_claim_blocks": claim_heights,
        }
    return {
        "verified": True,
        "verified_blocks": verified_blocks,
        "untrusted_claim_blocks": [],
    }


def upgrade(ots_bytes: bytes, timeout: int = 20, get=None) -> tuple[bytes, list[int]]:
    """Спросить календари, вошёл ли отпечаток в блок Bitcoin. Возвращает (новые байты штампа, номера блоков).

    get(url, msg, timeout) -> Timestamp — для тестов без сети. Если ничего не изменилось — исходные байты."""
    notary, op, serialize, timestamp, calendar = _lib()
    d = _read(ots_bytes)
    спросить = get or (lambda url, msg, t: calendar.RemoteCalendar(url).get_timestamp(msg, timeout=t))
    изменено = False

    def обход(ts):
        nonlocal изменено
        for att in list(ts.attestations):
            if isinstance(att, notary.PendingAttestation):
                try:
                    ts.merge(спросить(att.uri, ts.msg, timeout))
                    изменено = True
                except Exception:                                # ещё не готово — не ошибка
                    pass
        for _, sub in ts.ops.items():
            обход(sub)

    обход(d.timestamp)
    блоки = sorted({a.height for _, a in d.timestamp.all_attestations()
                    if isinstance(a, notary.BitcoinBlockHeaderAttestation)})
    if not изменено:
        return ots_bytes, блоки
    buf = io.BytesIO()
    d.serialize(serialize.StreamSerializationContext(buf))
    return buf.getvalue(), блоки
