"""Постквантовый гибридный обмен ключами (X-Wing: ML-KEM-768 + X25519) и синхронизация дельт (В3).

Использование:
- Каждое устройство генерирует долгосрочную пару KEM (ML-KEM-768 + X25519)
  и пару подписей (ML-DSA-65 + Ed25519).
- При первом спаривании два устройства сверяют 6-значный SAS-код (защита от MITM).
  По умолчанию все новые/неподтверждённые устройства не доверены.
- Сеансовый ключ синхронизации выводится по комбинатору X-Wing (SHA3-256 + HKDF-SHA256)
  с последующим шифрованием дельты AES-256-GCM и двойной подписью (Ed25519 + ML-DSA-65).
- Право на забвение (forget_receipt) имеет безусловный приоритет: забытая на узле A
  запись затирается на узле B и никогда не воскрешается при обратном обмене.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
except ImportError:
    mlkem = None  # type: ignore[assignment]

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:
    mldsa = None  # type: ignore[assignment]

from . import integrity, keyvault, pqc_mlkem
from .i18n import t
from .store import now_iso

HAS_NATIVE_MLKEM = mlkem is not None and hasattr(mlkem, "MLKEM768PrivateKey")
HAS_MLDSA = mldsa is not None and hasattr(mldsa, "MLDSA65PrivateKey")
# X-Wing (ML-KEM-768 + X25519) работает везде: нативно при cryptography>=48 или через PureMLKEM768 (Android).
HAS_PQC = True

SCHEME = "xwing-mlkem768-x25519+mldsa65-ed25519+aes256gcm"
SCHEME_ED25519_ONLY = "xwing-mlkem768-x25519+ed25519+aes256gcm"
SUPPORTED_SCHEMES = (SCHEME, SCHEME_ED25519_ONLY)
XWING_LABEL = b"\x5c\x2e\x2f\x2f\x5e\x5c"  # \.//^\ по draft-connolly-cfrg-xwing-kem
PROTOCOL_VERSION = 1


class PqcSyncError(Exception):
    """Базовая ошибка постквантовой синхронизации."""


class PqcUnavailableError(PqcSyncError):
    """В окружении отсутствуют ML-KEM-768 / ML-DSA-65 (нужна cryptography>=48)."""


class PeerNotTrustedError(PqcSyncError):
    """Устройство-получатель или отправитель не подтверждено через SAS-код."""


class PacketVerificationError(PqcSyncError):
    """Подпись или заголовок пакета синхронизации не прошли проверку."""


class PacketDecryptionError(PqcSyncError):
    """Не удалось расшифровать пакет синхронизации этим ключом устройства."""


def _has_mldsa() -> bool:
    return bool(HAS_MLDSA and mldsa is not None and hasattr(mldsa, "MLDSA65PrivateKey"))


def _require_pqc() -> None:
    # X-Wing (ML-KEM-768 + X25519) обеспечен через pqc_mlkem (включая Android Chaquopy).
    return None


def _generate_mlkem_priv():
    if HAS_NATIVE_MLKEM and mlkem is not None:
        return mlkem.MLKEM768PrivateKey.generate()
    return pqc_mlkem.PureMLKEM768PrivateKey.generate()


def _load_mlkem_priv(seed_bytes: bytes):
    if HAS_NATIVE_MLKEM and mlkem is not None and len(seed_bytes) == 64:
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(seed_bytes)
    return pqc_mlkem.PureMLKEM768PrivateKey.from_private_bytes(seed_bytes)


def _load_mlkem_pub(pub_bytes: bytes):
    if HAS_NATIVE_MLKEM and mlkem is not None:
        return mlkem.MLKEM768PublicKey.from_public_bytes(pub_bytes)
    return pqc_mlkem.PureMLKEM768PublicKey.from_public_bytes(pub_bytes)


def _mlkem_raw_pub(pub_obj) -> bytes:
    if hasattr(pub_obj, "public_bytes_raw"):
        return pub_obj.public_bytes_raw()
    return pub_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _mlkem_raw_priv(priv_obj) -> bytes:
    return priv_obj.private_bytes_raw()


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _local_wrap_key(memory) -> bytes:
    raw, _ = integrity.owner_key(memory.store)
    return hashlib.sha256(b"padam-pqc-sync-v1|" + raw).digest()


def _wrap_secret(memory, label: str, secret_bytes: bytes) -> str:
    if keyvault.is_enabled(memory):
        return keyvault.wrap(memory, label, secret_bytes)
    if os.environ.get("PADAM_PQC_REQUIRE_KEYVAULT", "0").strip() == "1":
        raise PqcSyncError(
            "PQC-01: PADAM_PQC_REQUIRE_KEYVAULT=1 requires enabled keyvault (passphrase KDF) instead of plaintext owner.key wrapping"
        )
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_local_wrap_key(memory)).encrypt(nonce, secret_bytes, label.encode("utf-8"))
    return "k1:" + (nonce + ct).hex()


def _unwrap_secret(memory, label: str, wrapped: str) -> bytes:
    if wrapped.startswith(keyvault.PREFIX):
        return keyvault.unwrap(memory, label, wrapped)
    if wrapped.startswith("k1:"):
        if os.environ.get("PADAM_PQC_REQUIRE_KEYVAULT", "0").strip() == "1":
            raise PqcSyncError(
                "PQC-01: plaintext owner.key wrapped secret (k1:) rejected when PADAM_PQC_REQUIRE_KEYVAULT=1"
            )
        blob = bytes.fromhex(wrapped[3:])
        try:
            return AESGCM(_local_wrap_key(memory)).decrypt(blob[:12], blob[12:], label.encode("utf-8"))
        except InvalidTag as exc:
            raise PqcSyncError("failed to unwrap device identity key") from exc
    raise PqcSyncError(f"unsupported key wrapping format for {label}")


def _bundle_fingerprint(pk_mlkem: bytes, pk_x25519: bytes, pk_mldsa: bytes, pk_ed25519: bytes) -> str:
    h = hashlib.sha3_256(
        b"padam-device-v1|" + pk_mlkem + b"|" + pk_x25519 + b"|" + pk_mldsa + b"|" + pk_ed25519
    ).hexdigest()
    return h[:32]


def compute_sas_code(bundle_a: dict[str, Any], bundle_b: dict[str, Any]) -> str:
    """Возвращает 6-значный SAS-код для взаимной сверки двух устройств человеком (защита от MITM)."""
    fp_a = _bundle_fingerprint(
        _b64d(bundle_a["pk_mlkem"]),
        _b64d(bundle_a["pk_x25519"]),
        _b64d(bundle_a["pk_mldsa"]),
        _b64d(bundle_a["pk_ed25519"]),
    )
    fp_b = _bundle_fingerprint(
        _b64d(bundle_b["pk_mlkem"]),
        _b64d(bundle_b["pk_x25519"]),
        _b64d(bundle_b["pk_mldsa"]),
        _b64d(bundle_b["pk_ed25519"]),
    )
    lo, hi = sorted([fp_a, fp_b])
    digest = hashlib.sha256(f"padam-sas-v1|{lo}|{hi}".encode("ascii")).digest()
    num = int.from_bytes(digest[:4], "big") % 1_000_000
    return f"{num:06d}"


@dataclass
class DeviceIdentity:
    """Локальный гибридный набор ключей устройства (KEM: X-Wing, подпись: ML-DSA-65 + Ed25519 или Ed25519 на Android)."""

    device_id: str
    kem_mlkem: Any
    kem_x25519: x25519.X25519PrivateKey
    sig_mldsa: Any
    sig_ed25519: ed25519.Ed25519PrivateKey

    @property
    def active_scheme(self) -> str:
        return SCHEME if self.sig_mldsa is not None else SCHEME_ED25519_ONLY

    @classmethod
    def generate(cls) -> "DeviceIdentity":
        _require_pqc()
        km = _generate_mlkem_priv()
        kx = x25519.X25519PrivateKey.generate()
        dm = mldsa.MLDSA65PrivateKey.generate() if _has_mldsa() else None
        de = ed25519.Ed25519PrivateKey.generate()
        pk_mldsa = dm.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) if dm is not None else b""
        dev_id = _bundle_fingerprint(
            _mlkem_raw_pub(km.public_key()),
            kx.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            pk_mldsa,
            de.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        )
        return cls(device_id=dev_id, kem_mlkem=km, kem_x25519=kx, sig_mldsa=dm, sig_ed25519=de)

    def public_bundle(self) -> dict[str, Any]:
        pk_mldsa = self.sig_mldsa.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) if self.sig_mldsa is not None else b""
        return {
            "version": PROTOCOL_VERSION,
            "scheme": self.active_scheme,
            "device_id": self.device_id,
            "pk_mlkem": _b64e(_mlkem_raw_pub(self.kem_mlkem.public_key())),
            "pk_x25519": _b64e(self.kem_x25519.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
            "pk_mldsa": _b64e(pk_mldsa),
            "pk_ed25519": _b64e(self.sig_ed25519.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        }

    def export_seeds(self) -> bytes:
        payload = {
            "device_id": self.device_id,
            "scheme": self.active_scheme,
            "sk_mlkem": _b64e(_mlkem_raw_priv(self.kem_mlkem)),
            "sk_x25519": _b64e(self.kem_x25519.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            "sk_mldsa": _b64e(self.sig_mldsa.private_bytes_raw()) if self.sig_mldsa is not None else "",
            "sk_ed25519": _b64e(self.sig_ed25519.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        }
        return json.dumps(payload).encode("utf-8")

    @classmethod
    def from_seeds(cls, raw_bytes: bytes) -> "DeviceIdentity":
        _require_pqc()
        data = json.loads(raw_bytes.decode("utf-8"))
        km = _load_mlkem_priv(_b64d(data["sk_mlkem"]))
        kx = x25519.X25519PrivateKey.from_private_bytes(_b64d(data["sk_x25519"]))
        sk_mldsa_b64 = str(data.get("sk_mldsa") or "")
        if sk_mldsa_b64:
            if not _has_mldsa():
                raise PqcUnavailableError("ML-DSA-65 seed requires cryptography>=48")
            dm = mldsa.MLDSA65PrivateKey.from_seed_bytes(_b64d(sk_mldsa_b64))
        else:
            dm = None
        de = ed25519.Ed25519PrivateKey.from_private_bytes(_b64d(data["sk_ed25519"]))
        pk_mldsa = dm.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) if dm is not None else b""
        dev_id = _bundle_fingerprint(
            _mlkem_raw_pub(km.public_key()),
            kx.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            pk_mldsa,
            de.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        )
        return cls(device_id=dev_id, kem_mlkem=km, kem_x25519=kx, sig_mldsa=dm, sig_ed25519=de)


def ensure_local_identity(memory) -> DeviceIdentity:
    """Возвращает существующую пару ключей этого устройства или создаёт и шифрует новую."""
    _require_pqc()
    row = memory.store.one(
        "SELECT device_id, sk_enc, pk_bundle_json FROM sync_identity WHERE user_id = ?",
        (memory.user_id,),
    )
    if row:
        seeds = _unwrap_secret(memory, f"sync_identity:{row['device_id']}", row["sk_enc"])
        return DeviceIdentity.from_seeds(seeds)

    ident = DeviceIdentity.generate()
    sk_enc = _wrap_secret(memory, f"sync_identity:{ident.device_id}", ident.export_seeds())
    ts = now_iso()
    memory.store.execute(
        """INSERT INTO sync_identity (user_id, device_id, scheme, pk_bundle_json, sk_enc, created_at)
           VALUES (?,?,?,?,?,?)""",
        (memory.user_id, ident.device_id, ident.active_scheme, json.dumps(ident.public_bundle()), sk_enc, ts),
    )
    memory._log_audit("pqc_identity_init", ident.device_id, actor="owner", outcome="ok", detail=ident.active_scheme)
    return ident


def register_peer(
    memory,
    peer_bundle: dict[str, Any],
    *,
    label: str = "",
    verified_sas: str | None = None,
) -> dict[str, Any]:
    """Регистрирует публичный бандл другого устройства; доверие даётся только после проверки SAS."""
    _require_pqc()
    pk_mlkem = _b64d(peer_bundle["pk_mlkem"])
    pk_x25519 = _b64d(peer_bundle["pk_x25519"])
    pk_mldsa_raw = str(peer_bundle.get("pk_mldsa") or "")
    pk_mldsa = _b64d(pk_mldsa_raw) if pk_mldsa_raw else b""
    pk_ed25519 = _b64d(peer_bundle["pk_ed25519"])
    # Валидация форматов ключей при регистрации
    _load_mlkem_pub(pk_mlkem)
    x25519.X25519PublicKey.from_public_bytes(pk_x25519)
    if pk_mldsa:
        if not _has_mldsa():
            raise PqcUnavailableError("peer uses ML-DSA-65 which requires cryptography>=48")
        mldsa.MLDSA65PublicKey.from_public_bytes(pk_mldsa)
    ed25519.Ed25519PublicKey.from_public_bytes(pk_ed25519)

    peer_scheme = SCHEME if pk_mldsa else SCHEME_ED25519_ONLY
    dev_id = _bundle_fingerprint(pk_mlkem, pk_x25519, pk_mldsa, pk_ed25519)
    if peer_bundle.get("device_id") and peer_bundle["device_id"] != dev_id:
        raise PacketVerificationError("peer bundle device_id mismatch")

    local_ident = ensure_local_identity(memory)
    expected_sas = compute_sas_code(local_ident.public_bundle(), peer_bundle)
    trusted = 0
    if verified_sas is not None:
        if not hmac.compare_digest(verified_sas.strip(), expected_sas):
            raise PeerNotTrustedError(t(
                "SAS-код подтверждения не совпал — возможна подмена ключа (MITM)",
                "SAS verification code mismatch — possible MITM key substitution",
            ))
        trusted = 1

    canonical = {
        "version": PROTOCOL_VERSION,
        "scheme": peer_scheme,
        "device_id": dev_id,
        "pk_mlkem": _b64e(pk_mlkem),
        "pk_x25519": _b64e(pk_x25519),
        "pk_mldsa": _b64e(pk_mldsa),
        "pk_ed25519": _b64e(pk_ed25519),
    }
    ts = now_iso()
    memory.store.execute(
        """INSERT INTO sync_peer (user_id, peer_device_id, label, pk_bundle_json, sas_code, trusted, created_at, last_sync_at)
           VALUES (?,?,?,?,?,?,?,NULL)
           ON CONFLICT(user_id, peer_device_id) DO UPDATE SET
               label = COALESCE(NULLIF(excluded.label, ''), sync_peer.label),
               pk_bundle_json = excluded.pk_bundle_json,
               sas_code = excluded.sas_code,
               trusted = CASE WHEN excluded.trusted = 1 THEN 1 ELSE sync_peer.trusted END""",
        (memory.user_id, dev_id, label.strip(), json.dumps(canonical), expected_sas, trusted, ts),
    )
    return {"peer_device_id": dev_id, "sas_code": expected_sas, "trusted": bool(trusted)}


def trust_peer(memory, peer_device_id: str, sas_code: str) -> dict[str, Any]:
    """Подтверждает спаренное устройство после ручной сверки 6-значного SAS-кода."""
    row = memory.store.one(
        "SELECT * FROM sync_peer WHERE user_id = ? AND peer_device_id = ?",
        (memory.user_id, peer_device_id),
    )
    if not row:
        raise PeerNotTrustedError(f"unknown peer device: {peer_device_id}")
    if not hmac.compare_digest((sas_code or "").strip(), str(row["sas_code"])):
        raise PeerNotTrustedError("SAS confirmation code mismatch")
    memory.store.execute(
        "UPDATE sync_peer SET trusted = 1 WHERE user_id = ? AND peer_device_id = ?",
        (memory.user_id, peer_device_id),
    )
    memory._log_audit("pqc_peer_trust", peer_device_id, actor="owner", outcome="ok")
    return {"peer_device_id": peer_device_id, "trusted": True}


def _xwing_combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def _derive_session_key(ss_xwing: bytes, transcript: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(transcript).digest(),
        info=b"padam-pqc-sync-v1|aes-256-gcm",
    ).derive(ss_xwing)


def _collect_delta_payload(memory) -> dict[str, Any]:
    """Собирает разрешённые записи (без revoked-текстов) и все квитанции забвения."""
    recs = []
    for r in memory.store.query(
        """SELECT id, user_id, kind, content, scope, origin, agent_id, status,
                  importance, confidence, created_at, last_seen_at, last_confirmed_at,
                  valid_from, valid_to, supersedes, visibility, workspace_id, content_hash
           FROM memory
           WHERE user_id = ? AND status IN ('active', 'superseded', 'archived') AND content IS NOT NULL""",
        (memory.user_id,),
    ):
        d = dict(r)
        ch = d.pop("content_hash", None)
        d["content_hash_b64"] = _b64e(bytes(ch)) if isinstance(ch, (bytes, bytearray, memoryview)) else None
        recs.append(d)
    links = [
        dict(r)
        for r in memory.store.query(
            """SELECT l.src, l.dst, l.relation, l.created_at
               FROM memory_link l
               JOIN memory m1 ON m1.id = l.src AND m1.user_id = ?
               JOIN memory m2 ON m2.id = l.dst AND m2.user_id = ?""",
            (memory.user_id, memory.user_id),
        )
    ]
    receipts = [
        dict(r)
        for r in memory.store.query(
            """SELECT receipt_id, user_id, memory_id, forgotten_at, content_hash_sha256,
                      kind, scope, with_derived, wiped_count, wiped_ids_json,
                      key_destroyed, anchor_tx, leaf_forget_hex
               FROM forget_receipt
               WHERE user_id = ?""",
            (memory.user_id,),
        )
    ]
    return {
        "exported_at": now_iso(),
        "records": recs,
        "links": links,
        "forget_receipts": receipts,
    }


def _forgotten_ids(memory) -> set[str]:
    out: set[str] = set()
    for r in memory.store.query("SELECT id FROM memory WHERE user_id = ? AND status = 'revoked'", (memory.user_id,)):
        out.add(str(r["id"]))
    for r in memory.store.query(
        "SELECT memory_id, wiped_ids_json FROM forget_receipt WHERE user_id = ?",
        (memory.user_id,),
    ):
        out.add(str(r["memory_id"]))
        try:
            for wid in json.loads(r["wiped_ids_json"] or "[]"):
                out.add(str(wid))
        except Exception:
            pass
    return out


def seal_sync_packet(memory, peer_device_id: str) -> dict[str, Any]:
    """Шифрует и подписывает дельту памяти для доверенного устройства по гибриду X-Wing."""
    _require_pqc()
    local_ident = ensure_local_identity(memory)
    peer_row = memory.store.one(
        "SELECT * FROM sync_peer WHERE user_id = ? AND peer_device_id = ?",
        (memory.user_id, peer_device_id),
    )
    if not peer_row or not peer_row["trusted"]:
        raise PeerNotTrustedError(t(
            f"устройство {peer_device_id} не подтверждено через SAS",
            f"peer device {peer_device_id} is not SAS-trusted",
        ))
    peer_bundle = json.loads(peer_row["pk_bundle_json"])
    pk_mlkem_bytes = _b64d(peer_bundle["pk_mlkem"])
    pk_x25519_bytes = _b64d(peer_bundle["pk_x25519"])

    peer_mlkem_pk = _load_mlkem_pub(pk_mlkem_bytes)
    peer_x25519_pk = x25519.X25519PublicKey.from_public_bytes(pk_x25519_bytes)

    ss_m, ct_mlkem = peer_mlkem_pk.encapsulate()
    eph_x = x25519.X25519PrivateKey.generate()
    ct_x25519 = eph_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ss_x = eph_x.exchange(peer_x25519_pk)
    ss_xwing = _xwing_combine(ss_m, ss_x, ct_x25519, pk_x25519_bytes)

    use_scheme = local_ident.active_scheme
    session_nonce = secrets.token_bytes(16)
    transcript = json.dumps({
        "v": PROTOCOL_VERSION,
        "scheme": use_scheme,
        "sender": local_ident.device_id,
        "receiver": peer_bundle["device_id"],
        "nonce": _b64e(session_nonce),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    aes_key = _derive_session_key(ss_xwing, transcript)
    gcm_nonce = secrets.token_bytes(12)
    plaintext = json.dumps(_collect_delta_payload(memory), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(aes_key).encrypt(gcm_nonce, plaintext, transcript)

    signed_blob = transcript + b"|" + ct_mlkem + b"|" + ct_x25519 + b"|" + gcm_nonce + b"|" + ciphertext
    sig_ed = local_ident.sig_ed25519.sign(signed_blob)
    sig_mldsa = local_ident.sig_mldsa.sign(signed_blob) if local_ident.sig_mldsa is not None else b""

    memory._log_audit("pqc_seal", peer_device_id, actor="owner", outcome="ok", detail=use_scheme)
    return {
        "version": PROTOCOL_VERSION,
        "scheme": use_scheme,
        "sender_id": local_ident.device_id,
        "receiver_id": peer_bundle["device_id"],
        "session_nonce": _b64e(session_nonce),
        "ct_mlkem": _b64e(ct_mlkem),
        "ct_x25519": _b64e(ct_x25519),
        "gcm_nonce": _b64e(gcm_nonce),
        "ciphertext": _b64e(ciphertext),
        "sig_ed25519": _b64e(sig_ed),
        "sig_mldsa65": _b64e(sig_mldsa),
    }


def open_sync_packet(memory, packet: dict[str, Any]) -> dict[str, Any]:
    """Проверяет обе подписи (Ed25519 + ML-DSA-65) доверенного пира и расшифровывает пакет."""
    _require_pqc()
    local_ident = ensure_local_identity(memory)
    pkt_scheme = str(packet.get("scheme") or "")
    if packet.get("version") != PROTOCOL_VERSION or pkt_scheme not in SUPPORTED_SCHEMES:
        raise PacketVerificationError("unsupported protocol version or PQC scheme")
    if packet.get("receiver_id") != local_ident.device_id:
        raise PacketDecryptionError("packet is addressed to a different device_id")

    sender_id = str(packet.get("sender_id") or "")
    peer_row = memory.store.one(
        "SELECT * FROM sync_peer WHERE user_id = ? AND peer_device_id = ?",
        (memory.user_id, sender_id),
    )
    if not peer_row or not peer_row["trusted"]:
        raise PeerNotTrustedError(f"sender {sender_id} is not SAS-trusted")

    peer_bundle = json.loads(peer_row["pk_bundle_json"])
    peer_has_mldsa = bool(peer_bundle.get("pk_mldsa"))
    if peer_has_mldsa and pkt_scheme != SCHEME:
        raise PacketVerificationError("downgrade rejected: peer requires ML-DSA-65 signature")
    if (not peer_has_mldsa) and pkt_scheme != SCHEME_ED25519_ONLY:
        raise PacketVerificationError("scheme mismatch for peer without ML-DSA-65 key")

    sender_ed_pk = ed25519.Ed25519PublicKey.from_public_bytes(_b64d(peer_bundle["pk_ed25519"]))
    sender_mldsa_pk = None
    if peer_has_mldsa:
        if not _has_mldsa():
            raise PqcUnavailableError("cannot verify ML-DSA-65 packet without cryptography>=48")
        sender_mldsa_pk = mldsa.MLDSA65PublicKey.from_public_bytes(_b64d(peer_bundle["pk_mldsa"]))

    ct_mlkem = _b64d(packet["ct_mlkem"])
    ct_x25519 = _b64d(packet["ct_x25519"])
    gcm_nonce = _b64d(packet["gcm_nonce"])
    ciphertext = _b64d(packet["ciphertext"])
    sig_ed = _b64d(packet["sig_ed25519"])
    sig_mldsa = _b64d(packet.get("sig_mldsa65") or "") if peer_has_mldsa else b""

    transcript = json.dumps({
        "v": PROTOCOL_VERSION,
        "scheme": pkt_scheme,
        "sender": sender_id,
        "receiver": local_ident.device_id,
        "nonce": packet["session_nonce"],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signed_blob = transcript + b"|" + ct_mlkem + b"|" + ct_x25519 + b"|" + gcm_nonce + b"|" + ciphertext

    try:
        sender_ed_pk.verify(sig_ed, signed_blob)
        if sender_mldsa_pk is not None:
            sender_mldsa_pk.verify(sig_mldsa, signed_blob)
    except InvalidSignature as exc:
        raise PacketVerificationError("hybrid packet signature verification failed") from exc

    try:
        ss_m = local_ident.kem_mlkem.decapsulate(ct_mlkem)
        eph_pk = x25519.X25519PublicKey.from_public_bytes(ct_x25519)
        ss_x = local_ident.kem_x25519.exchange(eph_pk)
        pk_x_self = local_ident.kem_x25519.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ss_xwing = _xwing_combine(ss_m, ss_x, ct_x25519, pk_x_self)
        aes_key = _derive_session_key(ss_xwing, transcript)
        plaintext = AESGCM(aes_key).decrypt(gcm_nonce, ciphertext, transcript)
    except (InvalidTag, ValueError) as exc:
        raise PacketDecryptionError("AES-256-GCM decryption failed with local X-Wing key") from exc

    return json.loads(plaintext.decode("utf-8"))


def apply_sync_packet(memory, packet: dict[str, Any]) -> dict[str, int]:
    """Применяет расшифрованную дельту: сначала forget_receipt (запрет воскрешения), затем новые записи."""
    delta = open_sync_packet(memory, packet)
    sender_id = str(packet["sender_id"])

    # 1. Сначала применяем все квитанции забвения, чтобы забытое исчезло и не воскресилось
    wiped_from_receipts = 0
    for rc in delta.get("forget_receipts") or []:
        rid = str(rc["receipt_id"])
        wiped_list = [str(x) for x in json.loads(rc.get("wiped_ids_json") or "[]")]
        if rc.get("memory_id") and str(rc["memory_id"]) not in wiped_list:
            wiped_list.append(str(rc["memory_id"]))
        for target_id in wiped_list:
            existing = memory.store.one(
                "SELECT id, status FROM memory WHERE id = ? AND user_id = ?",
                (target_id, memory.user_id),
            )
            if existing and existing["status"] != "revoked":
                memory.store.execute(
                    """UPDATE memory
                       SET content = NULL, status = 'revoked', importance = 0.0, confidence = 0.0, owner_sig = NULL
                       WHERE id = ? AND user_id = ?""",
                    (target_id, memory.user_id),
                )
                wiped_from_receipts += 1
        memory.store.execute(
            """INSERT OR IGNORE INTO forget_receipt (
                   receipt_id, user_id, memory_id, forgotten_at, content_hash_sha256,
                   kind, scope, with_derived, wiped_count, wiped_ids_json,
                   key_destroyed, anchor_tx, leaf_forget_hex
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rid,
                memory.user_id,
                str(rc["memory_id"]),
                str(rc["forgotten_at"]),
                rc.get("content_hash_sha256"),
                rc.get("kind"),
                rc.get("scope"),
                int(rc.get("with_derived") or 0),
                int(rc.get("wiped_count") or len(wiped_list) or 1),
                json.dumps(wiped_list),
                int(rc.get("key_destroyed", 1)),
                rc.get("anchor_tx"),
                str(rc["leaf_forget_hex"]),
            ),
        )

    if wiped_from_receipts:
        memory.store.purge()

    # Собираем единый реестр забвения: ни один ID из него не смеет воскреснуть
    forgotten = _forgotten_ids(memory)

    imported = 0
    skipped_forgotten = 0
    skipped_existing = 0

    for rec in delta.get("records") or []:
        rec_id = str(rec["id"])
        if rec_id in forgotten:
            skipped_forgotten += 1
            continue
        cur = memory.store.one("SELECT id, status FROM memory WHERE id = ? AND user_id = ?", (rec_id, memory.user_id))
        if cur:
            skipped_existing += 1
            continue
        content = str(rec.get("content") or "")
        if not content:
            continue
        kind = str(rec.get("kind") or "fact")
        created_ts = str(rec.get("created_at") or now_iso())
        scope_val = str(rec.get("scope") or "global")
        owner_sig = None
        if kind in ("identity", "preference"):
            key, _ = integrity.owner_key(memory.store)
            owner_sig = integrity.sign(
                key,
                rec_id,
                kind,
                content,
                scope=scope_val,
                user_id=memory.user_id,
                created_at=created_ts,
                status="active",
            )
        chash = (
            _b64d(rec["content_hash_b64"])
            if rec.get("content_hash_b64")
            else hashlib.sha256(content.encode("utf-8")).digest()
        )
        last_seen_ts = str(rec.get("last_seen_at") or created_ts)
        last_conf_ts = str(rec.get("last_confirmed_at") or created_ts)
        memory.store.execute(
            """INSERT INTO memory (
                   id, user_id, kind, content, scope, origin, agent_id, status,
                   importance, confidence, created_at, last_seen_at, last_confirmed_at,
                   valid_from, valid_to, supersedes, owner_sig, visibility, workspace_id, content_hash
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rec_id,
                memory.user_id,
                kind,
                content,
                str(rec.get("scope") or "global"),
                str(rec.get("origin") or "user"),
                rec.get("agent_id"),
                str(rec.get("status") or "active"),
                float(rec.get("importance") or 0.5),
                float(rec.get("confidence") or 1.0),
                created_ts,
                last_seen_ts,
                last_conf_ts,
                rec.get("valid_from"),
                rec.get("valid_to"),
                rec.get("supersedes"),
                owner_sig,
                str(rec.get("visibility") or "private"),
                rec.get("workspace_id"),
                chash,
            ),
        )
        imported += 1

    for lk in delta.get("links") or []:
        s_id, d_id = str(lk["src"]), str(lk["dst"])
        if s_id in forgotten or d_id in forgotten:
            continue
        memory.store.execute(
            """INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at)
               VALUES (?,?,?,?)""",
            (s_id, d_id, str(lk.get("relation") or "derived"), str(lk.get("created_at") or now_iso())),
        )

    memory.store.execute(
        "UPDATE sync_peer SET last_sync_at = ? WHERE user_id = ? AND peer_device_id = ?",
        (now_iso(), memory.user_id, sender_id),
    )
    memory._log_audit(
        "pqc_sync_apply", sender_id, actor="owner", outcome="ok",
        detail=f"imported={imported} wiped={wiped_from_receipts} skipped_forgotten={skipped_forgotten}",
    )
    return {
        "imported": imported,
        "wiped_from_receipts": wiped_from_receipts,
        "skipped_forgotten": skipped_forgotten,
        "skipped_existing": skipped_existing,
    }
