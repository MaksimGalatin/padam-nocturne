"""Аппаратная Печать Души (Hardware-Locked Genesis).

Запечатывает файл SQLite целиком в аутентифицированный контейнер ``PADAMHW1``
на AES-256-GCM с 256-битным DEK, обёрнутым аппаратными факторами:
  - ``dpapi``: Windows CryptProtectData / CryptUnprotectData (учётка текущего ПК),
  - ``fido2``: WebAuthn ECDSA P-256 / Ed25519 challenge-response (UP + UV + счётчик replay) + HKDF(hmac-secret),
  - ``fido2+dpapi``: строгая двухфакторная связка (оба фактора требуются одновременно).
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import struct
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .memory import Memory
from .store import HW_SEAL_MAGIC, HardwareLockedError, Store

CONTAINER_MAGIC = HW_SEAL_MAGIC  # b"PADAMHW1"
_DPAPI_ENTROPY = b"padam-nocturne-hardware-seal-v1"


class HardwareSealError(RuntimeError):
    """Ошибка формата или операций контейнера PADAMHW1."""


class HardwareAuthError(PermissionError):
    """Отказ аппаратной аутентификации (нет касания, неверная подпись, replay или чужой ПК)."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _b64u_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _wipe_bytes(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def _secure_delete(path: Path) -> None:
    try:
        if not path.exists() or not path.is_file():
            return
        size = path.stat().st_size
        if size > 0:
            chunk = b"\x00" * min(size, 65536)
            with path.open("r+b") as fh:
                rem = size
                while rem > 0:
                    n = min(rem, len(chunk))
                    fh.write(chunk[:n])
                    rem -= n
                fh.flush()
                os.fsync(fh.fileno())
        path.unlink()
    except OSError:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Аппаратные зонды и Windows DPAPI (crypt32)
# ---------------------------------------------------------------------------


def probe_hardware_capabilities() -> dict[str, Any]:
    """Честно проверяет реальные аппаратные интерфейсы текущей ОС (без заглушек)."""
    dpapi_available = False
    webauthn_api_version: int | None = None
    webauthn_dll = False
    platform_auth = False   # на Linux и macOS ветки win32 нет — без этого UnboundLocalError ронял padam_stats

    if sys.platform == "win32":
        try:
            crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
            dpapi_available = hasattr(crypt32, "CryptProtectData") and hasattr(crypt32, "CryptUnprotectData")
        except Exception:
            dpapi_available = False
        try:
            from . import webauthn_win

            dll = webauthn_win.load_webauthn_dll()
            webauthn_dll = True
            webauthn_api_version = webauthn_win.api_version(dll)
            platform_auth = bool(webauthn_win.platform_authenticator_available(dll))
        except Exception:
            webauthn_dll = False
            platform_auth = False

    bioutil_present = sys.platform == "darwin" and Path("/usr/bin/bioutil").exists()
    return {
        "platform": sys.platform,
        "dpapi_available": bool(dpapi_available),
        "webauthn_dll": bool(webauthn_dll),
        "webauthn_api_version": webauthn_api_version,
        "platform_authenticator_available": platform_auth,
        "macos_bioutil": bool(bioutil_present),
        "fido2_crypto_engine": "cryptography(ECDSA-P256/Ed25519/RSA-SHA256+HKDF-SHA256)",
    }


def _dpapi_protect(data: bytes, entropy: bytes = _DPAPI_ENTROPY) -> bytes:
    if sys.platform != "win32":
        raise HardwareSealError("Windows DPAPI is only available on win32")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_uint32),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    in_buf = ctypes.create_string_buffer(data, len(data))
    ent_buf = ctypes.create_string_buffer(entropy, len(entropy))
    in_blob = DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_byte)))
    ent_blob = DATA_BLOB(len(entropy), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()

    # CRYPTPROTECT_UI_FORBIDDEN = 0x1
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "PADAM_HW_SEAL",
        ctypes.byref(ent_blob),
        None,
        None,
        0x1,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise HardwareSealError("CryptProtectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(blob: bytes, entropy: bytes = _DPAPI_ENTROPY) -> bytes:
    if sys.platform != "win32":
        raise HardwareSealError("Windows DPAPI is only available on win32")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_uint32),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    in_buf = ctypes.create_string_buffer(blob, len(blob))
    ent_buf = ctypes.create_string_buffer(entropy, len(entropy))
    in_blob = DATA_BLOB(len(blob), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_byte)))
    ent_blob = DATA_BLOB(len(entropy), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob),
        None,
        None,
        0x1,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise HardwareAuthError("DPAPI decryption failed (wrong OS user or corrupted seal)")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)


# ---------------------------------------------------------------------------
# WebAuthn / FIDO2 криптография (ECDSA P-256 / Ed25519 + hmac-secret)
# ---------------------------------------------------------------------------


@dataclass
class Fido2Assertion:
    credential_id: bytes
    authenticator_data: bytes
    client_data_json: bytes
    signature: bytes
    hmac_secret: bytes


class SoftwareFido2Token:
    """Аппаратно-эквивалентный локальный токен FIDO2/WebAuthn для тестов и без-USB среды.

    Реализует настоящий протокол WebAuthn:
      - пара ключей ECDSA P-256 или Ed25519,
      - 37-байтный ``authenticatorData`` (SHA256(rpId) || flags(UP/UV) || BE32(signCount)),
      - подпись по ``authenticatorData || SHA256(clientDataJSON)``,
      - детерминированный ``hmac_secret = HMAC-SHA256(device_hmac_root, salt)``,
      - строгий отказ без явного присутствия пользователя (``present=False``).
    """

    def __init__(
        self,
        *,
        algorithm: str = "ES256",
        rp_id: str = "padam.local",
        present: bool = True,
        user_verified: bool = True,
        insecure_test_token: bool = False,
    ) -> None:
        # HW-03: программная заглушка FIDO2 запрещена по умолчанию (только для тестов с явным флагом)
        if not insecure_test_token and os.environ.get("PADAM_INSECURE_TEST_TOKEN", "0").strip() != "1":
            raise HardwareAuthError(
                "SoftwareFido2Token is disabled by default; pass insecure_test_token=True or set PADAM_INSECURE_TEST_TOKEN=1 (tests only)"
            )
        self._insecure_test_token = True
        self.algorithm = algorithm.upper()
        self.rp_id = rp_id
        self.present = bool(present)
        self.user_verified = bool(user_verified)
        self.credential_id = secrets.token_bytes(32)
        self._hmac_root = secrets.token_bytes(32)
        self.sign_count = 0
        if self.algorithm == "EDDSA":
            self._sk = ed25519.Ed25519PrivateKey.generate()
        elif self.algorithm == "ES256":
            self._sk = ec.generate_private_key(ec.SECP256R1())
        else:
            raise ValueError(f"Unsupported FIDO2 algorithm: {algorithm}")

    def public_key_pem(self) -> str:
        return (
            self._sk.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )

    def derive_hmac_secret(self, salt: bytes) -> bytes:
        import hmac as _hmac
        return _hmac.new(self._hmac_root, salt, hashlib.sha256).digest()

    def assert_challenge(self, challenge: bytes, salt: bytes, *, increment_counter: bool = True) -> Fido2Assertion:
        if not self.present:
            raise HardwareAuthError("User presence (touch/biometric) required by FIDO2 device")
        if increment_counter:
            self.sign_count += 1
        flags = 0x01 | (0x04 if self.user_verified else 0x00)
        rp_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        auth_data = rp_hash + bytes([flags]) + struct.pack(">I", self.sign_count)
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": _b64u_enc(challenge),
                "origin": f"https://{self.rp_id}",
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        signed_payload = auth_data + hashlib.sha256(client_data).digest()
        if isinstance(self._sk, ed25519.Ed25519PrivateKey):
            sig = self._sk.sign(signed_payload)
        else:
            sig = self._sk.sign(signed_payload, ec.ECDSA(hashes.SHA256()))
        return Fido2Assertion(
            credential_id=self.credential_id,
            authenticator_data=auth_data,
            client_data_json=client_data,
            signature=sig,
            hmac_secret=self.derive_hmac_secret(salt),
        )


def verify_fido2_assertion(
    assertion: Fido2Assertion,
    *,
    expected_credential_id: bytes,
    public_key_pem: str,
    expected_challenge: bytes,
    rp_id: str,
    last_sign_count: int,
    require_uv: bool = True,
) -> int:
    """Криптографически проверяет WebAuthn assertion (UP, UV, RP ID, challenge, подпись, анти-replay sign_count)."""
    import hmac as _hmac

    if not _hmac.compare_digest(assertion.credential_id, expected_credential_id):
        raise HardwareAuthError("FIDO2 credential_id mismatch")
    if len(assertion.authenticator_data) < 37:
        raise HardwareAuthError("Invalid authenticatorData length")

    rp_hash = assertion.authenticator_data[:32]
    expected_rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    if not _hmac.compare_digest(rp_hash, expected_rp_hash):
        raise HardwareAuthError("FIDO2 rpIdHash mismatch")

    flags = assertion.authenticator_data[32]
    up = bool(flags & 0x01)
    uv = bool(flags & 0x04)
    if not up:
        raise HardwareAuthError("FIDO2 User Presence (UP=1) check failed")
    if require_uv and not uv:
        raise HardwareAuthError("FIDO2 User Verification (UV=1) check failed")

    sign_count = struct.unpack(">I", assertion.authenticator_data[33:37])[0]
    if last_sign_count >= 0:
        # По W3C WebAuthn платформенные TPM (Windows Hello) могут возвращать signCount=0 всегда
        if not (sign_count == 0 and last_sign_count == 0) and sign_count <= last_sign_count:
            raise HardwareAuthError(
                f"FIDO2 replay detected: sign_count {sign_count} <= last {last_sign_count}"
            )

    try:
        cd = json.loads(assertion.client_data_json.decode("utf-8"))
    except Exception as exc:
        raise HardwareAuthError(f"Invalid clientDataJSON: {exc}") from exc
    if cd.get("type") != "webauthn.get" or cd.get("challenge") != _b64u_enc(expected_challenge):
        raise HardwareAuthError("FIDO2 challenge mismatch")

    signed_payload = assertion.authenticator_data + hashlib.sha256(assertion.client_data_json).digest()
    pub = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(assertion.signature, signed_payload)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(assertion.signature, signed_payload, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(assertion.signature, signed_payload, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise HardwareAuthError("Unsupported public key type")
    except InvalidSignature as exc:
        raise HardwareAuthError("FIDO2 signature verification failed") from exc

    return sign_count


# ---------------------------------------------------------------------------
# Запечатывание и распечатывание SQLite-файла в контейнер PADAMHW1
# ---------------------------------------------------------------------------


def is_sealed_database(db_path: Path | str) -> bool:
    p = Path(db_path)
    if str(p) == ":memory:" or not p.exists() or not p.is_file():
        return False
    try:
        with p.open("rb") as fh:
            return fh.read(8) == CONTAINER_MAGIC
    except OSError:
        return False


def read_seal_header(db_path: Path | str) -> dict[str, Any]:
    p = Path(db_path)
    if not p.exists():
        raise FileNotFoundError(f"Database not found: {p}")
    with p.open("rb") as fh:
        magic = fh.read(8)
        if magic != CONTAINER_MAGIC:
            raise HardwareSealError("Database is not hardware-sealed (PADAMHW1)")
        raw_len = fh.read(4)
        if len(raw_len) != 4:
            raise HardwareSealError("Corrupted PADAMHW1 container length")
        hdr_len = struct.unpack(">I", raw_len)[0]
        if hdr_len <= 2 or hdr_len > 1024 * 1024:
            raise HardwareSealError("Corrupted PADAMHW1 header size")
        hdr_bytes = fh.read(hdr_len)
        if len(hdr_bytes) != hdr_len:
            raise HardwareSealError("Truncated PADAMHW1 header")
    return json.loads(hdr_bytes.decode("utf-8"))


def _wrap_dek_fido2(dek: bytes, hmac_secret: bytes, salt: bytes, rp_id: str) -> str:
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"padam-hw-fido2-kek-v1",
    ).derive(hmac_secret)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(kek).encrypt(nonce, dek, f"padam-hw|{rp_id}".encode("utf-8"))
    return (nonce + ct).hex()


def _unwrap_dek_fido2(sealed_hex: str, hmac_secret: bytes, salt: bytes, rp_id: str) -> bytes:
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"padam-hw-fido2-kek-v1",
    ).derive(hmac_secret)
    blob = bytes.fromhex(sealed_hex)
    if len(blob) < 28:
        raise HardwareAuthError("Corrupted FIDO2 wrapped key")
    try:
        return AESGCM(kek).decrypt(blob[:12], blob[12:], f"padam-hw|{rp_id}".encode("utf-8"))
    except InvalidTag as exc:
        raise HardwareAuthError("FIDO2 hmac-secret failed to unwrap DEK") from exc


def _checkpoint_sqlite_if_openable(db_path: Path) -> None:
    """Сливает WAL в основной SQLite-файл и удаляет побочные -wal/-shm, не оставляя открытых копий."""
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    for suffix in ("-wal", "-shm"):
        side = Path(str(db_path) + suffix)
        if side.exists():
            _secure_delete(side)


def _hw_owner_paths(db_path: Path) -> tuple[Path, Path, Path]:
    base = str(db_path)
    return (
        Path(base + ".hwseal.owner.key"),
        Path(base + ".hwseal.owner.pub"),
        Path(base + ".hwseal.state.json"),
    )


def _get_or_create_hw_owner_key(db_path: Path) -> tuple[ed25519.Ed25519PrivateKey, str]:
    from . import net_guard
    kpath, pubpath, _ = _hw_owner_paths(db_path)
    if kpath.exists():
        raw_sk = bytes.fromhex(kpath.read_text(encoding="ascii").strip())
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(raw_sk)
    else:
        sk = ed25519.Ed25519PrivateKey.generate()
        raw_sk = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        kpath.write_text(raw_sk.hex(), encoding="ascii")
        net_guard.restrict_file_to_owner(kpath)
    pub_hex = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    if not pubpath.exists():
        pubpath.write_text(pub_hex, encoding="ascii")
        net_guard.restrict_file_to_owner(pubpath)
    return sk, pub_hex


def _sign_hw_header(header: dict[str, Any], sk: ed25519.Ed25519PrivateKey) -> dict[str, Any]:
    h = {k: v for k, v in header.items() if k != "owner_sig_hex"}
    h["owner_pubkey_hex"] = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    canon = json.dumps(h, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h["owner_sig_hex"] = sk.sign(b"PADAMHW1-HDR|" + canon).hex()
    return h


def _verify_hw_header_and_monotonic(
    db_path: Path,
    header: dict[str, Any],
    *,
    expected_owner_pubkey_hex: str | None = None,
    require_owner_signature: bool = True,
) -> dict[str, Any]:
    _, pubpath, stpath = _hw_owner_paths(db_path)
    pinned_pub = (
        (expected_owner_pubkey_hex or "").strip().lower()
        or os.environ.get("PADAM_HW_SEAL_PUBKEY_HEX", "").strip().lower()
        or (pubpath.read_text(encoding="ascii").strip().lower() if pubpath.exists() else "")
    )
    sig_hex = str(header.get("owner_sig_hex") or "").strip().lower()
    hdr_pub_hex = str(header.get("owner_pubkey_hex") or "").strip().lower()

    if require_owner_signature:
        if not sig_hex or not hdr_pub_hex:
            raise HardwareAuthError("Container missing owner Ed25519 signature (HW-01)")
        if pinned_pub and hdr_pub_hex != pinned_pub:
            raise HardwareAuthError("Container owner pubkey mismatch (possible container replacement)")
        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(hdr_pub_hex))
            canon = json.dumps({k: v for k, v in header.items() if k != "owner_sig_hex"}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            pk.verify(bytes.fromhex(sig_hex), b"PADAMHW1-HDR|" + canon)
        except Exception as exc:
            raise HardwareAuthError(f"Container owner Ed25519 signature verification failed: {exc}") from exc

    # HW-02: монотонный счётчик seal_seq против rollback-подмены старым контейнером
    seq = int(header.get("seal_seq") or 0)
    if stpath.exists():
        try:
            st = json.loads(stpath.read_text(encoding="utf-8"))
        except Exception as exc:
            raise HardwareAuthError(f"Corrupted hardware seal monotonic state: {exc}") from exc
        st_sig = str(st.get("state_sig_hex") or "")
        st_pub = pinned_pub or hdr_pub_hex
        if st_pub and st_sig:
            try:
                pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(st_pub))
                st_canon = json.dumps({k: v for k, v in st.items() if k != "state_sig_hex"}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                pk.verify(bytes.fromhex(st_sig), b"PADAMHW1-STATE|" + st_canon)
            except Exception as exc:
                raise HardwareAuthError(f"Monotonic state signature invalid: {exc}") from exc
        max_seq = int(st.get("max_seal_seq") or 0)
        if seq < max_seq:
            raise HardwareAuthError(f"Container rollback detected: seal_seq={seq} < max_known={max_seq}")
        st_cid = str(st.get("container_id") or "")
        if st_cid and header.get("container_id") and st_cid != str(header.get("container_id")):
            raise HardwareAuthError("Container identity mismatch against monotonic state (container replacement)")
        return st
    return {}


def _save_hw_monotonic_state(db_path: Path, header: dict[str, Any], sk: ed25519.Ed25519PrivateKey) -> None:
    from . import net_guard
    _, _, stpath = _hw_owner_paths(db_path)
    st_body = {
        "container_id": str(header.get("container_id") or ""),
        "max_seal_seq": int(header.get("seal_seq") or 1),
        "last_sealed_at": str(header.get("sealed_at") or ""),
        "last_plain_sha256": str(header.get("plain_sha256") or ""),
    }
    st_canon = json.dumps(st_body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    st_body["state_sig_hex"] = sk.sign(b"PADAMHW1-STATE|" + st_canon).hex()
    stpath.write_text(json.dumps(st_body, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    net_guard.restrict_file_to_owner(stpath)


def _reject_software_token_unless_allowed(token: Any, allow_insecure_test_token: bool) -> None:
    if isinstance(token, SoftwareFido2Token):
        if not allow_insecure_test_token and os.environ.get("PADAM_INSECURE_TEST_TOKEN", "0").strip() != "1":
            raise HardwareAuthError("SoftwareFido2Token rejected without allow_insecure_test_token=True or PADAM_INSECURE_TEST_TOKEN=1")


def seal_database(
    db_path: Path | str,
    *,
    mode: str = "dpapi",
    fido2_token: Any | None = None,
    rp_id: str = "padam.local",
    require_uv: bool = True,
    allow_insecure_test_token: bool = False,
) -> dict[str, Any]:
    """Запечатывает SQLite-файл целиком в контейнер ``PADAMHW1`` с подписью владельца и монотонным счётчиком."""
    p = Path(db_path)
    if str(p) == ":memory:":
        raise HardwareSealError("Cannot seal :memory: database")
    if not p.exists():
        raise FileNotFoundError(f"Database not found: {p}")
    if is_sealed_database(p):
        raise HardwareSealError("Database is already hardware-sealed")

    clean_mode = (mode or "dpapi").strip().lower()
    if clean_mode not in ("dpapi", "fido2", "fido2+dpapi"):
        raise ValueError(f"Unsupported seal mode: {mode}")
    if clean_mode in ("fido2", "fido2+dpapi") and fido2_token is None:
        raise HardwareAuthError("FIDO2 token / public key credential is required for fido2 seal mode")
    if fido2_token is not None:
        _reject_software_token_unless_allowed(fido2_token, allow_insecure_test_token)
    if clean_mode in ("dpapi", "fido2+dpapi") and not probe_hardware_capabilities()["dpapi_available"]:
        raise HardwareSealError("Windows DPAPI is not available on this host")

    _checkpoint_sqlite_if_openable(p)
    plain_bytes = bytearray(p.read_bytes())
    try:
        dek = bytearray(secrets.token_bytes(32))
        owner_sk, owner_pub_hex = _get_or_create_hw_owner_key(p)
        _, _, stpath = _hw_owner_paths(p)
        prev_seq = 0
        prev_cid = ""
        if stpath.exists():
            try:
                old_st = json.loads(stpath.read_text(encoding="utf-8"))
                prev_seq = int(old_st.get("max_seal_seq") or 0)
                prev_cid = str(old_st.get("container_id") or "")
            except Exception:
                pass
        next_seq = prev_seq + 1
        container_id = prev_cid or secrets.token_hex(16)
        try:
            header: dict[str, Any] = {
                "v": 2,
                "container_id": container_id,
                "seal_seq": next_seq,
                "mode": clean_mode,
                "rp_id": rp_id,
                "require_uv": bool(require_uv),
                "sealed_at": _utc_now(),
                "plain_sha256": hashlib.sha256(plain_bytes).hexdigest(),
                "plain_size": len(plain_bytes),
                "wrapped_keys": {},
            }

            if clean_mode == "dpapi":
                header["wrapped_keys"]["dpapi_hex"] = _dpapi_protect(bytes(dek)).hex()
            elif clean_mode == "fido2":
                assert fido2_token is not None
                fido_salt = secrets.token_bytes(32)
                challenge = secrets.token_bytes(32)
                ass = fido2_token.assert_challenge(challenge, fido_salt, increment_counter=True)
                sc = verify_fido2_assertion(
                    ass,
                    expected_credential_id=fido2_token.credential_id,
                    public_key_pem=fido2_token.public_key_pem(),
                    expected_challenge=challenge,
                    rp_id=rp_id,
                    last_sign_count=-1,
                    require_uv=require_uv,
                )
                header["fido2"] = {
                    "rp_id": rp_id,
                    "credential_id_hex": fido2_token.credential_id.hex(),
                    "public_key_pem": fido2_token.public_key_pem(),
                    "hmac_salt_hex": fido_salt.hex(),
                    "last_sign_count": sc,
                }
                header["wrapped_keys"]["fido2_hex"] = _wrap_dek_fido2(
                    bytes(dek), ass.hmac_secret, fido_salt, rp_id
                )
            elif clean_mode == "fido2+dpapi":
                assert fido2_token is not None
                # Настоящая 2FA: DEK = fido2_share XOR dpapi_share
                share_dpapi = bytearray(secrets.token_bytes(32))
                share_fido = bytearray(bytes(a ^ b for a, b in zip(dek, share_dpapi)))
                try:
                    fido_salt = secrets.token_bytes(32)
                    challenge = secrets.token_bytes(32)
                    ass = fido2_token.assert_challenge(challenge, fido_salt, increment_counter=True)
                    sc = verify_fido2_assertion(
                        ass,
                        expected_credential_id=fido2_token.credential_id,
                        public_key_pem=fido2_token.public_key_pem(),
                        expected_challenge=challenge,
                        rp_id=rp_id,
                        last_sign_count=-1,
                        require_uv=require_uv,
                    )
                    header["fido2"] = {
                        "rp_id": rp_id,
                        "credential_id_hex": fido2_token.credential_id.hex(),
                        "public_key_pem": fido2_token.public_key_pem(),
                        "hmac_salt_hex": fido_salt.hex(),
                        "last_sign_count": sc,
                    }
                    header["wrapped_keys"]["dpapi_share_hex"] = _dpapi_protect(bytes(share_dpapi)).hex()
                    header["wrapped_keys"]["fido2_share_hex"] = _wrap_dek_fido2(
                        bytes(share_fido), ass.hmac_secret, fido_salt, rp_id
                    )
                finally:
                    _wipe_bytes(share_dpapi)
                    _wipe_bytes(share_fido)

            header = _sign_hw_header(header, owner_sk)
            hdr_bytes = json.dumps(header, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            aad = b"PADAMHW1|" + hdr_bytes
            db_nonce = secrets.token_bytes(12)
            ct = AESGCM(bytes(dek)).encrypt(db_nonce, bytes(plain_bytes), aad)
            container = (
                CONTAINER_MAGIC
                + struct.pack(">I", len(hdr_bytes))
                + hdr_bytes
                + db_nonce
                + ct
            )
            tmp_out = p.with_name(p.name + ".hwseal.tmp")
            tmp_out.write_bytes(container)
            _secure_delete(p)
            tmp_out.replace(p)
            _save_hw_monotonic_state(p, header, owner_sk)
            return {
                "status": "sealed",
                "db": str(p),
                "mode": clean_mode,
                "seal_seq": next_seq,
                "container_id": container_id,
                "owner_pubkey_hex": owner_pub_hex,
                "plain_sha256": header["plain_sha256"],
                "plain_size": header["plain_size"],
                "container_size": len(container),
            }
        finally:
            _wipe_bytes(dek)
    finally:
        _wipe_bytes(plain_bytes)


def _recover_dek_and_update_header(
    header: dict[str, Any],
    *,
    assertion_cb: Callable[[bytes, bytes, dict[str, Any]], Fido2Assertion] | None = None,
    fido2_token: Any | None = None,
    use_webauthn: bool = False,
) -> tuple[bytearray, dict[str, Any]]:
    mode = header["mode"]
    rp_id = str(header.get("rp_id") or "padam.local")
    require_uv = bool(header.get("require_uv", True))
    wk = header.get("wrapped_keys") or {}
    new_header = dict(header)

    if mode == "dpapi":
        raw_dek = _dpapi_unprotect(bytes.fromhex(wk["dpapi_hex"]))
        return bytearray(raw_dek), new_header

    finfo = header.get("fido2") or {}
    salt = bytes.fromhex(finfo["hmac_salt_hex"])
    challenge = secrets.token_bytes(32)
    if assertion_cb is not None:
        ass = assertion_cb(challenge, salt, finfo)
    elif fido2_token is not None:
        ass = fido2_token.assert_challenge(challenge, salt, increment_counter=True)
    elif use_webauthn:
        from . import webauthn_win

        ass = webauthn_win.webauthn_assertion_cb()(challenge, salt, finfo)
    else:
        raise HardwareAuthError("FIDO2 assertion callback or token required to unseal database")

    new_sc = verify_fido2_assertion(
        ass,
        expected_credential_id=bytes.fromhex(finfo["credential_id_hex"]),
        public_key_pem=finfo["public_key_pem"],
        expected_challenge=challenge,
        rp_id=rp_id,
        last_sign_count=int(finfo.get("last_sign_count", 0)),
        require_uv=require_uv,
    )
    new_finfo = dict(finfo)
    new_finfo["last_sign_count"] = new_sc
    new_header["fido2"] = new_finfo

    if mode == "fido2":
        raw_dek = _unwrap_dek_fido2(wk["fido2_hex"], ass.hmac_secret, salt, rp_id)
        return bytearray(raw_dek), new_header

    if mode == "fido2+dpapi":
        share_dpapi = bytearray(_dpapi_unprotect(bytes.fromhex(wk["dpapi_share_hex"])))
        share_fido = bytearray(_unwrap_dek_fido2(wk["fido2_share_hex"], ass.hmac_secret, salt, rp_id))
        try:
            dek = bytearray(bytes(a ^ b for a, b in zip(share_dpapi, share_fido)))
            return dek, new_header
        finally:
            _wipe_bytes(share_dpapi)
            _wipe_bytes(share_fido)

    raise HardwareSealError(f"Unsupported container mode: {mode}")


def unseal_database(
    db_path: Path | str,
    *,
    fido2_token: Any | None = None,
    assertion_cb: Callable[[bytes, bytes, dict[str, Any]], Fido2Assertion] | None = None,
    use_webauthn: bool = False,
    expected_owner_pubkey_hex: str | None = None,
    allow_insecure_test_token: bool = False,
) -> dict[str, Any]:
    """Проверяет подпись владельца, монотонный счётчик, аппаратное доказательство и распечатывает БД."""
    if fido2_token is not None:
        _reject_software_token_unless_allowed(fido2_token, allow_insecure_test_token)
    p = Path(db_path)
    raw = p.read_bytes()
    if len(raw) < 28 or raw[:8] != CONTAINER_MAGIC:
        raise HardwareSealError("Database is not a valid PADAMHW1 container")
    hdr_len = struct.unpack(">I", raw[8:12])[0]
    hdr_bytes = raw[12 : 12 + hdr_len]
    header = json.loads(hdr_bytes.decode("utf-8"))
    _verify_hw_header_and_monotonic(p, header, expected_owner_pubkey_hex=expected_owner_pubkey_hex)
    db_nonce = raw[12 + hdr_len : 12 + hdr_len + 12]
    ct = raw[12 + hdr_len + 12 :]

    dek, _ = _recover_dek_and_update_header(
        header, assertion_cb=assertion_cb, fido2_token=fido2_token, use_webauthn=use_webauthn
    )
    try:
        try:
            plain = bytearray(AESGCM(bytes(dek)).decrypt(db_nonce, ct, b"PADAMHW1|" + hdr_bytes))
        except InvalidTag as exc:
            raise HardwareAuthError("Container GCM authentication failed") from exc
        try:
            if hashlib.sha256(plain).hexdigest() != header.get("plain_sha256"):
                raise HardwareSealError("Unsealed database SHA-256 mismatch")
            tmp_plain = p.with_name(p.name + ".unseal.tmp")
            tmp_plain.write_bytes(plain)
            tmp_plain.replace(p)
            return {
                "status": "unsealed",
                "db": str(p),
                "mode": header["mode"],
                "plain_sha256": header["plain_sha256"],
                "plain_size": len(plain),
            }
        finally:
            _wipe_bytes(plain)
    finally:
        _wipe_bytes(dek)


class HardwareSealedMemory:
    """Контекстный менеджер защищённой памяти: открывает после FIDO2/DPAPI и автоперезапечатывает при выходе."""

    def __init__(
        self,
        sealed_db_path: Path | str,
        *,
        user_id: str = "default",
        fido2_token: Any | None = None,
        assertion_cb: Callable[[bytes, bytes, dict[str, Any]], Fido2Assertion] | None = None,
        use_webauthn: bool = False,
        expected_owner_pubkey_hex: str | None = None,
        allow_insecure_test_token: bool = False,
    ) -> None:
        if fido2_token is not None:
            _reject_software_token_unless_allowed(fido2_token, allow_insecure_test_token)
        self.sealed_path = Path(sealed_db_path)
        self.user_id = user_id
        self.fido2_token = fido2_token
        self.assertion_cb = assertion_cb
        self.use_webauthn = bool(use_webauthn)
        self.expected_owner_pubkey_hex = expected_owner_pubkey_hex
        self.allow_insecure_test_token = bool(allow_insecure_test_token)
        self._work_dir: Path | None = None
        self._work_db: Path | None = None
        self._header: dict[str, Any] | None = None
        self._dek: bytearray | None = None
        self.mem: Memory | None = None

    def open(self) -> Memory:
        if self.fido2_token is not None:
            _reject_software_token_unless_allowed(self.fido2_token, self.allow_insecure_test_token)
        raw = self.sealed_path.read_bytes()
        if len(raw) < 28 or raw[:8] != CONTAINER_MAGIC:
            raise HardwareSealError("Database is not a valid PADAMHW1 container")
        hdr_len = struct.unpack(">I", raw[8:12])[0]
        hdr_bytes = raw[12 : 12 + hdr_len]
        header = json.loads(hdr_bytes.decode("utf-8"))
        _verify_hw_header_and_monotonic(
            self.sealed_path, header, expected_owner_pubkey_hex=self.expected_owner_pubkey_hex
        )
        db_nonce = raw[12 + hdr_len : 12 + hdr_len + 12]
        ct = raw[12 + hdr_len + 12 :]

        dek, updated_header = _recover_dek_and_update_header(
            header, assertion_cb=self.assertion_cb, fido2_token=self.fido2_token, use_webauthn=self.use_webauthn
        )
        try:
            plain = bytearray(AESGCM(bytes(dek)).decrypt(db_nonce, ct, b"PADAMHW1|" + hdr_bytes))
        except InvalidTag as exc:
            _wipe_bytes(dek)
            raise HardwareAuthError("Container GCM authentication failed") from exc

        self._dek = dek
        self._header = updated_header
        self._work_dir = Path(tempfile.mkdtemp(prefix="padam_hw_"))
        self._work_db = self._work_dir / self.sealed_path.name
        try:
            self._work_db.write_bytes(plain)
        finally:
            _wipe_bytes(plain)
        self.mem = Memory(user_id=self.user_id, store=Store(self._work_db))
        return self.mem

    def close(self) -> None:
        if self.mem is not None:
            try:
                self.mem.close()
            finally:
                self.mem = None
        if self._work_db is not None and self._work_db.exists() and self._dek is not None and self._header is not None:
            _checkpoint_sqlite_if_openable(self._work_db)
            plain = bytearray(self._work_db.read_bytes())
            try:
                upd = dict(self._header)
                upd["seal_seq"] = int(upd.get("seal_seq") or 1) + 1
                upd["sealed_at"] = _utc_now()
                upd["plain_sha256"] = hashlib.sha256(plain).hexdigest()
                upd["plain_size"] = len(plain)
                owner_sk, _ = _get_or_create_hw_owner_key(self.sealed_path)
                upd = _sign_hw_header(upd, owner_sk)
                hdr_bytes = json.dumps(upd, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                nonce = secrets.token_bytes(12)
                ct = AESGCM(bytes(self._dek)).encrypt(nonce, bytes(plain), b"PADAMHW1|" + hdr_bytes)
                container = CONTAINER_MAGIC + struct.pack(">I", len(hdr_bytes)) + hdr_bytes + nonce + ct
                tmp_out = self.sealed_path.with_name(self.sealed_path.name + ".hwre.tmp")
                tmp_out.write_bytes(container)
                tmp_out.replace(self.sealed_path)
                _save_hw_monotonic_state(self.sealed_path, upd, owner_sk)
            finally:
                _wipe_bytes(plain)
        if self._dek is not None:
            _wipe_bytes(self._dek)
            self._dek = None
        if self._work_db is not None:
            _secure_delete(self._work_db)
            self._work_db = None
        if self._work_dir is not None and self._work_dir.exists():
            shutil.rmtree(self._work_dir, ignore_errors=True)
            self._work_dir = None

    def __enter__(self) -> Memory:
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
