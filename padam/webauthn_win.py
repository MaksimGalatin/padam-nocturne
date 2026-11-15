"""Настоящий FIDO2 / Windows Hello через системную webauthn.dll (без сторонних пакетов).

Структуры повторяют официальный заголовок Microsoft ``webauthn.h`` (microsoft/webauthn,
WEBAUTHN_API_CURRENT_VERSION = 9). Версии вложенных структур выбираются по номеру API,
который вернула ``WebAuthNGetApiVersionNumber()`` — как требует комментарий в заголовке.

Живые вызовы ``WebAuthNAuthenticatorMakeCredential`` / ``WebAuthNAuthenticatorGetAssertion``
показывают системное окно Windows Hello / ключа безопасности и требуют касания человека.
Поэтому они выполняются ТОЛЬКО по явной команде владельца (``padam seal --webauthn``),
а в тестах используется подставной объект ``dll`` с теми же функциями.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import secrets
import struct
import sys
from ctypes import POINTER, Structure, c_int, c_long, c_ubyte, c_uint32, c_void_p, c_wchar_p
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

DWORD = c_uint32
BOOL = c_int
LONG = c_long
PBYTE = POINTER(c_ubyte)

S_OK = 0
COSE_ALG_ES256 = -7
COSE_ALG_EDDSA = -8
COSE_ALG_RS256 = -257

ATTACHMENT_ANY = 0
ATTACHMENT_PLATFORM = 1
ATTACHMENT_CROSS_PLATFORM = 2

UV_REQUIRED = 1
UV_PREFERRED = 2

ATTESTATION_NONE = 1


class WebAuthnUnavailableError(RuntimeError):
    """webauthn.dll недоступна (не Windows или старая сборка)."""


class WebAuthnCallError(PermissionError):
    """Системный вызов WebAuthn вернул ошибку (отмена, таймаут, нет ключа)."""


# ---------------------------------------------------------------------------
# Структуры webauthn.h (полные, до версии 9; dwVersion выставляется по API)
# ---------------------------------------------------------------------------


class WEBAUTHN_RP_ENTITY_INFORMATION(Structure):
    _fields_ = [("dwVersion", DWORD), ("pwszId", c_wchar_p), ("pwszName", c_wchar_p), ("pwszIcon", c_wchar_p)]


class WEBAUTHN_USER_ENTITY_INFORMATION(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("cbId", DWORD),
        ("pbId", PBYTE),
        ("pwszName", c_wchar_p),
        ("pwszIcon", c_wchar_p),
        ("pwszDisplayName", c_wchar_p),
    ]


class WEBAUTHN_CLIENT_DATA(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("cbClientDataJSON", DWORD),
        ("pbClientDataJSON", PBYTE),
        ("pwszHashAlgId", c_wchar_p),
    ]


class WEBAUTHN_COSE_CREDENTIAL_PARAMETER(Structure):
    _fields_ = [("dwVersion", DWORD), ("pwszCredentialType", c_wchar_p), ("lAlg", LONG)]


class WEBAUTHN_COSE_CREDENTIAL_PARAMETERS(Structure):
    _fields_ = [
        ("cCredentialParameters", DWORD),
        ("pCredentialParameters", POINTER(WEBAUTHN_COSE_CREDENTIAL_PARAMETER)),
    ]


class WEBAUTHN_CREDENTIAL(Structure):
    _fields_ = [("dwVersion", DWORD), ("cbId", DWORD), ("pbId", PBYTE), ("pwszCredentialType", c_wchar_p)]


class WEBAUTHN_CREDENTIALS(Structure):
    _fields_ = [("cCredentials", DWORD), ("pCredentials", POINTER(WEBAUTHN_CREDENTIAL))]


class WEBAUTHN_CREDENTIAL_EX(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("cbId", DWORD),
        ("pbId", PBYTE),
        ("pwszCredentialType", c_wchar_p),
        ("dwTransports", DWORD),
    ]


class WEBAUTHN_CREDENTIAL_LIST(Structure):
    _fields_ = [("cCredentials", DWORD), ("ppCredentials", POINTER(POINTER(WEBAUTHN_CREDENTIAL_EX)))]


class WEBAUTHN_HMAC_SECRET_SALT(Structure):
    _fields_ = [("cbFirst", DWORD), ("pbFirst", PBYTE), ("cbSecond", DWORD), ("pbSecond", PBYTE)]


class WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT(Structure):
    _fields_ = [("cbCredID", DWORD), ("pbCredID", PBYTE), ("pHmacSecretSalt", POINTER(WEBAUTHN_HMAC_SECRET_SALT))]


class WEBAUTHN_HMAC_SECRET_SALT_VALUES(Structure):
    _fields_ = [
        ("pGlobalHmacSalt", POINTER(WEBAUTHN_HMAC_SECRET_SALT)),
        ("cCredWithHmacSecretSaltList", DWORD),
        ("pCredWithHmacSecretSaltList", POINTER(WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT)),
    ]


class WEBAUTHN_EXTENSION(Structure):
    _fields_ = [("pwszExtensionIdentifier", c_wchar_p), ("cbExtension", DWORD), ("pvExtension", c_void_p)]


class WEBAUTHN_EXTENSIONS(Structure):
    _fields_ = [("cExtensions", DWORD), ("pExtensions", POINTER(WEBAUTHN_EXTENSION))]


class WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("dwTimeoutMilliseconds", DWORD),
        ("CredentialList", WEBAUTHN_CREDENTIALS),
        ("Extensions", WEBAUTHN_EXTENSIONS),
        ("dwAuthenticatorAttachment", DWORD),
        ("bRequireResidentKey", BOOL),
        ("dwUserVerificationRequirement", DWORD),
        ("dwAttestationConveyancePreference", DWORD),
        ("dwFlags", DWORD),
        # v2
        ("pCancellationId", c_void_p),
        # v3
        ("pExcludeCredentialList", POINTER(WEBAUTHN_CREDENTIAL_LIST)),
        # v4
        ("dwEnterpriseAttestation", DWORD),
        ("dwLargeBlobSupport", DWORD),
        ("bPreferResidentKey", BOOL),
        # v5
        ("bBrowserInPrivateMode", BOOL),
        # v6
        ("bEnablePrf", BOOL),
        # v7
        ("pLinkedDevice", c_void_p),
        ("cbJsonExt", DWORD),
        ("pbJsonExt", PBYTE),
        # v8
        ("pPRFGlobalEval", POINTER(WEBAUTHN_HMAC_SECRET_SALT)),
        ("cCredentialHints", DWORD),
        ("ppwszCredentialHints", POINTER(c_wchar_p)),
        ("bThirdPartyPayment", BOOL),
        # v9
        ("pwszRemoteWebOrigin", c_wchar_p),
        ("cbPublicKeyCredentialCreationOptionsJSON", DWORD),
        ("pbPublicKeyCredentialCreationOptionsJSON", PBYTE),
        ("cbAuthenticatorId", DWORD),
        ("pbAuthenticatorId", PBYTE),
    ]


class WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("dwTimeoutMilliseconds", DWORD),
        ("CredentialList", WEBAUTHN_CREDENTIALS),
        ("Extensions", WEBAUTHN_EXTENSIONS),
        ("dwAuthenticatorAttachment", DWORD),
        ("dwUserVerificationRequirement", DWORD),
        ("dwFlags", DWORD),
        # v2
        ("pwszU2fAppId", c_wchar_p),
        ("pbU2fAppId", POINTER(BOOL)),
        # v3
        ("pCancellationId", c_void_p),
        # v4
        ("pAllowCredentialList", POINTER(WEBAUTHN_CREDENTIAL_LIST)),
        # v5
        ("dwCredLargeBlobOperation", DWORD),
        ("cbCredLargeBlob", DWORD),
        ("pbCredLargeBlob", PBYTE),
        # v6
        ("pHmacSecretSaltValues", POINTER(WEBAUTHN_HMAC_SECRET_SALT_VALUES)),
        ("bBrowserInPrivateMode", BOOL),
        # v7
        ("pLinkedDevice", c_void_p),
        ("bAutoFill", BOOL),
        ("cbJsonExt", DWORD),
        ("pbJsonExt", PBYTE),
        # v8
        ("cCredentialHints", DWORD),
        ("ppwszCredentialHints", POINTER(c_wchar_p)),
        # v9
        ("pwszRemoteWebOrigin", c_wchar_p),
        ("cbPublicKeyCredentialRequestOptionsJSON", DWORD),
        ("pbPublicKeyCredentialRequestOptionsJSON", PBYTE),
        ("cbAuthenticatorId", DWORD),
        ("pbAuthenticatorId", PBYTE),
    ]


class WEBAUTHN_CREDENTIAL_ATTESTATION(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("pwszFormatType", c_wchar_p),
        ("cbAuthenticatorData", DWORD),
        ("pbAuthenticatorData", PBYTE),
        ("cbAttestation", DWORD),
        ("pbAttestation", PBYTE),
        ("dwAttestationDecodeType", DWORD),
        ("pvAttestationDecode", c_void_p),
        ("cbAttestationObject", DWORD),
        ("pbAttestationObject", PBYTE),
        ("cbCredentialId", DWORD),
        ("pbCredentialId", PBYTE),
        # v2
        ("Extensions", WEBAUTHN_EXTENSIONS),
        # v3
        ("dwUsedTransport", DWORD),
        # v4
        ("bEpAtt", BOOL),
        ("bLargeBlobSupported", BOOL),
        ("bResidentKey", BOOL),
        # v5
        ("bPrfEnabled", BOOL),
        # v6
        ("cbUnsignedExtensionOutputs", DWORD),
        ("pbUnsignedExtensionOutputs", PBYTE),
        # v7
        ("pHmacSecret", POINTER(WEBAUTHN_HMAC_SECRET_SALT)),
        ("bThirdPartyPayment", BOOL),
        # v8
        ("dwTransports", DWORD),
        ("cbClientDataJSON", DWORD),
        ("pbClientDataJSON", PBYTE),
        ("cbRegistrationResponseJSON", DWORD),
        ("pbRegistrationResponseJSON", PBYTE),
    ]


class WEBAUTHN_ASSERTION(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("cbAuthenticatorData", DWORD),
        ("pbAuthenticatorData", PBYTE),
        ("cbSignature", DWORD),
        ("pbSignature", PBYTE),
        ("Credential", WEBAUTHN_CREDENTIAL),
        ("cbUserId", DWORD),
        ("pbUserId", PBYTE),
        # v2
        ("Extensions", WEBAUTHN_EXTENSIONS),
        ("cbCredLargeBlob", DWORD),
        ("pbCredLargeBlob", PBYTE),
        ("dwCredLargeBlobStatus", DWORD),
        # v3
        ("pHmacSecret", POINTER(WEBAUTHN_HMAC_SECRET_SALT)),
        # v4
        ("dwUsedTransport", DWORD),
        # v5
        ("cbUnsignedExtensionOutputs", DWORD),
        ("pbUnsignedExtensionOutputs", PBYTE),
        # v6
        ("cbClientDataJSON", DWORD),
        ("pbClientDataJSON", PBYTE),
        ("cbAuthenticationResponseJSON", DWORD),
        ("pbAuthenticationResponseJSON", PBYTE),
    ]


# Таблица из комментариев webauthn.h: номер API -> версия структуры опций
_MC_OPTIONS_BY_API = {1: 3, 2: 3, 3: 4, 4: 5, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9}
_GA_OPTIONS_BY_API = {1: 4, 2: 4, 3: 5, 4: 6, 5: 6, 6: 6, 7: 7, 8: 8, 9: 9}


def mc_options_version(api: int) -> int:
    return _MC_OPTIONS_BY_API.get(int(api), 9 if api > 9 else 3)


def ga_options_version(api: int) -> int:
    return _GA_OPTIONS_BY_API.get(int(api), 9 if api > 9 else 4)


# ---------------------------------------------------------------------------
# Минимальный CBOR (RFC 8949) для COSE-ключей и authenticatorData
# ---------------------------------------------------------------------------


def cbor_decode(data: bytes, pos: int = 0) -> tuple[Any, int]:
    """Декодирует один CBOR-элемент (целые, байты, строки, массивы, словари, простые значения)."""
    if pos >= len(data):
        raise ValueError("CBOR: unexpected end of data")
    ib = data[pos]
    major, info = ib >> 5, ib & 0x1F
    pos += 1
    if info < 24:
        val = info
    elif info == 24:
        val = data[pos]
        pos += 1
    elif info == 25:
        val = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
    elif info == 26:
        val = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
    elif info == 27:
        val = struct.unpack(">Q", data[pos:pos + 8])[0]
        pos += 8
    else:
        raise ValueError("CBOR: indefinite length is not supported")
    if major == 0:
        return val, pos
    if major == 1:
        return -1 - val, pos
    if major == 2:
        if pos + val > len(data):
            raise ValueError("CBOR: byte string out of range")
        return bytes(data[pos:pos + val]), pos + val
    if major == 3:
        if pos + val > len(data):
            raise ValueError("CBOR: text string out of range")
        return data[pos:pos + val].decode("utf-8"), pos + val
    if major == 4:
        arr = []
        for _ in range(val):
            item, pos = cbor_decode(data, pos)
            arr.append(item)
        return arr, pos
    if major == 5:
        mp: dict = {}
        for _ in range(val):
            k, pos = cbor_decode(data, pos)
            v, pos = cbor_decode(data, pos)
            mp[k] = v
        return mp, pos
    if major == 7:
        return {20: False, 21: True, 22: None}.get(val, val), pos
    raise ValueError(f"CBOR: unsupported major type {major}")


def _cbor_head(major: int, val: int) -> bytes:
    if val < 24:
        return bytes([(major << 5) | val])
    if val < 256:
        return bytes([(major << 5) | 24, val])
    if val < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", val)
    return bytes([(major << 5) | 26]) + struct.pack(">I", val)


def cbor_encode(obj: Any) -> bytes:
    """Кодирует подмножество CBOR (нужно для тестовых COSE-ключей)."""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_head(0, obj) if obj >= 0 else _cbor_head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(obj, list):
        return _cbor_head(4, len(obj)) + b"".join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        return _cbor_head(5, len(obj)) + b"".join(cbor_encode(k) + cbor_encode(v) for k, v in obj.items())
    raise TypeError(f"CBOR: cannot encode {type(obj)!r}")


def cose_key_to_pem(cose: dict) -> tuple[str, int]:
    """Переводит COSE_Key (RFC 9053) в PEM SubjectPublicKeyInfo. Возвращает (pem, alg)."""
    kty = cose.get(1)
    alg = int(cose.get(3, 0))
    if kty == 2:  # EC2
        crv = cose.get(-1)
        if crv != 1:
            raise ValueError(f"COSE EC2 curve {crv} is not supported (only P-256)")
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
            raise ValueError("COSE EC2 key must have 32-byte x and y")
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)
    elif kty == 1:  # OKP
        if cose.get(-1) != 6:
            raise ValueError("COSE OKP curve is not supported (only Ed25519)")
        x = cose.get(-2)
        if not (isinstance(x, bytes) and len(x) == 32):
            raise ValueError("COSE Ed25519 key must be 32 bytes")
        pub = ed25519.Ed25519PublicKey.from_public_bytes(x)
    elif kty == 3:  # RSA
        n, e = cose.get(-1), cose.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes)):
            raise ValueError("COSE RSA key must have n and e")
        pub = rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
    else:
        raise ValueError(f"COSE key type {kty} is not supported")
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return pem, alg


def parse_attested_authenticator_data(auth_data: bytes) -> dict:
    """Разбирает authenticatorData с attestedCredentialData (флаг AT=0x40)."""
    if len(auth_data) < 37:
        raise ValueError("authenticatorData is too short")
    flags = auth_data[32]
    sign_count = struct.unpack(">I", auth_data[33:37])[0]
    out = {
        "rp_id_hash": auth_data[:32],
        "flags": flags,
        "up": bool(flags & 0x01),
        "uv": bool(flags & 0x04),
        "sign_count": sign_count,
    }
    if not flags & 0x40:
        raise ValueError("authenticatorData has no attested credential data (AT=0)")
    pos = 37
    out["aaguid"] = auth_data[pos:pos + 16]
    pos += 16
    cred_len = struct.unpack(">H", auth_data[pos:pos + 2])[0]
    pos += 2
    out["credential_id"] = auth_data[pos:pos + cred_len]
    pos += cred_len
    cose, _ = cbor_decode(auth_data, pos)
    if not isinstance(cose, dict):
        raise ValueError("credentialPublicKey is not a COSE map")
    out["cose_key"] = cose
    return out


# ---------------------------------------------------------------------------
# Доступ к системной библиотеке
# ---------------------------------------------------------------------------


def _bytes_buf(data: bytes, keep: list) -> Any:
    buf = (c_ubyte * max(1, len(data))).from_buffer_copy(data if data else b"\x00")
    keep.append(buf)
    return ctypes.cast(buf, PBYTE)


def _read_bytes(ptr: Any, size: int) -> bytes:
    if not ptr or int(size) <= 0:
        return b""
    return bytes(ctypes.string_at(ptr, int(size)))


def load_webauthn_dll() -> Any:
    """Загружает webauthn.dll с объявленными сигнатурами из webauthn.h."""
    if sys.platform != "win32":
        raise WebAuthnUnavailableError("webauthn.dll exists only on Windows")
    try:
        dll = ctypes.WinDLL("webauthn.dll")
    except OSError as exc:
        raise WebAuthnUnavailableError(f"cannot load webauthn.dll: {exc}") from exc
    dll.WebAuthNGetApiVersionNumber.restype = DWORD
    dll.WebAuthNGetApiVersionNumber.argtypes = []
    dll.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.restype = c_long
    dll.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.argtypes = [POINTER(BOOL)]
    dll.WebAuthNAuthenticatorMakeCredential.restype = c_long
    dll.WebAuthNAuthenticatorMakeCredential.argtypes = [
        c_void_p,
        POINTER(WEBAUTHN_RP_ENTITY_INFORMATION),
        POINTER(WEBAUTHN_USER_ENTITY_INFORMATION),
        POINTER(WEBAUTHN_COSE_CREDENTIAL_PARAMETERS),
        POINTER(WEBAUTHN_CLIENT_DATA),
        POINTER(WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS),
        POINTER(POINTER(WEBAUTHN_CREDENTIAL_ATTESTATION)),
    ]
    dll.WebAuthNAuthenticatorGetAssertion.restype = c_long
    dll.WebAuthNAuthenticatorGetAssertion.argtypes = [
        c_void_p,
        c_wchar_p,
        POINTER(WEBAUTHN_CLIENT_DATA),
        POINTER(WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS),
        POINTER(POINTER(WEBAUTHN_ASSERTION)),
    ]
    dll.WebAuthNFreeCredentialAttestation.restype = None
    dll.WebAuthNFreeCredentialAttestation.argtypes = [POINTER(WEBAUTHN_CREDENTIAL_ATTESTATION)]
    dll.WebAuthNFreeAssertion.restype = None
    dll.WebAuthNFreeAssertion.argtypes = [POINTER(WEBAUTHN_ASSERTION)]
    dll.WebAuthNGetErrorName.restype = c_wchar_p
    dll.WebAuthNGetErrorName.argtypes = [c_long]
    return dll


def api_version(dll: Any = None) -> int:
    """Номер API webauthn.dll (функция без аргументов, возвращает DWORD)."""
    d = dll if dll is not None else load_webauthn_dll()
    return int(d.WebAuthNGetApiVersionNumber())


def platform_authenticator_available(dll: Any = None) -> bool:
    d = dll if dll is not None else load_webauthn_dll()
    flag = BOOL(0)
    hr = d.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(ctypes.byref(flag))
    return int(hr) == S_OK and bool(flag.value)


def _error_name(dll: Any, hr: int) -> str:
    try:
        name = dll.WebAuthNGetErrorName(int(hr))
        return str(name) if name else "UnknownError"
    except Exception:
        return "UnknownError"


def _owner_hwnd() -> int:
    if sys.platform != "win32":
        return 0
    try:
        hwnd = ctypes.windll.user32.GetForegroundWindow()  # type: ignore[attr-defined]
        if not hwnd:
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()  # type: ignore[attr-defined]
        return int(hwnd or 0)
    except Exception:
        return 0


def build_client_data(kind: str, challenge: bytes, rp_id: str) -> bytes:
    """clientDataJSON собирается нами; Windows хеширует его SHA-256 и подписывает authData || hash."""
    import base64
    return json.dumps(
        {
            "type": kind,
            "challenge": base64.urlsafe_b64encode(challenge).rstrip(b"=").decode("ascii"),
            "origin": f"https://{rp_id}",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def make_credential(
    rp_id: str = "padam.local",
    *,
    rp_name: str = "PADAM Nocturne",
    user_name: str = "padam-owner",
    attachment: int = ATTACHMENT_ANY,
    timeout_ms: int = 60000,
    dll: Any = None,
    hwnd: int | None = None,
) -> dict:
    """Регистрирует новый ключ FIDO2 с PRF/hmac-secret. Показывает окно Windows Hello."""
    d = dll if dll is not None else load_webauthn_dll()
    api = api_version(d)
    keep: list = []

    rp = WEBAUTHN_RP_ENTITY_INFORMATION(1, rp_id, rp_name, None)
    user_id = secrets.token_bytes(32)
    user = WEBAUTHN_USER_ENTITY_INFORMATION(1, len(user_id), _bytes_buf(user_id, keep), user_name, None, user_name)

    params_arr = (WEBAUTHN_COSE_CREDENTIAL_PARAMETER * 3)(
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER(1, "public-key", COSE_ALG_ES256),
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER(1, "public-key", COSE_ALG_EDDSA),
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER(1, "public-key", COSE_ALG_RS256),
    )
    keep.append(params_arr)
    params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS(3, ctypes.cast(params_arr, POINTER(WEBAUTHN_COSE_CREDENTIAL_PARAMETER)))

    challenge = secrets.token_bytes(32)
    cdj = build_client_data("webauthn.create", challenge, rp_id)
    client = WEBAUTHN_CLIENT_DATA(1, len(cdj), _bytes_buf(cdj, keep), "SHA-256")

    opts = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS()
    opts.dwVersion = mc_options_version(api)
    opts.dwTimeoutMilliseconds = int(timeout_ms)
    opts.dwAuthenticatorAttachment = int(attachment)
    opts.dwUserVerificationRequirement = UV_REQUIRED
    opts.dwAttestationConveyancePreference = ATTESTATION_NONE
    hmac_flag = BOOL(1)
    keep.append(hmac_flag)
    ext_arr = (WEBAUTHN_EXTENSION * 1)(
        WEBAUTHN_EXTENSION("hmac-secret", ctypes.sizeof(BOOL), ctypes.cast(ctypes.byref(hmac_flag), c_void_p))
    )
    keep.append(ext_arr)
    opts.Extensions = WEBAUTHN_EXTENSIONS(1, ctypes.cast(ext_arr, POINTER(WEBAUTHN_EXTENSION)))
    if opts.dwVersion >= 6:
        opts.bEnablePrf = 1

    out_ptr = POINTER(WEBAUTHN_CREDENTIAL_ATTESTATION)()
    hr = d.WebAuthNAuthenticatorMakeCredential(
        hwnd if hwnd is not None else _owner_hwnd(),
        ctypes.byref(rp),
        ctypes.byref(user),
        ctypes.byref(params),
        ctypes.byref(client),
        ctypes.byref(opts),
        ctypes.byref(out_ptr),
    )
    if int(hr) != S_OK or not out_ptr:
        raise WebAuthnCallError(f"WebAuthNAuthenticatorMakeCredential failed: {_error_name(d, hr)} (0x{int(hr) & 0xFFFFFFFF:08X})")
    try:
        att = out_ptr.contents
        auth_data = _read_bytes(att.pbAuthenticatorData, att.cbAuthenticatorData)
        parsed = parse_attested_authenticator_data(auth_data)
        pem, alg = cose_key_to_pem(parsed["cose_key"])
        prf_enabled = bool(att.bPrfEnabled) if att.dwVersion >= 5 else None
        cred_id = _read_bytes(att.pbCredentialId, att.cbCredentialId) or parsed["credential_id"]
        return {
            "rp_id": rp_id,
            "credential_id": cred_id,
            "public_key_pem": pem,
            "cose_alg": alg,
            "sign_count": parsed["sign_count"],
            "uv": parsed["uv"],
            "prf_enabled": prf_enabled,
            "api_version": api,
        }
    finally:
        d.WebAuthNFreeCredentialAttestation(out_ptr)


def get_assertion(
    rp_id: str,
    credential_id: bytes,
    challenge: bytes,
    salt: bytes,
    *,
    timeout_ms: int = 60000,
    dll: Any = None,
    hwnd: int | None = None,
):
    """Запрашивает подпись и hmac-secret (PRF) у ключа. Показывает окно Windows Hello."""
    from .hardware_seal import Fido2Assertion

    d = dll if dll is not None else load_webauthn_dll()
    api = api_version(d)
    ga_ver = ga_options_version(api)
    if ga_ver < 6:
        raise WebAuthnUnavailableError(f"webauthn.dll API {api} has no hmac-secret salt support (need >= 4)")
    keep: list = []

    cdj = build_client_data("webauthn.get", challenge, rp_id)
    client = WEBAUTHN_CLIENT_DATA(1, len(cdj), _bytes_buf(cdj, keep), "SHA-256")

    cred_arr = (WEBAUTHN_CREDENTIAL * 1)(
        WEBAUTHN_CREDENTIAL(1, len(credential_id), _bytes_buf(credential_id, keep), "public-key")
    )
    keep.append(cred_arr)

    salt_struct = WEBAUTHN_HMAC_SECRET_SALT(len(salt), _bytes_buf(salt, keep), 0, None)
    keep.append(salt_struct)
    salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES(ctypes.pointer(salt_struct), 0, None)
    keep.append(salt_values)

    opts = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS()
    opts.dwVersion = ga_ver
    opts.dwTimeoutMilliseconds = int(timeout_ms)
    opts.CredentialList = WEBAUTHN_CREDENTIALS(1, ctypes.cast(cred_arr, POINTER(WEBAUTHN_CREDENTIAL)))
    opts.dwAuthenticatorAttachment = ATTACHMENT_ANY
    opts.dwUserVerificationRequirement = UV_REQUIRED
    opts.pHmacSecretSaltValues = ctypes.pointer(salt_values)

    out_ptr = POINTER(WEBAUTHN_ASSERTION)()
    hr = d.WebAuthNAuthenticatorGetAssertion(
        hwnd if hwnd is not None else _owner_hwnd(),
        rp_id,
        ctypes.byref(client),
        ctypes.byref(opts),
        ctypes.byref(out_ptr),
    )
    if int(hr) != S_OK or not out_ptr:
        raise WebAuthnCallError(f"WebAuthNAuthenticatorGetAssertion failed: {_error_name(d, hr)} (0x{int(hr) & 0xFFFFFFFF:08X})")
    try:
        a = out_ptr.contents
        auth_data = _read_bytes(a.pbAuthenticatorData, a.cbAuthenticatorData)
        sig = _read_bytes(a.pbSignature, a.cbSignature)
        used_cred = _read_bytes(a.Credential.pbId, a.Credential.cbId) or credential_id
        hmac_secret = b""
        if a.dwVersion >= 3 and a.pHmacSecret:
            hs = a.pHmacSecret.contents
            hmac_secret = _read_bytes(hs.pbFirst, hs.cbFirst)
        if len(hmac_secret) != 32:
            raise WebAuthnCallError("authenticator returned no hmac-secret (PRF) output; key cannot unwrap the seal")
        return Fido2Assertion(
            credential_id=used_cred,
            authenticator_data=auth_data,
            client_data_json=cdj,
            signature=sig,
            hmac_secret=hmac_secret,
        )
    finally:
        d.WebAuthNFreeAssertion(out_ptr)


class WindowsWebAuthnToken:
    """Токен с тем же интерфейсом, что SoftwareFido2Token, но поверх настоящей webauthn.dll."""

    def __init__(self, credential: dict, *, dll: Any = None, timeout_ms: int = 60000) -> None:
        self.rp_id = str(credential.get("rp_id") or "padam.local")
        self.credential_id = bytes(credential["credential_id"])
        self._pem = str(credential["public_key_pem"])
        self._dll = dll
        self._timeout_ms = int(timeout_ms)

    @classmethod
    def enroll(cls, rp_id: str = "padam.local", *, dll: Any = None, **kw) -> "WindowsWebAuthnToken":
        cred = make_credential(rp_id, dll=dll, **kw)
        return cls(cred, dll=dll)

    def public_key_pem(self) -> str:
        return self._pem

    def assert_challenge(self, challenge: bytes, salt: bytes, *, increment_counter: bool = True):
        # increment_counter игнорируется: счётчик ведёт сам ключ
        return get_assertion(
            self.rp_id, self.credential_id, challenge, salt,
            timeout_ms=self._timeout_ms, dll=self._dll,
        )


def webauthn_assertion_cb(*, dll: Any = None, timeout_ms: int = 60000):
    """Колбэк для unseal_database/HardwareSealedMemory: берёт credential_id и rp_id из заголовка PADAMHW1."""

    def _cb(challenge: bytes, salt: bytes, finfo: dict):
        rp = str(finfo.get("rp_id") or "padam.local")
        return get_assertion(
            rp, bytes.fromhex(finfo["credential_id_hex"]), challenge, salt,
            timeout_ms=timeout_ms, dll=dll,
        )

    return _cb


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
