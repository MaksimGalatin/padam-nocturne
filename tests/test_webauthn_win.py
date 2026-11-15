"""Тесты нативного интерфейса Windows Hello / FIDO2 через webauthn.dll."""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import secrets
import struct
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from padam import hardware_seal, webauthn_win
from padam.memory import Memory
from padam.store import Store


def _build_attested_auth_data(rp_id: str, cred_id: bytes, cose_map: dict, sign_count: int = 0) -> bytes:
    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = 0x01 | 0x04 | 0x40  # UP | UV | AT
    aaguid = b"\x11" * 16
    cose_bytes = webauthn_win.cbor_encode(cose_map)
    return (
        rp_hash
        + bytes([flags])
        + struct.pack(">I", sign_count)
        + aaguid
        + struct.pack(">H", len(cred_id))
        + cred_id
        + cose_bytes
    )


class _FakeWebAuthnDll:
    """Честный ABI-мок webauthn.dll для автотестов без модального окна Windows Hello."""

    def __init__(self, *, alg: str = "ES256", sign_count_step: int = 0, fail_get_hr: int = 0) -> None:
        self.alg = alg
        self.sign_count = 0
        self.sign_count_step = sign_count_step
        self.fail_get_hr = fail_get_hr
        self.cred_id = secrets.token_bytes(32)
        self.hmac_root = secrets.token_bytes(32)
        self.freed_attestations = 0
        self.freed_assertions = 0
        self._keep: list[object] = []

        if alg == "ES256":
            self.sk = ec.generate_private_key(ec.SECP256R1())
            nums = self.sk.public_key().public_numbers()
            self.cose = {
                1: 2,
                3: -7,
                -1: 1,
                -2: nums.x.to_bytes(32, "big"),
                -3: nums.y.to_bytes(32, "big"),
            }
        elif alg == "EdDSA":
            self.sk = ed25519.Ed25519PrivateKey.generate()
            raw = self.sk.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self.cose = {1: 1, 3: -8, -1: 6, -2: raw}
        elif alg == "RS256":
            self.sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            nums = self.sk.public_key().public_numbers()
            n_len = (nums.n.bit_length() + 7) // 8
            e_len = (nums.e.bit_length() + 7) // 8
            self.cose = {
                1: 3,
                3: -257,
                -1: nums.n.to_bytes(n_len, "big"),
                -2: nums.e.to_bytes(e_len, "big"),
            }
        else:
            raise ValueError(alg)

    def _buf(self, data: bytes):
        arr = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        self._keep.append(arr)
        return ctypes.cast(arr, ctypes.POINTER(ctypes.c_ubyte)), len(data)

    def WebAuthNGetApiVersionNumber(self) -> int:
        return 7

    def WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(self, ptr) -> int:
        ptr._obj.value = 1
        return 0

    def WebAuthNGetErrorName(self, hr: int) -> str:
        return "NotAllowedError" if hr else "Success"

    def _deref(self, p):
        return p._obj if hasattr(p, "_obj") else p.contents

    def WebAuthNAuthenticatorMakeCredential(self, hwnd, rp_p, user_p, pubs_p, cd_p, opts_p, out_pp) -> int:
        rp_id = self._deref(rp_p).pwszId
        assert self._deref(opts_p).dwVersion == webauthn_win.mc_options_version(7)
        auth_data = _build_attested_auth_data(rp_id, self.cred_id, self.cose, sign_count=0)
        att_obj = webauthn_win.cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})

        att = webauthn_win.WEBAUTHN_CREDENTIAL_ATTESTATION()
        att.dwVersion = 6
        att.pwszFormatType = "none"
        att.pbAuthenticatorData, att.cbAuthenticatorData = self._buf(auth_data)
        att.pbAttestation, att.cbAttestation = self._buf(att_obj)
        att.pbCredentialId, att.cbCredentialId = self._buf(self.cred_id)
        att.dwUsedTransport = 4
        att.bResidentKey = 1
        ptr_val = ctypes.pointer(att)
        self._keep.extend([att, ptr_val])
        target = out_pp._obj if hasattr(out_pp, "_obj") else out_pp
        ctypes.memmove(ctypes.byref(target), ctypes.byref(ptr_val), ctypes.sizeof(ctypes.c_void_p))
        return 0

    def WebAuthNAuthenticatorGetAssertion(self, hwnd, rp_id, cd_p, opts_p, out_pp) -> int:
        if self.fail_get_hr:
            return self.fail_get_hr
        opts = self._deref(opts_p)
        cd_s = self._deref(cd_p)
        assert opts.dwVersion == webauthn_win.ga_options_version(7)
        cd = ctypes.string_at(cd_s.pbClientDataJSON, cd_s.cbClientDataJSON)
        self.sign_count += self.sign_count_step
        auth_data = (
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + bytes([0x01 | 0x04])
            + struct.pack(">I", self.sign_count)
        )
        payload = auth_data + hashlib.sha256(cd).digest()
        if isinstance(self.sk, ed25519.Ed25519PrivateKey):
            sig = self.sk.sign(payload)
        elif isinstance(self.sk, ec.EllipticCurvePrivateKey):
            sig = self.sk.sign(payload, ec.ECDSA(hashes.SHA256()))
        else:
            sig = self.sk.sign(payload, padding.PKCS1v15(), hashes.SHA256())

        salt_ptr = opts.pHmacSecretSaltValues.contents.pGlobalHmacSalt
        salt = ctypes.string_at(salt_ptr.contents.pbFirst, salt_ptr.contents.cbFirst)
        prf = hmac.new(self.hmac_root, salt, hashlib.sha256).digest()

        hs = webauthn_win.WEBAUTHN_HMAC_SECRET_SALT()
        hs.pbFirst, hs.cbFirst = self._buf(prf)
        hs.pbSecond, hs.cbSecond = self._buf(b"\x00")
        hs.cbSecond = 0

        a = webauthn_win.WEBAUTHN_ASSERTION()
        a.dwVersion = 4
        a.pbAuthenticatorData, a.cbAuthenticatorData = self._buf(auth_data)
        a.pbSignature, a.cbSignature = self._buf(sig)
        a.Credential.dwVersion = 1
        a.Credential.pbId, a.Credential.cbId = self._buf(self.cred_id)
        a.Credential.pwszCredentialType = "public-key"
        a.pHmacSecret = ctypes.pointer(hs)
        ptr_val = ctypes.pointer(a)
        self._keep.extend([hs, a, ptr_val])
        target = out_pp._obj if hasattr(out_pp, "_obj") else out_pp
        ctypes.memmove(ctypes.byref(target), ctypes.byref(ptr_val), ctypes.sizeof(ctypes.c_void_p))
        return 0

    def WebAuthNFreeCredentialAttestation(self, ptr) -> None:
        self.freed_attestations += 1

    def WebAuthNFreeAssertion(self, ptr) -> None:
        self.freed_assertions += 1


def test_real_windows_webauthn_dll_silent_probes() -> None:
    if sys.platform != "win32":
        pytest.skip("webauthn.dll exists only on Windows")
    dll = webauthn_win.load_webauthn_dll()
    ver = webauthn_win.api_version(dll)
    assert ver >= 1
    avail = webauthn_win.platform_authenticator_available(dll)
    assert isinstance(avail, bool)
    caps = hardware_seal.probe_hardware_capabilities()
    assert caps["webauthn_dll"] is True
    assert caps["webauthn_api_version"] == ver
    assert caps["platform_authenticator_available"] == avail


@pytest.mark.parametrize("alg", ["ES256", "EdDSA", "RS256"])
def test_cbor_cose_and_attested_auth_data_roundtrip(alg: str) -> None:
    fake = _FakeWebAuthnDll(alg=alg)
    auth_data = _build_attested_auth_data("padam.local", fake.cred_id, fake.cose, sign_count=0)
    parsed = webauthn_win.parse_attested_authenticator_data(auth_data)
    assert parsed["credential_id"] == fake.cred_id
    pem, cose_alg = webauthn_win.cose_key_to_pem(parsed["cose_key"])
    assert "BEGIN PUBLIC KEY" in pem
    assert cose_alg in (-7, -8, -257)


@pytest.mark.parametrize("alg,step", [("ES256", 0), ("EdDSA", 1), ("RS256", 0)])
def test_windows_webauthn_seal_open_and_unseal_end_to_end(tmp_path: Path, alg: str, step: int, monkeypatch) -> None:
    db_path = tmp_path / "vault.db"
    m = Memory(user_id="owner", store=Store(db_path))
    m.remember("Главный секрет для Windows Hello", kind="fact", scope="sec", agent_id="owner")
    m.close()

    fake = _FakeWebAuthnDll(alg=alg, sign_count_step=step)
    tok = webauthn_win.WindowsWebAuthnToken.enroll(rp_id="padam.local", dll=fake)
    assert fake.freed_attestations == 1

    sealed = hardware_seal.seal_database(db_path, mode="fido2", fido2_token=tok, rp_id="padam.local")
    assert sealed["mode"] == "fido2"
    assert fake.freed_assertions == 1

    monkeypatch.setattr(webauthn_win, "load_webauthn_dll", lambda: fake)
    with hardware_seal.HardwareSealedMemory(db_path, user_id="owner", use_webauthn=True) as hm:
        hits = hm.recall("Windows Hello", scope="sec", limit=5)
        assert any("Windows Hello" in h.content for h in hits)
    assert fake.freed_assertions == 2

    res = hardware_seal.unseal_database(db_path, use_webauthn=True)
    assert res["status"] == "unsealed"
    assert fake.freed_assertions == 3


def test_windows_webauthn_user_cancel_fails_closed(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "vault.db"
    m = Memory(user_id="owner", store=Store(db_path))
    m.remember("Закрытый факт", kind="fact", scope="sec", agent_id="owner")
    m.close()

    fake = _FakeWebAuthnDll(alg="ES256", sign_count_step=1)
    tok = webauthn_win.WindowsWebAuthnToken.enroll(rp_id="padam.local", dll=fake)
    hardware_seal.seal_database(db_path, mode="fido2", fido2_token=tok, rp_id="padam.local")

    fake.fail_get_hr = -2147023673  # ERROR_CANCELLED
    monkeypatch.setattr(webauthn_win, "load_webauthn_dll", lambda: fake)
    with pytest.raises(webauthn_win.WebAuthnCallError, match="WebAuthNAuthenticatorGetAssertion failed"):
        hardware_seal.unseal_database(db_path, use_webauthn=True)
