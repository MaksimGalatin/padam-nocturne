# -*- coding: utf-8 -*-
"""Чистая реализация NIST FIPS 203 ML-KEM-768 (Kyber-768) на стандартном Python.

Зачем: на Android (Chaquopy) и ряде систем установлена `cryptography < 48`, где нет
встроенного `mlkem`. Этот модуль реализует математику кольца R_q = Z_3329[X]/(X^256 + 1),
преобразование NTT / Inverse NTT, сжатие/разжатие и KEM (KeyGen, Encaps, Decaps)
по стандарту FIPS 203 ML-KEM-768 только на стандартном `hashlib` и `secrets`.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

Q = 3329
N = 256
K = 3
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4

# Корни из единицы в бит-реверсивном порядке для NTT по FIPS 203 (zeta = 17 mod 3329)
def _bitrev7(x: int) -> int:
    res = 0
    for _ in range(7):
        res = (res << 1) | (x & 1)
        x >>= 1
    return res


_ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]
_GAMMAS = [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]
_INV_128 = pow(128, Q - 2, Q)  # 3303


def _ntt(f: list[int]) -> list[int]:
    a = list(f)
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = _ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * a[j + length]) % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
        length //= 2
    return a


def _inv_ntt(f: list[int]) -> list[int]:
    a = list(f)
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = _ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = (zeta * (a[j + length] - t)) % Q
        length *= 2
    return [(x * _INV_128) % Q for x in a]


def _multiply_ntts(f: list[int], g: list[int]) -> list[int]:
    h = [0] * 256
    for i in range(128):
        a0, a1 = f[2 * i], f[2 * i + 1]
        b0, b1 = g[2 * i], g[2 * i + 1]
        gamma = _GAMMAS[i]
        h[2 * i] = (a0 * b0 + a1 * b1 * gamma) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def _poly_add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def _poly_sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(a, b)]


def _sample_ntt(seed34: bytes) -> list[int]:
    stream = hashlib.shake_128(seed34).digest(840)
    a: list[int] = []
    idx = 0
    while len(a) < 256:
        b0, b1, b2 = stream[idx], stream[idx + 1], stream[idx + 2]
        idx += 3
        d1 = b0 + 256 * (b1 & 0x0F)
        d2 = (b1 >> 4) + 16 * b2
        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < 256:
            a.append(d2)
    return a


def _cbd(buf: bytes, eta: int) -> list[int]:
    bits = []
    for byte in buf:
        for b in range(8):
            bits.append((byte >> b) & 1)
    f = [0] * 256
    for i in range(256):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f[i] = (x - y) % Q
    return f


def _prf(eta: int, sigma: bytes, n_byte: int) -> bytes:
    return hashlib.shake_256(sigma + bytes([n_byte])).digest(64 * eta)


def _byte_encode(f: list[int], d: int) -> bytes:
    bits: list[int] = []
    for x in f:
        val = x % (Q if d == 12 else (1 << d))
        for b in range(d):
            bits.append((val >> b) & 1)
    out = bytearray(32 * d)
    for idx, bit in enumerate(bits):
        if bit:
            out[idx >> 3] |= 1 << (idx & 7)
    return bytes(out)


def _byte_decode(data: bytes, d: int) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for b in range(8):
            bits.append((byte >> b) & 1)
    mod = Q if d == 12 else (1 << d)
    out = [0] * 256
    for i in range(256):
        val = 0
        for b in range(d):
            val |= bits[i * d + b] << b
        out[i] = val % mod
    return out


def _compress(f: list[int], d: int) -> list[int]:
    m = 1 << d
    return [(((x % Q) * m + (Q // 2)) // Q) % m for x in f]


def _decompress(f: list[int], d: int) -> list[int]:
    m = 1 << d
    return [((x * Q + (m // 2)) // m) % Q for x in f]


def _kpke_keygen(d_seed: bytes) -> tuple[bytes, bytes]:
    g = hashlib.sha3_512(d_seed + bytes([K])).digest()
    rho, sigma = g[:32], g[32:]
    A = [[_sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]
    s = [_ntt(_cbd(_prf(ETA1, sigma, i), ETA1)) for i in range(K)]
    e = [_ntt(_cbd(_prf(ETA1, sigma, K + i), ETA1)) for i in range(K)]
    t = []
    for i in range(K):
        acc = [0] * 256
        for j in range(K):
            acc = _poly_add(acc, _multiply_ntts(A[i][j], s[j]))
        t.append(_poly_add(acc, e[i]))
    ek = b"".join(_byte_encode(ti, 12) for ti in t) + rho
    dk = b"".join(_byte_encode(si, 12) for si in s)
    return ek, dk


def _kpke_encrypt(ek: bytes, m32: bytes, r32: bytes) -> bytes:
    t = [_byte_decode(ek[384 * i : 384 * (i + 1)], 12) for i in range(K)]
    rho = ek[384 * K : 384 * K + 32]
    A = [[_sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]
    y = [_ntt(_cbd(_prf(ETA1, r32, i), ETA1)) for i in range(K)]
    e1 = [_cbd(_prf(ETA2, r32, K + i), ETA2) for i in range(K)]
    e2 = _cbd(_prf(ETA2, r32, 2 * K), ETA2)
    u = []
    for j in range(K):
        acc = [0] * 256
        for i in range(K):
            acc = _poly_add(acc, _multiply_ntts(A[i][j], y[i]))
        u.append(_poly_add(_inv_ntt(acc), e1[j]))
    mu = _decompress(_byte_decode(m32, 1), 1)
    v_ntt = [0] * 256
    for i in range(K):
        v_ntt = _poly_add(v_ntt, _multiply_ntts(t[i], y[i]))
    v = _poly_add(_poly_add(_inv_ntt(v_ntt), e2), mu)
    c1 = b"".join(_byte_encode(_compress(ui, DU), DU) for ui in u)
    c2 = _byte_encode(_compress(v, DV), DV)
    return c1 + c2


def _kpke_decrypt(dk: bytes, c: bytes) -> bytes:
    u_len = 32 * DU * K  # 960
    c1, c2 = c[:u_len], c[u_len:]
    u = [_decompress(_byte_decode(c1[32 * DU * i : 32 * DU * (i + 1)], DU), DU) for i in range(K)]
    v = _decompress(_byte_decode(c2, DV), DV)
    s = [_byte_decode(dk[384 * i : 384 * (i + 1)], 12) for i in range(K)]
    acc = [0] * 256
    for i in range(K):
        acc = _poly_add(acc, _multiply_ntts(s[i], _ntt(u[i])))
    w = _poly_sub(v, _inv_ntt(acc))
    return _byte_encode(_compress(w, 1), 1)


class PureMLKEM768PublicKey:
    """Публичный ключ ML-KEM-768 (1184 байта)."""

    def __init__(self, ek: bytes) -> None:
        if len(ek) != 1184:
            raise ValueError(f"ML-KEM-768 public key must be 1184 bytes, got {len(ek)}")
        self._ek = bytes(ek)

    @classmethod
    def from_public_bytes(cls, data: bytes) -> PureMLKEM768PublicKey:
        return cls(data)

    def public_bytes_raw(self) -> bytes:
        return self._ek

    def encapsulate(self) -> tuple[bytes, bytes]:
        """Возвращает (shared_key_32, ciphertext_1088) по совместимости с cryptography."""
        m = secrets.token_bytes(32)
        h_ek = hashlib.sha3_256(self._ek).digest()
        kr = hashlib.sha3_512(m + h_ek).digest()
        shared_k, r = kr[:32], kr[32:]
        ct = _kpke_encrypt(self._ek, m, r)
        return shared_k, ct


class PureMLKEM768PrivateKey:
    """Приватный ключ ML-KEM-768 (2400 байт по FIPS 203)."""

    def __init__(self, dk_full: bytes) -> None:
        if len(dk_full) != 2400:
            raise ValueError(f"ML-KEM-768 private key must be 2400 bytes, got {len(dk_full)}")
        self._dk = bytes(dk_full)

    @classmethod
    def generate(cls) -> PureMLKEM768PrivateKey:
        d = secrets.token_bytes(32)
        z = secrets.token_bytes(32)
        ek, dk_pke = _kpke_keygen(d)
        h_ek = hashlib.sha3_256(ek).digest()
        return cls(dk_pke + ek + h_ek + z)

    @classmethod
    def from_private_bytes(cls, data: bytes) -> PureMLKEM768PrivateKey:
        return cls(data)

    def private_bytes_raw(self) -> bytes:
        return self._dk

    def public_key(self) -> PureMLKEM768PublicKey:
        return PureMLKEM768PublicKey(self._dk[1152:2336])

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != 1088:
            raise ValueError(f"ML-KEM-768 ciphertext must be 1088 bytes, got {len(ciphertext)}")
        dk_pke = self._dk[:1152]
        ek = self._dk[1152:2336]
        h_ek = self._dk[2336:2368]
        z = self._dk[2368:2400]
        m_prime = _kpke_decrypt(dk_pke, ciphertext)
        kr_prime = hashlib.sha3_512(m_prime + h_ek).digest()
        k_prime, r_prime = kr_prime[:32], kr_prime[32:]
        k_bar = hashlib.shake_256(z + ciphertext).digest(32)
        c_prime = _kpke_encrypt(ek, m_prime, r_prime)
        if hmac.compare_digest(ciphertext, c_prime):
            return k_prime
        return k_bar


XWING_LABEL = b"\x5c\x2e\x2f\x2f\x5e\x5c"  # \.//^\ по draft-connolly-cfrg-xwing-kem


def generate_xwing_keypair() -> dict[str, bytes]:
    """Генерирует гибридную постквантовую пару ключей X-Wing (ML-KEM-768 + X25519) на любой платформе."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

    kem_sk = PureMLKEM768PrivateKey.generate()
    kem_pk = kem_sk.public_key()
    x_sk = x25519.X25519PrivateKey.generate()
    x_pk = x_sk.public_key()
    return {
        "mlkem_private": kem_sk.private_bytes_raw(),
        "mlkem_public": kem_pk.public_bytes_raw(),
        "x25519_private": x_sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        "x25519_public": x_pk.public_bytes(Encoding.Raw, PublicFormat.Raw),
    }


def pqc_seal_bytes(plaintext: bytes, mlkem_public: bytes, x25519_public: bytes) -> dict[str, str]:
    """Запечатывает байты гибридным постквантовым шифром X-Wing (ML-KEM-768 + X25519) + AES-256-GCM."""
    import base64
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    kem_pk = PureMLKEM768PublicKey.from_public_bytes(mlkem_public)
    ss_kem, ct_kem = kem_pk.encapsulate()

    peer_x_pk = x25519.X25519PublicKey.from_public_bytes(x25519_public)
    eph_x_sk = x25519.X25519PrivateKey.generate()
    eph_x_pk_bytes = eph_x_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ss_x = eph_x_sk.exchange(peer_x_pk)

    combined_key = hashlib.sha3_256(ss_kem + ss_x + eph_x_pk_bytes + x25519_public + XWING_LABEL).digest()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(combined_key).encrypt(nonce, plaintext, XWING_LABEL)
    return {
        "scheme": "xwing-mlkem768-x25519-aes256gcm-v1",
        "ct_kem_b64": base64.b64encode(ct_kem).decode("ascii"),
        "eph_x25519_b64": base64.b64encode(eph_x_pk_bytes).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }


def pqc_open_bytes(envelope: dict[str, str], mlkem_private: bytes, x25519_private: bytes) -> bytes:
    """Распечатывает конверт X-Wing (ML-KEM-768 + X25519) + AES-256-GCM."""
    import base64
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if envelope.get("scheme") != "xwing-mlkem768-x25519-aes256gcm-v1":
        raise ValueError(f"Unsupported PQC scheme: {envelope.get('scheme')}")
    ct_kem = base64.b64decode(envelope["ct_kem_b64"])
    eph_x_bytes = base64.b64decode(envelope["eph_x25519_b64"])
    nonce = base64.b64decode(envelope["nonce_b64"])
    ciphertext = base64.b64decode(envelope["ciphertext_b64"])

    kem_sk = PureMLKEM768PrivateKey.from_private_bytes(mlkem_private)
    ss_kem = kem_sk.decapsulate(ct_kem)

    x_sk = x25519.X25519PrivateKey.from_private_bytes(x25519_private)
    x_pk_bytes = x_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ss_x = x_sk.exchange(x25519.X25519PublicKey.from_public_bytes(eph_x_bytes))

    combined_key = hashlib.sha3_256(ss_kem + ss_x + eph_x_bytes + x_pk_bytes + XWING_LABEL).digest()
    return AESGCM(combined_key).decrypt(nonce, ciphertext, XWING_LABEL)
