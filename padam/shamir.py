# -*- coding: utf-8 -*-
"""Криптографическая схема разделения секрета Шамира (k-из-n) над GF(256).

Реализация на чистом Python без внешних зависимостей для «Хранителей Семьи»:
ни одна доля сама по себе не раскрывает ни бита секрета (и ни бита его отпечатка), а любые `k` из `n` долей
восстанавливают исходный ключ байт-в-байт (используется неприводимый полином AES 0x11B).
"""
from __future__ import annotations

import hashlib
import secrets

_SHARE_PREFIX = "padam-shamir-v1"


def _gf_add(a: int, b: int) -> int:
    return a ^ b


def _gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return res


def _gf_pow(a: int, power: int) -> int:
    res = 1
    base = a
    while power > 0:
        if power & 1:
            res = _gf_mul(res, base)
        base = _gf_mul(base, base)
        power >>= 1
    return res


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("Zero has no multiplicative inverse in GF(256)")
    return _gf_pow(a, 254)


def _eval_poly(coeffs: list[int], x: int) -> int:
    y = 0
    for c in reversed(coeffs):
        y = _gf_add(_gf_mul(y, x), c)
    return y


def split_secret(secret: bytes, k: int, n: int) -> list[str]:
    """Разбивает секрет на `n` долей с порогом восстановления `k`."""
    if not secret:
        raise ValueError("Secret must not be empty")
    if not (2 <= k <= n <= 255):
        raise ValueError("Require 2 <= k <= n <= 255")

    # 17.11.2026: в долю больше не пишется отпечаток самого секрета — 32 бита SHA-256 в каждой доле позволяли
    # по ОДНОЙ доле перебирать слабый секрет (пароль, фразу). Проверочные байты делятся вместе с секретом и так же
    # скрыты схемой; в долю пишется только случайный номер разбиения, чтобы отличать доли разных разбиений.
    digest = secrets.token_hex(4)
    payload = secret + hashlib.sha256(secret).digest()[:4]
    raw_shares = [bytearray() for _ in range(n)]
    for byte_val in payload:
        coeffs = [byte_val] + [secrets.randbelow(256) for _ in range(k - 1)]
        for idx in range(1, n + 1):
            raw_shares[idx - 1].append(_eval_poly(coeffs, idx))

    out: list[str] = []
    for idx in range(1, n + 1):
        out.append(f"{_SHARE_PREFIX}:{k}:{idx}:{digest}:{bytes(raw_shares[idx - 1]).hex()}")
    return out


def combine_shares(shares: list[str]) -> bytes:
    """Восстанавливает исходный секрет по `k` или более долям через интерполяцию Лагранжа."""
    if not shares:
        raise ValueError("No shares provided")

    parsed: list[tuple[int, int, str, bytes]] = []
    seen_x: set[int] = set()
    for s in shares:
        parts = str(s or "").strip().split(":")
        if len(parts) != 5 or parts[0] != _SHARE_PREFIX:
            raise ValueError("Invalid Shamir share format")
        k = int(parts[1])
        x = int(parts[2])
        digest = parts[3]
        data = bytes.fromhex(parts[4])
        if not (1 <= x <= 255):
            raise ValueError(f"Invalid share index: {x}")
        if x in seen_x:
            raise ValueError(f"Duplicate share index: {x}")
        seen_x.add(x)
        parsed.append((k, x, digest, data))

    k_req = parsed[0][0]
    exp_digest = parsed[0][2]
    secret_len = len(parsed[0][3])
    if len(parsed) < k_req:
        raise ValueError(f"Need at least {k_req} shares, got {len(parsed)}")
    for k_i, _, dig_i, data_i in parsed:
        if k_i != k_req or dig_i != exp_digest or len(data_i) != secret_len:
            raise ValueError("Incompatible shares from different splits")

    used = parsed[:k_req]
    xs = [p[1] for p in used]
    recovered = bytearray(secret_len)

    for byte_pos in range(secret_len):
        val = 0
        for i, (_, xi, _, data_i) in enumerate(used):
            yi = data_i[byte_pos]
            num = 1
            den = 1
            for j, xj in enumerate(xs):
                if i == j:
                    continue
                num = _gf_mul(num, xj)  # (0 ^ xj) = xj
                den = _gf_mul(den, _gf_add(xi, xj))
            lagrange = _gf_mul(num, _gf_inv(den))
            val = _gf_add(val, _gf_mul(yi, lagrange))
        recovered[byte_pos] = val

    if secret_len < 5:
        raise ValueError("Invalid Shamir share length")
    result, tag = bytes(recovered[:-4]), bytes(recovered[-4:])
    if hashlib.sha256(result).digest()[:4] != tag:
        raise ValueError("Recovered secret checksum mismatch (corrupted shares)")
    return result
