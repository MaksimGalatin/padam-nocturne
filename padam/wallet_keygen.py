# -*- coding: utf-8 -*-
"""Офлайн-генератор криптокошельков ($0, без сети и посредников) для владельца.

Поддерживает 5 сетей с криптографически стойким CSPRNG:
- SOLANA: Ed25519 (адрес Base58 + 64-байтовый массив keypair.json совместимый с Phantom/Solflare)
- USDT_TRC20 (TRON): secp256k1 + Keccak-256 + префикс 0x41 + Base58Check (адрес T...)
- EVM (Ethereum/Base/Arbitrum/Polygon/BSC): secp256k1 + Keccak-256 + EIP-55 (адрес 0x...)
- ARWEAVE: RSA-4096 JWK + Base64URL(SHA-256(n)) (43 символа, готов для вечной памяти L3)
- BITCOIN: secp256k1 + HASH160 + Bech32 P2WPKH (адрес bc1q...)

Приватные ключи генерируются строго локально и никогда не передаются ИИ-агентам через MCP.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Константы раундов оригинального Keccak-256 (FIPS-202 ДО стандартизации SHA3 — паддинг 0x01)
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f1600(state: list[list[int]]) -> None:
    for rc in _KECCAK_RC:
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(state[x][y], _KECCAK_RHO[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        state[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Вычисляет Ethereum/TRON Keccak-256 (rate=1088 бит = 136 байт, паддинг 0x01..0x80)."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for idx in range(rate // 8):
            lane = int.from_bytes(block[idx * 8 : (idx + 1) * 8], "little")
            state[idx % 5][idx // 5] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    for idx in range(4):
        out.extend(state[idx % 5][idx // 5].to_bytes(8, "little"))
    return bytes(out)


def b58encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    chars: list[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(_B58_ALPHABET[rem])
    pad = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * pad) + "".join(reversed(chars))


def _b58check(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)


def eip55_checksum(addr20: bytes) -> str:
    hex_str = addr20.hex()
    h = keccak256(hex_str.encode("ascii")).hex()
    out = ["0x"]
    for i, ch in enumerate(hex_str):
        if ch in "abcdef" and int(h[i], 16) >= 8:
            out.append(ch.upper())
        else:
            out.append(ch)
    return "".join(out)


def _bech32_polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: bytes, frombits: int, tobits: int) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def _segwit_bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + _convertbits(witprog, 8, 5)
    chk_vals = _bech32_hrp_expand(hrp) + data + [0] * 6
    mod = _bech32_polymod(chk_vals) ^ 1
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in (data + checksum))


def _b64u_int(val: int) -> str:
    raw = val.to_bytes((val.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def generate_offline_wallet_material(network: str) -> dict[str, Any]:
    """Создаёт локальную ключевую пару и публичный адрес для выбранной сети."""
    net = str(network or "").strip().upper()
    if net in ("SOL", "SOLANA"):
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_raw = priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        addr = b58encode(pub_raw)
        keypair_list = list(priv_raw + pub_raw)
        return {
            "network": "SOLANA",
            "address": addr,
            "explorer_url": f"https://solscan.io/account/{addr}",
            "secret_format": "solana_keypair_json",
            "one_time_secret": json.dumps(keypair_list),
            "import_hint": "Phantom / Solflare / Solana CLI keypair JSON (64 bytes [priv+pub])",
        }

    if net in ("TRON", "TRC20", "USDT_TRC20", "USDT", "EVM", "ETH", "ETH_BASE_EVM", "BASE", "POLYGON"):
        priv = ec.generate_private_key(ec.SECP256K1())
        nums = priv.private_numbers()
        pub_nums = nums.public_numbers
        priv_hex = f"{nums.private_value:064x}"
        uncompressed = pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
        addr20 = keccak256(uncompressed)[-20:]
        if net in ("EVM", "ETH", "ETH_BASE_EVM", "BASE", "POLYGON"):
            addr = eip55_checksum(addr20)
            return {
                "network": "EVM",
                "address": addr,
                "explorer_url": f"https://etherscan.io/address/{addr}",
                "secret_format": "secp256k1_private_hex",
                "one_time_secret": "0x" + priv_hex,
                "import_hint": "MetaMask / Rabby / Trust Wallet (Import Private Key)",
            }
        addr = _b58check(b"\x41" + addr20)
        return {
            "network": "USDT_TRC20",
            "address": addr,
            "explorer_url": f"https://tronscan.org/#/address/{addr}",
            "secret_format": "tron_private_hex",
            "one_time_secret": priv_hex,
            "import_hint": "TronLink / Trust Wallet / Exodus (Import TRON Private Key; keeps TRX/USDT TRC20)",
        }

    if net in ("AR", "ARWEAVE"):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        pn = priv.private_numbers()
        pub_n = pn.public_numbers
        mod_bytes = pub_n.n.to_bytes((pub_n.n.bit_length() + 7) // 8, "big")
        addr = base64.urlsafe_b64encode(hashlib.sha256(mod_bytes).digest()).decode("ascii").rstrip("=")
        jwk = {
            "kty": "RSA",
            "n": _b64u_int(pub_n.n),
            "e": _b64u_int(pub_n.e),
            "d": _b64u_int(pn.d),
            "p": _b64u_int(pn.p),
            "q": _b64u_int(pn.q),
            "dp": _b64u_int(pn.dmp1),
            "dq": _b64u_int(pn.dmq1),
            "qi": _b64u_int(pn.iqmp),
        }
        return {
            "network": "ARWEAVE",
            "address": addr,
            "explorer_url": f"https://viewblock.io/arweave/address/{addr}",
            "secret_format": "arweave_jwk_json",
            "one_time_secret": json.dumps(jwk),
            "import_hint": "ArConnect / Wander / Arweave JWK keyfile (4096-bit RSA)",
        }

    if net in ("BTC", "BITCOIN"):
        priv = ec.generate_private_key(ec.SECP256K1())
        nums = priv.private_numbers()
        priv_bytes = nums.private_value.to_bytes(32, "big")
        pub_comp = priv.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )
        h160 = hashlib.new("ripemd160", hashlib.sha256(pub_comp).digest()).digest()
        addr = _segwit_bech32_encode("bc", 0, h160)
        wif = _b58check(b"\x80" + priv_bytes + b"\x01")
        return {
            "network": "BITCOIN",
            "address": addr,
            "explorer_url": f"https://mempool.space/address/{addr}",
            "secret_format": "bitcoin_wif_compressed",
            "one_time_secret": wif,
            "import_hint": "Sparrow / Electrum / BlueWallet (Import WIF Private Key -> wpkh / bc1q)",
        }

    raise ValueError(f"Unsupported network {network!r}; use SOLANA, USDT_TRC20, EVM, ARWEAVE or BITCOIN")
