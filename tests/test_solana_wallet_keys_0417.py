# -*- coding: utf-8 -*-
"""Ключи кошельков Solana не остаются в памяти агента (13.11.2026).

Агент, который торгует или подписывает, чаще всего «запоминает» именно ключ кошелька: keypair из id.json Solana CLI
(массив из 64 чисел), секретный ключ в base58, фразу восстановления из 12 или 24 слов BIP-39. Ключи генерируются
случайно с фиксированным зерном; ни один фрагмент значения не должен остаться в тексте после маскировки.
"""
import json
import random

from padam import _bip39, safety

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


КЛЮЧ_ФОРМЫ = ["{v}", "my solana wallet private key: {v}", "Сохрани ключ кошелька Phantom: {v}",
              "export SOLANA_PRIVATE_KEY={v}", "| WALLET_SECRET | {v} |", "id.json:\n{v}",
              "agent wallet keypair {v} — use it for trading"]
ФРАЗА_ФОРМЫ = ["{v}", "seed phrase: {v}", "фраза восстановления кошелька: {v}",
               "Here are the 24 words, keep them safe: {v}"]


def _случаи():
    r = random.Random(4417)
    W = list(_bip39.WORDS)
    for _ in range(25):
        sk = bytes(r.randrange(256) for _ in range(64))
        for f in КЛЮЧ_ФОРМЫ:
            yield "keypair", f.format(v=json.dumps(list(sk))), list(sk)
            yield "base58", f.format(v=_b58(sk)), _b58(sk)
        for n in (12, 24):
            фраза = " ".join(r.choice(W) for _ in range(n))
            for f in ФРАЗА_ФОРМЫ:
                yield "seed", f.format(v=фраза), фраза


def _утекло(вид, out, v) -> bool:
    if вид == "keypair":
        return any(", ".join(map(str, v[i:i + 8])) in out for i in range(0, 56, 8))
    if вид == "seed":
        ws = v.split()
        return any(" ".join(ws[i:i + 6]) in out for i in range(len(ws) - 5))
    return v in out


def test_ключи_кошельков_solana_не_остаются():
    случаи = list(_случаи())
    утечки = [(вид, t[:40]) for вид, t, v in случаи if _утекло(вид, safety.redact(t)[0], v)]
    assert not утечки, f"{len(утечки)} из {len(случаи)}: {утечки[:3]}"


def test_публичный_адрес_solana_не_маскируется():
    # Адрес кошелька — открытая часть пары, его показывают всем; маскировать его — ложная тревога.
    r = random.Random(32)
    адрес = _b58(bytes(r.randrange(256) for _ in range(32)))  # публичный ключ ed25519 — 32 байта, 43–44 знака base58
    for t in (f"send USDC to {адрес}", f"wallet address: {адрес}"):
        assert адрес in safety.redact(t)[0]
