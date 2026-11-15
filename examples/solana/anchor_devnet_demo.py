#!/usr/bin/env python3
"""Бесплатная ($0) локальная проверка подписи якоря памяти L3 и devnet-демо для Solana Confidential Compute (В5).

Запуск:
    python examples/solana/anchor_devnet_demo.py           # полностью офлайн ($0, без сети)
    python examples/solana/anchor_devnet_demo.py --rpc-slot  # + read-only запрос текущего слота devnet ($0)

Никогда не отправляет транзакции, не использует mainnet и не тратит средства.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Позволяет запускать скрипт напрямую из корня репозитория без установки пакета
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from padam import anchor
from padam.memory import Memory
from padam.store import Store


def main() -> int:
    parser = argparse.ArgumentParser(description="PADAM L3 + Solana devnet attestation demo ($0)")
    parser.add_argument(
        "--rpc-slot",
        action="store_true",
        help="Сделать read-only запрос getSlot на публичный Solana devnet RPC (бесплатно, без ключей)",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as td:
        m = Memory(user_id="devnet-demo", store=Store(Path(td) / "demo.db"))
        try:
            anchor.ensure_schema(m)
            m.remember("Solana devnet anchor verification demo fact", kind="fact", importance=0.8)
            m.remember("Architect prefers private local-first memory", kind="preference", importance=0.9)
            anchor.ensure_keys(m)
            bundle = anchor.build_bundle(m)
            assert bundle is not None

            root_hex = bundle.root.hex()
            memo = f"{anchor.MEMO_PREFIX} root={root_hex}"

            # Демонстрационная пара Ed25519 (имитация ключа анклава / владельца на devnet)
            sk = Ed25519PrivateKey.generate()
            measurement = "devnet-enclave-demo-sha256:0000000000000000"

            devnet_slot = 0
            if args.rpc_slot:
                devnet_slot = int(anchor.read_devnet_slot())
                print(f"[devnet RPC] current slot = {devnet_slot}", file=sys.stderr)

            att = anchor.sign_anchor_attestation(
                memo=memo,
                root_hex=root_hex,
                signing_key=sk,
                network="devnet",
                measurement=measurement,
                slot=devnet_slot,
            )
            verdict = anchor.verify_anchor_attestation(
                bundle.payload,
                memo,
                att,
                expected_measurement=measurement,
                reject_mainnet=True,
            )
            print(json.dumps({"attestation": att, "verification": verdict}, indent=2, ensure_ascii=False))
            return 0 if verdict["ok"] else 1
        finally:
            m.close()


if __name__ == "__main__":
    raise SystemExit(main())
