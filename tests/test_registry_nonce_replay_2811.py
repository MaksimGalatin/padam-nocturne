# -*- coding: utf-8 -*-
"""28.11.2026 — учёт одноразовых чисел подписи агента.

Подпись `<did>|<инструмент>|<число>` раньше принималась сколько угодно раз, и перехваченную подпись можно
было повторить. Теперь каждое число принимается один раз; сухая проверка (consume=False) число не тратит;
числа разных агентов и разных владельцев не мешают друг другу.
"""
from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from padam.memory import Memory
from padam.store import Store
from padam.shield import register_agent_identity, verify_agent_identity_action


def _mem(tmp_path: Path, user: str = "owner", name: str = "reg.db") -> Memory:
    return Memory(user_id=user, store=Store(str(tmp_path / name)))


def _sign(priv_pem: str, msg: str) -> str:
    key = serialization.load_pem_private_key(priv_pem.encode("ascii"), password=None)
    return base64.b64encode(key.sign(msg.encode("utf-8"))).decode("ascii")


def _call(m: Memory, did: str, tool: str, sig: str, msg: str, **kw):
    return verify_agent_identity_action(m, agent_did=did, tool_name=tool, signature_b64=sig, signed_message=msg, **kw)


def test_same_signature_twice_is_replay(tmp_path: Path) -> None:
    m = _mem(tmp_path)
    try:
        ag = register_agent_identity(m, agent_name="lead", owner_id="owner", allowed_tools=["read_file"])
        did, pk = ag["agent_did"], ag["private_key_pem"]
        msg = f"{did}|read_file|n-1"
        sig = _sign(pk, msg)
        first = _call(m, did, "read_file", sig, msg)
        assert first["allowed"] is True
        again = _call(m, did, "read_file", sig, msg)
        assert again["blocked"] is True and again["rule_id"] == "REGISTRY-NONCE-REPLAY"
        # новое число — снова можно
        msg2 = f"{did}|read_file|n-2"
        assert _call(m, did, "read_file", _sign(pk, msg2), msg2)["allowed"] is True
    finally:
        m.store.conn.close()


def test_dry_run_does_not_spend_nonce(tmp_path: Path) -> None:
    m = _mem(tmp_path)
    try:
        ag = register_agent_identity(m, agent_name="lead", owner_id="owner", allowed_tools=["read_file"])
        did, pk = ag["agent_did"], ag["private_key_pem"]
        msg = f"{did}|read_file|dry"
        sig = _sign(pk, msg)
        assert _call(m, did, "read_file", sig, msg, consume=False)["allowed"] is True
        assert _call(m, did, "read_file", sig, msg, consume=False)["allowed"] is True
        assert _call(m, did, "read_file", sig, msg)["allowed"] is True
        assert _call(m, did, "read_file", sig, msg)["rule_id"] == "REGISTRY-NONCE-REPLAY"
    finally:
        m.store.conn.close()


def test_refused_call_does_not_spend_nonce(tmp_path: Path) -> None:
    m = _mem(tmp_path)
    try:
        ag = register_agent_identity(
            m, agent_name="payer", owner_id="owner", allowed_tools=["pay"], spend_limit_cents=100.0
        )
        did, pk = ag["agent_did"], ag["private_key_pem"]
        msg = f"{did}|pay|p-1"
        sig = _sign(pk, msg)
        over = _call(m, did, "pay", sig, msg, spend_cents=500.0)
        assert over["rule_id"] == "REGISTRY-SPEND-LIMIT-EXCEEDED"
        # отказ по лимиту число не тратит: та же подпись с допустимой суммой проходит один раз
        assert _call(m, did, "pay", sig, msg, spend_cents=50.0)["allowed"] is True
        assert _call(m, did, "pay", sig, msg, spend_cents=10.0)["rule_id"] == "REGISTRY-NONCE-REPLAY"
    finally:
        m.store.conn.close()


def test_nonces_are_per_agent(tmp_path: Path) -> None:
    m = _mem(tmp_path)
    try:
        a = register_agent_identity(m, agent_name="a", owner_id="owner", allowed_tools=["read_file"])
        b = register_agent_identity(m, agent_name="b", owner_id="owner", allowed_tools=["read_file"])
        for ag in (a, b):
            msg = f"{ag['agent_did']}|read_file|same"
            assert _call(m, ag["agent_did"], "read_file", _sign(ag["private_key_pem"], msg), msg)["allowed"] is True
    finally:
        m.store.conn.close()


def test_oversized_nonce_rejected(tmp_path: Path) -> None:
    m = _mem(tmp_path)
    try:
        ag = register_agent_identity(m, agent_name="lead", owner_id="owner", allowed_tools=["read_file"])
        did, pk = ag["agent_did"], ag["private_key_pem"]
        msg = f"{did}|read_file|" + "x" * 300
        assert _call(m, did, "read_file", _sign(pk, msg), msg)["rule_id"] == "REGISTRY-SIGNATURE-INVALID"
    finally:
        m.store.conn.close()
