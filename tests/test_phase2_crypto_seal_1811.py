# -*- coding: utf-8 -*-
"""Red-тесты Фазы 2 аудита GLM (Пакет 2: HW-01..03, ANCH-01, OTS-01, PQC-01, ARK-01..03, AUD-01, SIG-01).

Все тесты спроектированы падать на уязвимом коде (37abc2d) и проходить после исправлений Пакета 2.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from padam import (
    anchor,
    audit_chain,
    hardware_seal,
    integrity,
    keyvault,
    l3_pqc_bundle,
    ots,
    pqc_mlkem,
    pqc_sync,
)
from padam.memory import Memory
from padam.store import Store


def _mem(tmp_path: Path, name: str = "m.db", user_id: str = "u_p2") -> Memory:
    return Memory(user_id=user_id, store=Store(tmp_path / name))


def test_hw03_software_fido2_token_blocked_without_insecure_flag(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("PADAM_INSECURE_TEST_TOKEN", raising=False)
    with pytest.raises(hardware_seal.HardwareAuthError):
        hardware_seal.SoftwareFido2Token()


def test_hw01_and_hw02_container_replacement_and_rollback_blocked(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PADAM_INSECURE_TEST_TOKEN", "1")
    db_path = tmp_path / "vault.db"
    m = Memory(user_id="hw", store=Store(db_path))
    m.remember("Главный факт T1", kind="fact", origin="user")
    m.close()

    tok = hardware_seal.SoftwareFido2Token(insecure_test_token=True)
    hardware_seal.seal_database(db_path, mode="fido2", fido2_token=tok, allow_insecure_test_token=True)

    # Сохраняем снимок контейнера T1 (для атаки rollback HW-02)
    t1_container = db_path.read_bytes()

    # T2: открываем и пере-запечатываем (должен инкрементироваться монотонный seal_seq)
    with hardware_seal.HardwareSealedMemory(db_path, user_id="hw", fido2_token=tok, allow_insecure_test_token=True) as hm:
        hm.remember("Факт состояния T2", kind="fact", origin="user")

    # HW-02: попытка отката файла на старый T1-контейнер должна отвергаться
    db_path.write_bytes(t1_container)
    with pytest.raises(hardware_seal.HardwareAuthError, match="rollback"):
        hardware_seal.unseal_database(db_path, fido2_token=tok, allow_insecure_test_token=True)

    # HW-01: замена целиком на новый легитимно запечатанный под другим ключом контейнер атакующего
    evil_db = tmp_path / "evil.db"
    em = Memory(user_id="hw", store=Store(evil_db))
    em.remember("Подменная БД атакующего", kind="fact", origin="user")
    em.close()
    evil_tok = hardware_seal.SoftwareFido2Token(insecure_test_token=True)
    hardware_seal.seal_database(evil_db, mode="fido2", fido2_token=evil_tok, allow_insecure_test_token=True)
    # Подкладываем контейнер атакующего на место оригинального (чужая подпись/без подписи владельца оригинальной БД)
    db_path.write_bytes(evil_db.read_bytes())
    with pytest.raises(hardware_seal.HardwareAuthError):
        hardware_seal.unseal_database(db_path, fido2_token=evil_tok, allow_insecure_test_token=True)


def test_anch01_verify_bundle_requires_pinned_owner_attestation_in_strict_mode(tmp_path: Path):
    mem = _mem(tmp_path, "anch.db")
    try:
        mem.remember("Запись якоря L3", kind="fact", origin="user")
        b = anchor.build_bundle(mem)
        assert b is not None
        memo = f"{anchor.MEMO_PREFIX} root={b.root.hex()} n={len(b.leaves)}"

        # Атакующий подписывает бандл своим произвольным Ed25519 ключом
        owner_sk = Ed25519PrivateKey.generate()
        attacker_sk = Ed25519PrivateKey.generate()
        owner_pub_hex = owner_sk.public_key().public_bytes_raw().hex() if hasattr(owner_sk.public_key(), "public_bytes_raw") else anchor.sign_anchor_attestation(memo, b.root.hex(), owner_sk)["pubkey_hex"]
        att_evil = anchor.sign_anchor_attestation(memo, b.root.hex(), attacker_sk)

        # Строгий верификатор (ANCH-01) обязан отклонить без pinned owner pubkey / при чужом ключе
        res_strict = anchor.verify_bundle(
            b.payload,
            memo,
            attestation=att_evil,
            expected_pubkey_hex=owner_pub_hex,
            require_owner_attestation=True,
        )
        assert res_strict["ok"] is False
        assert res_strict.get("signature_ok") is False

        # Без attestation даже совместимый вызов честно помечает owner_verified=False
        res_unattested = anchor.verify_bundle(b.payload, memo)
        assert res_unattested.get("owner_verified") is False
    finally:
        mem.close()


def test_ots01_fake_bitcoin_height_marked_untrusted_and_rejected_by_verify(tmp_path: Path):
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.timestamp import Timestamp

    payload = b"padam-l3-bundle-data-for-ots"
    digest = hashlib.sha256(payload).digest()

    def _fake_cal(url, msg, timeout):
        ts = Timestamp(msg)
        ts.attestations.add(BitcoinBlockHeaderAttestation(999999))
        return ts

    ots_bytes = ots.stamp(digest, calendars=("https://fake.ots",), submit=_fake_cal)
    meta = ots.info(ots_bytes)
    assert meta.get("unverified_metadata") is True
    assert meta.get("bitcoin_proof_verified") is False

    # Настоящая проверка ots.verify обязана отвергнуть поддельный блок (и без header-источника, и с чужим merkleroot)
    v_no_hdr = ots.verify(ots_bytes, payload)
    assert v_no_hdr["verified"] is False

    class _FakeHeader:
        hashMerkleRoot = b"\xaa" * 32
        nTime = 1700000000

    v_bad_hdr = ots.verify(ots_bytes, payload, block_header_fn=lambda h: _FakeHeader())
    assert v_bad_hdr["verified"] is False


def test_pqc01_require_keyvault_flag_enforced_when_enabled(monkeypatch, tmp_path: Path):
    mem = _mem(tmp_path, "pqc.db")
    try:
        # По умолчанию (без флага) поведение сохраняется
        # Но при PADAM_PQC_REQUIRE_KEYVAULT=1 без включённого keyvault создание/открытие запрещено
        monkeypatch.setenv("PADAM_PQC_REQUIRE_KEYVAULT", "1")
        with pytest.raises(pqc_sync.PqcSyncError, match="keyvault"):
            pqc_sync.ensure_local_identity(mem)

        # С включённым keyvault — работает и оборачивает ключи через w1: (scrypt+AESGCM), а не owner.key
        keyvault.enable(mem, "strong-passphrase-2026")
        ident = pqc_sync.ensure_local_identity(mem)
        row = mem.store.one("SELECT sk_enc FROM sync_identity WHERE user_id = ?", (mem.user_id,))
        assert str(row["sk_enc"]).startswith(keyvault.PREFIX)
        assert ident.device_id
    finally:
        mem.close()


def test_ark01_ark02_ark03_domain_sep_leaf_binding_and_id_binding(tmp_path: Path):
    mem = _mem(tmp_path, "ark.db")
    try:
        _, rid = mem.remember("L3 record integrity test", kind="fact", origin="user")
        kp = pqc_mlkem.generate_xwing_keypair()
        bundle = l3_pqc_bundle.seal_l3_pqc_bundle(mem, bytes(kp["mlkem_public"]), bytes(kp["x25519_public"]))
        assert bundle["schema"] == "padam-l3-pqc-envelope-v2"

        # ARK-03: подмена record.id в бандле anchor.py должна ломаться при verify_bundle
        b = anchor.build_bundle(mem)
        assert b is not None
        memo = f"{anchor.MEMO_PREFIX} root={b.root.hex()} n={len(b.leaves)}"
        tampered_obj = json.loads(b.payload.decode("utf-8"))
        tampered_obj["records"][0]["id"] = "tampered-wrong-record-id"
        tampered_payload = json.dumps(tampered_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        v_id = anchor.verify_bundle(tampered_payload, memo)
        assert v_id["ok"] is False

        # ARK-02: db_leaves fallback при расхождении l3_leaf.memory_id с реальной памятью должен возвращать ok=False
        l3_dir = Path(str(mem.store.path) + ".l3")
        anchor.run_l3(mem, uploader=lambda p, t: "ar1", anchorer=lambda m: ("sig1", 1), save_dir=str(l3_dir))
        # Удаляем локальную json-копию (включая fallback на db_leaves) и подменяем memory_id в l3_leaf на несуществующий
        for f in l3_dir.glob("*.json"):
            f.unlink()
        mem.store.conn.execute("UPDATE l3_leaf SET memory_id = 'ghost-deleted-id'")
        mem.store.conn.commit()
        ver_db = mem.l3_verify_anchor()
        assert ver_db["ok"] is False
    finally:
        mem.close()


def test_aud01_wiped_empty_audit_chain_detected(tmp_path: Path):
    mem = _mem(tmp_path, "aud.db")
    try:
        audit_chain.append_audit(mem, "important_op", {"x": 1})
        assert audit_chain.verify_audit_chain(mem)["ok"] is True

        # Атакующий стирает ОБЕ таблицы: и цепочку, и якорь
        mem.store.conn.execute("DELETE FROM ark_audit_chain")
        mem.store.conn.execute("DELETE FROM ark_audit_anchor")
        mem.store.conn.commit()

        ver = audit_chain.verify_audit_chain(mem)
        assert ver["ok"] is False
        assert ver.get("reason") == "chain_and_anchor_wiped"
    finally:
        mem.close()


def test_sig01_owner_sig_binds_scope_and_timestamp(tmp_path: Path):
    mem = _mem(tmp_path, "sig.db")
    try:
        _, pid = mem.remember("Предпочтение для scope=global", kind="preference", scope="global", origin="user")
        assert len(mem.profile(scope="global")["preferences"]) == 1

        # Атакующий в обход PADAM переносит подписанное предпочтение в чужой scope или меняет created_at
        mem.store.conn.execute("UPDATE memory SET scope = 'workspace-evil' WHERE id = ?", (pid,))
        mem.store.conn.commit()
        assert len(mem.profile(scope="workspace-evil")["preferences"]) == 0
    finally:
        mem.close()
