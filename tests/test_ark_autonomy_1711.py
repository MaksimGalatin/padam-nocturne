# -*- coding: utf-8 -*-
"""Тесты 5 поправок приёмки (коммит 275e07b) и 12 пунктов плана полной автономии 17.11.2026."""
from __future__ import annotations

import base64
import inspect
import json
import secrets
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from padam import api, ark, integrity, live_mesh, phoenix, pqc_mlkem
from padam._httpserver import ThreadingHTTPServer
from padam.memory import Memory
from padam.store import Store


def _mem(tmp_path: Path, name: str = "auto.db") -> Memory:
    return Memory(user_id="autonomy", store=Store(tmp_path / name))


# --- Правка 1 и 2: Эталон ML-KEM-768, 64B seed, совместимость 20x20 в обе стороны, 2400B fallback ---

def test_mlkem768_native_vs_pure_cross_compat_and_fips203_seed64():
    if not pqc_mlkem.HAS_NATIVE_MLKEM:
        pytest.skip("cryptography.hazmat.primitives.asymmetric.mlkem unavailable")

    from cryptography.hazmat.primitives.asymmetric import mlkem

    # 1. Детерминированный KAT по FIPS 203 seed64 -> одинаковый публичный ключ 1184B
    kat_seed64 = bytes(range(64))
    ref_sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(kat_seed64)
    pure_sk = pqc_mlkem.PureMLKEM768PrivateKey.from_seed_bytes(kat_seed64)
    assert ref_sk.public_key().public_bytes_raw() == pure_sk.public_key().public_bytes_raw()
    assert len(pure_sk.private_bytes_raw()) == 64
    assert len(pure_sk.full_dk_bytes()) == 2400

    # 2. Перекрёстная проверка 20 из 20 в обе стороны
    for _ in range(20):
        seed = secrets.token_bytes(64)
        nat_sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
        nat_pk = nat_sk.public_key()
        py_sk = pqc_mlkem.PureMLKEM768PrivateKey.from_seed_bytes(seed)
        py_pk = py_sk.public_key()

        # Эталон шифрует -> PurePython расшифровывает
        ss1, ct1 = nat_pk.encapsulate()
        assert py_sk.decapsulate(ct1) == ss1

        # PurePython шифрует -> Эталон расшифровывает
        ss2, ct2 = py_pk.encapsulate()
        assert nat_sk.decapsulate(ct2) == ss2

    # 3. Обратная совместимость: чтение устаревшего 2400-байтного dk_full в pqc_open_bytes
    kp_native = pqc_mlkem.generate_xwing_keypair(prefer_native=True)
    assert kp_native["backend"] == "cryptography_native"
    assert len(kp_native["mlkem_private"]) == 64

    msg = b"Phoenix backwards compatibility test 2400 bytes"
    env = pqc_mlkem.pqc_seal_bytes(msg, bytes(kp_native["mlkem_public"]), bytes(kp_native["x25519_public"]))
    assert env["mlkem_backend"] == "cryptography_native"

    # Получаем 2400-байтный dk из того же seed64 и проверяем расшифровку
    legacy_dk = pqc_mlkem.PureMLKEM768PrivateKey.from_seed_bytes(bytes(kp_native["mlkem_private"])).full_dk_bytes()
    assert len(legacy_dk) == 2400
    assert pqc_mlkem.pqc_open_bytes(env, legacy_dk, bytes(kp_native["x25519_private"])) == msg

    # 4. Режим без эталона (имитация Android) тоже шифрует и расшифровывает с тем же 64B ключом
    env_py = pqc_mlkem.pqc_seal_bytes(msg, bytes(kp_native["mlkem_public"]), bytes(kp_native["x25519_public"]), prefer_native=False)
    assert env_py["mlkem_backend"] == "pure_python_fips203"
    assert pqc_mlkem.pqc_open_bytes(env_py, bytes(kp_native["mlkem_private"]), bytes(kp_native["x25519_private"])) == msg


# --- Правка 3: Закрытые ключи узла вне SQLite + миграция без потерь ---

def test_live_mesh_node_secrets_outside_sqlite_and_migration(tmp_path):
    mem = _mem(tmp_path, "migrate_node.db")
    try:
        # Имитируем старую базу, где ключи лежали в таблице ark_mesh_Identity открытым текстом
        kp = pqc_mlkem.generate_xwing_keypair(prefer_native=False)
        legacy_dk = pqc_mlkem.PureMLKEM768PrivateKey.from_seed_bytes(bytes(kp["mlkem_private"])).full_dk_bytes()
        ml_priv_b64 = base64.b64encode(legacy_dk).decode("ascii")
        ml_pub_b64 = base64.b64encode(bytes(kp["mlkem_public"])).decode("ascii")
        x_priv_b64 = base64.b64encode(bytes(kp["x25519_private"])).decode("ascii")
        x_pub_b64 = base64.b64encode(bytes(kp["x25519_public"])).decode("ascii")

        mem.store.conn.executescript(live_mesh._MESH_DDL)
        mem.store.conn.execute(
            "INSERT INTO ark_mesh_Identity (user_id, node_id, device_name, device_type, mlkem_priv, mlkem_pub, x25519_priv, x25519_pub, created_at) "
            "VALUES (?, 'node-legacy-1', 'LegacyPC', 'pc', ?, ?, ?, ?, '2026-11-17T00:00:00Z')",
            (mem.user_id, ml_priv_b64, ml_pub_b64, x_priv_b64, x_pub_b64),
        )
        mem.store.conn.commit()

        # Первый вызов get_or_create_node_identity обязан мигрировать ключи во внешний шифрованный файл и затереть SQLite
        ident = live_mesh.get_or_create_node_identity(mem)
        assert ident["node_id"] == "node-legacy-1"

        row = mem.store.conn.execute("SELECT mlkem_priv, x25519_priv FROM ark_mesh_Identity WHERE user_id = ?", (mem.user_id,)).fetchone()
        assert row["mlkem_priv"] == "external"
        assert row["x25519_priv"] == "external"

        key_file = tmp_path / "migrate_node.db.node.key.json"
        assert key_file.is_file()
        raw_json = json.loads(key_file.read_text(encoding="utf-8"))
        assert raw_json["enc"] == "aes256gcm-v1"
        assert ml_priv_b64 not in key_file.read_text(encoding="utf-8")

        # Мигрированные ключи расшифровывают старый X-Wing конверт на старые публичные ключи
        env = pqc_mlkem.pqc_seal_bytes(b"migrated secret ok", base64.b64decode(ml_pub_b64), base64.b64decode(x_pub_b64))
        sec = live_mesh._load_node_secrets(mem)
        assert pqc_mlkem.pqc_open_bytes(env, base64.b64decode(sec["mlkem_priv_b64"]), base64.b64decode(sec["x25519_priv_b64"])) == b"migrated secret ok"
    finally:
        mem.close()


# --- Правка 4 и 5: Сопряжение устройств с SAS, без trust_hmac=False и запрет открытых дельт в API ---

def test_live_mesh_pairing_sas_mandatory_hmac_and_api_encryption(tmp_path):
    assert "trust_hmac" not in inspect.signature(live_mesh.apply_mesh_delta).parameters

    pc = Memory(user_id="family", store=Store(tmp_path / "pc.db"))
    phone = Memory(user_id="family", store=Store(tmp_path / "phone.db"))
    try:
        # Устройства гарантированно имеют РАЗНЫЕ owner_key
        k_pc, _ = integrity.owner_key(pc.store)
        k_ph, _ = integrity.owner_key(phone.store)
        assert k_pc != k_ph

        pc_node = live_mesh.get_or_create_node_identity(pc, device_name="PC", device_type="pc")
        ph_node = live_mesh.get_or_create_node_identity(phone, device_name="Phone", device_type="phone")

        # 1. Незарегистрированный / несопряжённый пир отклоняется везде
        live_mesh.register_peer(pc, ph_node["node_id"], "Phone", mlkem_public_b64=ph_node["mlkem_public_b64"], x25519_public_b64=ph_node["x25519_public_b64"])
        with pytest.raises(PermissionError, match="not trusted|not paired"):
            live_mesh.export_mesh_delta(pc, peer_id=ph_node["node_id"])

        # 2. Запускаем сопряжение (обмен общим sync_key по X-Wing + 6-значный SAS)
        pair_init = live_mesh.initiate_pairing(pc, ph_node)
        pair_acc = live_mesh.accept_pairing_invite(phone, pair_init["pairing_invite"])
        assert len(pair_init["sas_code"]) == 6 and pair_init["sas_code"] == pair_acc["sas_code"]

        # Неверный SAS-код отклоняется
        with pytest.raises(PermissionError, match="SAS"):
            live_mesh.confirm_peer_sas(pc, ph_node["node_id"], "000000" if pair_init["sas_code"] != "000000" else "999999")

        # Подтверждаем верный SAS на обоих экранах
        live_mesh.confirm_peer_sas(pc, ph_node["node_id"], pair_init["sas_code"])
        live_mesh.confirm_peer_sas(phone, pc_node["node_id"], pair_acc["sas_code"])

        # Поддельная HMAC-подпись отклоняется всегда
        pc.remember("Important shared memory", kind="fact", origin="user")
        pkt = live_mesh.export_mesh_delta(pc, peer_id=ph_node["node_id"])
        bad_pkt = dict(pkt, hmac_sig="f" * 64)
        with pytest.raises(PermissionError, match="HMAC"):
            live_mesh.apply_mesh_delta(phone, bad_pkt)

        # Открытая (незашифрованная) дельта отклоняется по умолчанию в apply_mesh_delta и в HTTP API
        with pytest.raises(PermissionError, match="PQC envelope required"):
            live_mesh.apply_mesh_delta(phone, {"encrypted": False, "source_node": pc_node["node_id"], "hmac_sig": "0" * 64, "delta": {}})

        prev = dict(api._state)
        api._state["memory"] = phone
        api._state["token"] = "tok-mesh"
        api._state["local"] = True
        srv = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            # Plaintext -> 403
            req_plain = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/v2/ark/mesh/apply",
                data=json.dumps({"encrypted": False, "delta": {"memories": []}}).encode("utf-8"),
                headers={"Authorization": "Bearer tok-mesh", "Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req_plain, timeout=5)
            assert exc.value.code == 403

            # Зашифрованный PQC-пакет с валидным HMAC от сопряжённого ПК -> 200 OK
            req_ok = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/v2/ark/mesh/apply",
                data=json.dumps({"packet": pkt}).encode("utf-8"),
                headers={"Authorization": "Bearer tok-mesh", "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req_ok, timeout=5) as r_ok:
                assert r_ok.status == 200
                body = json.loads(r_ok.read().decode("utf-8"))
                assert body["applied_memories"] == 1
        finally:
            srv.shutdown()
            srv.server_close()
            api._state.clear()
            api._state.update(prev)
    finally:
        pc.close()
        phone.close()
