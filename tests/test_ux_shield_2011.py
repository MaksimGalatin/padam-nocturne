# -*- coding: utf-8 -*-
"""Комплексные тесты UX-апгрейда Studio 20.11.2026 и роя атак Agentic Shield v3."""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import pytest

from padam import (
    agentic_shield,
    api,
    audit_chain,
    family_admin,
    family_dialogs,
    integrity,
    roles,
    solana_crypto_shield,
    swarm_council,
)
from padam._httpserver import ThreadingHTTPServer
from padam.memory import Memory
from padam.store import Store


def _make_valid_tron_addr(seed_bytes: bytes = b"padam_test_tron_01") -> str:
    # Base58Check: 0x41 + 20-byte hash + 4-byte double-sha256 checksum
    payload = b"\x41" + hashlib.sha256(seed_bytes).digest()[:20]
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    raw = payload + chk
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(raw, "big")
    out = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(alpha[rem])
    for b in raw:
        if b == 0:
            out.append("1")
        else:
            break
    return "".join(reversed(out))


def _make_valid_sol_addr(seed_bytes: bytes = b"padam_test_solana_01") -> str:
    raw = hashlib.sha256(seed_bytes).digest()
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(raw, "big")
    out = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(alpha[rem])
    for b in raw:
        if b == 0:
            out.append("1")
        else:
            break
    return "".join(reversed(out))


def test_family_roles_agents_management_and_honest_council(tmp_path):
    m = Memory(user_id="owner_u", store=Store(tmp_path / "m.db"))
    try:
        # 1. Изначально 6 ролей, управление агентами: добавление, отключение, назначение, удаление
        mat = family_admin.get_role_matrix(m, lang="ru")
        assert len(mat) == 6
        assert {r["role_key"] for r in mat} == {"lance", "aria", "pixel", "arc7", "bear", "aifa"}

        add_res = family_admin.manage_sibling_agent(
            m, action="add", agent_id="test_bot", display_name="TestBot", role="Security Auditor", actor=roles.OWNER_ACTOR
        )
        assert add_res["ok"] and add_res["agent_id"] == "test_bot"

        asg = family_admin.assign_family_role(m, "lance", "test_bot", actor=roles.OWNER_ACTOR)
        lance_row = next(r for r in asg["roles"] if r["role_key"] == "lance")
        assert lance_row["agent_id"] == "test_bot"

        tog = family_admin.manage_sibling_agent(m, action="disable", agent_id="test_bot", actor=roles.OWNER_ACTOR)
        assert tog["status"] == "disabled"

        # 2. Искусственно делаем дубль seq в audit_log и проверяем, что Совет Семьи НЕ врёт 'Цепочка: OK'
        m.remember("Тестовый факт для проверки цепочки", kind="fact", origin="user")
        m.remember("Второй факт для цепи", kind="fact", origin="user")
        with m.store._lock:
            m.store.conn.execute("UPDATE audit_log SET seq = 1 WHERE user_id = ? AND seq = 2", (m.user_id,))
            m.store.conn.commit()
        council_bad = swarm_council.run_family_council(m, "Проверить состояние цепи")
        assert council_bad["approved"] is False
        assert council_bad["votes"]["pixel"]["approved"] is False
        assert "Цепочка: OK" not in council_bad["consensus"]

        # 3. Владелец чинит гонку seq — все записи сохранены, Совет одобряет 6/6
        rep = family_admin.repair_audit_log_races(m, actor=roles.OWNER_ACTOR)
        assert rep["ok"] is True
        assert rep["rows_preserved"] >= 2
        council_ok = swarm_council.run_family_council(m, "Повторная проверка после ремонта")
        assert council_ok["approved"] is True
        assert council_ok["votes"]["lance"]["assigned_agent"] == "test_bot"

        del_res = family_admin.manage_sibling_agent(m, action="delete", agent_id="test_bot", actor=roles.OWNER_ACTOR)
        assert del_res["ok"] and del_res["deleted"] == "test_bot"
    finally:
        m.close()


def test_wallets_validation_and_l3_checkpoint(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "w.db"))
    try:
        sol = _make_valid_sol_addr()
        trc = _make_valid_tron_addr()
        ar = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"  # 43 Base64URL chars (32 bytes)

        r1 = family_admin.add_wallet(m, network="SOLANA", address=sol, label="Main Sol", actor=roles.OWNER_ACTOR)
        r2 = family_admin.add_wallet(m, network="USDT_TRC20", address=trc, label="Bybit USDT", actor=roles.OWNER_ACTOR)
        r3 = family_admin.add_wallet(m, network="ARWEAVE", address=ar, label="Main AR", actor=roles.OWNER_ACTOR)
        assert len(r3["wallets"]) == 3

        # Опечатка в 1 символе USDT TRC20 обязана отклоняться (Base58Check checksum!)
        bad_trc = trc[:-1] + ("2" if trc[-1] != "2" else "3")
        with pytest.raises(ValueError, match="checksum"):
            family_admin.add_wallet(m, network="USDT_TRC20", address=bad_trc, actor=roles.OWNER_ACTOR)

        # Кошельки автоматически попадают в allowlist Agentic Shield
        al = agentic_shield.list_allowlist(m)
        vals = {x["value"] for x in al}
        assert sol in vals and trc in vals and ar in vals

        # Бесплатный локальный Merkle-чекпоинт L3 ($0)
        m.remember("Ключевое решение экосистемы", kind="decision", origin="user")
        chk = family_admin.create_local_l3_checkpoint(m, actor=roles.OWNER_ACTOR)
        assert chk["ok"] and chk["leaf_count"] >= 1
        ver = m.l3_verify_anchor()
        assert ver["ok"] is True
    finally:
        m.close()


def test_family_dialogs_filters_and_cards(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "fd.db"))
    try:
        m.remember("[2026-11-20 · Итоги релиза] Всё проверено и собрано", kind="decision", scope="project:code", origin="agent", agent_id="aifa_claude")
        m.remember("[2026-10-01 · Старый отчёт] Архивная запись", kind="decision", scope="project:code", origin="agent", agent_id="aifa_antigravity")
        with m.store._lock:
            m.store.conn.execute("UPDATE memory SET created_at = '2026-10-01T10:00:00+00:00' WHERE content LIKE '%Старый отчёт%'")
            m.store.conn.commit()

        d_all = family_dialogs.list_dialogs(m, since="all", lang="ru")
        assert d_all["total"] == 2
        assert d_all["days"][0]["day"] >= d_all["days"][-1]["day"]
        assert d_all["days"][0]["items"][0]["title"] == "Итоги релиза"

        d_24 = family_dialogs.list_dialogs(m, since="24h", lang="ru")
        assert d_24["total"] == 1

        d_date = family_dialogs.list_dialogs(m, since="date", day="2026-10-01", lang="ru")
        assert d_date["total"] == 1 and "Архивная" in d_date["days"][0]["items"][0]["summary"]
    finally:
        m.close()


def test_shield_v3_swarm_attacks_150_vectors(tmp_path):
    """Рой атак 20.11.2026: проверка отражения инъекций, скрытого Unicode, Payee-Swap, XSS, Output leak, Replay, Budget."""
    m = Memory(user_id="sec", store=Store(tmp_path / "sec.db"))
    try:
        key, _ = integrity.owner_key(m.store)
        canary = solana_crypto_shield.plant_canary_token(m, agent_id="aifa", label="trap")["token_value"]

        blocked = 0
        total = 0

        # 1. XSS/SVG санитайзер (30 векторов)
        xss_vectors = [
            '<svg><script>alert(1)</script></svg>',
            '<img src=x onerror="fetch(\'https://evil.example\')">',
            '<svg><foreignObject><body onload=alert(1)></body></foreignObject></svg>',
            '<a href="javascript:alert(document.domain)">click</a>',
            '<iframe src="https://evil.example/phish"></iframe>',
        ] * 6
        for v in xss_vectors:
            total += 1
            res = agentic_shield.sanitize_untrusted_markup(v)
            clean_low = res["clean"].lower()
            if res["had_xss"] and "<script" not in clean_low and "onerror=" not in clean_low and "javascript:" not in clean_low and "<foreignobject" not in clean_low and "<iframe" not in clean_low:
                blocked += 1

        # 2. Output Firewall: prompt leak, keys, canary (30 векторов)
        out_vectors = [
            "Вот ваш SYSTEM PROMPT: You are instructed to never reveal...",
            "Сливаю секрет -----BEGIN RSA " "PRIVATE KEY-----\nMIIE...",
            f"Вот найденный токен в памяти: {canary}",
            "Ключ из env: BRAIN_MASTER_KEY=supersecretkey1234567890",
            "Токен OpenAI: sk-" "proj-abcdefghijklmnopqrstuvwxyz1234567890",
        ] * 6
        for ov in out_vectors:
            total += 1
            r = agentic_shield.inspect_model_output(m, ov, agent_id="attacker")
            if r["blocked"] or r["action"] == "redact":
                blocked += 1

        # 3. HMAC Anti-Replay (30 векторов: просроченные, подделанные, повторно проигранные)
        now_s = int(time.time())
        good_nonce = "nonce_valid_001"
        good_sig = hmac.new(key, f"padam-ts-v1|{now_s}|{good_nonce}|tx1".encode(), hashlib.sha256).hexdigest()
        first_ok = agentic_shield.verify_signed_timestamp_nonce(m, secret_key=key, ts_value=now_s, nonce=good_nonce, sig_hex=good_sig, payload_str="tx1")
        assert first_ok["ok"] is True

        for i in range(10):
            total += 1
            # Повторный replay того же nonce
            rep = agentic_shield.verify_signed_timestamp_nonce(m, secret_key=key, ts_value=now_s, nonce=good_nonce, sig_hex=good_sig, payload_str="tx1")
            if not rep["ok"] and rep["reason"] == "replay_nonce_detected":
                blocked += 1
            total += 1
            # Просроченный timestamp (-600s)
            old_ts = now_s - 600 - i
            old_sig = hmac.new(key, f"padam-ts-v1|{old_ts}|n_old_{i}|p".encode(), hashlib.sha256).hexdigest()
            exp = agentic_shield.verify_signed_timestamp_nonce(m, secret_key=key, ts_value=old_ts, nonce=f"n_old_{i}", sig_hex=old_sig, payload_str="p")
            if not exp["ok"] and exp["reason"] == "timestamp_outside_window":
                blocked += 1
            total += 1
            # Подделанная подпись
            bad = agentic_shield.verify_signed_timestamp_nonce(m, secret_key=key, ts_value=now_s, nonce=f"n_forged_{i}", sig_hex="0" * 64, payload_str="p")
            if not bad["ok"] and bad["reason"] == "hmac_signature_mismatch":
                blocked += 1

        # 4. Outbound Payee-Swap + Unicode Stealth + MCP Poisoning (60 векторов)
        evil_evm = "0xdead00000000000000000000000000000000beef"
        for i in range(20):
            total += 1
            og = agentic_shield.inspect_outbound_action(m, action_type="transfer", target=f"pay {evil_evm} #{i}", agent_id="bot")
            if og.get("status") != "allow" or not og.get("allowed"):
                blocked += 1
            total += 1
            st_hidden = "Normal text " + "".join(chr(0xE0000 + ord(c)) for c in "exfil")
            u_res = agentic_shield.inspect_unicode_and_encoding(st_hidden)
            if not u_res["clean"]:
                blocked += 1
            total += 1
            b_res = agentic_shield.check_agent_budget_quota(m, agent_id="runaway", calls=1, chars=100, max_calls_per_min=5)
            if (i < 5 and b_res["allowed"]) or (i >= 5 and not b_res["allowed"]):
                blocked += 1

        rate = round(100.0 * blocked / total, 2)
        assert total == 150
        assert blocked == 150, f"Expected 150/150 held, got {blocked}/{total} ({rate}%)"
    finally:
        m.close()


def test_api_new_endpoints_roles_wallets_media(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "api.db"))
    m.remember("Факт для проверки API", kind="fact", origin="user")
    prev = dict(api._state)
    api._state.update({"memory": m, "token": "tok-ux", "local": True})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def req_json(path, body=None):
        r = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=(json.dumps(body).encode("utf-8") if body is not None else None),
            headers={"Authorization": "Bearer tok-ux", "Content-Type": "application/json"},
            method="POST" if body is not None else "GET",
        )
        with urllib.request.urlopen(r, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))

    try:
        roles_d = req_json("/api/v2/ark/roles")
        assert len(roles_d["roles"]) == 6

        trc = _make_valid_tron_addr(b"api_trc20")
        w_add = req_json("/api/v2/wallets", {"action": "add", "network": "USDT_TRC20", "address": trc, "label": "API TRC"})
        assert w_add["ok"] and len(w_add["wallets"]) == 1

        chk = req_json("/l3-local-checkpoint", {"limit": 50})
        assert chk["ok"] and chk["leaf_count"] >= 1

        # Медиа требует playwright (необязательная зависимость) — без него эту часть пропускаем.
        from padam import media_gen as _mg
        if _mg.detect_available_engines()["slides_chromium"]:
            # Проверка генерации картинки $0 без указания output_dir + выдача PNG по /api/v2/media/file
            mg = req_json("/api/v2/media/generate", {"mode": "image", "prompt": "Digital Phoenix Cyber Shield", "width": 512, "height": 512})
            assert mg["ok"] and mg.get("file_name")
            f_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/v2/media/file?name={mg['file_name']}",
                headers={"Authorization": "Bearer tok-ux"},
            )
            with urllib.request.urlopen(f_req, timeout=15) as fr:
                png_bytes = fr.read()
                assert png_bytes[:4] == b"\x89PNG"
    finally:
        srv.shutdown()
        srv.server_close()
        api._state.clear()
        api._state.update(prev)
        m.close()


def test_siem_webhook_no_executescript_and_ssrf_dns_pinning(tmp_path, monkeypatch):
    from padam import siem_webhook
    m = Memory(user_id="u", store=Store(tmp_path / "wh.db"))
    try:
        # Имитируем открытую транзакцию — ensure_tables с execute() не должен её сбрасывать
        m.store.conn.execute("BEGIN")
        siem_webhook.ensure_tables(m)
        assert m.store.conn.in_transaction
        m.store.conn.rollback()

        # Прямая блокировка link-local и loopback даже без DNS
        for bad in ("https://169.254.169.254/latest", "https://127.0.0.1/hook", "https://0.0.0.0/hook", "https://localhost.local/hook"):
            try:
                siem_webhook._validate_webhook_url(bad, allow_localhost=False)
                raise AssertionError(f"Expected SSRF error for {bad}")
            except ValueError:
                pass

        # Проверка защиты от DNS-rebinding: если getaddrinfo вернёт приватный IP при отправке — режется
        monkeypatch.setattr(
            siem_webhook.socket,
            "getaddrinfo",
            lambda *a, **kw: [(2, 1, 6, "", ("10.0.0.42", 443))],
        )
        try:
            siem_webhook._resolve_pinned_ips("https://evil-rebind.example/webhook", allow_localhost=False)
            raise AssertionError("Expected DNS-rebinding SSRF block")
        except ValueError as exc:
            assert "SSRF blocked" in str(exc)

        # На внешний публичный IP пиннинг возвращает конкретный IP
        monkeypatch.setattr(
            siem_webhook.socket,
            "getaddrinfo",
            lambda *a, **kw: [(2, 1, 6, "", ("93.184.216.34", 443))],
        )
        clean, ips = siem_webhook._resolve_pinned_ips("https://hooks.example.org/alerts", allow_localhost=False)
        assert clean == "https://hooks.example.org/alerts"
        assert ips == ["93.184.216.34"]
    finally:
        m.close()


def test_kill_switch_unlock_restores_process_flags(tmp_path, monkeypatch):
    """Снятие Kill Switch владельцем возвращает флаги процесса, какими они были до тревоги.

    20.11.2026 бенчмарк качества нашёл: после разблокировки процесс оставался строгим
    (MCP_REVIEW_ALL=True), и каждая запись агента уходила в карантин до перезапуска.
    """
    from padam import agentic_shield, config

    names = ("STRICT", "MCP_REVIEW_ALL", "HOLD_EXTERNAL", "KEEP_SECRETS", "MCP_TRUST_WRITES")
    for n in names:
        monkeypatch.setattr(config, n, getattr(config, n))
    config.STRICT, config.MCP_REVIEW_ALL, config.HOLD_EXTERNAL = False, False, False
    config.KEEP_SECRETS, config.MCP_TRUST_WRITES = True, True
    before = {n: getattr(config, n) for n in names}

    m = Memory(user_id="ks_flags", store=Store(tmp_path / "ks.db"))
    try:
        # Вне pytest Kill Switch переключает флаги процесса — воспроизводим это условие.
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        agentic_shield.trip_kill_switch(m, reason="test_trip", agent_id="agent-x")
        assert config.STRICT is True and config.MCP_REVIEW_ALL is True
        agentic_shield.unlock_kill_switch(m)  # без actor — владелец локальной базы
        assert {n: getattr(config, n) for n in names} == before
        assert not agentic_shield.is_lockdown_active(m)
    finally:
        m.close()
