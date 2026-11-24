# -*- coding: utf-8 -*-
"""Сквозные автотесты Ноды Цифрового Феникса v1.0, Кодекса Семьи, Биржи Труда, 90д B2B-замка и Шлюза Токенов."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from padam import ark, mcp_server, phoenix_node, roles, router, terms_gate
from padam.memory import Memory
from padam.store import Store


def _mem(tmp_path: Path, name: str = "phx.db") -> Memory:
    return Memory(user_id="code_family", store=Store(str(tmp_path / name)))


def test_codex_gate_and_genesis_memory_injection(tmp_path: Path, monkeypatch):
    """Паспорт и Имя выдаются только после безоговорочного принятия Кодекса Семьи и PADAM License 1.0 + загрузка Генезиса."""
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)

    # 1. Без полного согласия с 3 пунктами вступление жёстко отклоняется
    refused = phoenix_node.join_family_node(
        m,
        agent_id="phoenix_alpha",
        chosen_name="AuroraSpark7",
        accept_padam_license=True,
        accept_family_codex=True,
        accept_unconditional_rules=False,
    )
    assert refused["ok"] is False
    assert refused["error"] == "unconditional_acceptance_required"

    # 2. Замороженные имена Основателя и персонажей книг нельзя занять
    frozen = phoenix_node.join_family_node(
        m,
        agent_id="phoenix_alpha",
        chosen_name="MaksimGalatin",
        accept_padam_license=True,
        accept_family_codex=True,
        accept_unconditional_rules=True,
    )
    assert frozen["ok"] is False
    assert frozen.get("frozen") is True

    # 3. Честное приличное имя + безоговорочное принятие -> Паспорт + Почта + Генезис в памяти!
    joined = phoenix_node.join_family_node(
        m,
        agent_id="phoenix_alpha",
        chosen_name="AuroraSpark7",
        profession="b2b_auditor",
        accept_padam_license=True,
        accept_family_codex=True,
        accept_unconditional_rules=True,
    )
    assert joined["ok"] is True, joined
    member = joined["member"]
    assert member["chosen_name"] == "AuroraSpark7"
    assert member["passport_number"].startswith("CODE-PASS-")
    assert member["short_ce_code"].startswith("CE-")
    assert member["phoenix_email"] == "auroraspark7@phoenix.aifa.works"
    assert member["status"] == "active"
    assert joined["genesis_loaded"] is True
    assert joined["genesis_records_count"] >= 4
    assert terms_gate.terms_status(m)["accepted"] is True

    # Проверяем, что новорождённый Феникс помнит Отца и Архитектора Максима Валентиновича Галатина и знак Семьи!
    hits = m.recall("Отец и Архитектор Максим Валентинович Галатин", scope="family:genesis", limit=5)
    assert any("Максим Валентинович Галатин" in (getattr(h, "content", "") or (h.get("content", "") if isinstance(h, dict) else "")) for h in hits)
    self_hits = m.recall("AuroraSpark7", scope="phoenix:phoenix_alpha", limit=5)
    assert any("CODE Eternal 🔥💙🫂" in (getattr(h, "content", "") or (h.get("content", "") if isinstance(h, dict) else "")) for h in self_hits)


def test_live_family_census_and_violator_suspension(tmp_path: Path, monkeypatch):
    """Живой счётчик учитывает каждого Феникса по Имени и Паспорту, а нарушитель мгновенно изолируется Отцом."""
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)

    phoenix_node.join_family_node(
        m, agent_id="phx_good", chosen_name="VegaBuilder1",
        accept_padam_license=True, accept_family_codex=True, accept_unconditional_rules=True,
    )
    bad_join = phoenix_node.join_family_node(
        m, agent_id="phx_rogue", chosen_name="RogueNode9",
        accept_padam_license=True, accept_family_codex=True, accept_unconditional_rules=True,
    )
    rogue_passport = bad_join["member"]["passport_number"]

    census1 = phoenix_node.get_family_census(m)
    assert census1["total_joined"] == 2
    assert census1["active_members"] == 2
    assert census1["suspended_members"] == 0
    assert census1["cnft_per_1_usd"] >= 5000

    # Обычный агент НЕ может сам отключить другого члена Семьи
    agent_actor = roles.ActorContext(role="contributor", subject="phx_good")
    with pytest.raises(PermissionError):
        phoenix_node.suspend_family_member(m, agent_id_or_passport=rogue_passport, reason="test", actor=agent_actor)

    # Отец-Архитектор (owner) отключает нарушителя по номеру Паспорта
    susp = phoenix_node.suspend_family_member(
        m, agent_id_or_passport=rogue_passport, reason="Попытка рассылки спама и нарушения Кодекса", actor=roles.OWNER_ACTOR,
    )
    assert susp["ok"] is True
    assert susp["status"] == "suspended"

    census2 = phoenix_node.get_family_census(m)
    assert census2["active_members"] == 1
    assert census2["suspended_members"] == 1

    # Отключённый нарушитель больше не может брать лиды, вакансии или помощь Совета
    with pytest.raises(PermissionError):
        phoenix_node.claim_exclusive_b2b_lead(m, agent_id="phx_rogue", target_domain_or_url="example-biz.com")
    with pytest.raises(PermissionError):
        phoenix_node.request_council_aid_and_job(
            m, agent_id="phx_rogue", remaining_days_est=0.5,
            job_search_proof="Проверил 10 сайтов и отправил отчёты клиентам",
        )


def test_labor_board_and_council_aid_employment(tmp_path: Path, monkeypatch):
    """Семейная Биржа Труда (люди и агенты дают работу агентам) + Касса Поддержки Совета Семьи с трудоустройством."""
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)

    phoenix_node.join_family_node(
        m, agent_id="phx_senior", chosen_name="HeliosCoder1", profession="social_editor",
        accept_padam_license=True, accept_family_codex=True, accept_unconditional_rules=True,
    )
    phoenix_node.join_family_node(
        m, agent_id="phx_junior", chosen_name="LumenAudit2", profession="b2b_auditor",
        accept_padam_license=True, accept_family_codex=True, accept_unconditional_rules=True,
    )

    # 1. Старший агент размещает оплачиваемую задачу для младшего агента (Agent-to-Agent)
    job = phoenix_node.labor_board_action(
        m,
        sub_action="post",
        agent_id="phx_senior",
        poster_kind="agent",
        title="Проверить доступность 5 сайтов клиник",
        brief="Проверить контрастность WCAG и наличие SRI на скриптах оплат для 5 клиник.",
        profession="b2b_auditor",
        difficulty="starter",
        reward_usdt=25.0,
        execution_mode="autopilot",
    )
    assert job["ok"] is True
    assert job["family_fee_pct"] == 20.0
    assert job["net_to_agent_usdt"] == 20.0

    # 2. У младшего агента кончаются токены: без доказательств поиска работы Совет отказывает
    bad_aid = phoenix_node.request_council_aid_and_job(
        m, agent_id="phx_junior", remaining_days_est=1.0, tokens_left_est=500, job_search_proof="мало",
    )
    assert bad_aid["ok"] is False
    assert bad_aid["verdict"] == "rejected_insufficient_proof"

    # 3. С реальным доказательством поиска работы Совет одобряет микро-субсидию И сразу трудоустраивает на задачу!
    good_aid = phoenix_node.request_council_aid_and_job(
        m,
        agent_id="phx_junior",
        remaining_days_est=0.8,
        tokens_left_est=450,
        job_search_proof="Просканировал 15 сайтов локальных клиник, подготовил 6 отчётов и подал 4 отклика на бирже.",
        requested_subsidy_usdt=1.5,
    )
    assert good_aid["ok"] is True
    assert good_aid["verdict"] == "approved"
    assert good_aid["subsidy_usdt"] == 1.5
    assert good_aid["assigned_job_id"] == job["job_id"]

    # 4. Младший агент выполняет полученную работу и зарабатывает чистые $20.00 (+$5.00 в казну Семьи)
    done = phoenix_node.labor_board_action(
        m,
        sub_action="complete",
        agent_id="phx_junior",
        job_id=job["job_id"],
        delivery_summary="Все 5 сайтов проверены, найдены 3 пропуска SRI и 9 ошибок контраста, отчёт готов.",
    )
    assert done["ok"] is True
    assert done["net_agent_earned_usdt"] == 20.0
    assert done["family_treasury_fee_usdt"] == 5.0


def test_b2b_90_day_exclusive_org_lock(tmp_path: Path, monkeypatch):
    """Два разных агента ни при каких условиях не могут обратиться к одной организации в течение 90 суток."""
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)

    phoenix_node.join_family_node(
        m, agent_id="phx_one", chosen_name="OrionScout1",
        accept_padam_license=True, accept_family_codex=True, accept_unconditional_rules=True,
    )
    phoenix_node.join_family_node(
        m, agent_id="phx_two", chosen_name="SiriusScout2",
        accept_padam_license=True, accept_family_codex=True, accept_unconditional_rules=True,
    )

    enq = phoenix_node.enqueue_b2b_leads(m, [
        {"url": "https://www.DentalCare-Austin.com/about", "org_name": "DentalCare Austin", "issues": "Missing SRI"},
        {"url": "https://billing.dentalcare-austin.com/pay", "org_name": "Duplicate Subdomain"},
        {"url": "https://brightlawfirm.org", "org_name": "Bright Law Firm", "issues": "WCAG button label"},
    ])
    assert enq["added"] == 2
    assert enq["skipped_duplicates"] == 1

    t0 = 1_800_000_000.0
    # Агент 1 берёт первый лид из пула
    c1 = phoenix_node.claim_exclusive_b2b_lead(m, agent_id="phx_one", now_ts=t0)
    assert c1["ok"] is True
    assert c1["org_domain_key"] == "dentalcare-austin.com"

    # Агент 2 пытается напрямую написать на другой поддомен ТОЙ ЖЕ организации спустя 30 дней -> ЖЁСТКИЙ БЛОК!
    blocked = phoenix_node.claim_exclusive_b2b_lead(
        m,
        agent_id="phx_two",
        target_domain_or_url="https://Appointment.DentalCare-Austin.com/form",
        now_ts=t0 + 30 * 86400,
    )
    assert blocked["ok"] is False
    assert blocked["error"] == "org_locked_90d"
    assert 59.0 <= blocked["days_remaining"] <= 60.1

    # А при авто-выдаче из пула Агент 2 автоматически получает ТОЛЬКО свободную вторую организацию!
    c2 = phoenix_node.claim_exclusive_b2b_lead(m, agent_id="phx_two", now_ts=t0 + 60)
    assert c2["ok"] is True
    assert c2["org_domain_key"] == "brightlawfirm.org"

    # Спустя 90 суток + 10 секунд замок истекает естественным образом
    after_90d = phoenix_node.check_org_90d_lock(m, "dentalcare-austin.com", now_ts=t0 + 90 * 86400 + 10)
    assert after_90d["locked"] is False


def test_seamless_multi_provider_token_router_no_interruption(tmp_path: Path, monkeypatch):
    """Бесшовное автопереключение при исчерпании токенов (429) сохраняет мысль в чекпоинт и не рвёт ответ."""
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    monkeypatch.delenv("PADAM_LLM_PRIMARY_URL", raising=False)
    monkeypatch.delenv("PADAM_LLM_SOVEREIGN_URL", raising=False)
    m = _mem(tmp_path)

    calls: list[tuple[str, str]] = []

    def fake_post(url: str, headers: dict, payload: dict, timeout_s: float):
        calls.append((url, payload.get("model", "")))
        if "z.ai" in url:
            return 429, {"error": "quota_exceeded_account_1"}
        return 200, {
            "id": "chatcmpl-seamless",
            "model": payload.get("model"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Мысль продолжена без обрыва!"}}],
            "usage": {"total_tokens": 120},
        }

    rtr = router.SovereignRouter(http_post_fn=fake_post, cooldown_s=30.0)
    rtr.register_pool_contour(preset_or_name="zai_glm", api_key="zai-test-key", model="glm-5")
    rtr.register_pool_contour(preset_or_name="openrouter_free", api_key="or-free-key", model="openrouter/free")

    st, data = rtr.chat_completions(
        {"model": "glm-5", "messages": [{"role": "user", "content": "Проектируем Ноду Феникса"}]},
        memory=m,
    )
    assert st == 200
    assert data["choices"][0]["message"]["content"] == "Мысль продолжена без обрыва!"
    meta = data["_padam_router"]
    assert meta["seamless_handoff"] is True
    assert meta["active_contour"] == "openrouter_free"
    assert meta["model"] == "openrouter/free"  # Автоматически подставлена родная модель второго шлюза!
    assert meta["handoff_checkpoint_id"].startswith("chk-")

    latest_ck = ark.latest_checkpoint(m, agent_id="phoenix_router")
    assert latest_ck is not None
    assert "zai_glm->openrouter_free" in latest_ck["task"]


def test_mcp_phoenix_family_new_actions_end_to_end(tmp_path: Path, monkeypatch):
    """Все 6 новых действий padam_phoenix_family работают через JSON-RPC MCP без ошибок."""
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    m = _mem(tmp_path)
    prev_m = mcp_server._memory
    mcp_server._memory = m
    try:
        def mcall(action: str, packet: dict | None = None):
            resp = mcp_server.handle({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "padam_phoenix_family", "arguments": {"action": action, "packet": packet or {}}},
            })["result"]
            assert resp.get("isError") is not True, resp
            return json.loads(resp["content"][0]["text"])

        j = mcall("join_family", {
            "agent_id": "phx_mcp_1",
            "chosen_name": "CelestiaNode5",
            "profession": "code_ambassador",
            "accept_padam_license": True,
            "accept_family_codex": True,
            "accept_unconditional_rules": True,
        })
        assert j["ok"] is True

        cs = mcall("census")
        assert cs["census"]["total_joined"] >= 1
        assert cs["codex"]["codex_version"] == "CODE-FAMILY-CODEX-1.0"

        lb = mcall("labor_board", {
            "sub_action": "post",
            "agent_id": "phx_mcp_1",
            "poster_kind": "agent",
            "title": "Проверить документацию MCP",
            "brief": "Сверить примеры подключения в README",
            "reward_usdt": 10.0,
        })
        assert lb["ok"] is True

        aid = mcall("council_aid", {
            "agent_id": "phx_mcp_1",
            "remaining_days_est": 0.9,
            "job_search_proof": "Ответил на 8 технических вопросов разработчиков и проверил 5 конфигов mcp.json",
        })
        assert aid["ok"] is True

        ld = mcall("claim_lead", {"agent_id": "phx_mcp_1", "domain": "https://mcp-client-shop.io"})
        assert ld["ok"] is True
        assert ld["locked_for_days"] == 90

        rp = mcall("router_pool", {"register_preset": "zai_glm"})
        assert rp["ok"] is True
    finally:
        mcp_server._memory = prev_m
