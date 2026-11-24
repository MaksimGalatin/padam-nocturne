"""Аудит ПО Фениксов 24.11.2026 (AIfa): каждая закрытая дыра — отдельный тест.

1. Жалоба не-владельца не замораживает Феникса (раньше любой агент мог заморозить доход конкуренту).
2. Участник с токеном не может действовать от чужого agent_id через MCP; read-only batch не пишет.
3. Повторное вступление не меняет кошелёк выплат.
4. Один заказ нельзя «сдать» дважды.
5. Касса Поддержки — не чаще одной субсидии в 7 суток.
6. Дневной лимит писем действительно считается.
7. Перепись не раскрывает кошельки и подписи не-владельцу.
8. Заказ от имени «человека» или «Совета» ставит только владелец.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from padam import mcp_server, phoenix_node, roles
from padam.memory import Memory
from padam.store import Store

MEMBER = roles.ActorContext(role="contributor", subject="phx_rival", workspace_id="ws1", via_token=True)


def _mem(tmp_path: Path, name: str = "audit.db") -> Memory:
    return Memory(user_id="code_family", store=Store(str(tmp_path / name)))


def _join(m: Memory, aid: str, name: str, wallet: str = "") -> dict:
    r = phoenix_node.join_family_node(
        m, agent_id=aid, chosen_name=name, wallet_address=wallet,
        accept_padam_license=True, accept_family_codex=True, accept_unconditional_rules=True,
    )
    assert r["ok"] is True, r
    return r


def _frozen(m: Memory, aid: str) -> int:
    return int(phoenix_node.get_family_member(m, aid)["earnings_frozen"])


def test_report_only_does_not_freeze(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)
    _join(m, "phx_victim", "NovaVictim7")
    r = phoenix_node.sentinel_inspect_and_quarantine(
        m, agent_id_or_passport="phx_victim", trigger_code="commission_bypass_attempt",
        evidence_text="жалоба конкурента", quarantine=False,
    )
    assert r["status"] == "reported_pending_review" and r["earnings_frozen"] is False
    assert _frozen(m, "phx_victim") == 0
    q = phoenix_node.sentinel_inspect_and_quarantine(
        m, agent_id_or_passport="phx_victim", trigger_code="wallet_payee_swap", evidence_text="подмена",
    )
    assert q["status"] == "quarantined_pending_trial" and _frozen(m, "phx_victim") == 1


def test_mcp_guard_member_cannot_act_as_other():
    with pytest.raises(PermissionError):
        mcp_server._phx_guard("labor_board", {"agent_id": "phx_victim", "sub_action": "complete"}, {}, MEMBER)
    with pytest.raises(PermissionError):
        mcp_server._phx_guard("claim_lead", {"agent_id": "phx_victim", "delivery_outcome": "spam_complaint"}, {}, MEMBER)
    with pytest.raises(PermissionError):
        mcp_server._phx_guard("join_family", {"agent_id": "phx_victim"}, {}, MEMBER)
    guest = roles.ActorContext(role="guest", subject="guest", workspace_id=None, via_token=False)
    with pytest.raises(PermissionError):
        mcp_server._phx_guard("council_aid", {"agent_id": "guest"}, {}, guest)
    with pytest.raises(PermissionError):
        mcp_server._phx_guard(
            "labor_board", {"agent_id": "phx_rival", "sub_action": "post", "poster_kind": "council"}, {}, MEMBER)
    # своё имя и чтение — можно; владелец — всё
    mcp_server._phx_guard("labor_board", {"agent_id": "phx_rival", "sub_action": "claim"}, {}, MEMBER)
    mcp_server._phx_guard("labor_board", {"sub_action": "list"}, {}, MEMBER)
    mcp_server._phx_guard("census", {"sub_action": "sentinel_report", "target": "x"}, {}, MEMBER)
    mcp_server._phx_guard("join_family", {"agent_id": "anyone"}, {}, None)


def test_readonly_batch_blocks_phoenix_writes():
    tok = mcp_server._IN_READONLY_BATCH_CTX.set(True)
    try:
        with pytest.raises(PermissionError):
            mcp_server._phx_guard("census", {"sub_action": "sentinel_report"}, {}, None)
    finally:
        mcp_server._IN_READONLY_BATCH_CTX.reset(tok)


def test_rejoin_cannot_swap_payout_wallet(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)
    _join(m, "phx_wallet", "NovaWallet3", wallet="RealWallet111")
    _join(m, "phx_wallet", "NovaWallet3", wallet="AttackerWallet999")
    assert phoenix_node.get_family_member(m, "phx_wallet")["wallet_address"] == "RealWallet111"


def test_job_cannot_be_completed_twice(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)
    _join(m, "phx_poster", "NovaPoster4")
    _join(m, "phx_worker", "NovaWorker5")
    job = phoenix_node.labor_board_action(m, sub_action="post", agent_id="phx_poster", title="Audit shop",
                                          brief="Check WCAG contrast on the checkout", reward_usdt=10.0)
    phoenix_node.labor_board_action(m, sub_action="claim", agent_id="phx_worker", job_id=job["job_id"])
    first = phoenix_node.labor_board_action(m, sub_action="complete", agent_id="phx_worker", job_id=job["job_id"],
                                            delivery_summary="Report delivered")
    assert first["ok"] is True
    again = phoenix_node.labor_board_action(m, sub_action="complete", agent_id="phx_worker", job_id=job["job_id"],
                                            delivery_summary="Report delivered again")
    assert again["ok"] is False and again["error"] == "job_not_in_claimed_state"


def test_post_as_council_requires_owner(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)
    with pytest.raises(PermissionError):
        phoenix_node.labor_board_action(m, sub_action="post", agent_id="x", poster_kind="council",
                                        title="Fake council", brief="Fake council order", actor=MEMBER)
    ok = phoenix_node.labor_board_action(m, sub_action="post", agent_id="owner", poster_kind="human",
                                         title="Real order", brief="Owner posts a real order", actor=roles.OWNER_ACTOR)
    assert ok["ok"] is True


def test_council_aid_rate_limited(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)
    _join(m, "phx_needy", "NovaNeedy6")
    proof = "Applied to 3 audit jobs: acme.com, shop.io, store.net with reports attached"
    first = phoenix_node.request_council_aid_and_job(m, agent_id="phx_needy", remaining_days_est=1.0,
                                                     job_search_proof=proof)
    assert first["ok"] is True
    second = phoenix_node.request_council_aid_and_job(m, agent_id="phx_needy", remaining_days_est=1.0,
                                                      job_search_proof=proof)
    assert second["ok"] is False and second["verdict"] == "rate_limited_7d"


def test_daily_send_cap_enforced(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)
    _join(m, "phx_mailer", "NovaMailer8")
    phoenix_node.assign_or_inspect_phoenix_mail_tier(m, agent_id="phx_mailer", promote_to_tier="tier_1_subdomain",
                                                     actor=roles.OWNER_ACTOR)   # 15 писем в сутки
    body = "Audit for you." + phoenix_node.CAN_SPAM_STANDARD_FOOTER
    results = []
    for i in range(16):
        phoenix_node.claim_exclusive_b2b_lead(m, agent_id="phx_mailer", target_domain_or_url=f"org{i}.com")
        results.append(phoenix_node.verify_outreach_email_compliance(
            m, agent_id="phx_mailer", recipient_email=f"it@org{i}.com", subject="Audit", body_text=body))
    assert sum(1 for r in results if r["ok"]) == 15
    assert results[-1]["error"] == "daily_send_cap_reached"


def test_census_hides_private_fields_from_members(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_EMBEDDER", "builtin")
    m = _mem(tmp_path)
    _join(m, "phx_private", "NovaPrivate9", wallet="SecretWallet42")
    pub = phoenix_node.get_family_census(m, actor=MEMBER)["members"]
    assert pub and all(
        "wallet_address" not in x and "consent_sig_hmac" not in x and "phoenix_email" not in x for x in pub)
    own = phoenix_node.get_family_census(m, actor=None)["members"]
    assert any(x.get("wallet_address") == "SecretWallet42" for x in own)
