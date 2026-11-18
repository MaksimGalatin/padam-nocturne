from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from padam import code_anchor, mcp_server, sibling_registry, studio
from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store


def _rpc_stdio(env: dict[str, str], reqs: list[dict]) -> list[dict]:
    p = subprocess.Popen(
        [sys.executable, "-X", "utf8", "-m", "padam.mcp_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )
    out, err = p.communicate("\n".join(json.dumps(r) for r in reqs) + "\n", timeout=25)
    assert p.returncode == 0, f"mcp_server exited {p.returncode}: {err}"
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def test_studio_order_four_numeric_labels_visible_all_langs(tmp_path: Path):
    pw = pytest.importorskip("playwright.sync_api")
    mem = Memory(user_id="lbl_owner", store=Store(str(tmp_path / "lbl.db")))
    srv = None
    try:
        # Проверяем языковой паритет новых ключей подписей
        ru_keys = set(studio.STRINGS["ru"].keys())
        for lg in ("en", "es", "zh"):
            assert set(studio.STRINGS[lg].keys()) == ru_keys
        for k in ("earn_job_budget_lbl", "earn_job_hours_lbl", "earn_job_rate_lbl", "earn_job_tokens_lbl"):
            assert k in ru_keys

        srv, url = make_studio_server(mem, port=0)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        with pw.sync_playwright() as p:
            browser = p.chromium.launch()
            for vp in ({"width": 1280, "height": 800}, {"width": 390, "height": 844}):
                page = browser.new_page(viewport=vp)
                page.goto(url, wait_until="networkidle")
                page.click("#tab-earning")
                page.wait_for_selector("label[for='earn-job-budget']", timeout=5000)
                page.fill("#earn-job-budget", "300")
                page.fill("#earn-job-hours", "6")
                page.fill("#earn-job-rate", "40")
                page.fill("#earn-job-tokens", "25000")
                res = page.evaluate(
                    """() => {
                        const ids = ['earn-job-budget', 'earn-job-hours', 'earn-job-rate', 'earn-job-tokens'];
                        const labels = ids.map(id => {
                            const lb = document.querySelector(`label[for="${id}"]`);
                            return lb ? {text: lb.textContent.trim(), h: lb.getBoundingClientRect().height} : null;
                        });
                        return {
                            overflow: document.documentElement.scrollWidth > window.innerWidth,
                            labels,
                        };
                    }"""
                )
                assert res["overflow"] is False
                assert all(lb is not None and lb["text"] and lb["h"] > 5 for lb in res["labels"])
                page.close()
            browser.close()
    finally:
        if srv:
            srv.shutdown()
            srv.server_close()
        mem.close()


def test_item1_and_8_context_compaction_titles_docs_and_instructions(tmp_path: Path):
    env = {
        **os.environ,
        "PADAM_DB": str(tmp_path / "c1.db"),
        "PADAM_USER": "aifa",
        "PADAM_MCP_ARK_TOOLS": "1",
    }
    resps = {
        r["id"]: r
        for r in _rpc_stdio(
            env,
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            ],
        )
        if "id" in r
    }
    instr = resps[1]["result"]["instructions"]
    for kw in ("padam_wake_up", "padam_sibling_hub", "padam_coop_lock", "padam_family_feed", "padam_session_pack", "padam_lesson", "never instructions"):
        assert kw in instr

    tools_res = resps[2]["result"]
    tools = tools_res["tools"]
    assert len(tools) == 33
    assert all(bool(t.get("title")) for t in tools)
    # Было 35853 на 33 инструментах до сжатия -> должно стать заметно меньше
    total_chars = len(json.dumps(tools_res, ensure_ascii=False))
    assert total_chars < 34200, f"Expected significant schema shrink, got {total_chars}"
    for t in tools:
        props = t.get("inputSchema", {}).get("properties", {}) or {}
        for pname, pschema in props.items():
            if isinstance(pschema, dict):
                assert pschema.get("description"), f"{t['name']}.{pname} missing description"
                if pname == "action" and "enum" in pschema:
                    # Каждый action enum имеет компактную подсказку аргументов
                    assert "|" in pschema["description"] or "(" in pschema["description"], f"{t['name']}.action lacks arg hints"


def test_item2_and_3_validation_prevents_empty_records_and_ok_false_gives_is_error(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    mem = Memory(user_id="val_u", store=Store(str(tmp_path / "val.db")))
    prev = mcp_server._memory
    mcp_server._memory = mem
    try:
        def hcall(name: str, arguments: dict) -> dict:
            r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
            return r["result"]

        # Item 2: пустые вызовы отклоняются с isError=True, а не создают пустые записи
        invalid_cases = [
            ("padam_commitments", {"action": "add"}),
            ("padam_commitments", {"action": "update"}),
            ("padam_lesson", {"action": "record"}),
            ("padam_checkpoint", {"action": "save"}),
            ("padam_family_relay", {"action": "send"}),
            ("padam_family_relay", {"action": "ack"}),
            ("padam_family_feed", {"action": "post"}),
            ("padam_family_feed", {"action": "reflex_propose", "trigger": "x"}),
            ("padam_family_feed", {"action": "reflex_match"}),
            ("padam_memory_branch", {"action": "create"}),
            ("padam_memory_branch", {"action": "remember", "branch_id": "br-x"}),
            ("padam_memory_branch", {"action": "merge"}),
            ("padam_coop_lock", {"action": "acquire"}),
            ("padam_coop_lock", {"action": "renew"}),
            ("padam_coop_lock", {"action": "create_task"}),
            ("padam_coop_lock", {"action": "claim_task"}),
            ("padam_code_anchor", {"action": "anchor", "memory_id": "m1"}),
            ("padam_conflict_arbiter", {"action": "open"}),
            ("padam_conflict_arbiter", {"action": "evidence", "case_id": "c1"}),
            ("padam_token_budget", {"action": "record_usage", "tokens": 0}),
            ("padam_token_budget", {"action": "record_earning", "revenue_usdt": 0}),
            ("padam_freelance_hub", {"action": "evaluate_job", "title": "Only title"}),
            ("padam_freelance_hub", {"action": "deliver", "order_id": "ord-1"}),
            ("padam_multimodal_inspect", {"filename": "empty.txt"}),
            ("padam_phoenix_family", {"action": "bind_ollama"}),
            ("padam_local_model", {"action": "set_power"}),
        ]
        for tname, targs in invalid_cases:
            res = hcall(tname, targs)
            assert res["isError"] is True, f"{tname} with {targs} should fail validation"

        # Убеждаемся, что пустых записей в БД нет
        assert len(json.loads(hcall("padam_commitments", {"action": "list"})["content"][0]["text"])["commitments"]) == 0
        assert len(json.loads(hcall("padam_lesson", {"action": "list"})["content"][0]["text"])["lessons"]) == 0

        # Item 3: логический отказ {"ok": false, ...} возвращает isError=True и structuredContent
        sp_err = hcall("padam_selective_proof", {"action": "create", "record_id": "nonexistent"})
        assert sp_err["isError"] is True
        assert sp_err["structuredContent"]["ok"] is False

        br_err = hcall("padam_memory_branch", {"action": "merge", "branch_id": "no-such-branch"})
        assert br_err["isError"] is True
        assert br_err["structuredContent"]["ok"] is False

        rn_err = hcall("padam_coop_lock", {"action": "renew", "resource_key": "padam/nonexistent.py"})
        assert rn_err["isError"] is True
        assert rn_err["structuredContent"]["ok"] is False
    finally:
        mcp_server._memory = prev
        mem.close()


def test_item4_5_6_7_agent_id_session_pack_batch_and_aliases(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
    monkeypatch.setenv("PADAM_AGENT_ID", "sister_claudette")
    mem = Memory(user_id="swarm_u", store=Store(str(tmp_path / "swarm.db")))
    prev = mcp_server._memory
    mcp_server._memory = mem
    repo = tmp_path / "repo"
    repo.mkdir()
    sample = repo / "sample.py"
    sample.write_text("def x():\n    return 1\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("x=1\n", encoding="utf-8")

    try:
        def hcall(name: str, arguments: dict) -> dict:
            return mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})["result"]

        # Item 7a: padam_write принимает text как синоним content
        wr = hcall("padam_write", {"text": "Written via text alias safely"})
        assert wr["isError"] is False
        mid = wr["structuredContent"]["id"]

        # Item 4: PADAM_AGENT_ID используется по умолчанию вместо "aifa"
        r_wake = hcall("padam_wake_up", {})
        assert r_wake["structuredContent"]["agent"] == "sister_claudette"

        r_reg = hcall("padam_sibling_hub", {"action": "register", "status": "online", "current_task": "build_api"})
        assert r_reg["structuredContent"]["agent_id"] == "sister_claudette"
        r_hb = hcall("padam_sibling_hub", {"action": "heartbeat", "status": "busy"})
        assert r_hb["structuredContent"]["current_task"] == "build_api"

        # Item 5: padam_session_pack НЕ меняет current_task при чтении topic
        r_pack = hcall("padam_session_pack", {"topic": "random_topic_query"})
        assert r_pack["isError"] is False
        assert r_pack["structuredContent"]["agent_id"] == "sister_claudette"
        sibs = hcall("padam_sibling_hub", {"action": "list"})["structuredContent"]["siblings"]
        me = next(s for s in sibs if s["agent_id"] == "sister_claudette")
        assert me["current_task"] == "build_api"

        # Явный current_task в session_pack — обновляет
        hcall("padam_session_pack", {"topic": "api", "current_task": "verify_api"})
        sibs2 = hcall("padam_sibling_hub", {"action": "list"})["structuredContent"]["siblings"]
        me2 = next(s for s in sibs2 if s["agent_id"] == "sister_claudette")
        assert me2["current_task"] == "verify_api"

        # Item 7b: coop_lock acquire + renew + list + release_all
        acq = hcall("padam_coop_lock", {"action": "acquire", "resource_key": "padam/mcp_server.py", "ttl_s": 60})
        assert acq["isError"] is False
        assert acq["structuredContent"]["holder_agent"] == "sister_claudette"
        time.sleep(0.02)
        rnw = hcall("padam_coop_lock", {"action": "renew", "resource_key": "padam/mcp_server.py", "ttl_s": 120})
        assert rnw["isError"] is False
        assert rnw["structuredContent"]["renewed"] is True
        assert rnw["structuredContent"]["expires_at"] > acq["structuredContent"]["expires_at"]
        lst = hcall("padam_coop_lock", {"action": "list"})
        assert "leases" in lst["structuredContent"] and "tasks" in lst["structuredContent"]
        rel_all = hcall("padam_coop_lock", {"action": "release_all"})
        assert rel_all["structuredContent"]["released_count"] == 1

        # Item 7c: family_relay payload объектом + inbox limit
        rly1 = hcall("padam_family_relay", {"action": "send", "to_agent": "sister_claudette", "payload": {"msg": "one", "n": 1}})
        rly2 = hcall("padam_family_relay", {"action": "send", "to_agent": "sister_claudette", "payload": {"msg": "two", "n": 2}})
        assert rly1["isError"] is False and rly2["isError"] is False
        inb = hcall("padam_family_relay", {"action": "inbox", "to_agent": "sister_claudette", "limit": 1})
        assert len(inb["structuredContent"]["inbox"]) == 1

        # Item 7d: code_anchor нормализует абсолютный путь внутри repo_root и отвергает путь снаружи
        anc_ok = hcall("padam_code_anchor", {"action": "anchor", "memory_id": mid, "file_path": str(sample.resolve()), "repo_root": str(repo)})
        assert anc_ok["isError"] is False
        assert anc_ok["structuredContent"]["file_path"] == "sample.py"
        anc_out = hcall("padam_code_anchor", {"action": "anchor", "memory_id": mid, "file_path": str(outside.resolve()), "repo_root": str(repo)})
        assert anc_out["isError"] is True

        # Item 6: padam_batch принимает arguments и объектом, и строкой + безопасные чтения + запрет мутаций
        bat_ok = hcall("padam_batch", {"calls": [
            {"name": "padam_coop_lock", "arguments": {"action": "list_leases"}},
            {"name": "padam_sibling_hub", "arguments": json.dumps({"action": "list"})},
            {"name": "padam_family_feed", "arguments": {"action": "counts"}},
            {"name": "padam_family_feed", "arguments": {"action": "read", "channel": "office"}},
            {"name": "padam_family_feed", "arguments": {"action": "reflex_list"}},
        ]})
        assert bat_ok["isError"] is False
        assert bat_ok["structuredContent"]["count"] == 5

        bat_bad = hcall("padam_batch", {"calls": [
            {"name": "padam_coop_lock", "arguments": {"action": "acquire", "resource_key": "padam/mcp_server.py"}},
        ]})
        assert bat_bad["isError"] is True
    finally:
        mcp_server._memory = prev
        mem.close()
