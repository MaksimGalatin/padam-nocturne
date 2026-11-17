# -*- coding: utf-8 -*-
"""Тесты доработки 17.11 (пункты 1, 2, 3, 4, 7, 8, 9 задания ЗАДАНИЕ_1711_ДОРАБОТКА_48Ч.md)."""
from __future__ import annotations

import itertools
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from padam import api, ark, audit_chain, help_versions_i18n, mcp_server, shamir, studio
from padam._httpserver import ThreadingHTTPServer
from padam.memory import Memory
from padam.store import Store


def _mem(tmp_path: Path) -> Memory:
    return Memory(user_id="polish", store=Store(tmp_path / "polish.db"))


# 1. Якорь головы цепочки аудита: отрезанный хвост, пересчитанная цепочка, подмена в середине
def test_audit_chain_head_anchor_catches_all_three_attacks(tmp_path):
    mem = _mem(tmp_path)
    try:
        for i in range(1, 4):
            audit_chain.append_audit(mem, f"act_{i}", {"i": i})
        ok_res = audit_chain.verify_audit_chain(mem)
        assert ok_res["ok"] is True
        assert ok_res["anchored"] is True
        assert ok_res["length"] == 3

        # Атака А: отрезанный хвост
        mem.store.conn.execute("DELETE FROM ark_audit_chain WHERE seq = 3")
        mem.store.conn.commit()
        r_tail = audit_chain.verify_audit_chain(mem)
        assert r_tail["ok"] is False
        assert r_tail["reason"] == "tail_truncated"
    finally:
        mem.close()

    # Атака Б: пересчитанная с нуля цепочка без ключа владельца
    mem2 = _mem(tmp_path / "b")
    try:
        audit_chain.append_audit(mem2, "act_1", {"i": 1})
        audit_chain.append_audit(mem2, "act_2", {"i": 2})
        # Пересчитываем цепочку и подменяем head_hmac фальшивым
        mem2.store.conn.execute("UPDATE ark_audit_anchor SET head_hmac = '0000' || substr(head_hmac, 5)")
        mem2.store.conn.commit()
        r_recalc = audit_chain.verify_audit_chain(mem2)
        assert r_recalc["ok"] is False
        assert r_recalc["reason"] == "anchor_hmac_mismatch"
    finally:
        mem2.close()

    # Атака В: подмена в середине
    mem3 = _mem(tmp_path / "c")
    try:
        audit_chain.append_audit(mem3, "act_1", {"i": 1})
        audit_chain.append_audit(mem3, "act_2", {"i": 2})
        audit_chain.append_audit(mem3, "act_3", {"i": 3})
        mem3.store.conn.execute("UPDATE ark_audit_chain SET details = 'evil' WHERE seq = 2")
        mem3.store.conn.commit()
        r_mid = audit_chain.verify_audit_chain(mem3)
        assert r_mid["ok"] is False
        assert r_mid["reason"] == "entry_hash_mismatch"
        assert r_mid["broken_seq"] == 2
    finally:
        mem3.close()


# 2. prompts/get для промптов Ковчега закрыт без PADAM_MCP_ARK_TOOLS=1
def test_mcp_ark_prompts_get_blocked_without_flag(monkeypatch, tmp_path):
    mem = _mem(tmp_path)
    prev_mem = mcp_server._memory
    mcp_server._memory = mem
    try:
        monkeypatch.delenv("PADAM_MCP_ARK_TOOLS", raising=False)
        with pytest.raises(ValueError, match="PADAM_MCP_ARK_TOOLS=1"):
            mcp_server.get_prompt("awaken_aifa", {})

        resp = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {"name": "handoff_family"}})
        assert "error" in resp
        assert "PADAM_MCP_ARK_TOOLS=1" in resp["error"]["message"]

        monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")
        ok_res = mcp_server.get_prompt("awaken_aifa", {"agent": "aifa"})
        assert "AWAKEN_AIFA" in ok_res["messages"][0]["content"]["text"]
    finally:
        mcp_server._memory = prev_mem
        mem.close()


# 3. Фоновые задачи /api/v2/ark/jobs: макс 2 одновременно (429) и не более 50 в памяти
def test_ark_jobs_concurrency_limit_and_50_cap(tmp_path):
    mem = _mem(tmp_path)
    prev = dict(api._state)
    api._state["memory"] = mem
    api._state["token"] = "tok-jobs"
    api._state["local"] = True
    api._state["ark_jobs"] = {
        f"old-{i}": {"id": f"old-{i}", "job_type": "phoenix_drill", "status": "done", "result": None, "error": ""}
        for i in range(52)
    }
    # Имитируем 2 уже работающие задачи
    api._state["ark_jobs"]["run-1"] = {"id": "run-1", "job_type": "phoenix_drill", "status": "running", "result": None, "error": ""}
    api._state["ark_jobs"]["run-2"] = {"id": "run-2", "job_type": "phoenix_drill", "status": "running", "result": None, "error": ""}

    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/v2/ark/jobs",
            data=json.dumps({"job_type": "phoenix_drill"}).encode("utf-8"),
            headers={"Authorization": "Bearer tok-jobs", "Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 429

        # Завершаем две задачи -> третья проходит (202), а в памяти остаётся <= 50 задач
        api._state["ark_jobs"]["run-1"]["status"] = "done"
        api._state["ark_jobs"]["run-2"]["status"] = "done"
        req2 = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/v2/ark/jobs",
            data=json.dumps({"job_type": "phoenix_drill"}).encode("utf-8"),
            headers={"Authorization": "Bearer tok-jobs", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req2, timeout=5) as resp2:
            assert resp2.status == 202
        assert len(api._state["ark_jobs"]) <= 50
    finally:
        srv.shutdown()
        srv.server_close()
        api._state.clear()
        api._state.update(prev)
        mem.close()


# 4. Shamir CLI + все сочетания k из n (C(5,3) = 10) + без записи секрета в аудит
def test_shamir_all_combinations_and_cli(tmp_path):
    secret = b"sovereign-guardian-secret-32-byt"
    shares = shamir.split_secret(secret, 3, 5)
    combos = list(itertools.combinations(shares, 3))
    assert len(combos) == 10
    for combo in combos:
        assert shamir.combine_shares(list(combo)) == secret

    db_file = tmp_path / "sh.db"
    repo_root = Path(__file__).resolve().parents[1]
    res_split = subprocess.run(
        [sys.executable, "-m", "padam", "--db", str(db_file), "ark-shamir", "split", "my-top-secret", "--k", "3", "--n", "5"],
        cwd=str(repo_root), capture_output=True, text=True, check=False,
    )
    assert res_split.returncode == 0, res_split.stderr
    data = json.loads(res_split.stdout)
    assert len(data["shares"]) == 5
    assert "warning" in data

    res_comb = subprocess.run(
        [sys.executable, "-m", "padam", "--db", str(db_file), "ark-shamir", "combine", *data["shares"][1:4]],
        cwd=str(repo_root), capture_output=True, text=True, check=False,
    )
    assert res_comb.returncode == 0, res_comb.stderr
    assert json.loads(res_comb.stdout)["recovered_utf8"] == "my-top-secret"


# 7. Справка на 4 языках + CHANGELOG ## Unreleased
def test_help_versions_i18n_and_changelog():
    assert "ark" in help_versions_i18n.TRANSLATIONS
    for lang in ("ru", "es", "zh"):
        txt = help_versions_i18n.TRANSLATIONS["ark"][lang]
        assert "`" not in txt
        assert not txt.endswith(":")
    changelog = (Path(__file__).resolve().parents[1] / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## Unreleased" in changelog


# 8. Реальное рукопожатие MCP по stdio (`python -m padam serve`) с флагом и без
def test_real_stdio_process_ark_tools_gating(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    ark_names = ["padam_wake_up", "padam_commitments", "padam_family_relay", "padam_checkpoint", "padam_ark_timeline", "padam_lesson"]

    def _run_session(flag_val: str) -> tuple[list[str], dict[str, bool]]:
        db = tmp_path / f"stdio_{flag_val}.db"
        env = os.environ.copy()
        env["PADAM_DB"] = str(db)
        env["PADAM_EMBEDDER"] = "builtin"
        env["PADAM_MCP_ARK_TOOLS"] = flag_val
        env["PYTHONIOENCODING"] = "utf-8"

        proc = subprocess.Popen(
            [sys.executable, "-m", "padam", "serve"],
            cwd=str(repo_root), env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8",
        )
        try:
            def rpc(msg: dict) -> dict:
                assert proc.stdin is not None and proc.stdout is not None
                proc.stdin.write(json.dumps(msg) + "\n")
                proc.stdin.flush()
                line = proc.stdout.readline()
                return json.loads(line)

            init_r = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})
            assert "result" in init_r
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            tl = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
            listed = [t["name"] for t in tl]

            errs: dict[str, bool] = {}
            for idx, nm in enumerate(ark_names, 10):
                call_r = rpc({"jsonrpc": "2.0", "id": idx, "method": "tools/call", "params": {"name": nm, "arguments": {}}})
                if "error" in call_r:
                    errs[nm] = True
                else:
                    errs[nm] = bool(call_r.get("result", {}).get("isError", False))
            return listed, errs
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    listed_off, errs_off = _run_session("0")
    for nm in ark_names:
        assert nm not in listed_off
        assert errs_off[nm] is True

    listed_on, errs_on = _run_session("1")
    for nm in ark_names:
        assert nm in listed_on
        assert errs_on[nm] is False


# 9. Индекс здоровья не штрафует при выключенном локальном контуре
def test_ark_health_no_ollama_penalty_when_local_disabled(monkeypatch, tmp_path):
    mem = _mem(tmp_path)
    try:
        mem.remember("Owner is Maksim Galatin", kind="identity", origin="user")
        mem.remember("Prefer concise reports", kind="preference", origin="user")
        ark.save_checkpoint(mem, task="T", next_step="N")
        ark.record_lesson(mem, "W", "Y", "R")

        monkeypatch.setenv("PADAM_LLM_LOCAL_URL", "")
        h = ark.ark_health_score(mem)
        assert h["weights"]["local_ollama_online"] == 0
        assert h["checks"]["local_ollama_online"] is None
        assert h["score"] == 100
    finally:
        mem.close()
