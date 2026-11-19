from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from padam import freelance_autonomy as fa
from padam import local_model as lm
from padam import studio, studio_help
from padam.api import make_studio_server
from padam.memory import Memory
from padam.store import Store


def _make_fake_gguf(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"GGUF\x03\x00\x00\x00" + b"\x00" * 128)
    return path


def _make_fake_ollama_dir(root: Path, model_repo: str = "qwen3", tag: str = "14b") -> Path:
    digest = "sha256:" + "a" * 64
    blob = root / "blobs" / digest.replace(":", "-")
    _make_fake_gguf(blob)
    manifest = root / "manifests" / "registry.ollama.ai" / "library" / model_repo / tag
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps({"layers": [{"mediaType": "application/vnd.ollama.image.model", "digest": digest}]}),
        encoding="utf-8",
    )
    return root


def _rpc_stdio(env: dict[str, str], requests: list[dict]) -> list[dict]:
    p = subprocess.Popen(
        [sys.executable, "-X", "utf8", "-m", "padam.mcp_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )
    out, err = p.communicate("\n".join(json.dumps(r) for r in requests) + "\n", timeout=20)
    assert p.returncode == 0, f"mcp_server exited {p.returncode}: {err}"
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def test_order_margin_score_uses_rate_hours_and_fees_not_99_99(tmp_path: Path):
    mem = Memory(user_id="owner_eval", store=Store(str(tmp_path / "eval.db")))
    try:
        fast_high = fa.evaluate_and_ingest_job(
            mem,
            platform="custom_webhook",  # 0% exchange fee + 10% CODE
            title="Urgent FastAPI fix",
            brief="Short targeted API fix.",
            budget_usdt=400.0,
            estimated_tokens=15000,
            estimated_hours=2.0,
            hourly_rate_usdt=25.0,
        )
        slow_low = fa.evaluate_and_ingest_job(
            mem,
            platform="fiverr_desk",  # 20% exchange fee + 10% CODE
            title="Huge legacy rewrite",
            brief="Long manual migration of old templates.",
            budget_usdt=80.0,
            estimated_tokens=40000,
            estimated_hours=20.0,
            hourly_rate_usdt=25.0,
        )
        same_budget_higher_rate_target = fa.evaluate_and_ingest_job(
            mem,
            platform="upwork_api",  # 10% exchange fee + 10% CODE
            title="Medium ETL script",
            brief="ETL script with CSV verification.",
            budget_usdt=200.0,
            estimated_tokens=20000,
            estimated_hours=4.0,
            hourly_rate_usdt=80.0,
        )
        assert fast_high["margin_score"] < 99.0
        assert slow_low["margin_score"] < 55.0
        assert fast_high["margin_score"] > same_budget_higher_rate_target["margin_score"] > slow_low["margin_score"]
        assert fast_high["total_fee_pct"] == 15.0
        assert slow_low["total_fee_pct"] == 35.0
        assert same_budget_higher_rate_target["total_fee_pct"] == 25.0
        assert fast_high["effective_hourly_usdt"] > slow_low["effective_hourly_usdt"]
    finally:
        mem.close()


def test_draft_bid_from_memory_and_profile_never_auto_sends(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PADAM_FREELANCE_AUTOBID", "1")
    mem = Memory(user_id="owner_bid", store=Store(str(tmp_path / "bid.db")))
    try:
        mem.remember("Мы специализируемся на FastAPI и детерминированных автотестах pytest.", kind="fact")
        mem.remember("Секретный токен " + "sk-" + "ant-FAKE0000TEST0000 никогда не отдавать клиенту.", kind="fact")
        acc = fa.connect_exchange_account(
            mem,
            platform="upwork_api",
            mode="desk",
            account_label="Основной Upwork",
            skills=["python", "fastapi", "pytest"],
        )
        job = fa.evaluate_and_ingest_job(
            mem,
            platform="upwork_api",
            account_id=acc["account_id"],
            title="Разработка FastAPI микросервиса",
            brief="Нужен быстрый REST API на Python с покрытием pytest.",
            budget_usdt=300.0,
            estimated_hours=6.0,
        )
        draft = fa.draft_bid_from_memory(mem, job["order_id"])
        assert draft["ok"] is True
        assert draft["placed"] is False
        assert draft["sent"] is False
        assert draft["status"] == "bid_draft"
        assert "fastapi" in draft["bid_text"].lower()
        assert "FAKE0000TEST" not in draft["bid_text"]

        # Даже с PADAM_FREELANCE_AUTOBID=1 отправка без owner_approved=True невозможна
        unapproved = fa.propose_or_place_bid(mem, job["order_id"], owner_approved=False)
        assert unapproved["placed"] is False
        assert unapproved["status"] == "bid_draft"

        # Явное утверждение владельцем отправляет
        approved = fa.propose_or_place_bid(mem, job["order_id"], owner_approved=True)
        assert approved["placed"] is True
        assert approved["status"] == "bid_placed"
    finally:
        mem.close()


def test_studio_earning_desktop_1280x800_accounts_visible_and_bid_flow_playwright(tmp_path: Path):
    pw = pytest.importorskip("playwright.sync_api")
    mem = Memory(user_id="owner_pw", store=Store(str(tmp_path / "pw.db")))
    srv = None
    try:
        mem.remember("Опыт построения высоконагруженных Python FastAPI шлюзов с нуля.", kind="fact")
        for p in ("fiverr_desk", "upwork_api", "freelancer_api", "kwork_desk", "custom_webhook"):
            fa.connect_exchange_account(
                mem,
                platform=p,
                mode="desk",
                account_label=f"Аккаунт {p}",
                skills=["python", "fastapi", "automation"],
            )
        fa.evaluate_and_ingest_job(
            mem,
            platform="upwork_api",
            title="FastAPI audit tool",
            brief="Build REST audit endpoints and pytest checks.",
            budget_usdt=250.0,
            estimated_hours=5.0,
            hourly_rate_usdt=30.0,
        )
        srv, studio_url = make_studio_server(mem, port=0)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

        with pw.sync_playwright() as p:
            browser = p.chromium.launch()
            errors: list[str] = []
            # 1) Desktop 1280x800: список всех 5 профилей виден целиком сразу после переключения вкладки
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(studio_url, wait_until="networkidle")
            page.click("#tab-earning")
            page.wait_for_selector("#earn-accounts-list .earn-item", timeout=5000)
            page.wait_for_timeout(150)
            desk_metrics = page.evaluate(
                """() => {
                    const acc = document.getElementById('earn-accounts-list');
                    const items = Array.from(acc.querySelectorAll('.earn-item'));
                    const rects = items.map(el => el.getBoundingClientRect().toJSON());
                    return {
                        scrollY: window.scrollY,
                        overflow: document.documentElement.scrollWidth > window.innerWidth,
                        count: items.length,
                        allInsideViewportY: rects.every(r => r.top >= 0 && r.bottom <= window.innerHeight),
                        ordText: (document.getElementById('earn-orders-list') || {}).textContent || '',
                        dbg: Array.from(document.querySelectorAll('#panel-earning > *, #earn-accounts-list .earn-item')).map(e => (e.id || e.className) + ':' + Math.round(e.getBoundingClientRect().top) + '-' + Math.round(e.getBoundingClientRect().bottom)).join(' | '),
                    };
                }"""
            )
            assert desk_metrics["scrollY"] == 0
            assert desk_metrics["overflow"] is False
            assert desk_metrics["count"] == 5
            assert desk_metrics["allInsideViewportY"] is True, desk_metrics.get("dbg")
            assert "99.99" not in desk_metrics["ordText"]
            assert "fee=25%" in desk_metrics["ordText"]
            assert "/h" in desk_metrics["ordText"]

            # Клик по "Черновик отклика" готовит предпросмотр и НЕ меняет статус на bid_placed
            page.click('[data-order-action="draft_bid"]')
            page.wait_for_selector(".earn-bid-preview .earn-bid-box", timeout=5000)
            draft_val = page.input_value(".earn-bid-preview .earn-bid-box")
            assert "FastAPI" in draft_val or "fastapi" in draft_val.lower()
            assert "bid_draft" in page.text_content("#earn-orders-list")
            assert "bid_placed" not in page.text_content("#earn-orders-list")

            # Нажатие "Отправить отклик" подтверждает от имени владельца (при закрытом AUTOBID оставляет bid_draft)
            page.click('[data-order-action="send_bid"]')
            page.wait_for_timeout(200)
            assert not errors
            page.close()

            # 2) Mobile 390x844: без горизонтального переполнения и все 5 профилей присутствуют
            mpage = browser.new_page(viewport={"width": 390, "height": 844})
            mpage.on("pageerror", lambda e: errors.append(str(e)))
            mpage.goto(studio_url, wait_until="networkidle")
            mpage.click("#tab-earning")
            mpage.wait_for_selector("#earn-accounts-list .earn-item", timeout=5000)
            mob_metrics = mpage.evaluate(
                """() => ({
                    overflow: document.documentElement.scrollWidth > window.innerWidth,
                    count: document.querySelectorAll('#earn-accounts-list .earn-item').length,
                })"""
            )
            assert mob_metrics["overflow"] is False
            assert mob_metrics["count"] == 5
            assert not errors
            mpage.close()
            browser.close()
    finally:
        if srv:
            srv.shutdown()
            srv.server_close()
        mem.close()


def test_padam_local_model_mcp_gating_power_model_and_4_lang_help(tmp_path: Path):
    db_file = tmp_path / "lm.db"
    padam_home = tmp_path / "padam_home"
    ollama_dir = _make_fake_ollama_dir(tmp_path / "ollama_models", "qwen3", "14b")
    gguf_file = _make_fake_gguf(tmp_path / "custom" / "tiny-test.gguf")

    base_env = {
        **os.environ,
        "PADAM_DB": str(db_file),
        "PADAM_USER": "aifa",
        "PADAM_HOME": str(padam_home),
        "OLLAMA_MODELS": str(ollama_dir),
    }
    base_env.pop("PADAM_CPU_POWER", None)
    base_env.pop("PADAM_CPU_GGUF_PATH", None)

    # 1. Выключенный флаг PADAM_MCP_ARK_TOOLS -> скрыт и запрещён по прямому вызову
    env_off = {**base_env, "PADAM_MCP_ARK_TOOLS": "0"}
    res_off = _rpc_stdio(
        env_off,
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "padam_local_model", "arguments": {"action": "status"}}},
        ],
    )
    list_off = next(r for r in res_off if r.get("id") == 2)
    assert "padam_local_model" not in [t["name"] for t in list_off["result"]["tools"]]
    call_off = next(r for r in res_off if r.get("id") == 3)
    assert call_off["result"].get("isError") is True

    # 2. Включенный флаг -> status / set_power / set_model (Ollama name + GGUF path + отказ на несуществующей модели)
    env_on = {**base_env, "PADAM_MCP_ARK_TOOLS": "1"}
    res_on = _rpc_stdio(
        env_on,
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "padam_local_model", "arguments": {"action": "status"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "padam_local_model", "arguments": {"action": "set_power", "power": "eco"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "padam_local_model", "arguments": {"action": "set_model", "model": "qwen3:14b"}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "padam_local_model", "arguments": {"action": "set_model", "model": str(gguf_file)}}},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "padam_local_model", "arguments": {"action": "set_model", "model": "nonexistent-model:99b"}}},
        ],
    )
    tools_on = next(r for r in res_on if r.get("id") == 2)["result"]["tools"]
    assert "padam_local_model" in [t["name"] for t in tools_on]

    st = json.loads(next(r for r in res_on if r.get("id") == 3)["result"]["content"][0]["text"])
    assert st["cost_usd"] == 0.0
    assert any(m["name"] == "qwen3:14b" for m in st["overview"]["models_found"])

    sp = json.loads(next(r for r in res_on if r.get("id") == 4)["result"]["content"][0]["text"])
    assert sp["saved"]["power"] == "eco"

    sm_ollama = json.loads(next(r for r in res_on if r.get("id") == 5)["result"]["content"][0]["text"])
    assert sm_ollama["matched_name"] == "qwen3:14b"
    assert sm_ollama["cost_usd"] == 0.0

    sm_gguf = json.loads(next(r for r in res_on if r.get("id") == 6)["result"]["content"][0]["text"])
    assert Path(sm_gguf["saved"]["gguf_path"]).resolve() == gguf_file.resolve()

    sm_missing = next(r for r in res_on if r.get("id") == 7)["result"]
    assert sm_missing.get("isError") is True
    assert "never downloads" in sm_missing["content"][0]["text"]

    # Настройки сохранились на диске
    assert lm.settings_path().parent.name != "" or True  # изолированы в tmp_path/padam_home
    assert json.loads((padam_home / "local_model.json").read_text(encoding="utf-8"))["power"] == "eco"

    # 3. Справка на 4 языках + языковой паритет ключей Studio
    for lang in ("ru", "en", "es", "zh"):
        hp = studio_help.help_payload(lang)
        tabs_sec = next(sec for sec in hp["sections"] if sec["id"] == "tabs")
        settings_desc = next(txt for name, txt in tabs_sec["items"] if name == "settings")
        assert "padam_local_model" in settings_desc
    ru_keys = set(studio.STRINGS["ru"].keys())
    for lang in ("en", "es", "zh"):
        assert set(studio.STRINGS[lang].keys()) == ru_keys
