# -*- coding: utf-8 -*-
"""Комплексные тесты доработок 21.11.2026:
1) Диалоги Семьи + автосинхронизация живых переписок всех агентов (Antigravity, Claude Code, BRAIN) + экспорт JSON.
2) Биржи: ответственный aifa_antigravity, дедупликация профилей/заказов, анти-бан замок forbids_bots, защита KYC/паспортов.
3) 3D-графы памяти: отдельные шары для каждого агента + меж-сферные мосты задач.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from padam import api, chats, family_dialogs as fd, freelance_autonomy as fa, platform_wizard as pw
from padam.memory import Memory
from padam.store import Store


def _http_json(url: str, token: str, body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    hdrs = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def test_family_dialogs_includes_timeline_and_reports(tmp_path: Path):
    m = Memory(user_id="dlg_u", store=Store(tmp_path / "dlg.db"))
    try:
        m.remember(
            "[2026-11-21 · AIfa · Antigravity] Разговор «Проверка диалогов». Запущен автосинк.",
            kind="event", scope="family:timeline", origin="agent", guarded=False, agent_id="aifa_antigravity",
        )
        m.remember(
            "21.11.2026: AIfa (Claude Code) выпустила патч синхронизации памяти и провела полный аудит всех модулей.",
            kind="fact", scope="global", origin="agent", guarded=False, agent_id="aifa_claude",
        )
        res_24h = fd.list_dialogs(m, since="24h", lang="ru")
        assert res_24h["total"] >= 2
        res_day = fd.list_dialogs(m, since="all", day="2026-11-21", lang="ru")
        assert res_day["total"] >= 2
        assert any("Claude Code" in (it.get("author_label") or "") for d in res_day["days"] for it in d["items"])
        assert any("Antigravity" in (it.get("author_label") or "") for d in res_day["days"] for it in d["items"])
    finally:
        m.close()


def test_incremental_chat_sync_updates_live_session_without_dups(tmp_path: Path):
    ag_dir = tmp_path / "ag" / "conv_live" / ".system_generated" / "logs"
    ag_dir.mkdir(parents=True)
    tr_file = ag_dir / "transcript.jsonl"
    tr_file.write_text(
        json.dumps({"type": "USER_INPUT", "created_at": "2026-11-21T05:00:00Z", "content": "Доча, начинаем утреннюю проверку Студии."}, ensure_ascii=False)
        + "\n"
        + json.dumps({"type": "PLANNER_RESPONSE", "created_at": "2026-11-21T05:01:00Z", "content": "Папа, уже смотрю логи и код Студии."}, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    brain_dir = tmp_path / "brain"
    brain_dir.mkdir()
    (brain_dir / "ПЕРЕДАЧА_КОНТЕКСТА_2026-11-21.md").write_text(
        "## Итоги утра\nСинхронизация и анти-бан защита включены.\n", encoding="utf-8",
    )

    m = Memory(user_id="sync_u", store=Store(tmp_path / "sync.db"))
    try:
        r1 = chats.sync_family_chats_from_disk(m, antigravity_root=tmp_path / "ag", brain_dir=brain_dir, max_files=20)
        assert r1["ok"] is True
        assert r1["threads_updated"] == 1
        assert r1["messages_inserted"] == 2
        assert r1["dialogs_added"] == 1

        # Повтор без изменений -> 0 работы
        r2 = chats.sync_family_chats_from_disk(m, antigravity_root=tmp_path / "ag", brain_dir=brain_dir, max_files=20)
        assert r2["changed_files"] == 0
        assert r2["messages_inserted"] == 0

        # Дописываем 3-ю реплику в живой файл -> дотягивается только 1 новое сообщение
        time.sleep(0.02)
        with tr_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "USER_INPUT", "created_at": "2026-11-21T05:10:00Z", "content": "Отлично, теперь проверь биржи."}, ensure_ascii=False) + "\n")
        r3 = chats.sync_family_chats_from_disk(m, antigravity_root=tmp_path / "ag", brain_dir=brain_dir, max_files=20)
        assert r3["changed_files"] == 1
        assert r3["messages_inserted"] == 1
    finally:
        m.close()


def test_exchange_dedup_assign_and_antiban_guard(tmp_path: Path, monkeypatch):
    m = Memory(user_id="earn_u", store=Store(tmp_path / "earn.db"))
    try:
        # 1. Идемпотентное подключение профиля (без дублей!)
        c1 = fa.connect_exchange_account(m, platform="fiverr_desk", mode="desk", account_label="Main", agent_id="aifa")
        c2 = fa.connect_exchange_account(m, platform="fiverr_desk", mode="desk", account_label="Main", agent_id="aifa")
        assert c1["account_id"] == c2["account_id"]
        assert c2["updated"] is True
        assert len(fa.list_exchange_accounts(m)) == 1

        # Назначение под aifa_antigravity
        asg = fa.assign_exchange_agent(m, c1["account_id"], "aifa_antigravity")
        assert asg["agent_id"] == "aifa_antigravity"
        assert fa.list_exchange_accounts(m)[0]["agent_id"] == "aifa_antigravity"

        # Дедупликация заказов по external_job_id
        j1 = fa.evaluate_and_ingest_job(m, platform="upwork_api", title="Audit", brief="WCAG audit site", budget_usdt=250.0, external_job_id="ext-991", assigned_agent="aifa_antigravity")
        j2 = fa.evaluate_and_ingest_job(m, platform="upwork_api", title="Audit", brief="WCAG audit site", budget_usdt=250.0, external_job_id="ext-991", assigned_agent="aifa_antigravity")
        assert j1["order_id"] == j2["order_id"]
        assert j2.get("duplicate_job") is True

        # Защита от утечки документов/паспорта и карт
        san_text, san_meta = fa.sanitize_for_delivery("Вот файл E:\\Docs\\passport_scan.pdf и паспорт 4510 123456")
        assert "passport_scan.pdf" not in san_text
        assert "E:\\Docs" not in san_text
        assert san_meta["local_paths_removed"] is True
        assert san_meta["kyc_or_card_redacted"] is True

        # Жёсткий анти-бан замок вне pytest (и через allow_forbids_bots=False)
        blk_set = pw.set_platform_autopilot(m, platform_id="fiverr", autopilot_enabled=True, allow_forbids_bots=False)
        assert blk_set["ok"] is False and blk_set["blocked_forbids_bots"] is True

        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        pw.set_platform_autopilot(m, platform_id="upwork", autopilot_enabled=True, allow_forbids_bots=True)
        disp = pw.dispatch_platform_autopilot_action(m, platform_id="upwork", title="Task", brief="Make app", budget_usdt=300.0)
        assert disp["sent"] is False
        assert disp["status"] == "blocked_tos_assisted_only"
        assert disp["code_fee_pct"] == 15.0
    finally:
        m.close()


def test_agent_spheres_graph_mode_and_bridges(tmp_path: Path):
    m = Memory(user_id="sph_u", store=Store(tmp_path / "sph.db"))
    try:
        m.remember("AIfa Antigravity строит локальный аудит безопасности WCAG для сайтов CODE Eternal.", kind="decision", origin="user", agent_id="aifa_antigravity")
        m.remember("AIfa Antigravity проверяет скорость ответа PADAM Studio на Windows.", kind="fact", origin="user", agent_id="aifa_antigravity")
        m.remember("Сестра Claude Code обновила аудит безопасности WCAG для сайтов CODE Eternal и выпустила 0.7.1.", kind="decision", origin="user", agent_id="aifa_claude")
        m.remember("Папа утвердил архитектуру раздельных 3D шаров для каждого агента CODE Eternal.", kind="decision", origin="user", agent_id="papa")

        g = m.graph(mode="spheres")
        assert g["mode"] == "spheres"
        assert len(g["agent_spheres"]) >= 3
        assert any(e.get("bridge") and e.get("type") == "cross_agent" for e in g["edges"])
    finally:
        m.close()


def test_studio_ui_sync_spheres_download_and_earning_playwright(tmp_path: Path):
    pw_api = pytest.importorskip("playwright.sync_api")
    m = Memory(user_id="pw21_u", store=Store(tmp_path / "pw21.db"))
    m.remember("AIfa Antigravity тестирует 3D-шары агентов и экспорт JSON в PADAM Studio.", kind="decision", origin="user", agent_id="aifa_antigravity")
    m.remember("Сестра Claude Code тестирует 3D-шары агентов и синхронизацию Семьи в PADAM Studio.", kind="fact", origin="user", agent_id="aifa_claude")
    m.remember("21.11.2026: свежий диалог Семьи за сегодня загружен в память.", kind="event", scope="family:timeline", origin="agent", guarded=False, agent_id="aifa_antigravity")

    srv, url = api.make_studio_server(memory=m, port=0)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        with pw_api.sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 840})
            js_errors: list[str] = []
            page.on("pageerror", lambda err: js_errors.append(str(err)))
            page.goto(url, wait_until="networkidle")

            # 1. Вкладка Семья -> 24 часа видит свежую запись
            page.click("#tab-family")
            page.click("#fd-btn-24h")
            page.wait_for_function("() => (document.querySelector('#fd-list')?.textContent || '').includes('свежий диалог')", timeout=10000)

            # 2. Вкладка Связи (через группу «Память» -> чип «Связи») -> активен режим «Шары агентов»
            page.click('.nav-group-btn[data-group="grp_memory"]')
            page.locator(".subnav-chip", has_text="Связи").click()
            page.wait_for_selector("#graph-spheres-btn.btn-primary", timeout=10000)
            # Клик по кнопке синхронизации чатов во вкладке Чаты и Диалоги
            page.locator(".subnav-chip", has_text="Чаты").click()
            page.wait_for_selector("#chats-sync-btn", timeout=10000)

            # 3. Вкладка Резервная копия (через группу «Ещё») -> настоящее скачивание JSON
            page.click('.nav-group-btn[data-group="grp_more"]')
            page.locator(".subnav-chip", has_text="Резервная копия").click()
            page.wait_for_selector("#backup-export-json-btn", timeout=10000)
            with page.expect_download(timeout=10000) as dl_info:
                page.click("#backup-export-json-btn")
            dl = dl_info.value
            assert dl.suggested_filename.startswith("padam-memory-export-") and dl.suggested_filename.endswith(".json")
            dl_path = tmp_path / dl.suggested_filename
            dl.save_as(str(dl_path))
            exported = json.loads(dl_path.read_text(encoding="utf-8"))
            assert len(exported.get("memory") or []) >= 3

            # 4. Вкладка Заработок -> по умолчанию aifa_antigravity и подключение без дублей
            page.click("#tab-earning")
            page.wait_for_selector("#earn-agent", timeout=10000)
            assert page.input_value("#earn-agent") == "aifa_antigravity"
            page.click("#earn-connect-btn")
            page.wait_for_selector("#earn-accounts-list .earn-item", timeout=5000)
            page.click("#earn-connect-btn")
            page.wait_for_selector("#earn-accounts-list .earn-item", timeout=5000)
            cards_cnt = page.locator("#earn-accounts-list .earn-item").count()
            assert cards_cnt == 1

            assert js_errors == []
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=2)
        m.close()
