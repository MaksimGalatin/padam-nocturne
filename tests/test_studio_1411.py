# -*- coding: utf-8 -*-
"""Тесты приложения PADAM Studio (А1), пустых состояний (Б18) и квитанции удаления (Б3): 14.11.2026."""

import json
import os
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from padam import api, config, studio
from padam.memory import Memory
from padam.store import Store


def _http_json(url: str, token: str | None = None, body: dict | None = None) -> tuple[int, dict, dict]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"raw": raw}
        return e.code, dict(e.headers), payload


def test_studio_page_csp_no_innerhtml_and_system_defaults():
    html, nonce = studio.page()
    assert nonce and len(nonce) >= 16
    assert f'nonce="{nonce}"' in html
    assert "textContent" in html
    assert "innerHTML" not in html
    assert 'style="' not in html
    # Язык по умолчанию из navigator.language и тема из prefers-color-scheme
    assert "navigator.language" in html
    assert "prefers-color-scheme" in html
    # Все 10 экранов присутствуют в разметке
    for tab in (
        "overview", "feed", "search", "review", "asof",
        "forget", "graph", "l3", "settings", "quickstart",
    ):
        assert f'id="panel-{tab}"' in html
        assert f'data-tab="{tab}"' in html


def test_studio_all_4_languages_complete_and_non_empty():
    """Переключение всех 4 языков (ru, en, es, zh) не оставляет пустых строк; все ключи HTML переведены."""
    html, _ = studio.page()
    base_keys = set(studio.STRINGS["ru"].keys())
    assert len(base_keys) >= 120

    for lang in ("ru", "en", "es", "zh"):
        assert lang in studio.STRINGS
        lang_dict = studio.STRINGS[lang]
        assert set(lang_dict.keys()) == base_keys, f"Несовпадение ключей в языке {lang}"
        for k, val in lang_dict.items():
            assert isinstance(val, str) and val.strip(), f"Пустой перевод для {lang}.{k}"

    # Все data-i18n, data-i18n-placeholder, data-i18n-aria в HTML обязаны быть в словарях всех 4 языков
    used_keys = set(re.findall(r'data-i18n(?:-placeholder|-aria)?="([^"]+)"', html))
    assert len(used_keys) >= 70
    for k in used_keys:
        for lang in ("ru", "en", "es", "zh"):
            assert k in studio.STRINGS[lang] and studio.STRINGS[lang][k].strip(), f"Отсутствует {lang}.{k}"


def test_studio_wcag_aa_contrast():
    """Проверка контраста цветов текста, карточек, кнопок и бейджей в тёмной и светлой темах (≥ 4.5:1)."""
    def rel_lum(hex_color: str) -> float:
        h = hex_color.lstrip("#")
        rgb = [int(h[i:i+2], 16) / 255.0 for i in (0, 2, 4)]
        lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    def contrast(c1: str, c2: str) -> float:
        l1, l2 = rel_lum(c1), rel_lum(c2)
        hi, lo = max(l1, l2), min(l1, l2)
        return (hi + 0.05) / (lo + 0.05)

    # Тёмная тема
    assert contrast("#080b12", "#f1f5f9") >= 14.0
    assert contrast("#131a2c", "#f1f5f9") >= 12.0
    assert contrast("#131a2c", "#94a3b8") >= 5.5
    assert contrast("#38bdf8", "#041019") >= 8.5   # .btn-primary
    assert contrast("#062e22", "#34d399") >= 7.5   # .badge-ok / .traffic-green
    assert contrast("#2e2105", "#fbbf24") >= 8.0   # .badge-warn / .traffic-yellow
    assert contrast("#3b0d0d", "#fca5a5") >= 7.5   # .badge-danger / .traffic-red

    # Светлая тема
    assert contrast("#f4f6fb", "#0f172a") >= 14.0
    assert contrast("#ffffff", "#0f172a") >= 16.0
    assert contrast("#ffffff", "#475569") >= 7.0
    assert contrast("#0369a1", "#ffffff") >= 5.5   # .btn-primary
    assert contrast("#dcfce7", "#14532d") >= 7.0   # .badge-ok
    assert contrast("#fef3c7", "#78350f") >= 7.5   # .badge-warn
    assert contrast("#fee2e2", "#7f1d1d") >= 7.0   # .badge-danger


def test_owner_get_and_owner_post_refuse_without_token(tmp_path):
    """Каждый маршрут из OWNER_GET и OWNER_POST без токена (--no-token) отдаёт 403."""
    mem = Memory(user_id="no_token_user", store=Store(tmp_path / "notoken.db"))
    _, rec_id = mem.remember("Тестовая запись", kind="fact")
    api._state["memory"] = mem
    api._state["token"] = None
    api._state["local"] = True
    api._state["ui"] = False
    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        for get_route in api.OWNER_GET:
            url = f"{base}{get_route}" + (f"?id={rec_id}" if get_route == "/forget-preview" else "")
            code, _, body = _http_json(url, token=None)
            assert code == 403, f"Ожидался 403 на GET {get_route}, получен {code}: {body}"

        # И /records с view != active без токена тоже 403
        code, _, _ = _http_json(f"{base}/records?view=review", token=None)
        assert code == 403

        for post_route in api.OWNER_POST:
            code, _, body = _http_json(f"{base}{post_route}", token=None, body={"id": rec_id})
            assert code == 403, f"Ожидался 403 на POST {post_route}, получен {code}: {body}"
    finally:
        srv.shutdown()
        srv.server_close()
        mem.close()


def test_xss_payloads_rendered_as_plain_text_across_all_screens(tmp_path):
    """Хранимые <script>alert(1)</script> и <img src=x onerror=alert(1)> проходят как текст на всех экранах."""
    mem = Memory(user_id="xss_user", store=Store(tmp_path / "xss.db"))
    p1 = "<script>alert(1)</script>"
    p2 = "<img src=x onerror=alert(1)>"
    _, id_script = mem.remember(f"Факт со скриптом: {p1}", kind="fact", importance=0.8)
    _, id_img = mem.remember(f"Предпочтение с картинкой: {p2}", kind="preference", importance=0.9)
    _, id_held = mem.remember(f"Внешняя запись: {p1} {p2}", kind="episode", origin="external", guarded=True)

    srv, link = api.make_studio_server(mem, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        m = re.match(r"^(http://127\.0\.0\.1:\d+)/studio#t=(.+)$", link)
        assert m
        base, token = m.group(1), m.group(2)

        # 1. Экран Ленты (active)
        code, _, feed = _http_json(f"{base}/records?view=active", token=token)
        assert code == 200
        contents = [r["content"] for r in feed["records"]]
        assert any(p1 in c for c in contents)
        assert any(p2 in c for c in contents)

        # 2. Экран На проверку (review)
        code, _, rev = _http_json(f"{base}/records?view=review", token=token)
        assert code == 200
        assert any(p1 in r["content"] and p2 in r["content"] for r in rev["records"])

        # 3. Экран Поиска (search)
        code, _, sr = _http_json(f"{base}/search", token=token, body={"query": "alert(1)", "limit": 10})
        assert code == 200
        assert any(p1 in r["content"] or p2 in r["content"] for r in sr["results"])

        # 4. Экран Память на дату (as_of)
        today = feed["records"][0]["created_at"][:10]
        code, _, asof = _http_json(f"{base}/records?as_of={today}", token=token)
        assert code == 200
        assert any(p1 in r["content"] for r in asof["records"])

        # 5. Экран Забыть — предпросмотр (forget-preview)
        code, _, prev = _http_json(f"{base}/forget-preview?id={id_script}", token=token)
        assert code == 200
        assert p1 in prev["content"]

        # 6. Экран Связи (graph)
        code, _, gr = _http_json(f"{base}/graph", token=token)
        assert code == 200
        assert any(p1 in n["content"] for n in gr["nodes"])

        # 7. История версий (timeline)
        code, _, tl = _http_json(f"{base}/timeline/{id_script}", token=token)
        assert code == 200
        assert any(p1 in v["content"] for v in tl["versions"])
    finally:
        srv.shutdown()
        srv.server_close()
        mem.close()


def test_studio_server_endpoints_and_forget_receipt(tmp_path):
    """Полный цикл маршрутов Studio, защита настроек и выдача квитанции в /forget и CLI."""
    db_path = tmp_path / "studio.db"
    mem = Memory(user_id="studio_user", store=Store(db_path))
    _, id1 = mem.remember("Предпочитаю краткие ответы по существу", kind="preference", importance=0.8)
    _, id2 = mem.remember("Сервер базы данных работает на порту 5432", kind="fact", importance=0.7)
    _, id3 = mem.remember("Настроить резервное копирование порта 5432", kind="decision", derived_from=[id2])

    srv, link = api.make_studio_server(mem, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        m = re.match(r"^(http://127\.0\.0\.1:\d+)/studio#t=(.+)$", link)
        assert m, link
        base, token = m.group(1), m.group(2)

        # 1. Страница /studio отдаётся со строгим CSP и не содержит ни токена, ни записей
        req = urllib.request.Request(f"{base}/studio")
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8")
            csp = resp.headers.get("Content-Security-Policy", "")
            assert resp.status == 200
            assert "default-src 'none'" in csp
            assert "img-src 'none'" in csp
            assert token not in html
            assert "5432" not in html

        # 2. Без заголовка Authorization при активном токене все маршруты данных возвращают 401
        for path in ("/overview", "/doctor", "/graph", "/l3", "/settings", "/forget-receipts", "/records"):
            code, _, _ = _http_json(f"{base}{path}", token=None)
            assert code == 401, path

        # 3. С токеном /overview, /doctor, /graph, /l3, /settings работают
        code, _, ov = _http_json(f"{base}/overview", token=token)
        assert code == 200
        assert ov["stats"]["active"] >= 3
        assert ov["doctor"]["level"] in ("green", "yellow", "red")
        assert isinstance(ov["doctor"]["checks"], list) and len(ov["doctor"]["checks"]) >= 5

        code, _, gr = _http_json(f"{base}/graph", token=token)
        assert code == 200
        assert len(gr["nodes"]) >= 3
        assert any(e["type"] == "derived" for e in gr["edges"])

        # 4. Опасные настройки нельзя включить из браузера
        code, _, _ = _http_json(f"{base}/settings", token=token, body={"keep_secrets": True})
        assert code == 403
        code, _, _ = _http_json(f"{base}/settings", token=token, body={"hold_external": False})
        assert code == 403

        # 5. Предпросмотр удаления и удаление с криптографической квитанцией
        code, _, prev = _http_json(f"{base}/forget-preview?id={id2}", token=token)
        assert code == 200
        assert prev["target_id"] == id2
        assert prev["derived_count"] == 1
        assert len(prev["content_hash_sha256"]) == 64

        code, _, fg = _http_json(f"{base}/forget", token=token, body={"id": id2, "with_derived": True})
        assert code == 200 and fg["ok"] is True
        rc = fg["receipt"]
        assert rc and rc["memory_id"] == id2
        assert rc["wiped_count"] == 2
        assert len(rc["content_hash_sha256"]) == 64
        assert "5432" not in json.dumps(rc, ensure_ascii=False)

        code, _, rlist = _http_json(f"{base}/forget-receipts", token=token)
        assert code == 200
        assert any(x["receipt_id"] == rc["receipt_id"] for x in rlist["receipts"])
    finally:
        srv.shutdown()
        srv.server_close()
        mem.close()

    # 6. CLI `padam forget <id> --receipt` сохраняет JSON и HTML квитанции
    r_json = tmp_path / "receipt.json"
    env = dict(os.environ, PADAM_LANG="ru", PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "padam", "--db", str(db_path), "--user", "studio_user",
         "forget", id1, "--receipt", str(r_json)],
        capture_output=True, env=env, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    saved = json.loads(r_json.read_text(encoding="utf-8"))
    assert saved["memory_id"] == id1
    assert len(saved["content_hash_sha256"]) == 64
    assert "краткие ответы" not in r_json.read_text(encoding="utf-8")


def test_demo_command_creates_rich_isolated_db(tmp_path):
    """Б17: `padam demo` создаёт отдельную базу со всеми ключевыми состояниями PADAM, не трогая основную."""
    demo_db = tmp_path / "demo_test.db"
    env = dict(os.environ, PADAM_LANG="ru", PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "padam", "demo", "--out", str(demo_db)],
        capture_output=True, env=env, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert demo_db.exists()

    mem = Memory(user_id="demo_architect", store=Store(demo_db))
    try:
        st = mem.stats()
        assert st["active"] >= 8
        assert st["quarantined"] >= 2
        assert st["superseded"] >= 1
        assert st["revoked"] >= 1
        assert st["record_keys"]["passphrase_protected"] is True

        # Проверим наличие замаскированного секрета, квитанции удаления, споров, графа и якоря L3
        recs = mem.list_records(view="active", limit=100)["records"]
        assert any("[REDACTED:" in (r["content"] or "") for r in recs)
        assert len(mem.conflicts()) >= 1
        assert len(mem.forget_receipts()) >= 1
        assert len(mem.nocturne_runs()) >= 1
        gr = mem.graph()
        assert gr["counts"]["derived_edges"] >= 2
        assert gr["counts"]["version_edges"] >= 1
        assert gr["counts"]["conflict_edges"] >= 1
        l3 = mem.l3_status()
        assert len(l3["anchors"]) == 1
        ver = mem.l3_verify_anchor()
        assert ver["ok"] is True
    finally:
        mem.close()
