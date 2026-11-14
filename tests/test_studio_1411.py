from pathlib import Path
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


def _http_json(url: str, token: str | None = None, body: dict | None = None, extra_headers: dict[str, str] | None = None) -> tuple[int, dict, dict]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
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


def test_settings_get_and_safe_toggle(tmp_path):
    """GET /settings возвращает 200 со всеми переключателями, а POST /settings меняет безопасные режимы."""
    mem = Memory(user_id="set_user", store=Store(tmp_path / "set.db"))
    srv, link = api.make_studio_server(mem, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        m = re.match(r"^(http://127\.0\.0\.1:\d+)/studio#t=(.+)$", link)
        assert m
        base, token = m.group(1), m.group(2)

        code, _, st_get = _http_json(f"{base}/settings", token=token)
        assert code == 200
        assert st_get["profile"] in ("default", "ops", "creative")
        assert "strict" in st_get and "hold_external" in st_get

        code, _, st_post = _http_json(f"{base}/settings", token=token, body={"profile": "ops"})
        assert code == 200 and st_post["profile"] == "ops"
        _http_json(f"{base}/settings", token=token, body={"profile": "default"})
    finally:
        srv.shutdown()
        srv.server_close()
        mem.close()


def test_russian_ui_has_no_3_english_words_chain_and_section9_fixes():
    """Раздел 9.6: в русском интерфейсе нет строк из 3+ английских слов подряд вне кода и id."""
    ru = studio.STRINGS["ru"]
    # Разрешённые собственные названия продуктов в заголовке/шагах подключения
    allowed_names = (
        "PADAM · NOCTURNE Studio",
        "PADAM NOCTURNE",
        "CODE Eternal",
        "Claude Code",
        "VS Code",
        "SQLite backup API",
        "padam remember",
        "padam recall",
        "padam forget",
        "padam l3",
        "padam demo",
        "padam review",
        "padam protect-keys",
    )
    three_eng_words = re.compile(r"\b[A-Za-z]{2,}\s+[A-Za-z]{2,}\s+[A-Za-z]{2,}\b")
    offenders = []
    for key, val in ru.items():
        cleaned = val
        for name in allowed_names:
            cleaned = cleaned.replace(name, "")
        # Убираем CLI-команды после двоеточия
        cleaned = re.sub(r"padam\s+[^\n]+$", "", cleaned)
        m = three_eng_words.search(cleaned)
        if m:
            offenders.append((key, val, m.group(0)))
    assert not offenders, f"Найдены 3+ английских слова подряд в русском UI: {offenders}"

    # Проверим также новые ключи раздела 9 во всех 4 языках
    for lang in ("ru", "en", "es", "zh"):
        s = studio.STRINGS[lang]
        for k in ("time_local", "ov_conflict_two", "ov_btn_compare", "origin_external", "status_quarantined"):
            assert k in s and s[k].strip(), (lang, k)


def test_desktop_mode_and_tauri_security_section10(tmp_path):
    """Раздел 10 (А2): настольный режим работает без .exe-дроппера, без зашитых путей и без --token в argv."""
    from padam import desktop

    # 1. Создание ярлыка запуска без записи .exe в AppData
    shortcut_dir = tmp_path / "shortcuts"
    shortcut = desktop.create_launcher_shortcut(shortcut_dir)
    assert shortcut.exists()
    content = shortcut.read_text(encoding="utf-8")
    assert "padam" in content
    assert "FromBase64String" not in content

    # 2. Самопроверка настольного центра памяти в одном процессе
    db_path = tmp_path / "desk.db"
    mem = Memory(user_id="desk_user", store=Store(db_path))
    mem.remember("Проверка настольного центра памяти PADAM Studio", kind="fact")
    try:
        rc = desktop.run_desktop_gui(mem, port=0, self_test=True)
        assert rc == 0
    finally:
        mem.close()

    # 3. В исходниках desktop/ и padam/desktop.py нет зашитых путей E:\CODE, версий Edge и --token в спауне
    root = Path(__file__).resolve().parents[1]
    desk_py = (root / "padam" / "desktop.py").read_text(encoding="utf-8")
    tauri_rs = (root / "desktop" / "tauri" / "src" / "main.rs").read_text(encoding="utf-8")
    for src in (desk_py, tauri_rs):
        assert "E:\\CODE" not in src and "E:/CODE" not in src
        assert "157.0.4341.42" not in src
        assert 'args(["--token"' not in src and '"--token"' not in src


def test_chromium_extension_manifest_v3_and_external_quarantine():
    """А3: расширение Chrome/Edge Manifest V3 имеет строгий CSP, 0 innerHTML и отправляет записи с origin=external."""
    root = Path(__file__).resolve().parents[1]
    ext_dir = root / "extensions" / "chromium"
    manifest = json.loads((ext_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["manifest_version"] == 3
    assert "contextMenus" in manifest["permissions"]
    csp = manifest["content_security_policy"]["extension_pages"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp

    bg_js = (ext_dir / "background.js").read_text(encoding="utf-8")
    popup_js = (ext_dir / "popup.js").read_text(encoding="utf-8")
    popup_html = (ext_dir / "popup.html").read_text(encoding="utf-8")
    assert "origin: 'external'" in bg_js
    assert "origin: 'external'" in popup_js
    assert "innerHTML" not in bg_js and "innerHTML" not in popup_js
    assert 'style="' not in popup_html
    for sz in (16, 48, 128):
        assert (ext_dir / "icons" / f"icon{sz}.png").exists()


def test_chrome_extension_origin_forces_external_and_review_queue(tmp_path):
    """Раздел 11 (А3): запрос с Origin: chrome-extension://<32 буквы>, валидным токеном и origin='user'
    принудительно получает origin='external' на сервере и удерживается в очереди проверки."""
    db_path = tmp_path / "ext_origin.db"
    mem = Memory(user_id="ext_test_user", store=Store(db_path))
    srv, url = api.make_studio_server(mem, port=0)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        m = re.match(r"^(http://127\.0\.0\.1:\d+)/studio#t=(.+)$", url)
        assert m
        base, token = m.group(1), m.group(2)
        ext_origin = "chrome-extension://" + ("a" * 32)

        code, _, res = _http_json(
            f"{base}/write",
            token=token,
            body={"content": "Запись из расширения с подменённым origin=user", "origin": "user", "kind": "fact"},
            extra_headers={"Origin": ext_origin},
        )
        assert code == 200
        assert res["outcome"] == "quarantined"
        rec_id = res["id"]

        # В активной памяти записи нет — она удерживается в очереди проверки (review) с origin='external'
        _, _, active = _http_json(f"{base}/records?view=active", token=token)
        assert all(r["id"] != rec_id for r in active["records"])

        _, _, review = _http_json(f"{base}/records?view=review", token=token)
        matched = [r for r in review["records"] if r["id"] == rec_id]
        assert len(matched) == 1
        assert matched[0]["origin"] == "external"
        assert matched[0]["status"] == "quarantined"
    finally:
        srv.shutdown()
        srv.server_close()
        mem.close()



def test_b20_export_markdown_active_only_and_obsidian_links(tmp_path):
    """Б20: экспорт в папку Markdown / Obsidian выгружает ТОЛЬКО действующие записи (active) с YAML и [[ссылками]]."""
    db_path = tmp_path / "md_export.db"
    mem = Memory(user_id="md_user", store=Store(db_path))
    try:
        # 1. Активные записи + связь derived
        _, id_src = mem.remember("Основной сервер работает на порту 8077.", kind="fact", importance=0.8)
        _, id_dst = mem.remember("Для подключения к серверу укажите порт 8077.", kind="decision", importance=0.7)
        mem._связать([id_src], id_dst)

        # 2. Запись, которая будет заменена (superseded)
        _, id_old = mem.remember("Секрет старой версии: OLD_SUPERSEDED_MARKER", kind="fact")
        mem.store.execute("UPDATE memory SET status = 'superseded' WHERE id = ?", (id_old,))

        # 3. Удержанная запись (quarantined)
        _, id_held = mem.remember("Внешняя непроверенная запись: QUARANTINED_MARKER", kind="fact",
                                  origin="external", guarded=True)

        # 4. Отклонённая запись (rejected)
        _, id_rej = mem.remember("Отклонённая запись агента: REJECTED_MARKER", kind="fact",
                                 origin="external", guarded=True)
        mem.reject(id_rej)

        # 5. Забытая запись (revoked)
        _, id_rev = mem.remember("Удалённая запись: REVOKED_MARKER", kind="fact")
        mem.revoke(id_rev)

        out_dir = tmp_path / "obsidian_vault"
        rep = mem.export_markdown(str(out_dir))
        assert rep["exported"] == 2
        assert (out_dir / "INDEX.md").exists()

        all_md_text = "\n".join(p.read_text(encoding="utf-8") for p in out_dir.rglob("*.md"))
        assert "Основной сервер работает на порту 8077." in all_md_text
        assert "Для подключения к серверу укажите порт 8077." in all_md_text
        # Вики-ссылки Obsidian между источником и выводом
        assert f"|{id_src[:8]}]]" in all_md_text
        assert f"|{id_dst[:8]}]]" in all_md_text
        # Ни одна неактивная запись не попала в экспорт
        for forbidden in ("OLD_SUPERSEDED_MARKER", "QUARANTINED_MARKER", "REJECTED_MARKER", "REVOKED_MARKER"):
            assert forbidden not in all_md_text
    finally:
        mem.close()


def test_b8_import_external_formats_quarantined_and_secrets_masked(tmp_path):
    """Б8: импорт из ChatGPT, Claude, Markdown/Obsidian и mem0 маскирует секреты и ставит origin=external в карантин."""
    db_path = tmp_path / "ext_import.db"
    mem = Memory(user_id="import_user", store=Store(db_path))
    try:
        # 1. Формат ChatGPT conversations.json
        chatgpt_file = tmp_path / "chatgpt_conversations.json"
        chatgpt_file.write_text(json.dumps([
            {
                "title": "Архитектура",
                "mapping": {
                    "node1": {
                        "message": {
                            "author": {"role": "user"},
                            "content": {"parts": ["Используем SQLite в режиме WAL и токен sk-1234567890abcdefghijklmnop."]},
                        }
                    },
                    "node2": {
                        "message": {
                            "author": {"role": "assistant"},
                            "content": {"parts": ["Ответ ассистента не должен импортироваться как слова человека."]},
                        }
                    },
                },
            }
        ], ensure_ascii=False), encoding="utf-8")
        r1 = mem.import_external(chatgpt_file, fmt="auto")
        assert r1["format"] == "chatgpt"
        assert r1["imported"] == 1
        assert r1["outcomes"].get("quarantined") == 1

        # 2. Формат Claude conversations.json
        claude_file = tmp_path / "claude_conversations.json"
        claude_file.write_text(json.dumps([
            {
                "name": "Дизайн Studio",
                "chat_messages": [
                    {"sender": "human", "text": "Предпочитаю тёмную тему по умолчанию."},
                    {"sender": "assistant", "text": "Принято."},
                ],
            }
        ], ensure_ascii=False), encoding="utf-8")
        r2 = mem.import_external(claude_file, fmt="auto")
        assert r2["format"] == "claude"
        assert r2["imported"] == 1
        assert r2["outcomes"].get("quarantined") == 1

        # 3. Формат папки Markdown / Obsidian
        md_dir = tmp_path / "notes"
        (md_dir / "preference").mkdir(parents=True)
        (md_dir / "preference" / "note1.md").write_text(
            "---\nkind: preference\nimportance: 0.9\n---\n\nВсегда отвечать по-русски.\n",
            encoding="utf-8",
        )
        r3 = mem.import_external(md_dir, fmt="auto")
        assert r3["format"] == "markdown"
        assert r3["imported"] == 1
        assert r3["outcomes"].get("quarantined") == 1

        # 4. Формат mem0 JSON
        mem0_file = tmp_path / "mem0_export.json"
        mem0_file.write_text(json.dumps({
            "memories": [
                {"memory": "Любимый редактор кода — VS Code и Cursor.", "metadata": {"kind": "preference"}}
            ]
        }, ensure_ascii=False), encoding="utf-8")
        r4 = mem.import_external(mem0_file, fmt="auto")
        assert r4["format"] == "mem0"
        assert r4["imported"] == 1
        assert r4["outcomes"].get("quarantined") == 1

        # Все 4 импортированные записи находятся на проверке (quarantined), с origin='external', а секрет замаскирован
        assert mem.stats()["active"] == 0
        held = mem.quarantined()
        assert len(held) == 4
        for h in held:
            assert h["origin"] == "external"
            assert "sk-1234567890abcdefghijklmnop" not in h["content"]
        assert any("[REDACTED:" in h["content"] for h in held)
    finally:
        mem.close()


def test_b4_mask_pii_toggle_emails_and_phones(tmp_path):
    """Б4: при выключенном PADAM_MASK_PII контакты владельца не портятся, а при включённом маскируются почта и телефон."""
    from padam import config as pcfg, safety

    orig = pcfg.MASK_PII
    try:
        pcfg.MASK_PII = False
        sample = "Связаться со мной можно по почте architect@codeeternal.org или телефону +1 (415) 555-2671."
        out_off, counts_off = safety.redact(sample)
        assert "architect@codeeternal.org" in out_off
        assert "555-2671" in out_off
        assert "[REDACTED:email]" not in out_off
        assert "[REDACTED:phone]" not in out_off
        assert counts_off == {}

        pcfg.MASK_PII = True
        out_on, counts_on = safety.redact(sample)
        assert "architect@codeeternal.org" not in out_on
        assert "555-2671" not in out_on
        assert "[REDACTED:email]" in out_on
        assert "[REDACTED:phone]" in out_on
        assert counts_on.get("email") == 1 and counts_on.get("phone") == 1

        # Проверим переключение через /settings в Studio
        mem = Memory(user_id="pii_user", store=Store(tmp_path / "pii.db"))
        srv, link = api.make_studio_server(mem, port=0)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            m = re.match(r"^(http://127\.0\.0\.1:\d+)/studio#t=(.+)$", link)
            assert m
            base, token = m.group(1), m.group(2)
            code, _, st = _http_json(f"{base}/settings", token=token, body={"mask_pii": True})
            assert code == 200 and st["mask_pii"] is True
            code, _, st2 = _http_json(f"{base}/settings", token=token, body={"mask_pii": False})
            assert code == 200 and st2["mask_pii"] is False
        finally:
            srv.shutdown()
            srv.server_close()
            mem.close()
    finally:
        pcfg.MASK_PII = orig


def test_b9_profile_returns_only_owner_signed_identity_and_preferences(tmp_path):
    """Б9: `Memory.profile()` и `GET /profile` возвращают только подписанные владельцем записи identity и preference."""
    db_path = tmp_path / "prof.db"
    mem = Memory(user_id="prof_user", store=Store(db_path))
    try:
        mem.remember("Я — главный архитектор проекта.", kind="identity", origin="user", importance=0.95)
        mem.remember("Отвечать всегда кратко и по-русски.", kind="preference", origin="user", importance=0.9)
        mem.remember("Обычный рабочий факт о сервере.", kind="fact", origin="user")

        # Добавим запись и сотрём у неё owner_sig напрямую в SQLite (имитация записи в обход ключа владельца)
        _, forged_id = mem.remember("FORGED_UNSIGNED_IDENTITY_MARKER", kind="identity", origin="user")
        mem.store.execute("UPDATE memory SET owner_sig = NULL WHERE id = ?", (forged_id,))

        prof = mem.profile()
        assert len(prof["identity"]) == 1
        assert len(prof["preferences"]) == 1
        assert prof["unsigned_skipped"] == 1
        assert "FORGED_UNSIGNED_IDENTITY_MARKER" not in prof["summary"]
        assert "главный архитектор" in prof["summary"]
        assert "по-русски" in prof["summary"]

        # Проверим маршрут GET /profile
        srv, link = api.make_studio_server(mem, port=0)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            m = re.match(r"^(http://127\.0\.0\.1:\d+)/studio#t=(.+)$", link)
            assert m
            base, token = m.group(1), m.group(2)
            code, _, http_prof = _http_json(f"{base}/profile", token=token)
            assert code == 200
            assert http_prof["unsigned_skipped"] == 1
            assert "FORGED_UNSIGNED_IDENTITY_MARKER" not in http_prof["summary"]
        finally:
            srv.shutdown()
            srv.server_close()
    finally:
        mem.close()


def test_b11_agent_id_header_and_filtering(tmp_path):
    """Б11: заголовок X-Agent-ID и поле agent_id сохраняются в записи и позволяют фильтровать выдачу."""
    db_path = tmp_path / "agents.db"
    mem = Memory(user_id="ag_user", store=Store(db_path))
    srv, link = api.make_studio_server(mem, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        m = re.match(r"^(http://127\.0\.0\.1:\d+)/studio#t=(.+)$", link)
        assert m
        base, token = m.group(1), m.group(2)

        # Запись от первого агента через заголовок X-Agent-ID
        code, _, r1 = _http_json(
            f"{base}/write",
            token=token,
            body={"content": "Сборка бэкенда выполнена агентом Claude Code", "kind": "fact", "origin": "user"},
            extra_headers={"X-Agent-ID": "claude-code"},
        )
        assert code == 200 and r1["outcome"] == "created"

        # Запись от второго агента через поле agent_id
        code, _, r2 = _http_json(
            f"{base}/write",
            token=token,
            body={"content": "Вёрстка проверена агентом Cursor", "kind": "fact", "origin": "user", "agent_id": "cursor"},
        )
        assert code == 200 and r2["outcome"] == "created"

        # Фильтрация в /records?agent_id=claude-code
        code, _, feed_cc = _http_json(f"{base}/records?view=active&agent_id=claude-code", token=token)
        assert code == 200
        assert feed_cc["total"] == 1
        assert feed_cc["records"][0]["agent_id"] == "claude-code"

        # Фильтрация в /search по agent_id
        code, _, sr_cur = _http_json(
            f"{base}/search",
            token=token,
            body={"query": "проверена агентом", "agent_id": "cursor"},
        )
        assert code == 200
        assert len(sr_cur["results"]) == 1
        assert sr_cur["results"][0]["agent_id"] == "cursor"
    finally:
        srv.shutdown()
        srv.server_close()
        mem.close()


def test_b12_audit_log_records_actions_without_content(tmp_path):
    """Б12: таблица audit_log и маршрут GET /audit фиксируют действия (write, approve, reject, forget), но не хранят текст."""
    db_path = tmp_path / "audit.db"
    mem = Memory(user_id="audit_user", store=Store(db_path))
    try:
        secret_phrase = "SUPER_SENSITIVE_CONTENT_NEVER_IN_AUDIT_LOG_9911"
        _, id_ok = mem.remember(secret_phrase, kind="fact", origin="user", agent_id="claude-code")
        _, id_q1 = mem.remember("Внешняя запись 1: " + secret_phrase, kind="fact", origin="external", guarded=True, agent_id="web-clipper")
        _, id_q2 = mem.remember("Внешняя запись 2: " + secret_phrase, kind="fact", origin="external", guarded=True, agent_id="web-clipper")
        mem.approve(id_q1)
        mem.reject(id_q2)
        mem.revoke(id_ok)

        entries = mem.audit_log(limit=50)
        actions = [e["action"] for e in entries]
        assert "write" in actions
        assert "approve" in actions
        assert "reject" in actions
        assert "forget" in actions

        # Ни в одном поле audit_log нет текста записи
        dump = json.dumps(entries, ensure_ascii=False)
        assert secret_phrase not in dump
        assert any(e["agent_id"] == "claude-code" for e in entries)
        assert any(e["agent_id"] == "web-clipper" for e in entries)

        # Проверим маршрут GET /audit
        srv, link = api.make_studio_server(mem, port=0)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            m = re.match(r"^(http://127\.0\.0\.1:\d+)/studio#t=(.+)$", link)
            assert m
            base, token = m.group(1), m.group(2)
            code, _, http_au = _http_json(f"{base}/audit?limit=20", token=token)
            assert code == 200
            assert len(http_au["entries"]) >= 6
            assert secret_phrase not in json.dumps(http_au, ensure_ascii=False)
        finally:
            srv.shutdown()
            srv.server_close()
    finally:
        mem.close()
