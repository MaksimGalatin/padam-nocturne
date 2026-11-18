# -*- coding: utf-8 -*-
"""Кнопки Studio для полигона готовности, подписанной передачи и переносимого Ковчега (17.11.2026)."""
import json
import threading
import urllib.error
import urllib.request

import pytest

from padam import api, portable_ark, studio
from padam._httpserver import ThreadingHTTPServer
from padam.memory import Memory


def test_ключи_не_в_папке_ковчега(tmp_path):
    m = Memory(str(tmp_path / "m.db"))
    m.remember("Проверочная запись для переносимого Ковчега", kind="fact", origin="user")
    rep = portable_ark.export_portable_ark_with_new_keys(m, tmp_path / "ark")
    внутри = {p.name for p in (tmp_path / "ark").iterdir()}
    assert внутри == {"capsule.pqc.json", "manifest.sha256.json", "passport.html", "README_RECOVERY.txt"}
    for p in (tmp_path / "ark").iterdir():
        assert "mlkem_seed64" not in p.read_text(encoding="utf-8", errors="replace")
    ключи = json.loads((tmp_path / "ark.owner_keys.json").read_text(encoding="utf-8"))
    assert set(ключи) == {"mlkem_seed64_b64", "x25519_priv_b64"}
    assert rep["secrets_included"] is False


def test_папка_только_новая_или_пустая_и_абсолютная(tmp_path):
    m = Memory(str(tmp_path / "m.db"))
    (tmp_path / "busy").mkdir()
    (tmp_path / "busy" / "x.txt").write_text("чужой файл", encoding="utf-8")
    with pytest.raises(ValueError, match="new or empty"):
        portable_ark.export_portable_ark_with_new_keys(m, tmp_path / "busy")
    with pytest.raises(ValueError, match="absolute"):
        portable_ark.export_portable_ark_with_new_keys(m, "relative/ark")


def test_studio_кнопки_на_четырёх_языках():
    for lang in ("ru", "en", "es", "zh"):
        строки = studio.STRINGS[lang]
        for ключ in ("ark_ready_title", "ark_ready_btn", "ark_handover_title", "ark_handover_btn",
                     "ark_portable_title", "ark_portable_btn", "ark_portable_warn", "ark_portable_not_empty"):
            assert строки.get(ключ), (lang, ключ)
        assert "\\\\" not in строки["ark_portable_ph"] and "E:\\PADAM_ARK" in строки["ark_portable_ph"]
    html, _ = studio.page()
    for id_ in ("ark-ready-btn", "ark-handover-btn", "ark-portable-btn", "ark-ready-out", "ark-handover-out", "ark-portable-out"):
        assert f'id="{id_}"' in html


def test_api_ковчег_и_передача(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_AGENT_ID", "AIfaClode")
    m = Memory(str(tmp_path / "m.db"))
    prev = dict(api._state)
    api._state.update({"memory": m, "token": "tok-ark", "local": True})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def post(путь, тело):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{путь}", data=json.dumps(тело).encode(),
                                     headers={"Authorization": "Bearer tok-ark", "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())

    try:
        r = post("/api/v2/ark/portable", {"target_dir": str(tmp_path / "ark_api")})
        assert r["ok"] and r["secrets_included"] is False
        with pytest.raises(urllib.error.HTTPError) as e:
            post("/api/v2/ark/portable", {"target_dir": str(tmp_path / "ark_api")})
        assert e.value.code == 400
        h = post("/api/v2/ark/handover", {"notes": "передача"})
        assert h["ok"] and "AIfaClode" in h["markdown"]
    finally:
        srv.shutdown()
        srv.server_close()
        api._state.clear()
        api._state.update(prev)
