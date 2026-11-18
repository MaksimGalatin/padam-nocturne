# -*- coding: utf-8 -*-
"""Локальная модель (18.11.2026): по умолчанию половина мощности, выбор в один клик, файл переживает перезапуск."""
import json
import threading
import urllib.request

import pytest

from padam import api, cpu_engine, local_model
from padam._httpserver import ThreadingHTTPServer
from padam.memory import Memory


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("PADAM_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("PADAM_CPU_POWER", raising=False)
    monkeypatch.delenv("PADAM_CPU_GGUF_PATH", raising=False)
    monkeypatch.delenv("PADAM_CPU_GGUF_THREADS", raising=False)


def test_по_умолчанию_половина():
    assert local_model.load()["power"] == "half"
    assert {p: local_model.threads_for(28, p) for p in local_model.POWER_MODES} == {"eco": 7, "half": 14, "full": 27}
    assert local_model.capped_threads(64, 28, "half") == 27  # вручную не выше «все ядра минус одно»
    r = cpu_engine.recommend_quantized_profile(ram_gb=64, cpu_cores=28)
    assert r["power_mode"] == "half" and r["threads_recommended"] == 14
    assert r["tier"] == "pro_16gb_24gb" and r["full_power_tier"] == "server_32gb_plus"


def test_эко_и_полная(monkeypatch):
    monkeypatch.setenv("PADAM_CPU_POWER", "eco")
    assert cpu_engine.recommend_quantized_profile(ram_gb=64, cpu_cores=28)["tier"] == "workstation_8gb_12gb"
    monkeypatch.setenv("PADAM_CPU_POWER", "full")
    assert cpu_engine.recommend_quantized_profile(ram_gb=64, cpu_cores=28)["threads_recommended"] == 27


def test_сохранение_и_проверка_файла(tmp_path):
    fake = tmp_path / "m.gguf"
    fake.write_bytes(b"GGUF" + b"\0" * 32)
    bad = tmp_path / "x.gguf"
    bad.write_bytes(b"NOPE")
    saved = local_model.save(power="eco", gguf_path=str(fake))
    assert saved["power"] == "eco" and saved["gguf_path"] == str(fake.resolve())
    assert local_model.load()["power"] == "eco"  # пережило «перезапуск» — читается из файла
    with pytest.raises(ValueError, match="GGUF"):
        local_model.save(gguf_path=str(bad))
    with pytest.raises(ValueError, match="power"):
        local_model.save(power="turbo")
    with pytest.raises(ValueError, match="absolute"):
        local_model.save(gguf_path="relative.gguf")


def test_поиск_моделей_ollama(tmp_path):
    root = tmp_path / "ollama"
    (root / "manifests/registry.ollama.ai/library/qwen3").mkdir(parents=True)
    (root / "manifests/registry.ollama.ai/library/gpt-oss").mkdir(parents=True)
    (root / "blobs").mkdir()
    (root / "blobs/sha256-abc").write_bytes(b"GGUF" + b"\0" * 64)
    (root / "manifests/registry.ollama.ai/library/qwen3/4b").write_text(json.dumps(
        {"layers": [{"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:abc", "size": 68}]}), encoding="utf-8")
    (root / "manifests/registry.ollama.ai/library/gpt-oss/120b-cloud").write_text(json.dumps({"layers": []}), encoding="utf-8")
    found = local_model.list_ollama_models(root)
    assert [m["name"] for m in found] == ["qwen3:4b"] and found[0]["kind"] == "chat"


def test_api_только_с_этого_компьютера(tmp_path):
    m = Memory(str(tmp_path / "m.db"))
    prev = dict(api._state)
    api._state.update({"memory": m, "token": "tok-lm", "local": True})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v2/local-model", headers={"Authorization": "Bearer tok-lm"})
        with urllib.request.urlopen(req, timeout=10) as r:
            view = json.loads(r.read().decode())
        assert view["power"] == "half" and view["cost_usd"] == 0.0 and {x["id"] for x in view["power_modes"]} == {"eco", "half", "full"}
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v2/local-model", data=json.dumps({"power": "eco"}).encode(),
                                     headers={"Authorization": "Bearer tok-lm", "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            assert json.loads(r.read().decode())["power"] == "eco"
    finally:
        srv.shutdown(); srv.server_close()
        api._state.clear(); api._state.update(prev)
