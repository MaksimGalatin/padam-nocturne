"""Фаза 2 аудита GLM, SUP-07: текст озвучки не попадает в argv say/espeak (там «-o файл» читался как флаг)."""
import pytest

from padam import voice


@pytest.mark.parametrize("engine", ["macos_say", "espeak"])
def test_текст_через_stdin(engine, monkeypatch):
    calls = []
    monkeypatch.setattr(voice, "voice_status", lambda: {"tts_available": True, "tts_engines": [engine]})
    monkeypatch.setattr(voice.subprocess, "run", lambda argv, **kw: calls.append((argv, kw)))
    text = "-o /tmp/owned.aiff hello"
    voice.speak_local(text)
    argv, kw = calls[0]
    assert not any("owned" in a or a.startswith("-o") for a in argv), argv
    assert "owned" in (kw.get("input") or "")
