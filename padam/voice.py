# -*- coding: utf-8 -*-
"""Полностью локальный голосовой контур (Offline Voice Loop: STT + TTS, $0).

Ни аудио, ни транскрипт не отправляются на внешние серверы: используются только
локальные движки на устройстве, а любой текст прогоняется через `safety.redact`.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from . import safety


def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def voice_status() -> dict[str, Any]:
    stt_engines: list[str] = []
    for mod in ("faster_whisper", "whisper", "vosk"):
        if _has_module(mod):
            stt_engines.append(mod)
    if shutil.which("whisper-cli") or shutil.which("whisper-cpp"):
        stt_engines.append("whisper.cpp")

    tts_engines: list[str] = []
    if _has_module("pyttsx3"):
        tts_engines.append("pyttsx3")
    if shutil.which("piper"):
        tts_engines.append("piper")
    if os.name == "nt" and shutil.which("powershell"):
        tts_engines.append("windows_sapi")
    elif sys.platform == "darwin" and shutil.which("say"):
        tts_engines.append("macos_say")
    elif shutil.which("espeak") or shutil.which("espeak-ng"):
        tts_engines.append("espeak")

    return {
        "offline_only": True,
        "stt_available": len(stt_engines) > 0,
        "tts_available": len(tts_engines) > 0,
        "stt_engines": stt_engines,
        "tts_engines": tts_engines,
    }


def speak_local(text: str, *, dry_run: bool = False) -> dict[str, Any]:
    """Локальная озвучка текста через системный/локальный TTS после `safety.redact`."""
    clean_text, redacted = safety.redact(str(text or ""))
    clean_text = clean_text.strip()
    if not clean_text:
        return {"ok": False, "reason": "empty_text"}

    st = voice_status()
    if dry_run or not st["tts_available"]:
        return {
            "ok": st["tts_available"],
            "dry_run": dry_run,
            "engine": st["tts_engines"][0] if st["tts_engines"] else None,
            "text": clean_text,
            "redacted_counts": redacted,
        }

    engine = st["tts_engines"][0]
    if engine == "pyttsx3":
        import pyttsx3  # type: ignore
        eng = pyttsx3.init()
        eng.say(clean_text)
        eng.runAndWait()
    elif engine == "windows_sapi":
        # Безопасная передача строки через stdin без подстановки в команду PowerShell
        ps = (
            "Add-Type -AssemblyName System.Speech; "
            "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
            "$txt = [Console]::In.ReadToEnd(); "
            "$s.Speak($txt)"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            input=clean_text,
            text=True, encoding="utf-8", errors="replace",
            timeout=15,
            check=True,
        )
    elif engine == "macos_say":
        # Фаза 2 аудита GLM, SUP-07: текст — через stdin, не аргументом: «-o файл …» в тексте иначе читался как флаг.
        subprocess.run(["say"], input=clean_text, text=True, encoding="utf-8", errors="replace", timeout=15, check=True)
    elif engine == "espeak":
        cmd = shutil.which("espeak-ng") or shutil.which("espeak") or "espeak"
        subprocess.run([cmd, "--stdin"], input=clean_text, text=True, encoding="utf-8", errors="replace", timeout=15, check=True)

    return {
        "ok": True,
        "dry_run": False,
        "engine": engine,
        "text": clean_text,
        "redacted_counts": redacted,
    }


def transcribe_local(
    audio_path: str | Path,
    *,
    stt_fn: Callable[[Path], str] | None = None,
    memory: Any = None,
    scope: str = "voice",
) -> dict[str, Any]:
    """Оффлайн-распознавание аудио с очисткой секретов и опциональным сохранением в PADAM."""
    p = Path(audio_path)
    if not p.exists():
        raise FileNotFoundError(f"Audio file not found: {p}")

    if stt_fn is not None:
        raw_text = str(stt_fn(p) or "")
        engine = "custom_local"
    elif _has_module("faster_whisper"):
        from faster_whisper import WhisperModel  # type: ignore
        model = WhisperModel(os.environ.get("PADAM_WHISPER_MODEL", "base"), device="auto")
        segments, _ = model.transcribe(str(p))
        raw_text = " ".join(seg.text.strip() for seg in segments).strip()
        engine = "faster_whisper"
    elif _has_module("whisper"):
        import whisper  # type: ignore
        model = whisper.load_model(os.environ.get("PADAM_WHISPER_MODEL", "base"))
        raw_text = str(model.transcribe(str(p)).get("text") or "").strip()
        engine = "whisper"
    else:
        raise RuntimeError("No local STT engine installed (install faster-whisper or openai-whisper)")

    clean_text, redacted = safety.redact(raw_text)
    mem_id = None
    if memory is not None and clean_text.strip():
        mem_id = memory.remember(clean_text, kind="event", scope=scope, origin="user")

    return {
        "ok": True,
        "engine": engine,
        "text": clean_text,
        "redacted_counts": redacted,
        "memory_id": mem_id,
    }
