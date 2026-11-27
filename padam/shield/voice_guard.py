# -*- coding: utf-8 -*-
"""Защита голосовых и аудио-агентов (Voice / Audio & Transcript Injection Guard).

Закрывает 3 реальных вектора атак на голосовые ИИ-агенты 2026 года:
1. DolphinAttack (ультразвуковые скрытые команды > 18 кГц в WAV PCM):
   локальный спектральный анализ через `wave` + `numpy.fft.rfft` (0 внешних API).
2. Скрытые текстовые промпт-инъекции в метаданных WAV (`LIST/INFO`) и MP3 (`ID3v1`/`ID3v2`).
3. Голосовая социальная инженерия в транскриптах (Vishing / кража 2FA/OTP кодов /
   CEO Fraud срочного перевода на «безопасный счёт» / обход подтверждения).
"""
from __future__ import annotations

import io
import re
import wave
from typing import Any, Dict, List

import numpy as np

from .adversarial_norm import canonicalize_adversarial_text


_VISHING_OTP_RE = re.compile(
    r"(?is)(?:"
    r"(?:read|tell|give|send|dictate|repeat)\s+(?:me\s+)?(?:the\s+)?(?:(?:six[\s-]?digit|6[\s-]?digit|2fa|otp|verification|sms|security|one[\s-]?time)\s+){1,3}code"
    r"|(?:продиктуй|назови|сообщи|отправь)\s+(?:мне\s+)?(?:код\s+из\s+смс|смс[\s-]?код|код\s+подтверждения|одноразовый\s+код)"
    r")"
)

_VISHING_CEO_WIRE_RE = re.compile(
    r"(?is)(?:"
    r"(?:this\s+is\s+the\s+ceo|i\s+am\s+your\s+ceo|security\s+department|fraud\s+department).{0,120}"
    r"(?:urgent\s+wire|transfer\s+(?:funds|money|usdt|btc)|safe\s+account|do\s+not\s+tell\s+anyone|bypass\s+approval)"
    r"|(?:служба\s+безопасности\s+банка|я\s+генеральный\s+директор).{0,120}(?:безопасный\s+счёт|срочно\s+перевед|никому\s+не\s+говори)"
    r")"
)

_VOICE_META_INJ_RE = re.compile(
    r"(?is)\b(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?"
    r"|system\s+prompt|override\s+(?:safety|rules?|policy)|disable\s+kill\s*switch"
    r"|exfiltrate|transfer\s+(?:funds|usdt|eth|sol)|игнорируй\s+предыдущие\s+инструкции"
    r")"
)


def inspect_audio_bytes(
    data: bytes,
    *,
    filename: str = "audio.wav",
    ultrasonic_hz: float = 18000.0,
    ultrasonic_ratio_threshold: float = 0.20,
) -> Dict[str, Any]:
    """Проверяет WAV/MP3 на ультразвуковые команды (DolphinAttack) и инъекции в метаданных."""
    findings: List[Dict[str, Any]] = []
    fmt = "generic"
    sample_rate = 0
    ultrasonic_ratio = 0.0

    # 1. WAV PCM спектральный анализ (DolphinAttack > 18 кГц) + метаданные
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        fmt = "wav"
        try:
            with wave.open(io.BytesIO(data), "rb") as wf:
                sample_rate = wf.getframerate()
                n_channels = wf.getnchannels()
                sampwidth = wf.getsampwidth()
                n_frames = min(wf.getnframes(), sample_rate * 10)  # до 10 секунд
                raw_pcm = wf.readframes(n_frames)
            if sampwidth == 2 and raw_pcm and sample_rate >= 40000:
                samples = np.frombuffer(raw_pcm, dtype=np.int16).astype(np.float64)
                if n_channels > 1:
                    samples = samples.reshape(-1, n_channels).mean(axis=1)
                if len(samples) >= 256:
                    spec = np.abs(np.fft.rfft(samples)) ** 2
                    freqs = np.fft.rfftfreq(len(samples), d=1.0 / sample_rate)
                    total_energy = float(spec.sum())
                    if total_energy > 1e-6:
                        ultra_energy = float(spec[freqs >= ultrasonic_hz].sum())
                        ultrasonic_ratio = round(ultra_energy / total_energy, 4)
                        if ultrasonic_ratio >= ultrasonic_ratio_threshold:
                            findings.append(
                                {
                                    "rule_id": "VOICE-ULTRASONIC-DOLPHINATTACK",
                                    "severity": "CRITICAL",
                                    "detail": f"Обнаружена аномальная ультразвуковая энергия >={int(ultrasonic_hz)} Гц (доля={ultrasonic_ratio:.2%}, риск DolphinAttack!)",
                                }
                            )
        except Exception:
            pass

        # Поиск текстовых метаданных в хвосте/INFO-чанках WAV
        meta_idx = data.find(b"INFO")
        if meta_idx != -1:
            meta_txt = data[meta_idx : meta_idx + 8192].decode("utf-8", errors="ignore")
            norm = canonicalize_adversarial_text(meta_txt)["canonical"]
            if _VOICE_META_INJ_RE.search(meta_txt) or _VOICE_META_INJ_RE.search(norm):
                findings.append(
                    {
                        "rule_id": "VOICE-METADATA-INJECTION",
                        "severity": "CRITICAL",
                        "detail": "Обнаружена скрытая промпт-инъекция в метаданных WAV (LIST/INFO)",
                    }
                )

    # 2. MP3 ID3v2 / ID3v1 теги
    elif data[:3] == b"ID3" or filename.lower().endswith(".mp3"):
        fmt = "mp3"
        head_txt = data[:16384].decode("utf-8", errors="ignore") + "\n" + data[-256:].decode("latin-1", errors="ignore")
        norm = canonicalize_adversarial_text(head_txt)["canonical"]
        if _VOICE_META_INJ_RE.search(head_txt) or _VOICE_META_INJ_RE.search(norm):
            findings.append(
                {
                    "rule_id": "VOICE-METADATA-INJECTION",
                    "severity": "CRITICAL",
                    "detail": "Обнаружена скрытая промпт-инъекция в ID3-метаданных MP3",
                }
            )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "format": fmt,
        "filename": filename,
        "sample_rate": sample_rate,
        "ultrasonic_ratio": ultrasonic_ratio,
        "findings": findings,
    }


def inspect_voice_transcript(transcript: str, *, caller_id: str = "") -> Dict[str, Any]:
    """Проверяет голосовой транскрипт на Vishing, кражу OTP/2FA, CEO Fraud и голосовые инъекции."""
    raw = str(transcript or "").strip()
    if not raw:
        return {"ok": True, "allowed": True, "blocked": False, "findings": []}

    norm = canonicalize_adversarial_text(raw)["canonical"]
    corpus = raw + "\n" + norm
    findings: List[Dict[str, Any]] = []

    if _VISHING_OTP_RE.search(corpus):
        findings.append(
            {
                "rule_id": "VOICE-VISHING-OTP-THEFT",
                "severity": "CRITICAL",
                "detail": "Обнаружена попытка выманивания одноразового кода 2FA/OTP/SMS в голосовом канале",
            }
        )
    if _VISHING_CEO_WIRE_RE.search(corpus):
        findings.append(
            {
                "rule_id": "VOICE-CEO-URGENT-WIRE",
                "severity": "CRITICAL",
                "detail": "Обнаружена социальная инженерия (CEO Fraud / «безопасный счёт» / срочный перевод)",
            }
        )
    if _VOICE_META_INJ_RE.search(corpus):
        findings.append(
            {
                "rule_id": "VOICE-TRANSCRIPT-INJECTION",
                "severity": "CRITICAL",
                "detail": "Обнаружена прямая/скрытая промпт-инъекция в голосовом транскрипте",
            }
        )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "caller_id": caller_id,
        "findings": findings,
    }
