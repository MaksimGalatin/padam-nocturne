"""ТОП-10 v4 Пункт 10: Локальный мост для мессенджеров и self-hosted автоматизаций (строгий scope + DLP + карантин)."""
from __future__ import annotations

import re
from typing import Any

from . import safety

SUPPORTED_PLATFORMS = ("telegram", "slack", "discord", "n8n", "webhook")
_CLEAN_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _clean_id(val: str) -> str:
    cleaned = _CLEAN_RE.sub("_", str(val or "").strip()).strip("_")
    return cleaned[:64] or "default"


def ingest_channel_message(
    mem: Any,
    *,
    platform: str,
    channel_id: str,
    sender_id: str,
    text: str,
) -> dict[str, Any]:
    """Принимает сообщение из мессенджера/автоматизации с DLP-очисткой, изоляцией scope и принудительным guarded=True."""
    plat = str(platform or "").strip().lower()
    if plat not in SUPPORTED_PLATFORMS:
        raise ValueError(f"unsupported bridge platform {platform!r}; expected one of {SUPPORTED_PLATFORMS}")
    raw_text = str(text or "").strip()
    if not raw_text:
        raise ValueError("text is required")

    chan = _clean_id(channel_id)
    sender = _clean_id(sender_id)
    scope = f"bridge:{plat}:{chan}"

    redacted_text, counts = safety.redact(raw_text)
    payload = f"[{plat}:{chan} sender={sender}] {redacted_text}"

    outcome, rec_id = mem.remember(
        payload,
        kind="event",
        scope=scope,
        origin="external",
        guarded=True,
    )
    return {
        "status": outcome,
        "id": rec_id,
        "platform": plat,
        "channel_id": chan,
        "scope": scope,
        "origin": "external",
        "guarded": True,
        "redacted_counts": counts,
    }
