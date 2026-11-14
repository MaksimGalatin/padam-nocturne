# -*- coding: utf-8 -*-
"""Канонический векторный логотип проекта CODE Eternal (@CODE_AIfa).

Единый источник правды для SVG в PADAM Studio, favicon, docs/site и настольной оболочки.
"""
from __future__ import annotations

import base64
import struct
from pathlib import Path

CODE_LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="none">
  <defs>
    <linearGradient id="code-bg" x1="256" y1="12" x2="256" y2="500" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#070a18"/>
      <stop offset="100%" stop-color="#091025"/>
    </linearGradient>
    <filter id="code-glow" x="-22%" y="-22%" width="144%" height="144%">
      <feGaussianBlur in="SourceAlpha" stdDeviation="8" result="blur-wide"/>
      <feFlood flood-color="#93c5fd" flood-opacity="0.55" result="tint"/>
      <feComposite in="tint" in2="blur-wide" operator="in" result="glow-wide"/>
      <feGaussianBlur in="SourceAlpha" stdDeviation="2.8" result="blur-core"/>
      <feFlood flood-color="#ffffff" flood-opacity="0.55" result="white"/>
      <feComposite in="white" in2="blur-core" operator="in" result="glow-core"/>
      <feMerge>
        <feMergeNode in="glow-wide"/>
        <feMergeNode in="glow-core"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
  <circle cx="256" cy="256" r="240" fill="url(#code-bg)" stroke="#ffffff" stroke-width="13"/>
  <g filter="url(#code-glow)">
    <circle cx="193.5" cy="195.0" r="32.2" fill="#ffffff"/>
    <circle cx="318.5" cy="195.0" r="32.2" fill="#ffffff"/>
    <path d="M 148.0 351.0 L 148.0 306.0 A 45.5 45.5 0 0 1 239.0 306.0 L 239.0 333.5 A 17.0 17.0 0 0 0 273.0 333.5 L 273.0 306.0 A 45.5 45.5 0 0 1 364.0 306.0 L 364.0 351.0"
          fill="none" stroke="#ffffff" stroke-width="22.0" stroke-linecap="round" stroke-linejoin="round"/>
  </g>
</svg>
"""

_FALLBACK_PNG32_B64 = (
    "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"
)


def code_logo_svg_inline(cls: str = "brand-logo") -> str:
    """Возвращает встроенный <svg> с классом cls без внешних зависимостей."""
    return CODE_LOGO_SVG.replace(
        '<svg xmlns="http://www.w3.org/2000/svg" ',
        f'<svg class="{cls}" aria-hidden="true" ',
        1,
    )


def favicon_ico_bytes() -> bytes:
    """Возвращает байты .ico (сначала из desktop/icons/padam.ico, иначе встроенный 32x32 PNG-в-ICO)."""
    repo_ico = Path(__file__).resolve().parents[1] / "desktop" / "icons" / "padam.ico"
    if repo_ico.is_file():
        return repo_ico.read_bytes()
    png = base64.b64decode(_FALLBACK_PNG32_B64)
    # Стандартный ICO-заголовок (ICONDIR + ICONDIRENTRY для 32x32 32-bit PNG)
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", 32, 32, 0, 0, 1, 32, len(png), 22)
    return header + entry + png
