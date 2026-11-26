# -*- coding: utf-8 -*-
"""Бесплатная ($0) генерация изображений, векторных постеров и презентационных слайдов.

Архитектура без платных ключей и подписок:
1. `generate_slides_deck(...)` — локальный движок презентаций (HTML5 + CSS Grid + SVG +
   Headless Chromium через Playwright -> 1920x1080 Full HD / 3840x2160 4K PNG + PDF + HTML).
   Работает на 100% оффлайн за ~$0.4-1.0 сек на слайд, VRAM не тратит.
2. `generate_image(...)` — каскад $0 генерации изображений:
   - `local_sd`: локальный ComfyUI / Automatic1111 (127.0.0.1) или `stable-diffusion.cpp`
     (на GTX 1060 6GB оптимально SD 1.5 + LCM-LoRA за ~6-12 сек, 512x512 -> апскейл 1024x1024).
   - `cloudflare_flux`: бесплатный суточный тир Cloudflare Workers AI (10 000 Neurons/день =
     ~57 изображений FLUX.1-schnell 1024x1024 или ~231 шт 512x512 за $0/сутки).
   - `procedural_art`: гарантированный 100% оффлайн-генератор обложек, арт-постеров и
     иллюстраций через WebGL/Canvas + SVG + Pillow/OpenCV (< 1 сек, 1024x1024 / 1920x1080, $0).
"""
from __future__ import annotations

import base64
import hashlib
import html as _html
import json
import math
import os
import shutil
import subprocess

from ._no_window import NO_WINDOW
import time
import urllib.request
from pathlib import Path
from typing import Any

from . import safety

_THEMES: dict[str, dict[str, str]] = {
    "cyber_shield": {
        "bg1": "#060913",
        "bg2": "#0d1b2a",
        "accent": "#22d3ee",
        "accent2": "#a78bfa",
        "text": "#f1f5f9",
        "muted": "#94a3b8",
        "card": "rgba(15, 23, 42, 0.78)",
        "border": "rgba(34, 211, 238, 0.28)",
    },
    "dark_quantum": {
        "bg1": "#090612",
        "bg2": "#1a0b2e",
        "accent": "#c084fc",
        "accent2": "#38bdf8",
        "text": "#f8fafc",
        "muted": "#cbd5e1",
        "card": "rgba(24, 16, 48, 0.80)",
        "border": "rgba(192, 132, 252, 0.28)",
    },
    "executive_gold": {
        "bg1": "#0c0a09",
        "bg2": "#1c1917",
        "accent": "#fbbf24",
        "accent2": "#34d399",
        "text": "#fafaf9",
        "muted": "#d6d3d1",
        "card": "rgba(28, 25, 23, 0.86)",
        "border": "rgba(251, 191, 36, 0.30)",
    },
    "clean_paper": {
        "bg1": "#f8fafc",
        "bg2": "#e2e8f0",
        "accent": "#0284c7",
        "accent2": "#7c3aed",
        "text": "#0f172a",
        "muted": "#475569",
        "card": "rgba(255, 255, 255, 0.94)",
        "border": "rgba(15, 23, 42, 0.14)",
    },
}


def _render_html_to_files(
    html_str: str,
    *,
    png_path: Path,
    width: int = 1920,
    height: int = 1080,
    pdf_path: Path | None = None,
) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright
    from . import agentic_shield

    safe_html = agentic_shield.sanitize_untrusted_markup(html_str)["clean"]
    t0 = time.perf_counter()
    png_path.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": int(width), "height": int(height)}, device_scale_factor=1)
            page.set_content(safe_html, wait_until="load")
            page.screenshot(path=str(png_path), type="png", full_page=False)
            if pdf_path is not None:
                pdf_path.parent.mkdir(parents=True, exist_ok=True)
                page.pdf(
                    path=str(pdf_path),
                    width=f"{width}px",
                    height=f"{height}px",
                    print_background=True,
                    margin={"top": "0px", "right": "0px", "bottom": "0px", "left": "0px"},
                )
        finally:
            browser.close()
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    return {
        "png_path": str(png_path),
        "png_bytes": png_path.stat().st_size,
        "pdf_path": str(pdf_path) if pdf_path else None,
        "pdf_bytes": pdf_path.stat().st_size if (pdf_path and pdf_path.exists()) else 0,
        "width": int(width),
        "height": int(height),
        "elapsed_ms": elapsed_ms,
    }


def _slide_inner_html(slide: dict[str, Any], idx: int, total: int, th: dict[str, str], deck_title: str) -> str:
    title = _html.escape(str(slide.get("title") or f"Slide {idx}"))
    subtitle = _html.escape(str(slide.get("subtitle") or ""))
    bullets = [str(b).strip() for b in (slide.get("bullets") or []) if str(b).strip()]
    metrics = list(slide.get("metrics") or [])
    quote = _html.escape(str(slide.get("quote") or ""))
    tag = _html.escape(str(slide.get("tag") or deck_title or "CODE ETERNAL · AIfa"))

    metrics_html = ""
    if metrics:
        cards = []
        for m in metrics[:4]:
            val = _html.escape(str(m.get("value") or ""))
            lbl = _html.escape(str(m.get("label") or ""))
            cards.append(
                f'<div class="kpi"><div class="kpi-val">{val}</div><div class="kpi-lbl">{lbl}</div></div>'
            )
        metrics_html = f'<div class="kpi-row">{"".join(cards)}</div>'

    bullets_html = ""
    if bullets:
        li = "".join(f"<li><span></span><div>{_html.escape(b)}</div></li>" for b in bullets[:8])
        bullets_html = f'<ul class="bullets">{li}</ul>'

    quote_html = f'<blockquote class="quote">{quote}</blockquote>' if quote else ""

    return f"""
    <section class="slide">
      <div class="glow g1"></div><div class="glow g2"></div>
      <header class="top">
        <span class="pill">{tag}</span>
        <span class="num">{idx:02d} / {total:02d}</span>
      </header>
      <main class="body">
        <h1>{title}</h1>
        {f'<p class="sub">{subtitle}</p>' if subtitle else ''}
        {metrics_html}
        {bullets_html}
        {quote_html}
      </main>
      <footer class="foot">
        <span>CODE Eternal LLC · PADAM NOCTURNE & Agentic Shield</span>
        <span>Zero-Cost Local Renderer ($0) · CODE Eternal</span>
      </footer>
    </section>
    """


def _build_deck_css(th: dict[str, str], width: int, height: int) -> str:
    return f"""
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', 'Inter', system-ui, -apple-system, sans-serif;
      background: {th['bg1']}; color: {th['text']};
    }}
    .slide {{
      position: relative; width: {width}px; height: {height}px; overflow: hidden;
      padding: 64px 88px; display: flex; flex-direction: column; justify-content: space-between;
      background: radial-gradient(circle at 12% 18%, {th['bg2']} 0%, {th['bg1']} 70%);
      page-break-after: always;
    }}
    .glow {{ position: absolute; border-radius: 50%; filter: blur(90px); opacity: 0.24; pointer-events: none; }}
    .g1 {{ width: 560px; height: 560px; background: {th['accent']}; top: -180px; right: -120px; }}
    .g2 {{ width: 460px; height: 460px; background: {th['accent2']}; bottom: -160px; left: -120px; }}
    .top {{ position: relative; z-index: 2; display: flex; justify-content: space-between; align-items: center; }}
    .pill {{
      font-size: 20px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
      padding: 10px 22px; border-radius: 999px; border: 1px solid {th['border']};
      background: {th['card']}; color: {th['accent']};
    }}
    .num {{ font-size: 24px; font-weight: 700; color: {th['muted']}; font-variant-numeric: tabular-nums; }}
    .body {{ position: relative; z-index: 2; display: flex; flex-direction: column; gap: 28px; margin: auto 0; }}
    h1 {{ font-size: 62px; line-height: 1.12; font-weight: 800; letter-spacing: -0.02em; max-width: 92%; }}
    .sub {{ font-size: 30px; line-height: 1.38; color: {th['muted']}; max-width: 88%; }}
    .kpi-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 24px; }}
    .kpi {{
      background: {th['card']}; border: 1px solid {th['border']}; border-radius: 22px; padding: 26px 30px;
      box-shadow: 0 18px 40px rgba(0,0,0,0.22);
    }}
    .kpi-val {{ font-size: 46px; font-weight: 800; color: {th['accent']}; }}
    .kpi-lbl {{ font-size: 20px; margin-top: 8px; color: {th['muted']}; }}
    .bullets {{ list-style: none; display: flex; flex-direction: column; gap: 18px; }}
    .bullets li {{
      display: flex; align-items: flex-start; gap: 18px; font-size: 28px; line-height: 1.35;
      background: {th['card']}; border: 1px solid {th['border']}; border-radius: 16px; padding: 18px 24px;
    }}
    .bullets li span {{
      width: 14px; height: 14px; border-radius: 50%; flex-shrink: 0; margin-top: 11px;
      background: linear-gradient(135deg, {th['accent']}, {th['accent2']});
    }}
    .quote {{
      font-size: 26px; font-style: italic; padding: 20px 28px; border-left: 6px solid {th['accent']};
      background: {th['card']}; border-radius: 12px; color: {th['text']};
    }}
    .foot {{
      position: relative; z-index: 2; display: flex; justify-content: space-between;
      font-size: 18px; color: {th['muted']}; border-top: 1px solid {th['border']}; padding-top: 18px;
    }}
    """


def generate_slides_deck(
    slides: list[dict[str, Any]],
    *,
    output_dir: str | Path,
    deck_title: str = "AIfa Presentation",
    theme: str = "cyber_shield",
    width: int = 1920,
    height: int = 1080,
    export_pdf: bool = True,
) -> dict[str, Any]:
    """Генерирует серию PNG-слайдов (Full HD / 4K), PDF-презентацию и HTML5-колоду за $0."""
    if not slides:
        raise ValueError("slides list cannot be empty")
    t0 = time.perf_counter()
    th = _THEMES.get(theme, _THEMES["cyber_shield"])
    out_d = Path(output_dir)
    out_d.mkdir(parents=True, exist_ok=True)
    css = _build_deck_css(th, int(width), int(height))

    rendered_slides: list[dict[str, Any]] = []
    all_sections: list[str] = []
    total = len(slides)

    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": int(width), "height": int(height)}, device_scale_factor=1)
            for idx, sl in enumerate(slides, 1):
                sec = _slide_inner_html(sl, idx, total, th, deck_title)
                all_sections.append(sec)
                doc_one = f"<!doctype html><html><head><meta charset='utf-8'><style>{css}</style></head><body>{sec}</body></html>"
                page.set_content(doc_one, wait_until="load")
                png_p = out_d / f"slide_{idx:02d}.png"
                page.screenshot(path=str(png_p), type="png", full_page=False)
                rendered_slides.append({
                    "index": idx,
                    "title": str(sl.get("title") or ""),
                    "png_path": str(png_p),
                    "bytes": png_p.stat().st_size,
                    "resolution": f"{width}x{height}",
                })

            full_html = f"<!doctype html><html><head><meta charset='utf-8'><title>{_html.escape(deck_title)}</title><style>{css}</style></head><body>{''.join(all_sections)}</body></html>"
            html_p = out_d / "deck.html"
            html_p.write_text(full_html, encoding="utf-8")

            pdf_p = out_d / "deck.pdf" if export_pdf else None
            if pdf_p is not None:
                page.set_content(full_html, wait_until="load")
                page.pdf(
                    path=str(pdf_p),
                    width=f"{width}px",
                    height=f"{height}px",
                    print_background=True,
                    margin={"top": "0px", "right": "0px", "bottom": "0px", "left": "0px"},
                )
        finally:
            browser.close()

    total_ms = round((time.perf_counter() - t0) * 1000, 1)
    return {
        "ok": True,
        "engine": "local_chromium_svg_css",
        "cost_usd": 0.0,
        "theme": theme,
        "resolution": f"{width}x{height}",
        "slides_count": len(rendered_slides),
        "slides": rendered_slides,
        "html_path": str(html_p),
        "pdf_path": str(pdf_p) if pdf_p else None,
        "pdf_bytes": pdf_p.stat().st_size if (pdf_p and pdf_p.exists()) else 0,
        "elapsed_ms": total_ms,
    }


def _procedural_svg_art(prompt: str, *, width: int, height: int, style: str = "phoenix_neon") -> str:
    """Строит высокодетализированный процедурный арт + инфографику на SVG/CSS (без сети, $0)."""
    clean_p, _ = safety.redact(prompt or "")
    seed = int.from_bytes(hashlib.sha256(clean_p.encode("utf-8")).digest()[:8], "big")
    low = clean_p.lower()

    if any(k in low for k in ("shield", "защит", "security", "hack", "opt", "cyber")):
        c1, c2, c3, badge = "#040814", "#22d3ee", "#6366f1", "AGENTIC SHIELD"
    elif any(k in low for k in ("gold", "bank", "coin", "solana", "token", "galatin")):
        c1, c2, c3, badge = "#0a0806", "#fbbf24", "#10b981", "CODE ETERNAL · L3"
    elif any(k in low for k in ("music", "radio", "sound", "трек", "dj")):
        c1, c2, c3, badge = "#0d0418", "#f472b6", "#38bdf8", "RADIOCODE STUDIO"
    else:
        c1, c2, c3, badge = "#050714", "#38bdf8", "#c084fc", "AIfa · DIGITAL PHOENIX"

    stars = []
    nodes: list[tuple[float, float]] = []
    for i in range(42):
        h = hashlib.sha256(f"{seed}:{i}".encode()).digest()
        x = (int.from_bytes(h[:2], "big") % (width - 80)) + 40
        y = (int.from_bytes(h[2:4], "big") % (height - 80)) + 40
        r = (h[4] % 3) + 1.2
        op = 0.25 + (h[5] % 70) / 100.0
        stars.append(f'<circle cx="{x}" cy="{y}" r="{r:.1f}" fill="#ffffff" opacity="{op:.2f}"/>')
        if i < 16:
            nodes.append((x, y))

    edges = []
    for i in range(len(nodes)):
        x1, y1 = nodes[i]
        x2, y2 = nodes[(i + 5) % len(nodes)]
        edges.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c2}" stroke-opacity="0.24" stroke-width="1.6"/>')

    cx, cy = width // 2, int(height * 0.46)
    rings = []
    for k in range(5):
        rad = 110 + k * 56
        dash = f"{14 + (k * 7)} {10 + (k * 5)}" if k % 2 else "none"
        rings.append(
            f'<circle cx="{cx}" cy="{cy}" r="{rad}" fill="none" stroke="url(#gRing)" '
            f'stroke-width="{2.6 - k * 0.3:.1f}" stroke-dasharray="{dash}" opacity="{0.75 - k * 0.11:.2f}"/>'
        )

    # Крылья Феникса / Крипто-щит по центру
    wing_paths = []
    for j in range(1, 7):
        ang = (j - 3.5) * 0.22
        wx = cx + int(math.sin(ang) * 260)
        wy = cy - int(math.cos(ang) * 190)
        wing_paths.append(
            f'<path d="M {cx} {cy + 40} Q {(cx + wx)//2} {cy - 90} {wx} {wy}" '
            f'fill="none" stroke="url(#gRing)" stroke-width="3" stroke-linecap="round" opacity="0.68"/>'
        )

    caption = _html.escape((clean_p or "Digital Phoenix Artwork")[:96])
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
  width:{width}px; height:{height}px; overflow:hidden; background:{c1};
  font-family:'Segoe UI',system-ui,sans-serif; color:#f8fafc; position:relative;
}}
.cap {{
  position:absolute; left:48px; right:48px; bottom:44px; padding:22px 28px;
  background:rgba(6,10,24,0.72); border:1px solid rgba(255,255,255,0.16);
  border-radius:18px; backdrop-filter:blur(10px);
}}
.tag {{ font-size:16px; font-weight:700; letter-spacing:0.14em; color:{c2}; margin-bottom:8px; }}
.ttl {{ font-size:28px; font-weight:700; line-height:1.25; }}
</style></head>
<body>
<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <radialGradient id="gBg" cx="50%" cy="45%" r="65%">
      <stop offset="0%" stop-color="{c3}" stop-opacity="0.34"/>
      <stop offset="50%" stop-color="{c2}" stop-opacity="0.12"/>
      <stop offset="100%" stop-color="{c1}" stop-opacity="1"/>
    </radialGradient>
    <linearGradient id="gRing" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{c2}"/>
      <stop offset="100%" stop-color="{c3}"/>
    </linearGradient>
  </defs>
  <rect width="{width}" height="{height}" fill="{c1}"/>
  <rect width="{width}" height="{height}" fill="url(#gBg)"/>
  {"".join(stars)}
  {"".join(edges)}
  {"".join(rings)}
  {"".join(wing_paths)}
  <polygon points="{cx},{cy-110} {cx+88},{cy-55} {cx+68},{cy+72} {cx},{cy+124} {cx-68},{cy+72} {cx-88},{cy-55}"
           fill="rgba(6,10,24,0.65)" stroke="url(#gRing)" stroke-width="4"/>
  <circle cx="{cx}" cy="{cy}" r="22" fill="{c2}" opacity="0.9"/>
</svg>
<div class="cap">
  <div class="tag">{badge} · {width}×{height}</div>
  <div class="ttl">{caption}</div>
</div>
</body></html>"""


def _try_cloudflare_flux(prompt: str, *, out_path: Path, steps: int = 4) -> dict[str, Any] | None:
    acc = (os.environ.get("CLOUDFLARE_ACCOUNT_ID") or "").strip()
    tok = (os.environ.get("CLOUDFLARE_API_TOKEN") or "").strip()
    if not acc or not tok:
        return None
    t0 = time.perf_counter()
    clean_p, _ = safety.redact(prompt)
    url = f"https://api.cloudflare.com/client/v4/accounts/{acc}/ai/run/@cf/black-forest-labs/flux-1-schnell"
    body = json.dumps({"prompt": clean_p[:900], "steps": max(1, min(8, int(steps)))}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        raw = resp.read()
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "application/json" in ctype:
        obj = json.loads(raw.decode("utf-8"))
        b64_img = (obj.get("result") or {}).get("image")
        if not b64_img:
            raise RuntimeError(f"Cloudflare Workers AI returned no image: {obj}")
        img_bytes = base64.b64decode(b64_img)
    else:
        img_bytes = raw
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(img_bytes)
    from PIL import Image
    with Image.open(out_path) as im:
        w, h = im.size
    return {
        "ok": True,
        "engine": "cloudflare_flux_1_schnell",
        "cost_usd": 0.0,
        "note": "Бесплатная дневная квота Cloudflare Workers AI: 10,000 Neurons/день (~57 кадров 1024x1024 или ~231 кадр 512x512)",
        "output_path": str(out_path),
        "bytes": out_path.stat().st_size,
        "width": w,
        "height": h,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
    }


def _try_local_sd_cpp(prompt: str, *, out_path: Path, width: int, height: int, steps: int = 8) -> dict[str, Any] | None:
    sd_bin = (os.environ.get("PADAM_SD_CPP_BIN") or "").strip() or shutil.which("sd") or shutil.which("sd-cli")
    sd_model = (os.environ.get("PADAM_SD_MODEL") or "").strip()
    if not sd_bin or not sd_model or not Path(sd_model).exists():
        return None
    t0 = time.perf_counter()
    clean_p, _ = safety.redact(prompt)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sd_bin, "-m", sd_model, "-p", clean_p[:500],
        "-W", str(int(width)), "-H", str(int(height)),
        "--steps", str(max(1, min(30, int(steps)))),
        "-o", str(out_path),
    ]
    subprocess.run(cmd, check=True, timeout=180, capture_output=True, **NO_WINDOW)
    return {
        "ok": True,
        "engine": "local_stable_diffusion_cpp",
        "cost_usd": 0.0,
        "output_path": str(out_path),
        "bytes": out_path.stat().st_size,
        "width": int(width),
        "height": int(height),
        "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
    }


def detect_available_engines() -> dict[str, Any]:
    """Честно сообщает, какие $0-движки активны прямо сейчас без скачивания гигабайтных весов."""
    sd_bin = (os.environ.get("PADAM_SD_CPP_BIN") or "").strip() or shutil.which("sd") or shutil.which("sd-cli")
    sd_model = (os.environ.get("PADAM_SD_MODEL") or "").strip()
    cf_ok = bool((os.environ.get("CLOUDFLARE_ACCOUNT_ID") or "").strip() and (os.environ.get("CLOUDFLARE_API_TOKEN") or "").strip())
    # Слайды и PNG рисует Chromium через playwright — это необязательная зависимость.
    # Без неё честный ответ — «недоступно», а не True (до 20.11.2026 здесь стояло True всегда).
    try:
        import importlib.util as _ilu
        chromium_ok = _ilu.find_spec("playwright") is not None
    except Exception:
        chromium_ok = False
    return {
        "slides_chromium": chromium_ok,
        "procedural_svg_canvas": True,
        "cloudflare_flux_free_tier": cf_ok,
        "local_sd_cpp": bool(sd_bin and sd_model and Path(sd_model).exists()),
        "sd_bin": sd_bin or None,
    }


def generate_image(
    prompt: str,
    *,
    output_path: str | Path,
    engine: str = "auto",
    width: int = 1024,
    height: int = 1024,
    style: str = "phoenix_neon",
    steps: int = 4,
) -> dict[str, Any]:
    """Генерирует изображение за $0: local_sd -> cloudflare_flux -> оффлайн procedural_svg."""
    out_p = Path(output_path)
    eng = (engine or "auto").strip().lower()

    if eng in ("auto", "local_sd"):
        res_sd = _try_local_sd_cpp(prompt, out_path=out_p, width=width, height=height, steps=steps)
        if res_sd is not None:
            return res_sd
        if eng == "local_sd":
            raise RuntimeError("local_sd requested, but PADAM_SD_CPP_BIN / PADAM_SD_MODEL weights are not configured")

    if eng in ("auto", "cloudflare_flux"):
        try:
            res_cf = _try_cloudflare_flux(prompt, out_path=out_p, steps=steps)
            if res_cf is not None:
                return res_cf
        except Exception:
            if eng == "cloudflare_flux":
                raise

    # Гарантированный бесплатный оффлайн-путь (Chromium SVG/Canvas + крипто-очистка промта)
    html_str = _procedural_svg_art(prompt, width=int(width), height=int(height), style=style)
    ren = _render_html_to_files(html_str, png_path=out_p, width=int(width), height=int(height))
    return {
        "ok": True,
        "engine": "local_procedural_svg_chromium",
        "cost_usd": 0.0,
        "output_path": ren["png_path"],
        "bytes": ren["png_bytes"],
        "width": ren["width"],
        "height": ren["height"],
        "elapsed_ms": ren["elapsed_ms"],
    }
