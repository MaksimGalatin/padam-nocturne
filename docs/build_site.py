# -*- coding: utf-8 -*-
"""Генератор автономного статического сайта документации PADAM · NOCTURNE (Б15).

Без внешних зависимостей, CDN и встроенных скриптов/стилей.
Запуск: python docs/build_site.py [--out docs/site]
"""

from __future__ import annotations

import argparse
import html
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from padam.logo import CODE_LOGO_SVG as LOGO_SVG
from site_locales import (
    CLI_COMMANDS,
    COMPETITORS_ROWS,
    ENV_VARS,
    KINDS_DATA,
    L3_MAINNET_ROWS,
    LANG_NAMES,
    LANGUAGES,
    MCP_TOOLS,
    PAGES,
    REST_ENDPOINTS,
    UI_STRINGS,
)

DOCS_DIR = ROOT / "docs"
DEFAULT_OUT = DOCS_DIR / "site"

CSP_META = (
    '<meta http-equiv="Content-Security-Policy" '
    "content=\"default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; object-src 'none'; base-uri 'self'\">"
)

STYLE_CSS = """/* Автономная дизайн-система документации PADAM · NOCTURNE (CODE Eternal) */
:root {
  --bg: #080b12;
  --bg-elev: #0e1422;
  --card: #121a2c;
  --card-2: #172138;
  --fg: #eef4ff;
  --muted: #9aaac4;
  --line: rgba(148, 163, 184, 0.22);
  --accent: #38bdf8;
  --accent-2: #8b5cf6;
  --accent-fg: #04121f;
  --ok: #34d399;
  --ok-bg: rgba(52, 211, 153, 0.14);
  --warn: #fbbf24;
  --code-bg: #0a0f1c;
  --shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
  --radius: 14px;
}

html[data-theme="light"] {
  --bg: #f4f6fb;
  --bg-elev: #ffffff;
  --card: #ffffff;
  --card-2: #eef2fa;
  --fg: #0f172a;
  --muted: #475569;
  --line: rgba(15, 23, 42, 0.14);
  --accent: #0284c7;
  --accent-2: #6d28d9;
  --accent-fg: #ffffff;
  --ok: #047857;
  --ok-bg: rgba(4, 120, 87, 0.1);
  --warn: #b45309;
  --code-bg: #f1f5f9;
  --shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
}

*, *::before, *::after { box-sizing: border-box; }
html { font-size: 16px; scroll-behavior: smooth; }
body {
  margin: 0;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif;
  background: var(--bg);
  color: var(--fg);
  line-height: 1.6;
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, pre {
  font-family: ui-monospace, "Cascadia Code", "JetBrains Mono", Consolas, monospace;
}
code {
  background: var(--code-bg);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 0.1em 0.4em;
  font-size: 0.9em;
}
pre {
  background: var(--code-bg);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 1rem 1.15rem;
  overflow-x: auto;
  position: relative;
  margin: 0.9rem 0 1.25rem;
}
pre code {
  border: none;
  background: transparent;
  padding: 0;
  font-size: 0.88rem;
  line-height: 1.55;
  display: block;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 30;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.75rem 1.25rem;
  background: var(--bg-elev);
  border-bottom: 1px solid var(--line);
}
.brand {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  color: var(--fg);
  font-weight: 700;
}
.brand:hover { text-decoration: none; }
.brand img { width: 36px; height: 36px; display: block; }
.brand-sub { display: block; font-size: 0.78rem; font-weight: 400; color: var(--muted); }

.top-actions { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.lang-pills { display: flex; gap: 0.3rem; flex-wrap: wrap; }
.pill, .btn {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.38rem 0.72rem;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--fg);
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
}
.pill:hover, .btn:hover { border-color: var(--accent); text-decoration: none; }
.pill.active {
  background: var(--accent);
  color: var(--accent-fg);
  border-color: transparent;
}
.btn-menu { display: none; }

.shell {
  max-width: 1280px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr);
  gap: 1.75rem;
  padding: 1.5rem 1.25rem 3rem;
}
.sidebar {
  position: sticky;
  top: 76px;
  align-self: start;
  background: var(--bg-elev);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 1rem;
}
.nav-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.35rem; }
.nav-link {
  display: block;
  padding: 0.55rem 0.85rem;
  border-radius: 10px;
  color: var(--fg);
  font-weight: 500;
  border: 1px solid transparent;
}
.nav-link:hover { background: var(--card); text-decoration: none; border-color: var(--line); }
.nav-link[aria-current="page"] {
  background: var(--card-2);
  border-color: var(--accent);
  color: var(--accent);
  font-weight: 700;
}

main { min-width: 0; }
.hero {
  background: linear-gradient(135deg, var(--card), var(--bg-elev));
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 1.75rem;
  box-shadow: var(--shadow);
  margin-bottom: 1.5rem;
}
.badge {
  display: inline-block;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--ok);
  background: var(--ok-bg);
  border: 1px solid rgba(52, 211, 153, 0.35);
  border-radius: 999px;
  padding: 0.25rem 0.75rem;
  margin-bottom: 0.8rem;
}
h1 { margin: 0 0 0.65rem; font-size: clamp(1.55rem, 3vw, 2.2rem); line-height: 1.25; }
h2 { margin: 2rem 0 0.85rem; font-size: 1.35rem; border-bottom: 1px solid var(--line); padding-bottom: 0.4rem; }
h3 { margin: 1.25rem 0 0.5rem; font-size: 1.08rem; }
.lead { margin: 0; color: var(--muted); font-size: 1.05rem; }

.grid { display: grid; gap: 1rem; grid-template-columns: repeat(2, minmax(0, 1fr)); margin: 1.25rem 0; }
.grid-3 { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); margin: 1.25rem 0; }
.card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 1.1rem 1.2rem;
}
.card h3 { margin-top: 0; color: var(--accent); }
.card p:last-child { margin-bottom: 0; }

.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--card);
  margin: 0.9rem 0 1.5rem;
}
table { width: 100%; border-collapse: collapse; font-size: 0.92rem; text-align: left; }
th, td { padding: 0.68rem 0.9rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--card-2); font-weight: 700; white-space: nowrap; }
tr:last-child td { border-bottom: none; }
.tag-yes {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 6px;
  font-weight: 700;
  color: var(--ok);
  background: var(--ok-bg);
}

.filter-bar {
  display: flex;
  gap: 0.75rem;
  align-items: center;
  margin: 1rem 0;
}
.filter-input {
  width: 100%;
  max-width: 420px;
  padding: 0.55rem 0.85rem;
  border-radius: 10px;
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--fg);
  font-size: 0.95rem;
}

.shot-grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }
.shot {
  margin: 0;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  overflow: hidden;
}
.shot img { width: 100%; height: auto; display: block; }
.shot figcaption { padding: 0.7rem 0.9rem; font-size: 0.88rem; color: var(--muted); }

.copy-btn {
  position: absolute;
  top: 0.55rem;
  right: 0.55rem;
  padding: 0.25rem 0.55rem;
  border-radius: 8px;
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--fg);
  font-size: 0.76rem;
  cursor: pointer;
}
.copy-btn:hover { border-color: var(--accent); }

.footer {
  max-width: 1280px;
  margin: 0 auto;
  padding: 1.25rem;
  border-top: 1px solid var(--line);
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  color: var(--muted);
  font-size: 0.86rem;
}

.landing {
  max-width: 760px;
  margin: 4rem auto;
  padding: 2rem 1.25rem;
  text-align: center;
}
.landing-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 0.9rem;
  margin-top: 1.5rem;
}
.landing-card {
  display: block;
  padding: 1.15rem;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  color: var(--fg);
  font-weight: 700;
  font-size: 1.08rem;
}
.landing-card:hover { border-color: var(--accent); text-decoration: none; }

@media (max-width: 860px) {
  .btn-menu { display: inline-flex; }
  .shell { grid-template-columns: 1fr; padding-top: 1rem; }
  .sidebar { display: none; position: static; }
  .sidebar.open { display: block; }
}
@media (max-width: 680px) {
  .topbar { flex-direction: column; align-items: stretch; gap: 0.55rem; }
  .grid { grid-template-columns: 1fr; }
}
"""

SITE_JS = """(function () {
  "use strict";
  var root = document.documentElement;
  var savedTheme = null;
  try {
    savedTheme = localStorage.getItem("padam-docs-theme");
  } catch (e) {}

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      var darkLabel = btn.getAttribute("data-dark-label") || "Dark";
      var lightLabel = btn.getAttribute("data-light-label") || "Light";
      btn.textContent = theme === "light" ? darkLabel : lightLabel;
      btn.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
    }
  }

  var initial = savedTheme || "dark";
  applyTheme(initial);

  var themeBtn = document.getElementById("theme-toggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      try { localStorage.setItem("padam-docs-theme", next); } catch (e) {}
      applyTheme(next);
    });
  }

  var menuBtn = document.getElementById("menu-toggle");
  var sidebar = document.getElementById("docs-sidebar");
  if (menuBtn && sidebar) {
    menuBtn.addEventListener("click", function () {
      var open = sidebar.classList.toggle("open");
      menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  var langLinks = document.querySelectorAll("[data-set-lang]");
  for (var i = 0; i < langLinks.length; i++) {
    langLinks[i].addEventListener("click", function (ev) {
      var lang = ev.currentTarget.getAttribute("data-set-lang");
      try { localStorage.setItem("padam-docs-lang", lang); } catch (e) {}
    });
  }

  var blocks = document.querySelectorAll("pre");
  var copyLabel = root.getAttribute("data-copy-label") || "Copy";
  var copiedLabel = root.getAttribute("data-copied-label") || "Copied";
  for (var j = 0; j < blocks.length; j++) {
    (function (pre) {
      var code = pre.querySelector("code");
      if (!code) return;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-btn";
      btn.textContent = copyLabel;
      btn.addEventListener("click", function () {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(code.textContent || "").then(function () {
            btn.textContent = copiedLabel;
            setTimeout(function () { btn.textContent = copyLabel; }, 1400);
          });
        }
      });
      pre.appendChild(btn);
    })(blocks[j]);
  }

  var filterInput = document.getElementById("ref-filter");
  if (filterInput) {
    filterInput.addEventListener("input", function () {
      var q = filterInput.value.trim().toLowerCase();
      var rows = document.querySelectorAll("tbody tr");
      for (var k = 0; k < rows.length; k++) {
        var txt = (rows[k].textContent || "").toLowerCase();
        rows[k].hidden = Boolean(q && txt.indexOf(q) === -1);
      }
    });
  }
})();
"""

REDIRECT_JS = """(function () {
  "use strict";
  if (window.location.search.indexOf("stay=1") !== -1) return;
  var lang = null;
  try { lang = localStorage.getItem("padam-docs-lang"); } catch (e) {}
  if (!lang) {
    var nav = (navigator.language || "en").slice(0, 2).toLowerCase();
    lang = ["ru", "en", "es", "zh"].indexOf(nav) !== -1 ? nav : "en";
  }
  if (["ru", "en", "es", "zh"].indexOf(lang) !== -1) {
    window.location.replace("./" + lang + "/index.html");
  }
})();
"""


def _esc(val: object) -> str:
    return html.escape(str(val), quote=True)


def _inline_code(val: object) -> str:
    """Преобразует `код` внутри строки в безопасные теги <code>."""
    parts = str(val).split("`")
    out: list[str] = []
    for idx, part in enumerate(parts):
        if idx % 2 == 1 and idx < len(parts) - 1:
            out.append(f"<code>{_esc(part)}</code>")
        else:
            out.append(_esc(part))
    return "".join(out)


def _code_block(code: str) -> str:
    return f"<pre><code>{_esc(code)}</code></pre>"


def _table(headers: list[str], rows: list[tuple[str, ...]]) -> str:
    ths = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    trs = []
    for row in rows:
        tds = "".join(f"<td>{cell}</td>" for cell in row)
        trs.append(f"<tr>{tds}</tr>")
    return f'<div class="table-wrap"><table><thead><tr>{ths}</tr></thead><tbody>{"".join(trs)}</tbody></table></div>'


def _render_overview(lang: str, s: dict) -> str:
    d = s["overview"]
    cards = "".join(
        f'<article class="card"><h3>{_esc(title)}</h3><p>{_inline_code(desc)}</p></article>'
        for title, desc in d["cards"]
    )
    layers = "".join(
        f'<article class="card"><h3>{_esc(title)}</h3><p>{_inline_code(desc)}</p></article>'
        for title, desc in d["layers"]
    )
    perf = _table(
        ["Records", "Write", "Search", "SQLite size"] if lang != "ru" else ["Записей", "Запись", "Поиск", "Размер БД"],
        [(f"<strong>{_esc(r)}</strong>", _esc(w), _esc(sr), _esc(sz)) for r, w, sr, sz in d["perf_rows"]],
    )
    return f"""
<section class="hero">
  <span class="badge">{_esc(s["hero_badge"])}</span>
  <h1>{_esc(d["title"])}</h1>
  <p class="lead">{_esc(d["lead"])}</p>
</section>
<div class="grid">{cards}</div>
<h2>{_esc(d["layers_h"])}</h2>
<div class="grid-3">{layers}</div>
<h2>{_esc(d["perf_h"])}</h2>
{perf}
<h2>{_esc(d["screens_h"])}</h2>
<div class="shot-grid">
  <figure class="shot">
    <img src="../assets/images/studio-overview.png" alt="{_esc(d["screens_cap_1"])}">
    <figcaption>{_esc(d["screens_cap_1"])}</figcaption>
  </figure>
  <figure class="shot">
    <img src="../assets/images/studio-graph.png" alt="{_esc(d["screens_cap_2"])}">
    <figcaption>{_esc(d["screens_cap_2"])}</figcaption>
  </figure>
</div>
"""


def _render_quickstart(lang: str, s: dict) -> str:
    d = s["quickstart"]
    install_code = (
        "pip install padam-nocturne\n"
        "# or with local model2vec embeddings (~30 MB):\n"
        'pip install "padam-nocturne[embed]"\n'
        "# optional L3 anchoring & ONNX injection detector:\n"
        'pip install "padam-nocturne[l3,guard]"'
    )
    demo_code = (
        "python -m padam demo --studio\n"
        "# quick CLI tour:\n"
        'python -m padam remember "Answer in Russian, numbers first" --kind preference --importance 1.0\n'
        'python -m padam recall "which language to use" --explain\n'
        "python -m padam doctor"
    )
    mcp_cfg = (
        'claude mcp add padam -- uvx padam-nocturne\n'
        '# Multilingual Russian/Spanish/Chinese memory:\n'
        'claude mcp add padam -e PADAM_EMBEDDER=model2vec -e PADAM_LOCAL_EMBED_MODEL=minishlab/potion-multilingual-128M -- uvx --from "padam-nocturne[embed]" padam-nocturne'
    )
    clients = "".join(
        f'<article class="card"><h3>{_esc(t)}</h3><p>{_inline_code(txt)}</p></article>'
        for t, txt in d["clients"]
    )
    feat_li = "".join(f"<li>{_inline_code(x)}</li>" for x in d["studio_features"])
    return f"""
<section class="hero">
  <h1>{_esc(d["title"])}</h1>
  <p class="lead">{_esc(d["lead"])}</p>
</section>
<h2>{_esc(d["install_h"])}</h2>
{_code_block(install_code)}
<h2>{_esc(d["demo_h"])}</h2>
<p>{_inline_code(d["demo_desc"])}</p>
{_code_block(demo_code)}
<h2>{_esc(d["clients_h"])}</h2>
{_code_block(mcp_cfg)}
<div class="grid-3">{clients}</div>
<h2>{_esc(d["studio_features_h"])}</h2>
<div class="card"><ul>{feat_li}</ul></div>
"""


def _render_reference(lang: str, s: dict) -> str:
    d = s["reference"]
    mcp_tbl = _table(
        ["Tool", "Fenced", "Hints", "Parameters"],
        [(f"<code>{_esc(n)}</code>", _inline_code(f), f"<code>{_esc(h)}</code>", _inline_code(p)) for n, f, h, p in MCP_TOOLS],
    )
    rest_tbl = _table(
        ["Method", "Path", "Auth", "Purpose"],
        [(f"<code>{_esc(m)}</code>", f"<code>{_esc(p)}</code>", _inline_code(a), _inline_code(desc)) for m, p, a, desc in REST_ENDPOINTS],
    )
    cli_tbl = _table(
        ["Command", "Purpose"],
        [(f"<code>{_esc(c)}</code>", _inline_code(desc)) for c, desc in CLI_COMMANDS],
    )
    env_tbl = _table(
        ["Variable", "Default", "Meaning"],
        [(f"<code>{_esc(v)}</code>", f"<code>{_esc(df)}</code>", _inline_code(desc)) for v, df, desc in ENV_VARS],
    )
    return f"""
<section class="hero">
  <h1>{_esc(d["title"])}</h1>
  <p class="lead">{_esc(d["lead"])}</p>
</section>
<div class="filter-bar">
  <input id="ref-filter" class="filter-input" type="search" placeholder="{_esc(s["search_placeholder"])}" aria-label="{_esc(s["search_placeholder"])}">
</div>
<h2>{_esc(d["mcp_h"])}</h2>
{mcp_tbl}
<h2>{_esc(d["rest_h"])}</h2>
{rest_tbl}
<h2>{_esc(d["cli_h"])}</h2>
{cli_tbl}
<h2>{_esc(d["env_h"])}</h2>
{env_tbl}
"""


def _render_security(lang: str, s: dict) -> str:
    d = s["security"]
    pillars = "".join(
        f'<article class="card"><h3>{_esc(t)}</h3><p>{_inline_code(txt)}</p></article>'
        for t, txt in d["pillars"]
    )
    metrics_tbl = _table(
        ["Benchmark / Test", "Measured result"],
        [(f"<strong>{_esc(k)}</strong>", _inline_code(v)) for k, v in d["metrics_rows"]],
    )
    strict_cmd = (
        "export PADAM_STRICT=1\n"
        "export PADAM_MASK_PII=1\n"
        "python -m padam protect-keys\n"
        "python -m padam doctor"
    )
    return f"""
<section class="hero">
  <h1>{_esc(d["title"])}</h1>
  <p class="lead">{_esc(d["lead"])}</p>
</section>
<h2>{_esc(d["pillars_h"])}</h2>
<div class="grid">{pillars}</div>
<h2>{_esc(d["metrics_h"])}</h2>
{metrics_tbl}
{_code_block(strict_cmd)}
"""


def _render_nocturne(lang: str, s: dict) -> str:
    d = s["nocturne"]
    lim_li = "".join(f"<li>{_inline_code(x)}</li>" for x in d["limiters"])
    kinds_tbl = _table(
        ["Kind", "Half-life", "Role"],
        [(f"<code>{_esc(k)}</code>", f"<strong>{_esc(hl)}</strong>", _inline_code(role)) for k, hl, role in KINDS_DATA],
    )
    l3_li = "".join(f"<li>{_inline_code(x)}</li>" for x in d["l3_steps"])
    l3_tbl = _table(
        ["Anchor", "Solana TX", "Arweave ID"],
        [
            (
                _esc(what),
                f'<a href="https://solscan.io/tx/{_esc(tx)}" rel="noopener noreferrer"><code>{_esc(tx[:14])}…</code></a>',
                f'<a href="https://arweave.net/{_esc(ar)}" rel="noopener noreferrer"><code>{_esc(ar[:14])}…</code></a>',
            )
            for what, tx, ar in L3_MAINNET_ROWS
        ],
    )
    l3_cmd = (
        "python -m padam sleep\n"
        "python -m padam l3 --dry-run\n"
        "python -m padam l3 --network devnet\n"
        "python -m padam l3-verify\n"
        "python -m padam forget <record_id> --with-derived --receipt deletion_proof.html"
    )
    return f"""
<section class="hero">
  <h1>{_esc(d["title"])}</h1>
  <p class="lead">{_esc(d["lead"])}</p>
</section>
<h2>{_esc(d["limiters_h"])}</h2>
<p>{_esc(d["limiters_desc"])}</p>
<div class="card"><ul>{lim_li}</ul></div>
<h2>{_esc(d["kinds_h"])}</h2>
<p>{_inline_code(d["kinds_desc"])}</p>
{kinds_tbl}
<h2>{_esc(d["l3_h"])}</h2>
<div class="card"><ol>{l3_li}</ol></div>
{_code_block(l3_cmd)}
<h2>{_inline_code(d["l3_live_h"])}</h2>
{l3_tbl}
"""


def _render_comparison(lang: str, s: dict) -> str:
    d = s["comparison"]
    rows = []
    for name, url, is_padam, c1, c2, c3, c4, c5, c6 in COMPETITORS_ROWS:
        link = f'<a href="{_esc(url)}" rel="noopener noreferrer"><strong>{_esc(name)}</strong></a>'
        cells = [c1, c2, c3, c4, c5, c6]
        formatted = []
        for c in cells:
            if not c:
                formatted.append(_esc(s["not_stated"]))
            elif is_padam:
                formatted.append(f'<span class="tag-yes">{_esc(s["yes"])}</span> · {_esc(c)}')
            else:
                formatted.append(_esc(c))
        rows.append((link, *formatted))
    comp_tbl = _table(d["cols"], rows)
    mem0_tbl = _table(
        ["System (BAAI/bge-small-en-v1.5)", "any@5", "any@10", "all@5", "all@10"],
        [
            ("<strong>PADAM 0.4.13</strong>", "94.7 %", "97.9 %", "<strong>86.2 %</strong>", "<strong>93.6 %</strong>"),
            ("mem0 2.2.1", "96.8 %", "98.9 %", "85.1 %", "91.5 %"),
        ],
    )
    return f"""
<section class="hero">
  <h1>{_esc(d["title"])}</h1>
  <p class="lead">{_esc(d["lead"])}</p>
</section>
{comp_tbl}
<h2>{_esc(d["mem0_h"])}</h2>
<p>{_esc(d["mem0_desc"])}</p>
{mem0_tbl}
"""


PAGE_RENDERERS = {
    "index.html": _render_overview,
    "quickstart.html": _render_quickstart,
    "reference.html": _render_reference,
    "security.html": _render_security,
    "nocturne-l3.html": _render_nocturne,
    "comparison.html": _render_comparison,
}


def render_page(lang: str, page: str) -> str:
    s = UI_STRINGS[lang]
    page_title = s["nav"][page]
    lang_pills = "".join(
        f'<a class="pill{" active" if lc == lang else ""}" data-set-lang="{lc}" href="../{lc}/{page}">{_esc(LANG_NAMES[lc])}</a>'
        for lc in LANGUAGES
    )
    # Python 3.10/3.11 do not allow a backslash inside an f-string expression, so the attribute lives in a variable.
    aria_current = 'aria-current="page" '
    nav_items = "".join(
        f'<li><a class="nav-link" {aria_current if p == page else ""}href="{p}">{_esc(s["nav"][p])}</a></li>'
        for p in PAGES
    )
    body_html = PAGE_RENDERERS[page](lang, s)
    return f"""<!DOCTYPE html>
<html lang="{_esc(lang)}" data-theme="dark" data-copy-label="{_esc(s["copy"])}" data-copied-label="{_esc(s["copied"])}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {CSP_META}
  <title>{_esc(page_title)} · PADAM · NOCTURNE</title>
  <link rel="icon" type="image/svg+xml" href="../assets/logo.svg">
  <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="index.html">
      <img src="../assets/logo.svg" alt="PADAM NOCTURNE">
      <span>PADAM · NOCTURNE<span class="brand-sub">{_esc(s["brand_sub"])}</span></span>
    </a>
    <div class="top-actions">
      <nav class="lang-pills" aria-label="{_esc(s["all_docs"])}">{lang_pills}</nav>
      <button id="theme-toggle" class="btn" type="button" data-dark-label="{_esc(s["theme_dark"])}" data-light-label="{_esc(s["theme_light"])}" aria-pressed="false">{_esc(s["theme_light"])}</button>
      <button id="menu-toggle" class="btn btn-menu" type="button" aria-expanded="false" aria-controls="docs-sidebar">{_esc(s["menu"])}</button>
    </div>
  </header>
  <div class="shell">
    <aside id="docs-sidebar" class="sidebar" aria-label="Docs navigation">
      <ul class="nav-list">{nav_items}</ul>
    </aside>
    <main>{body_html}</main>
  </div>
  <footer class="footer">
    <span>{_esc(s["footer_left"])}</span>
    <span>{_esc(s["footer_right"])}</span>
  </footer>
  <script src="../assets/site.js" defer></script>
</body>
</html>
"""


def render_root_index() -> str:
    cards = "".join(
        f'<a class="landing-card" data-set-lang="{lc}" href="./{lc}/index.html">{_esc(LANG_NAMES[lc])}</a>'
        for lc in LANGUAGES
    )
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {CSP_META}
  <title>PADAM · NOCTURNE Documentation</title>
  <link rel="icon" type="image/svg+xml" href="./assets/logo.svg">
  <link rel="stylesheet" href="./assets/style.css">
</head>
<body>
  <main class="landing">
    <img src="./assets/logo.svg" width="64" height="64" alt="PADAM NOCTURNE">
    <h1>PADAM · NOCTURNE 0.4.18</h1>
    <p class="lead">Self-defending local memory for AI agents · Select language</p>
    <div class="landing-grid">{cards}</div>
  </main>
  <script src="./assets/redirect.js" defer></script>
</body>
</html>
"""


def build_site(out_dir: Path = DEFAULT_OUT) -> list[Path]:
    """Собирает статический сайт документации в out_dir без внешних зависимостей."""
    assets_dir = out_dir / "assets"
    img_out = assets_dir / "images"
    assets_dir.mkdir(parents=True, exist_ok=True)
    img_out.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for rel, content in (
        (assets_dir / "style.css", STYLE_CSS),
        (assets_dir / "site.js", SITE_JS),
        (assets_dir / "redirect.js", REDIRECT_JS),
        (assets_dir / "logo.svg", LOGO_SVG),
        (out_dir / "index.html", render_root_index()),
    ):
        rel.write_text(content, encoding="utf-8", newline="\n")
        written.append(rel)

    for png_name in ("studio-overview.png", "studio-graph.png"):
        src = DOCS_DIR / "images" / png_name
        if src.exists():
            dst = img_out / png_name
            shutil.copy2(src, dst)
            written.append(dst)

    for lang in LANGUAGES:
        ldir = out_dir / lang
        ldir.mkdir(parents=True, exist_ok=True)
        for page in PAGES:
            target = ldir / page
            target.write_text(render_page(lang, page), encoding="utf-8", newline="\n")
            written.append(target)

    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build PADAM static docs site (4 languages, offline)")
    p.add_argument("--out", default=str(DEFAULT_OUT))
    args = p.parse_args(argv)
    files = build_site(Path(args.out))
    print(f"Built {len(files)} files in {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
