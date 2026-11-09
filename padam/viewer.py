"""Просмотр памяти в браузере: временная шкала записей и кнопки владельца.

Запуск: `padam viewer`. Сервер слушает только 127.0.0.1 и печатает одноразовую ссылку с токеном
во фрагменте адреса (#t=...): фрагмент не уходит ни в журнал сервера, ни в заголовок Referer.
Страница сама данных не содержит и берёт их через REST API с этим токеном, поэтому чужая
страница в том же браузере не может ни прочитать память, ни нажать «забыть» (см. api._trusted).

Текст памяти — чужие слова: он выводится только как текст (textContent), а заголовок CSP
запрещает странице всё внешнее, включая картинки, через которые утекают данные.
"""

from __future__ import annotations

import json
import secrets

from .i18n import t


def _strings() -> dict:
    return {
        "title": t("Память PADAM", "PADAM memory"),
        "active": t("Действующие", "Active"),
        "review": t("На проверке", "Waiting for you"),
        "history": t("История", "History"),
        "filter": t("Найти в тексте", "Filter by text"),
        "asof": t("Память на дату", "Memory as of"),
        "asof_query": t("о чём спросить на эту дату", "what to ask about that date"),
        "search": t("Искать", "Search"),
        "more": t("Показать ещё", "Show more"),
        "forget": t("Забыть", "Forget"),
        "forget_sure": t("Забыть навсегда — это не отменить", "Forget for good — cannot be undone"),
        "cancel": t("Отмена", "Cancel"),
        "approve": t("Принять", "Approve"),
        "reject": t("Отклонить", "Reject"),
        "restore": t("Вернуть", "Restore"),
        "no_token": t("Откройте ссылку, которую напечатала команда padam viewer.",
                      "Open the link printed by `padam viewer`."),
        "empty": t("Здесь пусто.", "Nothing here."),
        "done": t("Готово.", "Done."),
        "failed": t("Не получилось", "Failed"),
        "replaced": t("было верно тогда, позже заменено", "true then, replaced later"),
        "held_reason": t("почему на проверке", "why held"),
        "confidence": t("уверенность", "confidence"),
        "records": t("записей", "records"),
        "pending": t("эпизодов ждут сна", "episodes waiting for sleep"),
        "stale": t("векторов старой модели", "vectors from an older model"),
        "all_kinds": t("все виды", "all kinds"),
    }


_CSS = """
:root{--bg:#f7f6f2;--fg:#1d1d1f;--muted:#6b6b70;--card:#fff;--line:#e3e1da;--accent:#4a3aa8;--warn:#a8452f;
--ok:#2f7a4a;--chip:#eeecf9}
@media (prefers-color-scheme:dark){:root{--bg:#141417;--fg:#ececf0;--muted:#9a9aa3;--card:#1d1d22;--line:#2d2d34;
--accent:#a99cf2;--warn:#f08a70;--ok:#7fd3a0;--chip:#2a2740}}
*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header,nav,.tools,#kinds,main,#more{max-width:920px;margin:0 auto;padding:0 16px}
header{padding-top:20px;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:baseline}
h1{font-size:20px;margin:0}#stats{color:var(--muted);font-size:13px}
nav{display:flex;gap:6px;margin-top:14px;flex-wrap:wrap}
button{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:8px;
padding:5px 12px;cursor:pointer}button:hover{border-color:var(--accent)}
nav button[aria-pressed=true]{background:var(--accent);color:var(--bg);border-color:var(--accent)}
.tools{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
input{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:8px;
padding:5px 10px;min-width:0}#q{flex:1 1 220px}#asq{flex:1 1 200px}
#kinds{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
.chip{background:var(--chip);border:0;border-radius:999px;padding:2px 10px;font-size:13px}
.chip[aria-pressed=true]{outline:2px solid var(--accent)}
.day{margin:22px 0 6px;color:var(--muted);font-size:13px;letter-spacing:.04em;text-transform:uppercase}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:6px 0}
.meta{display:flex;flex-wrap:wrap;gap:4px 10px;font-size:12px;color:var(--muted)}
.text{white-space:pre-wrap;overflow-wrap:anywhere;margin:6px 0}
.bar{display:inline-block;width:60px;height:6px;background:var(--line);border-radius:3px;vertical-align:middle}
.bar i{display:block;height:6px;border-radius:3px;background:var(--accent)}
.acts{display:flex;flex-wrap:wrap;gap:6px}.danger{color:var(--warn);border-color:var(--warn)}
.note{color:var(--warn);font-size:13px}.ok{color:var(--ok)}#msg{min-height:1.5em;font-size:13px}
#more{display:block;margin:16px auto 40px}
"""

_JS = r"""
const S = JSON.parse(document.getElementById('strings').textContent);
let token = new URLSearchParams(location.hash.slice(1)).get('t');
try { if (token) sessionStorage.setItem('padam_t', token); else token = sessionStorage.getItem('padam_t'); } catch (e) {}
if (location.hash) history.replaceState(null, '', location.pathname);
const $ = id => document.getElementById(id);
let view = 'active', offset = 0, kindFilter = null, shown = [], keepMsg = false;

function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text; return e; }
async function api(path, body) {
  const r = await fetch(path, {method: body ? 'POST' : 'GET',
    headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
    body: body ? JSON.stringify(body) : undefined});
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.status);
  return data;
}
function say(text, good) { const m = $('msg'); m.textContent = text; m.className = good ? 'ok' : 'note'; }

function card(r) {
  const c = el('div', 'card');
  const meta = el('div', 'meta');
  meta.append(el('span', 'chip', r.kind), el('span', '', r.origin || ''), el('span', '', r.scope || ''),
              el('span', '', (r.created_at || '').slice(0, 16).replace('T', ' ')));
  if (typeof r.confidence === 'number') {
    const b = el('span', 'bar'); const i = el('i'); i.style.width = Math.round(r.confidence * 100) + '%';
    b.append(i); b.title = S.confidence + ' ' + r.confidence.toFixed(2); meta.append(b);
  }
  if (r.status && r.status !== 'active') meta.append(el('span', '', r.status));
  c.append(meta, el('div', 'text', r.content === null ? '—' : r.content));
  if (r.status === 'superseded' && view === 'asof') c.append(el('div', 'note', S.replaced));
  if (r.quarantine_reason && (r.status === 'quarantined' || r.status === 'rejected'))
    c.append(el('div', 'note', S.held_reason + ': ' + r.quarantine_reason));
  const acts = el('div', 'acts');
  const act = (label, path, cls) => { const b = el('button', cls || '', label);
    b.onclick = async () => { try { await api(path, {id: r.id}); say(S.done, true); keepMsg = true; load(true); }
                              catch (e) { say(S.failed + ': ' + e.message); } }; return b; };
  if (r.status === 'quarantined') acts.append(act(S.approve, '/approve'), act(S.reject, '/reject'));
  if (r.status === 'archived') acts.append(act(S.restore, '/restore'));
  if (r.status !== 'revoked') {
    const f = el('button', 'danger', S.forget);
    f.onclick = () => { f.hidden = true;
      const sure = act(S.forget_sure, '/forget', 'danger'); const no = el('button', '', S.cancel);
      no.onclick = () => { sure.remove(); no.remove(); f.hidden = false; }; acts.append(sure, no); };
    acts.append(f);
  }
  c.append(acts);
  return c;
}
function render() {
  const list = $('list'); list.replaceChildren();
  const rows = kindFilter ? shown.filter(r => r.kind === kindFilter) : shown;
  if (!rows.length) { list.append(el('p', 'note', S.empty)); return; }
  let day = '';
  for (const r of rows) {
    const d = (r.created_at || '').slice(0, 10);
    if (d !== day) { day = d; list.append(el('div', 'day', d)); }
    list.append(card(r));
  }
}
function kinds() {
  const box = $('kinds'); box.replaceChildren(); const counts = {};
  for (const r of shown) counts[r.kind] = (counts[r.kind] || 0) + 1;
  const chip = (k, label) => { const b = el('button', 'chip', label);
    b.setAttribute('aria-pressed', String(kindFilter === k)); b.onclick = () => { kindFilter = k; kinds(); render(); };
    return b; };
  box.append(chip(null, S.all_kinds));
  for (const [k, n] of Object.entries(counts).sort((a, b) => b[1] - a[1])) box.append(chip(k, k + ' · ' + n));
}
async function stats() {
  try { const s = await api('/stats');
    $('stats').textContent = s.active + ' ' + S.records + ' · ' + s.episodes_pending + ' ' + S.pending +
      (s.stale_vectors ? ' · ' + s.stale_vectors + ' ' + S.stale : '');
    $('tab-review').textContent = S.review + (s.quarantined ? ' · ' + s.quarantined : '');
  } catch (e) {}
}
async function load(reset) {
  if (!token) { say(S.no_token); return; }
  if (reset) { offset = 0; shown = []; }
  if (reset && !keepMsg) say('', true);
  keepMsg = false;
  try {
    if (view === 'asof' && $('asq').value.trim()) {
      const r = await api('/search', {query: $('asq').value.trim(), as_of: $('asof').value, limit: 50});
      shown = r.results; $('more').hidden = true;
    } else if (view === 'asof') {
      const r = await api('/records?as_of=' + encodeURIComponent($('asof').value) + '&limit=100&offset=' + offset);
      shown = shown.concat(r.records); offset += r.records.length; $('more').hidden = offset >= r.total;
    } else {
      const q = encodeURIComponent($('q').value.trim());
      const r = await api('/records?view=' + view + '&q=' + q + '&limit=100&offset=' + offset);
      shown = shown.concat(r.records); offset += r.records.length; $('more').hidden = offset >= r.total;
    }
    kinds(); render(); stats();
  } catch (e) { say(S.failed + ': ' + e.message); }
}
for (const v of ['active', 'review', 'history']) {
  $('tab-' + v).onclick = () => { view = v; kindFilter = null;
    for (const w of ['active', 'review', 'history']) $('tab-' + w).setAttribute('aria-pressed', String(w === v));
    load(true); };
}
$('q').oninput = () => { clearTimeout(window._qt); window._qt = setTimeout(() => load(true), 250); };
$('find').onclick = () => { if (!$('asof').value) return; view = 'asof'; kindFilter = null;
  for (const w of ['active', 'review', 'history']) $('tab-' + w).setAttribute('aria-pressed', 'false'); load(true); };
$('more').onclick = () => load(false);
load(true);
"""


def page() -> tuple[str, str]:
    """HTML страницы и nonce для заголовка CSP."""
    nonce = secrets.token_urlsafe(16)
    s = _strings()
    # JSON внутри <script>: «<» экранирован, чтобы строка не закрыла тег.
    данные = json.dumps(s, ensure_ascii=False).replace("<", "\\u003c")
    html = f"""<!doctype html>
<html lang="{t('ru', 'en')}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{s['title']}</title><style nonce="{nonce}">{_CSS}</style></head>
<body>
<header><h1>{s['title']}</h1><span id="stats"></span></header>
<nav>
<button id="tab-active" aria-pressed="true">{s['active']}</button>
<button id="tab-review" aria-pressed="false">{s['review']}</button>
<button id="tab-history" aria-pressed="false">{s['history']}</button>
</nav>
<div class="tools">
<input id="q" type="search" placeholder="{s['filter']}" aria-label="{s['filter']}">
<input id="asof" type="date" aria-label="{s['asof']}" title="{s['asof']}">
<input id="asq" type="search" placeholder="{s['asof_query']}" aria-label="{s['asof_query']}">
<button id="find">{s['search']}</button>
</div>
<div id="kinds"></div>
<main><div id="msg" role="status"></div><div id="list"></div></main>
<button id="more" hidden>{s['more']}</button>
<script id="strings" type="application/json" nonce="{nonce}">{данные}</script>
<script nonce="{nonce}">{_JS}</script>
</body></html>"""
    return html, nonce
