"""MCP Apps (ui://padam/*): изолированные интерактивные HTML-интерфейсы без внешних зависимостей."""
from __future__ import annotations

import json
from datetime import datetime, timezone

MCP_APP_MIME = "text/html;profile=mcp-app"
UI_CSP_META = {
    "ui": {
        "prefersBorder": True,
        "csp": {
            "connectDomains": [],
            "resourceDomains": [],
        },
    }
}

UI_RESOURCES = [
    {
        "uri": "ui://padam/review-queue",
        "name": "Interactive review queue (MCP App)",
        "title": "Интерактивная очередь проверки / Review queue UI",
        "description": "Self-contained HTML view for inspecting quarantined memory records and calling padam_review.",
        "mimeType": MCP_APP_MIME,
        "annotations": {"audience": ["user"], "priority": 0.88, "lastModified": "2026-11-15T00:00:00Z"},
        "_meta": UI_CSP_META,
    }
]

UI_RESOURCE_TEMPLATES = [
    {
        "uriTemplate": "ui://padam/graph/{id}",
        "name": "Interactive memory graph (MCP App)",
        "title": "Интерактивный граф памяти / Memory graph UI",
        "description": "Self-contained SVG neighborhood explorer for a memory record and its typed relations.",
        "mimeType": MCP_APP_MIME,
        "annotations": {"audience": ["user"], "priority": 0.82, "lastModified": "2026-11-15T00:00:00Z"},
        "_meta": UI_CSP_META,
    }
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def list_ui_resources(*, ts: str | None = None) -> list[dict]:
    mod_ts = ts or _now_iso()
    return [
        {**res, "annotations": {**res["annotations"], "lastModified": mod_ts}}
        for res in UI_RESOURCES
    ]


def list_ui_templates(*, ts: str | None = None) -> list[dict]:
    mod_ts = ts or _now_iso()
    return [
        {**tpl, "annotations": {**tpl["annotations"], "lastModified": mod_ts}}
        for tpl in UI_RESOURCE_TEMPLATES
    ]


def safe_json_for_script(obj) -> str:
    """Экранирует <, >, & чтобы данные памяти никогда не вышли из <script type='application/json'>."""
    return (
        json.dumps(obj, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


_BASE_STYLE = """
:root{color-scheme:light dark;--bg:#f8fafc;--card:#ffffff;--fg:#0f172a;--muted:#64748b;--border:#e2e8f0;--accent:#2563eb;--ok:#15803d;--bad:#b91c1c;--pill:#eff6ff}
@media(prefers-color-scheme:dark){:root{--bg:#0b1120;--card:#111827;--fg:#f1f5f9;--muted:#94a3b8;--border:#1f2937;--accent:#60a5fa;--ok:#4ade80;--bad:#f87171;--pill:#1e293b}}
html[data-theme="dark"]{--bg:#0b1120;--card:#111827;--fg:#f1f5f9;--muted:#94a3b8;--border:#1f2937;--accent:#60a5fa;--ok:#4ade80;--bad:#f87171;--pill:#1e293b}
html[data-theme="light"]{--bg:#f8fafc;--card:#ffffff;--fg:#0f172a;--muted:#64748b;--border:#e2e8f0;--accent:#2563eb;--ok:#15803d;--bad:#b91c1c;--pill:#eff6ff}
*{box-sizing:border-box}
body{margin:0;padding:16px;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
.hdr{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.hdr h1{margin:0;font-size:16px;font-weight:600}
.muted{color:var(--muted);font-size:12px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:10px}
.row{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:var(--pill);font-size:11px;font-weight:600}
.btn{border:1px solid var(--border);background:var(--card);color:var(--fg);padding:6px 12px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600}
.btn.ok{border-color:var(--ok);color:var(--ok)}
.btn.bad{border-color:var(--bad);color:var(--bad)}
.btn:disabled{opacity:.5;cursor:default}
pre.txt{margin:8px 0;padding:8px;border-radius:6px;background:var(--bg);border:1px solid var(--border);white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,Consolas,monospace;font-size:12px}
"""

_MCP_BRIDGE_JS = """
const _pending = new Map();
let _rpcId = 1;
function mcpCall(method, params) {
  const id = _rpcId++;
  return new Promise((resolve, reject) => {
    _pending.set(id, { resolve, reject });
    try {
      window.parent.postMessage({ jsonrpc: "2.0", id, method, params: params || {} }, "*");
    } catch (e) {
      _pending.delete(id);
      reject(e);
    }
    setTimeout(() => {
      if (_pending.has(id)) {
        _pending.delete(id);
        resolve({ queued: true, id });
      }
    }, 8000);
  });
}
window.addEventListener("message", (ev) => {
  const msg = ev && ev.data;
  if (!msg || typeof msg !== "object") return;
  if (msg.method === "ui/notifications/host-context-changed" && msg.params && msg.params.theme) {
    document.documentElement.setAttribute("data-theme", msg.params.theme === "dark" ? "dark" : "light");
  }
  if (msg.id != null && _pending.has(msg.id)) {
    const h = _pending.get(msg.id);
    _pending.delete(msg.id);
    if (msg.error) h.reject(msg.error);
    else h.resolve(msg.result);
  }
});
try { window.parent.postMessage({ jsonrpc: "2.0", method: "ui/initialize", params: { app: "padam-mcp-app", version: "1.0" } }, "*"); } catch (_) {}
"""

_REVIEW_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PADAM Review Queue</title>
<style>__BASE_STYLE__</style>
</head>
<body>
<div class="hdr">
  <div>
    <h1>PADAM Review Queue</h1>
    <div id="summary" class="muted"></div>
  </div>
  <button id="refreshBtn" class="btn" type="button">Refresh</button>
</div>
<div id="list"></div>
<script id="padam-data" type="application/json">__PAYLOAD__</script>
<script>
__MCP_BRIDGE_JS__
const data = JSON.parse(document.getElementById("padam-data").textContent || "{}");
const rows = Array.isArray(data.records) ? data.records : [];
const listEl = document.getElementById("list");
const sumEl = document.getElementById("summary");
sumEl.textContent = rows.length + " held record(s) awaiting owner decision";

async function reviewAction(action, id, cardEl, statusEl) {
  const btns = cardEl.querySelectorAll("button");
  btns.forEach(b => b.disabled = true);
  statusEl.textContent = "Sending " + action + "...";
  try {
    await mcpCall("tools/call", { name: "padam_review", arguments: { action, id } });
    statusEl.textContent = action === "approve" ? "Approved" : "Rejected";
  } catch (err) {
    statusEl.textContent = "Error: " + (err && err.message ? err.message : String(err));
    btns.forEach(b => b.disabled = false);
  }
}

if (!rows.length) {
  const empty = document.createElement("div");
  empty.className = "card muted";
  empty.textContent = "Review queue is empty.";
  listEl.appendChild(empty);
} else {
  for (const r of rows) {
    const card = document.createElement("div");
    card.className = "card";
    const top = document.createElement("div");
    top.className = "row";
    const meta = document.createElement("div");
    for (const label of [r.kind, r.scope, r.origin]) {
      const b = document.createElement("span");
      b.className = "badge";
      b.style.marginRight = "6px";
      b.textContent = label;
      meta.appendChild(b);
    }
    const ts = document.createElement("span");
    ts.className = "muted";
    ts.textContent = r.id + " · " + r.created_at;
    top.appendChild(meta);
    top.appendChild(ts);

    const reason = document.createElement("div");
    reason.className = "muted";
    reason.style.marginTop = "6px";
    reason.textContent = "Reason: " + (r.reason || "held for review");

    const pre = document.createElement("pre");
    pre.className = "txt";
    pre.textContent = r.content;

    const actions = document.createElement("div");
    actions.className = "row";
    const btns = document.createElement("div");
    const okBtn = document.createElement("button");
    okBtn.className = "btn ok";
    okBtn.type = "button";
    okBtn.textContent = "Approve";
    const badBtn = document.createElement("button");
    badBtn.className = "btn bad";
    badBtn.type = "button";
    badBtn.style.marginLeft = "6px";
    badBtn.textContent = "Reject";
    const status = document.createElement("span");
    status.className = "muted";
    okBtn.addEventListener("click", () => reviewAction("approve", r.id, card, status));
    badBtn.addEventListener("click", () => reviewAction("reject", r.id, card, status));
    btns.appendChild(okBtn);
    btns.appendChild(badBtn);
    actions.appendChild(btns);
    actions.appendChild(status);

    card.appendChild(top);
    card.appendChild(reason);
    card.appendChild(pre);
    card.appendChild(actions);
    listEl.appendChild(card);
  }
}
document.getElementById("refreshBtn").addEventListener("click", () => {
  mcpCall("resources/read", { uri: "ui://padam/review-queue" });
});
</script>
</body>
</html>
"""

_GRAPH_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PADAM Memory Graph</title>
<style>
__BASE_STYLE__
.layout{display:grid;grid-template-columns:1fr 260px;gap:12px}
@media(max-width:700px){.layout{grid-template-columns:1fr}}
svg{width:100%;height:360px;background:var(--card);border:1px solid var(--border);border-radius:10px}
</style>
</head>
<body>
<div class="hdr">
  <div>
    <h1>PADAM Graph Explorer</h1>
    <div id="gmeta" class="muted"></div>
  </div>
  <select id="relFilter" class="btn" aria-label="Filter relation"></select>
</div>
<div class="layout">
  <svg id="canvas" viewBox="0 0 640 360" role="img" aria-label="Memory graph"></svg>
  <div class="card">
    <div class="muted" style="margin-bottom:6px">Selected node</div>
    <div id="selId" class="badge"></div>
    <div id="selMeta" class="muted" style="margin-top:6px"></div>
    <pre id="selText" class="txt"></pre>
    <button id="openBtn" class="btn" type="button">Inspect node</button>
  </div>
</div>
<script id="padam-graph" type="application/json">__PAYLOAD__</script>
<script>
__MCP_BRIDGE_JS__
const payload = JSON.parse(document.getElementById("padam-graph").textContent || "{}");
const nodes = Array.isArray(payload.nodes) ? payload.nodes : [];
const edges = Array.isArray(payload.edges) ? payload.edges : [];
const centerId = String(payload.center_id || "");
document.getElementById("gmeta").textContent = "center=" + centerId + " · " + nodes.length + " node(s) · " + edges.length + " edge(s)";

const relSel = document.getElementById("relFilter");
const rels = ["all", ...Array.from(new Set(edges.map(e => e.relation || "related")))];
for (const r of rels) {
  const o = document.createElement("option");
  o.value = r;
  o.textContent = "relation: " + r;
  relSel.appendChild(o);
}

const pos = new Map();
const cx = 320, cy = 180;
const others = nodes.filter(n => n.id !== centerId);
pos.set(centerId, { x: cx, y: cy });
others.forEach((n, idx) => {
  const ang = (2 * Math.PI * idx) / Math.max(1, others.length);
  const rad = 125;
  pos.set(n.id, { x: Math.round(cx + rad * Math.cos(ang)), y: Math.round(cy + rad * Math.sin(ang)) });
});

let selected = nodes.find(n => n.id === centerId) || nodes[0] || { id: centerId, kind: "", scope: "", status: "", content: "" };
function showSelected(n) {
  selected = n;
  document.getElementById("selId").textContent = n.id;
  document.getElementById("selMeta").textContent = n.kind + " · " + n.scope + " · " + n.status;
  document.getElementById("selText").textContent = n.content;
}

const NS = "http://www.w3.org/2000/svg";
function draw() {
  const svg = document.getElementById("canvas");
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  const f = relSel.value;
  for (const e of edges) {
    if (f !== "all" && e.relation !== f) continue;
    const a = pos.get(e.src), b = pos.get(e.dst);
    if (!a || !b) continue;
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
    line.setAttribute("stroke", "#94a3b8"); line.setAttribute("stroke-width", "1.5");
    svg.appendChild(line);
    const lbl = document.createElementNS(NS, "text");
    lbl.setAttribute("x", Math.round((a.x + b.x) / 2));
    lbl.setAttribute("y", Math.round((a.y + b.y) / 2) - 4);
    lbl.setAttribute("fill", "#64748b");
    lbl.setAttribute("font-size", "10");
    lbl.setAttribute("text-anchor", "middle");
    lbl.textContent = e.relation;
    svg.appendChild(lbl);
  }
  for (const n of nodes) {
    const p = pos.get(n.id);
    if (!p) continue;
    const g = document.createElementNS(NS, "g");
    g.style.cursor = "pointer";
    const c = document.createElementNS(NS, "circle");
    c.setAttribute("cx", p.x); c.setAttribute("cy", p.y);
    c.setAttribute("r", n.id === centerId ? "22" : "16");
    c.setAttribute("fill", n.id === centerId ? "#2563eb" : "#334155");
    c.setAttribute("stroke", n.id === selected.id ? "#f59e0b" : "#cbd5e1");
    c.setAttribute("stroke-width", "2");
    const t = document.createElementNS(NS, "text");
    t.setAttribute("x", p.x); t.setAttribute("y", p.y + 30);
    t.setAttribute("fill", "currentColor");
    t.setAttribute("font-size", "10");
    t.setAttribute("text-anchor", "middle");
    t.textContent = (n.content || n.id).slice(0, 20);
    g.appendChild(c); g.appendChild(t);
    g.addEventListener("click", () => { showSelected(n); draw(); });
    svg.appendChild(g);
  }
}
relSel.addEventListener("change", draw);
document.getElementById("openBtn").addEventListener("click", () => {
  if (selected && selected.id) mcpCall("resources/read", { uri: "ui://padam/graph/" + selected.id });
});
showSelected(selected);
draw();
</script>
</body>
</html>
"""


def render_review_queue_html(records: list[dict]) -> str:
    """Рендерит самодостаточную HTML-страницу очереди проверки карантина PADAM."""
    safe_rows = [
        {
            "id": str(r.get("id") or ""),
            "kind": str(r.get("kind") or "fact"),
            "scope": str(r.get("scope") or "global"),
            "origin": str(r.get("origin") or "agent"),
            "created_at": str(r.get("created_at") or "")[:19],
            "reason": str(r.get("reason") or r.get("quarantine_reason") or ""),
            "content": str(r.get("content") or ""),
        }
        for r in records
    ]
    payload_json = safe_json_for_script({"records": safe_rows})
    return (
        _REVIEW_TEMPLATE
        .replace("__BASE_STYLE__", _BASE_STYLE)
        .replace("__MCP_BRIDGE_JS__", _MCP_BRIDGE_JS)
        .replace("__PAYLOAD__", payload_json)
    )


def render_graph_html(center_id: str, safe_nodes: list[dict], edges: list[dict]) -> str:
    """Рендерит самодостаточный SVG-проводник графа вокруг center_id (карантин уже скрыт)."""
    nodes_clean = [
        {
            "id": str(n.get("id") or ""),
            "kind": str(n.get("kind") or "fact"),
            "scope": str(n.get("scope") or "global"),
            "status": str(n.get("status") or "active"),
            "content": str(n.get("content") or ""),
        }
        for n in safe_nodes
    ]
    edges_clean = [
        {
            "src": str(e.get("src") or ""),
            "dst": str(e.get("dst") or ""),
            "relation": str(e.get("relation") or "related"),
        }
        for e in edges
    ]
    payload_json = safe_json_for_script({"center_id": str(center_id), "nodes": nodes_clean, "edges": edges_clean})
    return (
        _GRAPH_TEMPLATE
        .replace("__BASE_STYLE__", _BASE_STYLE)
        .replace("__MCP_BRIDGE_JS__", _MCP_BRIDGE_JS)
        .replace("__PAYLOAD__", payload_json)
    )
