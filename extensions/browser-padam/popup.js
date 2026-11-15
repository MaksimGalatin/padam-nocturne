const ALLOWED_PREFIXES = ["http://127.0.0.1:", "http://127.0.0.1/", "http://localhost:", "http://localhost/"];

function assertLocalUrl(rawUrl) {
  const clean = String(rawUrl || "").trim().replace(/\/+$/, "");
  const ok = ALLOWED_PREFIXES.some((p) => clean.startsWith(p) || clean === p.slice(0, -1));
  if (!ok) {
    throw new Error("Blocked: only local 127.0.0.1/localhost endpoints are allowed.");
  }
  return clean;
}

function formatFencedContext(items) {
  const lines = (items || []).map((x) => `- [${x.kind || "fact"}] ${x.text || x.content || ""}`);
  return `<padam_context origin="local_padam">\n${lines.join("\n")}\n</padam_context>`;
}

async function callLocalApi(path, method, payload) {
  const apiUrl = assertLocalUrl(document.getElementById("apiUrl").value);
  const token = document.getElementById("token").value.trim();
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.set({ apiUrl, token });
  }

  const resp = await fetch(`${apiUrl}${path}`, {
    method,
    headers,
    body: payload ? JSON.stringify(payload) : undefined,
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return await resp.json();
}

document.addEventListener("DOMContentLoaded", () => {
  const out = document.getElementById("output");
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["apiUrl", "token"], (res) => {
      if (res.apiUrl) document.getElementById("apiUrl").value = res.apiUrl;
      if (res.token) document.getElementById("token").value = res.token;
    });
  }

  document.getElementById("askBtn").addEventListener("click", async () => {
    try {
      const q = document.getElementById("inputText").value.trim();
      const data = await callLocalApi("/ask", "POST", { q, limit: 5 });
      out.textContent = formatFencedContext(data.items || data.memories || []);
    } catch (err) {
      out.textContent = `Error: ${err.message}`;
    }
  });

  document.getElementById("saveBtn").addEventListener("click", async () => {
    try {
      const text = document.getElementById("inputText").value.trim();
      const data = await callLocalApi("/remember", "POST", { text, origin: "browser_extension" });
      out.textContent = `Saved: ${JSON.stringify(data)}`;
    } catch (err) {
      out.textContent = `Error: ${err.message}`;
    }
  });

  document.getElementById("copyBtn").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(out.textContent);
    } catch (err) {
      out.textContent = `Copy error: ${err.message}`;
    }
  });
});
