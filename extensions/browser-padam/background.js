// PADAM Nocturne MV3 service worker: strictly local loopback operation.
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["apiUrl"], (res) => {
    const val = String(res.apiUrl || "");
    if (!val.startsWith("http://127.0.0.1")) {
      chrome.storage.local.set({ apiUrl: "http://127.0.0.1:8787" });
    }
  });
});
