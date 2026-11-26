// PADAM · NOCTURNE Memory Guard — Manifest V3 Background Service Worker
// Отправляет выделенный текст и страницы в локальный PADAM REST API строго с origin: "external",
// чтобы веб-страница не могла подсунуть скрытый приказ (Prompt Injection) в активную память агента.

const DEFAULT_API_URL = 'http://127.0.0.1:8078';

async function getConfig() {
  const data = await chrome.storage.local.get(['apiUrl', 'apiToken', 'lang']);
  return {
    apiUrl: (data.apiUrl || DEFAULT_API_URL).replace(/\/+$/, ''),
    apiToken: data.apiToken || '',
    lang: data.lang || 'ru'
  };
}

async function saveExternalRecord(content, sourceTitle, sourceUrl) {
  const cfg = await getConfig();
  if (!cfg.apiToken) {
    throw new Error('NO_TOKEN');
  }
  const cleanText = String(content || '').trim();
  if (!cleanText) {
    throw new Error('EMPTY_TEXT');
  }
  const headerPrefix = sourceTitle
    ? `[${sourceTitle}] (${sourceUrl || 'web'}): `
    : `(${sourceUrl || 'web'}): `;
  const payload = {
    content: (headerPrefix + cleanText).slice(0, 8000),
    kind: 'fact',
    origin: 'external',
    scope: 'browser'
  };

  const resp = await fetch(`${cfg.apiUrl}/write`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${cfg.apiToken}`
    },
    body: JSON.stringify(payload)
  });
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(body.error || `HTTP ${resp.status}`);
  }
  await updateReviewBadge();
  return body;
}

async function updateReviewBadge() {
  try {
    const cfg = await getConfig();
    const headers = {};
    if (cfg.apiToken) {
      headers['Authorization'] = `Bearer ${cfg.apiToken}`;
    }
    const resp = await fetch(`${cfg.apiUrl}/stats`, { headers });
    if (!resp.ok) {
      await chrome.action.setBadgeText({ text: '' });
      return null;
    }
    const stats = await resp.json();
    const count = Number(stats.quarantined || 0);
    if (count > 0) {
      await chrome.action.setBadgeText({ text: count > 99 ? '99+' : String(count) });
      await chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
    } else {
      await chrome.action.setBadgeText({ text: '' });
    }
    return stats;
  } catch (err) {
    await chrome.action.setBadgeText({ text: '' });
    return null;
  }
}

function setupContextMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: 'padam-save-selection',
      title: chrome.i18n.getMessage('menuSaveSelection') || 'PADAM: Save selection to memory (for review)',  // 26.11: язык браузера, а не только русский
      contexts: ['selection']
    });
    chrome.contextMenus.create({
      id: 'padam-save-page',
      title: chrome.i18n.getMessage('menuSavePage') || 'PADAM: Save page to memory (for review)',
      contexts: ['page']
    });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  setupContextMenus();
  chrome.alarms.create('padam-badge-poll', { periodInMinutes: 1 });
  updateReviewBadge();
});

chrome.runtime.onStartup.addListener(() => {
  setupContextMenus();
  updateReviewBadge();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'padam-badge-poll') {
    updateReviewBadge();
  }
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  try {
    if (info.menuItemId === 'padam-save-selection' && info.selectionText) {
      await saveExternalRecord(info.selectionText, tab?.title || '', tab?.url || info.pageUrl || '');
    } else if (info.menuItemId === 'padam-save-page' && tab?.id) {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const sel = window.getSelection()?.toString()?.trim();
          const bodyText = (document.body?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 2000);
          return sel || bodyText || document.title;
        }
      });
      const extracted = results?.[0]?.result || tab.title || tab.url;
      await saveExternalRecord(extracted, tab.title || '', tab.url || '');
    }
  } catch (err) {
    console.warn('PADAM context menu save error:', err);
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.action === 'saveExternal') {
    saveExternalRecord(msg.content, msg.title, msg.url)
      .then((res) => sendResponse({ ok: true, result: res }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }
  if (msg?.action === 'refreshBadge') {
    updateReviewBadge()
      .then((stats) => sendResponse({ ok: true, stats }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});
