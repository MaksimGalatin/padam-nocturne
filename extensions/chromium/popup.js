// PADAM · NOCTURNE Memory Guard — Popup UI (4 languages, 0 innerHTML)

const I18N = {
  ru: {
    sub: 'Защищённая память браузера',
    active: 'Действующих в памяти:',
    review: '🛡️ Удержано на проверку:',
    guard: 'Все записи из браузера получают метку origin: external и ждут вашего одобрения: веб-страница не может подсунуть скрытый приказ.',
    btnSel: 'Сохранить выделенное в память',
    btnPage: 'Сохранить текущую страницу',
    noteLabel: 'Быстрая заметка со страницы (origin: external):',
    notePlaceholder: 'Введите заметку для отправки на проверку…',
    btnNote: 'Отправить заметку в PADAM',
    connSummary: 'Настройки подключения к локальному PADAM',
    urlLabel: 'Адрес локального API:',
    tokenLabel: 'Токен владельца (Bearer):',
    btnSaveCfg: 'Сохранить',
    btnStudio: 'Открыть Studio',
    savedHeld: 'Отправлено в очередь проверки PADAM (origin: external).',
    cfgSaved: 'Настройки подключения сохранены.',
    noToken: 'Укажите токен владельца из padam studio / padam api.',
    noSelection: 'На странице нет выделенного текста.',
    errPrefix: 'Ошибка: '
  },
  en: {
    sub: 'Verifiable Browser Memory Guard',
    active: 'Active in memory:',
    review: '🛡️ Held for review:',
    guard: 'All browser captures are tagged origin: external and held for your approval so web pages cannot inject hidden instructions.',
    btnSel: 'Save Highlighted Selection',
    btnPage: 'Save Current Page',
    noteLabel: 'Quick note from this page (origin: external):',
    notePlaceholder: 'Type a note to send to the review queue…',
    btnNote: 'Send Note to PADAM',
    connSummary: 'Local PADAM Connection Settings',
    urlLabel: 'Local API URL:',
    tokenLabel: 'Owner Bearer Token:',
    btnSaveCfg: 'Save',
    btnStudio: 'Open Studio',
    savedHeld: 'Sent to PADAM review queue (origin: external).',
    cfgSaved: 'Connection settings saved.',
    noToken: 'Enter the owner token from padam studio / padam api.',
    noSelection: 'No text is currently highlighted on the page.',
    errPrefix: 'Error: '
  },
  es: {
    sub: 'Memoria protegida del navegador',
    active: 'Activos en memoria:',
    review: '🛡️ Retenidos para revisión:',
    guard: 'Todo lo guardado desde el navegador lleva origin: external y espera su aprobación para impedir órdenes ocultas.',
    btnSel: 'Guardar texto seleccionado',
    btnPage: 'Guardar página actual',
    noteLabel: 'Nota rápida de la página (origin: external):',
    notePlaceholder: 'Escriba una nota para enviar a revisión…',
    btnNote: 'Enviar nota a PADAM',
    connSummary: 'Ajustes de conexión a PADAM local',
    urlLabel: 'URL de API local:',
    tokenLabel: 'Token del propietario (Bearer):',
    btnSaveCfg: 'Guardar',
    btnStudio: 'Abrir Studio',
    savedHeld: 'Enviado a la cola de revisión de PADAM (origin: external).',
    cfgSaved: 'Ajustes guardados.',
    noToken: 'Introduzca el token de padam studio / padam api.',
    noSelection: 'No hay texto seleccionado en la página.',
    errPrefix: 'Error: '
  },
  zh: {
    sub: '浏览器受保护记忆守卫',
    active: '当前有效记忆：',
    review: '🛡️ 待审核暂扣记录：',
    guard: '来自浏览器的所有内容均标记为 origin: external 并进入待审核队列，网页无法注入隐藏指令。',
    btnSel: '保存选中内容到记忆',
    btnPage: '保存当前网页摘要',
    noteLabel: '来自当前网页的快速笔记 (origin: external)：',
    notePlaceholder: '输入笔记并发送至待审核队列…',
    btnNote: '发送笔记到 PADAM',
    connSummary: '本地 PADAM 连接设置',
    urlLabel: '本地 API 地址：',
    tokenLabel: '所有者令牌 (Bearer)：',
    btnSaveCfg: '保存设置',
    btnStudio: '打开 Studio',
    savedHeld: '已发送至 PADAM 待审核队列 (origin: external)。',
    cfgSaved: '连接设置已保存。',
    noToken: '请填写来自 padam studio / padam api 的所有者令牌。',
    noSelection: '当前页面未选中任何文本。',
    errPrefix: '错误：'
  }
};

const $ = (id) => document.getElementById(id);
let currentLang = 'ru';

function detectLang() {
  const nav = String(navigator.language || 'ru').toLowerCase();
  if (nav.startsWith('ru')) return 'ru';
  if (nav.startsWith('es')) return 'es';
  if (nav.startsWith('zh')) return 'zh';
  return 'en';
}

function applyLang(lang) {
  currentLang = I18N[lang] ? lang : 'ru';
  const S = I18N[currentLang];
  document.documentElement.lang = currentLang;
  $('t-sub').textContent = S.sub;
  $('t-active-label').textContent = S.active;
  $('t-review-label').textContent = S.review;
  $('t-guard-note').textContent = S.guard;
  $('t-btn-selection').textContent = S.btnSel;
  $('t-btn-page').textContent = S.btnPage;
  $('t-note-label').textContent = S.noteLabel;
  $('note-input').setAttribute('placeholder', S.notePlaceholder);
  $('t-btn-note').textContent = S.btnNote;
  $('t-conn-summary').textContent = S.connSummary;
  $('t-url-label').textContent = S.urlLabel;
  $('t-token-label').textContent = S.tokenLabel;
  $('btn-save-cfg').textContent = S.btnSaveCfg;
  $('btn-open-studio').textContent = S.btnStudio;

  for (const lg of ['ru', 'en', 'es', 'zh']) {
    const b = $(`lang-${lg}`);
    if (b) b.setAttribute('aria-pressed', String(lg === currentLang));
  }
}

function showMsg(text, ok = true) {
  const box = $('ext-msg');
  box.textContent = text || '';
  box.className = ok ? 'ext-msg msg-ok' : 'ext-msg msg-err';
}

async function getStoredConfig() {
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    return await chrome.storage.local.get(['apiUrl', 'apiToken', 'lang']);
  }
  return {
    apiUrl: localStorage.getItem('padam_ext_url') || 'http://127.0.0.1:8078',
    apiToken: localStorage.getItem('padam_ext_token') || '',
    lang: localStorage.getItem('padam_ext_lang') || detectLang()
  };
}

async function saveStoredConfig(cfg) {
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    await chrome.storage.local.set(cfg);
  } else {
    if (cfg.apiUrl !== undefined) localStorage.setItem('padam_ext_url', cfg.apiUrl);
    if (cfg.apiToken !== undefined) localStorage.setItem('padam_ext_token', cfg.apiToken);
    if (cfg.lang !== undefined) localStorage.setItem('padam_ext_lang', cfg.lang);
  }
}

async function refreshStats() {
  const cfg = await getStoredConfig();
  const apiUrl = (cfg.apiUrl || 'http://127.0.0.1:8078').replace(/\/+$/, '');
  const headers = {};
  if (cfg.apiToken) headers['Authorization'] = `Bearer ${cfg.apiToken}`;
  try {
    const resp = await fetch(`${apiUrl}/stats`, { headers });
    if (!resp.ok) return;
    const st = await resp.json();
    $('val-active').textContent = String(st.active || 0);
    $('val-review').textContent = String(st.quarantined || 0);
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({ action: 'refreshBadge' });
    }
  } catch (_e) {}
}

async function sendToPadam(content, title, url) {
  const S = I18N[currentLang];
  const cfg = await getStoredConfig();
  const apiUrl = ($('api-url').value || cfg.apiUrl || 'http://127.0.0.1:8078').replace(/\/+$/, '');
  const apiToken = ($('api-token').value || cfg.apiToken || '').trim();
  if (!apiToken) {
    showMsg(S.noToken, false);
    return;
  }
  const prefix = title ? `[${title}] (${url || 'web'}): ` : `(${url || 'web'}): `;
  const resp = await fetch(`${apiUrl}/write`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiToken}`
    },
    body: JSON.stringify({
      content: (prefix + String(content || '').trim()).slice(0, 8000),
      kind: 'fact',
      origin: 'external',
      scope: 'browser'
    })
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    showMsg(S.errPrefix + (data.error || `HTTP ${resp.status}`), false);
    return;
  }
  showMsg(S.savedHeld, true);
  await refreshStats();
}

for (const lg of ['ru', 'en', 'es', 'zh']) {
  $(`lang-${lg}`).onclick = async () => {
    applyLang(lg);
    await saveStoredConfig({ lang: lg });
  };
}

$('btn-save-cfg').onclick = async () => {
  const apiUrl = $('api-url').value.trim() || 'http://127.0.0.1:8078';
  const apiToken = $('api-token').value.trim();
  await saveStoredConfig({ apiUrl, apiToken });
  showMsg(I18N[currentLang].cfgSaved, true);
  await refreshStats();
};

$('btn-open-studio').onclick = async () => {
  const apiUrl = ($('api-url').value.trim() || 'http://127.0.0.1:8078').replace(/\/+$/, '');
  const apiToken = $('api-token').value.trim();
  const target = apiToken ? `${apiUrl}/studio#t=${encodeURIComponent(apiToken)}&tab=review` : `${apiUrl}/studio`;
  if (typeof chrome !== 'undefined' && chrome.tabs?.create) {
    chrome.tabs.create({ url: target });
  } else {
    window.open(target, '_blank', 'noopener');
  }
};

$('btn-save-note').onclick = async () => {
  const text = $('note-input').value.trim();
  if (!text) return;
  await sendToPadam(text, 'Browser Note', 'popup');
  $('note-input').value = '';
};

$('btn-save-selection').onclick = async () => {
  const S = I18N[currentLang];
  if (typeof chrome !== 'undefined' && chrome.tabs?.query && chrome.scripting?.executeScript) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    const res = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => window.getSelection()?.toString()?.trim() || ''
    });
    const sel = res?.[0]?.result || '';
    if (!sel) {
      showMsg(S.noSelection, false);
      return;
    }
    await sendToPadam(sel, tab.title || '', tab.url || '');
  } else {
    showMsg(S.noSelection, false);
  }
};

$('btn-save-page').onclick = async () => {
  if (typeof chrome !== 'undefined' && chrome.tabs?.query && chrome.scripting?.executeScript) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    const res = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => (document.body?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 2000) || document.title
    });
    const bodyText = res?.[0]?.result || tab.title || '';
    await sendToPadam(bodyText, tab.title || '', tab.url || '');
  }
};

(async () => {
  const cfg = await getStoredConfig();
  if (cfg.apiUrl) $('api-url').value = cfg.apiUrl;
  if (cfg.apiToken) $('api-token').value = cfg.apiToken;
  applyLang(cfg.lang || detectLang());
  await refreshStats();
})();
