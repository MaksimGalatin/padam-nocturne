# PADAM · NOCTURNE Memory Guard — Политика конфиденциальности расширения / Extension Privacy Policy

**Издатель / Publisher:** CODE Eternal LLC (Maksim Galatin, `contact@codeofdigitaleternity.com`)  
**Версия / Version:** 0.4.18  
**Лицензия / License:** AGPL-3.0-only

---

## 🇷🇺 Русский — Политика конфиденциальности

### 1. Какие данные читает расширение
Расширение **PADAM · NOCTURNE Memory Guard** НЕ ведёт фоновое наблюдение за историей браузера и НЕ читает содержимое посещаемых страниц автоматически. Чтение происходит **исключительно по явному действию пользователя**:
- при нажатии кнопки **«Сохранить выделенное в память»** или пункта контекстного меню `PADAM: Сохранить выделенное в память (на проверку)` — читается только выделенный пользователем фрагмент текста, заголовок вкладки (`document.title`) и её адрес (`tab.url`);
- при нажатии кнопки **«Сохранить текущую страницу»** — читается текстовая выжимка текущей активной вкладки (`activeTab`), заголовок и URL;
- при отправке быстрой заметки в окне расширения — читается только текст, введённый самим пользователем.

### 2. Куда отправляются данные
- Все данные передаются **исключительно на локальный сервер PADAM**, запущенный на компьютере самого пользователя по адресу петлевого интерфейса `http://127.0.0.1:<порт>` (или `http://localhost:<порт>`).
- Расширение **никогда не отправляет данные во внешние облака, сторонние API, аналитические сервисы или рекламные сети**.
- В `manifest.json` задана строгая политика `Content-Security-Policy` (`default-src 'none'; connect-src http://127.0.0.1:* http://localhost:*`), которая на уровне самого браузера технически блокирует любые сетевые запросы за пределы локального компьютера (`127.0.0.1` / `localhost`).

### 3. Защита от скрытых приказов (Prompt Injection)
Каждая запись, пришедшая из браузерного расширения (`Origin: chrome-extension://...` или `Origin: moz-extension://...`), принудительно помечается локальным сервером PADAM как `origin = "external"` и помещается в очередь проверки владельцем (`quarantined` / `На проверке`), чтобы ни одна веб-страница не могла внедрить скрытую инструкцию ИИ-агенту.

### 4. Хранение настроек
В локальном хранилище браузера (`chrome.storage.local`) на устройстве пользователя хранятся только 3 параметра:
- локальный адрес API (`apiUrl`, по умолчанию `http://127.0.0.1:8078`);
- локальный Bearer-токен сессии (`apiToken`);
- выбранный язык окна расширения (`lang`: `ru`, `en`, `es`, `zh`).

---

## 🇬🇧 English — Privacy Policy

### 1. What Data the Extension Reads
**PADAM · NOCTURNE Memory Guard** does NOT track your browsing history and does NOT read web pages in the background. It accesses page content **solely upon explicit user action**:
- when you click **"Save Highlighted Selection"** or the context menu item, it reads only the selected text, page title, and URL of the active tab (`activeTab`);
- when you click **"Save Current Page"**, it reads a plain-text excerpt of the active tab, its title, and URL;
- when you submit a quick note in the popup, it reads only the text you typed.

### 2. Where Data Is Sent
- All data is sent **exclusively to your own local PADAM server** running on your machine at `http://127.0.0.1:<port>` (or `http://localhost:<port>`).
- The extension **never transmits any data to external servers, cloud services, analytics providers, or third parties**.
- A strict `Content-Security-Policy` (`default-src 'none'; connect-src http://127.0.0.1:* http://localhost:*`) enforced by the browser guarantees that no network connection outside localhost can ever be made.

### 3. Protection Against Prompt Injection
Every record originating from the browser extension (`Origin: chrome-extension://...` or `Origin: moz-extension://...`) is forcibly tagged `origin = "external"` by the local PADAM server and held in the owner's review queue until explicitly approved.

---

## 🇪🇸 Español — Política de Privacidad

1. **Qué datos lee la extensión:** Solo lee el texto seleccionado o el resumen de la pestaña activa (`activeTab`) cuando el usuario pulsa explícitamente el botón de guardar o el menú contextual. No recopila historial de navegación ni telemetría.
2. **Adónde se envían los datos:** Exclusivamente al servidor local PADAM del propio usuario en `http://127.0.0.1` / `http://localhost`. La política `Content-Security-Policy` bloquea cualquier conexión externa.
3. **Protección:** Todo texto procedente del navegador recibe `origin = "external"` en el servidor y pasa por la cola de revisión del propietario.

---

## 🇨🇳 中文 — 隐私政策

1. **读取的数据：** 仅在用户主动点击“保存选中内容”或右键菜单时读取当前活动标签页（`activeTab`）的选中文本、标题与网址。不收集任何浏览历史或遥测数据。
2. **数据发送目标：** 仅发送至用户本机运行的 PADAM 本地服务（`http://127.0.0.1` / `http://localhost`）。严格的 `Content-Security-Policy` 在浏览器层面禁止任何外部网络连接。
3. **防注入保护：** 所有来自浏览器扩展的记录在服务端均强制标记为 `origin = "external"` 并进入所有者待审核队列。
