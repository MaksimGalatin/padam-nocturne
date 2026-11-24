# Пошаговая инструкция по публикации расширения в магазинах (Chrome Web Store, Edge Add-ons, Firefox AMO)

Публикация выполняется Архитектором со своих официальных аккаунтов разработчика **CODE Eternal LLC**. Готовые проверенные архивы и снимки экрана уже собраны в репозитории:

- **Пакет для Chrome Web Store и Microsoft Edge Add-ons:**  
  `extensions/dist/padam-memory-guard-chromium.zip`
- **Пакет для Mozilla Firefox Add-ons (AMO):**  
  `extensions/dist/padam-memory-guard-firefox.zip`
- **Настоящие снимки экрана `1280×800` (3 шт.):**
  1. `extensions/screenshots/store_1_popup_ru.png` — окно расширения (4 языка, счётчик очереди проверки, логотип CODE) поверх локального центра памяти;
  2. `extensions/screenshots/store_2_capture_quarantine_en.png` — сохранение выделенного текста со страницы и перехват скрытого приказа (`origin=external`) в очередь проверки;
  3. `extensions/screenshots/store_3_studio_review_4langs.png` — просмотр и одобрение/отклонение удержанной записи из браузера в `PADAM · NOCTURNE Studio`.
- **Политика конфиденциальности:**  
  `extensions/PRIVACY.md` (можно указать прямую ссылку на файл `extensions/PRIVACY.md` в репозитории GitHub или на `https://aifa.works/privacy`).

---

## 1. Публикация в Chrome Web Store (Google Chrome / Brave / Vivaldi)

1. Откройте консоль разработчика Chrome Web Store: `https://chrome.google.com/webstore/devconsole`
2. Нажмите **«Новый элемент» (New item)** и загрузите файл `extensions/dist/padam-memory-guard-chromium.zip`.
3. На вкладке **«Описание в магазине» (Store listing)**:
   - Языки и названия автоматически подтянутся из `_locales/{en,ru,es,zh,zh_CN}/messages.json`.
   - Категория: **Productivity** (Продуктивность) или **Developer Tools** (Инструменты разработчика).
   - Загрузите 3 снимка `1280×800` из папки `extensions/screenshots/`.
4. На вкладке **«Конфиденциальность» (Privacy practices)**:
   - **Единственное назначение (Single purpose):** *«Сохранение выделенного текста и заметок с веб-страниц в локальную защищённую память ИИ-агентов PADAM (127.0.0.1) с проверкой владельцем»*.
   - **Обоснование разрешений (Permission justifications):**
     * `activeTab` и `scripting`: чтение выделенного фрагмента текста (`window.getSelection()`) или текста активной вкладки исключительно в момент нажатия кнопки пользователем;
     * `contextMenus`: добавление пунктов «Сохранить выделенное в память» в контекстное меню правой кнопки мыши;
     * `storage`: локальное сохранение адреса `http://127.0.0.1:8078`, Bearer-токена владельца и выбранного языка интерфейса;
     * `alarms`: обновление значка счётчика очереди проверки с локального сервера раз в минуту;
     * `host_permissions` (`http://127.0.0.1/*`, `http://localhost/*`): обращение к локальному серверу памяти PADAM на компьютере пользователя.
   - **Сбор данных (Data usage):** отметьте, что расширение **НЕ собирает и НЕ передаёт данные пользователя третьим лицам** (всё остаётся на `127.0.0.1`).
   - В поле URL политики конфиденциальности укажите ссылку на `PRIVACY.md`.
5. Нажмите **«Отправить на проверку» (Submit for review)**.

---

## 2. Публикация в Microsoft Edge Add-ons

1. Откройте Partner Center для Microsoft Edge: `https://partner.microsoft.com/dashboard/microsoftedge/overview`
2. Нажмите **Create new extension** и загрузите тот же архив `extensions/dist/padam-memory-guard-chromium.zip`.
3. Заполните карточку описания, приложите 3 снимка `1280×800` из `extensions/screenshots/` и ссылку на `extensions/PRIVACY.md`.
4. В разделе **Notes for certification** укажите:
   > *This extension connects to the user's local PADAM memory server (source-available, PADAM License 1.0) on `http://127.0.0.1:8078` (`pip install padam-nocturne && padam studio`). No external cloud servers are contacted.*
5. Нажмите **Publish**.

---

## 3. Публикация в Mozilla Add-ons (Firefox AMO)

1. Откройте Developer Hub Firefox Add-ons: `https://addons.mozilla.org/developers/`
2. Нажмите **Submit a New Add-on** → **On this site** (публикация в каталоге AMO) или **On your own** (подпись `.xpi` для самостоятельного распространения).
3. Загрузите архив `extensions/dist/padam-memory-guard-firefox.zip` (архив 0.8.0 собран `scripts/pack_browser_extensions.py` 23.11.2026, sha256 `a6c99cb5a961bd5f`; проверено `npx web-ext lint --source-dir extensions/firefox`: **0 errors, 0 notices, 0 warnings**; содержит `browser_specific_settings.gecko.id = "padam-memory-guard@codeofdigitaleternity.com"`, `strict_min_version = "140.0"` (Firefox для Android — `142.0`) и `data_collection_permissions.required = ["none"]`).
4. На вопрос **«Does your add-on require source code submission?»** выберите **No** (код в `background.js` и `popup.js` полностью читаемый, без минификации, обфускации и сборщиков).
5. Добавьте 3 снимка `1280×800` из `extensions/screenshots/` и отправьте на модерацию.

---

## 4. Публикация расширения VS Code и Open-VSX

1. Готовый пакет `.vsix` собран из `extensions/vscode-padam/` командой `npx @vscode/vsce package`:
   `extensions/dist/padam-nocturne-mcp-0.8.0.vsix` (0 предупреждений)
2. Visual Studio Marketplace (`https://marketplace.visualstudio.com/manage/publishers/code-eternal`): загрузите файл `.vsix` как новое расширение издателя `code-eternal`.
3. Open-VSX (`https://open-vsx.org/user-settings/tokens`, используется в Cursor, Windsurf и VSCodium):
   `npx ovsx publish extensions/dist/padam-nocturne-mcp-0.8.0.vsix -p <OPEN_VSX_TOKEN>`

## Support & Source Code

- ⭐ **Star PADAM NOCTURNE on GitHub:** https://github.com/MaksimGalatin/padam-nocturne
- ⭐ **Star AIfa Memory MCP (Cloud):** https://github.com/MaksimGalatin/aifa-memory-mcp
- Free 100% client-side MCP & Web SRI/CSP Scanner: https://aifa.works/shield
