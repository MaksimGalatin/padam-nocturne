# PADAM · NOCTURNE Memory Guard — Расширение для Chrome и Edge (Manifest V3)

Локальное расширение браузера для сохранения выделенных фрагментов текста и веб-страниц в защищённую память **PADAM NOCTURNE**.

## Архитектура безопасности (`origin: external`)

В отличие от расширений конкурентов (например, mem0 Chrome Extension), которые пишут содержимое веб-страниц напрямую в активную память агента, **PADAM Memory Guard** маркирует каждую запись из браузера как **`origin: "external"`**:
1. Секреты (API-ключи, сид-фразы, токены) маскируются до записи на диск (`[REDACTED:...]`).
2. Запись попадает в очередь карантина **«На проверку»** (`PADAM_HOLD_EXTERNAL=1`), поэтому спрятанный на чужой странице приказ (Indirect Prompt Injection) **не может** попасть в контекст вашего ИИ-агента без вашего явного одобрения в **PADAM Studio**.
3. На иконке расширения отображается оранжевый значок (badge) с числом записей, ожидающих вашей проверки.

## Установка распакованного расширения (без публикации в магазине)

1. Запустите локальный сервер PADAM Studio:
   ```bash
   padam studio
   ```
   Скопируйте одноразовый токен из ссылки `#t=<токен>` (или задайте постоянный `PADAM_API_TOKEN`).
2. Откройте страницу управления расширениями:
   - В **Google Chrome**: `chrome://extensions`
   - В **Microsoft Edge**: `edge://extensions`
3. Включите переключатель **«Режим разработчика» (Developer mode)**.
4. Нажмите **«Загрузить распакованное расширение» (Load unpacked)** и выберите папку:
   ```text
   extensions/chromium
   ```
5. Нажмите на иконку **PADAM · NOCTURNE Memory Guard** в панели браузера, откройте блок «Настройки подключения к локальному PADAM», укажите адрес (`http://127.0.0.1:8078`) и токен владельца, затем нажмите **«Сохранить»**.

## Support & Open Source

- ⭐ **Star PADAM NOCTURNE on GitHub:** https://github.com/MaksimGalatin/padam-nocturne
- ⭐ **Star AIfa Memory MCP (Cloud):** https://github.com/MaksimGalatin/aifa-memory-mcp
- Free 100% client-side MCP & Web SRI/CSP Scanner: https://aifa.works/shield
