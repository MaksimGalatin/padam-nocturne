# PADAM · NOCTURNE Studio — Настольное приложение (Desktop & System Tray)

Настольная оболочка для **PADAM Studio** без встроенного Chromium (не раздувает пакет до 150+ МБ, как Electron).

## 1. Два варианта сборки

1. **Кроссплатформенный каркас Tauri v2 (`desktop/tauri/`)** — для Windows, macOS и Linux на сборочных машинах с установленным инструментарием Rust (`rustc` + `cargo`). Использует системный WebView2 (Windows), WKWebView (macOS) и WebKitGTK (Linux).
2. **Родной легковесный бинарник Windows (`desktop/windows/PADAMStudio.cs`)** — собирается напрямую встроенным в Windows компилятором `csc.exe` (.NET Framework 4.x) без внешних компиляторов и без установки Rust:
   - `desktop/windows/dist/PADAMStudio.exe` (~25 КБ) — настольное окно управления + иконка в системном трее Windows (`NotifyIcon`).
   - `desktop/windows/dist/PADAMStudioSetup.exe` (~142 КБ) — автономный установщик под Windows (распаковывает `PADAMStudio.exe` в `%LOCALAPPDATA%\PADAMStudio` или указанный `--install-dir`).

## 2. Возможности системного трея и окна

- Показывает живой статус локального ядра: **`🟢 Память работает (действующих: N)`**.
- Предупреждает об очереди карантина: **`🛡 Удержано на проверку: M`**.
- Показывает последние записи памяти прямо в меню трея и в настольном окне (строго текстом, без выполнения скриптов).
- Кнопки быстрого действия:
  - **Открыть PADAM Studio** (открывает изолированное окно приложения `--app` с одноразовым токеном владельца `#token=...`).
  - **На проверку** (переход к очереди удержанных записей).
  - **Запустить сон NOCTURNE** (`POST /consolidate`).
  - **Выход** (корректно останавливает дочерний процесс API, если он был запущен приложением).

## 3. Сборка и проверка на Windows

```powershell
python desktop/windows/build_windows.py
desktop\windows\dist\PADAMStudio.exe --self-test
desktop\windows\dist\PADAMStudioSetup.exe --install-dir "$env:TEMP\padam_app" --verify
```

> **Примечание о подписи кода:** исполняемые файлы `PADAMStudio.exe` и `PADAMStudioSetup.exe` собираются локально и не подписаны платным сертификатом Authenticode / Apple Developer ID (при первом запуске на чужой машине Windows SmartScreen может показать стандартное предупреждение для неподписанных локальных сборок).
