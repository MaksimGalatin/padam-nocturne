# PADAM · NOCTURNE Studio — Настольное приложение и установщик Windows (Г7 + Г8 + 14.3 + п. 1.1–1.5)

Настольное приложение **PADAM · NOCTURNE Studio** с каноническим векторным логотипом **CODE («две фигуры»)**, собственным окном без браузера и адресной строки (системный WebView2), значком в системном трее, нативными уведомлениями Windows при удержании подозрительных записей агента и встроенной средой Python 3.14.4 внутри установщика.

---

## 1. Установщик Windows `PADAM-Studio-Setup.exe` (Tauri v2 + NSIS)

Собранный установщик предоставляет привычную установку настольной программы на ПК без использования командной строки:

1. **Единая точка правды для версии (`1.1`):** версия установщика, исполняемого файла и заголовка окна (`PADAM · NOCTURNE Studio 0.4.18`) автоматически синхронизируется из `padam/__init__.py` (`__version__`) скриптами `desktop/build_windows_installer.ps1` и `desktop/tauri/build.rs`.
2. **Мастер установки в два шага (`1.2`):** выбор языка интерфейса (русский, английский, испанский, китайский) и папки установки, создание ярлыков **«PADAM Studio»** с нашей иконкой CODE на **Рабочем столе** и в **меню «Пуск»**, регистрация в системном списке **«Установка и удаление программ»** (`DisplayName = PADAM Studio`, `DisplayVersion = 0.4.18`, `Publisher = CODE Eternal LLC`) и чистое удаление через `uninstall.exe`.
3. **Собственное окно Studio (WebView2):** открывается в отдельном нативном окне без вкладок браузера и адресной строки, запоминает размер и положение на экране в `%LOCALAPPDATA%\PADAM Studio\window-state.json`.
4. **Встроенный Python 3.14.4 (`runtime/python.exe`):** приложение включает официальный интерпретатор Python 3.14.4 (`python-3.14.4-embed-amd64`), колёса `numpy`, `requests`, `cryptography` и пакет `padam` в открытой папке `runtime/` — пользователю не нужно устанавливать Python, Git или Visual Studio.
5. **Системный трей с логотипом CODE (`1.3`):** при нажатии на крестик `[X]` окно не убивает защиту памяти, а сворачивается в область уведомлений (трей). Меню значка в трее содержит:
   - **«На проверке: N»** — живой счётчик записей агентов, удерживаемых на проверке (клик сразу открывает окно Studio на вкладке «На проверке»);
   - **«Открыть PADAM Studio»** — разворачивает главное окно;
   - **«Сон NOCTURNE»** — запускает цикл консолидации памяти;
   - **«Выход»** — штатно останавливает локальный сервер и закрывает приложение.
6. **Нативные уведомления Windows (`Г8`, `1.3`):** когда агент пытается записать текст, похожий на скрытый приказ (инъекцию) или затрагивающий защищённые записи, и запись попадает в очередь «На проверку», приложение отправляет системное уведомление Windows (WinRT Toast):
   > **PADAM · NOCTURNE Studio**  
   > *Агент хотел записать похожее на приказ — проверь (на проверке: N)*
7. **Автозапуск по выбору владельца:** на вкладке **«Настройки»** в Studio добавлена галочка **«Запускать при входе в Windows (в трее)»** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PADAMStudio`, запускает приложение с флагом `--minimized`). По умолчанию автозапуск **выключен** — программа ничего не прописывает в автозагрузку без решения человека.

---

## 2. Что именно установщик кладёт на диск и почему не срабатывает антивирус (`1.4`)

В отличие от `PyInstaller --onefile` и самораспаковывающихся скриптов-дропперов (которые декодируют base64 или распаковывают `.dll`/`.pyd` во временную папку `%TEMP%\_MEI*` при каждом старте и вызывают срабатывание эвристики `IDP.Generic` в AVG/Avast), стандартный установщик **NSIS (`PADAM-Studio-Setup.exe`)** один раз раскладывает обычные файлы в пользовательскую папку программ:

| Путь назначения | Что именно кладётся | Назначение |
|---|---|---|
| `%LOCALAPPDATA%\Programs\PADAM Studio\padam-studio-desktop.exe` | Нативный бинарник Tauri v2 (Rust + системный WebView2) | Главное окно, системный трей и отправка уведомлений Windows |
| `%LOCALAPPDATA%\Programs\PADAM Studio\runtime\python.exe`, `python314.dll`, `*.pyd`, `*.dll` | Официальный дистрибутив `python-3.14.4-embed-amd64` с цифровой подписью **Python Software Foundation** | Локальный интерпретатор Python без самораспаковки в `%TEMP%` |
| `%LOCALAPPDATA%\Programs\PADAM Studio\runtime\Lib\site-packages\` | Зависимости `numpy`, `requests`, `cryptography` | Векторный поиск и шифрование AES-256-GCM / Ed25519 |
| `%LOCALAPPDATA%\Programs\PADAM Studio\runtime\app\padam\` | Исходный пакет `padam` | Локальный сервер защиты памяти (`127.0.0.1`) и интерфейс Studio |
| `%LOCALAPPDATA%\Programs\PADAM Studio\uninstall.exe` | Штатный деинсталлятор NSIS | Полное удаление файлов приложения, ярлыков и записи автозапуска |
| `%USERPROFILE%\Desktop\PADAM Studio.lnk` | Ярлык на Рабочем столе с логотипом CODE | Запуск одним двойным щелчком |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\PADAM Studio.lnk` | Ярлык в меню «Пуск» | Запуск из меню «Пуск» и поиска Windows |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\PADAM Studio` | Запись в «Установке и удалении программ» (`Publisher = CODE Eternal LLC`, `DisplayVersion = 0.4.18`) | Просмотр версии, издателя и удаление через Параметры Windows |
| `%LOCALAPPDATA%\PADAM Studio\window-state.json`, `desktop.log`, `server.log` | Состояние геометрии окна и журналы работы | Сохранение позиции окна между запусками |

---

## 3. Честное примечание о Windows SmartScreen и подписи кода (`14.3`, `1.4`)

Проект сознательно не приобретает коммерческий сертификат подписи кода (Microsoft Authenticode OV/EV) на текущем этапе:

- **Проверка `Get-AuthenticodeSignature`:** у `PADAM-Studio-Setup.exe` и `padam-studio-desktop.exe` статус подписи — `NotSigned` (это штатно до покупки сертификата; решение о покупке сертификата — за Архитектором), при этом встроенный `runtime\python.exe` имеет статус `Valid` (`CN=Python Software Foundation, O=Python Software Foundation, L=Beaverton, S=Oregon, C=US`).
- **Что увидит пользователь при первом запуске скачанного установщика:** поскольку `PADAM-Studio-Setup.exe` пока не подписан платным сертификатом Authenticode, фильтр **Windows SmartScreen** при первом запуске файла из интернета покажет стандартное синее окно предупреждения *«Система Windows защитила ваш компьютер»*. Чтобы продолжить установку, нажмите **«Подробнее» → «Выполнить в любом случае»** (*More info → Run anyway*).
- **Готовность сборочного конвейера к подписи:** шаг цифровой подписи `signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256` уже встроен в `desktop/build_windows_installer.ps1` и автоматически активируется при наличии переменной окружения `PADAM_SIGN_PFX`.
- **Локальная антивирусная проверка:** на рабочей машине сборка и установка проверены при активном антивирусе **AVG Antivirus** (`0` предупреждений).

---

## 4. Воспроизводимая сборка Windows, macOS и Linux (`1.5`)

- **Локальная сборка Windows:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File desktop\build_windows_installer.ps1 -SkipRuntime
  ```
- **Сборка для macOS (`.dmg`) и Linux (`.AppImage` / `.deb`):** описана в workflow GitHub Actions [`.github/workflows/desktop-build.yml`](../.github/workflows/desktop-build.yml) (запускается вручную через `workflow_dispatch`, синхронизирует версию из `padam/__init__.py` и выкладывает готовые установочные пакеты в артефакты прогона).
