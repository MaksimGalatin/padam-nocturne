# PADAM Studio для Apple (iPhone / iPad)

## Вариант 1 — Мгновенная установка без Xcode (PWA)
PADAM Studio уже содержит Apple PWA-манифест (`/manifest.webmanifest`) и иконки (`/icon-192.png`, `/icon-512.png`, `apple-touch-icon`):
1. Откройте `https://aifa.works/nocturne` (или локальный адрес Studio в сети) в **Safari** на iPhone/iPad.
2. Нажмите **Поделиться** -> **На экран «Домой»** — приложение установится с иконкой PADAM без App Store.

## Вариант 2 — Нативная сборка `.ipa` (macOS + Xcode)
> Примечание: сборка и подпись `.ipa` для Apple возможна только на macOS с Xcode (или в GitHub Actions на раннере `macos-15` через `.github/workflows/ios-ipa.yml`).

```bash
cd ios/PADAMStudio
brew install xcodegen
xcodegen generate
open PADAMStudio.xcodeproj
```
