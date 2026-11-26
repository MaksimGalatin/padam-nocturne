; Хуки NSIS-установщика PADAM · NOCTURNE Studio (14.2)
; Явно фиксирует описание встроенного локального Python runtime, реквизиты издателя CODE Eternal LLC
; в свойствах PE-файла и гарантирует чистые ярлыки с логотипом CODE на Рабочем столе и в меню «Пуск».

VIAddVersionKey "CompanyName" "CODE Eternal LLC"

!macro NSIS_HOOK_PREINSTALL
  ; 26.11.2026: фоновый python.exe Studio держит .pyd в runtime, и копирование падает с
  ; «Невозможно открыть файл для записи». Закрываем ТОЛЬКО процессы, запущенные из папки
  ; runtime этой установки (по полному пути) — чужие python.exe не трогаются.
  DetailPrint "Останавливаю фоновый процесс PADAM Studio…"
  nsExec::Exec `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$$r = [IO.Path]::GetFullPath('$INSTDIR\runtime') + '\'; Get-Process -ErrorAction SilentlyContinue | Where-Object { $$_.Path -and $$_.Path.StartsWith($$r, [StringComparison]::OrdinalIgnoreCase) } | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 700"`
  Pop $0
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Создаём / обновляем ярлык на Рабочем столе с нашим логотипом CODE
  CreateShortCut "$DESKTOP\PADAM Studio.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "" "$INSTDIR\${MAINBINARYNAME}.exe" 0
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  Delete "$DESKTOP\PADAM Studio.lnk"
  Delete "$SMPROGRAMS\PADAM Studio.lnk"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PADAMStudio"
  RMDir /r "$INSTDIR\runtime"
!macroend
