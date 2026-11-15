; Хуки NSIS-установщика PADAM · NOCTURNE Studio (14.2)
; Явно фиксирует описание встроенного локального Python runtime, реквизиты издателя CODE Eternal LLC
; в свойствах PE-файла и гарантирует чистые ярлыки с логотипом CODE на Рабочем столе и в меню «Пуск».

VIAddVersionKey "CompanyName" "CODE Eternal LLC"

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
