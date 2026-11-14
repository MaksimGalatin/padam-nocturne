# Сборка автономного установщика Windows для PADAM · NOCTURNE Studio (14.2 Г7 + 14.3).
# Запускает бесплатный локальный тулчейн из E:\Tools (без установки VS на C:),
# собирает встроенный Python 3.14 runtime в desktop\tauri\runtime и NSIS-установщик.
# Шаг подписи кода выключен по умолчанию (14.3): активируется только при наличии PADAM_SIGN_PFX.

param(
    [string]$ToolsRoot = "E:\Tools",
    [switch]$SkipRuntime
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$TauriDir = Join-Path $RepoRoot "desktop\tauri"
$RuntimeDir = Join-Path $TauriDir "runtime"

$env:RUSTUP_HOME = Join-Path $ToolsRoot "rustup"
$env:CARGO_HOME = Join-Path $ToolsRoot "cargo"
$env:XWIN_CACHE_DIR = Join-Path $ToolsRoot "xwin"
$env:XWIN_ACCEPT_LICENSE = "yes"
$env:PATH = "$(Join-Path $ToolsRoot 'cargo\bin');$(Join-Path $ToolsRoot 'llvm\bin');$env:PATH"

if (-not $SkipRuntime) {
    $EmbedZip = Join-Path $ToolsRoot "downloads\python-3.14.4-embed-amd64.zip"
    if (-not (Test-Path $EmbedZip)) {
        New-Item -ItemType Directory -Force -Path (Split-Path $EmbedZip) | Out-Null
        curl.exe -fsSL -o $EmbedZip "https://www.python.org/ftp/python/3.14.4/python-3.14.4-embed-amd64.zip"
    }
    if (Test-Path $RuntimeDir) {
        Remove-Item -Recurse -Force $RuntimeDir
    }
    Expand-Archive -Path $EmbedZip -DestinationPath $RuntimeDir

    $PthFile = Join-Path $RuntimeDir "python314._pth"
    $Lines = Get-Content $PthFile | ForEach-Object {
        if ($_ -match "^#\s*import site") { "import site" } else { $_ }
    }
    $Lines += "Lib\site-packages"
    $Lines += "app"
    $Lines | Set-Content $PthFile -Encoding ASCII

    New-Item -ItemType Directory -Force -Path (Join-Path $RuntimeDir "Lib\site-packages"), (Join-Path $RuntimeDir "app") | Out-Null
    uv pip install --no-cache --target (Join-Path $RuntimeDir "Lib\site-packages") `
        --python-version 3.14 --python-platform x86_64-pc-windows-msvc `
        "numpy>=1.24" "requests>=2.33.0" "cryptography>=50.0.0"

    # Чистая копия пакета padam внутрь runtime\app\padam (без __pycache__)
    # Удаляем тестовые подпапки внутри site-packages (ускоряет установку NSIS)
    Get-ChildItem -Path (Join-Path $RuntimeDir "Lib\site-packages") -Recurse -Directory -Filter "tests" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    $PadamDst = Join-Path $RuntimeDir "app\padam"
    Copy-Item -Recurse -Force (Join-Path $RepoRoot "padam") $PadamDst
    Get-ChildItem -Path $PadamDst -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
}

Write-Output "[BUILD] Компиляция PADAM Studio (Tauri v2 + cargo-xwin, --jobs 8)..."
$env:CARGO_BUILD_JOBS = "8"
Push-Location $TauriDir
try {
    cargo tauri build --runner cargo-xwin --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$NsisOut = Get-ChildItem (Join-Path $TauriDir "target\x86_64-pc-windows-msvc\release\bundle\nsis") -Filter "*-setup.exe" | Select-Object -First 1
if (-not $NsisOut) {
    throw "Установщик NSIS *-setup.exe не найден!"
}

$OutCopy = Join-Path $RepoRoot "desktop\PADAM-Studio-Setup.exe"
Copy-Item -Force $NsisOut.FullName $OutCopy

# 14.3: Опциональный шаг подписи кода (выключен по умолчанию до покупки сертификата).
if ($env:PADAM_SIGN_PFX -and (Test-Path $env:PADAM_SIGN_PFX)) {
    Write-Output "[SIGN] Подпись установщика сертификатом $env:PADAM_SIGN_PFX..."
    signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f $env:PADAM_SIGN_PFX $OutCopy
} else {
    Write-Output "[14.3] Подпись кода отключена (сертификат не задан - SmartScreen ожидаем до подписи)."
}

$SizeMB = [math]::Round($NsisOut.Length / 1MB, 2)
Write-Output "BUILD_SUCCESS=$($OutCopy) SIZE_BYTES=$($NsisOut.Length) SIZE_MB=$SizeMB"
