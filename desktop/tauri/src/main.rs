// PADAM NOCTURNE Studio — Tauri v2 Desktop & System Tray wrapper (Windows, macOS, Linux)
// Запускает локальный демон `python -m padam api` с одноразовым токеном владельца,
// выводит в системный трей статус памяти («память работает», последние записи, «удержано на проверку: N»)
// и открывает окно PADAM Studio без встроенного Chromium (системный WebView2 / WebKit).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Command, Stdio};

fn main() {
    let _child = Command::new("python")
        .args(["-m", "padam", "studio", "--no-browser"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    // В полной сборке Tauri v2 окно подключается к локальному URL с #token=<owner_token>
}
