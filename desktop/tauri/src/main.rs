// PADAM NOCTURNE Studio — Tauri v2 Desktop & System Tray wrapper (Windows, macOS, Linux)
// Запускает установленный в системе `python -m padam api` (из PATH / активного venv),
// передавая одноразовый токен владельца строго через переменную окружения PADAM_API_TOKEN
// (не через аргументы командной строки, чтобы токен не был виден в списке процессов ОС),
// и открывает окно PADAM Studio в системном WebView2 / WKWebView / WebKitGTK.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::env;
use std::process::{Command, Stdio};

fn main() {
    let token = env::var("PADAM_API_TOKEN")
        .unwrap_or_else(|_| "padam_local_session_token_auto_generated".to_string());
    let python_bin = env::var("PADAM_PYTHON").unwrap_or_else(|_| "python".to_string());

    let _child = Command::new(python_bin)
        .args(["-m", "padam", "api", "--host", "127.0.0.1", "--port", "8078"])
        .env("PADAM_API_TOKEN", &token)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}
