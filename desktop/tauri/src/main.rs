#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, PhysicalPosition, PhysicalSize, Url, WebviewWindow, WindowEvent};
use tauri_plugin_updater::UpdaterExt;

fn auto_update_enabled() -> bool {
    matches!(
        env::var("PADAM_AUTO_UPDATE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn spawn_update_check(app_handle: AppHandle, ru: bool, install_allowed: bool) {
    tauri::async_runtime::spawn(async move {
        let updater = match app_handle.updater() {
            Ok(u) => u,
            Err(e) => {
                log_line(&format!("update_init_error={e}"));
                return;
            }
        };
        match updater.check().await {
            Ok(Some(update)) => {
                let ver = update.version.clone();
                log_line(&format!("update_available={ver}"));
                #[cfg(windows)]
                {
                    let title = if ru {
                        "PADAM · NOCTURNE Studio — доступно обновление"
                    } else {
                        "PADAM · NOCTURNE Studio — update available"
                    };
                    let body = if ru {
                        format!("Найдена подписанная версия {ver}. Выберите установку на GitHub Releases.")
                    } else {
                        format!("Signed release {ver} is available on GitHub Releases.")
                    };
                    let _ = tauri_winrt_notification::Toast::new(APP_IDENTIFIER)
                        .title(title)
                        .text1(&body)
                        .show();
                }
                if install_allowed
                    && matches!(
                        env::var("PADAM_AUTO_UPDATE_INSTALL").as_deref(),
                        Ok("1") | Ok("true")
                    )
                {
                    if let Err(e) = update.download_and_install(|_, _| {}, || {}).await {
                        log_line(&format!("update_install_error={e}"));
                    }
                }
            }
            Ok(None) => log_line("update_up_to_date"),
            Err(e) => log_line(&format!("update_check_error={e}")),
        }
    });
}

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const APP_IDENTIFIER: &str = "com.codeofdigitaleternity.padam.studio";
const PADAM_VERSION: &str = env!("PADAM_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WindowGeom {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    maximized: bool,
}

struct ServerGuard {
    child: Mutex<Option<Child>>,
    port: u16,
    token: String,
    stopping: AtomicBool,
}

impl ServerGuard {
    fn shutdown(&self) {
        if self.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = local_http_request(self.port, "POST", "/shutdown", &self.token, Some("{}"));
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut ch) = guard.take() {
                let deadline = Instant::now() + Duration::from_millis(1500);
                loop {
                    if let Ok(Some(_)) = ch.try_wait() {
                        break;
                    }
                    if Instant::now() >= deadline {
                        let _ = ch.kill();
                        let _ = ch.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
            }
        }
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn env_lang_override(cli_lang: Option<&str>) -> Option<String> {
    let raw = cli_lang
        .map(|s| s.to_string())
        .or_else(|| env::var("PADAM_LANG").ok())?;
    let low = raw.trim().to_ascii_lowercase();
    if low.is_empty() || low == "system" {
        return None;
    }
    for code in ["ru", "en", "es", "zh"] {
        if low.starts_with(code) {
            return Some(code.to_string());
        }
    }
    None
}

#[cfg(windows)]
fn is_russian_ui(cli_lang: Option<&str>) -> bool {
    if let Some(code) = env_lang_override(cli_lang) {
        return code == "ru";
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    let lang_id = unsafe { GetUserDefaultUILanguage() };
    (lang_id & 0x03ff) == 0x19
}

#[cfg(not(windows))]
fn is_russian_ui(cli_lang: Option<&str>) -> bool {
    if let Some(code) = env_lang_override(cli_lang) {
        return code == "ru";
    }
    env::var("LANG")
        .map(|v| v.to_ascii_lowercase().starts_with("ru"))
        .unwrap_or(false)
}

fn app_data_dir() -> PathBuf {
    let base = env::var_os("LOCALAPPDATA")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    let dir = base.join("PADAM Studio");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn log_line(msg: &str) {
    let path = app_data_dir().join("desktop.log");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{msg}");
    }
}

fn generate_token() -> String {
    let mut raw = [0u8; 24];
    getrandom::getrandom(&mut raw).expect("CSPRNG failure");
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    listener.local_addr().expect("local addr").port()
}

fn resolve_python_bin(app: &AppHandle) -> PathBuf {
    if let Ok(custom) = env::var("PADAM_PYTHON") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(res_dir) = app.path().resource_dir() {
        candidates.push(res_dir.join("runtime").join("python.exe"));
        candidates.push(res_dir.join("runtime").join("python3"));
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("runtime").join("python.exe"));
            candidates.push(dir.join("runtime").join("python3"));
        }
    }
    for cand in candidates {
        if cand.is_file() {
            return cand;
        }
    }
    PathBuf::from("python")
}

fn spawn_padam_server(
    app: &AppHandle,
    port: u16,
    token: &str,
    db_arg: Option<&str>,
) -> std::io::Result<Child> {
    let python_bin = resolve_python_bin(app);
    let log_path = app_data_dir().join("server.log");
    let stdout_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_path)
        .or_else(|_| {
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(app_data_dir().join(format!("server-{port}.log")))
        });
    let stderr_file = OpenOptions::new().create(true).append(true).open(&log_path);

    let mut cmd = Command::new(&python_bin);
    cmd.args([
        "-m",
        "padam.api",
        "--ui",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
    ]);
    cmd.env("PADAM_API_TOKEN", token);
    cmd.env("PADAM_ALLOW_SHUTDOWN", "1");
    if let Ok(exe) = env::current_exe() {
        cmd.env("PADAM_DESKTOP_EXE", exe);
    }
    if let Some(db) = db_arg {
        cmd.env("PADAM_DB", db);
    }
    if let Ok(f) = stdout_file {
        cmd.stdout(Stdio::from(f));
    } else {
        cmd.stdout(Stdio::null());
    }
    if let Ok(f) = stderr_file {
        cmd.stderr(Stdio::from(f));
    } else {
        cmd.stderr(Stdio::null());
    }
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    cmd.spawn()
}

fn local_http_request(
    port: u16,
    method: &str,
    path: &str,
    token: &str,
    json_body: Option<&str>,
) -> Option<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));

    let body_bytes = json_body.unwrap_or("").as_bytes();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n"
    );
    if !body_bytes.is_empty() || method == "POST" {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes).ok()?;
    }

    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let hdr_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..hdr_end]).ok()?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    Some((status, buf[hdr_end + 4..].to_vec()))
}

fn load_window_geometry() -> Option<WindowGeom> {
    let raw = fs::read_to_string(app_data_dir().join("window-state.json")).ok()?;
    let g: WindowGeom = serde_json::from_str(&raw).ok()?;
    if g.width < 390 || g.height < 640 || g.x < -3000 || g.y < -3000 {
        return None;
    }
    Some(g)
}

fn save_window_geometry(win: &tauri::Window) {
    if win.is_minimized().unwrap_or(false) {
        return;
    }
    let maximized = win.is_maximized().unwrap_or(false);
    let pos = win.outer_position().ok();
    let size = win.inner_size().ok();
    if let (Some(p), Some(s)) = (pos, size) {
        if s.width >= 390 && s.height >= 640 && p.x > -3000 && p.y > -3000 {
            let geom = WindowGeom {
                x: p.x,
                y: p.y,
                width: s.width,
                height: s.height,
                maximized,
            };
            if let Ok(txt) = serde_json::to_string_pretty(&geom) {
                let _ = fs::write(app_data_dir().join("window-state.json"), txt);
            }
        }
    }
}

fn save_webview_geometry(win: &WebviewWindow) {
    if win.is_minimized().unwrap_or(false) {
        return;
    }
    let maximized = win.is_maximized().unwrap_or(false);
    let pos = win.outer_position().ok();
    let size = win.inner_size().ok();
    if let (Some(p), Some(s)) = (pos, size) {
        if s.width >= 390 && s.height >= 640 && p.x > -3000 && p.y > -3000 {
            let geom = WindowGeom {
                x: p.x,
                y: p.y,
                width: s.width,
                height: s.height,
                maximized,
            };
            if let Ok(txt) = serde_json::to_string_pretty(&geom) {
                let _ = fs::write(app_data_dir().join("window-state.json"), txt);
            }
        }
    }
}

fn apply_saved_geometry(win: &WebviewWindow) {
    if let Some(g) = load_window_geometry() {
        let w = g.width.clamp(390, 3840);
        let h = g.height.clamp(640, 2160);
        let _ = win.set_size(PhysicalSize::new(w, h));
        if g.x >= -100 && g.y >= -100 && g.x < 3200 && g.y < 1800 {
            let _ = win.set_position(PhysicalPosition::new(g.x, g.y));
        }
        if g.maximized {
            let _ = win.maximize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DesktopIpcInfo {
    port: u16,
    token: String,
    pid: u32,
    version: String,
    #[serde(default)]
    session_id: u32,
    #[serde(default)]
    desktop_name: String,
}

#[cfg(windows)]
fn current_session_id() -> u32 {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn ProcessIdToSessionId(pid: u32, session_id: *mut u32) -> i32;
    }
    let mut sid: u32 = 0;
    unsafe {
        let pid = GetCurrentProcessId();
        let _ = ProcessIdToSessionId(pid, &mut sid as *mut u32);
    }
    sid
}

#[cfg(not(windows))]
fn current_session_id() -> u32 {
    0
}

#[cfg(windows)]
fn current_desktop_name() -> String {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThreadId() -> u32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn GetThreadDesktop(thread_id: u32) -> *mut std::ffi::c_void;
        fn GetUserObjectInformationW(
            obj: *mut std::ffi::c_void,
            index: i32,
            info: *mut std::ffi::c_void,
            len: u32,
            needed: *mut u32,
        ) -> i32;
    }
    const UOI_NAME: i32 = 2;
    unsafe {
        let hdesk = GetThreadDesktop(GetCurrentThreadId());
        if hdesk.is_null() {
            return "Default".to_string();
        }
        let mut buf: [u16; 128] = [0; 128];
        let mut needed: u32 = 0;
        let ok = GetUserObjectInformationW(
            hdesk,
            UOI_NAME,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            (buf.len() * 2) as u32,
            &mut needed as *mut u32,
        );
        if ok == 0 {
            return "Default".to_string();
        }
        let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let name = String::from_utf16_lossy(&buf[..nul]);
        if name.is_empty() { "Default".to_string() } else { name }
    }
}

#[cfg(not(windows))]
fn current_desktop_name() -> String {
    "Default".to_string()
}

#[cfg(windows)]
fn allow_foreground_for_pid(pid: u32) {
    #[link(name = "user32")]
    extern "system" {
        fn AllowSetForegroundWindow(pid: u32) -> i32;
    }
    if pid != 0 {
        unsafe {
            let _ = AllowSetForegroundWindow(pid);
        }
    }
}

#[cfg(not(windows))]
fn allow_foreground_for_pid(_pid: u32) {}

fn desktop_ipc_path() -> PathBuf {
    app_data_dir().join("desktop_ipc.json")
}

fn write_desktop_ipc(info: &DesktopIpcInfo) {
    if let Ok(txt) = serde_json::to_string(info) {
        let _ = fs::write(desktop_ipc_path(), txt);
    }
}

fn remove_desktop_ipc_if_mine() {
    let p = desktop_ipc_path();
    if let Ok(raw) = fs::read_to_string(&p) {
        if let Ok(info) = serde_json::from_str::<DesktopIpcInfo>(&raw) {
            if info.pid == std::process::id() {
                let _ = fs::remove_file(&p);
            }
        }
    }
}

fn send_desktop_ipc_command(info: &DesktopIpcInfo, cmd: &str) -> bool {
    let addr = format!("127.0.0.1:{}", info.port);
    let sock = match addr.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let mut stream = match TcpStream::connect_timeout(&sock, Duration::from_millis(700)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(700)));
    let line = format!("{} {}\n", info.token, cmd);
    if stream.write_all(line.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).contains("OK"),
        _ => false,
    }
}

fn try_handoff_to_running_instance(tab: Option<&str>, start_minimized: bool) -> bool {
    let raw = match fs::read_to_string(desktop_ipc_path()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let info: DesktopIpcInfo = match serde_json::from_str(&raw) {
        Ok(i) => i,
        Err(_) => return false,
    };
    if info.port == 0 || info.token.is_empty() {
        return false;
    }
    let cur_sid = current_session_id();
    let cur_desk = current_desktop_name();
    let same_desktop = info.session_id == cur_sid
        && !info.desktop_name.is_empty()
        && info.desktop_name.eq_ignore_ascii_case(&cur_desk);
    if info.version == PADAM_VERSION && same_desktop {
        allow_foreground_for_pid(info.pid);
        let cmd = if start_minimized {
            "PING".to_string()
        } else if let Some(t) = tab {
            format!("WAKE {t}")
        } else {
            "WAKE".to_string()
        };
        if send_desktop_ipc_command(&info, &cmd) {
            log_line(&format!(
                "single_instance_handoff pid={} sid={} desk={} cmd={}",
                info.pid, cur_sid, cur_desk, cmd
            ));
            return true;
        }
        return false;
    }
    if send_desktop_ipc_command(&info, "QUIT") {
        log_line(&format!("stopping_old_desktop old_ver={} new_ver={}", info.version, PADAM_VERSION));
        let deadline = Instant::now() + Duration::from_millis(2500);
        while Instant::now() < deadline {
            if !send_desktop_ipc_command(&info, "PING") {
                break;
            }
            std::thread::sleep(Duration::from_millis(80));
        }
    }
    false
}

fn spawn_desktop_ipc_listener(app: AppHandle, guard: Arc<ServerGuard>, token: String) {
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            log_line(&format!("ipc_bind_error={e}"));
            return;
        }
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(_) => return,
    };
    write_desktop_ipc(&DesktopIpcInfo {
        port,
        token: token.clone(),
        pid: std::process::id(),
        version: PADAM_VERSION.to_string(),
        session_id: current_session_id(),
        desktop_name: current_desktop_name(),
    });
    std::thread::spawn(move || {
        for stream_res in listener.incoming() {
            if guard.stopping.load(Ordering::SeqCst) {
                break;
            }
            let mut stream = match stream_res {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
            let mut buf = [0u8; 512];
            let n = match stream.read(&mut buf) {
                Ok(n) if n > 0 => n,
                _ => continue,
            };
            let line = String::from_utf8_lossy(&buf[..n]);
            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            if parts.is_empty() || parts[0] != token {
                let _ = stream.write_all(b"ERR\n");
                continue;
            }
            let cmd = parts.get(1).copied().unwrap_or("");
            match cmd {
                "PING" => {
                    let _ = stream.write_all(b"OK\n");
                }
                "WAKE" => {
                    let tab = parts.get(2).copied().map(|s| s.to_string());
                    let app_ui = app.clone();
                    let _ = app.run_on_main_thread(move || {
                        show_studio_window(&app_ui, tab.as_deref());
                    });
                    let _ = stream.write_all(b"OK\n");
                }
                "QUIT" => {
                    let _ = stream.write_all(b"OK\n");
                    remove_desktop_ipc_if_mine();
                    guard.shutdown();
                    app.exit(0);
                    break;
                }
                _ => {
                    let _ = stream.write_all(b"ERR\n");
                }
            }
        }
    });
}

fn show_studio_window(app: &AppHandle, tab: Option<&str>) {
    if let Some(win) = app.get_webview_window("main") {
        let v0 = win.is_visible().ok();
        let _ = win.set_skip_taskbar(false);
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_always_on_top(true);
        let _ = win.set_focus();
        let _ = win.set_always_on_top(false);
        save_webview_geometry(&win);
        let v1 = win.is_visible().ok();
        log_line(&format!("wake_window before={v0:?} after={v1:?}"));
        if let Some(t) = tab {
            let clean_tab: String = t
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !clean_tab.is_empty() {
                let js = format!("location.hash = '#tab={clean_tab}';");
                let _ = win.eval(&js);
            }
        }
    }
}

#[cfg(windows)]
fn send_quarantine_toast(count: u64, ru: bool) {
    let body = if ru {
        format!("Агент хотел записать похожее на приказ — проверь (на проверке: {count})")
    } else {
        format!("Agent write looked like a command — check review queue (held: {count})")
    };
    let primary = tauri_winrt_notification::Toast::new(APP_IDENTIFIER)
        .title("PADAM · NOCTURNE Studio")
        .text1(&body)
        .show();
    if let Err(err) = primary {
        log_line(&format!("toast_primary_error={err:?}"));
        let _ = tauri_winrt_notification::Toast::new(tauri_winrt_notification::Toast::POWERSHELL_APP_ID)
            .title("PADAM · NOCTURNE Studio")
            .text1(&body)
            .show();
    } else {
        log_line(&format!("toast_sent quarantined={count}"));
    }
}

#[cfg(not(windows))]
fn send_quarantine_toast(_count: u64, _ru: bool) {}

fn extract_quarantined_count(body: &[u8]) -> Option<u64> {
    let val: serde_json::Value = serde_json::from_slice(body).ok()?;
    val.get("stats")?.get("quarantined")?.as_u64()
}

struct CliArgs {
    minimized: bool,
    db: Option<String>,
    lang: Option<String>,
    tab: Option<String>,
    theme: Option<String>,
}

fn parse_cli_args() -> CliArgs {
    let mut args = CliArgs {
        minimized: false,
        db: None,
        lang: None,
        tab: None,
        theme: None,
    };
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--minimized" | "--tray" => args.minimized = true,
            "--db" => args.db = it.next(),
            "--lang" => args.lang = it.next(),
            "--tab" => args.tab = it.next(),
            "--theme" => args.theme = it.next(),
            _ => {}
        }
    }
    args
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        log_line(&format!("desktop_panic={info}"));
    }));
    let t0 = Instant::now();
    let cli = parse_cli_args();
    let start_minimized = cli.minimized;
    let db_arg = cli.db;
    let lang_override = env_lang_override(cli.lang.as_deref());
    let tab_override = cli.tab.filter(|s| {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    });
    if try_handoff_to_running_instance(tab_override.as_deref(), start_minimized) {
        return;
    }
    #[cfg(windows)]
    if env::var_os("WEBVIEW2_USER_DATA_FOLDER").is_none() {
        let desk_safe: String = current_desktop_name()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let wv_dir = app_data_dir().join(format!("EBWebView_s{}_{}", current_session_id(), desk_safe));
        let _ = fs::create_dir_all(&wv_dir);
        env::set_var("WEBVIEW2_USER_DATA_FOLDER", &wv_dir);
    }
    let theme_override = cli.theme.filter(|s| s == "light" || s == "dark");
    let ru = is_russian_ui(cli.lang.as_deref());
    let port = pick_free_port();
    let token = generate_token();

    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            let child = spawn_padam_server(app.handle(), port, &token, db_arg.as_deref())
                .map_err(|e| {
                    log_line(&format!("spawn_error={e}"));
                    e
                })?;

            let guard = Arc::new(ServerGuard {
                child: Mutex::new(Some(child)),
                port,
                token: token.clone(),
                stopping: AtomicBool::new(false),
            });
            app.manage(guard.clone());
            spawn_desktop_ipc_listener(app.handle().clone(), guard.clone(), token.clone());

            let review_label = if ru { "На проверке: 0" } else { "Pending review: 0" };
            let open_label = if ru { "Открыть PADAM Studio" } else { "Open PADAM Studio" };
            let sleep_label = if ru { "Сон NOCTURNE" } else { "Run NOCTURNE Sleep" };
            let update_label = if ru {
                "Проверить обновления"
            } else {
                "Check for Updates"
            };
            let quit_label = if ru { "Выход" } else { "Quit" };

            let review_item = MenuItem::with_id(app, "review", review_label, true, None::<&str>)?;
            let open_item = MenuItem::with_id(app, "open", open_label, true, None::<&str>)?;
            let sleep_item = MenuItem::with_id(app, "sleep", sleep_label, true, None::<&str>)?;
            let update_item = MenuItem::with_id(app, "update", update_label, true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItem::with_id(app, "quit", quit_label, true, None::<&str>)?;

            let tray_menu = Menu::with_items(
                app,
                &[
                    &review_item,
                    &open_item,
                    &sleep_item,
                    &update_item,
                    &sep,
                    &quit_item,
                ],
            )?;

            let icon = app
                .default_window_icon()
                .cloned()
                .expect("default window icon configured");

            let guard_menu = guard.clone();
            let review_for_sleep = review_item.clone();
            let tray = TrayIconBuilder::with_id("padam-tray")
                .icon(icon)
                .tooltip(format!("PADAM · NOCTURNE Studio {PADAM_VERSION}"))
                .menu(&tray_menu)
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray_icon, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_studio_window(tray_icon.app_handle(), None);
                    }
                })
                .on_menu_event(move |app_handle, event| match event.id.as_ref() {
                    "open" => show_studio_window(app_handle, None),
                    "review" => show_studio_window(app_handle, Some("review")),
                    "sleep" => {
                        let p = guard_menu.port;
                        let tk = guard_menu.token.clone();
                        let item_c = review_for_sleep.clone();
                        std::thread::spawn(move || {
                            let _ = local_http_request(p, "POST", "/sleep", &tk, Some("{}"));
                            if let Some((200, body)) =
                                local_http_request(p, "GET", "/overview", &tk, None)
                            {
                                if let Some(q) = extract_quarantined_count(&body) {
                                    let label = if ru {
                                        format!("На проверке: {q}")
                                    } else {
                                        format!("Pending review: {q}")
                                    };
                                    let _ = item_c.set_text(label);
                                }
                            }
                        });
                    }
                    "update" => spawn_update_check(app_handle.clone(), ru, true),
                    "quit" => {
                        guard_menu.shutdown();
                        app_handle.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            if let Some(win) = app.get_webview_window("main") {
                let _ = win.set_title(&format!("PADAM · NOCTURNE Studio {PADAM_VERSION}"));
                apply_saved_geometry(&win);
                if !start_minimized {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
                save_webview_geometry(&win);
            }

            // Фоновый поток ожидания /health, навигации на локальную Studio и наблюдения очереди (Г8)
            let app_bg = app.handle().clone();
            let guard_bg = guard.clone();
            let review_bg = review_item.clone();
            let tray_bg = tray.clone();
            let token_bg = token.clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(15);
                let mut healthy = false;
                while !guard_bg.stopping.load(Ordering::SeqCst) && Instant::now() < deadline {
                    if let Some((200, _)) = local_http_request(port, "GET", "/health", &token_bg, None)
                    {
                        healthy = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
                if healthy {
                    let ready_ms = t0.elapsed().as_millis();
                    log_line(&format!("startup_ready_ms={ready_ms} port={port}"));
                    if let Some(win) = app_bg.get_webview_window("main") {
                        let mut url_str = format!("http://127.0.0.1:{port}/studio#t={token_bg}");
                        if let Some(ref lg) = lang_override {
                            url_str.push_str(&format!("&lang={lg}"));
                        }
                        if let Some(ref tb) = tab_override {
                            url_str.push_str(&format!("&tab={tb}"));
                        }
                        if let Some(ref th) = theme_override {
                            url_str.push_str(&format!("&theme={th}"));
                        }
                        if let Ok(url) = Url::parse(&url_str) {
                            let _ = win.navigate(url);
                        }
                    }
                } else {
                    log_line("health_timeout_15s");
                }

                if auto_update_enabled() {
                    // 23.11.2026, слово Архитектора: «чтобы на ПК всегда подтягивалась новая версия».
                    // Установка при запуске — только если владелец сам задал PADAM_AUTO_UPDATE_INSTALL=1;
                    // без неё по-прежнему лишь уведомление. Версия проверяется подписью minisign из tauri.conf.json.
                    spawn_update_check(app_bg.clone(), ru, true);
                }

                let mut prev_quarantined: Option<u64> = None;
                while !guard_bg.stopping.load(Ordering::SeqCst) {
                    if let Some((200, body)) =
                        local_http_request(port, "GET", "/overview", &token_bg, None)
                    {
                        if let Ok(ov_val) = serde_json::from_slice::<serde_json::Value>(&body) {
                            if let Some(cmds) = ov_val.get("desktop_cmds").and_then(|v| v.as_array()) {
                                for cmd in cmds {
                                    if let Some(tab) = cmd.get("tab").and_then(|v| v.as_str()) {
                                        show_studio_window(&app_bg, Some(tab));
                                    }
                                    if let Some(js) = cmd.get("eval").and_then(|v| v.as_str()) {
                                        if let Some(win) = app_bg.get_webview_window("main") {
                                            let _ = win.eval(js);
                                        }
                                    }
                                    if let Some(wcmd) = cmd.get("window_cmd").and_then(|v| v.as_str()) {
                                        match wcmd {
                                            "hide" => {
                                                if let Some(win) = app_bg.get_webview_window("main") {
                                                    save_webview_geometry(&win);
                                                    let _ = win.hide();
                                                }
                                            }
                                            "restore" => show_studio_window(&app_bg, None),
                                            "toast" => {
                                                let q_val = cmd.get("count").and_then(|v| v.as_u64()).unwrap_or(1);
                                                send_quarantine_toast(q_val, ru);
                                            }
                                            "update" => spawn_update_check(app_bg.clone(), ru, true),
                                            "quit" => {
                                                guard_bg.shutdown();
                                                app_bg.exit(0);
                                                return;
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(q) = extract_quarantined_count(&body) {
                            let txt = if ru {
                                format!("На проверке: {q}")
                            } else {
                                format!("Pending review: {q}")
                            };
                            let tip = if ru {
                                format!("PADAM · NOCTURNE Studio (на проверке: {q})")
                            } else {
                                format!("PADAM · NOCTURNE Studio (held: {q})")
                            };
                            let _ = review_bg.set_text(txt);
                            let _ = tray_bg.set_tooltip(Some(tip));
                            if let Some(prev) = prev_quarantined {
                                if q > prev {
                                    send_quarantine_toast(q, ru);
                                }
                            }
                            prev_quarantined = Some(q);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(1500));
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::Moved(_) | WindowEvent::Resized(_) => save_window_geometry(window),
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                save_window_geometry(window);
                let _ = window.hide();
            }
            _ => {}
        })
        .build(tauri::generate_context!())
        .expect("error building PADAM Studio desktop app")
        .run(|app_handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit = event {
                remove_desktop_ipc_if_mine();
                if let Some(guard) = app_handle.try_state::<Arc<ServerGuard>>() {
                    guard.shutdown();
                }
            }
        });
}
