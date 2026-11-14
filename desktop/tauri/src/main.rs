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

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const APP_IDENTIFIER: &str = "com.codeofdigitaleternity.padam.studio";

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

#[cfg(windows)]
fn is_russian_ui() -> bool {
    if let Ok(val) = env::var("PADAM_LANG") {
        let low = val.trim().to_ascii_lowercase();
        if low.starts_with("ru") {
            return true;
        }
        if !low.is_empty() && low != "system" {
            return false;
        }
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    let lang_id = unsafe { GetUserDefaultUILanguage() };
    (lang_id & 0x03ff) == 0x19
}

#[cfg(not(windows))]
fn is_russian_ui() -> bool {
    env::var("PADAM_LANG")
        .or_else(|_| env::var("LANG"))
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
    let stdout_file = OpenOptions::new().create(true).write(true).truncate(true).open(&log_path);
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
        let _ = win.set_size(PhysicalSize::new(g.width, g.height));
        let _ = win.set_position(PhysicalPosition::new(g.x, g.y));
        if g.maximized {
            let _ = win.maximize();
        }
    }
}

fn show_studio_window(app: &AppHandle, tab: Option<&str>) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
        save_webview_geometry(&win);
        if let Some(t) = tab {
            let js = format!("location.hash = '#tab={t}';");
            let _ = win.eval(&js);
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
    if let Err(err) = tauri_winrt_notification::Toast::new(APP_IDENTIFIER)
        .title("PADAM · NOCTURNE Studio")
        .text1(&body)
        .show()
    {
        log_line(&format!("toast_error={err:?}"));
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

fn parse_cli_args() -> (bool, Option<String>) {
    let mut minimized = false;
    let mut db: Option<String> = None;
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--minimized" || arg == "--tray" {
            minimized = true;
        } else if arg == "--db" {
            db = it.next();
        }
    }
    (minimized, db)
}

fn main() {
    let t0 = Instant::now();
    let (start_minimized, db_arg) = parse_cli_args();
    let ru = is_russian_ui();
    let port = pick_free_port();
    let token = generate_token();

    tauri::Builder::default()
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

            let review_label = if ru { "На проверке: 0" } else { "Pending review: 0" };
            let open_label = if ru { "Открыть PADAM Studio" } else { "Open PADAM Studio" };
            let sleep_label = if ru { "Сон NOCTURNE" } else { "Run NOCTURNE Sleep" };
            let quit_label = if ru { "Выход" } else { "Quit" };

            let review_item = MenuItem::with_id(app, "review", review_label, true, None::<&str>)?;
            let open_item = MenuItem::with_id(app, "open", open_label, true, None::<&str>)?;
            let sleep_item = MenuItem::with_id(app, "sleep", sleep_label, true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItem::with_id(app, "quit", quit_label, true, None::<&str>)?;

            let tray_menu = Menu::with_items(
                app,
                &[&review_item, &open_item, &sleep_item, &sep, &quit_item],
            )?;

            let icon = app
                .default_window_icon()
                .cloned()
                .expect("default window icon configured");

            let guard_menu = guard.clone();
            let review_for_sleep = review_item.clone();
            let tray = TrayIconBuilder::with_id("padam-tray")
                .icon(icon)
                .tooltip("PADAM · NOCTURNE Studio")
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
                    "quit" => {
                        guard_menu.shutdown();
                        app_handle.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            if let Some(win) = app.get_webview_window("main") {
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
                        let url_str = format!("http://127.0.0.1:{port}/studio#t={token_bg}");
                        if let Ok(url) = Url::parse(&url_str) {
                            let _ = win.navigate(url);
                        }
                    }
                } else {
                    log_line("health_timeout_15s");
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
                if let Some(guard) = app_handle.try_state::<Arc<ServerGuard>>() {
                    guard.shutdown();
                }
            }
        });
}
