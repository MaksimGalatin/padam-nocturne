# -*- coding: utf-8 -*-
"""PADAM · NOCTURNE Studio — Настольный центр памяти и системный трей (А2).

Работает без встроенного Chromium и без неподписанных .exe-дропперов:
1. Поднимает локальный сервер Studio в потоке того же процесса (без скрытого запуска subprocess
   и без передачи секретного токена в аргументах командной строки).
2. При подключении к внешнему локальному серверу берёт токен исключительно из переменной
   окружения PADAM_API_TOKEN.
3. Показывает настольное окно центра памяти и иконку в панели задач / трее:
   - «🟢 Память PADAM работает (действующих: N)»
   - «🛡 Удержано на проверку: M»
   - Последние записи памяти (с обрезкой строго по границе слова)
   - Кнопки: «Открыть PADAM Studio» (браузер по умолчанию), «На проверку», «Сон NOCTURNE», «Выход».
4. По флагу `--create-shortcut <папка>` создаёт стандартный ярлык запуска (`uvx padam-nocturne studio`
   или `python -m padam desktop`) без записи исполняемых бинарников в AppData.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import urllib.request
import webbrowser
from pathlib import Path

from . import api, config
from .i18n import t
from .memory import Memory
from .store import Store

_AUTOSTART_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
_AUTOSTART_VALUE_NAME = "PADAMStudio"


def autostart_supported() -> bool:
    """Автозапуск в настройках поддерживается на Windows (реестр текущего пользователя)."""
    return sys.platform == "win32"


def autostart_command(exe_path: str | None = None) -> str:
    """Формирует команду запуска PADAM Studio в трее без токенов и лишних путей."""
    exe = (exe_path or os.environ.get("PADAM_DESKTOP_EXE") or "").strip()
    if exe:
        return f'"{exe}" --minimized'
    return f'"{sys.executable}" -m padam desktop'


def get_autostart(
    reg_path: str = _AUTOSTART_REG_PATH,
    value_name: str = _AUTOSTART_VALUE_NAME,
) -> bool:
    """Проверяет, включён ли автозапуск PADAM Studio для текущего пользователя Windows."""
    if not autostart_supported():
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return bool(str(val or "").strip())
    except OSError:
        return False


def set_autostart(
    enabled: bool,
    exe_path: str | None = None,
    reg_path: str = _AUTOSTART_REG_PATH,
    value_name: str = _AUTOSTART_VALUE_NAME,
) -> bool:
    """Включает или выключает автозапуск PADAM Studio в HKCU Run (по умолчанию выключен)."""
    if not autostart_supported():
        return False
    import winreg

    if enabled:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, autostart_command(exe_path))
        return True
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
    except FileNotFoundError:
        pass
    except OSError:
        return get_autostart(reg_path=reg_path, value_name=value_name)
    return False


def _save_bgra_png(width: int, height: int, bgra: bytes, out_path: Path) -> None:
    import struct
    import zlib

    raw_rows = bytearray()
    stride = width * 4
    for y in range(height):
        raw_rows.append(0)
        row = bgra[y * stride : (y + 1) * stride]
        for i in range(0, len(row), 4):
            b, g, r = row[i], row[i + 1], row[i + 2]
            raw_rows.extend((r, g, b, 255))

    def _chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", zlib.compress(bytes(raw_rows), 6))
        + _chunk(b"IEND", b"")
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(png)


def control_native_window(
    action: str = "inspect",
    out_path: str | None = None,
    rect: list[int] | None = None,
    pid: int | None = None,
) -> dict:
    """Управляет нативным окном PADAM Studio в текущем интерактивном десктопе Windows (PrintWindow / геометрия / трей)."""
    if sys.platform != "win32":
        return {"ok": False, "error": "win32 only"}

    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass

    class RECT(ctypes.Structure):
        _fields_ = [
            ("left", ctypes.c_long),
            ("top", ctypes.c_long),
            ("right", ctypes.c_long),
            ("bottom", ctypes.c_long),
        ]

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", ctypes.c_long),
            ("biHeight", ctypes.c_long),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", ctypes.c_long),
            ("biYPelsPerMeter", ctypes.c_long),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    target_pid = int(pid or os.getppid())
    candidates: list[dict] = []
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _cb(hwnd, lparam):
        w_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(w_pid))
        length = user32.GetWindowTextLengthW(hwnd)
        title = ""
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value
        if w_pid.value == target_pid or ("PADAM" in title and "Studio" in title):
            cls_buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls_buf, 256)
            rc = RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rc))
            w = rc.right - rc.left
            h = rc.bottom - rc.top
            candidates.append({
                "hwnd": int(hwnd),
                "pid": int(w_pid.value),
                "visible": bool(user32.IsWindowVisible(hwnd)),
                "title": title,
                "class": cls_buf.value,
                "rect": [int(rc.left), int(rc.top), int(w), int(h)],
            })
        return True

    user32.EnumWindows(WNDENUMPROC(_cb), 0)
    main_wins = [
        c for c in candidates
        if ("PADAM" in c["title"] or c["rect"][2] >= 350) and c["rect"][3] >= 350
    ]
    if not main_wins:
        return {"ok": False, "target_pid": target_pid, "candidates": candidates}

    main_wins.sort(key=lambda c: (c["visible"], "PADAM" in c["title"], c["rect"][2] * c["rect"][3]), reverse=True)
    win = main_wins[0]
    hwnd = wintypes.HWND(win["hwnd"])

    if action == "move_resize" and rect and len(rect) == 4:
        x, y, w, h = [int(v) for v in rect]
        user32.MoveWindow(hwnd, x, y, w, h, True)
        rc = RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rc))
        win["rect"] = [int(rc.left), int(rc.top), int(rc.right - rc.left), int(rc.bottom - rc.top)]
        return {"ok": True, "window": win}

    if action == "close_to_tray":
        user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
        return {"ok": True, "window": win}

    if action == "restore_from_tray":
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        user32.ShowWindow(hwnd, 5)  # SW_SHOW
        user32.SetForegroundWindow(hwnd)
        return {"ok": True, "window": win}

    if action == "capture" and out_path:
        if not win["visible"]:
            user32.ShowWindow(hwnd, 5)
        rc = RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rc))
        w = int(rc.right - rc.left)
        h = int(rc.bottom - rc.top)
        if w <= 0 or h <= 0:
            return {"ok": False, "error": f"invalid rect {w}x{h}"}
        hwnd_dc = user32.GetWindowDC(hwnd)
        mem_dc = gdi32.CreateCompatibleDC(hwnd_dc)
        bmp = gdi32.CreateCompatibleBitmap(hwnd_dc, w, h)
        old = gdi32.SelectObject(mem_dc, bmp)
        ok = user32.PrintWindow(hwnd, mem_dc, 2)  # PW_RENDERFULLCONTENT
        if not ok:
            user32.PrintWindow(hwnd, mem_dc, 0)
        bmi = BITMAPINFOHEADER()
        bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.biWidth = w
        bmi.biHeight = -h
        bmi.biPlanes = 1
        bmi.biBitCount = 32
        bmi.biCompression = 0
        buf = ctypes.create_string_buffer(w * h * 4)
        gdi32.GetDIBits(mem_dc, bmp, 0, h, buf, ctypes.byref(bmi), 0)
        gdi32.SelectObject(mem_dc, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mem_dc)
        user32.ReleaseDC(hwnd, hwnd_dc)
        dst = Path(out_path)
        _save_bgra_png(w, h, buf.raw, dst)
        return {"ok": True, "window": win, "width": w, "height": h, "bytes": dst.stat().st_size, "path": str(dst)}

    return {"ok": True, "window": win}


def truncate_at_word(text: str, max_len: int = 56) -> str:
    """Обрезает строку строго по границе слова и добавляет многоточие."""
    s = (text or "").strip()
    if len(s) <= max_len:
        return s
    cut = s.rfind(" ", 0, max_len)
    if cut < max_len // 2:
        cut = max_len
    return s[:cut].rstrip(" ,.;:—-") + "…"


def create_launcher_shortcut(target_dir: str | Path) -> Path:
    """Создаёт безопасный текстовый/командный ярлык запуска PADAM Studio без .exe-дроппера."""
    folder = Path(target_dir).expanduser().resolve()
    folder.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        # Стандартный интернет-ярлык / скрипт запуска через установленный пакет из PATH
        cmd_file = folder / "PADAM Studio.cmd"
        content = (
            "@echo off\r\n"
            "REM Запуск PADAM Studio через установленный в PATH пакет (uvx или python)\r\n"
            "where uvx >nul 2>nul\r\n"
            "if %ERRORLEVEL% EQU 0 (\r\n"
            "    uvx padam-nocturne desktop %*\r\n"
            ") else (\r\n"
            "    python -m padam desktop %*\r\n"
            ")\r\n"
        )
        cmd_file.write_text(content, encoding="utf-8")
        return cmd_file
    else:
        desktop_file = folder / "padam-studio.desktop"
        content = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=PADAM Studio\n"
            "Comment=Local-First Verifiable Memory for AI Agents\n"
            "Exec=python3 -m padam desktop\n"
            "Terminal=false\n"
            "Categories=Utility;Development;\n"
        )
        desktop_file.write_text(content, encoding="utf-8")
        return desktop_file


def fetch_studio_snapshot(base_url: str, token: str) -> dict:
    """Запрашивает сводку `/overview` и последние записи `/records` по заголовку Authorization."""
    headers = {"Authorization": f"Bearer {token}"}
    req_ov = urllib.request.Request(f"{base_url}/overview", headers=headers)
    with urllib.request.urlopen(req_ov, timeout=3) as resp:
        ov = json.loads(resp.read().decode("utf-8"))

    req_rec = urllib.request.Request(f"{base_url}/records?view=active&limit=6&offset=0", headers=headers)
    with urllib.request.urlopen(req_rec, timeout=3) as resp:
        recs = json.loads(resp.read().decode("utf-8")).get("records", [])

    st = ov.get("stats", {})
    recent_lines = [
        f"[{r.get('kind', 'fact')}] {truncate_at_word(r.get('content') or '', 54)}"
        for r in recs[:6]
    ]
    return {
        "active": int(st.get("active", 0)),
        "quarantined": int(st.get("quarantined", 0)),
        "conflicts": len(ov.get("conflicts", [])),
        "level": ov.get("doctor", {}).get("level", "green"),
        "recent": recent_lines,
    }


def run_desktop_gui(memory: Memory, port: int = 0, self_test: bool = False) -> int:
    """Запускает локальный сервер Studio в том же процессе и открывает настольное окно центра памяти."""
    srv, studio_link = api.make_studio_server(memory, port=port)
    actual_port = srv.server_address[1]
    token = api._state["token"]
    # Передаём токен только в переменную окружения текущего процесса, никогда не в argv
    os.environ["PADAM_API_TOKEN"] = token
    base_url = f"http://127.0.0.1:{actual_port}"

    server_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    server_thread.start()

    try:
        snap = fetch_studio_snapshot(base_url, token)
        if self_test:
            print(
                f"DESKTOP_SELF_TEST_OK port={actual_port} active={snap['active']} "
                f"review={snap['quarantined']} recent={len(snap['recent'])}",
                flush=True,
            )
            return 0

        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.title(t("PADAM · NOCTURNE Studio — Настольный центр памяти",
                     "PADAM · NOCTURNE Studio — Desktop Memory Center"))
        root.geometry("560x450")
        root.configure(bg="#0b0f17")
        root.resizable(False, False)

        ico_path = Path(__file__).resolve().parents[1] / "desktop" / "icons" / "padam.ico"
        if sys.platform == "win32" and ico_path.exists():
            try:
                root.iconbitmap(default=str(ico_path))
            except Exception:
                pass

        header = tk.Frame(root, bg="#111827", padx=18, pady=14)
        header.pack(fill="x")

        lbl_title = tk.Label(
            header,
            text=t("🟢 Память PADAM работает · Локальная защита активна",
                   "🟢 PADAM memory is running · Local protection active"),
            bg="#111827", fg="#38bdf8", font=("Segoe UI Semibold", 12, "bold"), anchor="w"
        )
        lbl_title.pack(fill="x")

        lbl_metrics = tk.Label(
            header, text="", bg="#111827", fg="#94a3b8", font=("Segoe UI", 10), anchor="w"
        )
        lbl_metrics.pack(fill="x", pady=(4, 0))

        lbl_held = tk.Label(
            root, text="", bg="#172033", fg="#fbbf24", font=("Segoe UI Semibold", 10, "bold"),
            padx=12, pady=8, anchor="w"
        )
        lbl_held.pack(fill="x", padx=18, pady=(12, 8))

        lbl_rec_head = tk.Label(
            root,
            text=t("Последние записи в памяти (только чтение, без выполнения скриптов):",
                   "Recent memory records (read-only plain text):"),
            bg="#0b0f17", fg="#e2e8f0", font=("Segoe UI", 10), anchor="w"
        )
        lbl_rec_head.pack(fill="x", padx=18)

        lst_recent = tk.Listbox(
            root, bg="#111827", fg="#f1f5f9", font=("Consolas", 9),
            highlightthickness=1, highlightbackground="#23304d", bd=0, height=9
        )
        lst_recent.pack(fill="both", expand=True, padx=18, pady=8)

        def open_studio(tab: str = "") -> None:
            url = studio_link if not tab else f"{base_url}/studio#t={token}&tab={tab}"
            webbrowser.open(url)

        def run_sleep() -> None:
            try:
                req = urllib.request.Request(
                    f"{base_url}/sleep",
                    data=b"{}",
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10).read()
                refresh_ui()
            except Exception as exc:
                messagebox.showwarning("PADAM Studio", str(exc))

        def refresh_ui() -> None:
            try:
                cur = fetch_studio_snapshot(base_url, token)
                lbl_metrics.config(
                    text=t(
                        f"Действующих записей: {cur['active']}   ·   Противоречий: {cur['conflicts']}   ·   Порт: {actual_port}",
                        f"Active records: {cur['active']}   ·   Conflicts: {cur['conflicts']}   ·   Port: {actual_port}",
                    )
                )
                lbl_held.config(
                    text=t(
                        f"🛡 Удержано на проверку: {cur['quarantined']} (внешние записи ждут решения)",
                        f"🛡 Held for review: {cur['quarantined']} (external writes waiting for owner)",
                    )
                )
                lst_recent.delete(0, tk.END)
                for line in cur["recent"]:
                    lst_recent.insert(tk.END, line)
            except Exception as exc:
                lbl_metrics.config(text=str(exc))
            root.after(5000, refresh_ui)

        # Контекстное меню (вызывается правым кликом по окну или из панели)
        ctx_menu = tk.Menu(root, tearoff=0, bg="#111827", fg="#f1f5f9", font=("Segoe UI", 9))
        ctx_menu.add_command(
            label=t("Открыть PADAM Studio", "Open PADAM Studio"),
            command=lambda: open_studio("")
        )
        ctx_menu.add_command(
            label=t("Очередь проверки", "Review Queue"),
            command=lambda: open_studio("review")
        )
        ctx_menu.add_command(
            label=t("Запустить сон NOCTURNE", "Run NOCTURNE Sleep"),
            command=run_sleep
        )
        ctx_menu.add_separator()
        ctx_menu.add_command(label=t("Выход", "Exit"), command=root.destroy)
        root.bind("<Button-3>", lambda ev: ctx_menu.tk_popup(ev.x_root, ev.y_root))

        btn_bar = tk.Frame(root, bg="#0b0f17")
        btn_bar.pack(fill="x", padx=18, pady=(4, 16))

        tk.Button(
            btn_bar,
            text=t("Открыть окно PADAM Studio", "Open PADAM Studio"),
            command=lambda: open_studio(""),
            bg="#0ea5e9", fg="#080d1a", font=("Segoe UI Semibold", 9, "bold"),
            relief="flat", padx=14, pady=8
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            btn_bar,
            text=t("На проверку", "Review Queue"),
            command=lambda: open_studio("review"),
            bg="#1e293b", fg="#fbbf24", font=("Segoe UI Semibold", 9),
            relief="flat", padx=14, pady=8
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            btn_bar,
            text=t("Сон NOCTURNE", "NOCTURNE Sleep"),
            command=run_sleep,
            bg="#1e293b", fg="#f1f5f9", font=("Segoe UI", 9),
            relief="flat", padx=14, pady=8
        ).pack(side="left")

        refresh_ui()
        root.mainloop()
        return 0
    finally:
        srv.shutdown()
        srv.server_close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="padam desktop")
    p.add_argument("--db", default=None)
    p.add_argument("--user", default="default")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--create-shortcut", default=None, help="создать ярлык запуска в указанной папке")
    a = p.parse_args(argv)

    if a.create_shortcut:
        out = create_launcher_shortcut(a.create_shortcut)
        print(f"SHORTCUT_CREATED={out}", flush=True)
        return 0

    user = a.user
    if user == "default" and a.db and str(a.db).lower().endswith("demo.db"):
        user = "demo_architect"
    mem = Memory(user_id=user, store=Store(a.db) if a.db else None)
    try:
        return run_desktop_gui(mem, port=a.port, self_test=a.self_test)
    finally:
        mem.close()


if __name__ == "__main__":
    sys.exit(main())
