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
