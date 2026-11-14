# -*- coding: utf-8 -*-
"""Сборка настольного приложения PADAMStudio.exe и установщика PADAMStudioSetup.exe под Windows.

Использует встроенный в Windows компилятор C# (csc.exe), не требует встроенного Chromium
и не требует внешних платных сертификатов.
"""
from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[2]
ICONS_DIR = ROOT / "desktop" / "icons"
WIN_DIR = ROOT / "desktop" / "windows"
DIST_DIR = WIN_DIR / "dist"


def generate_padam_ico() -> Path:
    ICONS_DIR.mkdir(parents=True, exist_ok=True)
    ico_path = ICONS_DIR / "padam.ico"
    img = Image.new("RGBA", (64, 64), (11, 15, 23, 255))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle((4, 4, 60, 60), radius=14, fill=(17, 24, 39, 255), outline=(0, 210, 255, 255), width=3)
    draw.ellipse((14, 14, 50, 50), outline=(0, 210, 255, 255), width=3)
    draw.ellipse((24, 24, 40, 40), fill=(168, 85, 247, 255))
    img.save(ico_path, format="ICO", sizes=[(64, 64), (32, 32), (16, 16)])
    return ico_path


def find_csc() -> Path:
    candidates = [
        Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
        Path(r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"),
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError("Компилятор csc.exe не найден")


def build_executables() -> tuple[Path, Path]:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    ico_path = generate_padam_ico()
    csc = find_csc()

    app_exe = DIST_DIR / "PADAMStudio.exe"
    cs_file = WIN_DIR / "PADAMStudio.cs"

    cmd_app = [
        str(csc),
        "/nologo",
        "/target:exe",
        f"/out:{app_exe}",
        f"/win32icon:{ico_path}",
        "/r:System.dll",
        "/r:System.Drawing.dll",
        "/r:System.Windows.Forms.dll",
        str(cs_file),
    ]
    subprocess.run(cmd_app, check=True)

    # Генерируем установщик PADAMStudioSetup.exe со встроенным бинарником PADAMStudio.exe
    payload_b64 = base64.b64encode(app_exe.read_bytes()).decode("ascii")
    setup_cs = WIN_DIR / "PADAMStudioSetup.cs"
    setup_code = f"""using System;
using System.IO;
using System.Diagnostics;

class PadamInstaller {{
    private const string PAYLOAD = "{payload_b64}";
    static int Main(string[] args) {{
        string targetDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PADAMStudio");
        bool runSelfTest = false;
        for (int i = 0; i < args.Length; i++) {{
            if (args[i] == "--install-dir" && i + 1 < args.Length) targetDir = args[++i];
            else if (args[i] == "--verify") runSelfTest = true;
        }}
        Directory.CreateDirectory(targetDir);
        string exePath = Path.Combine(targetDir, "PADAMStudio.exe");
        byte[] raw = Convert.FromBase64String(PAYLOAD);
        File.WriteAllBytes(exePath, raw);
        Console.WriteLine("INSTALLED_TO=" + exePath + " BYTES=" + raw.Length);
        if (runSelfTest) {{
            Process p = Process.Start(exePath, "--self-test");
            p.WaitForExit(15000);
            return p.ExitCode;
        }}
        return 0;
    }}
}}
"""
    setup_cs.write_text(setup_code, encoding="utf-8")
    setup_exe = DIST_DIR / "PADAMStudioSetup.exe"
    cmd_setup = [
        str(csc),
        "/nologo",
        "/target:exe",
        f"/out:{setup_exe}",
        f"/win32icon:{ico_path}",
        str(setup_cs),
    ]
    subprocess.run(cmd_setup, check=True)
    return app_exe, setup_exe


if __name__ == "__main__":
    app_exe, setup_exe = build_executables()
    print(f"Built app:   {app_exe} ({app_exe.stat().st_size} bytes)")
    print(f"Built setup: {setup_exe} ({setup_exe.stat().st_size} bytes)")
