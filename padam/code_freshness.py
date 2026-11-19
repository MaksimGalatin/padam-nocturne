"""19.11.2026: «установлено обновление — перезапустите».

Окно PADAM Studio у владельца держало в памяти код, запущенный вечером 18.11, хотя файлы на диске были уже
новые: выкатка обновляла файлы, а работающий процесс их не перечитывал, и владелец видел старую страницу.
Здесь запоминается отпечаток кода при запуске и сравнивается с файлами на диске: разошлись — страница просит
перезапустить приложение, а не молча показывает старое."""
from __future__ import annotations

import hashlib
from pathlib import Path

_ПАПКА = Path(__file__).resolve().parent


def fingerprint() -> str:
    h = hashlib.sha256()
    for f in sorted(_ПАПКА.glob("*.py")):
        try:
            st = f.stat()
        except OSError:
            continue
        h.update(f"{f.name}:{st.st_size}:{st.st_mtime_ns}\n".encode())
    return h.hexdigest()[:16]


LOADED = fingerprint()


def status() -> dict:
    disk = fingerprint()
    return {"loaded": LOADED, "disk": disk, "stale": disk != LOADED}
