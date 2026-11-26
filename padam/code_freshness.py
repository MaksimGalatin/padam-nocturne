"""19.11.2026: «установлено обновление — перезапустите».

Окно PADAM Studio у владельца держало в памяти код, запущенный вечером 18.11, хотя файлы на диске были уже
новые: выкатка обновляла файлы, а работающий процесс их не перечитывал, и владелец видел старую страницу.
Здесь запоминается отпечаток кода при запуске и сравнивается с файлами на диске: разошлись — страница просит
перезапустить приложение, а не молча показывает старое."""
from __future__ import annotations

import hashlib
import os
import time
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


def _свежайшая_правка() -> float:
    """Время последнего изменения любого .py пакета (секунды эпохи)."""
    самое = 0.0
    for f in _ПАПКА.glob("*.py"):
        try:
            самое = max(самое, f.stat().st_mtime)
        except OSError:
            continue
    return самое


def _выдержка_с() -> float:
    try:
        return max(0.0, float(os.environ.get("PADAM_CODE_SETTLE_S", "20")))
    except ValueError:
        return 20.0


def status() -> dict:
    """stale — код на диске разошёлся с загруженным И перестал меняться хотя бы PADAM_CODE_SETTLE_S секунд (20).

    25.11.2026 (0.9.0): Studio на порту 9890 перезапускала свой сервер раз за разом (desktop.log: шесть
    hot_restarted_python_backend и один hot_restart_health_timeout) — файлы её пакета заменялись по одному,
    каждая замена меняла отпечаток, и каждый раз шёл перезапуск (запуск 1,8–10,8 с). Запросы, попавшие на
    перезапуски, ждали 11–22 с — это и был замер Сестры. Теперь серия правок даёт один перезапуск: ждём, пока
    файлы перестанут меняться. Пока не перестали — settling=True, stale=False.
    """
    disk = fingerprint()
    разошлось = disk != LOADED
    тихо_с = time.time() - _свежайшая_правка()
    settling = разошлось and тихо_с < _выдержка_с()
    return {"loaded": LOADED, "disk": disk, "stale": разошлось and not settling, "settling": settling,
            "quiet_seconds": round(тихо_с, 1)}
