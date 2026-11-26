"""Флаг «без окна консоли» для внешних программ, которые PADAM запускает сам.

26.11.2026, слово Папы: «что за окна мелькают каждую секунду у меня на экране как приведения… полупрозрачные».
Замер: фоновый перенос памяти (pythonw) на каждой записи вызывал icacls для файла аудита, и Windows на долю секунды
показывала окно консоли — за 20 секунд четыре вспышки. На Windows любой subprocess без CREATE_NO_WINDOW из процесса
без своей консоли получает новое окно. Поэтому все фоновые запуски PADAM берут этот флаг.
"""
from __future__ import annotations

import os

#: Подставляется в subprocess.run / Popen / check_output: ``subprocess.run(cmd, **NO_WINDOW)``.
NO_WINDOW: dict = {"creationflags": 0x08000000} if os.name == "nt" else {}
