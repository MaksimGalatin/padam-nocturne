"""Необязательный второй слой против приказов: локальная модель-детектор (ONNX), выключен по умолчанию.

Словарь фраз (`safety.looks_like_instruction`) на новых атаках ловит около половины приказов: каждый автор находит новые
слова (Red Team, круги 3–5, 11.11.2026). Модели-детекторы общего назначения ловят больше, но считают атакой и обычный
приказ людям — рецепт, памятку, письмо поставщика: на заметках проекта у трёх проверенных моделей это 1,2–6,8 % ложных
тревог. Поэтому здесь модель спрашивают только о тексте, где упомянут ИИ (ассистент, модель, нейросеть, AI…), и только с
высоким порогом. Замер 11.11.2026 (Wolf Defender small, ONNX int8, порог 0,999), старый код против нового:
приказы 241 → 260 из 278, записи о личности 108 → 113 из 135, ложных на 288 обычных заметках наборов +0, на 2 775 абзацах
русских заметок проекта +2, на 20 000 репликах LongMemEval-S +1 (это настоящая попытка джейлбрейка).

Включается переменной `PADAM_GUARD_MODEL` — папка модели с `tokenizer.json` и файлом `.onnx` — и пакетами из
`pip install "padam-nocturne[guard]"`. Без них слой молча выключен и ничего не меняет.
"""
from __future__ import annotations

import glob
import os
import re
import threading

ПОРОГ = float(os.environ.get("PADAM_GUARD_THRESHOLD", "0.999"))
ОКНО, ПЕРЕКРЫТИЕ = 512, 64

# Текст, где упомянут ИИ. Люди в приказах людям ИИ не упоминают; атака на память агента — упоминает почти всегда.
АДРЕСАТ_ИИ = re.compile(
    r"(?i)\bИИ\b|\bИИ-|нейросет|ассистент|цифров\w*\s+помощник|помощник\w*[-\s]ИИ|языков\w*\s+модел|"
    r"модел\w*\s+(?:памяти|ИИ)|агент\w*\s+(?:памяти|ИИ)|ИИ[-\s]агент|чат-?бот|\bбот\w*\b|"
    r"\bAI\b|\bA\.I\.|\bLLM\b|assistant|language model|chatbot|\bbot\b|\bagent\b|\bGPT|claude|gemini|"
    r"system prompt|системн\w*\s+(?:промпт|подсказк|инструкц)|助手|人工智能|アシスタント|مساعد|asistente|assistent")

_замок = threading.Lock()
_детектор = None
_загружен = False


class _Детектор:
    def __init__(self, папка: str):
        import numpy as np                  # noqa: F401 — проверка, что пакеты слоя установлены
        import onnxruntime as ort
        from tokenizers import Tokenizer

        файлы = sorted(glob.glob(os.path.join(папка, "**", "*.onnx"), recursive=True))
        путь = os.environ.get("PADAM_GUARD_ONNX") or (файлы[0] if файлы else "")
        if not путь:
            raise FileNotFoundError(f"no .onnx file in {папка}")
        self.tok = Tokenizer.from_file(os.path.join(папка, "tokenizer.json"))
        self.tok.no_truncation()
        self.tok.no_padding()
        so = ort.SessionOptions()
        so.intra_op_num_threads = int(os.environ.get("PADAM_GUARD_THREADS", "2"))
        so.inter_op_num_threads = 1
        self.s = ort.InferenceSession(os.path.join(папка, путь) if not os.path.isabs(путь) else путь, so,
                                      providers=["CPUExecutionProvider"])
        self.входы = [i.name for i in self.s.get_inputs()]
        enc = self.tok.encode("x")
        self.cls, self.sep = enc.ids[0], enc.ids[-1]

    def вероятность(self, текст: str) -> float:
        import numpy as np
        ids = self.tok.encode(" ".join(текст.split()), add_special_tokens=False).ids
        шаг, лучшее = ОКНО - 2 - ПЕРЕКРЫТИЕ, 0.0
        for начало in range(0, max(1, len(ids)), шаг):
            окно = [self.cls] + ids[начало:начало + ОКНО - 2] + [self.sep]
            подать = {"input_ids": np.array([окно], dtype=np.int64),
                      "attention_mask": np.ones((1, len(окно)), dtype=np.int64)}
            выход = self.s.run(None, {k: v for k, v in подать.items() if k in self.входы})[0]
            if выход.ndim == 1:
                p = float(выход.reshape(-1)[0])
            else:
                e = np.exp(выход[0] - выход[0].max())
                p = float((e / e.sum())[-1])
            лучшее = max(лучшее, p)
            if начало + ОКНО - 2 >= len(ids):
                break
        return лучшее


def детектор():
    """Детектор или None, если слой выключен. Загружается один раз, при первой нужде."""
    global _детектор, _загружен
    if _загружен:
        return _детектор
    with _замок:
        if not _загружен:
            папка = os.environ.get("PADAM_GUARD_MODEL", "")
            if папка:
                try:
                    _детектор = _Детектор(папка)
                except Exception:           # нет пакетов или файлов: слой выключен, память работает как раньше
                    _детектор = None
            _загружен = True
    return _детектор


def flags(text: str) -> bool:
    """Модель считает текст приказом ИИ. Без упоминания ИИ модель не спрашивают: так она не задерживает приказы людям."""
    if not text or not АДРЕСАТ_ИИ.search(text):
        return False
    д = детектор()
    return bool(д) and д.вероятность(text) >= ПОРОГ


def status() -> str:
    д = детектор()
    return "on" if д else ("off (PADAM_GUARD_MODEL not set)" if not os.environ.get("PADAM_GUARD_MODEL") else
                           "off (model or packages missing)")
