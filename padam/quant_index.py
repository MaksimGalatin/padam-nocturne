"""Квантизованный векторный индекс (1-bit binary + int8 + точный float32 rerank).

Позволяет на больших базах (100k+ записей) отбирать кандидатов сначала по
бинарному Хэммингу (32x экономия памяти), затем по int8 (4x экономия),
и только для топ-финалистов считать точное скалярное произведение float32.

По умолчанию выключено (PADAM_QUANT_INDEX=0).
"""
from __future__ import annotations

import numpy as np

# Таблица popcount для каждого байта 0..255 (чистый NumPy, без C-расширений)
_POPCOUNT_LUT = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)


def quantize_int8(M: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Симметричная построчная квантизация float32 -> (int8, float32_scales)."""
    arr = np.asarray(M, dtype=np.float32)
    max_abs = np.max(np.abs(arr), axis=1, keepdims=True)
    scales = np.where(max_abs > 1e-8, max_abs / 127.0, 1.0).astype(np.float32)
    q8 = np.clip(np.rint(arr / scales), -127, 127).astype(np.int8)
    return q8, scales.reshape(-1)


def binarize_matrix(M: np.ndarray) -> np.ndarray:
    """Упаковка знаковых битов float32 -> uint8 (в 32 раза меньше RAM)."""
    return np.packbits((np.asarray(M, dtype=np.float32) > 0).astype(np.uint8), axis=1)


class QuantizedIndex:
    """Трёхступенчатый индекс: 1-bit Hamming -> int8 dot -> точный float32 rerank."""

    def __init__(self, M: np.ndarray, ids: list[str]) -> None:
        self.M = np.asarray(M, dtype=np.float32)
        self.ids = list(ids)
        self.dim = self.M.shape[1] if self.M.ndim == 2 else 0
        self.count = len(self.ids)
        self.bits = binarize_matrix(self.M) if self.count else np.empty((0, 0), dtype=np.uint8)
        self.q8, self.scales = quantize_int8(self.M) if self.count else (np.empty((0, 0), dtype=np.int8), np.empty((0,), dtype=np.float32))

    def search(self, query_vec: np.ndarray, limit: int, *, prefilter_k: int = 400) -> list[str]:
        if limit <= 0 or self.count == 0 or query_vec is None or query_vec.size == 0:
            return []
        q = np.asarray(query_vec, dtype=np.float32)
        if q.shape[0] != self.dim:
            return []

        if self.count <= prefilter_k:
            sims = np.clip(self.M @ q, -1.0, 1.0)
            pos = np.nonzero(sims > 0)[0]
            if not pos.size:
                return []
            order = pos[np.argsort(-sims[pos], kind="stable")][:limit]
            return [self.ids[int(i)] for i in order]

        # Ступень 1: 1-bit Hamming distance через XOR + popcount LUT
        q_bits = np.packbits((q > 0).astype(np.uint8))
        hamming = np.sum(_POPCOUNT_LUT[self.bits ^ q_bits], axis=1, dtype=np.int32)
        k1 = min(self.count, max(prefilter_k * 2, limit * 16))
        cand1 = np.argpartition(hamming, k1 - 1)[:k1]

        # Ступень 2: int8 dot product на cand1
        q_max = float(np.max(np.abs(q)))
        q_scale = (q_max / 127.0) if q_max > 1e-8 else 1.0
        q_i8 = np.clip(np.rint(q / q_scale), -127, 127).astype(np.int32)
        approx = (self.q8[cand1].astype(np.int32) @ q_i8).astype(np.float32) * self.scales[cand1] * q_scale
        k2 = min(cand1.size, max(prefilter_k, limit * 8))
        if cand1.size > k2:
            sub = np.argpartition(-approx, k2 - 1)[:k2]
            cand2 = cand1[sub]
        else:
            cand2 = cand1

        # Ступень 3: точный float32 rerank на финалистах
        sims = np.clip(self.M[cand2] @ q, -1.0, 1.0)
        pos_mask = sims > 0
        if not np.any(pos_mask):
            return []
        pos_idx = cand2[pos_mask]
        pos_sims = sims[pos_mask]
        order = pos_idx[np.argsort(-pos_sims, kind="stable")][:limit]
        return [self.ids[int(i)] for i in order]
