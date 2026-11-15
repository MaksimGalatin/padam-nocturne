# -*- coding: utf-8 -*-
"""Тесты ТОП-10 v3 («для себя»): квантизация, брифинг, связка REM, X-Wing MemCube, компакция, doctor --fix, Studio/Apps, elicitation, OTLP, расширенный бенчмарк."""
from __future__ import annotations

import numpy as np

from padam import config, mcp_server, quant_index, retrieval


def test_top10v3_1_quantized_vector_index_accuracy_and_memory_savings(monkeypatch) -> None:
    """Пункт 1: 1-bit + int8 квантизованный индекс экономит RAM и сохраняет Recall@5 >= 0.90."""
    monkeypatch.delenv("PADAM_QUANT_INDEX", raising=False)
    assert config.mcp_quant_index_enabled() is False
    assert len(mcp_server.TOOLS) == 9

    rng = np.random.default_rng(42)
    n, dim = 2000, 128
    M = rng.normal(size=(n, dim)).astype(np.float32)
    M /= np.linalg.norm(M, axis=1, keepdims=True)
    ids = [f"rec-{i:04d}" for i in range(n)]

    qi = quant_index.QuantizedIndex(M, ids)
    assert qi.bits.nbytes == n * (dim // 8)          # 32x меньше float32
    assert qi.q8.nbytes == n * dim                    # 4x меньше float32
    assert qi.bits.nbytes * 32 == M.nbytes

    # 20 запросов (берём зашумлённые копии реальных векторов из M для реалистичного Recall@5)
    hits_match = 0
    for idx in range(0, 200, 10):
        q = M[idx] + rng.normal(scale=0.15, size=(dim,)).astype(np.float32)
        q /= np.linalg.norm(q)
        exact = retrieval.rank_semantic(q, [{"id": ids[j], "_vec": M[j]} for j in range(n)], 5)
        approx = qi.search(q, 5, prefilter_k=400)
        assert len(approx) == 5
        hits_match += len(set(exact) & set(approx))
    recall_at_5 = hits_match / (20 * 5)
    assert recall_at_5 >= 0.90

    # Проверка интеграции в retrieval.rank_semantic при PADAM_QUANT_INDEX=1
    monkeypatch.setenv("PADAM_QUANT_INDEX", "1")
    assert config.mcp_quant_index_enabled() is True
    cands = retrieval.Кандидаты()
    cands.матрица = (dim, M, ids)
    res_q = retrieval.rank_semantic(M[7], cands, 5)
    assert res_q[0] == "rec-0007"
    assert getattr(cands, "quant_index", None) is not None
