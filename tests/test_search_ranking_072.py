# -*- coding: utf-8 -*-
"""Тесты исправления поиска и ранжирования PADAM 0.7.2:
- честная проверка наличия embed-модели в Ollama (/api/tags) и честная метка embed_with_model при откате;
- строгая изоляция несовместимых векторных пространств embedding_model одинаковой размерности (768 vs 768);
- нормализация диакритики (cédula == cedula) с сохранением русской «й»;
- защита от случайных хеш-коллизий встроенного эмбеддера builtin;
- защита прямых совпадений от вытеснения вторым проходом (SEARCH_FEEDBACK=1) и строгая монотонность score;
- осмысленная шкала score (~0.5..1.0 вместо ~0.01) и приоритет охвата терминов при многословных запросах.
"""
from __future__ import annotations

from types import SimpleNamespace
import numpy as np

from padam import config, embeddings, retrieval
from padam.memory import Memory, pack
from padam.store import Store



def test_fold_diacritics_preserves_russian_short_i():
    assert embeddings.fold_diacritics("cédula") == "cedula"
    assert embeddings.fold_diacritics("CÉDULA España über façade") == "CEDULA Espana uber facade"
    assert embeddings.fold_diacritics("Мой ёжик и файл") == "Мой ежик и файл"
    assert embeddings.fold_diacritics("Ёлка") == "Елка"


def test_ollama_check_requires_embed_model_installed(monkeypatch):
    assert embeddings._ollama_has_model([{"name": "llama3.2:latest"}], "nomic-embed-text") is False
    assert embeddings._ollama_has_model([{"name": "nomic-embed-text:latest"}], "nomic-embed-text") is True
    assert embeddings._ollama_has_model([{"name": "nomic-embed-text:v1.5"}], "nomic-embed-text:v1.5") is True
    assert embeddings._ollama_has_model([{"name": "nomic-embed-text:v1.5"}], "nomic-embed-text:v2") is False

    monkeypatch.setattr(embeddings, "_check_ollama", embeddings._orig_check_ollama)
    monkeypatch.setattr(embeddings, "_ollama_available", None)
    monkeypatch.setattr(embeddings, "_ollama_checked_at", 0.0)
    monkeypatch.setattr(config, "EMBED_MODEL", "nomic-embed-text")

    class _Resp:
        def __init__(self, models):
            self.status_code = 200
            self._models = models

        def json(self):
            return {"models": self._models}

    import requests

    # Установлена только чат-модель llama3.2 — embed-модели нет -> _check_ollama() обязан вернуть False
    monkeypatch.setattr(requests, "get", lambda *a, **kw: _Resp([{"name": "llama3.2:latest"}]))
    assert embeddings._check_ollama() is False

    # Сбросим кэш и добавим nomic-embed-text:latest -> True
    monkeypatch.setattr(embeddings, "_ollama_available", None)
    monkeypatch.setattr(embeddings, "_ollama_checked_at", 0.0)
    monkeypatch.setattr(requests, "get", lambda *a, **kw: _Resp([{"name": "llama3.2:latest"}, {"name": "nomic-embed-text:latest"}]))
    assert embeddings._check_ollama() is True


def test_embed_with_model_reports_honest_builtin_on_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EMBEDDER", "ollama")
    monkeypatch.setattr(config, "ALLOW_FALLBACK", True)
    monkeypatch.setattr(embeddings, "_check_ollama", lambda: True)

    def _boom(_text: str):
        raise RuntimeError("404 model not found")

    monkeypatch.setattr(embeddings, "_ollama_embed", _boom)

    vec, tag = embeddings.embed_with_model("BanEcuador требует cédula")
    assert vec.shape == (config.EMBED_DIM,)
    assert tag == f"builtin:{config.EMBED_DIM}"

    mem = Memory(user_id="u_honest", store=Store(tmp_path / "honest.db"))
    try:
        _, rid = mem.remember("BanEcuador требует cédula", kind="fact", origin="user")
        row = mem.store.one("SELECT embedding_model FROM memory WHERE id = ?", (rid,))
        assert row["embedding_model"] == f"builtin:{config.EMBED_DIM}"
    finally:
        mem.close()


def test_semantic_isolates_incompatible_embedding_models():
    dim = 16
    q = np.zeros(dim, dtype=np.float32)
    q[0] = 1.0
    v_match = np.zeros(dim, dtype=np.float32)
    v_match[0] = 1.0
    v_other = np.zeros(dim, dtype=np.float32)
    v_other[0] = 1.0  # Идентичный вектор, но ДРУГОЙ embedding_model!

    rows = Memory._с_матрицей([
        {"id": "rec_builtin", "content": "коммит", "_vec": v_other, "embedding_model": "builtin:16"},
        {"id": "rec_ollama", "content": "целевая запись", "_vec": v_match, "embedding_model": "ollama:nomic-embed-text"},
    ])
    got_ollama = retrieval.rank_semantic(q, rows, limit=5, query_model="ollama:nomic-embed-text")
    assert got_ollama == ["rec_ollama"]

    got_builtin = retrieval.rank_semantic(q, rows, limit=5, query_model="builtin:16")
    assert got_builtin == ["rec_builtin"]


def test_diacritics_cedula_ranks_top_with_meaningful_score_and_no_global_noise(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EMBEDDER", "builtin")
    monkeypatch.setattr(config, "SEARCH_FEEDBACK", True)
    mem = Memory(user_id="u_ced", store=Store(tmp_path / "ced.db"))
    try:
        # Забиваем global высокоприоритетными коммитами (как в живой базе)
        for i in range(25):
            mem.remember(
                f"22.11.2026: AIfa сделала коммит abc00{i:02d} в PADAM NOCTURNE (release-071, файлов {i + 3}): Доработки и тесты студии #{i}",
                scope="global", kind="fact", importance=0.95, origin="user",
            )
        # Кладём в project:code целевую запись про cédula с обычной важностью 0.5 и шумовые заметки «Найдено»
        for i in range(15):
            mem.remember(
                f"[2026-10-{10 + (i % 15):02d} · Найдено] Очередной отчёт проверки сайта #{i}: кнопки и шрифты работают ровно.",
                scope="project:code", kind="decision", importance=0.85, origin="agent",
            )
        _, cid1 = mem.remember(
            "[2026-10-22 · Найдено] BanEcuador требует личного визита и cédula (документ иностранца).",
            scope="project:code", kind="decision", importance=0.5, origin="agent",
        )
        _, cid2 = mem.remember(
            "[2026-11-14 · Сводка] Банк просит удостоверение о законном проживании в Эквадоре, а ни визы, ни cédula у Папы нет.",
            scope="project:code", kind="decision", importance=0.5, origin="agent",
        )

        # 1) В global нет слова cédula -> честный пустой ответ, никаких случайных хеш-коллизий!
        assert mem.recall("cédula", scope="global", limit=5) == []
        assert mem.recall("cedula", scope="global", limit=5) == []

        # 2) В project:code оба варианта (с ударением и без) находят именно 2 целевые записи наверху с высокой оценкой
        r_accent = mem.recall("cédula", scope="project:code", limit=5)
        r_plain = mem.recall("cedula", scope="project:code", limit=5)
        assert [r.id for r in r_accent[:2]] == [r.id for r in r_plain[:2]]
        assert {r.id for r in r_accent[:2]} == {cid1, cid2}
        assert r_accent[0].score >= 0.45, f"Ожидалась осмысленная оценка >= 0.45, получено {r_accent[0].score}"
        assert r_accent[1].score >= 0.45

        # 3) Межскоуповый recall_many: реальные записи из project:code уверенно на #1..#2, коммиты global не лезут
        r_many = mem.recall_many("cédula", ["global", "project:code"], limit=5)
        assert {r.id for r in r_many[:2]} == {cid1, cid2}
        assert all("cedul" in embeddings.fold_diacritics(r.content.lower()) for r in r_many[:2])

        # 4) Многословный запрос поднимает длинную запись со ВСЕМИ словами («виза», «cédula», «Папа») на #1
        r_multi = mem.recall("нет визы и cédula у Папы", scope="project:code", limit=5)
        assert r_multi and r_multi[0].id == cid2
        assert r_multi[0].score >= 0.45
    finally:
        mem.close()


def test_feedback_second_pass_never_displaces_direct_hits_and_is_monotonic(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EMBEDDER", "builtin")
    monkeypatch.setattr(config, "SEARCH_FEEDBACK", True)
    mem = Memory(user_id="u_fb", store=Store(tmp_path / "fb.db"))
    try:
        direct_ids = set()
        for i in range(6):
            _, rid = mem.remember(
                f"[2026-10-2{i} · Найдено] Банк #{i} в Эквадоре запрашивает cédula при открытии счёта.",
                scope="project:code", kind="decision", importance=0.5, origin="agent",
            )
            direct_ids.add(rid)
        for i in range(15):
            mem.remember(
                f"[2026-10-0{1 + (i % 9)} · Найдено] Проверка сайта и роликов #{i}: никаких банковских документов не требуется.",
                scope="project:code", kind="decision", importance=0.9, origin="user",
            )
        res = mem.recall("cédula", scope="project:code", limit=10)
        assert len(res) >= 6
        assert {r.id for r in res[:6]} == direct_ids
        # Строгая невозрастающая последовательность score
        for a, b in zip(res, res[1:]):
            assert a.score >= b.score, f"Нарушена монотонность score: {a.score} < {b.score}"
    finally:
        mem.close()
