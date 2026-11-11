"""Второй проход поиска (псевдо-обратная связь, PADAM_SEARCH_FEEDBACK=1).

Опыт 11.11.2026 на LongMemEval-S: одну нужную беседу поиск находит почти всегда, а все 3–5 бесед об одном — реже.
Слова, общие для первых найденных записей, добирают беседы, где нет слов вопроса. С 0.4.13 включено по умолчанию."""
from padam import config, retrieval
from padam.memory import Memory
from padam.store import Store


def _память(tmp_path):
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    m.remember("The billing service runs on Postgres inside the Kubernetes cluster", kind="fact")
    m.remember("Billing invoices are stored in Postgres; the Kubernetes nodes were resized", kind="fact")
    m.remember("Postgres and Kubernetes upgrade is planned for Friday night", kind="fact")
    for i in range(12):
        m.remember(f"Lunch note {i}: the cafe on the corner serves soup number {i}", kind="fact")
    return m


def test_слова_обратной_связи():
    тексты = ["Billing runs on Postgres in Kubernetes", "Invoices in Postgres, Kubernetes resized", "Soup today"]
    assert retrieval.feedback_terms("billing", тексты) == ["postgres", "kubernetes"]
    # слово запроса и служебные слова не попадают; одно упоминание — мало
    assert retrieval.feedback_terms("postgres", тексты) == ["kubernetes"]
    assert retrieval.feedback_terms("x", ["this that there", "this that there"]) == []
    # русские слова тоже
    assert "postgres" in retrieval.feedback_terms("счёт", ["Счёт хранится в Postgres", "Сервер Postgres"])


def test_по_умолчанию_включено_и_выключается_переменной():
    # 0.4.13: включён по умолчанию; PADAM_SEARCH_FEEDBACK=0 выключает. Отдельный процесс: значение читается при импорте.
    import os
    import subprocess
    import sys
    def значение(**доп):
        env = {k: v for k, v in os.environ.items() if k != "PADAM_SEARCH_FEEDBACK"}
        env.update(доп)
        out = subprocess.run([sys.executable, "-c", "from padam import config; print(config.SEARCH_FEEDBACK)"],
                             env=env, capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
        return out.stdout.strip()
    assert значение() == "True"
    assert значение(PADAM_SEARCH_FEEDBACK="0") == "False"


def test_второй_проход_добирает_связанную_запись(tmp_path, monkeypatch):
    m = _память(tmp_path)
    try:
        monkeypatch.setattr(config, "SEARCH_FEEDBACK", False)
        без = [r.content for r in m.recall("billing", limit=5)]
        assert not any(c.startswith("Postgres and Kubernetes upgrade") for c in без)
        monkeypatch.setattr(config, "SEARCH_FEEDBACK", True)
        с = [r.content for r in m.recall("billing", limit=5)]
        assert any(c.startswith("Postgres and Kubernetes upgrade") for c in с)
        # первые записи первого прохода остаются наверху
        assert с[:2] == без[:2]
        assert len(с) <= 5
    finally:
        m.close()


def test_второй_проход_без_находок_ничего_не_ищет(tmp_path, monkeypatch):
    m = Memory(user_id="u", store=Store(tmp_path / "m.db"))
    try:
        monkeypatch.setattr(config, "SEARCH_FEEDBACK", True)
        assert m.recall("nothing at all", limit=5) == []
    finally:
        m.close()
