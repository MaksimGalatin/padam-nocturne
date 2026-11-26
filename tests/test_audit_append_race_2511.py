# 25.11.2026: гонка звена цепи аудита на общем соединении.
#
# Studio шлёт кнопки «ACL» и «сканер перед установкой» почти одновременно; потоки REST-сервера делят одно
# соединение SQLite. append_audit проверял «открыта ли транзакция» и выполнял BEGIN разными шагами, и между ними
# другой поток открывал свою транзакцию — ответ 500 «cannot start a transaction within a transaction»
# (воспроизведено 3 из 3 в test_21_power_and_coop_2211 до починки).
import threading

from padam import audit_chain
from padam.memory import Memory
from padam.store import Store


def _гонка(tmp_path, потоков: int = 8, звеньев: int = 20):
    m = Memory(user_id="u", store=Store(tmp_path / "race.db"))
    ошибки: list[str] = []
    старт = threading.Barrier(потоков + 2)

    def звенья(i: int) -> None:
        старт.wait()
        for k in range(звеньев):
            try:
                audit_chain.append_audit(m, "race_probe", {"t": i, "k": k}, agent_id=f"a{i}")
            except Exception as exc:  # noqa: BLE001 — собираем любую ошибку, тест проверяет, что их ноль
                ошибки.append(f"{type(exc).__name__}: {exc}")

    def записи() -> None:
        # Параллельная обычная запись памяти — она открывает неявные транзакции на том же соединении.
        старт.wait()
        for k in range(звеньев):
            try:
                m.remember(f"Race probe note number {k} for the audit chain", kind="fact")
            except Exception as exc:  # noqa: BLE001
                ошибки.append(f"{type(exc).__name__}: {exc}")

    нити = [threading.Thread(target=звенья, args=(i,)) for i in range(потоков)]
    нити += [threading.Thread(target=записи), threading.Thread(target=записи)]
    for н in нити:
        н.start()
    for н in нити:
        н.join(timeout=120)
    return m, ошибки


def test_одновременные_звенья_аудита_без_ошибок_транзакции(tmp_path):
    m, ошибки = _гонка(tmp_path)
    assert ошибки == [], ошибки[:5]
    всего = m.store.one("SELECT COUNT(*) AS n FROM ark_audit_chain WHERE user_id = ?", ("u",))["n"]
    assert всего == 8 * 20


def test_цепь_после_гонки_цела(tmp_path):
    m, ошибки = _гонка(tmp_path, потоков=6, звеньев=10)
    assert ошибки == []
    отчёт = audit_chain.verify_audit_chain(m)
    ark = отчёт.get("ark_audit_chain", отчёт)
    assert ark.get("ok", ark.get("valid")) is True, отчёт


def test_звено_внутри_уже_открытой_транзакции_не_фиксирует_её_раньше_времени(tmp_path):
    # Таблицы цепи создаются один раз: повторный executescript посреди чужой транзакции зафиксировал бы её половину.
    m = Memory(user_id="u", store=Store(tmp_path / "tx.db"))
    audit_chain.append_audit(m, "warmup", {"x": 1})
    with m.store._lock:
        m.store.conn.execute("CREATE TABLE IF NOT EXISTS t_probe (v TEXT)")
        m.store.conn.commit()
        m.store.conn.execute("INSERT INTO t_probe (v) VALUES ('inside')")
        assert m.store.conn.in_transaction
        audit_chain.append_audit(m, "inside_tx", {"x": 2})
    n = m.store.one("SELECT COUNT(*) AS n FROM ark_audit_chain WHERE action = 'inside_tx'")["n"]
    assert n == 1
