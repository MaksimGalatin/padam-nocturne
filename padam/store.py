"""Хранилище. SQLite — по умолчанию, работает без установки чего-либо.

Векторы хранятся как BLOB, поиск — полным перебором с numpy. Для объёмов
до десятков тысяч записей это быстрее, чем возня с индексом. Когда база
вырастет, слой заменяется на Postgres с pgvector без изменения логики
выше.
"""

from __future__ import annotations

import os
import sqlite3
import atexit
import threading
import time
import weakref
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from . import config

HW_SEAL_MAGIC = b"PADAMHW1"


class HardwareLockedError(RuntimeError):
    """База данных запечатана Аппаратной Печатью Души (PADAMHW1) и требует разблокировки FIDO2/DPAPI."""

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- L1: буфер эпизодов
CREATE TABLE IF NOT EXISTS episode (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    scope         TEXT NOT NULL DEFAULT 'global',
    role          TEXT NOT NULL,
    content       TEXT NOT NULL,
    embedding     BLOB,
    priority      REAL NOT NULL DEFAULT 1.0,
    replay_count  INTEGER NOT NULL DEFAULT 0,
    processed     INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS episode_pending
    ON episode (user_id, processed, priority DESC);

-- L2: семантическая память
CREATE TABLE IF NOT EXISTS memory (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    scope             TEXT NOT NULL DEFAULT 'global',
    kind              TEXT NOT NULL,
    content           TEXT,
    embedding         BLOB,
    importance        REAL NOT NULL DEFAULT 0.5,
    confidence        REAL NOT NULL DEFAULT 1.0,
    created_at        TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,     -- когда извлекали
    last_confirmed_at TEXT NOT NULL,     -- когда подтверждалась верной
    expires_at        TEXT,              -- известный горизонт истинности
    valid_from        TEXT,              -- с какого момента факт верен
    valid_to          TEXT,              -- до какого момента был верен
    access_count      INTEGER NOT NULL DEFAULT 0,
    refuted_count     INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL DEFAULT 'active',
    supersedes        TEXT,
    superseded_by     TEXT,
    source_episode_id TEXT,
    session_id        TEXT,
    content_hash      BLOB,
    anchor_tx         TEXT,
    anchor_slot       INTEGER,
    -- 🔴 Чем посчитан вектор. Добавлено 05.09.2026.
    -- Без этого поля нельзя даже задним числом узнать, в каком пространстве
    -- лежит запись. Встроенный метод и нейросетевой дают несовместимые
    -- векторы (косинус для одного и того же текста около нуля), и после
    -- смены способа поиск перестаёт находить старые записи ВОВСЕ. Отказ
    -- бесшумный: ни ошибки, ни предупреждения.
    embedding_model   TEXT,
    -- 🔴 Структурный ключ факта: «объект + свойство» без значения.
    -- Добавлено 05.09.2026. Позволяет найти спорящую запись ТОЧНО, а не по
    -- случайной близости векторов: «столица Франции — Париж» и «столица
    -- Франции — Рим» имеют один ключ и разные значения, значит спорят.
    -- Замер того дня показал цену отсутствия ключа: из 142 настоящих
    -- конфликтов поиск по вектору находил около 51.
    факт_ключ         TEXT,
    visibility        TEXT NOT NULL DEFAULT 'private',
    workspace_id      TEXT
);
CREATE INDEX IF NOT EXISTS memory_active
    ON memory (user_id, scope, kind, status);

-- полнотекстовый индекс: BM25 встроен в SQLite, отдельных зависимостей нет
CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    content,
    content='memory',
    content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS memory_fts_insert AFTER INSERT ON memory
WHEN new.content IS NOT NULL BEGIN
    INSERT INTO memory_fts(rowid, content) VALUES (new.rowid, new.content);
END;

-- Триггеры удаления и правки — в FTS_TRIGGERS ниже: они заменяются и в уже созданных базах.

-- сессии
CREATE TABLE IF NOT EXISTS session (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    last_active_at TEXT NOT NULL,
    centroid       BLOB,
    episode_count  INTEGER NOT NULL DEFAULT 0
);

-- журнал циклов консолидации
CREATE TABLE IF NOT EXISTS nocturne_run (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    started_at          TEXT NOT NULL,
    finished_at         TEXT,
    episodes_sampled    INTEGER,
    high_priority_share REAL,
    kind_entropy        REAL,
    records_created     INTEGER,
    records_merged      INTEGER,
    records_superseded  INTEGER
);

-- «вывод сделан из записи»: по этим связям забвение доходит до выводов (forget --with-derived)
CREATE TABLE IF NOT EXISTS memory_link (
    src         TEXT NOT NULL,          -- запись-источник
    dst         TEXT NOT NULL,          -- вывод из неё
    relation    TEXT NOT NULL DEFAULT 'derived',
    created_at  TEXT NOT NULL,
    PRIMARY KEY (src, dst, relation)
);
CREATE INDEX IF NOT EXISTS memory_link_dst ON memory_link (dst);

-- синонимы терминов: проект переименовали — поиск по новому имени находит и старые записи
CREATE TABLE IF NOT EXISTS term_alias (
    user_id     TEXT NOT NULL,
    term        TEXT NOT NULL,
    alias       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (user_id, term, alias)
);

-- память о самой памяти: сколько поисков и сколько из них ничего не нашли, по дням, без текста запросов
CREATE TABLE IF NOT EXISTS search_stats (
    user_id     TEXT NOT NULL,
    day         TEXT NOT NULL,
    searches    INTEGER NOT NULL DEFAULT 0,
    empty       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);

-- ключи для L3: уничтожение ключа = необратимое удаление содержания
CREATE TABLE IF NOT EXISTS anchor_key (
    memory_id    TEXT PRIMARY KEY,
    key_ref      TEXT NOT NULL,
    shard_count  INTEGER NOT NULL DEFAULT 2,
    threshold    INTEGER NOT NULL DEFAULT 2,
    destroyed_at TEXT,
    created_at   TEXT NOT NULL
);

-- квитанции об удалении (доказательство удаления без хранения самого текста)
CREATE TABLE IF NOT EXISTS forget_receipt (
    receipt_id          TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    memory_id           TEXT NOT NULL,
    forgotten_at        TEXT NOT NULL,
    content_hash_sha256 TEXT,
    kind                TEXT,
    scope               TEXT,
    with_derived        INTEGER NOT NULL DEFAULT 0,
    wiped_count         INTEGER NOT NULL DEFAULT 1,
    wiped_ids_json      TEXT NOT NULL,
    key_destroyed       INTEGER NOT NULL DEFAULT 1,
    anchor_tx           TEXT,
    leaf_forget_hex     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS forget_receipt_user ON forget_receipt (user_id, forgotten_at DESC);

-- Б12: журнал действий (кто, когда и что записал, принял, отклонил, восстановил или забыл; без хранения текста)
CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    action      TEXT NOT NULL,
    memory_id   TEXT,
    actor       TEXT NOT NULL DEFAULT 'user',
    agent_id    TEXT,
    scope       TEXT,
    kind        TEXT,
    outcome     TEXT,
    detail      TEXT,
    seq         INTEGER,
    prev_hash   TEXT,
    entry_hash  TEXT
);
CREATE INDEX IF NOT EXISTS audit_log_user ON audit_log (user_id, created_at DESC);

-- MEM-02 (Antigravity): якорь головы цепи журнала, подписанный ключом владельца
CREATE TABLE IF NOT EXISTS audit_log_anchor (
    user_id    TEXT PRIMARY KEY,
    head_seq   INTEGER NOT NULL,
    head_hash  TEXT NOT NULL,
    head_hmac  TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- В1: командные пространства и роли с солёными SHA-256 токенами
CREATE TABLE IF NOT EXISTS workspace (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspace_member (
    workspace_id  TEXT NOT NULL,
    subject       TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('owner', 'maintainer', 'contributor', 'auditor')),
    token_hash    TEXT NOT NULL,
    token_salt    TEXT NOT NULL,
    token_prefix  TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    revoked_at    TEXT,
    PRIMARY KEY (workspace_id, subject)
);
CREATE INDEX IF NOT EXISTS workspace_member_token ON workspace_member (token_hash);

-- В2: внешние коннекторы (по умолчанию выключены, токены зашифрованы локально)
CREATE TABLE IF NOT EXISTS connector_state (
    provider       TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 0,
    token_enc      TEXT,
    config_json    TEXT NOT NULL DEFAULT '{}',
    cursor         TEXT,
    last_sync_at   TEXT,
    last_status    TEXT NOT NULL DEFAULT 'disabled',
    last_error     TEXT,
    imported_count INTEGER NOT NULL DEFAULT 0,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (provider, user_id)
);

CREATE TABLE IF NOT EXISTS connector_item (
    user_id      TEXT NOT NULL,
    provider     TEXT NOT NULL,
    external_id  TEXT NOT NULL,
    memory_id    TEXT,
    content_hash TEXT NOT NULL,
    synced_at    TEXT NOT NULL,
    PRIMARY KEY (user_id, provider, external_id)
);

-- В3: постквантовый обмен ключами X-Wing (ML-KEM-768 + X25519) и доверенные устройства
CREATE TABLE IF NOT EXISTS sync_identity (
    user_id        TEXT PRIMARY KEY,
    device_id      TEXT NOT NULL,
    scheme         TEXT NOT NULL,
    pk_bundle_json TEXT NOT NULL,
    sk_enc         TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_peer (
    user_id        TEXT NOT NULL,
    peer_device_id TEXT NOT NULL,
    label          TEXT NOT NULL DEFAULT '',
    pk_bundle_json TEXT NOT NULL,
    sas_code       TEXT NOT NULL,
    trusted        INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL,
    last_sync_at   TEXT,
    PRIMARY KEY (user_id, peer_device_id)
);

-- Легенда Шаг 2: Когнитивный контроль версий (снапшоты без дублирования открытого текста)
CREATE TABLE IF NOT EXISTS cognitive_snapshot (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    name            TEXT NOT NULL,
    scope           TEXT,
    note            TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    record_count    INTEGER NOT NULL DEFAULT 0,
    state_sha256    TEXT NOT NULL,
    merkle_root_hex TEXT,
    anchor_tx       TEXT,
    rollback_count  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS cognitive_snapshot_user
    ON cognitive_snapshot (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cognitive_snapshot_item (
    snapshot_id   TEXT NOT NULL,
    memory_id     TEXT NOT NULL,
    status        TEXT NOT NULL,
    kind          TEXT NOT NULL,
    scope         TEXT NOT NULL,
    importance    REAL NOT NULL,
    confidence    REAL NOT NULL,
    supersedes    TEXT,
    superseded_by TEXT,
    valid_from    TEXT,
    valid_to      TEXT,
    expires_at    TEXT,
    content_hash  BLOB,
    PRIMARY KEY (snapshot_id, memory_id)
);

-- Легенда Шаг 3: Зашифрованное локальное хранилище псевдонимов DLP (AES-256-GCM)
CREATE TABLE IF NOT EXISTS dlp_vault (
    user_id     TEXT NOT NULL,
    alias       TEXT NOT NULL,
    kind        TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    sealed_hex  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    hit_count   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (user_id, alias)
);
CREATE INDEX IF NOT EXISTS dlp_vault_hash
    ON dlp_vault (user_id, secret_hash);

-- Реестр подключённых агентов (19.11.2026: новый агент -> отдельный граф и живая статистика)
CREATE TABLE IF NOT EXISTS agent_registry (
    user_id       TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    display_name  TEXT DEFAULT '',
    environment   TEXT DEFAULT '',
    color_hex     TEXT DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    last_action   TEXT DEFAULT '',
    writes_count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, agent_id)
);

-- Хронологическая история чистых переписок с каждым агентом (без кода и дампа инструментов)
CREATE TABLE IF NOT EXISTS chat_thread (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    title           TEXT NOT NULL,
    source_kind     TEXT NOT NULL DEFAULT 'manual',
    source_ref      TEXT DEFAULT '',
    started_at      TEXT NOT NULL,
    last_message_at TEXT NOT NULL,
    message_count   INTEGER NOT NULL DEFAULT 0,
    is_worker       INTEGER NOT NULL DEFAULT 0,
    summary         TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS chat_thread_user_agent
    ON chat_thread (user_id, agent_id, last_message_at DESC);

CREATE TABLE IF NOT EXISTS chat_message (
    id           TEXT PRIMARY KEY,
    thread_id    TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    seq          INTEGER NOT NULL DEFAULT 0,
    role         TEXT NOT NULL,
    author_label TEXT DEFAULT '',
    content      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    FOREIGN KEY(thread_id) REFERENCES chat_thread(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS chat_message_thread
    ON chat_message (thread_id, seq);
CREATE INDEX IF NOT EXISTS chat_message_hash
    ON chat_message (user_id, content_hash);
"""


# 09.11.2026: удаление из индекса строки, у которой текста уже нет, портит индекс FTS5 («database disk
# image is malformed»). Так падало повторное «забудь» и загрузка поверх отозванной записи.
FTS_TRIGGERS = """
DROP TRIGGER IF EXISTS memory_fts_delete;
CREATE TRIGGER memory_fts_delete AFTER DELETE ON memory
WHEN old.content IS NOT NULL BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, content)
    VALUES ('delete', old.rowid, old.content);
END;

DROP TRIGGER IF EXISTS memory_fts_update;
CREATE TRIGGER memory_fts_update AFTER UPDATE OF content ON memory BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, content)
    SELECT 'delete', old.rowid, old.content WHERE old.content IS NOT NULL;
    INSERT INTO memory_fts(rowid, content)
    SELECT new.rowid, new.content WHERE new.content IS NOT NULL;
END;
"""


_ALTER_LOCK = threading.RLock()

# 18.11.2026: при выходе процесса дописываем отложенные счётчики поиска всех открытых хранилищ.
_ЖИВЫЕ: "weakref.WeakSet" = weakref.WeakSet()


@atexit.register
def _сбросить_всё_при_выходе() -> None:
    for st in list(_ЖИВЫЕ):
        try:
            st.flush()
        except Exception:
            pass


def add_column_safe(conn, table: str, name: str, decl: str) -> bool:
    """Добавляет столбец, если его нет. Безопасно при одновременном вызове из двух потоков.

    18.11.2026: два запроса Studio (GET /l3 и POST /l3-verify) одновременно увидели, что столбца нет, оба сделали
    ALTER TABLE, второй упал «duplicate column name» — пользователь получил 500. Теперь проверка и ALTER идут под
    одним замком, а «duplicate column» от другого процесса не считается ошибкой. Возвращает True, если столбец добавлен.
    """
    with _ALTER_LOCK:
        есть = {r[1] for r in conn.execute('PRAGMA table_info("%s")' % table).fetchall()}
        if name in есть:
            return False
        try:
            conn.execute('ALTER TABLE "%s" ADD COLUMN %s %s' % (table, name, decl))
        except sqlite3.OperationalError as e:
            if "duplicate column" not in str(e).lower():
                raise
            return False
        return True


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_ts(s: str) -> datetime:
    s = str(s).strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"   # Python 3.10 не понимает «Z» в fromisoformat
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


def pack(vec: np.ndarray | None) -> bytes | None:
    return None if vec is None else np.asarray(vec, dtype=np.float32).tobytes()


def unpack(blob: bytes | None) -> np.ndarray | None:
    if blob is None:
        return None
    return np.frombuffer(blob, dtype=np.float32)


class _ConnUnderLock:
    """19.11.2026: соединение, у которого каждое обращение идёт под замком хранилища.

    CI (Windows, 3.10) упал на «cannot commit - no transaction is active» в параллельных запусках совета карантина:
    24 модуля (около 230 мест) ходят в store.conn напрямую, мимо замка, и commit одного потока попадал в середину
    чужой транзакции. Чинить поштучно — значит пропустить следующее место; поэтому замок встроен в само соединение.
    Замок RLock: методы Store, уже держащие его, берут его повторно без взаимной блокировки."""

    __slots__ = ("_c", "_l")

    def __init__(self, conn, lock):
        object.__setattr__(self, "_c", conn)
        object.__setattr__(self, "_l", lock)

    @property
    def raw(self):
        return self._c

    def execute(self, *a, **k):
        with self._l:
            return self._c.execute(*a, **k)

    def executemany(self, *a, **k):
        with self._l:
            return self._c.executemany(*a, **k)

    def executescript(self, *a, **k):
        with self._l:
            return self._c.executescript(*a, **k)

    def commit(self):
        with self._l:
            return self._c.commit()

    def rollback(self):
        with self._l:
            return self._c.rollback()

    def close(self):
        with self._l:
            return self._c.close()

    def backup(self, target, *a, **k):
        with self._l:
            return self._c.backup(getattr(target, "raw", target), *a, **k)

    def __enter__(self):
        self._l.acquire()
        try:
            return self._c.__enter__()
        except BaseException:
            self._l.release()
            raise

    def __exit__(self, *exc):
        try:
            return self._c.__exit__(*exc)
        finally:
            self._l.release()

    def __getattr__(self, name):
        return getattr(self._c, name)

    def __setattr__(self, name, value):
        setattr(self._c, name, value)


class Store:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else config.DB_PATH
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and self.path.is_file():
                try:
                    with self.path.open("rb") as _hf:
                        if _hf.read(8) == HW_SEAL_MAGIC:
                            raise HardwareLockedError(
                                f"Database {self.path} is hardware-sealed (PADAMHW1); unseal with FIDO2/DPAPI first."
                            )
                except OSError:
                    pass
        # 16.10.2026: одно соединение делят потоки REST-сервера (ThreadingHTTPServer). Без
        # блокировки два запроса одновременно портили транзакцию («cannot commit — no
        # transaction is active»). Все обращения к соединению идут под этим замком.
        self._lock = threading.RLock()
        # 18.11.2026: отложенные служебные счётчики поиска (см. counters()).
        self._отложенные: list[tuple[str, tuple]] = []
        self._сброшено = time.monotonic()
        _ЖИВЫЕ.add(self)
        # 0.4.4: счётчик своих коммитов — по нему (вместе с PRAGMA data_version для чужих соединений) кэш
        # векторов в Memory понимает, что база изменилась, и не может разойтись с ней.
        self.writes = 0
        # 18.11.2026: замер роя (20 процессов в один файл) давал 4–6 % «database is locked»: неявная транзакция
        # начиналась как чтение и при первой записи пыталась повыситься до записи — в WAL SQLite отбивает это сразу,
        # не дожидаясь busy_timeout. IMMEDIATE берёт замок записи в начале транзакции: писатели встают в очередь.
        self.conn = _ConnUnderLock(sqlite3.connect(str(self.path), timeout=15.0, check_same_thread=False,
                                                    isolation_level="IMMEDIATE"), self._lock)
        self.conn.row_factory = sqlite3.Row
        # 18.11.2026: при 20 процессах в один файл хвост очереди писателей изредка превышал 5 с — часть записей
        # терялась с «database is locked». 30 с ожидания срабатывают только при давке; замер 20 и 40 процессов: 0 ошибок.
        self.conn.execute("PRAGMA busy_timeout = 30000")
        # Память личная: на общем компьютере файл базы не должен читаться другими.
        # Папку закрываем только свою, по умолчанию: путь, заданный человеком, не наш.
        if str(self.path) != ":memory:" and os.name == "posix":
            try:
                os.chmod(self.path, 0o600)
                if self.path.parent == config.DB_PATH.parent:
                    os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
        # Без этого затёртый текст остаётся в свободных страницах файла и читается простым
        # поиском по байтам: «забвение» было бы только в интерфейсе.
        self.conn.execute("PRAGMA secure_delete = ON")
        self.conn.execute("PRAGMA cache_size = -16384")
        self.conn.execute("PRAGMA temp_store = MEMORY")
        # 18.11.2026: замер «20 процессов пишут в один файл» упал на «trigger memory_fts_delete already exists» —
        # процессы одновременно создавали схему отдельными командами. Теперь вся схема создаётся в ОДНОЙ транзакции
        # BEGIN IMMEDIATE: второй процесс ждёт первого (busy_timeout), а не ломается. Режимы журнала и внешних ключей
        # внутри транзакции не меняются — их ставим до неё.
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA foreign_keys = ON")
        _тело = SCHEMA.replace("PRAGMA journal_mode = WAL;", "").replace("PRAGMA foreign_keys = ON;", "")
        self.conn.executescript("BEGIN IMMEDIATE;" + _тело + FTS_TRIGGERS)
        try:
            self._дополнить_схему()
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    def _дополнить_схему(self) -> None:
        """Досоздаёт колонки, которых нет в уже существующих базах.

        `CREATE TABLE IF NOT EXISTS` не трогает таблицу, если она уже есть, —
        значит база, созданная прежней версией, останется без новых полей, и
        запись упадёт на «no such column». Добавляем недостающее по факту, а
        не по номеру версии: так работает и с базами неизвестного возраста.

        Только ДОБАВЛЯЕТ. Ничего не удаляет и не переписывает (раздел 19).
        """
        НУЖНЫЕ = {"memory": {"embedding_model": "TEXT", "факт_ключ": "TEXT",
                             "origin": "TEXT", "quarantine_reason": "TEXT", "owner_sig": "TEXT",
                             "agent_id": "TEXT", "visibility": "TEXT DEFAULT 'private'", "workspace_id": "TEXT",
                             "learned_at": "TEXT", "invalidated_at": "TEXT"},
                  "memory_link": {"relation": "TEXT DEFAULT 'derived'",
                                  "learned_at": "TEXT", "invalidated_at": "TEXT"},
                  "audit_log": {"seq": "INTEGER", "prev_hash": "TEXT", "entry_hash": "TEXT"}}
        for таблица, колонки in НУЖНЫЕ.items():
            try:
                есть = {r["name"] for r in
                        self.conn.execute("PRAGMA table_info(%s)" % таблица)}
            except sqlite3.Error:
                continue
            if not есть:
                continue
            for имя, тип in колонки.items():
                if имя not in есть:
                    add_column_safe(self.conn, таблица, имя, тип)

        # 🔴 ИНДЕКСЫ ПО ДОБАВЛЕННЫМ КОЛОНКАМ — ТОЛЬКО ЗДЕСЬ, ПОСЛЕ МИГРАЦИИ.
        #
        # Их нельзя держать в SCHEMA: `executescript` выполняется ДО
        # миграции, и на базе, созданной прежней версией, падает с
        # «no such column: факт_ключ». Замер 05.09.2026: так оборвался
        # перезапуск прогона на старой базе — код был верен, а порядок нет.
        self.conn.execute(
            """CREATE INDEX IF NOT EXISTS memory_факт_ключ
               ON memory (user_id, scope, факт_ключ, status)""")
        self.conn.execute(
            """CREATE INDEX IF NOT EXISTS memory_agent_id
               ON memory (user_id, agent_id, status)""")
        self.conn.execute(
            """CREATE INDEX IF NOT EXISTS memory_link_relation
               ON memory_link (relation, src, dst)""")
        self.conn.execute(
            """CREATE INDEX IF NOT EXISTS memory_vis
               ON memory (user_id, workspace_id, visibility, status)""")
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS app_access_policy (
                   client_id TEXT PRIMARY KEY,
                   status TEXT NOT NULL DEFAULT 'allow',
                   allowed_scopes_json TEXT,
                   allowed_tools_json TEXT,
                   note TEXT DEFAULT '',
                   updated_at TEXT NOT NULL
               )"""
        )
        self.conn.execute(
            """CREATE INDEX IF NOT EXISTS audit_log_seq
               ON audit_log (user_id, seq)""")
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS app_access_event (
                   seq INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts TEXT NOT NULL,
                   client_id TEXT NOT NULL,
                   tool_name TEXT NOT NULL,
                   scope TEXT,
                   decision TEXT NOT NULL,
                   reason TEXT DEFAULT '',
                   prev_hash TEXT NOT NULL,
                   entry_hash TEXT NOT NULL
               )"""
        )

    def close(self) -> None:
        # 18.11.2026: закрытие без замка проскакивало посреди запроса другого потока (сервер Studio ещё отвечал) —
        # SQLite падал с access violation и ронял весь процесс. Теперь закрытие ждёт, пока идущий запрос завершится.
        with self._lock:
            try:
                self._сбросить_счётчики()
            except sqlite3.Error:
                pass
            self.conn.close()

    def stamp(self) -> tuple[int, int]:
        """Отметка состояния базы: свои коммиты и data_version (меняется, когда коммитит другое соединение)."""
        with self._lock:
            return self.writes, self.conn.execute("PRAGMA data_version").fetchone()[0]

    def execute(self, sql: str, params: tuple = ()):
        with self._lock:
            cur = self.conn.execute(sql, params)
            self._влить_счётчики()        # отложенные счётчики уходят тем же коммитом — без лишней записи на диск
            self.conn.commit()
            self.writes += 1
            return cur

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            self._сбросить_если_читают(sql)
            return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            self._сбросить_если_читают(sql)
            return self.conn.execute(sql, params).fetchone()

    def purge(self) -> None:
        """Убирает следы затёртого текста из индекса и журнала: после этого его нет в файлах базы."""
        with self._lock:
            self.conn.execute("INSERT INTO memory_fts(memory_fts) VALUES('optimize')")
            self.conn.commit()
            self.writes += 1
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()

    def script(self, sql: str) -> None:
        """Схема модуля (executescript) — под тем же замком, что и остальные обращения."""
        with self._lock:
            self.conn.executescript(sql)
            self.conn.commit()
            self.writes += 1

    def counters(self, ops: list[tuple[str, tuple]]) -> None:
        """0.4.10: служебные счётчики поиска (сколько раз показана запись, статистика поисков) одной
        транзакцией и без сдвига отметки stamp(). Они не участвуют в ранжировании, поэтому не должны сбрасывать
        кэш кандидатов и векторов: раньше каждый поиск сам сбрасывал кэш своей же записью счётчика."""
        if not ops:
            return
        # 18.11.2026: статистику поиска откладывает search_stats_later() (профиль: 0,53 из 0,61 с поиска на 20 000
        # записях уходило на её commit; synchronous = FULL не ослабляем). Здесь — данные, которые пишутся сразу.
        with self._lock:
            try:
                for sql, params in ops:
                    self.conn.execute(sql, params)
                self._влить_счётчики()      # отложенная статистика поиска уходит тем же коммитом
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def search_stats_later(self, ops: list[tuple[str, tuple]]) -> None:
        """ТОЛЬКО статистика поиска (показы записи, счётчик поисков за день) — копится и пишется пачкой.

        Связи, подписи и журнал аудита сюда НЕ идут: они пишутся сразу через counters() (найдено полным прогоном:
        отложенные связи derived_from терялись, и каскадное забвение не находило выводы)."""
        if not ops:
            return
        with self._lock:
            self._отложенные.extend(ops)
            if time.monotonic() - self._сброшено >= 5.0 or len(self._отложенные) >= 2000:
                self._сбросить_счётчики()

    _ПОЛЯ_СЧЁТЧИКОВ = ("search_stats", "access_count", "last_seen_at")

    def _влить_счётчики(self) -> None:
        if self._отложенные:
            for sql, params in self._отложенные:
                self.conn.execute(sql, params)
            self._отложенные.clear()
            self._сброшено = time.monotonic()

    def _сбросить_счётчики(self) -> None:
        if not self._отложенные:
            return
        # Посреди чужой незавершённой транзакции (забвение, импорт из нескольких шагов) свой commit нельзя: он
        # зафиксировал бы половину чужой работы. Тогда счётчики уйдут с ближайшим коммитом через execute/atomic.
        if self.conn.in_transaction:
            return
        try:
            self._влить_счётчики()
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def _сбросить_если_читают(self, sql: str) -> None:
        if self._отложенные and any(п in sql for п in self._ПОЛЯ_СЧЁТЧИКОВ):
            self._сбросить_счётчики()

    def flush(self) -> None:
        """Записать отложенные счётчики сейчас (для экспорта, отчётов и тестов)."""
        with self._lock:
            self._сбросить_счётчики()

    def atomic(self, ops: list[tuple[str, tuple]]) -> None:
        """Несколько записей одной транзакцией: либо все, либо ни одной.

        16.10.2026: якорь L3 писал строку якоря, листья и пометки записей отдельными
        коммитами — сбой посередине оставлял якорь без части листьев.
        """
        with self._lock:
            try:
                for sql, params in ops:
                    self.conn.execute(sql, params)
                self._влить_счётчики()
                self.conn.commit()
                self.writes += 1
            except Exception:
                self.conn.rollback()
                raise
