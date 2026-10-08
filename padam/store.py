"""Хранилище. SQLite — по умолчанию, работает без установки чего-либо.

Векторы хранятся как BLOB, поиск — полным перебором с numpy. Для объёмов
до десятков тысяч записей это быстрее, чем возня с индексом. Когда база
вырастет, слой заменяется на Postgres с pgvector без изменения логики
выше.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from . import config

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
    факт_ключ         TEXT
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

CREATE TRIGGER IF NOT EXISTS memory_fts_delete AFTER DELETE ON memory BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, content)
    VALUES ('delete', old.rowid, old.content);
END;

CREATE TRIGGER IF NOT EXISTS memory_fts_update AFTER UPDATE OF content ON memory BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, content)
    VALUES ('delete', old.rowid, old.content);
    INSERT INTO memory_fts(rowid, content)
    SELECT new.rowid, new.content WHERE new.content IS NOT NULL;
END;

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

-- ключи для L3: уничтожение ключа = необратимое удаление содержания
CREATE TABLE IF NOT EXISTS anchor_key (
    memory_id    TEXT PRIMARY KEY,
    key_ref      TEXT NOT NULL,
    shard_count  INTEGER NOT NULL DEFAULT 2,
    threshold    INTEGER NOT NULL DEFAULT 2,
    destroyed_at TEXT,
    created_at   TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_ts(s: str) -> datetime:
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


class Store:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else config.DB_PATH
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._дополнить_схему()
        self.conn.commit()

    def _дополнить_схему(self) -> None:
        """Досоздаёт колонки, которых нет в уже существующих базах.

        `CREATE TABLE IF NOT EXISTS` не трогает таблицу, если она уже есть, —
        значит база, созданная прежней версией, останется без новых полей, и
        запись упадёт на «no such column». Добавляем недостающее по факту, а
        не по номеру версии: так работает и с базами неизвестного возраста.

        Только ДОБАВЛЯЕТ. Ничего не удаляет и не переписывает (раздел 19).
        """
        НУЖНЫЕ = {"memory": {"embedding_model": "TEXT", "факт_ключ": "TEXT"}}
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
                    self.conn.execute(
                        "ALTER TABLE %s ADD COLUMN %s %s" % (таблица, имя, тип))

        # 🔴 ИНДЕКСЫ ПО ДОБАВЛЕННЫМ КОЛОНКАМ — ТОЛЬКО ЗДЕСЬ, ПОСЛЕ МИГРАЦИИ.
        #
        # Их нельзя держать в SCHEMA: `executescript` выполняется ДО
        # миграции, и на базе, созданной прежней версией, падает с
        # «no such column: факт_ключ». Замер 05.09.2026: так оборвался
        # перезапуск прогона на старой базе — код был верен, а порядок нет.
        self.conn.execute(
            """CREATE INDEX IF NOT EXISTS memory_факт_ключ
               ON memory (user_id, scope, факт_ключ, status)""")

    def close(self) -> None:
        self.conn.close()

    def execute(self, sql: str, params: tuple = ()):
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        return cur

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()
