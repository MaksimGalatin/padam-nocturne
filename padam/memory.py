"""Ядро PADAM: запись, поиск, отзыв, история версий."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

import numpy as np

from . import classify, config, embeddings, retrieval
from .store import Store, new_id, now_iso, pack, parse_ts, unpack


@dataclass
class Record:
    id: str
    kind: str
    content: str | None
    importance: float
    confidence: float
    last_confirmed_at: datetime
    similarity: float = 0.0
    score: float = 0.0
    strategies: tuple[str, ...] = ()
    expired: bool = False

    def explain(self) -> str:
        d = decay(self.kind, self.last_confirmed_at)
        found_by = "+".join(self.strategies) if self.strategies else "—"
        stale = "  ИСТЁК СРОК" if self.expired else ""
        return (f"rrf={self.similarity:.3f} × imp={self.importance:.2f} "
                f"× conf={self.confidence:.2f} × decay={d:.2f} "
                f"= {self.score:.4f}   [{found_by}]{stale}")


def content_hash(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()


def decay(kind: str, last_seen: datetime) -> float:
    """exp(-ln2 · Δt / T½). preference и identity не затухают."""
    half_life = config.HALF_LIFE_DAYS.get(kind)
    if half_life is None:
        return 1.0
    days = (datetime.now(timezone.utc) - last_seen).total_seconds() / 86400
    return math.exp(-math.log(2) * max(days, 0) / half_life)


class Memory:
    def __init__(self, user_id: str = "default", store: Store | None = None):
        self.user_id = user_id
        self.store = store or Store()

    def close(self) -> None:
        self.store.close()

    # -- сессии --------------------------------------------------------

    def current_session(self, text: str) -> str:
        vec = embeddings.embed(text)
        row = self.store.one(
            """SELECT id, last_active_at, centroid, episode_count
               FROM session WHERE user_id = ?
               ORDER BY last_active_at DESC LIMIT 1""",
            (self.user_id,))

        if row:
            gap = datetime.now(timezone.utc) - parse_ts(row["last_active_at"])
            centroid = unpack(row["centroid"])
            same_topic = True
            if centroid is not None and centroid.shape == vec.shape:
                same_topic = (1 - embeddings.cosine(vec, centroid)) <= \
                    config.SESSION_TOPIC_DISTANCE

            if gap < timedelta(hours=config.SESSION_GAP_HOURS) and same_topic:
                n = row["episode_count"]
                new_centroid = vec if centroid is None or centroid.shape != vec.shape \
                    else (centroid * n + vec) / (n + 1)
                self.store.execute(
                    """UPDATE session SET last_active_at = ?, centroid = ?,
                       episode_count = episode_count + 1 WHERE id = ?""",
                    (now_iso(), pack(new_centroid), row["id"]))
                return row["id"]

        sid = new_id()
        self.store.execute(
            """INSERT INTO session
               (id, user_id, started_at, last_active_at, centroid, episode_count)
               VALUES (?,?,?,?,?,1)""",
            (sid, self.user_id, now_iso(), now_iso(), pack(vec)))
        return sid

    # -- L1: журнал эпизодов -------------------------------------------

    def log(self, content: str, role: str = "user",
            scope: str = "global", priority: float = 1.0) -> str:
        session_id = self.current_session(content)
        eid = new_id()
        self.store.execute(
            """INSERT INTO episode
               (id, user_id, session_id, scope, role, content, embedding,
                priority, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (eid, self.user_id, session_id, scope, role, content,
             pack(embeddings.embed(content)), priority, now_iso()))
        return eid

    # -- L2: запись с фильтром противоречий ----------------------------

    def remember(self, content: str, kind: str | None = None,
                 importance: float = 0.5, scope: str = "global",
                 source_episode_id: str | None = None) -> tuple[str, str]:
        """Возвращает (исход, id записи).

        Исходы: created | duplicate | merged | superseded | coexists
        """
        kind = kind or classify.infer_kind(content)
        if kind not in config.KINDS:
            kind = "fact"
        vec = embeddings.embed(content)

        # СНАЧАЛА точный поиск по структурному ключу, и только потом — по
        # близости векторов. Порядок важен: ключ находит спорящую запись
        # наверняка, а вектор — как повезёт. Подробности в `_по_ключу`.
        по_ключу = self._по_ключу(content, scope)
        if по_ключу is not None:
            old_id, old_content = по_ключу
        else:
            near = self._nearest_active(vec, kind, scope)
            threshold = config.similarity_threshold(embeddings.backend())

            if near is None or near[2] < threshold:
                return "created", self._insert(content, kind, vec, importance,
                                               scope, source_episode_id)

            old_id, old_content, _ = near
        verdict = classify.resolve(content, old_content)

        if verdict == "duplicate":
            self.store.execute(
                """UPDATE memory SET last_seen_at = ?, last_confirmed_at = ?,
                   access_count = access_count + 1,
                   confidence = MIN(confidence + 0.05, 1.0) WHERE id = ?""",
                (now_iso(), now_iso(), old_id))
            return "duplicate", old_id

        if verdict == "coexist":
            return "coexists", self._insert(content, kind, vec, importance,
                                            scope, source_episode_id)

        # refinement и contradiction создают новую версию
        new_mid = self._insert(content, kind, vec, importance, scope,
                               source_episode_id, supersedes=old_id)
        self.store.execute(
            """UPDATE memory SET status = 'superseded', superseded_by = ?,
               valid_to = ? WHERE id = ?""",
            (new_mid, now_iso(), old_id))
        return ("merged" if verdict == "refinement" else "superseded"), new_mid

    def _insert(self, content, kind, vec, importance, scope,
                source_episode_id=None, supersedes=None,
                expires_at: str | None = None) -> str:
        mid = new_id()
        ts = now_iso()
        self.store.execute(
            """INSERT INTO memory
               (id, user_id, scope, kind, content, embedding, importance,
                confidence, created_at, last_seen_at, last_confirmed_at,
                valid_from, expires_at, status, supersedes,
                source_episode_id, content_hash, embedding_model, факт_ключ)
               VALUES (?,?,?,?,?,?,?,1.0,?,?,?,?,?,'active',?,?,?,?,?)""",
            (mid, self.user_id, scope, kind, content, pack(vec),
             max(0.0, min(1.0, importance)), ts, ts, ts, ts, expires_at,
             supersedes, source_episode_id, content_hash(content),
             embeddings.метка_модели(), classify.разобрать_факт(content)[0]))
        return mid

    def связи_от(self, сущность: str, scope: str = "global",
                 предел: int = 12) -> list[str]:
        """Действующие записи, где `сущность` стоит в левой части утверждения.

        🔴 ЗАЧЕМ. Многошаговый вопрос («гражданство супруга автора книги»)
        решается только обходом по связям: сначала находим автора, потом
        супруга автора, потом гражданство супруга. По тексту так пройти
        нельзя — на втором шаге неизвестно, что искать, пока не разрешён
        первый.

        Структурный ключ уже хранит «объект + свойство», поэтому поиск
        записей ОБ ЭТОЙ сущности — это обычный запрос по префиксу ключа, а не
        угадывание по близости векторов. Берутся только действующие записи:
        устаревшие версии в обход не попадают, иначе цепочка уведёт в прошлое.

        Полезно и вне бенчмарка: «что я вообще знаю про этого человека» —
        обычный вопрос к памяти, на который поиск по смыслу отвечает хуже.
        """
        с = (сущность or "").strip().lower()
        if not с:
            return []
        rows = self.store.query(
            """SELECT content FROM memory
               WHERE user_id = ? AND scope = ? AND status = 'active'
                 AND факт_ключ IS NOT NULL
                 AND (факт_ключ LIKE ? OR факт_ключ LIKE ?)
               ORDER BY created_at DESC, rowid DESC
               LIMIT ?""",
            (self.user_id, scope, с + " %", "%" + с + " %", предел))
        return [r["content"] for r in rows]

    def _по_ключу(self, content, scope):
        """Действующая запись о ТОМ ЖЕ свойстве того же объекта, или None.

        🔴 ЗАЧЕМ ЭТО НУЖНО СВЕРХ ПОИСКА ПО ВЕКТОРУ (найдено замером 05.09.2026).

        Спорящая запись раньше искалась только по близости векторов, и если
        порог её не доставал — запись просто создавалась рядом, а конфликт
        оставался неразрешённым. Цена на срезе mh_6k: настоящих конфликтов
        142, а поиск по вектору доводил до разбора около 51. Остальные
        устаревшие факты продолжали жить как действующие и путали ответ.

        Ключ — «объект + свойство» без значения. Совпал ключ, различается
        значение — это противоречие по определению, без участия модели и без
        зависимости от случайной близости текстов.

        Возвращает самую свежую действующую запись с этим ключом: именно её
        новая версия и должна заместить.
        """
        ключ = classify.разобрать_факт(content)[0]
        if not ключ:
            return None
        rows = self.store.query(
            """SELECT id, content FROM memory
               WHERE user_id = ? AND scope = ? AND факт_ключ = ?
                 AND status = 'active'
               ORDER BY created_at DESC, rowid DESC LIMIT 1""",
            (self.user_id, scope, ключ))
        return (rows[0]["id"], rows[0]["content"]) if rows else None

    def _nearest_active(self, vec, kind, scope):
        rows = self.store.query(
            """SELECT id, content, embedding FROM memory
               WHERE user_id = ? AND scope = ? AND kind = ?
                 AND status = 'active' AND embedding IS NOT NULL""",
            (self.user_id, scope, kind))
        best = None
        for r in rows:
            sim = embeddings.cosine(vec, unpack(r["embedding"]))
            if best is None or sim > best[2]:
                best = (r["id"], r["content"], sim)
        return best

    # -- L2: поиск ------------------------------------------------------

    def recall(self, query: str, scope: str = "global",
               kind: str | None = None, limit: int = 10,
               session_id: str | None = None) -> list[Record]:
        """Гибридный поиск: вектор + BM25 + точные идентификаторы, RRF.

        Итог: rrf × важность × уверенность × затухание × свежесть сессии.
        Затухание считается от last_confirmed_at — от момента, когда запись
        в последний раз подтверждалась верной, а не когда её извлекали.
        """
        sql = """SELECT id, kind, content, embedding, importance, confidence,
                        last_confirmed_at, expires_at, session_id
                 FROM memory
                 WHERE user_id = ? AND scope = ? AND status = 'active'"""
        params: list = [self.user_id, scope]
        if kind:
            sql += " AND kind = ?"
            params.append(kind)

        raw = self.store.query(sql, tuple(params))
        if not raw:
            return []

        rows = [{"id": r["id"], "kind": r["kind"], "content": r["content"],
                 "_vec": unpack(r["embedding"]), "importance": r["importance"],
                 "confidence": r["confidence"],
                 "last_confirmed_at": r["last_confirmed_at"],
                 "expires_at": r["expires_at"],
                 "session_id": r["session_id"]} for r in raw]

        scores, rankings = retrieval.hybrid_rank(
            self.store, self.user_id, scope, query, rows)
        if not scores:
            return []

        by_id = {r["id"]: r for r in rows}
        now = datetime.now(timezone.utc)
        today = now.date()
        out: list[Record] = []

        for rid, rrf in scores.items():
            r = by_id.get(rid)
            if r is None:
                continue
            confirmed = parse_ts(r["last_confirmed_at"])

            expired = False
            if r["expires_at"]:
                expired = parse_ts(r["expires_at"]) < now

            boost = 1.0
            if session_id and r["session_id"] == session_id:
                boost = config.SESSION_BOOST_CURRENT
            elif confirmed.date() == today:
                boost = config.SESSION_BOOST_TODAY

            found_by = tuple(name for name, ids in rankings.items() if rid in ids)

            rec = Record(rid, r["kind"], r["content"], r["importance"],
                         r["confidence"], confirmed, rrf,
                         strategies=found_by, expired=expired)
            rec.score = (rrf * rec.importance * rec.confidence
                         * decay(rec.kind, confirmed) * boost
                         * (config.EXPIRED_PENALTY if expired else 1.0))
            out.append(rec)

        out.sort(key=lambda x: x.score, reverse=True)
        top = out[:limit]

        # извлечение обновляет только last_seen_at: сам факт того, что
        # запись показали, не делает её верной
        for rec in top:
            self.store.execute(
                """UPDATE memory SET access_count = access_count + 1,
                   last_seen_at = ? WHERE id = ?""", (now_iso(), rec.id))
        return top

    def confirm(self, memory_id: str) -> bool:
        """Запись оказалась верной: обновить свежесть, поднять уверенность.

        Это то, что должно вызываться, когда извлечённая запись подтвердилась
        в разговоре, а не при каждом показе.
        """
        cur = self.store.execute(
            """UPDATE memory SET last_confirmed_at = ?,
               confidence = MIN(confidence + 0.05, 1.0)
               WHERE id = ? AND user_id = ? AND status = 'active'""",
            (now_iso(), memory_id, self.user_id))
        return cur.rowcount > 0

    def refute(self, memory_id: str, drop: float = 0.3) -> bool:
        """Запись оказалась неверной: снизить уверенность.

        Свежесть НЕ обновляется. Если уверенность падает до нуля, запись
        уходит в архив, но остаётся в истории.
        """
        self.store.execute(
            """UPDATE memory SET confidence = MAX(confidence - ?, 0.0),
               refuted_count = refuted_count + 1
               WHERE id = ? AND user_id = ?""", (drop, memory_id, self.user_id))
        cur = self.store.execute(
            """UPDATE memory SET status = 'archived'
               WHERE id = ? AND user_id = ? AND confidence <= 0.0""",
            (memory_id, self.user_id))
        return True

    # -- отзыв ----------------------------------------------------------

    def revoke(self, memory_id: str) -> bool:
        """Физическое затирание содержания. Хеш и якорь остаются."""
        cur = self.store.execute(
            """UPDATE memory SET status = 'revoked', content = NULL,
               embedding = NULL WHERE id = ? AND user_id = ?""",
            (memory_id, self.user_id))
        # Затирается сам ключ, а не только ставится отметка: шифротекст этой
        # записи в Arweave без ключа — шум навсегда. Отметка времени уходит
        # в следующий корень L3 «квитанцией забвения» (anchor.py).
        self.store.execute(
            """UPDATE anchor_key SET key_ref = 'destroyed', destroyed_at = ?
               WHERE memory_id = ? AND destroyed_at IS NULL""",
            (now_iso(), memory_id))
        return cur.rowcount > 0

    # -- история версий -------------------------------------------------

    def timeline(self, memory_id: str) -> list[dict]:
        """Цепочка версий: от текущей вглубь, к самой первой."""
        chain, seen, cur_id = [], set(), memory_id
        while cur_id and cur_id not in seen:
            seen.add(cur_id)
            row = self.store.one(
                """SELECT id, content, status, created_at, supersedes
                   FROM memory WHERE id = ?""", (cur_id,))
            if not row:
                break
            chain.append(dict(row))
            cur_id = row["supersedes"]
        return list(reversed(chain))

    # -- выгрузка -------------------------------------------------------

    def export(self, include_superseded: bool = True,
               scope: str | None = None) -> dict:
        """Полная выгрузка памяти. Доступна всегда, без окна и без условий.

        Формат самодостаточен: по нему можно восстановить состояние в
        другой системе или просто прочитать глазами.
        """
        sql = "SELECT * FROM memory WHERE user_id = ?"
        params: list = [self.user_id]
        if scope:
            sql += " AND scope = ?"
            params.append(scope)
        if not include_superseded:
            sql += " AND status = 'active'"
        sql += " ORDER BY created_at"

        records = []
        for r in self.store.query(sql, tuple(params)):
            d = dict(r)
            d.pop("embedding", None)          # бинарь в выгрузке бесполезен
            h = d.pop("content_hash", None)
            d["content_hash"] = h.hex() if h else None
            records.append(d)

        sessions = [dict(r) for r in self.store.query(
            "SELECT id, started_at, last_active_at, episode_count "
            "FROM session WHERE user_id = ? ORDER BY started_at",
            (self.user_id,))]

        runs = [dict(r) for r in self.store.query(
            "SELECT * FROM nocturne_run WHERE user_id = ? ORDER BY started_at",
            (self.user_id,))]

        return {
            "format": "padam-export/1",
            "exported_at": now_iso(),
            "user_id": self.user_id,
            "counts": {"memory": len(records), "sessions": len(sessions),
                       "nocturne_runs": len(runs)},
            "memory": records,
            "sessions": sessions,
            "nocturne_runs": runs,
        }

    def import_(self, payload: dict, overwrite: bool = False) -> int:
        """Загрузка выгрузки обратно. Возвращает число внесённых записей."""
        if payload.get("format") != "padam-export/1":
            raise ValueError("неизвестный формат выгрузки")
        added = 0
        for rec in payload.get("memory", []):
            exists = self.store.one("SELECT id FROM memory WHERE id = ?",
                                    (rec["id"],))
            if exists and not overwrite:
                continue
            if exists:
                self.store.execute("DELETE FROM memory WHERE id = ?", (rec["id"],))
            vec = embeddings.embed(rec["content"]) if rec.get("content") else None
            ch = bytes.fromhex(rec["content_hash"]) if rec.get("content_hash") else None
            self.store.execute(
                """INSERT INTO memory
                   (id, user_id, scope, kind, content, embedding, importance,
                    confidence, created_at, last_seen_at, last_confirmed_at,
                    expires_at, valid_from, valid_to, access_count,
                    refuted_count, status, supersedes, superseded_by,
                    source_episode_id, session_id, content_hash,
                    anchor_tx, anchor_slot)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rec["id"], self.user_id, rec.get("scope", "global"),
                 rec.get("kind", "fact"), rec.get("content"), pack(vec),
                 rec.get("importance", 0.5), rec.get("confidence", 1.0),
                 rec.get("created_at", now_iso()),
                 rec.get("last_seen_at", now_iso()),
                 rec.get("last_confirmed_at", now_iso()),
                 rec.get("expires_at"), rec.get("valid_from"),
                 rec.get("valid_to"), rec.get("access_count", 0),
                 rec.get("refuted_count", 0), rec.get("status", "active"),
                 rec.get("supersedes"), rec.get("superseded_by"),
                 rec.get("source_episode_id"), rec.get("session_id"), ch,
                 rec.get("anchor_tx"), rec.get("anchor_slot")))
            added += 1
        return added

    # -- статистика -----------------------------------------------------

    def stats(self) -> dict:
        def scalar(sql, params=()):
            row = self.store.one(sql, params)
            return row[0] if row else 0

        by_kind = {
            r["kind"]: r["n"] for r in self.store.query(
                """SELECT kind, COUNT(*) AS n FROM memory
                   WHERE user_id = ? AND status = 'active'
                   GROUP BY kind""", (self.user_id,))}

        return {
            "backend": embeddings.backend(),
            "db": str(self.store.path),
            "active": scalar(
                "SELECT COUNT(*) FROM memory WHERE user_id=? AND status='active'",
                (self.user_id,)),
            "superseded": scalar(
                "SELECT COUNT(*) FROM memory WHERE user_id=? AND status='superseded'",
                (self.user_id,)),
            "revoked": scalar(
                "SELECT COUNT(*) FROM memory WHERE user_id=? AND status='revoked'",
                (self.user_id,)),
            "episodes_pending": scalar(
                "SELECT COUNT(*) FROM episode WHERE user_id=? AND processed=0",
                (self.user_id,)),
            "by_kind": by_kind,
        }
