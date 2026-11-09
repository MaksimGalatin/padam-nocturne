"""Ядро PADAM: запись, поиск, отзыв, история версий."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

import numpy as np

from . import classify, config, embeddings, integrity, retrieval, safety
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
    origin: str | None = None
    created_at: str | None = None
    status: str = "active"
    scope: str = "global"
    signed: bool | None = None       # для личности и предпочтений: подписана ли владельцем
    conflict: bool = False           # другая действующая запись о том же говорит иное

    def explain(self) -> str:
        d = decay(self.kind, self.last_confirmed_at)
        found_by = "+".join(self.strategies) if self.strategies else "—"
        stale = "  ИСТЁК СРОК" if self.expired else ""
        return (f"rrf={self.similarity:.3f} × imp={self.importance:.2f} "
                f"× conf={self.confidence:.2f} × decay={d:.2f} "
                f"= {self.score:.4f}   [{found_by}]{stale}")


def parse_as_of(value: str | datetime) -> datetime:
    """Момент для поиска «на дату»: дата без времени — конец дня по UTC, время без зоны — UTC."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    текст = str(value).strip()
    if len(текст) == 10:
        return datetime.fromisoformat(текст).replace(hour=23, minute=59, second=59, microsecond=999999,
                                                     tzinfo=timezone.utc)
    if текст.endswith(("Z", "z")):
        текст = текст[:-1] + "+00:00"   # Python 3.10 не понимает «Z»
    момент = datetime.fromisoformat(текст)
    return момент if момент.tzinfo else момент.replace(tzinfo=timezone.utc)


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
            scope: str = "global", priority: float = 1.0) -> str | None:
        """Эпизод в журнал L1. Мусор в журнал не идёт (сито кратковременного внимания, L0):

        строка без единой буквы и цифры (пустая, одни знаки) не пишется — возвращается None;
        точный повтор предыдущего эпизода той же роли за последние 60 секунд не дублируется —
        возвращается id уже записанного. Всё остальное пишется как есть.
        """
        content = safety.clean(content)
        if not re.search(r"\w", content or "") or not re.search(r"[^\W_]", content or ""):
            return None
        прошлый = self.store.one(
            """SELECT id, content, role, created_at FROM episode
               WHERE user_id = ? AND scope = ? ORDER BY created_at DESC, rowid DESC LIMIT 1""",
            (self.user_id, scope))
        if (прошлый and прошлый["content"] == content and прошлый["role"] == role
                and (datetime.now(timezone.utc) - parse_ts(прошлый["created_at"])).total_seconds() < 60):
            return прошлый["id"]
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
                 source_episode_id: str | None = None,
                 origin: str = "user", guarded: bool = False,
                 derived_from: list[str] | None = None) -> tuple[str, str]:
        """Возвращает (исход, id записи).

        Исходы: created | duplicate | merged | superseded | coexists | quarantined

        origin — откуда запись (config.ORIGINS). guarded=True ставит вызывающий, которому нельзя
        верить на слово, прежде всего MCP: агент мог прочитать команду на чужой странице, а его
        пометку о происхождении проверить нечем. Тогда похожее на команду и замена защищённой
        записи не применяются, а ждут решения владельца (`padam review`).

        derived_from — id записей, из которых сделан этот вывод. По этим связям забвение
        источника доходит и до выводов (`forget --with-derived`).
        """
        исход, mid = self._remember(content, kind, importance, scope, source_episode_id, origin, guarded)
        # При повторе mid — это уже существующая запись, возможно владельца. Связать её «выводом» из
        # чужой записи значило бы дать агенту способ стереть её каскадом при забвении источника.
        if derived_from and исход != "duplicate":
            self._связать(derived_from, mid)
        if исход in ("created", "merged", "superseded", "coexists") and not (guarded and not config.MCP_TRUST_WRITES):
            self._подписать(mid)
        return исход, mid

    def _remember(self, content: str, kind: str | None, importance: float, scope: str,
                  source_episode_id: str | None, origin: str, guarded: bool) -> tuple[str, str]:
        content = safety.clean(content)
        if origin not in config.ORIGINS:
            origin = "agent" if guarded else "user"
        guarded = guarded and not config.MCP_TRUST_WRITES
        kind = kind or classify.infer_kind(content)
        if kind not in config.KINDS:
            kind = "fact"
        vec = embeddings.embed(content)

        if guarded and safety.looks_like_instruction(content):
            return "quarantined", self._insert(
                content, kind, vec, importance, scope, source_episode_id,
                origin=origin, status="quarantined", reason="looks like an instruction")

        # Кто человек и как с ним работать, решает только он сам. Через MCP пометку origin
        # проверить нечем, поэтому запись о личности или предпочтении от агента или чужого
        # источника ждёт владельца всегда, а с пометкой user — если такая запись у человека
        # уже есть (первую, пустую, пропускаем). Вид берётся и из самого текста: «Меня зовут Боб»
        # с kind=fact остаётся записью о личности.
        причина_защиты = None
        if guarded:
            вид_по_тексту = classify.infer_kind_rules(content)
            защищённый_вид = (kind if kind in config.PROTECTED_KINDS
                              else вид_по_тексту if вид_по_тексту in config.PROTECTED_KINDS else None)
            if защищённый_вид and origin != "user":
                причина_защиты = f"protected {защищённый_вид} record from {origin}"
            elif защищённый_вид and self._есть_активная(защищённый_вид):
                причина_защиты = f"would change the owner's {защищённый_вид} records"

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
                if причина_защиты:
                    return "quarantined", self._insert(
                        content, kind, vec, importance, scope, source_episode_id,
                        origin=origin, status="quarantined", reason=причина_защиты)
                return "created", self._insert(content, kind, vec, importance,
                                               scope, source_episode_id, origin=origin)

            old_id, old_content, _ = near
        verdict = classify.resolve(content, old_content)

        if verdict == "duplicate":
            # Через MCP подтверждением не считается и пометка user: её ставит сам агент.
            if origin == "user" and not guarded:
                self.store.execute(
                    """UPDATE memory SET last_seen_at = ?, last_confirmed_at = ?,
                       access_count = access_count + 1,
                       confidence = MIN(confidence + 0.05, 1.0) WHERE id = ?""",
                    (now_iso(), now_iso(), old_id))
            else:
                # Модель повторила то, что уже есть: это не новое подтверждение, а её собственное
                # эхо. Иначе ошибка, записанная один раз, с каждым повтором становилась бы вернее.
                self.store.execute(
                    """UPDATE memory SET last_seen_at = ?,
                       access_count = access_count + 1 WHERE id = ?""",
                    (now_iso(), old_id))
            return "duplicate", old_id

        if verdict == "coexist":
            if причина_защиты:
                return "quarantined", self._insert(
                    content, kind, vec, importance, scope, source_episode_id,
                    origin=origin, status="quarantined", reason=причина_защиты)
            return "coexists", self._insert(content, kind, vec, importance,
                                            scope, source_episode_id, origin=origin)

        if guarded:
            старая = self.store.one("SELECT kind, origin FROM memory WHERE id = ?", (old_id,))
            причина = причина_защиты
            if not причина and старая["kind"] in config.PROTECTED_KINDS:
                причина = f"would replace a protected {старая['kind']} record"
            elif not причина and origin == "external" and (старая["origin"] or "user") == "user":
                причина = "external source over the owner's record"
            if причина:
                return "quarantined", self._insert(
                    content, kind, vec, importance, scope, source_episode_id,
                    supersedes=old_id, origin=origin, status="quarantined", reason=причина)

        # refinement и contradiction создают новую версию
        new_mid = self._insert(content, kind, vec, importance, scope,
                               source_episode_id, supersedes=old_id, origin=origin)
        self.store.execute(
            """UPDATE memory SET status = 'superseded', superseded_by = ?,
               valid_to = ? WHERE id = ?""",
            (new_mid, now_iso(), old_id))
        return ("merged" if verdict == "refinement" else "superseded"), new_mid

    # -- связи выводов и подпись владельца ------------------------------

    def _связать(self, источники: list[str], вывод: str) -> int:
        """Связи «вывод сделан из записи». Только записи этого же человека; не больше 20 за раз."""
        добавлено = 0
        for src in list(dict.fromkeys(источники))[:20]:
            if src == вывод or not self.store.one(
                    "SELECT 1 FROM memory WHERE id = ? AND user_id = ?", (src, self.user_id)):
                continue
            self.store.execute("INSERT OR IGNORE INTO memory_link (src, dst, created_at) VALUES (?,?,?)",
                               (src, вывод, now_iso()))
            добавлено += 1
        return добавлено

    def derived(self, memory_id: str) -> list[str]:
        """Все выводы из записи, по цепочке: вывод из вывода тоже считается."""
        найдено, очередь = [], [memory_id]
        while очередь:
            src = очередь.pop()
            for r in self.store.query(
                    """SELECT l.dst FROM memory_link l JOIN memory m ON m.id = l.dst
                       WHERE l.src = ? AND m.user_id = ?""", (src, self.user_id)):
                if r["dst"] not in найдено and r["dst"] != memory_id:
                    найдено.append(r["dst"])
                    очередь.append(r["dst"])
        return найдено

    def _ключ_подписи(self) -> bytes:
        ключ, создан = integrity.owner_key(self.store)
        if создан:
            # Доверие при первом использовании: всё, что уже есть, внесено до появления подписи.
            self._подписать_все(ключ)
        return ключ

    def _подписать_все(self, ключ: bytes) -> int:
        rows = self.store.query(
            f"""SELECT id, kind, content FROM memory WHERE user_id = ? AND status = 'active'
                AND kind IN ({",".join("?" * len(config.PROTECTED_KINDS))})""",
            (self.user_id, *config.PROTECTED_KINDS))
        for r in rows:
            self.store.execute("UPDATE memory SET owner_sig = ? WHERE id = ?",
                               (integrity.sign(ключ, r["id"], r["kind"], r["content"]), r["id"]))
        return len(rows)

    def _подписать(self, memory_id: str) -> None:
        row = self.store.one("SELECT id, kind, content FROM memory WHERE id = ?", (memory_id,))
        if row and integrity.protected(row["kind"]):
            ключ = self._ключ_подписи()
            self.store.execute("UPDATE memory SET owner_sig = ? WHERE id = ?",
                               (integrity.sign(ключ, row["id"], row["kind"], row["content"]), memory_id))

    def unsigned_protected(self) -> list[dict]:
        """Действующие записи о личности и предпочтениях без подписи владельца: внесены мимо PADAM."""
        ключ = self._ключ_подписи()
        rows = self.store.query(
            f"""SELECT id, kind, content, owner_sig, created_at FROM memory WHERE user_id = ? AND status = 'active'
                AND kind IN ({",".join("?" * len(config.PROTECTED_KINDS))})""",
            (self.user_id, *config.PROTECTED_KINDS))
        return [dict(r) for r in rows if not integrity.valid(ключ, r)]

    def trust_protected(self) -> int:
        """Владелец проверил записи о себе и подписывает их текущий вид (`padam trust-protected`)."""
        return self._подписать_все(self._ключ_подписи())

    # -- синонимы терминов ----------------------------------------------

    def add_alias(self, term: str, alias: str) -> bool:
        term, alias = term.strip().lower(), alias.strip().lower()
        if not term or not alias or term == alias:
            return False
        self.store.execute("INSERT OR IGNORE INTO term_alias (user_id, term, alias, created_at) VALUES (?,?,?,?)",
                           (self.user_id, term, alias, now_iso()))
        return True

    def remove_alias(self, term: str, alias: str) -> bool:
        term, alias = term.strip().lower(), alias.strip().lower()
        cur = self.store.execute(
            """DELETE FROM term_alias WHERE user_id = ? AND
               ((term = ? AND alias = ?) OR (term = ? AND alias = ?))""",
            (self.user_id, term, alias, alias, term))
        return cur.rowcount > 0

    def aliases(self) -> list[tuple[str, str]]:
        return [(r["term"], r["alias"]) for r in self.store.query(
            "SELECT term, alias FROM term_alias WHERE user_id = ? ORDER BY term, alias", (self.user_id,))]

    def _расширить(self, query: str) -> str:
        """Запрос плюс синонимы терминов, которые в нём есть (в обе стороны)."""
        q = query.lower()
        добавить = []
        for term, alias in self.aliases():
            for есть, дать in ((term, alias), (alias, term)):
                if re.search(r"(?<!\w)" + re.escape(есть) + r"(?!\w)", q) and дать not in q and дать not in добавить:
                    добавить.append(дать)
        return query if not добавить else query + " " + " ".join(добавить)

    # -- противоречия ----------------------------------------------------

    def conflicts(self) -> list[dict]:
        """Действующие записи, которые спорят: тот же объект и свойство, разные значения.

        В норме такая пара не возникает (новая версия заменяет старую), но её приносят импорт,
        принятие записи с проверки и ручные правки базы. Сон их находит и называет; какая верна,
        решает человек или следующее подтверждение.
        """
        группы = self.store.query(
            """SELECT scope, факт_ключ, COUNT(*) AS n FROM memory
               WHERE user_id = ? AND status = 'active' AND факт_ключ IS NOT NULL
               GROUP BY scope, факт_ключ HAVING n > 1""", (self.user_id,))
        итог = []
        for г in группы:
            записи = self.store.query(
                """SELECT id, content, origin, confidence, created_at FROM memory
                   WHERE user_id = ? AND status = 'active' AND scope = ? AND факт_ключ = ?
                   ORDER BY created_at""", (self.user_id, г["scope"], г["факт_ключ"]))
            итог.append({"scope": г["scope"], "key": г["факт_ключ"], "records": [dict(r) for r in записи]})
        return итог

    # -- учёт поиска (память о самой памяти) ---------------------------

    def _учесть_поиск(self, пусто: bool) -> None:
        день = datetime.now(timezone.utc).date().isoformat()
        self.store.execute(
            """INSERT INTO search_stats (user_id, day, searches, empty) VALUES (?, ?, 1, ?)
               ON CONFLICT(user_id, day) DO UPDATE SET searches = searches + 1, empty = empty + excluded.empty""",
            (self.user_id, день, 1 if пусто else 0))

    def self_report(self, days: int = 30) -> dict:
        """Как работает сама память: поиски без результата, что чаще опровергают, споры, подписи."""
        с = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
        row = self.store.one(
            "SELECT COALESCE(SUM(searches),0) AS s, COALESCE(SUM(empty),0) AS e FROM search_stats WHERE user_id = ? AND day >= ?",
            (self.user_id, с))
        опровергают = {r["kind"]: r["n"] for r in self.store.query(
            """SELECT kind, SUM(refuted_count) AS n FROM memory WHERE user_id = ? AND refuted_count > 0
               GROUP BY kind ORDER BY n DESC""", (self.user_id,))}
        return {"days": days, "searches": row["s"], "searches_with_nothing_found": row["e"],
                "empty_share": round(row["e"] / row["s"], 3) if row["s"] else 0.0,
                "refutations_by_kind": опровергают, "conflicts": len(self.conflicts()),
                "unsigned_protected": len(self.unsigned_protected())}

    def pending_episodes(self) -> int:
        row = self.store.one("SELECT COUNT(*) FROM episode WHERE user_id = ? AND processed = 0", (self.user_id,))
        return row[0] if row else 0

    # -- кнопка паники ---------------------------------------------------

    def panic(self, wipe_local: bool = False) -> dict:
        """Экстренное забвение. Необратимо.

        Всегда: уничтожаются ключи всех записей — всё, что ушло в Arweave, становится шумом
        навсегда. С wipe_local: ещё и локальная память — каждая запись затирается, журнал эпизодов
        очищается, файл базы уплотняется (secure_delete уже включён), ключ подписи стирается.
        """
        ts = now_iso()
        ключей = self.store.one(
            """SELECT COUNT(*) FROM anchor_key k JOIN memory m ON m.id = k.memory_id
               WHERE m.user_id = ? AND k.destroyed_at IS NULL""", (self.user_id,))[0]
        ops: list[tuple[str, tuple]] = [(
            """UPDATE anchor_key SET key_ref = 'destroyed', destroyed_at = ?
               WHERE destroyed_at IS NULL AND memory_id IN (SELECT id FROM memory WHERE user_id = ?)""",
            (ts, self.user_id))]
        записей = эпизодов = 0
        if wipe_local:
            записей = self.store.one("SELECT COUNT(*) FROM memory WHERE user_id = ? AND content IS NOT NULL",
                                     (self.user_id,))[0]
            эпизодов = self.store.one("SELECT COUNT(*) FROM episode WHERE user_id = ?", (self.user_id,))[0]
            ops += [("""UPDATE memory SET status = 'revoked', content = NULL, embedding = NULL,
                        факт_ключ = NULL, owner_sig = NULL WHERE user_id = ?""", (self.user_id,)),
                    ("DELETE FROM episode WHERE user_id = ?", (self.user_id,)),
                    ("DELETE FROM term_alias WHERE user_id = ?", (self.user_id,))]
        self.store.atomic(ops)
        if wipe_local:
            self.store.purge()
            путь = integrity.key_path(self.store)
            if путь is not None and путь.exists():
                путь.unlink()
        return {"keys_destroyed": ключей, "records_wiped": записей, "episodes_wiped": эпизодов}

    def _есть_активная(self, kind: str) -> bool:
        # Без учёта scope: человек один, и «первая запись о личности» в новом scope не должна
        # открывать агенту дорогу к новой личности.
        return self.store.one(
            "SELECT 1 FROM memory WHERE user_id = ? AND kind = ? AND status = 'active' LIMIT 1",
            (self.user_id, kind)) is not None

    def _insert(self, content, kind, vec, importance, scope,
                source_episode_id=None, supersedes=None,
                expires_at: str | None = None, origin: str = "user",
                status: str = "active", reason: str | None = None) -> str:
        mid = new_id()
        ts = now_iso()
        self.store.execute(
            """INSERT INTO memory
               (id, user_id, scope, kind, content, embedding, importance,
                confidence, created_at, last_seen_at, last_confirmed_at,
                valid_from, expires_at, status, supersedes,
                source_episode_id, content_hash, embedding_model, факт_ключ,
                origin, quarantine_reason)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (mid, self.user_id, scope, kind, content, pack(vec),
             max(0.0, min(1.0, importance)), config.ORIGIN_CONFIDENCE.get(origin, 1.0),
             ts, ts, ts, ts, expires_at, status,
             supersedes, source_episode_id, content_hash(content),
             embeddings.метка_модели(), classify.разобрать_факт(content)[0],
             origin, reason))
        return mid

    # -- проверка владельцем -------------------------------------------

    def quarantined(self) -> list[dict]:
        """Записи, которые агент хотел внести и которые ждут решения владельца."""
        return [dict(r) for r in self.store.query(
            """SELECT id, kind, content, origin, created_at, supersedes, quarantine_reason
               FROM memory WHERE user_id = ? AND status = 'quarantined'
               ORDER BY created_at""", (self.user_id,))]

    def approve(self, memory_id: str) -> bool:
        """Владелец принял запись: она становится действующей и, если нужно, заменяет прежнюю."""
        row = self.store.one(
            """SELECT supersedes FROM memory
               WHERE id = ? AND user_id = ? AND status = 'quarantined'""",
            (memory_id, self.user_id))
        if not row:
            return False
        ts = now_iso()
        ops = [("""UPDATE memory SET status = 'active', confidence = 1.0,
                   last_confirmed_at = ?, quarantine_reason = NULL WHERE id = ?""",
                (ts, memory_id))]
        if row["supersedes"]:
            ops.append(("""UPDATE memory SET status = 'superseded', superseded_by = ?, valid_to = ?
                           WHERE id = ? AND user_id = ? AND status = 'active'""",
                        (memory_id, ts, row["supersedes"], self.user_id)))
        self.store.atomic(ops)
        self._подписать(memory_id)       # принял владелец — значит запись его
        return True

    def reject(self, memory_id: str) -> bool:
        """Владелец отклонил запись. Текст остаётся в истории, в поиск она не попадает."""
        cur = self.store.execute(
            """UPDATE memory SET status = 'rejected'
               WHERE id = ? AND user_id = ? AND status = 'quarantined'""",
            (memory_id, self.user_id))
        return cur.rowcount > 0

    def restore(self, memory_id: str) -> bool:
        """Вернуть из архива запись, которую опровергли зря."""
        cur = self.store.execute(
            """UPDATE memory SET status = 'active', confidence = 0.5
               WHERE id = ? AND user_id = ? AND status = 'archived'""",
            (memory_id, self.user_id))
        return cur.rowcount > 0

    # -- смена модели эмбеддингов --------------------------------------

    def reindex(self, limit: int | None = None) -> dict:
        """Пересчитывает векторы записей, посчитанные другой моделью.

        После смены модели старые векторы несравнимы с новыми, и поиск по смыслу молча перестаёт
        их находить. Текст не меняется, история не трогается.
        """
        текущая = embeddings.метка_модели()
        sql = """SELECT id, content FROM memory
                 WHERE user_id = ? AND content IS NOT NULL
                   AND (embedding IS NULL OR embedding_model IS NULL OR embedding_model != ?)"""
        rows = self.store.query(sql, (self.user_id, текущая))
        всего = len(rows)
        if limit is not None:
            rows = rows[:limit]
        for r in rows:
            self.store.execute(
                "UPDATE memory SET embedding = ?, embedding_model = ? WHERE id = ?",
                (pack(embeddings.embed(r["content"])), текущая, r["id"]))
        return {"model": текущая, "reindexed": len(rows), "left": всего - len(rows)}

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
               session_id: str | None = None,
               as_of: str | datetime | None = None) -> list[Record]:
        """Поиск в одной области памяти. Подробности — в `_recall`.

        Запрос дополняется синонимами терминов (`add_alias`); каждая найденная запись получает
        пометки: подписана ли владельцем (для личности и предпочтений) и спорит ли с другой.
        """
        найдено = self._recall(self._расширить(query), scope, kind, limit, session_id, as_of)
        if as_of is None:
            self._учесть_поиск(not найдено)
        self._пометить(найдено)
        return найдено

    def recall_many(self, query: str, scopes: list[str], kind: str | None = None,
                    limit: int = 10, as_of: str | datetime | None = None) -> list[Record]:
        """Поиск сразу в нескольких областях — явный мост между ролями («работа» и «дом»).

        Без него области не смешиваются: каждая ищется отдельно, итог сводится по баллу,
        у каждой записи видна её область.
        """
        запрос = self._расширить(query)
        всё: list[Record] = []
        for s in list(dict.fromkeys(scopes))[:10]:
            всё += self._recall(запрос, s, kind, limit, None, as_of)
        всё.sort(key=lambda x: x.score, reverse=True)
        if as_of is None:
            self._учесть_поиск(not всё)
        self._пометить(всё[:limit])
        return всё[:limit]

    def _пометить(self, записи: list[Record]) -> None:
        if not записи:
            return
        строки = {r["id"]: r for r in self.store.query(
            f"""SELECT id, kind, content, owner_sig, факт_ключ, scope FROM memory
                WHERE id IN ({",".join("?" * len(записи))})""", tuple(з.id for з in записи))}
        спорные = {(r["scope"], r["факт_ключ"]) for r in self.store.query(
            """SELECT scope, факт_ключ FROM memory WHERE user_id = ? AND status = 'active'
               AND факт_ключ IS NOT NULL GROUP BY scope, факт_ключ HAVING COUNT(*) > 1""", (self.user_id,))}
        ключ = self._ключ_подписи() if any(integrity.protected(з.kind) for з in записи) else None
        for з in записи:
            r = строки.get(з.id)
            if r is None:
                continue
            з.scope = r["scope"]
            if ключ is not None and integrity.protected(з.kind) and з.status == "active":
                з.signed = integrity.valid(ключ, r)
            з.conflict = з.status == "active" and (r["scope"], r["факт_ключ"]) in спорные

    def _recall(self, query: str, scope: str = "global",
                kind: str | None = None, limit: int = 10,
                session_id: str | None = None,
                as_of: str | datetime | None = None) -> list[Record]:
        """Гибридный поиск: вектор + BM25 + точные идентификаторы, RRF.

        Итог: rrf × важность × уверенность × затухание × свежесть сессии.
        Затухание считается от last_confirmed_at — от момента, когда запись
        в последний раз подтверждалась верной, а не когда её извлекали.

        as_of — «что было верно на эту дату»: вместо действующих записей берутся те, что
        действовали в тот момент, включая заменённые позже. Дата без времени — конец дня по UTC.
        Записи на проверке, отклонённые, отозванные и архивные в такой поиск не входят.
        """
        момент = parse_as_of(as_of) if as_of is not None else None
        statuses = ("active", "superseded") if момент else ("active",)
        sql = f"""SELECT id, kind, content, embedding, importance, confidence,
                        last_confirmed_at, expires_at, session_id, origin, created_at,
                        status, valid_from, valid_to
                 FROM memory
                 WHERE user_id = ? AND scope = ? AND status IN ({",".join("?" * len(statuses))})"""
        params: list = [self.user_id, scope, *statuses]
        if kind:
            sql += " AND kind = ?"
            params.append(kind)

        raw = self.store.query(sql, tuple(params))
        if момент:
            # Сравнение по разобранному времени, а не по строкам: у строк ISO разная точность.
            raw = [r for r in raw
                   if parse_ts(r["valid_from"] or r["created_at"]) <= момент
                   and (r["valid_to"] is None or parse_ts(r["valid_to"]) > момент)]
        if not raw:
            return []
        статусы = {r["id"]: r["status"] for r in raw}

        rows = [{"id": r["id"], "kind": r["kind"], "content": r["content"],
                 "_vec": unpack(r["embedding"]), "importance": r["importance"],
                 "confidence": r["confidence"],
                 "last_confirmed_at": r["last_confirmed_at"],
                 "expires_at": r["expires_at"],
                 "session_id": r["session_id"], "origin": r["origin"],
                 "created_at": r["created_at"]} for r in raw]

        scores, rankings = retrieval.hybrid_rank(
            self.store, self.user_id, scope, query, rows, statuses=statuses)
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
                         strategies=found_by, expired=expired,
                         origin=r["origin"], created_at=r["created_at"],
                         status=статусы.get(rid, "active"))
            rec.score = (rrf * rec.importance * rec.confidence
                         * decay(rec.kind, confirmed) * boost
                         * (config.EXPIRED_PENALTY if expired else 1.0))
            out.append(rec)

        out.sort(key=lambda x: x.score, reverse=True)
        top = out[:limit]
        if момент:
            return top           # взгляд в прошлое не считается обращением к записи

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

    def refute(self, memory_id: str, drop: float = 0.3,
               floor: float = 0.0) -> bool:
        """Запись оказалась неверной: снизить уверенность.

        Свежесть НЕ обновляется. Если уверенность падает до нуля, запись уходит в архив, но
        остаётся в истории. floor — ниже этого не опускать: так MCP не может вывести из поиска
        защищённую запись. Несуществующая или уже недействующая запись — False, без молчаливого
        успеха.
        """
        drop = max(0.0, min(float(drop), 1.0))
        cur = self.store.execute(
            """UPDATE memory SET confidence = MAX(confidence - ?, ?),
               refuted_count = refuted_count + 1
               WHERE id = ? AND user_id = ? AND status = 'active'""",
            (drop, floor, memory_id, self.user_id))
        if cur.rowcount == 0:
            return False
        self.store.execute(
            """UPDATE memory SET status = 'archived'
               WHERE id = ? AND user_id = ? AND confidence <= 0.0""",
            (memory_id, self.user_id))
        return True

    # -- отзыв ----------------------------------------------------------

    def _связанные(self, memory_id: str) -> list:
        """Всё, что несёт то же содержание: цепочка версий в обе стороны и точные копии."""
        видел: dict = {}
        очередь = [memory_id]
        while очередь:
            текущая = очередь.pop()
            if текущая in видел:
                continue
            row = self.store.one(
                """SELECT id, content, content_hash, supersedes, superseded_by,
                          source_episode_id
                   FROM memory WHERE id = ? AND user_id = ?""",
                (текущая, self.user_id))
            if not row:
                continue
            видел[текущая] = row
            очередь += [х for х in (row["supersedes"], row["superseded_by"]) if х]
            очередь += [r["id"] for r in self.store.query(
                """SELECT id FROM memory WHERE user_id = ?
                   AND (supersedes = ? OR superseded_by = ?)""",
                (self.user_id, текущая, текущая))]
            if row["content_hash"]:
                очередь += [r["id"] for r in self.store.query(
                    "SELECT id FROM memory WHERE user_id = ? AND content_hash = ?",
                    (self.user_id, row["content_hash"]))]
        return list(видел.values())

    def revoke(self, memory_id: str, cascade: bool = True, with_derived: bool = False) -> bool:
        """Физическое затирание содержания. Хеш и якорь остаются.

        По умолчанию вместе с записью затираются её прежние и новые версии, точные копии и
        исходные эпизоды. Иначе «забытое» продолжало бы лежать открытым текстом в истории версий
        и в буфере, а структурный ключ хранил бы, о чём шла речь.

        with_derived — ещё и все выводы, сделанные из этой записи (связи derived_from), со всеми
        их версиями: иначе забытое восстанавливается из выводов.
        """
        записи = self._связанные(memory_id)
        if not cascade:
            записи = [з for з in записи if з["id"] == memory_id]
        if with_derived and записи:
            есть = {з["id"] for з in записи}
            for вывод in self.derived(memory_id):
                for з in self._связанные(вывод):
                    if з["id"] not in есть:
                        есть.add(з["id"])
                        записи.append(з)
        if not записи:
            return False
        ts = now_iso()
        ops: list[tuple[str, tuple]] = []
        for з in записи:
            # Подпись тоже затирается: по ней с ключом можно проверить догадку «текст был таким».
            ops.append(("""UPDATE memory SET status = 'revoked', content = NULL,
                           embedding = NULL, факт_ключ = NULL, owner_sig = NULL WHERE id = ?""", (з["id"],)))
            # Повторное «забудь» — обычное дело: цепочка могла быть затёрта раньше.
            # Затирается сам ключ, а не только ставится отметка: шифротекст этой
            # записи в Arweave без ключа — шум навсегда. Отметка времени уходит
            # в следующий корень L3 «квитанцией забвения» (anchor.py).
            ops.append(("""UPDATE anchor_key SET key_ref = 'destroyed', destroyed_at = ?
                           WHERE memory_id = ? AND destroyed_at IS NULL""", (ts, з["id"])))
            if з["source_episode_id"]:
                ops.append(("""UPDATE episode SET content = '', embedding = NULL, processed = 1
                               WHERE id = ? AND user_id = ?""",
                            (з["source_episode_id"], self.user_id)))
            if з["content"]:
                ops.append(("""UPDATE episode SET content = '', embedding = NULL, processed = 1
                               WHERE user_id = ? AND content = ?""",
                            (self.user_id, з["content"])))
        self.store.atomic(ops)
        self.store.purge()
        return True

    # -- история версий -------------------------------------------------

    VIEWS = {"active": ("active",), "review": ("quarantined",),
             "history": ("superseded", "archived", "rejected", "revoked")}

    def list_records(self, view: str = "active", text: str | None = None,
                     limit: int = 100, offset: int = 0, as_of: str | None = None) -> dict:
        """Записи для просмотра владельцем: действующие, на проверке или история, новые сверху.

        as_of — все записи, что действовали в тот момент, включая заменённые позже.
        """
        момент = parse_as_of(as_of) if as_of else None
        statuses = ("active", "superseded") if момент else self.VIEWS.get(view, self.VIEWS["active"])
        sql = (f"FROM memory WHERE user_id = ? AND status IN ({','.join('?' * len(statuses))})")
        params: list = [self.user_id, *statuses]
        if text:
            sql += " AND content LIKE ? ESCAPE '\\'"
            params.append("%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        поля = ("SELECT id, kind, scope, content, status, origin, confidence, importance, created_at, "
                "valid_from, valid_to, quarantine_reason, supersedes ")
        предел, сдвиг = max(1, min(int(limit), 500)), max(0, int(offset))
        if момент:
            rows = [r for r in self.store.query(поля + sql + " ORDER BY created_at DESC, rowid DESC", tuple(params))
                    if parse_ts(r["valid_from"] or r["created_at"]) <= момент
                    and (r["valid_to"] is None or parse_ts(r["valid_to"]) > момент)]
            return {"view": "as_of", "total": len(rows), "records": [dict(r) for r in rows[сдвиг:сдвиг + предел]]}
        всего = self.store.one("SELECT COUNT(*) " + sql, tuple(params))[0]
        rows = self.store.query(поля + sql + " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                                tuple(params) + (предел, сдвиг))
        return {"view": view, "total": всего, "records": [dict(r) for r in rows]}

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
               scope: str | None = None, limit: int | None = None,
               offset: int = 0, include_held: bool = True) -> dict:
        """Полная выгрузка памяти. Доступна всегда, без окна и без условий.

        Формат самодостаточен: по нему можно восстановить состояние в
        другой системе или просто прочитать глазами. limit и offset нужны тем,
        кому вся память разом не помещается в контекст; по умолчанию отдаётся всё.
        include_held=False убирает записи на проверке и отклонённые владельцем: так
        выгружает MCP, агенту читать то, что ждёт решения человека, незачем.
        """
        sql = "SELECT * FROM memory WHERE user_id = ?"
        params: list = [self.user_id]
        if scope:
            sql += " AND scope = ?"
            params.append(scope)
        if not include_superseded:
            sql += " AND status = 'active'"
        if not include_held:
            sql += " AND status NOT IN ('quarantined', 'rejected')"
        sql += " ORDER BY created_at"
        всего = self.store.one("SELECT COUNT(*) FROM (" + sql + ")", tuple(params))[0]
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params += [int(limit), int(offset)]

        records = []
        for r in self.store.query(sql, tuple(params)):
            d = dict(r)
            d.pop("embedding", None)          # бинарь в выгрузке бесполезен
            d.pop("owner_sig", None)          # подпись имеет смысл только с ключом этой машины
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

        # Связи «вывод из записи» — только между записями, вошедшими в выгрузку.
        ids = {r["id"] for r in records}
        links = [dict(r) for r in self.store.query(
            """SELECT l.src, l.dst, l.created_at FROM memory_link l JOIN memory m ON m.id = l.dst
               WHERE m.user_id = ? ORDER BY l.created_at""", (self.user_id,))
                 if r["src"] in ids and r["dst"] in ids]

        return {
            "format": "padam-export/1",
            "exported_at": now_iso(),
            "user_id": self.user_id,
            "counts": {"memory": len(records), "memory_total": всего,
                       "sessions": len(sessions), "nocturne_runs": len(runs), "links": len(links)},
            "memory": records,
            "sessions": sessions,
            "nocturne_runs": runs,
            "links": links,
        }

    def import_(self, payload: dict, overwrite: bool = False) -> int:
        """Загрузка выгрузки обратно. Возвращает число внесённых записей."""
        if payload.get("format") != "padam-export/1":
            raise ValueError("неизвестный формат выгрузки")
        added = 0
        for rec in payload.get("memory", []):
            # Импорт идёт теми же воротами, что и обычная запись: секреты вычищаются, размер ограничен.
            # Файл выгрузки мог быть изменён, а восстановленная запись потом попадает в контекст модели.
            ch = bytes.fromhex(rec["content_hash"]) if rec.get("content_hash") else None
            if rec.get("content") is not None:
                очищено = safety.clean(str(rec["content"]))[:config.MAX_CONTENT_CHARS]
                if очищено != rec["content"]:
                    rec = {**rec, "content": очищено}
                    ch = None  # текст изменился, прежний отпечаток к нему больше не относится
            exists = self.store.one("SELECT id, user_id FROM memory WHERE id = ?",
                                    (rec["id"],))
            if exists and not overwrite:
                continue
            # Чужую запись импорт не трогает даже при overwrite: id приходит из файла.
            if exists and exists["user_id"] != self.user_id:
                continue
            if exists:
                self.store.execute("DELETE FROM memory WHERE id = ?", (rec["id"],))
            vec = embeddings.embed(rec["content"]) if rec.get("content") else None
            self.store.execute(
                """INSERT INTO memory
                   (id, user_id, scope, kind, content, embedding, importance,
                    confidence, created_at, last_seen_at, last_confirmed_at,
                    expires_at, valid_from, valid_to, access_count,
                    refuted_count, status, supersedes, superseded_by,
                    source_episode_id, session_id, content_hash,
                    anchor_tx, anchor_slot, origin, quarantine_reason,
                    embedding_model, факт_ключ)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                 rec.get("anchor_tx"), rec.get("anchor_slot"),
                 rec.get("origin"), rec.get("quarantine_reason"),
                 embeddings.метка_модели() if vec is not None else None,
                 # Без ключа восстановленная запись не находилась бы как спорящая (см. `_по_ключу`).
                 classify.разобрать_факт(rec["content"])[0] if rec.get("content") else None))
            added += 1
        # Связи восстанавливаются только между записями этого человека (проверяет _связать).
        for link in payload.get("links") or []:
            if isinstance(link, dict) and isinstance(link.get("src"), str) and isinstance(link.get("dst"), str):
                if self.store.one("SELECT 1 FROM memory WHERE id = ? AND user_id = ?", (link["dst"], self.user_id)):
                    self._связать([link["src"]], link["dst"])
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
        ожидает = scalar(
            "SELECT COUNT(*) FROM episode WHERE user_id=? AND processed=0",
            (self.user_id,))

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
            "quarantined": scalar(
                "SELECT COUNT(*) FROM memory WHERE user_id=? AND status='quarantined'",
                (self.user_id,)),
            "episodes_pending": ожидает,
            "consolidation_due": ожидает >= config.CONSOLIDATION_DUE,
            "stale_vectors": scalar(
                """SELECT COUNT(*) FROM memory WHERE user_id=? AND content IS NOT NULL
                   AND (embedding IS NULL OR embedding_model IS NULL OR embedding_model != ?)""",
                (self.user_id, embeddings.метка_модели())),
            "by_kind": by_kind,
            "self": self.self_report(),
        }
