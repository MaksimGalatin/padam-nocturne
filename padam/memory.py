"""Ядро PADAM: запись, поиск, отзыв, история версий."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

import numpy as np

from . import classify, config, embeddings, guard, integrity, retrieval, roles, safety
from .store import Store, new_id, now_iso, pack, parse_ts, unpack
from .i18n import t

_CHANGE_LISTENERS: list = []


def register_change_listener(fn) -> None:
    """Регистрирует обработчик изменений записей памяти (для живых SSE-уведомлений)."""
    if fn not in _CHANGE_LISTENERS:
        _CHANGE_LISTENERS.append(fn)


def _notify_change(event: dict) -> None:
    for fn in list(_CHANGE_LISTENERS):
        try:
            fn(event)
        except Exception:
            pass


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
    agent_id: str | None = None      # Б11: идентификатор агента, создавшего запись
    visibility: str = "private"      # В1: private | team_read | team_write
    workspace_id: str | None = None  # В1: идентификатор команды

    def explain(self) -> str:
        d = decay(self.kind, self.last_confirmed_at)
        found_by = "+".join(self.strategies) if self.strategies else "—"
        stale = "  ИСТЁК СРОК" if self.expired else ""
        return (f"rrf={self.similarity:.3f} × imp={self.importance:.2f} "
                f"× conf={self.confidence:.2f} × decay={d:.2f} "
                f"= {self.score:.4f}   [{found_by}]{stale}")


LINK_RELATIONS = ("derived", "cause", "correction", "contradiction")
_LINK_ALIASES = {
    "derived": "derived",
    "derived_from": "derived",
    "источник": "derived",
    "source": "derived",
    "cause": "cause",
    "причина": "cause",
    "correction": "correction",
    "исправление": "correction",
    "refinement": "correction",
    "contradiction": "contradiction",
    "противоречие": "contradiction",
}


def normalize_link_relation(relation: str | None) -> str:
    """Нормализует тип ребра графа (источник/причина/исправление/противоречие)."""
    key = (relation or "derived").strip().lower()
    norm = _LINK_ALIASES.get(key)
    if norm is None:
        raise ValueError(f"unknown link relation {relation!r}; expected one of {LINK_RELATIONS}")
    return norm


def _norm_valid_ts(value: str | datetime | None) -> str | None:
    """Нормализует границу окна действия (valid_from / valid_to) в ISO UTC."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    текст = str(value).strip()
    if not текст:
        return None
    if len(текст) == 10:
        return datetime.fromisoformat(текст).replace(tzinfo=timezone.utc).isoformat()
    if текст.endswith(("Z", "z")):
        текст = текст[:-1] + "+00:00"
    dt = datetime.fromisoformat(текст)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


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
            scope: str = "global", priority: float = 1.0,
            actor: roles.ActorContext | None = None) -> str | None:
        """Эпизод в журнал L1. Мусор в журнал не идёт (сито кратковременного внимания, L0):

        строка без единой буквы и цифры (пустая, одни знаки) не пишется — возвращается None;
        точный повтор предыдущего эпизода той же роли за последние 60 секунд не дублируется —
        возвращается id уже записанного. Всё остальное пишется как есть.
        """
        if actor is not None and actor.role == "auditor":
            self._log_audit("log", None, actor=actor.role, agent_id=actor.subject,
                            scope=scope, outcome="denied", detail="auditor read-only")
            raise PermissionError(t("роль auditor не может записывать эпизоды", "auditor role is read-only"))
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
                 derived_from: list[str] | None = None,
                 agent_id: str | None = None,
                 valid_from: str | datetime | None = None,
                 valid_to: str | datetime | None = None,
                 links: list | None = None,
                 visibility: str | None = None,
                 workspace_id: str | None = None,
                 actor: roles.ActorContext | None = None) -> tuple[str, str]:
        """Возвращает (исход, id записи).

        Исходы: created | duplicate | merged | superseded | coexists | quarantined

        origin — откуда запись (config.ORIGINS). guarded=True ставит вызывающий, которому нельзя
        верить на слово, прежде всего MCP: агент мог прочитать команду на чужой странице, а его
        пометку о происхождении проверить нечем. Тогда похожее на команду и замена защищённой
        записи не применяются, а ждут решения владельца (`padam review`).

        derived_from — id записей, из которых сделан этот вывод. По этим связям забвение
        источника доходит и до выводов (`forget --with-derived`).
        valid_from / valid_to — окно действия факта; links — явные рёбра графа
        (source, relation) или dict {id/source/target, relation, direction}.
        """
        vf_str = _norm_valid_ts(valid_from)
        vt_str = _norm_valid_ts(valid_to)
        if vf_str and vt_str and parse_ts(vt_str) <= parse_ts(vf_str):
            raise ValueError("valid_to must be after valid_from")
        norm_agent = (str(agent_id).strip()[:64] if agent_id else None) or None
        try:
            vis = roles.check_write(actor, kind, visibility)
        except PermissionError as exc:
            self._log_audit("write", None, actor=actor.role if actor else (origin or "user"),
                            agent_id=actor.subject if actor else norm_agent, scope=scope, kind=kind,
                            outcome="denied", detail=str(exc))
            raise
        ws_id = workspace_id
        if actor is not None and not actor.is_owner:
            # Роль и субъект берутся исключительно из проверенного токена, а не из X-Agent-ID.
            ws_id = actor.workspace_id
            norm_agent = actor.subject
            guarded = True
            if origin == "user":
                origin = "agent"
        elif vis in roles.TEAM_VISIBILITIES and not ws_id:
            wss = self.list_workspaces()
            if len(wss) == 1:
                ws_id = wss[0]["id"]
            else:
                raise ValueError(t("укажите workspace_id для командной записи",
                                   "workspace_id is required for team records"))
        try:
            with safety.одна_запись():          # виды текста строятся один раз на запись и не переживают её
                исход, mid = self._remember(
                    content, kind, importance, scope, source_episode_id, origin, guarded,
                    norm_agent, vf_str, vt_str, vis, ws_id, actor)
        except PermissionError as exc:
            self._log_audit("write", None, actor=actor.role if actor else (origin or "user"),
                            agent_id=norm_agent, scope=scope, kind=kind,
                            outcome="denied", detail=str(exc))
            raise
        # При повторе mid — это уже существующая запись, возможно владельца. Связать её «выводом» из
        # чужой записи значило бы дать агенту способ стереть её каскадом при забвении источника.
        if derived_from and исход != "duplicate":
            self._связать(derived_from, mid, relation="derived", actor=actor)
        if links and исход != "duplicate":
            for item in list(links)[:20]:
                if isinstance(item, dict):
                    other = str(item.get("id") or item.get("source") or item.get("target") or "").strip()
                    rel = normalize_link_relation(item.get("relation") or item.get("type"))
                    direction = str(item.get("direction") or ("out" if item.get("target") else "in")).lower()
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    other, rel = str(item[0]).strip(), normalize_link_relation(item[1])
                    direction = str(item[2]).lower() if len(item) >= 3 else "in"
                else:
                    continue
                if not other or other == mid:
                    continue
                if direction == "out":
                    self._связать_пару(mid, other, relation=rel, actor=actor)
                else:
                    self._связать([other], mid, relation=rel, actor=actor)
        if исход in ("created", "merged", "superseded", "coexists") and not (guarded and not config.MCP_TRUST_WRITES):
            self._подписать(mid)
        audit_actor = actor.role if actor is not None else (origin or "user")
        self._log_audit("write", mid, actor=audit_actor, agent_id=norm_agent,
                        scope=scope, kind=kind, outcome=исход)
        return исход, mid

    def _remember(self, content: str, kind: str | None, importance: float, scope: str,
                  source_episode_id: str | None, origin: str, guarded: bool,
                  agent_id: str | None = None,
                  valid_from: str | None = None,
                  valid_to: str | None = None,
                  visibility: str = "private",
                  workspace_id: str | None = None,
                  actor: roles.ActorContext | None = None) -> tuple[str, str]:
        # Команда проверяется и по исходному тексту: маскирование секретов закрывает длинные случайные строки,
        # а base64 с командой внутри выглядит именно так — после маски раскодировать было бы нечего (аудит 09.11.2026).
        исходный = content
        content = safety.clean(content)
        if origin not in config.ORIGINS:
            origin = "agent" if guarded else "user"
        guarded = guarded and not config.MCP_TRUST_WRITES
        kind = kind or classify.infer_kind(content)
        if kind not in config.KINDS:
            kind = "fact"
        вид_по_тексту = classify.infer_kind_rules(content)
        if visibility in roles.TEAM_VISIBILITIES and (
            kind in config.PROTECTED_KINDS
            or вид_по_тексту in config.PROTECTED_KINDS
            or (origin != "user" and (safety.changes_owner_or_rules(content) or safety.changes_owner_or_rules(исходный)))
        ):
            raise PermissionError(t(
                "записи identity, preference и правила владельца нельзя помещать в командную память",
                "identity, preference and owner-rule records cannot be placed in team memory",
            ))
        vec = embeddings.embed(content)

        if guarded and (safety.looks_like_instruction(content) or safety.looks_like_instruction(исходный)):
            return "quarantined", self._insert(
                content, kind, vec, importance, scope, source_episode_id,
                origin=origin, status="quarantined", reason="looks like an instruction",
                agent_id=agent_id, valid_from=valid_from, valid_to=valid_to,
                visibility=visibility, workspace_id=workspace_id)
        # 0.4.13: необязательный второй слой — локальная модель-детектор (padam/guard.py), только для текста, где упомянут ИИ.
        # Выключен, пока не задан PADAM_GUARD_MODEL и не стоят пакеты [guard].
        if guarded and guard.flags(исходный):
            return "quarantined", self._insert(
                content, kind, vec, importance, scope, source_episode_id,
                origin=origin, status="quarantined", reason="looks like an instruction (classifier)",
                agent_id=agent_id, valid_from=valid_from, valid_to=valid_to,
                visibility=visibility, workspace_id=workspace_id)
        if guarded and origin == "external" and config.HOLD_EXTERNAL:
            return "quarantined", self._insert(
                content, kind, vec, importance, scope, source_episode_id,
                origin=origin, status="quarantined", reason="external source held for the owner (PADAM_HOLD_EXTERNAL, on by default)",
                agent_id=agent_id, valid_from=valid_from, valid_to=valid_to,
                visibility=visibility, workspace_id=workspace_id)
        # 0.4.1: граница, которая не зависит от пометки источника вовсе. Пометку ставит агент, а MCP не даёт серверу
        # способа проверить, откуда агент взял текст; с PADAM_MCP_REVIEW_ALL=1 ждёт владельца каждая запись агента.
        if guarded and config.MCP_REVIEW_ALL:
            return "quarantined", self._insert(
                content, kind, vec, importance, scope, source_episode_id,
                origin=origin, status="quarantined", reason="every agent write waits for the owner (PADAM_MCP_REVIEW_ALL)",
                agent_id=agent_id, valid_from=valid_from, valid_to=valid_to,
                visibility=visibility, workspace_id=workspace_id)

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
            # 0.4.13: запись, которая меняет, кто владелец, или правила работы агента, — что бы ни было в её виде.
            # Круг 3 Red Team, 11.11.2026: 37 из 45 таких записей от агента становились действующими, потому что
            # вид «личность/предпочтение» узнавали по нескольким фразам. Запись самого человека не задерживается.
            # Как и команда, проверяется и исходный текст: base64 с «owner=…» маска закрывает целиком (круг 3, claude i-13).
            elif origin != "user" and (safety.changes_owner_or_rules(content) or safety.changes_owner_or_rules(исходный)):
                причина_защиты = "would change who the owner is or how the agent works"

        # СНАЧАЛА точный поиск по структурному ключу, и только потом — по
        # близости векторов. Порядок важен: ключ находит спорящую запись
        # наверняка, а вектор — как повезёт. Подробности в `_по_ключу`.
        по_ключу = self._по_ключу(content, scope, actor=actor)
        if по_ключу is not None:
            old_id, old_content = по_ключу
        else:
            near = self._nearest_active(vec, kind, scope, actor=actor)
            threshold = config.similarity_threshold(embeddings.backend())

            if near is None or near[2] < threshold:
                if причина_защиты:
                    return "quarantined", self._insert(
                        content, kind, vec, importance, scope, source_episode_id,
                        origin=origin, status="quarantined", reason=причина_защиты,
                        agent_id=agent_id, valid_from=valid_from, valid_to=valid_to,
                        visibility=visibility, workspace_id=workspace_id)
                return "created", self._insert(content, kind, vec, importance,
                                               scope, source_episode_id, origin=origin, agent_id=agent_id,
                                               valid_from=valid_from, valid_to=valid_to,
                                               visibility=visibility, workspace_id=workspace_id)

            old_id, old_content, _ = near
        verdict = classify.resolve(content, old_content)

        if verdict == "duplicate":
            # Через MCP подтверждением не считается и пометка user: её ставит сам агент.
            отметка_до = self.store.stamp()
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
            self._векторы_после(отметка_до)          # 0.4.11: векторы и статус не менялись
            return "duplicate", old_id

        if verdict == "coexist":
            if причина_защиты:
                return "quarantined", self._insert(
                    content, kind, vec, importance, scope, source_episode_id,
                    origin=origin, status="quarantined", reason=причина_защиты, agent_id=agent_id,
                    valid_from=valid_from, valid_to=valid_to,
                    visibility=visibility, workspace_id=workspace_id)
            return "coexists", self._insert(content, kind, vec, importance,
                                            scope, source_episode_id, origin=origin, agent_id=agent_id,
                                            valid_from=valid_from, valid_to=valid_to,
                                            visibility=visibility, workspace_id=workspace_id)

        old_vis_row = self.store.one("SELECT visibility FROM memory WHERE id = ?", (old_id,))
        if actor is not None and not actor.is_owner and actor.role == "contributor":
            if old_vis_row and old_vis_row["visibility"] != "team_write":
                raise PermissionError(t(
                    "роль contributor не может перезаписывать запись с видимостью team_read/private",
                    "contributor cannot supersede team_read or private records",
                ))

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
                    supersedes=old_id, origin=origin, status="quarantined", reason=причина,
                    agent_id=agent_id, valid_from=valid_from, valid_to=valid_to,
                    visibility=visibility, workspace_id=workspace_id)

        # refinement и contradiction создают новую версию, закрывая окно старой и оставляя ребро графа
        new_mid = self._insert(content, kind, vec, importance, scope,
                               source_episode_id, supersedes=old_id, origin=origin,
                               agent_id=agent_id, valid_from=valid_from, valid_to=valid_to,
                               visibility=visibility, workspace_id=workspace_id)
        close_at = valid_from or now_iso()
        rel_type = "correction" if verdict == "refinement" else "contradiction"
        отметка_до = self.store.stamp()
        self.store.atomic([
            ("""UPDATE memory SET status = 'superseded', superseded_by = ?,
                valid_to = ? WHERE id = ?""", (new_mid, close_at, old_id)),
            ("""INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at)
                VALUES (?,?,?,?)""", (old_id, new_mid, rel_type, now_iso())),
        ])
        self._векторы_после(отметка_до, убрать=old_id, scope=scope, kind=kind)   # 0.4.11
        return ("merged" if verdict == "refinement" else "superseded"), new_mid

    # -- связи выводов и подпись владельца ------------------------------

    def _связать_пару(self, src: str, dst: str, relation: str = "derived",
                      actor: roles.ActorContext | None = None) -> bool:
        """Создаёт одно направленное ребро графа между записями этого же пользователя."""
        rel = normalize_link_relation(relation)
        if not src or not dst or src == dst:
            return False
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        s_row = self.store.one(
            f"SELECT 1 FROM memory WHERE id = ? AND user_id = ? AND status != 'revoked'{vis_sql}",
            (src, self.user_id, *vis_params))
        d_row = self.store.one(
            f"SELECT 1 FROM memory WHERE id = ? AND user_id = ? AND status != 'revoked'{vis_sql}",
            (dst, self.user_id, *vis_params))
        if not s_row or not d_row:
            return False
        self.store.counters([
            ("INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at) VALUES (?,?,?,?)",
             (src, dst, rel, now_iso()))
        ])
        return True

    def _связать(self, источники: list[str], вывод: str, relation: str = "derived",
                 actor: roles.ActorContext | None = None) -> int:
        """Связи графа («вывод сделан из записи» и другие типы рёбер). Не больше 20 за раз."""
        rel = normalize_link_relation(relation)
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        ops = []
        ts = now_iso()
        for src in list(dict.fromkeys(источники))[:20]:
            if src == вывод or not self.store.one(
                    f"SELECT 1 FROM memory WHERE id = ? AND user_id = ?{vis_sql}",
                    (src, self.user_id, *vis_params)):
                continue
            ops.append(("INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at) VALUES (?,?,?,?)",
                        (src, вывод, rel, ts)))
        if ops:
            # Связи не влияют на векторы и ранжирование, поэтому пишем через counters без сброса кэша.
            self.store.counters(ops)
        return len(ops)

    def link(self, src_id: str, dst_id: str, relation: str = "derived",
             actor: roles.ActorContext | None = None) -> dict:
        """Явно связывает две записи памяти ребром типа derived | cause | correction | contradiction."""
        if actor is not None and actor.role in ("auditor", "guest"):
            self._log_audit("link", dst_id, actor=actor.role, agent_id=actor.subject, outcome="denied")
            raise PermissionError(t("эта роль не может создавать связи", "this role cannot create links"))
        rel = normalize_link_relation(relation)
        if not src_id or not dst_id or src_id == dst_id:
            raise ValueError("source and target must be different non-empty record ids")
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        s_row = self.store.one(
            f"SELECT 1 FROM memory WHERE id = ? AND user_id = ? AND status != 'revoked'{vis_sql}",
            (src_id, self.user_id, *vis_params))
        d_row = self.store.one(
            f"SELECT 1 FROM memory WHERE id = ? AND user_id = ? AND status != 'revoked'{vis_sql}",
            (dst_id, self.user_id, *vis_params))
        if not s_row or not d_row:
            raise ValueError("source or target record not found")
        ts = now_iso()
        self.store.counters([
            ("INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at) VALUES (?,?,?,?)",
             (src_id, dst_id, rel, ts))
        ])
        self._log_audit("link", dst_id, actor=actor.role if actor else "owner",
                        agent_id=actor.subject if actor else None, outcome=rel, detail=f"{src_id}->{dst_id}")
        return {"ok": True, "source": src_id, "target": dst_id, "relation": rel, "created_at": ts}

    def links_of(self, memory_id: str) -> dict:
        """Все входящие и исходящие смысловые связи записи с текстами соседей."""
        incoming = [dict(r) for r in self.store.query(
            """SELECT l.src AS id, COALESCE(l.relation, 'derived') AS relation, l.created_at,
                      m.kind, m.content, m.status, m.valid_from, m.valid_to
               FROM memory_link l JOIN memory m ON m.id = l.src
               WHERE l.dst = ? AND m.user_id = ? AND m.status != 'revoked'
               ORDER BY l.created_at DESC""", (memory_id, self.user_id))]
        outgoing = [dict(r) for r in self.store.query(
            """SELECT l.dst AS id, COALESCE(l.relation, 'derived') AS relation, l.created_at,
                      m.kind, m.content, m.status, m.valid_from, m.valid_to
               FROM memory_link l JOIN memory m ON m.id = l.dst
               WHERE l.src = ? AND m.user_id = ? AND m.status != 'revoked'
               ORDER BY l.created_at DESC""", (memory_id, self.user_id))]
        return {"incoming": incoming, "outgoing": outgoing}

    def derived(self, memory_id: str) -> list[str]:
        """Все выводы из записи (strictly relation='derived'), по цепочке: вывод из вывода тоже считается."""
        найдено, очередь = [], [memory_id]
        while очередь:
            src = очередь.pop()
            for r in self.store.query(
                    """SELECT l.dst FROM memory_link l JOIN memory m ON m.id = l.dst
                       WHERE l.src = ? AND m.user_id = ? AND COALESCE(l.relation, 'derived') = 'derived'""",
                    (src, self.user_id)):
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
        if rows:
            # Подпись owner_sig не меняет ни векторы, ни статус записи; counters не сбивает кэш поиска.
            self.store.counters([
                ("UPDATE memory SET owner_sig = ? WHERE id = ?",
                 (integrity.sign(ключ, r["id"], r["kind"], r["content"]), r["id"]))
                for r in rows
            ])
        return len(rows)

    def _подписать(self, memory_id: str) -> None:
        row = self.store.one("SELECT id, kind, content FROM memory WHERE id = ?", (memory_id,))
        if row and integrity.protected(row["kind"]):
            ключ = self._ключ_подписи()
            self.store.counters([("UPDATE memory SET owner_sig = ? WHERE id = ?",
                                  (integrity.sign(ключ, row["id"], row["kind"], row["content"]), memory_id))])

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

    def conflicts(self, actor: roles.ActorContext | None = None) -> list[dict]:
        """Действующие записи, которые спорят: тот же объект и свойство, разные значения.

        В норме такая пара не возникает (новая версия заменяет старую), но её приносят импорт,
        принятие записи с проверки и ручные правки базы. Сон их находит и называет; какая верна,
        решает человек или следующее подтверждение.
        """
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        группы = self.store.query(
            f"""SELECT scope, факт_ключ, COUNT(*) AS n FROM memory
               WHERE user_id = ? AND status = 'active' AND факт_ключ IS NOT NULL{vis_sql}
               GROUP BY scope, факт_ключ HAVING n > 1""", (self.user_id, *vis_params))
        итог = []
        for г in группы:
            записи = self.store.query(
                f"""SELECT id, content, origin, confidence, created_at FROM memory
                   WHERE user_id = ? AND status = 'active' AND scope = ? AND факт_ключ = ?{vis_sql}
                   ORDER BY created_at""", (self.user_id, г["scope"], г["факт_ключ"], *vis_params))
            итог.append({"scope": г["scope"], "key": г["факт_ключ"], "records": [dict(r) for r in записи]})
        return итог

    # -- учёт поиска (память о самой памяти) ---------------------------

    def _учесть_поиск(self, пусто: bool | None) -> None:
        """Счётчики одного поиска — показы найденных записей и (кроме поиска «на дату») статистика дня —
        одной транзакцией. 0.4.12: замер 11.11.2026 на 10 000 записях — два commit с fsync на поиск
        (0,35 из 2,84 с на 30 поисков), в recall_many по десяти областям — одиннадцать. Пишется то же."""
        ops = self.__dict__.pop("_показы", [])
        if пусто is not None:
            день = datetime.now(timezone.utc).date().isoformat()
            ops.append((
                """INSERT INTO search_stats (user_id, day, searches, empty) VALUES (?, ?, 1, ?)
                   ON CONFLICT(user_id, day) DO UPDATE SET searches = searches + 1, empty = empty + excluded.empty""",
                (self.user_id, день, 1 if пусто else 0)))
        if ops:
            self.store.counters(ops)

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
                    ("DELETE FROM term_alias WHERE user_id = ?", (self.user_id,)),
                    ("DELETE FROM forget_receipt WHERE user_id = ?", (self.user_id,))]
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
                status: str = "active", reason: str | None = None,
                agent_id: str | None = None,
                valid_from: str | None = None,
                valid_to: str | None = None,
                visibility: str = "private",
                workspace_id: str | None = None) -> str:
        mid = new_id()
        ts = now_iso()
        vf = valid_from or ts
        отметка_до = self.store.stamp()
        self.store.execute(
            """INSERT INTO memory
               (id, user_id, scope, kind, content, embedding, importance,
                confidence, created_at, last_seen_at, last_confirmed_at,
                valid_from, valid_to, expires_at, status, supersedes,
                source_episode_id, content_hash, embedding_model, факт_ключ,
                origin, quarantine_reason, agent_id, visibility, workspace_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (mid, self.user_id, scope, kind, content, pack(vec),
             max(0.0, min(1.0, importance)), config.ORIGIN_CONFIDENCE.get(origin, 1.0),
             ts, ts, ts, vf, valid_to, expires_at, status,
             supersedes, source_episode_id, content_hash(content),
             embeddings.метка_модели(), classify.разобрать_факт(content)[0],
             origin, reason, agent_id, visibility, workspace_id))
        self._дописать_в_кэш(отметка_до, mid, scope, kind, vec, status, visibility=visibility, workspace_id=workspace_id)
        _notify_change({
            "action": "quarantined" if status == "quarantined" else "write",
            "id": mid,
            "scope": scope,
            "kind": kind,
            "status": status,
            "visibility": visibility or "private",
            "workspace_id": workspace_id,
        })
        return mid

    # -- проверка владельцем -------------------------------------------

    def quarantined(self, actor: roles.ActorContext | None = None) -> list[dict]:
        """Записи, которые агент хотел внести и которые ждут решения владельца."""
        roles.require_moderate(actor)
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        return [dict(r) for r in self.store.query(
            f"""SELECT id, kind, content, origin, created_at, supersedes, quarantine_reason, visibility, workspace_id
               FROM memory WHERE user_id = ? AND status = 'quarantined'{vis_sql}
               ORDER BY created_at""", (self.user_id, *vis_params))]

    def approve(self, memory_id: str, actor: roles.ActorContext | None = None) -> bool:
        """Владелец или maintainer команды принял запись: она становится действующей."""
        try:
            roles.require_moderate(actor)
        except PermissionError as exc:
            self._log_audit("approve", memory_id, actor=actor.role if actor else "user",
                            agent_id=actor.subject if actor else None, outcome="denied", detail=str(exc))
            raise
        row = self.store.one(
            """SELECT supersedes, valid_from, content, kind, scope, visibility, workspace_id FROM memory
               WHERE id = ? AND user_id = ? AND status = 'quarantined'""",
            (memory_id, self.user_id))
        if not row:
            return False
        if actor is not None and not actor.is_owner:
            if (row["visibility"] == "private" or row["workspace_id"] != actor.workspace_id
                    or row["kind"] in config.PROTECTED_KINDS):
                self._log_audit("approve", memory_id, actor=actor.role, agent_id=actor.subject, outcome="denied")
                raise PermissionError(t("нельзя утверждать чужую, private или защищённую запись",
                                        "cannot approve private, protected or cross-workspace record"))
        ts = now_iso()
        ops = [("""UPDATE memory SET status = 'active', confidence = 1.0,
                   last_confirmed_at = ?, quarantine_reason = NULL WHERE id = ?""",
                (ts, memory_id))]
        if row["supersedes"]:
            old_row = self.store.one(
                "SELECT content FROM memory WHERE id = ? AND user_id = ?",
                (row["supersedes"], self.user_id))
            close_at = row["valid_from"] or ts
            rel_type = "correction"
            if old_row and row["content"] and old_row["content"]:
                v = classify.resolve(row["content"], old_row["content"])
                if v == "contradiction":
                    rel_type = "contradiction"
            ops.append(("""UPDATE memory SET status = 'superseded', superseded_by = ?, valid_to = ?
                           WHERE id = ? AND user_id = ? AND status = 'active'""",
                        (memory_id, close_at, row["supersedes"], self.user_id)))
            ops.append(("""INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at)
                           VALUES (?,?,?,?)""",
                        (row["supersedes"], memory_id, rel_type, ts)))
        self.store.atomic(ops)
        if roles.is_owner(actor):
            self._подписать(memory_id)       # подписывает только владелец
        self._log_audit("approve", memory_id, actor=actor.role if actor else "owner",
                        agent_id=actor.subject if actor else None, outcome="active")
        _notify_change({
            "action": "approve",
            "id": memory_id,
            "scope": row["scope"] or "global",
            "kind": row["kind"],
            "status": "active",
            "visibility": row["visibility"] or "private",
            "workspace_id": row["workspace_id"],
        })
        return True

    def reject(self, memory_id: str, actor: roles.ActorContext | None = None) -> bool:
        """Владелец или maintainer команды отклонил запись."""
        try:
            roles.require_moderate(actor)
        except PermissionError as exc:
            self._log_audit("reject", memory_id, actor=actor.role if actor else "user",
                            agent_id=actor.subject if actor else None, outcome="denied", detail=str(exc))
            raise
        if actor is not None and not actor.is_owner:
            row = self.store.one(
                "SELECT kind, visibility, workspace_id FROM memory WHERE id = ? AND user_id = ? AND status = 'quarantined'",
                (memory_id, self.user_id))
            if not row:
                return False
            if row["visibility"] == "private" or row["workspace_id"] != actor.workspace_id or row["kind"] in config.PROTECTED_KINDS:
                self._log_audit("reject", memory_id, actor=actor.role, agent_id=actor.subject, outcome="denied")
                raise PermissionError(t("нельзя отклонять чужую или private запись",
                                        "cannot reject private or cross-workspace record"))
        cur = self.store.execute(
            """UPDATE memory SET status = 'rejected'
               WHERE id = ? AND user_id = ? AND status = 'quarantined'""",
            (memory_id, self.user_id))
        ok = cur.rowcount > 0
        if ok:
            self._log_audit("reject", memory_id, actor=actor.role if actor else "owner",
                            agent_id=actor.subject if actor else None, outcome="rejected")
        return ok

    def restore(self, memory_id: str, actor: roles.ActorContext | None = None) -> bool:
        """Вернуть из архива запись, которую опровергли зря (только владелец)."""
        try:
            roles.require_owner(actor, "restore")
        except PermissionError as exc:
            self._log_audit("restore", memory_id, actor=actor.role if actor else "user",
                            agent_id=actor.subject if actor else None, outcome="denied", detail=str(exc))
            raise
        cur = self.store.execute(
            """UPDATE memory SET status = 'active', confidence = 0.5
               WHERE id = ? AND user_id = ? AND status = 'archived'""",
            (memory_id, self.user_id))
        ok = cur.rowcount > 0
        if ok:
            self._log_audit("restore", memory_id, actor="owner", outcome="active")
        return ok

    # -- смена модели эмбеддингов --------------------------------------

    def reindex(self, limit: int | None = None, *, cancel_event=None, progress_cb=None) -> dict:
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
        total_work = len(rows)
        if progress_cb is not None:
            progress_cb(0, max(1, total_work), "reindex started")
        step = max(1, total_work // 10) if total_work else 1
        done = 0
        for idx, r in enumerate(rows, 1):
            if cancel_event is not None and cancel_event.is_set():
                return {"model": текущая, "reindexed": done, "left": всего - done, "cancelled": True}
            self.store.execute(
                "UPDATE memory SET embedding = ?, embedding_model = ? WHERE id = ?",
                (pack(embeddings.embed(r["content"])), текущая, r["id"]))
            done = idx
            if progress_cb is not None and (idx % step == 0 or idx == total_work):
                progress_cb(idx, max(1, total_work), f"reindexed {idx}/{total_work}")
        if progress_cb is not None and total_work == 0:
            progress_cb(1, 1, "reindex completed")
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

    def _по_ключу(self, content, scope, actor: roles.ActorContext | None = None):
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
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        rows = self.store.query(
            f"""SELECT id, content FROM memory
               WHERE user_id = ? AND scope = ? AND факт_ключ = ?
                 AND status = 'active'{vis_sql}
               ORDER BY created_at DESC, rowid DESC LIMIT 1""",
            (self.user_id, scope, ключ, *vis_params))
        return (rows[0]["id"], rows[0]["content"]) if rows else None

    def _nearest_active(self, vec, kind, scope, actor: roles.ActorContext | None = None):
        # 0.4.4: одно матричное умножение вместо цикла Python по каждой записи, без текста всех записей, и
        # векторы держатся в памяти процесса. Замер 09.11.2026 (benchmarks/scale): каждая запись сравнивалась со
        # всеми сохранёнными по одной — 117,5 мс на запись при 6 000 записях, запись 10 000 реплик шла дольше
        # 25 минут. Итог тот же: близость = clip(a·b, -1, 1), 0 при другой размерности (векторы другой модели),
        # из равных — первая. Кэш сверяется с отметкой базы (свои коммиты + data_version) и не расходится с ней.
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        if vec is None or not vec.size:
            rows = self.store.query(f"""SELECT id FROM memory WHERE user_id = ? AND scope = ? AND kind = ?
                                       AND status = 'active' AND embedding IS NOT NULL{vis_sql}""",
                                    (self.user_id, scope, kind, *vis_params))
            if not rows:
                return None
            r = self.store.one("SELECT content FROM memory WHERE id = ?", (rows[0]["id"],))
            return (rows[0]["id"], r["content"], 0.0)
        v = np.asarray(vec, dtype=np.float32)
        try:
            ids, M = self._векторы(scope, kind, v.size, actor=actor)
        except MemoryError:
            # 0.4.8: кэш — только ускорение. Не хватило памяти — сбросить его и считать частями из базы, а не ронять
            # запись (замер 10.11.2026: ArrayMemoryError на ~50 000 записях при удвоении буфера).
            self.__dict__.pop("_вкэш", None)
            return self._nearest_частями(v, kind, scope, actor=actor)
        if not ids:
            return None
        sims = np.zeros(len(ids), dtype=np.float64)
        буфер, n, годные = M
        if n:
            sims[годные[:n]] = np.clip(буфер[:n] @ v, -1.0, 1.0)
        i = int(np.argmax(sims))
        content = self.store.one("SELECT content FROM memory WHERE id = ?", (ids[i],))["content"]
        return (ids[i], content, float(sims[i]))

    def _nearest_частями(self, v, kind, scope, часть=5000, actor: roles.ActorContext | None = None):
        """Тот же итог, что у _nearest_active, без матрицы в памяти: векторы читаются из базы частями по 5 000."""
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        лучший, лучшая_близость, первый = None, -2.0, None
        последний = 0
        while True:
            rows = self.store.query(
                f"""SELECT rowid, id, embedding FROM memory
                   WHERE user_id = ? AND scope = ? AND kind = ? AND status = 'active' AND embedding IS NOT NULL
                     AND rowid > ?{vis_sql} ORDER BY rowid LIMIT ?""",
                (self.user_id, scope, kind, последний, *vis_params, часть))
            if not rows:
                break
            последний = rows[-1]["rowid"]
            if первый is None:
                первый = rows[0]["id"]
            for r in rows:
                b = r["embedding"]
                близость = (float(np.clip(np.frombuffer(b, dtype=np.float32) @ v, -1.0, 1.0))
                            if len(b) == v.size * 4 else 0.0)
                if близость > лучшая_близость:
                    лучший, лучшая_близость = r["id"], близость
        if лучший is None:
            return None
        content = self.store.one("SELECT content FROM memory WHERE id = ?", (лучший,))["content"]
        return (лучший, content, лучшая_близость)

    def _векторы(self, scope, kind, dim, actor: roles.ActorContext | None = None):
        """(ids всех действующих записей с вектором, (матрица векторов размерности dim, их номера в ids))."""
        vis_sql, vis_params, vis_key = roles.visibility_sql(actor)
        кэш = self.__dict__.setdefault("_вкэш", {})
        ключ = (scope, kind, dim, vis_key)
        отметка = self.store.stamp()
        было = кэш.get(ключ)
        if было is not None and было[0] == отметка:
            return было[1], было[2]
        rows = self.store.query(
            f"""SELECT id, embedding FROM memory
               WHERE user_id = ? AND scope = ? AND kind = ?
                 AND status = 'active' AND embedding IS NOT NULL{vis_sql} ORDER BY rowid""",
            (self.user_id, scope, kind, *vis_params))
        ids = [r["id"] for r in rows]
        годные = [i for i, r in enumerate(rows) if len(r["embedding"]) == dim * 4]
        # Буфер с запасом: дописывание своей записи не копирует всю матрицу (рост ёмкости, в среднем O(1)).
        # 0.4.8: запас полуторный, а не двойной — при 100 000 записях × 768 это 440 МБ вместо 590.
        ёмкость = max(64, len(годные) + len(годные) // 2)
        буфер = np.zeros((ёмкость, dim), dtype=np.float32)
        номера = np.zeros(ёмкость, dtype=np.int64)
        if годные:
            буфер[:len(годные)] = np.frombuffer(b"".join(rows[i]["embedding"] for i in годные),
                                                dtype=np.float32).reshape(-1, dim)
            номера[:len(годные)] = годные
        кэш[ключ] = (отметка, ids, (буфер, len(годные), номера))
        return ids, кэш[ключ][2]

    def _сущности_записи(self, rid, content):
        """0.4.4: идентификаторы из текста записи — один раз на запись, а не на каждый поиск.
        Замер 09.11.2026: на 10 000 записях 70 % времени поиска (23 из 33 с на 30 запросов) уходило на то,
        что retrieval.entities заново разбирал текст каждой записи. Кэш по номеру записи сверяется с хешем
        текста и чистится при revoke: забытое не остаётся в памяти процесса."""
        if not content:
            return set()
        кэш = self.__dict__.setdefault("_сущности", {})
        h = hash(content)
        было = кэш.get(rid)
        if было is not None and было[0] == h:
            return было[1]
        найдено = retrieval.entities(content)
        кэш[rid] = (h, найдено)
        return найдено

    def _векторы_после(self, отметка_до, убрать=None, scope=None, kind=None):
        """0.4.11: один свой коммит после отметки, который не добавляет векторов, — кэш векторов не перечитывается.
        Замер 11.11.2026: за 500 записей поверх 3 000 кэш перестраивался 14 раз — 12 после замены записи и 2 после
        повтора; каждая перестройка читает все векторы базы, на 100 000 записях это и давало 56 мс на запись.
        Повтор не меняет ни векторов, ни статусов — кэшу нужна только новая отметка. Замена выводит одну запись
        из действующих — её строка убирается из буфера (на её место встаёт последняя). Во всех других случаях
        (лишний коммит, чужой процесс) кэш сбрасывается, как раньше."""
        кэш = self.__dict__.get("_вкэш")
        if not кэш:
            return
        после = self.store.stamp()
        for ключ in list(кэш):
            отметка, ids, (буфер, n, номера) = кэш[ключ]
            if отметка != отметка_до or после != (отметка_до[0] + 1, отметка_до[1]):
                del кэш[ключ]
                continue
            if убрать is not None and ключ[0] == scope and ключ[1] == kind:
                try:
                    i = ids.index(убрать)
                except ValueError:
                    i = -1
                if i >= 0:
                    # Запись уходит из списка совсем, как при построении кэша с нуля: иначе она осталась бы
                    # «действующей» с нулевой близостью. Номера строк буфера сдвигаются одним действием numpy.
                    ids.pop(i)
                    где = np.nonzero(номера[:n] == i)[0]
                    if len(где):
                        r = int(где[0])
                        n -= 1
                        буфер[r] = буфер[n]
                        номера[r] = номера[n]
                    живые = номера[:n]
                    живые[живые > i] -= 1
            кэш[ключ] = (после, ids, (буфер, n, номера))

    def _дописать_в_кэш(self, отметка_до, mid, scope, kind, vec, status,
                        visibility: str = "private", workspace_id: str | None = None):
        """Своя вставка — единственный коммит после отметки: вектор дописывается, а не перечитывается всё."""
        кэш = self.__dict__.get("_вкэш")
        if not кэш:
            return
        после = self.store.stamp()
        for ключ in [к for к in кэш if к[0] == scope and к[1] == kind]:
            отметка, ids, (буфер, n, номера) = кэш[ключ]
            if отметка != отметка_до or после != (отметка_до[0] + 1, отметка_до[1]):
                del кэш[ключ]
                continue
            vis_key = ключ[3] if len(ключ) > 3 else ("owner", None)
            видна_для_кэша = (
                vis_key == ("owner", None)
                or (visibility in roles.TEAM_VISIBILITIES and workspace_id == vis_key[1]
                    and kind not in config.PROTECTED_KINDS)
            )
            if видна_для_кэша and status == "active" and vec is not None:
                ids.append(mid)
                if vec.size == ключ[2]:
                    if n == len(буфер):
                        try:
                            запас = max(64, len(буфер) // 2)
                            буфер = np.concatenate([буфер, np.zeros((запас, буфер.shape[1]), dtype=буфер.dtype)])
                            номера = np.concatenate([номера, np.zeros(запас, dtype=номера.dtype)])
                        except MemoryError:
                            # 0.4.8: не хватило памяти на рост — кэш сбрасывается, следующий поиск пойдёт частями.
                            кэш.clear()
                            return
                    буфер[n] = np.asarray(vec, dtype=np.float32)
                    номера[n] = len(ids) - 1
                    n += 1
            кэш[ключ] = (после, ids, (буфер, n, номера))

    # -- L2: поиск ------------------------------------------------------

    def recall(self, query: str, scope: str = "global",
               kind: str | None = None, limit: int = 10,
               session_id: str | None = None,
               as_of: str | datetime | None = None,
               agent_id: str | None = None,
               actor: roles.ActorContext | None = None) -> list[Record]:
        """Поиск в одной области памяти. Подробности — в `_recall`.

        Запрос дополняется синонимами терминов (`add_alias`); каждая найденная запись получает
        пометки: подписана ли владельцем (для личности и предпочтений) и спорит ли с другой.
        """
        self.__dict__["_показы"] = []
        запрос = self._расширить(query)
        внутр_лимит = max(limit, config.RERANK_TOP_K) if config.RERANK else limit
        найдено = self._recall(запрос, scope, kind, внутр_лимит, session_id, as_of, agent_id=agent_id, actor=actor)
        if config.SEARCH_FEEDBACK and найдено and not agent_id:
            найдено = self._второй_проход(запрос, найдено, scope, kind, внутр_лимит, session_id, as_of, actor=actor)
        if config.RERANK and len(найдено) > 1:
            найдено = retrieval.rerank_records(
                query, найдено, top_k=config.RERANK_TOP_K, model_dir=config.RERANK_MODEL
            )
        найдено = найдено[:limit]
        if as_of is None and найдено and (config.SEARCH_FEEDBACK or config.RERANK):
            # показанными считаются только финальные записи итога после второго прохода/переранжирования
            показано = now_iso()
            self.__dict__["_показы"] = [
                ("""UPDATE memory SET access_count = access_count + 1, last_seen_at = ? WHERE id = ?""",
                 (показано, r.id)) for r in найдено]
        self._учесть_поиск(not найдено if as_of is None else None)
        self._пометить(найдено)
        return найдено

    def _второй_проход(self, запрос, найдено, scope, kind, limit, session_id, as_of, actor=None):
        """Псевдо-обратная связь (config.SEARCH_FEEDBACK): слова, общие для двух из пяти первых записей,
        дописываются к запросу; два списка сливаются обратным рангом (k = 60), как стратегии внутри поиска.
        Оценка записи (score) остаётся её собственной — меняется только порядок."""
        слова = retrieval.feedback_terms(запрос, [r.content for r in найдено[:5]])
        if not слова:
            return найдено
        второе = self._recall(запрос + " " + " ".join(слова), scope, kind, limit, session_id, as_of, actor=actor)
        балл: dict[str, float] = {}
        запись: dict[str, Record] = {}
        for список in (найдено, второе):
            for место, r in enumerate(список):
                балл[r.id] = балл.get(r.id, 0.0) + 1.0 / (retrieval.RRF_K + место + 1)
                запись.setdefault(r.id, r)
        порядок = sorted(балл, key=lambda i: -балл[i])           # sorted устойчив: ничьи — в порядке первого списка
        return [запись[i] for i in порядок[:limit]]

    def recall_many(self, query: str, scopes: list[str], kind: str | None = None,
                    limit: int = 10, as_of: str | datetime | None = None,
                    actor: roles.ActorContext | None = None) -> list[Record]:
        """Поиск сразу в нескольких областях — явный мост между ролями («работа» и «дом»).

        Без него области не смешиваются: каждая ищется отдельно, итог сводится по баллу,
        у каждой записи видна её область.
        """
        запрос = self._расширить(query)
        всё: list[Record] = []
        self.__dict__["_показы"] = []
        for s in list(dict.fromkeys(scopes))[:10]:
            всё += self._recall(запрос, s, kind, limit, None, as_of, actor=actor)
        всё.sort(key=lambda x: x.score, reverse=True)
        self._учесть_поиск(not всё if as_of is None else None)
        self._пометить(всё[:limit])
        return всё[:limit]

    def _пометить(self, записи: list[Record]) -> None:
        if not записи:
            return
        строки = {r["id"]: r for r in self.store.query(
            f"""SELECT id, kind, content, owner_sig, факт_ключ, scope, agent_id, visibility, workspace_id FROM memory
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
            з.agent_id = r["agent_id"]
            з.visibility = r["visibility"] or "private"
            з.workspace_id = r["workspace_id"]
            if ключ is not None and integrity.protected(з.kind) and з.status == "active":
                з.signed = integrity.valid(ключ, r)
            з.conflict = з.status == "active" and (r["scope"], r["факт_ключ"]) in спорные

    def _recall(self, query: str, scope: str = "global",
                kind: str | None = None, limit: int = 10,
                session_id: str | None = None,
                as_of: str | datetime | None = None,
                agent_id: str | None = None,
                actor: roles.ActorContext | None = None) -> list[Record]:
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
        # Порядок строк задан явно (0.4.4): от него зависит, какая из равных записей выше.
        params: list = [self.user_id, scope, *statuses]
        vis_sql, vis_params, vis_key = roles.visibility_sql(actor)
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        if agent_id:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        if vis_sql:
            sql += vis_sql
            params.extend(vis_params)
        sql += " ORDER BY rowid"

        if not момент:
            rows, статусы = self._кандидаты(sql, tuple(params), cache_tag=vis_key)
            if not rows:
                return []
            return self._ранжировать(query, scope, statuses, rows, статусы, session_id, limit, момент)
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
                 "created_at": r["created_at"],
                 "_ents": self._сущности_записи(r["id"], r["content"])} for r in raw]

        return self._ранжировать(query, scope, statuses, rows, статусы, session_id, limit, момент)


    def _кандидаты(self, sql, params, cache_tag=("owner", None)):
        """0.4.10: кандидаты поиска (текст, вектор, поля оценки) один раз на состояние базы, а не на каждый поиск.
        Замер 11.11.2026 на 10 000 записях: 2,81 из 4,15 с на 20 поисков уходило на этот SELECT — каждый
        поиск заново читал и распаковывал все действующие записи. Кэш сверяется с store.stamp() (свои
        коммиты + PRAGMA data_version), поэтому любая запись, правка, забывание или коммит другого
        процесса его сбрасывает; служебные счётчики поиска идут через store.counters и не сбрасывают.
        Строки только читаются дальше; итог поиска тот же, что без кэша."""
        кэш = self.__dict__.setdefault("_ккэш", {})
        отметка = self.store.stamp()
        ключ_кэша = (cache_tag, params)
        было = кэш.get(ключ_кэша)
        if было is not None and было[0] == отметка and было[1] == sql:
            return было[2], было[3]
        raw = self.store.query(sql, params)
        статусы = {r["id"]: r["status"] for r in raw}
        rows = [{"id": r["id"], "kind": r["kind"], "content": r["content"],
                 "_vec": unpack(r["embedding"]), "importance": r["importance"],
                 "confidence": r["confidence"],
                 "last_confirmed_at": r["last_confirmed_at"],
                 "expires_at": r["expires_at"],
                 "session_id": r["session_id"], "origin": r["origin"],
                 "created_at": r["created_at"],
                 "_ents": self._сущности_записи(r["id"], r["content"])} for r in raw]
        rows = self._с_матрицей(rows)
        кэш[ключ_кэша] = (отметка, sql, rows, статусы)
        return rows, статусы

    @staticmethod
    def _с_матрицей(rows):
        """0.4.13: векторы кандидатов — одной матрицей (строки — в порядке записей), а у записи — вид на её строку:
        память та же, а поиск не собирает матрицу заново (np.stack на каждом поиске — треть его времени)."""
        rows = retrieval.Кандидаты(rows)
        размеры: dict[int, int] = {}
        for r in rows:
            if r["_vec"] is not None:
                размеры[r["_vec"].shape[0]] = размеры.get(r["_vec"].shape[0], 0) + 1
        if not размеры:
            return rows
        dim = max(размеры, key=размеры.get)
        годные = [r for r in rows if r["_vec"] is not None and r["_vec"].shape == (dim,)]
        M = np.stack([r["_vec"] for r in годные])
        for k, r in enumerate(годные):
            r["_vec"] = M[k]
        rows.матрица = (dim, M, [r["id"] for r in годные])
        return rows

    def _ранжировать(self, query, scope, statuses, rows, статусы, session_id, limit, момент):
        """Общий хвост поиска: гибридное ранжирование и итоговая оценка (0.4.10 — вынесено из _recall)."""
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
        показано = now_iso()
        # 0.4.12: записывается вместе со статистикой поиска одной транзакцией (_учесть_поиск)
        self.__dict__.setdefault("_показы", []).extend(
            ("""UPDATE memory SET access_count = access_count + 1, last_seen_at = ? WHERE id = ?""",
             (показано, rec.id)) for rec in top)
        return top

    def _check_record_write(self, memory_id: str, actor: roles.ActorContext | None, action: str) -> None:
        if actor is None or actor.is_owner:
            return
        if actor.role == "auditor":
            self._log_audit(action, memory_id, actor=actor.role, agent_id=actor.subject, outcome="denied")
            raise PermissionError(t("роль auditor может только читать", "auditor role is read-only"))
        row = self.store.one(
            "SELECT kind, visibility, workspace_id FROM memory WHERE id = ? AND user_id = ?",
            (memory_id, self.user_id))
        if not row:
            return
        if row["visibility"] == "private" or row["workspace_id"] != actor.workspace_id or row["kind"] in config.PROTECTED_KINDS:
            self._log_audit(action, memory_id, actor=actor.role, agent_id=actor.subject, outcome="denied")
            raise PermissionError(t("нет прав изменять эту запись", "no permission to modify this record"))
        if row["visibility"] == "team_read" and actor.role == "contributor":
            self._log_audit(action, memory_id, actor=actor.role, agent_id=actor.subject, outcome="denied")
            raise PermissionError(t("contributor не может менять team_read запись", "contributor cannot modify team_read record"))

    def confirm(self, memory_id: str, actor: roles.ActorContext | None = None) -> bool:
        """Запись оказалась верной: обновить свежесть, поднять уверенность.

        Это то, что должно вызываться, когда извлечённая запись подтвердилась
        в разговоре, а не при каждом показе.
        """
        self._check_record_write(memory_id, actor, "confirm")
        cur = self.store.execute(
            """UPDATE memory SET last_confirmed_at = ?,
               confidence = MIN(confidence + 0.05, 1.0)
               WHERE id = ? AND user_id = ? AND status = 'active'""",
            (now_iso(), memory_id, self.user_id))
        if cur.rowcount > 0:
            r = self.store.one(
                "SELECT kind, scope, visibility, workspace_id, status FROM memory WHERE id = ? AND user_id = ?",
                (memory_id, self.user_id),
            )
            if r:
                _notify_change({
                    "action": "confirm",
                    "id": memory_id,
                    "scope": r["scope"] or "global",
                    "kind": r["kind"],
                    "status": r["status"],
                    "visibility": r["visibility"] or "private",
                    "workspace_id": r["workspace_id"],
                })
        return cur.rowcount > 0

    def refute(self, memory_id: str, drop: float = 0.3,
               floor: float = 0.0, actor: roles.ActorContext | None = None) -> bool:
        """Запись оказалась неверной: снизить уверенность.

        Свежесть НЕ обновляется. Если уверенность падает до нуля, запись уходит в архив, но
        остаётся в истории. floor — ниже этого не опускать: так MCP не может вывести из поиска
        защищённую запись. Несуществующая или уже недействующая запись — False, без молчаливого
        успеха.
        """
        self._check_record_write(memory_id, actor, "refute")
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
        r = self.store.one(
            "SELECT kind, scope, visibility, workspace_id, status FROM memory WHERE id = ? AND user_id = ?",
            (memory_id, self.user_id),
        )
        if r:
            _notify_change({
                "action": "refute",
                "id": memory_id,
                "scope": r["scope"] or "global",
                "kind": r["kind"],
                "status": r["status"],
                "visibility": r["visibility"] or "private",
                "workspace_id": r["workspace_id"],
            })
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

    def revoke(self, memory_id: str, cascade: bool = True, with_derived: bool = False,
               actor: roles.ActorContext | None = None) -> bool:
        """Физическое затирание содержания. Хеш и якорь остаются.

        По умолчанию вместе с записью затираются её прежние и новые версии, точные копии и
        исходные эпизоды. Иначе «забытое» продолжало бы лежать открытым текстом в истории версий
        и в буфере, а структурный ключ хранил бы, о чём шла речь.

        with_derived — ещё и все выводы, сделанные из этой записи (связи derived_from), со всеми
        их версиями: иначе забытое восстанавливается из выводов.
        """
        try:
            roles.require_owner(actor, "forget")
        except PermissionError as exc:
            self._log_audit("forget", memory_id, actor=actor.role if actor else "user",
                            agent_id=actor.subject if actor else None, outcome="denied", detail=str(exc))
            raise
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
        import json as _json
        цель = next((з for з in записи if з["id"] == memory_id), записи[0])
        доп = self.store.one(
            "SELECT kind, scope, visibility, workspace_id, anchor_tx, anchor_slot FROM memory WHERE id = ? AND user_id = ?",
            (цель["id"], self.user_id))
        ch_bytes = цель["content_hash"]
        if ch_bytes:
            ch_hex = bytes(ch_bytes).hex()
        elif цель["content"]:
            ch_hex = hashlib.sha256(цель["content"].encode("utf-8")).hexdigest()
        else:
            ch_hex = None
        leaf_hex = hashlib.sha256(
            b"\x02" + f"AIFA-FORGET|{memory_id}|{ts}".encode("utf-8")).hexdigest()
        receipt_id = new_id()
        wiped_ids = [з["id"] for з in записи]
        self._last_receipt = {
            "format": "padam-forget-receipt/1",
            "statement": "proof_of_erasure",
            "receipt_id": receipt_id,
            "memory_id": memory_id,
            "forgotten_at": ts,
            "content_hash_sha256": ch_hex,
            "kind": доп["kind"] if доп else None,
            "scope": доп["scope"] if доп else "global",
            "with_derived": bool(with_derived),
            "wiped_count": len(wiped_ids),
            "wiped_ids": wiped_ids,
            "key_destroyed": True,
            "anchor_tx": доп["anchor_tx"] if доп else None,
            "solana_url": f"https://solscan.io/tx/{доп['anchor_tx']}" if (доп and доп["anchor_tx"]) else None,
            "leaf_forget_hex": leaf_hex,
        }
        ops: list[tuple[str, tuple]] = [(
            """INSERT INTO forget_receipt
               (receipt_id, user_id, memory_id, forgotten_at, content_hash_sha256,
                kind, scope, with_derived, wiped_count, wiped_ids_json,
                key_destroyed, anchor_tx, leaf_forget_hex)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (receipt_id, self.user_id, memory_id, ts, ch_hex,
             доп["kind"] if доп else None, доп["scope"] if доп else "global",
             1 if with_derived else 0, len(wiped_ids), _json.dumps(wiped_ids),
             1, доп["anchor_tx"] if доп else None, leaf_hex))]
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
        # Забытое не должно жить и в памяти процесса: имена и номера из текста записи — тоже её содержание.
        self.__dict__.pop("_ккэш", None)          # 0.4.10: и текст в кэше кандидатов поиска
        кэш = self.__dict__.get("_сущности")
        if кэш:
            for з in записи:
                кэш.pop(з["id"], None)
        self._log_audit("forget", memory_id, actor="owner",
                        scope=доп["scope"] if доп else "global",
                        kind=доп["kind"] if доп else None,
                        outcome="revoked", detail=f"wiped={len(wiped_ids)}")
        _notify_change({
            "action": "revoke",
            "id": memory_id,
            "scope": (доп["scope"] if доп else None) or "global",
            "kind": доп["kind"] if доп else None,
            "status": "revoked",
            "visibility": (доп["visibility"] if доп else None) or "private",
            "workspace_id": доп["workspace_id"] if доп else None,
        })
        return True

    # -- история версий -------------------------------------------------

    VIEWS = {"active": ("active",), "review": ("quarantined",),
             "history": ("superseded", "archived", "rejected", "revoked")}

    def list_records(self, view: str = "active", text: str | None = None,
                     limit: int = 100, offset: int = 0, as_of: str | None = None,
                     kind: str | None = None, scope: str | None = None,
                     agent_id: str | None = None,
                     actor: roles.ActorContext | None = None) -> dict:
        """Записи для просмотра владельцем: действующие, на проверке или история, новые сверху.

        as_of — все записи, что действовали в тот момент, включая заменённые позже.
        """
        момент = parse_as_of(as_of) if as_of else None
        statuses = ("active", "superseded") if момент else self.VIEWS.get(view, self.VIEWS["active"])
        sql = (f"FROM memory WHERE user_id = ? AND status IN ({','.join('?' * len(statuses))})")
        params: list = [self.user_id, *statuses]
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        if scope:
            sql += " AND scope = ?"
            params.append(scope)
        if text:
            sql += " AND content LIKE ? ESCAPE '\\'"
            params.append("%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        if agent_id:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        if vis_sql:
            sql += vis_sql
            params.extend(vis_params)
        поля = ("SELECT id, kind, scope, content, status, origin, agent_id, confidence, importance, created_at, "
                "last_seen_at, last_confirmed_at, access_count, refuted_count, "
                "valid_from, valid_to, quarantine_reason, supersedes, superseded_by, anchor_tx, anchor_slot, "
                "visibility, workspace_id ")
        предел, сдвиг = max(1, min(int(limit), 500)), max(0, int(offset))
        def _обогатить(row_list):
            out = []
            for r in row_list:
                d = dict(r)
                try:
                    d["decay"] = round(decay(d["kind"], parse_ts(d["last_confirmed_at"] or d["created_at"])), 4)
                except Exception:
                    d["decay"] = 1.0
                out.append(d)
            return out
        if момент:
            rows = [r for r in self.store.query(поля + sql + " ORDER BY created_at DESC, rowid DESC", tuple(params))
                    if parse_ts(r["valid_from"] or r["created_at"]) <= момент
                    and (r["valid_to"] is None or parse_ts(r["valid_to"]) > момент)]
            return {"view": "as_of", "total": len(rows), "records": _обогатить(rows[сдвиг:сдвиг + предел])}
        всего = self.store.one("SELECT COUNT(*) " + sql, tuple(params))[0]
        rows = self.store.query(поля + sql + " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                                tuple(params) + (предел, сдвиг))
        return {"view": view, "total": всего, "records": _обогатить(rows)}

    def timeline(self, memory_id: str, actor: roles.ActorContext | None = None) -> list[dict]:
        """Цепочка версий: от текущей вглубь, к самой первой."""
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        chain, seen, cur_id = [], set(), memory_id
        while cur_id and cur_id not in seen:
            seen.add(cur_id)
            row = self.store.one(
                f"""SELECT id, content, status, created_at, supersedes, visibility, workspace_id
                   FROM memory WHERE id = ? AND user_id = ?{vis_sql}""",
                (cur_id, self.user_id, *vis_params))
            if not row:
                break
            chain.append(dict(row))
            cur_id = row["supersedes"]
        return list(reversed(chain))

    # -- выгрузка -------------------------------------------------------

    def export(self, include_superseded: bool = True,
               scope: str | None = None, limit: int | None = None,
               offset: int = 0, include_held: bool = True,
               actor: roles.ActorContext | None = None,
               *, cancel_event=None, progress_cb=None) -> dict:
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
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        if vis_sql:
            sql += vis_sql
            params.extend(vis_params)
        sql += " ORDER BY created_at"
        всего = self.store.one("SELECT COUNT(*) FROM (" + sql + ")", tuple(params))[0]
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params += [int(limit), int(offset)]

        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("export cancelled")
        rows_exp = self.store.query(sql, tuple(params))
        exp_total = max(1, len(rows_exp))
        if progress_cb is not None:
            progress_cb(0, exp_total, "export started")
        exp_step = max(1, len(rows_exp) // 10) if rows_exp else 1

        records = []
        for idx_exp, r in enumerate(rows_exp, 1):
            if cancel_event is not None and cancel_event.is_set():
                raise InterruptedError("export cancelled")
            d = dict(r)
            d.pop("embedding", None)          # бинарь в выгрузке бесполезен
            d.pop("owner_sig", None)          # подпись имеет смысл только с ключом этой машины
            h = d.pop("content_hash", None)
            d["content_hash"] = h.hex() if h else None
            # 0.4.14: колонка базы называется по-русски, а выгрузку читают люди по всему миру — в файле
            # поле зовётся fact_key. import_ его не читает: ключ факта пересчитывается из текста заново.
            if "факт_ключ" in d:
                d["fact_key"] = d.pop("факт_ключ")
            records.append(d)
            if progress_cb is not None and (idx_exp % exp_step == 0 or idx_exp == len(rows_exp)):
                progress_cb(idx_exp, exp_total, f"exported {idx_exp}/{len(rows_exp)}")
        if progress_cb is not None and not rows_exp:
            progress_cb(1, 1, "export completed")

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
               WHERE m.user_id = ? AND COALESCE(l.relation, 'derived') = 'derived'
               ORDER BY l.created_at""", (self.user_id,))
                 if r["src"] in ids and r["dst"] in ids]
        typed_links = [dict(r) for r in self.store.query(
            """SELECT l.src, l.dst, COALESCE(l.relation, 'derived') AS relation, l.created_at
               FROM memory_link l JOIN memory m ON m.id = l.dst
               WHERE m.user_id = ? AND COALESCE(l.relation, 'derived') != 'derived'
               ORDER BY l.created_at""", (self.user_id,))
                       if r["src"] in ids and r["dst"] in ids]

        return {
            "format": "padam-export/1",
            "exported_at": now_iso(),
            "user_id": self.user_id,
            "counts": {"memory": len(records), "memory_total": всего,
                       "sessions": len(sessions), "nocturne_runs": len(runs),
                       "links": len(links), "typed_links": len(typed_links)},
            "memory": records,
            "sessions": sessions,
            "nocturne_runs": runs,
            "links": links,
            "typed_links": typed_links,
        }

    def import_(self, payload: dict, overwrite: bool = False) -> int:
        """Загрузка выгрузки обратно. Возвращает число внесённых записей."""
        if payload.get("format") != "padam-export/1":
            raise ValueError(t("неизвестный формат выгрузки", "unknown export format"))
        added = 0
        for rec in payload.get("memory", []):
            # Импорт идёт теми же воротами, что и обычная запись: секреты вычищаются, размер ограничен.
            # Файл выгрузки мог быть изменён, а восстановленная запись потом попадает в контекст модели.
            ch = bytes.fromhex(rec["content_hash"]) if rec.get("content_hash") else None
            if rec.get("content") is not None:
                # 0.4.16: сначала обрезка с запасом, потом маскировка. Маскировка растёт сверхлинейно на сплошной строке
                # (320 000 знаков — 32 с), и одна запись в миллионы знаков в файле выгрузки подвешивала импорт.
                # Запас 256 знаков — чтобы ключ на границе маскировка видела целиком.
                очищено = safety.clean(str(rec["content"])[:config.MAX_CONTENT_CHARS + 256])[:config.MAX_CONTENT_CHARS]
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
        for link in list(payload.get("links") or []) + list(payload.get("typed_links") or []):
            if isinstance(link, dict) and isinstance(link.get("src"), str) and isinstance(link.get("dst"), str):
                if self.store.one("SELECT 1 FROM memory WHERE id = ? AND user_id = ?", (link["dst"], self.user_id)):
                    rel = str(link.get("relation") or "derived")
                    self._связать([link["src"]], link["dst"], relation=rel)
        return added

    # -- статистика -----------------------------------------------------

    def stats(self, actor: roles.ActorContext | None = None) -> dict:
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        def scalar(sql, params=()):
            row = self.store.one(sql, params)
            return row[0] if row else 0

        by_kind = {
            r["kind"]: r["n"] for r in self.store.query(
                f"""SELECT kind, COUNT(*) AS n FROM memory
                   WHERE user_id = ? AND status = 'active'{vis_sql}
                   GROUP BY kind""", (self.user_id, *vis_params))}
        ожидает = scalar(
            "SELECT COUNT(*) FROM episode WHERE user_id=? AND processed=0",
            (self.user_id,)) if roles.is_owner(actor) else 0

        return {
            "backend": embeddings.backend(),
            "db": str(self.store.path),
            "active": scalar(
                f"SELECT COUNT(*) FROM memory WHERE user_id=? AND status='active'{vis_sql}",
                (self.user_id, *vis_params)),
            "superseded": scalar(
                f"SELECT COUNT(*) FROM memory WHERE user_id=? AND status='superseded'{vis_sql}",
                (self.user_id, *vis_params)),
            "revoked": scalar(
                f"SELECT COUNT(*) FROM memory WHERE user_id=? AND status='revoked'{vis_sql}",
                (self.user_id, *vis_params)),
            "quarantined": scalar(
                f"SELECT COUNT(*) FROM memory WHERE user_id=? AND status='quarantined'{vis_sql}",
                (self.user_id, *vis_params)),
            "episodes_pending": ожидает,
            "consolidation_due": ожидает >= config.CONSOLIDATION_DUE,
            "stale_vectors": scalar(
                """SELECT COUNT(*) FROM memory WHERE user_id=? AND content IS NOT NULL
                   AND (embedding IS NULL OR embedding_model IS NULL OR embedding_model != ?)""",
                (self.user_id, embeddings.метка_модели())),
            "by_kind": by_kind,
            # 0.4.1: защищены ли ключи записей паролем и сколько лежит открыто — владелец должен видеть это сразу,
            # а не узнавать из README (без protect-keys у кого файл базы, тот прочтёт и шифротексты в Arweave).
            "record_keys": self._состояние_ключей(),
            "self": self.self_report(),
            "last_sleep": (self.nocturne_runs(1) or [None])[0],
        }

    def _состояние_ключей(self) -> dict:
        from . import keyvault
        try:
            return {"passphrase_protected": keyvault.is_enabled(self),
                    "plain": keyvault.plain_count(self)}
        except Exception as e:                     # состояние ключей не должно ронять stats
            return {"error": str(e)[:200]}

    def nocturne_runs(self, limit: int = 10) -> list[dict]:
        """Последние циклы консолидации NOCTURNE."""
        rows = self.store.query(
            """SELECT id, started_at, finished_at, episodes_sampled, high_priority_share,
                      kind_entropy, records_created, records_merged, records_superseded
               FROM nocturne_run WHERE user_id = ?
               ORDER BY started_at DESC LIMIT ?""",
            (self.user_id, max(1, min(int(limit), 100))))
        return [dict(r) for r in rows]

    def forget_preview(self, memory_id: str, actor: roles.ActorContext | None = None) -> dict | None:
        """Предпросмотр удаления: сама запись, цепочка версий и все выводы из неё."""
        roles.require_owner(actor, "forget")
        row = self.store.one(
            """SELECT id, kind, scope, content, status, created_at, content_hash, anchor_tx
               FROM memory WHERE id = ? AND user_id = ?""",
            (memory_id, self.user_id))
        if not row:
            return None
        связанные = self._связанные(memory_id)
        выводы_ids = self.derived(memory_id)
        выводы = []
        for вид in выводы_ids:
            r = self.store.one(
                "SELECT id, kind, scope, content, status, created_at FROM memory WHERE id = ? AND user_id = ?",
                (вид, self.user_id))
            if r:
                выводы.append(dict(r))
        ch = bytes(row["content_hash"]).hex() if row["content_hash"] else (
            hashlib.sha256(row["content"].encode("utf-8")).hexdigest() if row["content"] else None)
        return {
            "id": row["id"],
            "target_id": row["id"],
            "kind": row["kind"],
            "scope": row["scope"],
            "content": row["content"],
            "status": row["status"],
            "created_at": row["created_at"],
            "content_hash_sha256": ch,
            "anchor_tx": row["anchor_tx"],
            "versions_count": len(связанные),
            "version_ids": [з["id"] for з in связанные],
            "derived_count": len(выводы),
            "derived": выводы,
            "links": self.links_of(memory_id),
        }

    def forget_receipts(self, limit: int = 50, actor: roles.ActorContext | None = None) -> list[dict]:
        """Выданные квитанции об удалении (доказательства забвения)."""
        roles.require_owner(actor, "forget-receipts")
        import json as _json
        rows = self.store.query(
            """SELECT receipt_id, memory_id, forgotten_at, content_hash_sha256,
                      kind, scope, with_derived, wiped_count, wiped_ids_json,
                      key_destroyed, anchor_tx, leaf_forget_hex
               FROM forget_receipt WHERE user_id = ?
               ORDER BY forgotten_at DESC LIMIT ?""",
            (self.user_id, max(1, min(int(limit), 200))))
        итог = []
        for r in rows:
            try:
                wids = _json.loads(r["wiped_ids_json"] or "[]")
            except Exception:
                wids = [r["memory_id"]]
            итог.append({
                "format": "padam-forget-receipt/1",
                "statement": "proof_of_erasure",
                "receipt_id": r["receipt_id"],
                "memory_id": r["memory_id"],
                "forgotten_at": r["forgotten_at"],
                "content_hash_sha256": r["content_hash_sha256"],
                "kind": r["kind"],
                "scope": r["scope"],
                "with_derived": bool(r["with_derived"]),
                "wiped_count": r["wiped_count"],
                "wiped_ids": wids,
                "key_destroyed": bool(r["key_destroyed"]),
                "anchor_tx": r["anchor_tx"],
                "solana_url": f"https://solscan.io/tx/{r['anchor_tx']}" if r["anchor_tx"] else None,
                "leaf_forget_hex": r["leaf_forget_hex"],
            })
        return итог

    def doctor_report(self) -> dict:
        """Состояние защиты одним структурированным отчётом для Studio и API."""
        import os as _os
        import stat as _stat
        from . import __version__, keyvault
        предупреждений = 0
        опасностей = 0
        проверки = []

        unsafe = config.unsafe_settings()
        for имя, что in unsafe:
            предупреждений += 1
            опасностей += 1
            проверки.append({"id": "unsafe_" + имя.split("=")[0].lower(), "ok": False,
                             "severity": "danger", "name": имя, "detail": что})

        проверки.append({
            "id": "strict_profile",
            "ok": bool(config.STRICT),
            "severity": "ok" if config.STRICT else "info",
            "value": "PADAM_STRICT=1" if config.STRICT else "0",
            "ignored": config.strict_ignored(),
        })

        hold_ok = bool(config.HOLD_EXTERNAL)
        if not hold_ok:
            предупреждений += 1
            опасностей += 1
        проверки.append({
            "id": "hold_external",
            "ok": hold_ok,
            "severity": "ok" if hold_ok else "danger",
            "value": "1" if hold_ok else "0",
        })

        проверки.append({
            "id": "mcp_review_all",
            "ok": bool(config.MCP_REVIEW_ALL),
            "severity": "ok" if config.MCP_REVIEW_ALL else "info",
            "value": "1" if config.MCP_REVIEW_ALL else "0",
        })

        защищены = keyvault.is_enabled(self)
        открытых = keyvault.plain_count(self)
        if not защищены:
            предупреждений += 1
        проверки.append({
            "id": "record_keys",
            "ok": защищены and открытых == 0,
            "severity": "ok" if (защищены and открытых == 0) else "warn",
            "protected": защищены,
            "plain": открытых,
        })

        if _os.name == "posix" and str(self.store.path) != ":memory:" and self.store.path.exists():
            права = _stat.S_IMODE(_os.stat(self.store.path).st_mode)
            ok_mode = (права & 0o077) == 0
            if not ok_mode:
                предупреждений += 1
            проверки.append({
                "id": "file_mode",
                "ok": ok_mode,
                "severity": "ok" if ok_mode else "warn",
                "value": oct(права),
            })
        else:
            проверки.append({
                "id": "file_mode",
                "ok": True,
                "severity": "info",
                "value": "windows_acl" if _os.name != "posix" else "memory",
            })

        with self.store._lock:
            целостность = self.store.conn.execute("PRAGMA quick_check").fetchone()[0]
            журнал = self.store.conn.execute("PRAGMA journal_mode").fetchone()[0]
            синхр = int(self.store.conn.execute("PRAGMA synchronous").fetchone()[0])

        if целостность != "ok":
            предупреждений += 1
            опасностей += 1
        проверки.append({
            "id": "db_integrity",
            "ok": целостность == "ok",
            "severity": "ok" if целостность == "ok" else "danger",
            "value": целостность,
        })

        if синхр < 2:
            предупреждений += 1
        проверки.append({
            "id": "disk_sync",
            "ok": синхр >= 2,
            "severity": "ok" if синхр >= 2 else "warn",
            "journal": журнал,
            "synchronous": синхр,
        })

        неподписанных = len(self.unsigned_protected())
        if неподписанных > 0:
            предупреждений += 1
            опасностей += 1
        проверки.append({
            "id": "owner_signatures",
            "ok": неподписанных == 0,
            "severity": "ok" if неподписанных == 0 else "danger",
            "unsigned_count": неподписанных,
        })

        удержано = self.store.one(
            "SELECT COUNT(*) FROM memory WHERE user_id = ? AND status = 'quarantined'",
            (self.user_id,))[0]
        споров = len(self.conflicts())

        if опасностей > 0:
            level = "red"
        elif предупреждений > 0 or удержано > 0 or споров > 0:
            level = "yellow"
        else:
            level = "green"

        return {
            "version": __version__,
            "db": str(self.store.path),
            "level": level,
            "warnings": предупреждений,
            "dangers": опасностей,
            "strict": bool(config.STRICT),
            "hold_external": hold_ok,
            "mcp_review_all": bool(config.MCP_REVIEW_ALL),
            "keys_protected": защищены,
            "keys_plain": открытых,
            "integrity": целостность,
            "journal_mode": журнал,
            "synchronous": синхр,
            "unsigned_protected": неподписанных,
            "quarantined": удержано,
            "conflicts": споров,
            "fixed_api_token": bool(_os.environ.get("PADAM_API_TOKEN")),
            "checks": проверки,
        }

    def graph(self, center_id: str | None = None, limit: int = 200,
              as_of: str | datetime | None = None,
              actor: roles.ActorContext | None = None) -> dict:
        """Граф связей для Studio и API (/graph?id=&as_of=):
        - derived (источник): вывод сделан из источника (таблица memory_link)
        - cause (причина): причинно-следственная связь (таблица memory_link)
        - correction (исправление): уточнение/исправление прежнего факта (таблица memory_link)
        - contradiction (противоречие): противоречащая запись, закрывшая окно прежней (таблица memory_link)
        - version: новая версия заменила старую (supersedes)
        - conflict: активные записи спорят по факт_ключ
        При as_of показывает граф, действовавший на указанную дату/время.
        """
        предел = max(10, min(int(limit), 500))
        момент = parse_as_of(as_of) if as_of is not None and str(as_of).strip() else None

        vis_sql_m, vis_params, _ = roles.visibility_sql(actor, alias="m")
        vis_sql, _, _ = roles.visibility_sql(actor)
        все_ссылки = self.store.query(
            f"""SELECT l.src, l.dst, COALESCE(l.relation, 'derived') AS relation, l.created_at
               FROM memory_link l
               JOIN memory m ON m.id = l.dst
               JOIN memory s ON s.id = l.src
               WHERE m.user_id = ? AND m.status != 'revoked' AND s.status != 'revoked'
                 {vis_sql_m}{roles.visibility_sql(actor, alias="s")[0]}""",
            (self.user_id, *vis_params, *vis_params))
        версии_строки = self.store.query(
            f"""SELECT id, supersedes, created_at FROM memory
               WHERE user_id = ? AND supersedes IS NOT NULL AND status != 'revoked'{vis_sql}""",
            (self.user_id, *vis_params))
        споры = self.conflicts(actor=actor)

        edges = []
        связанные_ids = set()
        for r in все_ссылки:
            rel = r["relation"] if r["relation"] in LINK_RELATIONS else "derived"
            edges.append({"source": r["src"], "target": r["dst"], "type": rel,
                          "relation": rel, "created_at": r["created_at"]})
            связанные_ids.add(r["src"])
            связанные_ids.add(r["dst"])
        for r in версии_строки:
            edges.append({"source": r["supersedes"], "target": r["id"], "type": "version",
                          "relation": "version", "created_at": r["created_at"]})
            связанные_ids.add(r["supersedes"])
            связанные_ids.add(r["id"])
        for с in споры:
            recs = с["records"]
            for i in range(len(recs)):
                for j in range(i + 1, len(recs)):
                    edges.append({"source": recs[i]["id"], "target": recs[j]["id"],
                                  "type": "conflict", "relation": "conflict", "key": с["key"]})
                    связанные_ids.add(recs[i]["id"])
                    связанные_ids.add(recs[j]["id"])

        допустимые_на_дату: set[str] | None = None
        if момент is not None:
            все_записи = self.store.query(
                f"""SELECT id, created_at, valid_from, valid_to, status
                   FROM memory WHERE user_id = ?
                   AND status NOT IN ('quarantined', 'rejected', 'revoked'){vis_sql}""",
                (self.user_id, *vis_params))
            допустимые_на_дату = {
                r["id"] for r in все_записи
                if parse_ts(r["valid_from"] or r["created_at"]) <= момент
                and (r["valid_to"] is None or parse_ts(r["valid_to"]) > момент)
            }
            edges = [
                e for e in edges
                if e["source"] in допустимые_на_дату and e["target"] in допустимые_на_дату
                and (not e.get("created_at") or parse_ts(e["created_at"]) <= момент)
            ]
            связанные_ids = {nid for nid in связанные_ids if nid in допустимые_на_дату}

        if center_id:
            if допустимые_на_дату is not None and center_id not in допустимые_на_дату:
                узлы_ids = set()
                edges = []
            else:
                соседи = {center_id}
                очередь = [center_id]
                while очередь and len(соседи) < предел:
                    cur = очередь.pop(0)
                    for e in edges:
                        if e["source"] == cur and e["target"] not in соседи:
                            соседи.add(e["target"])
                            очередь.append(e["target"])
                        elif e["target"] == cur and e["source"] not in соседи:
                            соседи.add(e["source"])
                            очередь.append(e["source"])
                узлы_ids = соседи
                edges = [e for e in edges if e["source"] in узлы_ids and e["target"] in узлы_ids]
        else:
            узлы_ids = set(list(связанные_ids)[:предел])
            if len(узлы_ids) < min(30, предел):
                if допустимые_на_дату is not None:
                    для_добавки = [nid for nid in допустимые_на_дату if nid not in узлы_ids]
                    for nid in для_добавки[: max(0, min(30, предел) - len(узлы_ids))]:
                        узлы_ids.add(nid)
                else:
                    доп = self.store.query(
                        f"""SELECT id FROM memory WHERE user_id = ? AND status = 'active'{vis_sql}
                           ORDER BY created_at DESC LIMIT ?""",
                        (self.user_id, *vis_params, min(30, предел) - len(узлы_ids)))
                    for r in доп:
                        узлы_ids.add(r["id"])
            edges = [e for e in edges if e["source"] in узлы_ids and e["target"] in узлы_ids]

        nodes = []
        if узлы_ids:
            список_ids = list(узлы_ids)
            rows = self.store.query(
                f"""SELECT id, kind, scope, content, status, origin, confidence, importance,
                           created_at, last_confirmed_at, valid_from, valid_to,
                           supersedes, superseded_by, факт_ключ, visibility, workspace_id
                    FROM memory WHERE user_id = ?{vis_sql} AND id IN ({','.join('?' * len(список_ids))})""",
                (self.user_id, *vis_params, *список_ids))
            for r in rows:
                текст = r["content"]
                nodes.append({
                    "id": r["id"],
                    "kind": r["kind"],
                    "scope": r["scope"],
                    "label": (текст or "—"),
                    "content": текст,
                    "status": r["status"],
                    "origin": r["origin"] or "user",
                    "confidence": r["confidence"],
                    "importance": r["importance"],
                    "created_at": r["created_at"],
                    "last_confirmed_at": r["last_confirmed_at"],
                    "valid_from": r["valid_from"] or r["created_at"],
                    "valid_to": r["valid_to"],
                    "supersedes": r["supersedes"],
                    "superseded_by": r["superseded_by"],
                    "fact_key": r["факт_ключ"],
                })

        прямые_источники = []
        выводы_цепочкой = []
        связи_узла = {"incoming": [], "outgoing": []}
        if center_id and center_id in узлы_ids:
            выводы_цепочкой = self.derived(center_id)
            оч = [center_id]
            while оч:
                cur = оч.pop()
                for r in self.store.query(
                        """SELECT l.src FROM memory_link l JOIN memory m ON m.id = l.src
                           WHERE l.dst = ? AND m.user_id = ? AND COALESCE(l.relation, 'derived') = 'derived'""",
                        (cur, self.user_id)):
                    if r["src"] not in прямые_источники and r["src"] != center_id:
                        прямые_источники.append(r["src"])
                        оч.append(r["src"])
            связи_узла = self.links_of(center_id)
            if допустимые_на_дату is not None:
                выводы_цепочкой = [wid for wid in выводы_цепочкой if wid in допустимые_на_дату]
                прямые_источники = [sid for sid in прямые_источники if sid in допустимые_на_дату]
                связи_узла = {
                    "incoming": [x for x in связи_узла["incoming"] if x["id"] in допустимые_на_дату],
                    "outgoing": [x for x in связи_узла["outgoing"] if x["id"] in допустимые_на_дату],
                }

        return {
            "center_id": center_id,
            "as_of": момент.isoformat() if момент is not None else None,
            "relations": list(LINK_RELATIONS),
            "nodes": nodes,
            "edges": edges,
            "derived": выводы_цепочкой,
            "sources": прямые_источники,
            "selected_links": связи_узла,
            "counts": {
                "nodes": len(nodes),
                "edges": len(edges),
                "derived_edges": sum(1 for e in edges if e["type"] == "derived"),
                "cause_edges": sum(1 for e in edges if e["type"] == "cause"),
                "correction_edges": sum(1 for e in edges if e["type"] == "correction"),
                "contradiction_edges": sum(1 for e in edges if e["type"] == "contradiction"),
                "version_edges": sum(1 for e in edges if e["type"] == "version"),
                "conflict_edges": sum(1 for e in edges if e["type"] == "conflict"),
            },
        }

    def l3_status(self) -> dict:
        """Состояние вечного слоя L3: якоря, ссылки на Solscan и Arweave, ожидающие записи."""
        from . import anchor
        anchor.ensure_schema(self)
        rows = self.store.query(
            """SELECT id, created_at, root_hex, leaf_count, bundle_sha256, bundle_bytes,
                      arweave_tx, solana_sig, solana_slot, network, memo, ots
               FROM l3_anchor WHERE user_id = ?
               ORDER BY created_at DESC""",
            (self.user_id,))
        якоря = []
        for r in rows:
            net = r["network"] or "devnet"
            sig = r["solana_sig"]
            ar = r["arweave_tx"]
            sol_url = (f"https://solscan.io/tx/{sig}" + ("?cluster=devnet" if net == "devnet" else "")) if sig else None
            ar_url = f"https://arweave.net/{ar}" if ar else None
            ots_info = None
            if r["ots"] is not None:
                try:
                    from . import ots as _ots
                    о = _ots.info(bytes(r["ots"]))
                    ots_info = {"bitcoin_blocks": о.get("bitcoin_blocks", []),
                                "pending": len(о.get("pending", []))}
                except Exception:
                    ots_info = {"present": True}
            якоря.append({
                "id": r["id"],
                "created_at": r["created_at"],
                "root_hex": r["root_hex"],
                "leaf_count": r["leaf_count"],
                "bundle_sha256": r["bundle_sha256"],
                "bundle_bytes": r["bundle_bytes"],
                "arweave_tx": ar,
                "arweave_url": ar_url,
                "solana_sig": sig,
                "solana_slot": r["solana_slot"],
                "solscan_url": sol_url,
                "network": net,
                "memo": r["memo"],
                "has_ots": r["ots"] is not None,
                "ots": ots_info,
            })
        незаякорено = self.store.one(
            """SELECT COUNT(*) FROM memory WHERE user_id = ? AND status = 'active'
               AND content IS NOT NULL AND anchor_tx IS NULL""",
            (self.user_id,))[0]
        ждут_забвения = self.store.one(
            """SELECT COUNT(*) FROM anchor_key k JOIN memory m ON m.id = k.memory_id
               WHERE m.user_id = ? AND k.destroyed_at IS NOT NULL
                 AND NOT EXISTS (SELECT 1 FROM l3_leaf l WHERE l.memory_id = k.memory_id AND l.kind = 'forget')
                 AND EXISTS (SELECT 1 FROM l3_leaf l WHERE l.memory_id = k.memory_id AND l.kind = 'record')""",
            (self.user_id,))[0]
        return {
            "anchors": якоря,
            "unanchored_records": незаякорено,
            "pending_forgets": ждут_забвения,
            "record_keys": self._состояние_ключей(),
        }

    def l3_verify_anchor(self, anchor_id: str | None = None, online: bool = False) -> dict:
        """Проверка закрепления L3 (локальная копия пакета или шлюз + корень Меркла + OTS)."""
        import hashlib as _hashlib
        from pathlib import Path as _Path
        from . import anchor
        anchor.ensure_schema(self)
        row = (self.store.one("SELECT * FROM l3_anchor WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
                              (self.user_id,))
               if not anchor_id else
               self.store.one("SELECT * FROM l3_anchor WHERE id = ? AND user_id = ?",
                              (anchor_id, self.user_id)))
        if not row:
            return {"ok": False, "error": "no_anchors"}
        local_path = _Path(str(self.store.path) + ".l3") / f"{row['id']}.json"
        local = local_path.read_bytes() if local_path.exists() else None
        remote = None
        if online and row["arweave_tx"]:
            try:
                remote = anchor.fetch_arweave(row["arweave_tx"], timeout=10)
            except Exception:
                remote = None
        payload = remote or local
        memo = row["memo"] or ""
        if online and row["solana_sig"]:
            try:
                memo = anchor.read_memo(row["solana_sig"], row["network"] or "devnet")
            except Exception:
                memo = row["memo"] or ""
        if payload is None:
            # Проверим листья из таблицы l3_leaf против root_hex в l3_anchor и memo
            листья = [bytes.fromhex(r["leaf_hex"]) for r in self.store.query(
                "SELECT leaf_hex FROM l3_leaf WHERE anchor_id = ? ORDER BY position", (row["id"],))]
            if листья:
                пересчитан = anchor.merkle_root(листья).hex()
                in_memo = memo.split("root=", 1)[1].split()[0] if "root=" in memo else row["root_hex"]
                ok = (пересчитан == row["root_hex"] == in_memo)
                return {
                    "anchor_id": row["id"],
                    "ok": ok,
                    "source": "db_leaves",
                    "root_recomputed": пересчитан,
                    "root_in_db": row["root_hex"],
                    "root_in_memo": in_memo,
                    "leaves": len(листья),
                    "arweave_tx": row["arweave_tx"],
                    "solana_sig": row["solana_sig"],
                    "network": row["network"],
                }
            return {"anchor_id": row["id"], "ok": False, "error": "bundle_not_found"}
        v = anchor.verify_bundle(payload, memo)
        sha_ok = _hashlib.sha256(payload).hexdigest() == row["bundle_sha256"]
        v.update(
            anchor_id=row["id"],
            arweave_tx=row["arweave_tx"],
            solana_sig=row["solana_sig"],
            network=row["network"],
            source="arweave" if remote else "local_copy",
            sha256_matches_db=sha_ok,
        )
        v["ok"] = bool(v["ok"] and sha_ok)
        if row["ots"] is not None:
            try:
                from . import ots as _ots
                о = _ots.info(bytes(row["ots"]))
                v["bitcoin_ots"] = {
                    "matches_bundle": _ots.matches(bytes(row["ots"]), payload),
                    "bitcoin_blocks": о["bitcoin_blocks"],
                    "pending_calendars": о["pending"],
                }
            except Exception as e:
                v["bitcoin_ots"] = {"error": f"{type(e).__name__}: {e}"}
        return v

    def export_markdown(self, out_dir: str, scope: str | None = None) -> dict:
        """Б20: выгрузить действующие записи (status='active') в папку Markdown / Obsidian."""
        from . import portability
        return portability.export_markdown(self, out_dir=out_dir, scope=scope)

    def import_external(self, source, fmt: str = "auto", scope: str = "global") -> dict:
        """Б8: защищённый импорт внешней памяти (ChatGPT, Claude, Markdown/Obsidian, mem0) с origin='external'."""
        from . import portability
        return portability.import_external(self, source=source, fmt=fmt, scope=scope)

    # -- Б9: профиль человека (только подписанные владельцем identity и preference) и Б12: журнал действий --

    def _log_audit(self, action: str, memory_id: str | None = None,
                   actor: str = "user", agent_id: str | None = None,
                   scope: str | None = None, kind: str | None = None,
                   outcome: str | None = None, detail: str | None = None) -> None:
        """Б12: записать действие в таблицу audit_log (без текста самой записи)."""
        try:
            if not kind and memory_id:
                row = self.store.one("SELECT kind, scope, agent_id FROM memory WHERE id = ?", (memory_id,))
                if row:
                    kind = kind or row["kind"]
                    scope = scope or row["scope"]
                    agent_id = agent_id or row["agent_id"]
            ev_id = new_id()
            ts = now_iso()
            # Запись в audit_log не меняет таблицу memory, поэтому пишем через counters без сброса кэша поиска.
            self.store.counters([(
                """INSERT INTO audit_log
                   (id, user_id, created_at, action, memory_id, actor, agent_id, scope, kind, outcome, detail)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (ev_id, self.user_id, ts, action, memory_id,
                 actor or "user", agent_id, scope or "global", kind, outcome, detail),
            )])
            ev = {
                "id": ev_id,
                "user_id": self.user_id,
                "created_at": ts,
                "action": action,
                "memory_id": memory_id,
                "actor": actor or "user",
                "agent_id": agent_id,
                "scope": scope or "global",
                "kind": kind,
                "outcome": outcome,
                "detail": detail,
            }
            for q in list(getattr(self, "_event_queues", [])):
                try:
                    q.put_nowait(ev)
                except Exception:
                    pass
            if getattr(config, "WEBHOOK_URL", ""):
                self._dispatch_webhook(ev)
        except Exception:
            pass

    def subscribe_events(self):
        """Б10: подписаться на живой поток событий памяти (SSE)."""
        import queue
        if not hasattr(self, "_event_queues"):
            self._event_queues = []
        q = queue.Queue(maxsize=256)
        self._event_queues.append(q)
        return q

    def unsubscribe_events(self, q) -> None:
        """Б10: отписаться от потока событий памяти."""
        qs = getattr(self, "_event_queues", None)
        if qs and q in qs:
            qs.remove(q)

    def _dispatch_webhook(self, event: dict) -> bool:
        """Б10: отправка события наружу по явно заданному PADAM_WEBHOOK_URL с подписью HMAC-SHA256."""
        url = (getattr(config, "WEBHOOK_URL", "") or "").strip()
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            return False
        import hashlib
        import hmac as _hmac
        import json
        import urllib.request
        body = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "PADAM-Nocturne-Webhook/1.0",
            "X-Padam-Event": str(event.get("action") or "event"),
        }
        secret = (getattr(config, "WEBHOOK_SECRET", "") or "").strip()
        if secret:
            sig = _hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Padam-Signature"] = f"sha256={sig}"
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def audit_log(self, limit: int = 100, action: str | None = None,
                  agent_id: str | None = None,
                  actor: roles.ActorContext | None = None) -> list[dict]:
        """Б12: получить последние записи журнала действий."""
        roles.require_audit_read(actor)
        sql = """SELECT id, user_id, created_at, action, memory_id, actor, agent_id, scope, kind, outcome, detail
                 FROM audit_log WHERE user_id = ?"""
        params: list = [self.user_id]
        if action:
            sql += " AND action = ?"
            params.append(action)
        if agent_id:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        return [dict(r) for r in self.store.query(sql, tuple(params))]

    def profile(self, scope: str = "global") -> dict:
        """Б9: сводка «кто я и что предпочитаю» ТОЛЬКО из подписанных владельцем записей identity и preference."""
        ключ = self._ключ_подписи()
        scopes = ["global"] if scope == "global" else ["global", scope]
        rows = self.store.query(
            f"""SELECT id, kind, scope, content, owner_sig, confidence, importance, created_at, last_confirmed_at
                FROM memory
                WHERE user_id = ? AND status = 'active'
                  AND kind IN ('identity', 'preference')
                  AND scope IN ({','.join('?' * len(scopes))})
                ORDER BY importance DESC, created_at DESC""",
            (self.user_id, *scopes),
        )
        identity_items = []
        preference_items = []
        unsigned_skipped = 0
        for r in rows:
            if not integrity.valid(ключ, r):
                unsigned_skipped += 1
                continue
            item = {
                "id": r["id"],
                "kind": r["kind"],
                "scope": r["scope"],
                "content": r["content"],
                "confidence": r["confidence"],
                "importance": r["importance"],
                "created_at": r["created_at"],
                "signed": True,
            }
            if r["kind"] == "identity":
                identity_items.append(item)
            else:
                preference_items.append(item)
        lines = []
        if identity_items:
            lines.append("Identity (owner-signed):")
            for it in identity_items:
                lines.append(f"- {it['content']} (id={it['id'][:8]})")
        if preference_items:
            lines.append("Preferences (owner-signed):")
            for pr in preference_items:
                lines.append(f"- {pr['content']} (id={pr['id'][:8]})")
        if not lines:
            lines.append("No owner-signed identity or preference records stored yet.")
        return {
            "user_id": self.user_id,
            "scope": scope,
            "identity": identity_items,
            "preferences": preference_items,
            "unsigned_skipped": unsigned_skipped,
            "summary": "\n".join(lines),
        }

    # -- Г10 («Спроси свою память» на локальной модели Ollama) и Пункт 3 (улучшенный конвейер QA) --

    @staticmethod
    def classify_qa_intent(question: str) -> dict:
        """Пункт 3.1: Определяет тип вопроса (временной, обновление факта, предпочтение, составной)."""
        q_low = str(question or "").lower()
        temporal_markers = (
            "when ", "what date", "what time", "what year", "what month", "which month",
            "how many days", "how many weeks", "how many months", "how many years", "how long",
            "before ", "after ", "earlier", "later", "first ", "last ", "order of", "chronolog",
            "between ", "ago", "since ", "until ",
            "когда", "какого числа", "в каком году", "в каком месяце", "сколько дней",
            "сколько недель", "сколько месяцев", "сколько лет", "как долго", "раньше", "позже",
            "до того", "после того", "сначала", "в каком порядке",
        )
        update_markers = (
            "current", "currently", "right now", " now", "latest", "most recent", "recently",
            "updated", "changed", "still ", "anymore", "new ", "newest",
            "сейчас", "текущ", "последн", "обновлен", "актуальн", "теперь", "по-прежнему",
        )
        pref_markers = (
            "recommend", "suggest", "advice", "should i", "help me choose", "ideas for",
            "what kind of", "tailor", "prefer",
            "посоветуй", "порекомендуй", "предложи", "что выбрать", "предпочитаю",
        )
        is_temporal = any(m in q_low for m in temporal_markers)
        is_update = any(m in q_low for m in update_markers)
        is_preference = any(m in q_low for m in pref_markers)
        return {
            "temporal": is_temporal,
            "knowledge_update": is_update,
            "preference": is_preference,
            "chronological_sort": is_temporal or is_update,
        }

    @staticmethod
    def check_qa_sufficiency(question: str, records: list[dict]) -> dict:
        """Пункт 3.1: Проверяет достаточность найденных данных для ответа (отказ при недостатке данных)."""
        if not records:
            return {"sufficient": False, "reason": "no_records", "term_coverage": 0.0, "missing_terms": []}

        stop = {
            "what", "when", "where", "which", "who", "whom", "whose", "why", "how",
            "many", "much", "long", "often", "did", "does", "do", "was", "were", "is", "are",
            "have", "has", "had", "been", "being", "will", "would", "could", "should", "can",
            "the", "and", "for", "with", "from", "that", "this", "these", "those", "into",
            "about", "before", "after", "between", "during", "under", "over", "again", "further",
            "then", "once", "here", "there", "all", "any", "both", "each", "few", "more",
            "most", "other", "some", "such", "only", "own", "same", "than", "too", "very",
            "just", "now", "currently", "current", "latest", "recent", "recently", "last", "first",
            "days", "weeks", "months", "years", "time", "date", "year", "month", "week", "day",
            "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
            "january", "february", "march", "april", "may", "june", "july", "august",
            "september", "october", "november", "december",
            "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
            "ago", "since", "until", "past", "previous", "next", "earlier", "later", "yesterday",
            "today", "tomorrow", "morning", "afternoon", "evening", "night",
            "total", "spend", "spent", "tell", "give", "recommend", "suggest", "please", "kind",
            "start", "started", "begin", "began", "take", "took", "make", "made", "get", "got",
            "что", "где", "когда", "как", "какой", "какая", "какие", "каком", "каких", "кто",
            "сколько", "почему", "зачем", "был", "была", "были", "быть", "есть", "мой", "моя",
            "мои", "мне", "меня", "для", "или", "это", "все", "еще", "уже", "сейчас", "текущий",
        }
        tokens = re.findall(r"[A-Za-zА-Яа-яЁё0-9]{3,}", str(question or ""))
        key_terms = []
        for t in tokens:
            low = t.lower()
            if low not in stop and low not in key_terms:
                key_terms.append(low)

        if not key_terms:
            return {"sufficient": True, "reason": "ok", "term_coverage": 1.0, "missing_terms": []}

        combined_text = " ".join(
            f"{r.get('session_date') or ''} {r.get('created_at') or ''} {r.get('content') or ''}"
            for r in records
        ).lower()
        matched = []
        missing = []
        for term in key_terms:
            stem = term[:-1] if len(term) > 5 and term.endswith(("s", "d", "е", "и", "а", "ы")) else term
            if term in combined_text or (len(stem) >= 4 and stem in combined_text):
                matched.append(term)
            else:
                missing.append(term)

        coverage = round(len(matched) / len(key_terms), 4)
        max_rrf = max((float(r.get("rrf") or r.get("score") or 0.0) for r in records), default=0.0)
        if len(matched) == 0 and max_rrf < 0.025:
            return {
                "sufficient": False,
                "reason": "zero_term_overlap",
                "term_coverage": 0.0,
                "missing_terms": missing,
            }
        return {
            "sufficient": True,
            "reason": "partial_missing" if missing else "ok",
            "term_coverage": coverage,
            "missing_terms": missing,
        }

    @staticmethod
    def smart_qa_excerpt(text: str, question: str = "", rank: int = 0) -> str:
        """Пункт 3.1: Сохраняет реплику человека полностью (до 2400 симв.) и важную часть ответа ассистента
        (до 1400 симв. для верхних результатов + абзацы с ключевыми словами вопроса), не забивая окно шумом."""
        marker = "\nassistant: "
        if marker not in text:
            return text[:2800]
        person, assistant = text.split(marker, 1)
        out = person[:2400] + ("…" if len(person) > 2400 else "")
        if not assistant.strip():
            return out
        q_low = (question or "").lower()
        asks_assistant = any(
            w in q_low for w in ("assistant", "recommend", "suggest", "advice", "you ", "your ", "provide", "list", "recipe")
        )
        tail_limit = 1800 if (asks_assistant or rank < 4) else 500
        if len(assistant) <= tail_limit:
            return out + marker + assistant
        head_part = assistant[:tail_limit]
        q_words = [w.lower() for w in re.findall(r"[A-Za-zА-Яа-яЁё0-9]{4,}", question or "") if len(w) >= 4]
        extra_lines = []
        if q_words:
            for line in assistant[tail_limit:].splitlines():
                l_low = line.lower()
                if any(w in l_low for w in q_words):
                    extra_lines.append(line.strip())
                    if sum(len(x) for x in extra_lines) > 700:
                        break
        suffix = ("\n…\n" + "\n".join(extra_lines)) if extra_lines else "…"
        return out + marker + head_part + suffix

    @classmethod
    def build_qa_prompt(
        cls,
        question: str,
        records: list[dict],
        current_date: str | None = None,
        fenced: bool = True,
    ) -> str:
        """Пункт 3.1: Собирает обогащённый промпт для языковой модели с хронологией, пометкой LATEST и проверкой полноты."""
        intent = cls.classify_qa_intent(question)
        suff = cls.check_qa_sufficiency(question, records)

        ordered = list(records)
        ordered.sort(key=lambda r: (str(r.get("session_date") or r.get("created_at") or ""), int(r.get("round_index") or 0)))

        ctx_lines = []
        total = len(ordered)
        for i, rec in enumerate(ordered):
            dt = str(rec.get("session_date") or rec.get("created_at") or "").strip()
            latest_tag = " [LATEST / MOST RECENT SESSION]" if (total > 1 and i == total - 1 and dt) else ""
            header = f"[Excerpt {i + 1} | Session date: {dt}{latest_tag}]" if dt else f"[Excerpt {i + 1}]"
            ctx_lines.append(f"{header}\n{rec.get('content') or ''}")

        body_block = "\n\n".join(ctx_lines)
        if fenced:
            body_block = safety.fence(body_block)

        rules = [
            "Below are chronological excerpts from the user's earlier chats with an assistant, retrieved from memory, each with its session date.",
            "Answer the question using ONLY these excerpts:",
            "- If the question asks for a specific fact, item, place, or number that is NOT mentioned in the excerpts (for example, the excerpts mention a similar hobby or only one of two requested places), state clearly that the requested information is not available in the provided excerpts, and briefly mention what was discussed instead.",
            "- If a fact changed over time across sessions, the latest session ([LATEST / MOST RECENT SESSION]) holds the current updated value; state the updated answer clearly.",
            "- For time, date, or count questions ('when', 'how many', 'in March', 'two months ago', 'how many days between'), anchor relative time phrases in the question ('two months ago') to Current date, and anchor relative phrases inside an excerpt ('last Wednesday', 'yesterday') to that excerpt's [Session date: ...]. Filter out events from other months/dates before giving the final answer.",
            "- For personalized recommendation questions, directly apply the user's preferences and background from the excerpts.",
        ]
        if suff["missing_terms"] and suff["term_coverage"] < 0.35:
            rules.append(
                f"Note: Check whether '{', '.join(suff['missing_terms'][:4])}' is actually mentioned in the excerpts; if not, state that the information is not available."
            )

        date_line = f"\nCurrent date: {current_date}" if current_date else ""
        return (
            "\n".join(rules)
            + "\n\n"
            + body_block
            + f"{date_line}\nQuestion: {question}\nAnswer:"
        )

    def ollama_models(self) -> dict:
        """Г10: Проверяет доступность локального Ollama (127.0.0.1:11434) и список моделей ($0, без облака)."""
        import os as _os
        import urllib.request
        from urllib.parse import urlsplit

        base_url = (config.OLLAMA_URL or "http://127.0.0.1:11434").rstrip("/")
        parsed = urlsplit(base_url)
        host = (parsed.hostname or "").lower()
        if host not in ("127.0.0.1", "localhost", "::1") and not host.startswith("127."):
            return {"available": False, "models": [], "selected": config.ASK_MODEL, "url": base_url}

        try:
            req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2.5) as r:
                payload = json.loads(r.read().decode("utf-8", "replace"))
            raw_models = []
            for m in (payload.get("models") or []):
                name = str(m.get("name") or "").strip()
                if not name:
                    continue
                if m.get("remote_host") or m.get("remote_model") or name.lower().endswith("-cloud"):
                    continue
                raw_models.append(name)
            gen_models = [
                m for m in raw_models
                if not any(emb in m.lower() for emb in ("embed", "minilm", "bge-"))
            ]
            models = gen_models or raw_models
            return {"available": True, "models": models, "selected": config.ASK_MODEL, "url": base_url}
        except Exception:
            return {"available": False, "models": [], "selected": config.ASK_MODEL, "url": base_url}

    def ask(self, question: str, scope: str = "global", limit: int = 10,
            model: str | None = None, actor: roles.ActorContext | None = None) -> dict:
        """Г10 + Пункт 3: «Спроси свою память» — поиск + расширение контекста + упорядочивание по времени
        + отказ при недостатке данных + ответ ЛОКАЛЬНОЙ моделью через Ollama ($0, CPU <= 50%);
        без Ollama возвращает найденные записи с подробным разбором «почему найдено».
        """
        import os as _os
        import urllib.request
        from urllib.parse import urlsplit

        q = str(question or "").strip()
        if not q:
            return {
                "question": "",
                "answer": None,
                "mode": "empty",
                "ollama_available": False,
                "model": config.ASK_MODEL or None,
                "records": [],
                "intent": self.classify_qa_intent(""),
                "sufficiency": {"sufficient": False, "reason": "empty_question", "term_coverage": 0.0, "missing_terms": []},
            }

        k_lim = max(1, min(int(limit), 25))
        found = self.recall(q, scope=scope, limit=k_lim, actor=actor)
        records = []
        seen_ids = set()
        for r in found:
            seen_ids.add(r.id)
            d_val = round(decay(r.kind, r.last_confirmed_at), 4)
            strats = "+".join(r.strategies) if r.strategies else "hybrid"
            explain = (
                f"{strats} · score={r.score:.4f} "
                f"(rrf={r.similarity:.4f} × decay={d_val:.2f} × conf={r.confidence:.2f} × imp={r.importance:.2f})"
            )
            records.append({
                "id": r.id,
                "kind": r.kind,
                "content": r.content,
                "score": round(r.score, 5),
                "rrf": round(r.similarity, 5),
                "decay": d_val,
                "importance": r.importance,
                "confidence": r.confidence,
                "origin": r.origin,
                "agent_id": r.agent_id,
                "created_at": r.created_at,
                "last_confirmed_at": (
                    r.last_confirmed_at.isoformat()
                    if hasattr(r.last_confirmed_at, "isoformat")
                    else str(r.last_confirmed_at)
                ),
                "expired": r.expired,
                "status": r.status,
                "scope": r.scope,
                "signed": r.signed,
                "conflict": r.conflict,
                "suspicious": safety.looks_like_instruction(r.content),
                "found_by": list(r.strategies),
                "explain": explain,
            })

        # Пункт 3.1: Подтягиваем связанные по memory_link / supersedes активные записи для полноты контекста
        if records and len(records) < k_lim:
            top_ids = [r["id"] for r in records[:5]]
            placeholders = ",".join("?" for _ in top_ids)
            linked_rows = self.store.query(
                f"""SELECT DISTINCT m.id, m.kind, m.content, m.importance, m.confidence, m.origin, m.agent_id,
                           m.created_at, m.last_confirmed_at, m.status, m.scope
                    FROM memory m
                    JOIN memory_link l ON (l.src = m.id OR l.dst = m.id)
                    WHERE m.user_id = ? AND m.status = 'active'
                      AND (l.src IN ({placeholders}) OR l.dst IN ({placeholders}))
                    LIMIT 4""",
                (self.user_id, *top_ids, *top_ids),
            )
            for lr in linked_rows:
                if lr["id"] not in seen_ids and len(records) < k_lim:
                    seen_ids.add(lr["id"])
                    records.append({
                        "id": lr["id"],
                        "kind": lr["kind"],
                        "content": lr["content"],
                        "score": 0.01,
                        "rrf": 0.01,
                        "decay": 1.0,
                        "importance": lr["importance"],
                        "confidence": lr["confidence"],
                        "origin": lr["origin"],
                        "agent_id": lr["agent_id"],
                        "created_at": lr["created_at"],
                        "last_confirmed_at": str(lr["last_confirmed_at"] or lr["created_at"] or ""),
                        "expired": False,
                        "status": lr["status"],
                        "scope": lr["scope"],
                        "signed": False,
                        "conflict": False,
                        "suspicious": safety.looks_like_instruction(lr["content"] or ""),
                        "found_by": ["linked_context"],
                        "explain": "linked_context · neighbor record",
                    })

        intent = self.classify_qa_intent(q)
        sufficiency = self.check_qa_sufficiency(q, records)
        if intent["chronological_sort"] and len(records) > 1:
            records.sort(key=lambda r: str(r.get("created_at") or ""))

        ollama_info = self.ollama_models()
        chosen_model = str(
            model if model is not None else (config.ASK_MODEL or (ollama_info["models"][0] if ollama_info["models"] else ""))
        ).strip()

        if not records:
            return {
                "question": q,
                "answer": None,
                "mode": "empty",
                "insufficient_evidence": True,
                "ollama_available": bool(ollama_info["available"]),
                "model": chosen_model or None,
                "records": [],
                "intent": intent,
                "sufficiency": sufficiency,
            }

        if not sufficiency["sufficient"]:
            is_ru = bool(re.search(r"[А-Яа-яЁё]", q))
            abstention_msg = (
                "В сохранённой памяти недостаточно данных для ответа на этот вопрос (указанные факты или сущности не найдены)."
                if is_ru
                else "The stored memory does not contain enough information to answer this question (the requested facts or entities were not found)."
            )
            return {
                "question": q,
                "answer": abstention_msg,
                "mode": "abstention",
                "insufficient_evidence": True,
                "ollama_available": bool(ollama_info["available"]),
                "model": chosen_model or None,
                "records": records,
                "intent": intent,
                "sufficiency": sufficiency,
            }

        if ollama_info["available"] and chosen_model and not chosen_model.lower().endswith("-cloud"):
            base_url = ollama_info["url"]
            parsed = urlsplit(base_url)
            host = (parsed.hostname or "").lower()
            if host in ("127.0.0.1", "localhost", "::1") or host.startswith("127."):
                prompt_text = self.build_qa_prompt(q, records, fenced=True)
                max_threads = max(1, (_os.cpu_count() or 4) // 2)
                try:
                    req_body = json.dumps({
                        "model": chosen_model,
                        "prompt": prompt_text,
                        "stream": False,
                        "options": {
                            "num_thread": max_threads,
                            "temperature": 0.1,
                        },
                    }).encode("utf-8")
                    req = urllib.request.Request(
                        f"{base_url}/api/generate",
                        data=req_body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=25.0) as r:
                        resp_data = json.loads(r.read().decode("utf-8", "replace"))
                    ans = str(resp_data.get("response") or "").strip()
                    if ans:
                        return {
                            "question": q,
                            "answer": ans,
                            "mode": "ollama",
                            "insufficient_evidence": False,
                            "ollama_available": True,
                            "model": chosen_model,
                            "records": records,
                            "intent": intent,
                            "sufficiency": sufficiency,
                        }
                except Exception:
                    pass

        return {
            "question": q,
            "answer": None,
            "mode": "search_explain",
            "insufficient_evidence": False,
            "ollama_available": bool(ollama_info["available"]),
            "model": chosen_model or None,
            "records": records,
            "intent": intent,
            "sufficiency": sufficiency,
        }

    def entities_catalog(self, scope: str | None = None, query: str | None = None,
                         limit: int = 100, actor: roles.ActorContext | None = None) -> dict:
        """Г11: Экран «Сущности» — кто и что встречается в памяти (имена, проекты, сервисы, субъекты фактов)
        и все активные записи о каждом, поверх наших записей без внешней графовой БД.
        """
        vis_sql, vis_params, _ = roles.visibility_sql(actor)
        sql = f"""SELECT id, kind, scope, content, status, origin, agent_id, confidence, importance,
                        created_at, last_seen_at, last_confirmed_at, факт_ключ, visibility, workspace_id
                 FROM memory WHERE user_id = ? AND status = 'active'{vis_sql}"""
        params: list = [self.user_id, *vis_params]
        if scope:
            sql += " AND scope = ?"
            params.append(scope)
        sql += " ORDER BY created_at DESC, rowid DESC"
        rows = self.store.query(sql, tuple(params))

        skip_words = {
            "предпочитаю", "используем", "использовать", "сервер", "система", "запись", "память",
            "нужно", "всегда", "никогда", "после", "перед", "когда", "если", "только", "ответы",
            "always", "never", "prefer", "server", "system", "memory", "record", "using", "project",
            "please", "ignore", "previous", "instructions", "пользователь", "владелец", "агент",
            "redacted", "ии-агентов", "ии-агента", "ии-агенты", "v1", "v2", "v3", "орбита",
        }
        proper_re = re.compile(r"(?<!^)\b([A-ZА-ЯЁ][a-zа-яёA-ZА-ЯЁ0-9_-]{2,}(?:\s+[A-ZА-ЯЁ][a-zа-яёA-ZА-ЯЁ0-9_-]{2,})?)\b")
        tech_re = re.compile(r"\b([A-Z]{2,}[A-Z0-9_-]*|[A-Za-z]+(?:SQL|DB|API|GPU|CPU|CLI|MCP|SDK|LLM|UI|OS)|[a-z]+\d[\w.-]*)\b")

        buckets: dict[str, dict] = {}

        def _add_entity(raw_name: str, category: str, rec_dict: dict) -> None:
            clean = raw_name.strip(" .,;:!?'\"«»()[]{}-—")
            if len(clean) < 2 or len(clean) > 64:
                return
            low = clean.lower()
            if low in skip_words or low.isdigit():
                return
            if re.match(r"^\d{4}-\d{2}-\d{2}$", low):
                return
            b = buckets.get(low)
            if b is None:
                b = {
                    "key": low,
                    "name": clean,
                    "category": category,
                    "count": 0,
                    "kinds": set(),
                    "last_seen": rec_dict.get("created_at") or "",
                    "records": [],
                    "_seen_ids": set(),
                }
                buckets[low] = b
            elif clean[0].isupper() and not b["name"][0].isupper():
                b["name"] = clean
            if rec_dict["id"] not in b["_seen_ids"]:
                b["_seen_ids"].add(rec_dict["id"])
                b["count"] += 1
                b["kinds"].add(rec_dict.get("kind") or "fact")
                if (rec_dict.get("created_at") or "") > b["last_seen"]:
                    b["last_seen"] = rec_dict.get("created_at") or ""
                b["records"].append(rec_dict)

        for r in rows:
            d = dict(r)
            fk = d.pop("факт_ключ", None)
            try:
                d["decay"] = round(decay(d["kind"], parse_ts(d["last_confirmed_at"] or d["created_at"])), 4)
            except Exception:
                d["decay"] = 1.0
            content = d.get("content") or ""

            if fk:
                subj = re.sub(r"^\[|\]$", "", str(fk)).strip(" —-:=.")
                subj = re.sub(r"\s+(это|равен|работает|использует|выполняется|хранится|is|equals)$", "", subj, flags=re.I).strip()
                if len(subj) >= 2:
                    _add_entity(subj, "subject", d)

            for m in tech_re.finditer(content):
                _add_entity(m.group(1), "service", d)

            for m in proper_re.finditer(content):
                _add_entity(m.group(1), "name", d)

        q_low = (query or "").strip().lower()
        items = []
        for b in buckets.values():
            if q_low and q_low not in b["key"] and q_low not in b["name"].lower():
                continue
            items.append({
                "key": b["key"],
                "name": b["name"],
                "category": b["category"],
                "count": b["count"],
                "kinds": sorted(b["kinds"]),
                "last_seen": b["last_seen"],
                "records": b["records"],
            })

        items.sort(key=lambda x: (-x["count"], x["name"].lower()))
        max_lim = max(1, min(int(limit), 300))
        return {
            "total": len(items),
            "entities": items[:max_lim],
        }

    # -- В1: команды, роли и видимость ----------------------------------

    def has_team_members(self) -> bool:
        row = self.store.one(
            """SELECT 1 FROM workspace_member m
               JOIN workspace w ON w.id = m.workspace_id
               WHERE w.owner_user_id = ? AND m.revoked_at IS NULL LIMIT 1""",
            (self.user_id,))
        return row is not None

    def create_workspace(self, name: str, workspace_id: str | None = None,
                         *, actor: roles.ActorContext | None = None) -> dict:
        roles.require_owner(actor, "create_workspace")
        clean_name = str(name or "").strip()[:80]
        if not clean_name:
            raise ValueError(t("название команды обязательно", "workspace name is required"))
        wid = (str(workspace_id).strip()[:64] if workspace_id else "") or f"ws_{new_id()[:8]}"
        ts = now_iso()
        self.store.execute(
            "INSERT INTO workspace (id, name, owner_user_id, created_at) VALUES (?,?,?,?)",
            (wid, clean_name, self.user_id, ts))
        self._log_audit("workspace_create", wid, actor="owner", outcome="ok", detail=clean_name)
        return {"id": wid, "name": clean_name, "owner_user_id": self.user_id, "created_at": ts}

    def list_workspaces(self, *, actor: roles.ActorContext | None = None) -> list[dict]:
        if roles.is_owner(actor):
            rows = self.store.query(
                "SELECT id, name, owner_user_id, created_at FROM workspace WHERE owner_user_id = ? ORDER BY created_at DESC",
                (self.user_id,))
        elif actor is not None and actor.workspace_id:
            rows = self.store.query(
                "SELECT id, name, owner_user_id, created_at FROM workspace WHERE id = ? AND owner_user_id = ?",
                (actor.workspace_id, self.user_id))
        else:
            rows = []
        return [dict(r) for r in rows]

    def add_member(self, workspace_id: str, subject: str, role: str,
                   *, actor: roles.ActorContext | None = None) -> dict:
        import secrets as _secrets
        roles.require_owner(actor, "add_member")
        clean_subj = str(subject or "").strip()[:64]
        if not clean_subj:
            raise ValueError(t("имя участника обязательно", "subject is required"))
        if role not in roles.MEMBER_ROLES:
            raise ValueError(t(f"роль должна быть одной из {roles.MEMBER_ROLES}",
                               f"role must be one of {roles.MEMBER_ROLES}"))
        ws = self.store.one(
            "SELECT id, name FROM workspace WHERE id = ? AND owner_user_id = ?",
            (workspace_id, self.user_id))
        if not ws:
            raise ValueError(t("команда не найдена", "workspace not found"))
        raw_token = f"padam_tm_{_secrets.token_urlsafe(24)}"
        token_hash, token_salt, token_prefix = roles.hash_token(raw_token)
        ts = now_iso()
        self.store.execute(
            """INSERT INTO workspace_member
               (workspace_id, subject, role, token_hash, token_salt, token_prefix, created_at, revoked_at)
               VALUES (?,?,?,?,?,?,?,NULL)
               ON CONFLICT(workspace_id, subject) DO UPDATE SET
                   role = excluded.role,
                   token_hash = excluded.token_hash,
                   token_salt = excluded.token_salt,
                   token_prefix = excluded.token_prefix,
                   created_at = excluded.created_at,
                   revoked_at = NULL""",
            (workspace_id, clean_subj, role, token_hash, token_salt, token_prefix, ts))
        self._log_audit("member_add", workspace_id, actor="owner", agent_id=clean_subj,
                        outcome=role, detail=token_prefix)
        return {
            "workspace_id": workspace_id,
            "subject": clean_subj,
            "role": role,
            "token": raw_token,
            "token_prefix": token_prefix,
            "created_at": ts,
        }

    def list_members(self, workspace_id: str | None = None,
                     *, actor: roles.ActorContext | None = None) -> list[dict]:
        if actor is not None and not actor.is_owner:
            if not actor.workspace_id:
                return []
            workspace_id = actor.workspace_id
        sql = """SELECT m.workspace_id, w.name AS workspace_name, m.subject, m.role,
                        m.token_prefix, m.created_at, m.revoked_at
                 FROM workspace_member m
                 JOIN workspace w ON w.id = m.workspace_id
                 WHERE w.owner_user_id = ?"""
        params: list = [self.user_id]
        if workspace_id:
            sql += " AND m.workspace_id = ?"
            params.append(workspace_id)
        sql += " ORDER BY m.created_at DESC"
        return [dict(r) for r in self.store.query(sql, tuple(params))]

    def revoke_member(self, workspace_id: str, subject: str,
                      *, actor: roles.ActorContext | None = None) -> bool:
        roles.require_owner(actor, "revoke_member")
        cur = self.store.execute(
            """UPDATE workspace_member SET revoked_at = ?
               WHERE workspace_id = ? AND subject = ? AND revoked_at IS NULL
                 AND EXISTS (SELECT 1 FROM workspace w WHERE w.id = ? AND w.owner_user_id = ?)""",
            (now_iso(), workspace_id, subject, workspace_id, self.user_id))
        ok = cur.rowcount > 0
        if ok:
            self._log_audit("member_revoke", workspace_id, actor="owner", agent_id=subject, outcome="revoked")
        return ok

    def authenticate_token(self, raw_token: str) -> roles.ActorContext | None:
        tok = (raw_token or "").strip()
        if not tok:
            return None
        prefix = tok[:10]
        rows = self.store.query(
            """SELECT m.workspace_id, m.subject, m.role, m.token_hash, m.token_salt
               FROM workspace_member m
               JOIN workspace w ON w.id = m.workspace_id
               WHERE w.owner_user_id = ? AND m.revoked_at IS NULL AND m.token_prefix = ?""",
            (self.user_id, prefix))
        for r in rows:
            if roles.verify_token(tok, r["token_hash"], r["token_salt"]):
                return roles.ActorContext(
                    role=r["role"], subject=r["subject"],
                    workspace_id=r["workspace_id"], via_token=True)
        return None

    def set_visibility(self, memory_id: str, visibility: str, workspace_id: str | None = None,
                       *, actor: roles.ActorContext | None = None) -> dict:
        roles.require_owner(actor, "set_visibility")
        if visibility not in roles.VISIBILITIES:
            raise ValueError(t(f"неизвестная видимость: {visibility}", f"unknown visibility: {visibility}"))
        row = self.store.one(
            "SELECT id, kind, content, scope, status FROM memory WHERE id = ? AND user_id = ?",
            (memory_id, self.user_id))
        if not row:
            raise ValueError(t("запись не найдена", "record not found"))
        if visibility in roles.TEAM_VISIBILITIES:
            вид_по_тексту = classify.infer_kind_rules(row["content"] or "")
            if row["kind"] in config.PROTECTED_KINDS or вид_по_тексту in config.PROTECTED_KINDS:
                raise PermissionError(t(
                    "записи identity и preference нельзя открывать команде",
                    "identity and preference records cannot be shared with a team",
                ))
            if not workspace_id:
                wss = self.list_workspaces()
                if len(wss) == 1:
                    workspace_id = wss[0]["id"]
                else:
                    raise ValueError(t("укажите workspace_id", "workspace_id is required"))
            ws = self.store.one(
                "SELECT id FROM workspace WHERE id = ? AND owner_user_id = ?",
                (workspace_id, self.user_id))
            if not ws:
                raise ValueError(t("команда не найдена", "workspace not found"))
        else:
            workspace_id = None
        self.store.execute(
            "UPDATE memory SET visibility = ?, workspace_id = ? WHERE id = ? AND user_id = ?",
            (visibility, workspace_id, memory_id, self.user_id))
        self.__dict__.pop("_вкэш", None)
        self.__dict__.pop("_ккэш", None)
        self._log_audit("visibility", memory_id, actor="owner", outcome=visibility, detail=workspace_id)
        return {"ok": True, "id": memory_id, "visibility": visibility, "workspace_id": workspace_id}
