"""Роли, рабочие пространства и разграничение доступа PADAM.

По умолчанию память однопользовательская: каждая запись имеет visibility = 'private'
и принадлежит владельцу без проверки командных таблиц. Когда владелец создаёт
команду (workspace) и выписывает солёные токены участникам, каждый запрос или вызов
получает ActorContext, а кэши поиска, SQL-фильтры и операции записи строго изолируются.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from . import config
from .i18n import t

ROLES = ("owner", "maintainer", "contributor", "auditor")
MEMBER_ROLES = ("maintainer", "contributor", "auditor")
VISIBILITIES = ("private", "team_read", "team_write")
TEAM_VISIBILITIES = ("team_read", "team_write")


@dataclass(frozen=True)
class ActorContext:
    """Проверенный субъект запроса (роль определяется исключительно по токену)."""

    role: str = "owner"
    subject: str = "owner"
    workspace_id: str | None = None
    via_token: bool = True

    @property
    def is_owner(self) -> bool:
        return self.role == "owner"

    @property
    def cache_key(self) -> tuple:
        if self.is_owner:
            return ("owner", None)
        return (self.role, self.workspace_id)


OWNER_ACTOR = ActorContext(role="owner", subject="owner", workspace_id=None, via_token=True)


def hash_token(raw_token: str, salt: str | None = None) -> tuple[str, str, str]:
    """Вернуть (sha256_hex, salt_hex, prefix) для солёного хранения токена."""
    used_salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256(f"{used_salt}:{raw_token}".encode("utf-8")).hexdigest()
    return digest, used_salt, raw_token[:10]


def verify_token(raw_token: str, token_hash: str, salt: str) -> bool:
    """Сверка токена с солёным SHA-256 за постоянное время."""
    if not raw_token or not token_hash or not salt:
        return False
    digest = hashlib.sha256(f"{salt}:{raw_token}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest.encode("ascii"), token_hash.encode("ascii"))


def is_owner(actor: ActorContext | None) -> bool:
    return actor is None or actor.role == "owner"


def visibility_sql(actor: ActorContext | None, alias: str = "") -> tuple[str, tuple, tuple]:
    """SQL-условие фильтра видимости, параметры и ключ изоляции кэша."""
    if is_owner(actor):
        return "", (), ("owner", None)
    assert actor is not None
    p = f"{alias}." if alias else ""
    if actor.role in ("maintainer", "contributor", "auditor") and actor.workspace_id:
        sql = (
            f" AND {p}visibility IN ('team_read', 'team_write')"
            f" AND {p}workspace_id = ?"
            f" AND {p}kind NOT IN ('identity', 'preference')"
        )
        return sql, (actor.workspace_id,), (actor.role, actor.workspace_id)
    return " AND 1 = 0", (), (actor.role, None)


def check_write(actor: ActorContext | None, kind: str | None, visibility: str | None) -> str:
    """Проверить право записи и вернуть нормализованный visibility."""
    if actor is not None and actor.role not in ROLES:
        raise PermissionError(t("недостаточно прав для записи", "insufficient permissions to write"))
    if actor is not None and actor.role == "auditor":
        raise PermissionError(t("роль auditor может только читать и просматривать аудит",
                                "auditor role is read-only"))
    vis = visibility
    if vis is None:
        vis = "private" if is_owner(actor) else "team_write"
    if vis not in VISIBILITIES:
        raise ValueError(t(f"неизвестная видимость: {vis}", f"unknown visibility: {vis}"))
    if kind in config.PROTECTED_KINDS and vis in TEAM_VISIBILITIES:
        raise PermissionError(t(
            "записи identity и preference нельзя открывать команде (всегда private)",
            "identity and preference records cannot be shared with a team (always private)",
        ))
    if not is_owner(actor) and vis == "private":
        raise PermissionError(t(
            "участник команды не может писать в private-область владельца",
            "team member cannot write to owner private scope",
        ))
    return vis


def require_owner(actor: ActorContext | None, action: str) -> None:
    if not is_owner(actor):
        raise PermissionError(t(
            f"действие «{action}» доступно только владельцу (owner)",
            f"action '{action}' requires the owner role",
        ))


def require_moderate(actor: ActorContext | None) -> None:
    if is_owner(actor):
        return
    assert actor is not None
    if actor.role != "maintainer":
        raise PermissionError(t(
            "утверждать и отклонять командные записи могут только owner и maintainer",
            "only owner and maintainer can approve or reject team records",
        ))


def require_audit_read(actor: ActorContext | None) -> None:
    if is_owner(actor):
        return
    assert actor is not None
    if actor.role not in ("maintainer", "auditor"):
        raise PermissionError(t(
            "журнал аудита доступен только owner, maintainer и auditor",
            "audit log is restricted to owner, maintainer and auditor",
        ))
