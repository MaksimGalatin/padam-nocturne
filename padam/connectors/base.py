"""Базовая логика внешних коннекторов (GitHub, Notion, Google Drive, Slack).

Все коннекторы по умолчанию выключены. Токены хранятся только локально
в зашифрованном виде (w1: через keyvault или k1: AES-256-GCM на локальном ключе),
никогда не отдаются обратно через API/UI и не попадают в экспорт памяти.
Любой импортируемый текст проходит исключительно как origin='external', guarded=True
через стандартную ограду, маскировку секретов и очередь проверки владельца.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import integrity, keyvault
from ..i18n import t
from ..store import now_iso


class ConnectorError(Exception):
    """Общая ошибка внешнего коннектора."""


class ConnectorDisabledError(ConnectorError):
    """Коннектор выключен по умолчанию или отключён владельцем."""


class TokenRevokedError(ConnectorError):
    """Токен отсутствует, отозван или отклонён внешним сервисом (401/403)."""


class RateLimitError(ConnectorError):
    """Внешний сервис ограничил частоту запросов."""


@dataclass
class ConnectorItem:
    """Единица данных, полученная из внешнего коннектора."""

    external_id: str
    title: str
    body: str
    url: str = ""
    scope: str = "global"
    kind: str = "fact"
    updated_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def render_text(self, provider: str) -> str:
        header = f"[{provider}] {self.title}".strip()
        parts = [header]
        if self.body and self.body.strip():
            parts.append(self.body.strip())
        if self.url:
            parts.append(f"URL: {self.url}")
        return "\n".join(parts)


HttpCallable = Callable[[str, str, dict[str, str], bytes | None, float], tuple[int, dict[str, str], bytes]]


class RateLimiter:
    """Простой ограничитель частоты HTTP-запросов между вызовами коннектора."""

    def __init__(self, min_interval_s: float = 0.2):
        self.min_interval_s = max(0.0, float(min_interval_s))
        self._last_ts: float = 0.0
        self.calls: int = 0

    def wait(self) -> None:
        now = time.monotonic()
        if self.min_interval_s > 0 and self._last_ts > 0:
            delta = now - self._last_ts
            if delta < self.min_interval_s:
                time.sleep(self.min_interval_s - delta)
        self._last_ts = time.monotonic()
        self.calls += 1


def default_http_call(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    """Безопасный HTTP-запрос без сторонних библиотек с обработкой 4xx/5xx."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_headers, resp.read()
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, resp_headers, e.read()
    except urllib.error.URLError as e:
        raise ConnectorError(t(f"сетевая ошибка при обращении к {url}: {e.reason}",
                               f"network error calling {url}: {e.reason}")) from e


def _local_key(memory) -> bytes:
    raw, _ = integrity.owner_key(memory.store)
    return hashlib.sha256(b"padam-connectors-v1|" + raw).digest()


def encrypt_token(memory, provider: str, raw_token: str) -> str:
    """Шифрует токен коннектора локально перед записью в connector_state."""
    tok = (raw_token or "").strip()
    if not tok:
        raise ValueError(t("пустой токен недопустим", "empty token is not allowed"))
    if keyvault.is_enabled(memory):
        return keyvault.wrap(memory, f"connector:{provider}", tok.encode("utf-8"))
    nonce = secrets.token_bytes(12)
    aad = f"padam-connector|{provider}".encode("utf-8")
    ct = AESGCM(_local_key(memory)).encrypt(nonce, tok.encode("utf-8"), aad)
    return "k1:" + (nonce + ct).hex()


def decrypt_token(memory, provider: str, token_enc: str | None) -> str:
    """Расшифровывает локально сохранённый токен коннектора."""
    if not token_enc:
        raise TokenRevokedError(t(
            f"токен коннектора {provider} не задан в Настройках",
            f"connector {provider} token is not configured in Settings",
        ))
    if token_enc.startswith(keyvault.PREFIX):
        return keyvault.unwrap(memory, f"connector:{provider}", token_enc).decode("utf-8")
    if token_enc.startswith("k1:"):
        blob = bytes.fromhex(token_enc[3:])
        aad = f"padam-connector|{provider}".encode("utf-8")
        try:
            return AESGCM(_local_key(memory)).decrypt(blob[:12], blob[12:], aad).decode("utf-8")
        except InvalidTag as exc:
            raise ConnectorError(t(
                f"повреждён или чужой зашифрованный токен для {provider}",
                f"corrupted encrypted token for {provider}",
            )) from exc
    raise ConnectorError(t(f"неизвестный формат токена {provider}", f"unknown token encoding for {provider}"))


class BaseConnector:
    """Общий каркас внешнего коннектора с дедупликацией и обязательной оградой."""

    provider: str = "base"

    def fetch_items(
        self,
        token: str,
        cfg: dict[str, Any],
        http_call: HttpCallable,
        limiter: RateLimiter,
    ) -> tuple[list[ConnectorItem], str | None]:
        raise NotImplementedError

    def _call_json(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        http_call: HttpCallable,
        limiter: RateLimiter,
        body: dict | None = None,
    ) -> tuple[dict | list, dict[str, str]]:
        limiter.wait()
        raw_body = json.dumps(body).encode("utf-8") if body is not None else None
        status, resp_headers, payload = http_call(method, url, headers, raw_body, 10.0)
        if status in (401, 403):
            raise TokenRevokedError(t(
                f"доступ к {self.provider} отклонён (HTTP {status}): токен отозван, истёк или не хватает прав; обновите его в Настройках",
                f"{self.provider} rejected access (HTTP {status}): token revoked, expired or insufficient scope; update it in Settings",
            ))
        if status == 429:
            retry_after = resp_headers.get("retry-after", "60")
            raise RateLimitError(t(
                f"превышен лимит запросов {self.provider} (повтор через {retry_after} с)",
                f"{self.provider} rate limit exceeded (retry after {retry_after}s)",
            ))
        if status >= 400:
            snippet = payload.decode("utf-8", errors="replace")[:200]
            raise ConnectorError(f"{self.provider} HTTP {status}: {snippet}")
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except Exception as exc:
            raise ConnectorError(f"{self.provider}: invalid JSON response ({exc})") from exc
        if resp_headers.get("x-ratelimit-remaining") == "0":
            # Предупредительная пауза, чтобы не получить 429 на следующем шаге.
            limiter.wait()
        return parsed, resp_headers

    def sync(
        self,
        memory,
        *,
        http_call: HttpCallable | None = None,
        rate_limit_s: float = 0.2,
        cancel_event=None,
        progress_cb=None,
    ) -> dict[str, Any]:
        """Синхронизация одного коннектора: проверяет флаг включения, расшифровывает токен и пропускает всё через ограду."""
        row = memory.store.one(
            "SELECT * FROM connector_state WHERE provider = ? AND user_id = ?",
            (self.provider, memory.user_id),
        )
        if not row or not row["enabled"]:
            raise ConnectorDisabledError(t(
                f"коннектор {self.provider} выключен по умолчанию (включите в Настройках)",
                f"connector {self.provider} is disabled by default (enable it in Settings)",
            ))

        prev_state = dict(row)
        cfg = json.loads(row["config_json"] or "{}")
        cfg.setdefault("cursor", row["cursor"])
        limiter = RateLimiter(min_interval_s=rate_limit_s)
        transport = http_call or default_http_call

        created_memory_ids: list[str] = []
        rollback_items: list[tuple[str, dict | None]] = []

        def _rollback_import() -> None:
            for mid in reversed(created_memory_ids):
                memory.store.execute(
                    "UPDATE memory SET status = 'active', superseded_by = NULL WHERE superseded_by = ?",
                    (mid,),
                )
                memory.store.execute("DELETE FROM anchor_key WHERE memory_id = ?", (mid,))
                memory.store.execute("DELETE FROM memory_link WHERE src = ? OR dst = ?", (mid, mid))
                memory.store.execute("DELETE FROM memory WHERE id = ? AND user_id = ?", (mid, memory.user_id))
            for ext_id, old_ci in reversed(rollback_items):
                if old_ci is None:
                    memory.store.execute(
                        "DELETE FROM connector_item WHERE user_id = ? AND provider = ? AND external_id = ?",
                        (memory.user_id, self.provider, ext_id),
                    )
                else:
                    memory.store.execute(
                        """INSERT OR REPLACE INTO connector_item
                           (user_id, provider, external_id, memory_id, content_hash, synced_at)
                           VALUES (?,?,?,?,?,?)""",
                        (
                            old_ci["user_id"],
                            old_ci["provider"],
                            old_ci["external_id"],
                            old_ci["memory_id"],
                            old_ci["content_hash"],
                            old_ci["synced_at"],
                        ),
                    )
            memory.store.execute(
                """UPDATE connector_state
                   SET cursor = ?, last_sync_at = ?, last_status = ?, last_error = ?, imported_count = ?
                   WHERE provider = ? AND user_id = ?""",
                (
                    prev_state.get("cursor"),
                    prev_state.get("last_sync_at"),
                    prev_state.get("last_status"),
                    prev_state.get("last_error"),
                    prev_state.get("imported_count", 0),
                    self.provider,
                    memory.user_id,
                ),
            )
            memory.__dict__.pop("_ккэш", None)

        try:
            token = decrypt_token(memory, self.provider, row["token_enc"])
            items, next_cursor = self.fetch_items(token, cfg, transport, limiter)
            total_items = len(items)
            if progress_cb is not None:
                progress_cb(0, total_items, f"fetched {total_items}")
            imported = 0
            quarantined = 0
            skipped = 0
            scope = str(cfg.get("scope") or f"connector:{self.provider}")

            for idx, item in enumerate(items):
                if cancel_event is not None and cancel_event.is_set():
                    _rollback_import()
                    memory._log_audit(
                        "connector_sync", self.provider, actor="connector", agent_id=self.provider,
                        scope=scope, outcome="cancelled", detail="rolled back on task cancellation",
                    )
                    return {
                        "ok": False,
                        "cancelled": True,
                        "rolled_back": True,
                        "provider": self.provider,
                        "fetched": total_items,
                        "imported": 0,
                        "quarantined": 0,
                        "skipped": 0,
                    }

                full_text = item.render_text(self.provider)
                chash = hashlib.sha256(full_text.encode("utf-8")).hexdigest()
                prev = memory.store.one(
                    """SELECT user_id, provider, external_id, memory_id, content_hash, synced_at
                       FROM connector_item
                       WHERE user_id = ? AND provider = ? AND external_id = ?""",
                    (memory.user_id, self.provider, item.external_id),
                )
                if prev and prev["content_hash"] == chash:
                    skipped += 1
                    if progress_cb is not None:
                        progress_cb(idx + 1, total_items, item.external_id)
                    continue

                rollback_items.append((item.external_id, dict(prev) if prev else None))
                outcome, mid = memory.remember(
                    full_text,
                    kind=item.kind,
                    scope=item.scope or scope,
                    origin="external",
                    guarded=True,
                    agent_id=f"connector:{self.provider}",
                    valid_from=item.updated_at,
                )
                if outcome != "duplicate":
                    created_memory_ids.append(mid)
                ts_now = now_iso()
                memory.store.execute(
                    """INSERT INTO connector_item (user_id, provider, external_id, memory_id, content_hash, synced_at)
                       VALUES (?,?,?,?,?,?)
                       ON CONFLICT(user_id, provider, external_id) DO UPDATE SET
                           memory_id = excluded.memory_id,
                           content_hash = excluded.content_hash,
                           synced_at = excluded.synced_at""",
                    (memory.user_id, self.provider, item.external_id, mid, chash, ts_now),
                )
                imported += 1
                if outcome == "quarantined":
                    quarantined += 1
                if progress_cb is not None:
                    progress_cb(idx + 1, total_items, item.external_id)

            ts_done = now_iso()
            memory.store.execute(
                """UPDATE connector_state
                   SET cursor = COALESCE(?, cursor),
                       last_sync_at = ?,
                       last_status = 'ok',
                       last_error = NULL,
                       imported_count = imported_count + ?
                   WHERE provider = ? AND user_id = ?""",
                (next_cursor, ts_done, imported, self.provider, memory.user_id),
            )
            memory._log_audit(
                "connector_sync", self.provider, actor="connector", agent_id=self.provider,
                scope=scope, outcome="ok",
                detail=f"fetched={len(items)} imported={imported} quarantined={quarantined} skipped={skipped}",
            )
            return {
                "ok": True,
                "provider": self.provider,
                "fetched": len(items),
                "imported": imported,
                "quarantined": quarantined,
                "skipped": skipped,
                "http_calls": limiter.calls,
                "synced_at": ts_done,
            }
        except ConnectorError as exc:
            memory.store.execute(
                """UPDATE connector_state
                   SET last_sync_at = ?, last_status = 'error', last_error = ?
                   WHERE provider = ? AND user_id = ?""",
                (now_iso(), str(exc)[:300], self.provider, memory.user_id),
            )
            memory._log_audit(
                "connector_sync", self.provider, actor="connector", agent_id=self.provider,
                outcome="error", detail=str(exc)[:200],
            )
            raise
