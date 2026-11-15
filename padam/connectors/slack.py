"""Коннектор Slack: чтение сообщений каналов только на чтение."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from ..i18n import t
from .base import (
    BaseConnector,
    ConnectorError,
    ConnectorItem,
    HttpCallable,
    RateLimitError,
    RateLimiter,
    TokenRevokedError,
)

SLACK_AUTH_ERRORS = {
    "invalid_auth",
    "token_revoked",
    "account_inactive",
    "not_authed",
    "missing_scope",
    "token_expired",
}


def _ts_to_iso(ts: str | None) -> str | None:
    if not ts:
        return None
    try:
        sec = float(str(ts))
        return datetime.fromtimestamp(sec, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return None


class SlackConnector(BaseConnector):
    provider = "slack"

    def _check_slack_ok(self, data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise ConnectorError("Slack response must be a JSON object")
        if data.get("ok") is True:
            return data
        err = str(data.get("error") or "unknown_error")
        if err in SLACK_AUTH_ERRORS:
            raise TokenRevokedError(t(
                f"Slack отклонил токен ({err}): обновите или переподключите токен в Настройках",
                f"Slack rejected token ({err}): update or reconnect token in Settings",
            ))
        if err == "ratelimited":
            raise RateLimitError(t(
                "превышен лимит запросов Slack API",
                "Slack API rate limit exceeded",
            ))
        raise ConnectorError(f"Slack API error: {err}")

    def fetch_items(
        self,
        token: str,
        cfg: dict[str, Any],
        http_call: HttpCallable,
        limiter: RateLimiter,
    ) -> tuple[list[ConnectorItem], str | None]:
        api_base = str(cfg.get("api_base") or "https://slack.com/api").rstrip("/")
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "padam-nocturne-connector/1",
        }
        channel = str(cfg.get("channel") or "").strip()
        if not channel:
            list_url = f"{api_base}/conversations.list?types=public_channel,private_channel&limit=10"
            cdata, _ = self._call_json("GET", list_url, headers, http_call, limiter)
            cdata = self._check_slack_ok(cdata)
            channels = cdata.get("channels") or []
            if not channels or not isinstance(channels[0], dict) or not channels[0].get("id"):
                raise ConnectorError(t(
                    "в Slack не указан channel и не найдены доступные каналы",
                    "no Slack channel configured and no accessible channels found",
                ))
            channel = str(channels[0]["id"])

        cursor = cfg.get("cursor")
        hist_url = f"{api_base}/conversations.history?channel={quote(channel)}&limit=50"
        if cursor:
            hist_url += f"&oldest={quote(str(cursor))}"

        hdata, _ = self._call_json("GET", hist_url, headers, http_call, limiter)
        hdata = self._check_slack_ok(hdata)
        messages = hdata.get("messages") or []
        if not isinstance(messages, list):
            raise ConnectorError("Slack messages field must be a list")

        newest: str | None = str(cursor) if cursor else None
        items: list[ConnectorItem] = []

        for msg in messages:
            if not isinstance(msg, dict):
                continue
            ts = str(msg.get("ts") or "")
            if not ts:
                continue
            if cursor and ts <= str(cursor):
                continue
            if not newest or ts > newest:
                newest = ts

            text = str(msg.get("text") or "").strip()
            if not text:
                continue
            author = str(msg.get("user") or msg.get("username") or "user")
            items.append(ConnectorItem(
                external_id=f"slack:{channel}:{ts}",
                title=f"#{channel} ({author})",
                body=text[:6000],
                scope=str(cfg.get("scope") or f"slack:{channel}"),
                updated_at=_ts_to_iso(ts),
            ))
        return items, newest
