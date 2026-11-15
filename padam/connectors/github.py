"""Коннектор GitHub: загрузка issues и pull requests в очередь внешней проверки."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote

from .base import BaseConnector, ConnectorError, ConnectorItem, HttpCallable, RateLimiter


class GitHubConnector(BaseConnector):
    provider = "github"

    def fetch_items(
        self,
        token: str,
        cfg: dict[str, Any],
        http_call: HttpCallable,
        limiter: RateLimiter,
    ) -> tuple[list[ConnectorItem], str | None]:
        repo = str(cfg.get("repo") or "").strip().strip("/")
        api_base = str(cfg.get("api_base") or "https://api.github.com").rstrip("/")
        if repo and "/" in repo:
            owner, name = repo.split("/", 1)
            url = f"{api_base}/repos/{quote(owner)}/{quote(name)}/issues?state=all&per_page=30&sort=updated"
        else:
            url = f"{api_base}/issues?filter=all&state=all&per_page=30"
        cursor = cfg.get("cursor")
        if cursor:
            url += f"&since={quote(str(cursor))}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "padam-nocturne-connector/1",
        }
        data, _ = self._call_json("GET", url, headers, http_call, limiter)
        if not isinstance(data, list):
            raise ConnectorError("GitHub response is not a list of issues")

        items: list[ConnectorItem] = []
        newest: str | None = cursor
        for entry in data:
            if not isinstance(entry, dict):
                continue
            num = entry.get("number")
            ext_id = f"gh:{entry.get('id') or num}"
            kind_label = "PR" if entry.get("pull_request") else "Issue"
            title = f"{kind_label} #{num}: {entry.get('title') or '(untitled)'}"
            state = entry.get("state") or "open"
            body_text = (entry.get("body") or "").strip()
            body = f"State: {state}\n{body_text}".strip()
            updated = entry.get("updated_at") or entry.get("created_at")
            if updated and (not newest or str(updated) > str(newest)):
                newest = str(updated)
            items.append(ConnectorItem(
                external_id=ext_id,
                title=title,
                body=body[:6000],
                url=str(entry.get("html_url") or ""),
                scope=str(cfg.get("scope") or f"github:{repo or 'inbox'}"),
                updated_at=str(updated) if updated else None,
            ))

        # Загрузка README репозитория (404 игнорируется, 401/403 обрабатывается)
        if repo and "/" in repo and cfg.get("include_readme", True):
            owner, name = repo.split("/", 1)
            rd_url = f"{api_base}/repos/{quote(owner)}/{quote(name)}/readme"
            limiter.wait()
            st, _, raw = http_call("GET", rd_url, headers, None, 10.0)
            if st == 200:
                try:
                    rd_obj = json.loads(raw.decode("utf-8"))
                    enc = str(rd_obj.get("encoding") or "")
                    content_b64 = str(rd_obj.get("content") or "")
                    if enc == "base64" and content_b64:
                        rd_text = base64.b64decode(content_b64.encode("ascii")).decode("utf-8", errors="replace").strip()
                    else:
                        rd_text = content_b64.strip()
                    if rd_text:
                        items.append(ConnectorItem(
                            external_id=f"gh:readme:{repo}",
                            title=f"README ({repo})",
                            body=rd_text[:6000],
                            url=str(rd_obj.get("html_url") or ""),
                            scope=str(cfg.get("scope") or f"github:{repo}"),
                        ))
                except Exception:
                    pass
        return items, newest
