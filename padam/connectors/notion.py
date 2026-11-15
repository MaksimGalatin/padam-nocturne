"""Коннектор Notion: чтение страниц и баз данных в очередь внешней проверки."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .base import BaseConnector, ConnectorError, ConnectorItem, HttpCallable, RateLimiter


def _extract_notion_title(page: dict[str, Any]) -> str:
    props = page.get("properties")
    if isinstance(props, dict):
        for prop in props.values():
            if not isinstance(prop, dict):
                continue
            if prop.get("type") == "title" and isinstance(prop.get("title"), list):
                text = "".join(str(x.get("plain_text") or "") for x in prop["title"] if isinstance(x, dict)).strip()
                if text:
                    return text
    if isinstance(page.get("title"), list):
        text = "".join(str(x.get("plain_text") or "") for x in page["title"] if isinstance(x, dict)).strip()
        if text:
            return text
    return str(page.get("id") or "Untitled page")


def _extract_notion_props_text(page: dict[str, Any]) -> str:
    lines: list[str] = []
    props = page.get("properties")
    if isinstance(props, dict):
        for name, prop in props.items():
            if not isinstance(prop, dict):
                continue
            ptype = prop.get("type")
            if ptype == "rich_text" and isinstance(prop.get("rich_text"), list):
                val = "".join(str(x.get("plain_text") or "") for x in prop["rich_text"] if isinstance(x, dict)).strip()
                if val:
                    lines.append(f"{name}: {val}")
            elif ptype == "select" and isinstance(prop.get("select"), dict):
                val = str(prop["select"].get("name") or "").strip()
                if val:
                    lines.append(f"{name}: {val}")
            elif ptype == "status" and isinstance(prop.get("status"), dict):
                val = str(prop["status"].get("name") or "").strip()
                if val:
                    lines.append(f"{name}: {val}")
            elif ptype == "url" and prop.get("url"):
                lines.append(f"{name}: {prop['url']}")
    return "\n".join(lines)


class NotionConnector(BaseConnector):
    provider = "notion"

    def fetch_items(
        self,
        token: str,
        cfg: dict[str, Any],
        http_call: HttpCallable,
        limiter: RateLimiter,
    ) -> tuple[list[ConnectorItem], str | None]:
        api_base = str(cfg.get("api_base") or "https://api.notion.com/v1").rstrip("/")
        database_id = str(cfg.get("database_id") or "").strip()
        headers = {
            "Authorization": f"Bearer {token}",
            "Notion-Version": "2022-06-28",
            "Content-Type": "application/json",
            "User-Agent": "padam-nocturne-connector/1",
        }
        if database_id:
            url = f"{api_base}/databases/{quote(database_id)}/query"
            body: dict[str, Any] = {
                "page_size": 30,
                "sorts": [{"timestamp": "last_edited_time", "direction": "descending"}],
            }
        else:
            url = f"{api_base}/search"
            body = {
                "page_size": 30,
                "sort": {"direction": "descending", "timestamp": "last_edited_time"},
                "filter": {"value": "page", "property": "object"},
            }
            if cfg.get("query"):
                body["query"] = str(cfg["query"])

        data, _ = self._call_json("POST", url, headers, http_call, limiter, body=body)
        if not isinstance(data, dict):
            raise ConnectorError("Notion response must be a JSON object")
        results = data.get("results") or []
        if not isinstance(results, list):
            raise ConnectorError("Notion results field must be a list")

        cursor = cfg.get("cursor")
        newest: str | None = str(cursor) if cursor else None
        items: list[ConnectorItem] = []

        for page in results:
            if not isinstance(page, dict):
                continue
            pid = str(page.get("id") or "")
            if not pid:
                continue
            updated = page.get("last_edited_time") or page.get("created_time")
            if cursor and updated and str(updated) <= str(cursor):
                continue
            if updated and (not newest or str(updated) > newest):
                newest = str(updated)

            title = _extract_notion_title(page)
            parts: list[str] = []
            prop_text = _extract_notion_props_text(page)
            if prop_text:
                parts.append(prop_text)
            if page.get("plain_text"):
                parts.append(str(page["plain_text"]).strip())
            elif cfg.get("fetch_blocks"):
                blk_url = f"{api_base}/blocks/{quote(pid)}/children?page_size=25"
                blk_data, _ = self._call_json("GET", blk_url, headers, http_call, limiter)
                if isinstance(blk_data, dict):
                    for blk in blk_data.get("results") or []:
                        if not isinstance(blk, dict):
                            continue
                        btype = str(blk.get("type") or "")
                        bobj = blk.get(btype)
                        if isinstance(bobj, dict) and isinstance(bobj.get("rich_text"), list):
                            line = "".join(
                                str(x.get("plain_text") or "") for x in bobj["rich_text"] if isinstance(x, dict)
                            ).strip()
                            if line:
                                parts.append(line)

            body_text = "\n".join(parts) if parts else f"Notion page {pid}"
            items.append(ConnectorItem(
                external_id=f"notion:{pid}",
                title=title,
                body=body_text[:6000],
                url=str(page.get("url") or ""),
                scope=str(cfg.get("scope") or f"notion:{database_id or 'workspace'}"),
                updated_at=str(updated) if updated else None,
            ))
        return items, newest
