"""Коннектор Google Drive: чтение документов и текстовых файлов только на чтение."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .base import (
    BaseConnector,
    ConnectorError,
    ConnectorItem,
    HttpCallable,
    RateLimitError,
    RateLimiter,
    TokenRevokedError,
)

MAX_FILE_BYTES = 1_000_000
TEXT_MIMES = {
    "text/plain",
    "text/markdown",
    "text/csv",
    "application/json",
}
GOOGLE_DOC_MIME = "application/vnd.google-apps.document"


class GoogleDriveConnector(BaseConnector):
    provider = "gdrive"

    def _download_text(
        self,
        url: str,
        headers: dict[str, str],
        http_call: HttpCallable,
        limiter: RateLimiter,
    ) -> str:
        limiter.wait()
        status, resp_headers, payload = http_call("GET", url, headers, None, 10.0)
        if status in (401, 403):
            raise TokenRevokedError("gdrive access rejected (HTTP %s)" % status)
        if status == 429:
            retry_after = resp_headers.get("retry-after", "60")
            raise RateLimitError(f"gdrive rate limit exceeded (retry after {retry_after}s)")
        if status >= 400:
            raise ConnectorError(f"gdrive download HTTP {status}")
        return payload[:MAX_FILE_BYTES].decode("utf-8", errors="replace").strip()

    def fetch_items(
        self,
        token: str,
        cfg: dict[str, Any],
        http_call: HttpCallable,
        limiter: RateLimiter,
    ) -> tuple[list[ConnectorItem], str | None]:
        api_base = str(cfg.get("api_base") or "https://www.googleapis.com/drive/v3").rstrip("/")
        folder_id = str(cfg.get("folder_id") or "").strip()
        cursor = cfg.get("cursor")

        q_parts = ["trashed = false"]
        if folder_id:
            safe_folder = folder_id.replace("'", "")
            q_parts.append(f"'{safe_folder}' in parents")
        if cursor:
            safe_cur = str(cursor).replace("'", "")
            q_parts.append(f"modifiedTime > '{safe_cur}'")
        q_expr = quote(" and ".join(q_parts))
        fields = quote("files(id,name,mimeType,modifiedTime,size,webViewLink,description)")
        url = f"{api_base}/files?q={q_expr}&fields={fields}&pageSize=30&orderBy=modifiedTime%20desc"

        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "padam-nocturne-connector/1",
        }
        data, _ = self._call_json("GET", url, headers, http_call, limiter)
        if not isinstance(data, dict):
            raise ConnectorError("Google Drive response must be a JSON object")
        files = data.get("files") or []
        if not isinstance(files, list):
            raise ConnectorError("Google Drive files field must be a list")

        newest: str | None = str(cursor) if cursor else None
        items: list[ConnectorItem] = []

        for fentry in files:
            if not isinstance(fentry, dict):
                continue
            fid = str(fentry.get("id") or "")
            if not fid:
                continue
            name = str(fentry.get("name") or fid)
            mime = str(fentry.get("mimeType") or "")
            modified = fentry.get("modifiedTime")
            size = int(fentry.get("size") or 0)
            if modified and (not newest or str(modified) > newest):
                newest = str(modified)

            content = ""
            if fentry.get("content"):
                content = str(fentry["content"]).strip()
            elif mime == GOOGLE_DOC_MIME:
                exp_url = f"{api_base}/files/{quote(fid)}/export?mimeType=text%2Fplain"
                content = self._download_text(exp_url, headers, http_call, limiter)
            elif (mime in TEXT_MIMES or mime.startswith("text/")) and size <= MAX_FILE_BYTES:
                dl_url = f"{api_base}/files/{quote(fid)}?alt=media"
                content = self._download_text(dl_url, headers, http_call, limiter)
            else:
                desc = str(fentry.get("description") or "").strip()
                content = f"File ({mime or 'unknown'}, {size} bytes)" + (f"\n{desc}" if desc else "")

            items.append(ConnectorItem(
                external_id=f"gdrive:{fid}",
                title=name,
                body=content[:6000] if content else name,
                url=str(fentry.get("webViewLink") or ""),
                scope=str(cfg.get("scope") or f"gdrive:{folder_id or 'drive'}"),
                updated_at=str(modified) if modified else None,
            ))
        return items, newest
