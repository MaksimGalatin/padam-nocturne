"""Zero-dependency адаптеры для OpenAI Agents SDK, LangGraph, PydanticAI, LlamaIndex и AutoGen."""
from __future__ import annotations

import json
from typing import Any

from .. import safety
from ..memory import Memory


class _BaseAdapter:
    def __init__(self, mem: Memory, *, scope: str = "global", agent_id: str = "sdk-agent") -> None:
        self.mem = mem
        self.scope = scope
        self.agent_id = agent_id

    def _safe_write(self, text: str, *, kind: str = "fact", scope: str | None = None) -> tuple[str, str]:
        cleaned, _ = safety.redact(str(text or ""))
        return self.mem.remember(
            cleaned,
            kind=kind,
            scope=scope or self.scope,
            origin="agent",
            guarded=True,
            agent_id=self.agent_id,
        )

    def _safe_recall_fenced(self, query: str, *, scope: str | None = None, limit: int = 5) -> str:
        recs = self.mem.recall(query, scope=scope or self.scope, limit=limit)
        if not recs:
            return ""
        body = "\n".join(f"[{r.kind}] {r.content}" for r in recs)
        return safety.fence(body)


class OpenAIAgentsMemory(_BaseAdapter):
    """Адаптер памяти для OpenAI Agents SDK (локальные tool-функции remember/recall)."""

    def remember(self, content: str, kind: str = "fact") -> dict[str, str]:
        st, mid = self._safe_write(content, kind=kind)
        return {"status": st, "id": mid}

    def recall(self, query: str, limit: int = 5) -> str:
        return self._safe_recall_fenced(query, limit=limit)

    def as_tools(self) -> list[Any]:
        return [self.remember, self.recall]


class LangGraphPadamStore(_BaseAdapter):
    """Store-совместимый адаптер для LangGraph (`put`, `get`, `search`)."""

    def put(self, namespace: tuple[str, ...], key: str, value: dict[str, Any] | str) -> str:
        ns = "/".join(namespace) if namespace else self.scope
        payload = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        _, mid = self._safe_write(f"[{key}] {payload}", scope=ns)
        return mid

    def get(self, namespace: tuple[str, ...], key: str) -> dict[str, Any] | None:
        ns = "/".join(namespace) if namespace else self.scope
        recs = self.mem.recall(key, scope=ns, limit=3)
        for r in recs:
            if f"[{key}]" in r.content:
                return {"id": r.id, "key": key, "value": r.content, "scope": ns}
        return None

    def search(self, namespace_prefix: tuple[str, ...], *, query: str = "", limit: int = 5) -> list[dict[str, Any]]:
        ns = "/".join(namespace_prefix) if namespace_prefix else self.scope
        recs = self.mem.recall(query or ns, scope=ns, limit=limit)
        return [{"id": r.id, "scope": r.scope, "content": r.content, "kind": r.kind} for r in recs]


class PydanticAIMemoryDeps(_BaseAdapter):
    """Зависимость (Deps) для PydanticAI-агентов с безопасным fenced-контекстом."""

    def remember_fact(self, text: str, kind: str = "fact") -> tuple[str, str]:
        return self._safe_write(text, kind=kind)

    def context_for(self, query: str, limit: int = 5) -> str:
        return self._safe_recall_fenced(query, limit=limit)


class LlamaIndexPadamMemory(_BaseAdapter):
    """Адаптер памяти для LlamaIndex (`get`, `put`, `reset`)."""

    def put(self, message: str | dict[str, Any]) -> tuple[str, str]:
        txt = message if isinstance(message, str) else str(message.get("content") or "")
        return self._safe_write(txt, kind="event")

    def get(self, input: str = "", limit: int = 5) -> list[dict[str, str]]:
        recs = self.mem.recall(input or "recent", scope=self.scope, limit=limit)
        return [{"role": "system", "content": safety.fence(r.content)} for r in recs]

    def reset(self) -> int:
        rows = self.mem.store.query(
            "SELECT id FROM memory WHERE user_id = ? AND scope = ? AND status != 'revoked'",
            (self.mem.user_id, self.scope),
        )
        cnt = 0
        for r in rows:
            self.mem.revoke(r["id"])
            cnt += 1
        return cnt


class AutoGenPadamMemory(_BaseAdapter):
    """Адаптер памяти для AutoGen (`add`, `query`)."""

    def add(self, content: str, kind: str = "fact") -> dict[str, str]:
        st, mid = self._safe_write(content, kind=kind)
        return {"status": st, "id": mid}

    def query(self, text: str, limit: int = 5) -> list[str]:
        recs = self.mem.recall(text, scope=self.scope, limit=limit)
        return [safety.fence(r.content) for r in recs]
