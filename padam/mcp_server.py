#!/usr/bin/env python3
"""MCP-сервер PADAM.

Делает память общей для всех клиентов, поддерживающих Model Context
Protocol: Claude Desktop, Claude Code, Cursor, VS Code. Начал разговор в
одном — продолжил в другом с тем же контекстом.

Протокол — JSON-RPC 2.0 поверх стандартного ввода-вывода. Реализован без
внешних зависимостей намеренно: у сервера памяти не должно быть своей
цепочки зависимостей.

Запуск вручную (для проверки):
    python -m padam.mcp_server

Подключение к Claude Desktop — файл claude_desktop_config.json:
    {
      "mcpServers": {
        "padam": {
          "command": "python",
          "args": ["-m", "padam.mcp_server"],
          "env": {"PADAM_DB": "/home/USER/.padam/memory.db"}
        }
      }
    }
"""

from __future__ import annotations

import json
import os
import sys
import traceback

from . import __version__
from .memory import Memory
from .nocturne import Nocturne
from .store import Store

PROTOCOL_VERSION = "2024-11-05"

_memory: Memory | None = None


def mem() -> Memory:
    global _memory
    if _memory is None:
        _memory = Memory(user_id=os.environ.get("PADAM_USER", "default"),
                         store=Store(os.environ.get("PADAM_DB") or None))
    return _memory


# --- описания инструментов --------------------------------------------

TOOLS = [
    {
        "name": "padam_search",
        "description": (
            "Search persistent memory. Use this at the start of a task to "
            "recover what is already known about the user, the project, or "
            "prior decisions. Returns records ranked by relevance, "
            "importance, confidence and freshness."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string",
                          "description": "What to look for, in natural language"},
                "kind": {"type": "string",
                         "enum": ["preference", "identity", "decision",
                                  "correction", "fact", "state", "event"],
                         "description": "Restrict to one record type"},
                "scope": {"type": "string", "default": "global",
                          "description": "Memory scope, e.g. 'project:code'"},
                "limit": {"type": "integer", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "padam_write",
        "description": (
            "Store something worth remembering across sessions: a stated "
            "preference, a decision, a stable fact, a correction. If a close "
            "record already exists, PADAM resolves the relation itself — "
            "duplicate, refinement or contradiction — and keeps the previous "
            "version in history. Nothing is ever deleted."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string",
                            "description": "The record, as one clear sentence"},
                "kind": {"type": "string",
                         "enum": ["preference", "identity", "decision",
                                  "correction", "fact", "state", "event"],
                         "description": (
                             "Type governs how fast it fades: preference and "
                             "identity never fade, decision and correction "
                             "over a year, fact over half a year, state over "
                             "two weeks, event over two days. Omit to detect "
                             "automatically.")},
                "importance": {"type": "number", "default": 0.5,
                               "minimum": 0.0, "maximum": 1.0},
                "scope": {"type": "string", "default": "global"},
            },
            "required": ["content"],
        },
    },
    {
        "name": "padam_confirm",
        "description": (
            "Mark a retrieved record as still true. Call this when a memory "
            "you used turned out to be correct. This refreshes the record and "
            "raises its confidence. Retrieval alone does NOT confirm a record "
            "— a wrong memory that gets retrieved often would otherwise stay "
            "forever fresh."),
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
    {
        "name": "padam_refute",
        "description": (
            "Mark a retrieved record as no longer true. Lowers confidence "
            "without refreshing the record. After enough refutations the "
            "record is archived but stays in history."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "drop": {"type": "number", "default": 0.3},
            },
            "required": ["id"],
        },
    },
    {
        "name": "padam_timeline",
        "description": (
            "Show the full version history of a record: every earlier "
            "version it replaced, in order. Use this to answer 'what did we "
            "think before' and 'when did this change'."),
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
    {
        "name": "padam_stats",
        "description": (
            "Current state of memory: counts by status and type, which "
            "embedding backend is active, where the database lives."),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "padam_sleep",
        "description": (
            "Run a consolidation cycle: move episodes from the buffer into "
            "semantic memory with safeguards against over-weighting rare "
            "dramatic episodes. Normally scheduled, not called by hand."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "batch": {"type": "integer", "default": 256},
                "dry_run": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "padam_export",
        "description": (
            "Export the entire memory as JSON. Always available, no window, "
            "no conditions. The export is self-contained and can be loaded "
            "back or read by hand."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_superseded": {"type": "boolean", "default": True},
                "scope": {"type": "string"},
            },
        },
    },
]


# --- выполнение инструментов ------------------------------------------

def call_tool(name: str, args: dict) -> str:
    m = mem()

    if name == "padam_search":
        found = m.recall(args["query"], scope=args.get("scope", "global"),
                         kind=args.get("kind"), limit=args.get("limit", 5))
        if not found:
            return "Nothing found in memory for this query."
        lines = []
        for r in found:
            flags = []
            if r.expired:
                flags.append("EXPIRED")
            if r.confidence < 0.7:
                flags.append(f"low confidence {r.confidence:.2f}")
            suffix = f"  [{'; '.join(flags)}]" if flags else ""
            lines.append(
                f"- {r.content}\n"
                f"  id={r.id}  kind={r.kind}  score={r.score:.4f}{suffix}")
        return ("Found in memory (use padam_confirm if a record proved "
                "correct, padam_refute if it did not):\n" + "\n".join(lines))

    if name == "padam_write":
        outcome, mid = m.remember(
            args["content"], kind=args.get("kind"),
            importance=args.get("importance", 0.5),
            scope=args.get("scope", "global"))
        notes = {
            "created": "stored as a new record",
            "duplicate": "already known; confidence raised, nothing duplicated",
            "merged": "refined an existing record; previous version kept in history",
            "superseded": "replaced an existing record; previous version kept in history",
            "coexists": "stored alongside a similar record",
        }
        return f"{notes.get(outcome, outcome)}  id={mid}"

    if name == "padam_confirm":
        ok = m.confirm(args["id"])
        return "Record confirmed and refreshed." if ok else "Record not found."

    if name == "padam_refute":
        m.refute(args["id"], drop=args.get("drop", 0.3))
        return "Confidence lowered. Record not refreshed."

    if name == "padam_timeline":
        chain = m.timeline(args["id"])
        if not chain:
            return "Record not found."
        out = []
        for row in chain:
            state = "" if row["status"] == "active" else f" [{row['status']}]"
            body = row["content"] or "(content wiped by revoke)"
            out.append(f"{row['created_at'][:19]}{state}\n  {body}")
        return "\n  ↓\n".join(out)

    if name == "padam_stats":
        return json.dumps(m.stats(), ensure_ascii=False, indent=2)

    if name == "padam_sleep":
        report = Nocturne(m, batch_size=args.get("batch", 256),
                          dry_run=args.get("dry_run", False)).run()
        report.pop("checks", None)
        return json.dumps(report, ensure_ascii=False, indent=2)

    if name == "padam_export":
        payload = m.export(
            include_superseded=args.get("include_superseded", True),
            scope=args.get("scope"))
        return json.dumps(payload, ensure_ascii=False, indent=2)

    raise ValueError(f"unknown tool: {name}")


# --- JSON-RPC ----------------------------------------------------------

def handle(req: dict) -> dict | None:
    method = req.get("method")
    req_id = req.get("id")

    def ok(result):
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def err(code, message):
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": code, "message": message}}

    if method == "initialize":
        return ok({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "padam", "version": __version__},
        })

    if method in ("notifications/initialized", "initialized"):
        return None                      # уведомление, ответа не требует

    if method == "tools/list":
        return ok({"tools": TOOLS})

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            text = call_tool(name, args)
            return ok({"content": [{"type": "text", "text": text}],
                       "isError": False})
        except Exception as e:
            return ok({"content": [{"type": "text",
                                    "text": f"PADAM error: {e}"}],
                       "isError": True})

    if method == "ping":
        return ok({})

    if req_id is None:
        return None                      # прочие уведомления игнорируем
    return err(-32601, f"method not found: {method}")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            resp = handle(req)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            resp = {"jsonrpc": "2.0", "id": req.get("id"),
                    "error": {"code": -32603, "message": "internal error"}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
