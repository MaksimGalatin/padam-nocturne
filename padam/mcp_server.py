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

from . import __version__, retrieval
from .memory import Memory
from .nocturne import Nocturne
from .store import Store

# Версии протокола MCP, которые сервер понимает (новая — первой). Клиент просит свою версию; если она здесь есть,
# сервер отвечает ею же, иначе — самой новой из своих (MCP, lifecycle / version negotiation). Подсказки инструментов
# (annotations) появились в 2025-03-26, названия (title) — в 2025-06-18; обе версии сервер поддерживает.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]

INSTRUCTIONS = ("Persistent memory for this user. Call padam_search at the start of a task; save lasting "
                "preferences, decisions and facts with padam_write; padam_confirm a record that proved right, "
                "padam_refute one that did not. Nothing is ever deleted.")

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
            "importance, confidence and freshness. For questions that "
            "aggregate across many conversations (\"how many\", \"how much "
            "in total\", \"all the times\"), ask for limit 25-30 with "
            "compact=true: more records in the same space finds more of "
            "the scattered facts."),
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
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
                "compact": {"type": "boolean", "default": False,
                            "description": "Shorten each record (the person's "
                                           "words kept, the assistant's reply "
                                           "trimmed) so more records fit"},
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
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
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
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
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
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
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
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
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
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "padam_sleep",
        "description": (
            "Run a consolidation cycle: move episodes from the buffer into "
            "semantic memory with safeguards against over-weighting rare "
            "dramatic episodes. Normally scheduled, not called by hand."),
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
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
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_superseded": {"type": "boolean", "default": True},
                "scope": {"type": "string"},
            },
        },
    },
]


# Человеческие названия инструментов (поле title, MCP 2025-06-18) — клиенты показывают их в интерфейсе.
_TITLES = {
    "padam_search": "Search memory",
    "padam_write": "Remember",
    "padam_confirm": "Confirm a record",
    "padam_refute": "Refute a record",
    "padam_timeline": "Version history of a record",
    "padam_stats": "Memory statistics",
    "padam_sleep": "Run NOCTURNE consolidation",
    "padam_export": "Export memory as JSON",
}
for _t in TOOLS:
    _t.setdefault("title", _TITLES[_t["name"]])
_TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}

# Заметки цикла сна приходят из ядра по-русски (их же печатает русский CLI); наружу через MCP — по-английски.
_SLEEP_NOTES_EN = {"буфер пуст": "episode buffer is empty", "нечего выбрать": "nothing to sample"}


def missing_arguments(name: str, args: dict) -> list[str]:
    """Обязательные поля из inputSchema, которых нет или которые пусты."""
    required = _TOOLS_BY_NAME[name]["inputSchema"].get("required", [])
    return [k for k in required if args.get(k) is None or args.get(k) == ""]


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
            text = (retrieval.compact_text(r.content) if args.get("compact")
                    else r.content)
            lines.append(
                f"- {text}\n"
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
        if "note" in report:
            report["note"] = _SLEEP_NOTES_EN.get(report["note"], report["note"])
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
        asked = (req.get("params") or {}).get("protocolVersion")
        return ok({
            "protocolVersion": asked if asked in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "padam", "title": "PADAM · NOCTURNE memory", "version": __version__},
            "instructions": INSTRUCTIONS,
        })

    if method in ("notifications/initialized", "initialized"):
        return None                      # уведомление, ответа не требует

    if method == "tools/list":
        return ok({"tools": TOOLS})

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        # Неизвестный инструмент и не-объект в arguments — ошибка протокола (MCP: -32602 Invalid params).
        if name not in _TOOLS_BY_NAME:
            return err(-32602, f"unknown tool: {name}")
        if not isinstance(args, dict):
            return err(-32602, "arguments must be an object")
        # Пропущенное обязательное поле — ошибка выполнения с понятным текстом (раньше: «PADAM error: 'content'»).
        missing = missing_arguments(name, args)
        if missing:
            return ok({"content": [{"type": "text", "text":
                                    f"PADAM error: missing required argument(s): {', '.join(missing)}"}],
                       "isError": True})
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
    # MCP stdio — всегда UTF-8. Без этого на Windows (Python 3.10–3.13) поток в трубе получает cp1251/cp1252:
    # кириллица в памяти портится или сервер падает с UnicodeEncodeError на первом же ответе.
    for _поток in (sys.stdin, sys.stdout):
        if hasattr(_поток, "reconfigure"):
            _поток.reconfigure(encoding="utf-8")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            # JSON-RPC 2.0: на неразбираемый запрос — ошибка разбора с id = null, а не молчание.
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                         "error": {"code": -32700, "message": "parse error"}}) + "\n")
            sys.stdout.flush()
            continue
        # 16.10.2026: валидный JSON, но не объект ([], null, 5, "x") — handle падал на req.get,
        # а обработчик ошибки снова звал req.get и ронял весь процесс MCP-сервера.
        if not isinstance(req, dict):
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                         "error": {"code": -32600, "message": "invalid request"}}) + "\n")
            sys.stdout.flush()
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
