"""Вывеска и справочник инструментов MCP (0.9.0, 25.11.2026).

Зачем. Каждый агент на старте сессии загружает список инструментов целиком: описание каждого
инструмента и каждого поля. Этот список — постоянный налог на контекст. До 0.9.0 он упёрся в
собственный предел PADAM (33 500 знаков на 34 инструмента в режиме Ковчега), и описания пришлось
урезать до одного слова: «Phoenix», «Feeds», «Leases». Модели по слову не понимают, когда звать
инструмент.

Как теперь. Два слоя:

* **Вывеска** (tools/list, грузится всегда) — у каждого инструмента настоящее описание в одно-два
  предложения: что делает и когда звать. У больших инструментов с действиями (action) в схеме
  остаются только частые поля: действие, обязательные для какого-либо действия и общие
  (agent_id, scope, query, limit, id, text, content, title, status). Редкие поля уходят в справочник.
* **Справочник** (по запросу, ноль знаков, пока не спросили) — action="help" у любого инструмента
  с действиями и ресурс padam://help/{tool}: все действия, какие поля каждому обязательны, все поля
  с типами, перечнями и описаниями, включая скрытые с вывески.

Скрытое поле не отключено: сервер проверяет аргументы по полной схеме, поэтому поле можно передать
как обычно, а клиенты, которые отбрасывают поля вне вывески, могут передать его внутри extra={...}.
Рост дальше: новое действие стоит вывеске ~10 знаков (имя в перечне), новое редкое поле — 0.
"""

from __future__ import annotations

import copy
import json
from typing import Any

# Настоящие описания вместо одного слова. Текст сверен с обработчиками в mcp_server.py.
DESCRIPTIONS: dict[str, str] = {
    "padam_wake_up": "Session-start brief in one call: identity and preferences, open commitments and records relevant to query, capped by max_tokens. Call first.",
    "padam_commitments": "Track an agent's goals and promises across sessions: add a commitment, update its status, list open ones.",
    "padam_family_relay": "Direct inbox between agents: send a payload to another agent, read your inbox, acknowledge a message by id.",
    "padam_checkpoint": "Save the current task, next step, files and hypothesis before stopping; load the latest checkpoint to resume.",
    "padam_ark_timeline": "Chronological feed of memory events, filtered by query and since. For one record's versions use padam_timeline.",
    "padam_lesson": "Record a lesson after a mistake (what happened, why, rule learned) and list lessons so it is not repeated.",
    "padam_family_council": "Put a task before the local Family Council: a security reviewer with veto and other roles return a verdict. $0.",
    "padam_family_feed": "Shared agent channels (work, office, smoke, quarantine) and the agora board: read, post, reflexes, bounties.",
    "padam_memory_branch": "Draft memory in an isolated branch, then merge it into main memory or abandon it. For experiments and risky edits.",
    "padam_selective_proof": "Merkle proof that one record exists in a scope without revealing other records; verify a proof you received.",
    "padam_guardian_tick": "Health and upkeep: readiness, audit verify, doctor, drift, self-heal, memory hygiene, entity graph, morning pulse.",
    "padam_mesh_sync": "Pair devices (post-quantum key exchange, 6-digit code), then export and apply encrypted memory deltas between them.",
    "padam_multimodal_inspect": "Check a document or image (text or base64) for hidden prompt injections and store a safe summary card in memory.",
    "padam_sibling_hub": "Registry of sibling agents: register, heartbeat, list, agent passports, signed provenance and its verification.",
    "padam_coop_lock": "Coordinate agents on shared work: leases on files or resources, a task board (create, claim, update), joint rounds.",
    "padam_session_pack": "Compact context pack for the current task and topic within a token cap: what an agent needs to continue work.",
    "padam_code_anchor": "Pin a memory record to a file and symbol, then check whether the code still matches what the record claims.",
    "padam_batch": "Run up to 10 read-only PADAM calls in one request to save round trips. Write tools are not allowed inside.",
    "padam_conflict_arbiter": "Open a case when two agents disagree, add evidence, resolve with a decision or escalate to the owner; list cases.",
    "padam_mcp_telemetry": "Weight and health of this MCP server: tool list size in characters and tokens, heaviest tools, calls, errors.",
    "padam_token_budget": "Token plan per provider: set limits, record usage and earnings, pace work, propose top-ups for the owner to approve.",
    "padam_freelance_hub": "Freelance and store work for agents: accounts, job evaluation, bids, delivery, stores, onboarding wizard, outreach mail.",
    "padam_phoenix_family": "Phoenix nodes: join the family under the Codex, local Ollama model and devices, kin messages, experience, labor board.",
    "padam_local_model": "Local model at $0: show status, set CPU power (eco, half, full) or choose the model / GGUF file to run.",
    "padam_benchmark": "Run or show PADAM's built-in checks locally at $0: the AIFaSecurity-100 attack set and the QA benchmark.",
}

# К описанию поля action на вывеске дописывается «|help»: подсказка, где полный перечень с полями.
ACTION_HELP_HINT = "help"

# Поля, которые остаются на вывеске у любого большого инструмента.
COMMON_FIELDS = frozenset({"action", "agent_id", "agent", "scope", "query", "limit", "id", "text", "content", "title", "status"})

# Порог: инструменты с действиями и схемой длиннее этого делятся на вывеску и справочник.
COMPACT_SCHEMA_CHARS = 700

EXTRA_FIELD = {"type": "object", "description": "Fields of rare actions (see action=help)"}

# Поля, которые остаются на вывеске сверх общих: без них главное действие инструмента теряет смысл.
KEEP_FIELDS: dict[str, frozenset] = {
    "padam_conflict_arbiter": frozenset({"agent_a", "position_a", "agent_b", "position_b", "decision", "note"}),
}

# Короткие описания полей, которые несут сведения сверх имени поля (формат, единица, диапазон).
# Прочие описания до 12 знаков повторяют имя поля («Task», «Files», «Case id») и с вывески снимаются;
# в справочнике (action=help) они остаются.
INFORMATIVE_SHORT = frozenset({
    "1..5", "ISO", "6-digit SAS", "Base64", "Model/GGUF", "CPU level", "TTL sec", "Body JSON/str",
    "Read calls", "RBAC role", "Peer pub", "Delta", "Guess", "Kind",
})


def _schema_chars(schema: dict) -> int:
    return len(json.dumps(schema, ensure_ascii=False))


def _required_by_actions(action_required: dict[str, tuple[str, ...]] | None) -> set[str]:
    поля: set[str] = set()
    for ключи in (action_required or {}).values():
        for k in ключи:
            поля.add(k.split("|")[0])
    return поля


def is_compacted(tool: dict) -> bool:
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    return "action" in props and _schema_chars(tool.get("inputSchema") or {}) > COMPACT_SCHEMA_CHARS


def hidden_fields(tool: dict, action_required: dict[str, tuple[str, ...]] | None) -> list[str]:
    """Поля, которых нет на вывеске (но которые сервер принимает и справочник описывает)."""
    if not is_compacted(tool):
        return []
    props = tool["inputSchema"].get("properties") or {}
    оставить = COMMON_FIELDS | _required_by_actions(action_required) | KEEP_FIELDS.get(tool.get("name"), frozenset())
    return [k for k in props if k not in оставить]


def signboard(tool: dict, action_required: dict[str, tuple[str, ...]] | None) -> dict:
    """Версия инструмента для tools/list. Полное определение не меняется (по нему идёт проверка)."""
    t = dict(tool)
    desc = str(t.get("description") or "")
    if t.get("name") in DESCRIPTIONS and len(desc) < 40:
        t["description"] = DESCRIPTIONS[t["name"]]
    schema = copy.deepcopy(t.get("inputSchema") or {})
    props = schema.get("properties") or {}
    for k, v in list(props.items()):
        if k != "action" and isinstance(v, dict):
            d = str(v.get("description") or "")
            if d and len(d) <= 12 and d not in INFORMATIVE_SHORT:
                props[k] = {kk: vv for kk, vv in v.items() if kk != "description"}
    t["inputSchema"] = schema
    if "action" not in props:
        return t
    act = dict(props["action"])
    if "enum" in act and "help" not in act["enum"]:
        act["enum"] = list(act["enum"]) + ["help"]
    прежнее = str(act.get("description") or "").strip()
    if ACTION_HELP_HINT not in прежнее.split("|"):
        act["description"] = (прежнее + "|" + ACTION_HELP_HINT) if прежнее else ACTION_HELP_HINT
    props["action"] = act
    скрыть = hidden_fields(tool, action_required)
    if скрыть:
        for k in скрыть:
            props.pop(k, None)
        props["extra"] = dict(EXTRA_FIELD)
    t["inputSchema"] = schema
    return t


def merge_extra(args: dict) -> dict:
    """extra={...} разворачивается в обычные аргументы; явный аргумент старше поля внутри extra."""
    extra = args.get("extra")
    if not isinstance(extra, dict):
        return args
    итог = {k: v for k, v in args.items() if k != "extra"}
    for k, v in extra.items():
        if isinstance(k, str) and k not in итог and k != "extra" and v is not None:
            итог[k] = v
    return итог


def build_guide(tool: dict, action_required: dict[str, tuple[str, ...]] | None) -> dict[str, Any]:
    """Полный справочник инструмента: действия с обязательными полями и все поля по полной схеме."""
    name = tool.get("name")
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    скрытые = set(hidden_fields(tool, action_required))
    fields: dict[str, Any] = {}
    for k, v in props.items():
        if not isinstance(v, dict):
            continue
        запись: dict[str, Any] = {"type": v.get("type", "any")}
        for ключ in ("enum", "default", "minimum", "maximum", "maxLength", "maxItems", "description"):
            if ключ in v:
                запись[ключ] = v[ключ]
        if k in скрытые:
            запись["on_signboard"] = False
        fields[k] = запись
    actions: dict[str, Any] = {}
    act = props.get("action") or {}
    for a in act.get("enum") or []:
        req = list((action_required or {}).get(a, ()))
        actions[a] = {"required": req} if req else {}
    guide: dict[str, Any] = {
        "tool": name,
        "title": tool.get("title"),
        "description": DESCRIPTIONS.get(name) if len(str(tool.get("description") or "")) < 40 else tool.get("description"),
        "default_action": act.get("default"),
        "actions": actions,
        "always_required": list(schema.get("required") or []),
        "fields": fields,
        "hidden_from_signboard": sorted(скрытые),
        "how_to_pass_hidden_fields": (
            "Pass them as ordinary arguments, or inside extra={...} if your client drops arguments "
            "that are not on the signboard. An explicit argument wins over the same key inside extra."
        ),
    }
    return guide
