"""Режим совместимости PADAM с официальной MCP-памятью (@modelcontextprotocol/server-memory).

Включается только по желанию: PADAM_MCP_COMPAT=official-memory или padam-mcp --compat official-memory.
Все 9 официальных инструментов работают поверх защищённого хранилища PADAM:
- запись идёт через Memory.remember(..., origin="agent", guarded=True): ключи маскируются, внедрения уходят в карантин;
- связи пишутся как записи с реальными ребрами memory_link;
- удаление выполняется через Memory.revoke(...) с криптографической квитанцией (не жёсткое удаление).
"""
from __future__ import annotations

import json
import re
from typing import Any

_ENTITY_LINE_RE = re.compile(r"^\[entity:(?P<name>[^\]|]+?)\s+type:(?P<etype>[^\]]+)\](?:\s+(?P<obs>.*))?$", re.DOTALL)
_REL_LINE_RE = re.compile(r"^\[relation:(?P<src>.+?)\s+--\((?P<rtype>.+?)\)-->\s+(?P<dst>.+?)\]$")

OFFICIAL_TOOL_NAMES = (
    "create_entities",
    "create_relations",
    "add_observations",
    "delete_entities",
    "delete_observations",
    "delete_relations",
    "read_graph",
    "search_nodes",
    "open_nodes",
)

OFFICIAL_MEMORY_TOOLS: list[dict[str, Any]] = [
    {
        "name": "create_entities",
        "title": "Create Entities",
        "description": (
            "Create multiple new entities in the knowledge graph. An entity whose name already exists, "
            "or repeats an earlier entity in the same call, is skipped and its observations are not added; "
            "the result lists the skipped names in `skipped`. Use add_observations to add observations to an existing entity."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "entities": {
                    "type": "array",
                    "description": "The entities to create, each with a name unique in the graph",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "The name of the entity"},
                            "entityType": {"type": "string", "description": "The type of the entity"},
                            "observations": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "An array of observation contents associated with the entity",
                            },
                        },
                        "required": ["name", "entityType", "observations"],
                    },
                }
            },
            "required": ["entities"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "create_relations",
        "title": "Create Relations",
        "description": "Create multiple new relations between entities in the knowledge graph. Relations should be in active voice",
        "inputSchema": {
            "type": "object",
            "properties": {
                "relations": {
                    "type": "array",
                    "description": "The relations to create. Both ends must name existing entities; a relation already in the graph is not added again",
                    "items": {
                        "type": "object",
                        "properties": {
                            "from": {"type": "string", "description": "The name of the entity where the relation starts"},
                            "to": {"type": "string", "description": "The name of the entity where the relation ends"},
                            "relationType": {"type": "string", "description": "The type of the relation"},
                        },
                        "required": ["from", "to", "relationType"],
                    },
                }
            },
            "required": ["relations"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "add_observations",
        "title": "Add Observations",
        "description": "Add new observations to existing entities in the knowledge graph",
        "inputSchema": {
            "type": "object",
            "properties": {
                "observations": {
                    "type": "array",
                    "description": "The observations to add, grouped by entity. Each entity must already exist; an observation it already has is not added again",
                    "items": {
                        "type": "object",
                        "properties": {
                            "entityName": {"type": "string", "description": "The name of the entity to add the observations to"},
                            "contents": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "An array of observation contents to add",
                            },
                        },
                        "required": ["entityName", "contents"],
                    },
                }
            },
            "required": ["observations"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "delete_entities",
        "title": "Delete Entities",
        "description": (
            "Delete whole entities from the knowledge graph, together with every relation that points to or from them "
            "and all their observations. Cannot be undone."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "entityNames": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "An array of entity names to delete",
                }
            },
            "required": ["entityNames"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "delete_observations",
        "title": "Delete Observations",
        "description": "Delete specific observations from entities in the knowledge graph",
        "inputSchema": {
            "type": "object",
            "properties": {
                "deletions": {
                    "type": "array",
                    "description": "The observations to delete, grouped by entity, each matched by its exact text",
                    "items": {
                        "type": "object",
                        "properties": {
                            "entityName": {"type": "string", "description": "The name of the entity containing the observations"},
                            "observations": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "An array of observations to delete",
                            },
                        },
                        "required": ["entityName", "observations"],
                    },
                }
            },
            "required": ["deletions"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "delete_relations",
        "title": "Delete Relations",
        "description": "Delete specific relations (from, to, relationType) from the knowledge graph and keep the entities they connect.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "relations": {
                    "type": "array",
                    "description": "An array of relations to delete",
                    "items": {
                        "type": "object",
                        "properties": {
                            "from": {"type": "string", "description": "The name of the entity where the relation starts"},
                            "to": {"type": "string", "description": "The name of the entity where the relation ends"},
                            "relationType": {"type": "string", "description": "The type of the relation"},
                        },
                        "required": ["from", "to", "relationType"],
                    },
                }
            },
            "required": ["relations"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "read_graph",
        "title": "Read Graph",
        "description": (
            "Read the entire knowledge graph: every entity with its observations, and every relation. "
            "Prefer search_nodes to find entities by keyword and open_nodes to read entities whose names you know."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "entityTypes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Return only entities whose entityType is one of these (exact match), and only the relations that touch one of them.",
                },
                "observationLimit": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Return at most this many observations per entity and add observationCount.",
                },
            },
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "search_nodes",
        "title": "Search Nodes",
        "description": (
            "Search the knowledge graph for entities whose name, type or observations contain the query (case-insensitive). "
            "Returns the matching entities and every relation that touches one of them."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "maxLength": 2048, "description": "The search query to match against entity names, types, and observation content"},
                "limit": {"type": "integer", "minimum": 1, "description": "Return at most this many matching entities"},
                "observationLimit": {"type": "integer", "minimum": 0, "description": "Return at most this many observations per entity and add observationCount."},
            },
            "required": ["query"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "open_nodes",
        "title": "Open Nodes",
        "description": "Retrieve specific entities by their exact names, with every relation that touches one of them.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "An array of entity names to retrieve",
                },
                "observationLimit": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Return at most this many observations per entity and add observationCount.",
                },
            },
            "required": ["names"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
]


def _clean_tag(val: str) -> str:
    return re.sub(r"[\r\n\]]+", " ", str(val or "").strip()).strip()


def _format_obs(name: str, etype: str, obs: str | None = None) -> str:
    head = f"[entity:{_clean_tag(name)} type:{_clean_tag(etype)}]"
    if obs is None or not str(obs).strip():
        return head
    return f"{head} {str(obs).strip()}"


def _format_rel(src: str, dst: str, rtype: str) -> str:
    return f"[relation:{_clean_tag(src)} --({_clean_tag(rtype)})--> {_clean_tag(dst)}]"


def _load_active_graph(m: Any, scope: str) -> dict[str, Any]:
    rows = m.store.query(
        "SELECT id, content, status FROM memory "
        "WHERE scope = ? AND status IN ('active', 'confirmed', 'protected') "
        "ORDER BY created_at ASC, rowid ASC",
        (scope,),
    )
    entities: dict[str, dict[str, Any]] = {}
    entity_records: dict[str, list[tuple[str, str]]] = {}  # name -> [(rec_id, obs_text)]
    relations: list[dict[str, str]] = []
    rel_records: list[tuple[str, dict[str, str]]] = []
    seen_rel: set[tuple[str, str, str]] = set()

    for row in rows:
        rec_id = str(row["id"])
        txt = str(row["content"] or "")
        me = _ENTITY_LINE_RE.match(txt)
        if me:
            name = me.group("name").strip()
            etype = me.group("etype").strip()
            obs = (me.group("obs") or "").strip()
            ent = entities.setdefault(name, {"name": name, "entityType": etype, "observations": []})
            entity_records.setdefault(name, []).append((rec_id, obs))
            if obs and obs not in ent["observations"]:
                ent["observations"].append(obs)
            continue
        mr = _REL_LINE_RE.match(txt)
        if mr:
            src = mr.group("src").strip()
            rtype = mr.group("rtype").strip()
            dst = mr.group("dst").strip()
            key = (src, dst, rtype)
            rel_obj = {"from": src, "to": dst, "relationType": rtype}
            rel_records.append((rec_id, rel_obj))
            if key not in seen_rel:
                seen_rel.add(key)
                relations.append(rel_obj)

    return {
        "entities": entities,
        "entity_records": entity_records,
        "relations": relations,
        "rel_records": rel_records,
    }


def _apply_obs_limit(ent: dict[str, Any], obs_limit: int | None) -> dict[str, Any]:
    obs = list(ent["observations"])
    out: dict[str, Any] = {
        "name": ent["name"],
        "entityType": ent["entityType"],
        "observations": obs[:obs_limit] if obs_limit is not None else obs,
    }
    if obs_limit is not None:
        out["observationCount"] = len(obs)
    return out


def _filter_relations(relations: list[dict[str, str]], names: set[str]) -> list[dict[str, str]]:
    return [r for r in relations if r["from"] in names and r["to"] in names]


def _held_reason(m: Any, rec_id: Any) -> str:
    # Причина берётся из самой записи; текст записи наружу не уходит (там может быть внедрённая команда).
    row = m.store.query("SELECT quarantine_reason FROM memory WHERE id = ?", (rec_id,))
    return str(row[0]["quarantine_reason"] or "held for owner review") if row else "held for owner review"


def _create_entities(m: Any, args: dict, *, scope: str, actor: Any) -> tuple[str, dict]:
    state = _load_active_graph(m, scope)
    existing = set(state["entities"].keys())
    created: list[dict[str, Any]] = []
    skipped: list[str] = []
    held: list[dict[str, str]] = []
    seen_in_call: set[str] = set()

    for raw in args.get("entities") or []:
        name = _clean_tag(raw.get("name", ""))
        etype = _clean_tag(raw.get("entityType", "entity")) or "entity"
        obs_list = [str(o) for o in (raw.get("observations") or []) if str(o).strip()]
        if not name:
            continue
        if name in existing or name in seen_in_call:
            skipped.append(name)
            continue
        seen_in_call.add(name)
        stored_obs: list[str] = []
        if not obs_list:
            m.remember(_format_obs(name, etype), kind="fact", scope=scope, origin="agent", guarded=True, actor=actor)
        else:
            for obs in obs_list:
                status, rec_id = m.remember(
                    _format_obs(name, etype, obs),
                    kind="fact",
                    scope=scope,
                    origin="agent",
                    guarded=True,
                    actor=actor,
                )
                if status == "quarantined":
                    held.append({"entityName": name, "reason": _held_reason(m, rec_id)})
                else:
                    # Получаем фактический (замаскированный) текст из записи
                    row = m.store.query("SELECT content FROM memory WHERE id = ?", (rec_id,))
                    if row:
                        me = _ENTITY_LINE_RE.match(str(row[0]["content"] or ""))
                        if me and me.group("obs"):
                            val = me.group("obs").strip()
                            if val not in stored_obs:
                                stored_obs.append(val)
        created.append({"name": name, "entityType": etype, "observations": stored_obs})

    struct: dict[str, Any] = {"entities": created}
    if skipped:
        struct["skipped"] = skipped
    if held:
        struct["heldForReview"] = held
    return json.dumps(created, ensure_ascii=False, indent=2), struct


def _create_relations(m: Any, args: dict, *, scope: str, actor: Any) -> tuple[str, dict]:
    state = _load_active_graph(m, scope)
    entities = state["entities"]
    ent_recs = state["entity_records"]
    existing_rels = {(r["from"], r["to"], r["relationType"]) for r in state["relations"]}
    created: list[dict[str, str]] = []
    held: list[dict[str, str]] = []

    for raw in args.get("relations") or []:
        src = _clean_tag(raw.get("from", ""))
        dst = _clean_tag(raw.get("to", ""))
        rtype = _clean_tag(raw.get("relationType", ""))
        if not (src and dst and rtype):
            continue
        if src not in entities or dst not in entities:
            continue
        if (src, dst, rtype) in existing_rels:
            continue
        src_id = ent_recs[src][0][0]
        dst_id = ent_recs[dst][0][0]
        status, rel_id = m.remember(
            _format_rel(src, dst, rtype),
            kind="fact",
            scope=scope,
            origin="agent",
            guarded=True,
            links=[
                {"target_id": src_id, "relation": "derived"},
                {"target_id": dst_id, "relation": "derived"},
            ],
            actor=actor,
        )
        if status == "quarantined":
            held.append({"entityName": f"{src} -> {dst}", "reason": _held_reason(m, rel_id)})
        else:
            existing_rels.add((src, dst, rtype))
            created.append({"from": src, "to": dst, "relationType": rtype})

    struct: dict[str, Any] = {"relations": created}
    if held:
        struct["heldForReview"] = held
    return json.dumps(created, ensure_ascii=False, indent=2), struct


def _add_observations(m: Any, args: dict, *, scope: str, actor: Any) -> tuple[str, dict]:
    state = _load_active_graph(m, scope)
    entities = state["entities"]
    ent_recs = state["entity_records"]
    results: list[dict[str, Any]] = []
    held: list[dict[str, str]] = []

    for item in args.get("observations") or []:
        ename = _clean_tag(item.get("entityName", ""))
        if ename not in entities:
            raise ValueError(f"Entity with name {ename} not found")
        ent = entities[ename]
        etype = ent["entityType"]
        anchor_id = ent_recs[ename][0][0] if ent_recs.get(ename) else None
        links = [{"target_id": anchor_id, "relation": "derived"}] if anchor_id else None
        added: list[str] = []
        for raw_obs in item.get("contents") or []:
            obs = str(raw_obs).strip()
            if not obs or obs in ent["observations"]:
                continue
            status, rec_id = m.remember(
                _format_obs(ename, etype, obs),
                kind="fact",
                scope=scope,
                origin="agent",
                guarded=True,
                links=links,
                actor=actor,
            )
            if status == "quarantined":
                held.append({"entityName": ename, "reason": _held_reason(m, rec_id)})
            else:
                row = m.store.query("SELECT content FROM memory WHERE id = ?", (rec_id,))
                if row:
                    me = _ENTITY_LINE_RE.match(str(row[0]["content"] or ""))
                    if me and me.group("obs"):
                        val = me.group("obs").strip()
                        if val not in ent["observations"]:
                            ent["observations"].append(val)
                            added.append(val)
        results.append({"entityName": ename, "addedObservations": added})

    struct: dict[str, Any] = {"results": results}
    if held:
        struct["heldForReview"] = held
    return json.dumps(results, ensure_ascii=False, indent=2), struct


def _delete_entities(m: Any, args: dict, *, scope: str, actor: Any) -> tuple[str, dict]:
    names_req = [_clean_tag(n) for n in (args.get("entityNames") or []) if _clean_tag(n)]
    state = _load_active_graph(m, scope)
    deleted: list[str] = []
    not_found: list[str] = []

    for name in names_req:
        recs = state["entity_records"].get(name)
        if not recs:
            not_found.append(name)
            continue
        for rec_id, _ in recs:
            m.revoke(rec_id, actor=actor)
        for rec_id, rel in state["rel_records"]:
            if rel["from"] == name or rel["to"] == name:
                m.revoke(rec_id, actor=actor)
        deleted.append(name)

    if not not_found:
        msg = "Entities deleted successfully"
    else:
        msg = f"Deleted {len(deleted)} of {len(names_req)} entities. Not found: {', '.join(not_found)}"
    return msg, {"success": True, "message": msg}


def _delete_observations(m: Any, args: dict, *, scope: str, actor: Any) -> tuple[str, dict]:
    state = _load_active_graph(m, scope)
    deleted_count = 0
    requested = 0
    missing_entities: list[str] = []

    for d in args.get("deletions") or []:
        ename = _clean_tag(d.get("entityName", ""))
        obs_list = [str(o).strip() for o in (d.get("observations") or [])]
        requested += len(obs_list)
        recs = state["entity_records"].get(ename)
        if not recs:
            if ename:
                missing_entities.append(ename)
            continue
        for target_obs in obs_list:
            for rec_id, stored_obs in recs:
                if stored_obs == target_obs:
                    if m.revoke(rec_id, actor=actor):
                        deleted_count += 1
                    break

    if deleted_count == requested:
        msg = "Observations deleted successfully"
    else:
        msg = f"Deleted {deleted_count} of {requested} observations."
        if missing_entities:
            msg += f" Entities not found: {', '.join(missing_entities)}"
    return msg, {"success": True, "message": msg}


def _delete_relations(m: Any, args: dict, *, scope: str, actor: Any) -> tuple[str, dict]:
    rels = args.get("relations") or []
    state = _load_active_graph(m, scope)
    deleted_count = 0
    wanted = {(_clean_tag(r.get("from", "")), _clean_tag(r.get("to", "")), _clean_tag(r.get("relationType", ""))) for r in rels}
    for rec_id, rel in state["rel_records"]:
        key = (rel["from"], rel["to"], rel["relationType"])
        if key in wanted:
            if m.revoke(rec_id, actor=actor):
                deleted_count += 1
    msg = (
        "Relations deleted successfully"
        if deleted_count == len(rels)
        else f"Deleted {deleted_count} of {len(rels)} relations. The rest matched nothing."
    )
    return msg, {"success": True, "message": msg}


def _read_graph(m: Any, args: dict, *, scope: str) -> tuple[str, dict]:
    state = _load_active_graph(m, scope)
    etypes = set(args.get("entityTypes") or [])
    obs_limit = args.get("observationLimit")
    ents = [
        _apply_obs_limit(e, obs_limit)
        for e in state["entities"].values()
        if not etypes or e["entityType"] in etypes
    ]
    names = {e["name"] for e in ents}
    rels = _filter_relations(state["relations"], names) if etypes else list(state["relations"])
    graph = {"entities": ents, "relations": rels}
    return json.dumps(graph, ensure_ascii=False, indent=2), graph


def _search_nodes(m: Any, args: dict, *, scope: str, actor: Any) -> tuple[str, dict]:
    query = str(args.get("query") or "").strip()
    limit = args.get("limit")
    obs_limit = args.get("observationLimit")
    state = _load_active_graph(m, scope)
    ql = query.lower()

    matched_names: list[str] = []
    matched_set: set[str] = set()

    # 1. Прямое совпадение (как в официальном сервере: имя, тип или наблюдения, без учёта регистра)
    for name, ent in state["entities"].items():
        if not ql or ql in name.lower() or ql in ent["entityType"].lower() or any(ql in o.lower() for o in ent["observations"]):
            matched_names.append(name)
            matched_set.add(name)

    # 2. Дополнение гибридным поиском PADAM (синонимы / семантика)
    if query:
        for rec in m.recall(query, scope=scope, limit=30, actor=actor):
            me = _ENTITY_LINE_RE.match(str(rec.content or ""))
            if me:
                name = me.group("name").strip()
                if name in state["entities"] and name not in matched_set:
                    matched_names.append(name)
                    matched_set.add(name)

    if limit is not None:
        matched_names = matched_names[: int(limit)]
    final_set = set(matched_names)
    ents = [_apply_obs_limit(state["entities"][n], obs_limit) for n in matched_names]
    rels = _filter_relations(state["relations"], final_set)
    graph = {"entities": ents, "relations": rels}
    return json.dumps(graph, ensure_ascii=False, indent=2), graph


def _open_nodes(m: Any, args: dict, *, scope: str) -> tuple[str, dict]:
    state = _load_active_graph(m, scope)
    names_req = [_clean_tag(n) for n in (args.get("names") or []) if _clean_tag(n)]
    obs_limit = args.get("observationLimit")
    ents = [_apply_obs_limit(state["entities"][n], obs_limit) for n in names_req if n in state["entities"]]
    final_set = {e["name"] for e in ents}
    rels = _filter_relations(state["relations"], final_set)
    graph = {"entities": ents, "relations": rels}
    return json.dumps(graph, ensure_ascii=False, indent=2), graph


def dispatch_tool(m: Any, name: str, args: dict, *, scope: str = "global", actor: Any = None) -> tuple[str, dict | None]:
    """Диспетчер 9 официальных инструментов MCP-памяти поверх PADAM Memory."""
    eff_scope = scope or "global"
    if name == "create_entities":
        return _create_entities(m, args, scope=eff_scope, actor=actor)
    if name == "create_relations":
        return _create_relations(m, args, scope=eff_scope, actor=actor)
    if name == "add_observations":
        return _add_observations(m, args, scope=eff_scope, actor=actor)
    if name == "delete_entities":
        return _delete_entities(m, args, scope=eff_scope, actor=actor)
    if name == "delete_observations":
        return _delete_observations(m, args, scope=eff_scope, actor=actor)
    if name == "delete_relations":
        return _delete_relations(m, args, scope=eff_scope, actor=actor)
    if name == "read_graph":
        return _read_graph(m, args, scope=eff_scope)
    if name == "search_nodes":
        return _search_nodes(m, args, scope=eff_scope, actor=actor)
    if name == "open_nodes":
        return _open_nodes(m, args, scope=eff_scope)
    raise ValueError(f"Unknown official-memory tool: {name}")
