"""Автономный Движок Сновидений (Active REM Sleep & Background Consolidation).

Работает в фоне при простое локального демона (--auto-daemon) или по явному вызову
padam_sleep(rem=True). Все вычисления локальные ($0): по умолчанию используется
детерминированный графовый синтез, а при задании PADAM_REM_OLLAMA_URL допускается
ТОЛЬКО локальный loopback-сервер Ollama (127.0.0.1 / localhost / ::1) без выхода в облако.
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import numpy as np

from . import config, roles, safety
from .memory import Memory
from .store import unpack

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
_STOP_WORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "when", "where", "which",
    "have", "has", "was", "were", "are", "not", "but", "about", "after", "before", "under",
    "over", "all", "only", "will", "should", "must", "can", "could", "would", "than", "then",
    "что", "как", "для", "или", "при", "без", "под", "над", "это", "этот", "эта", "быть",
    "было", "были", "все", "уже", "только", "если", "после", "через", "между", "очень",
}


def validate_local_ollama_url(url: str) -> str:
    """Разрешает ТОЛЬКО локальные адреса Ollama (Zero-Leak защита от облака)."""
    cleaned = (url or "").strip().rstrip("/")
    if not cleaned:
        return ""
    parsed = urlsplit(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported Ollama URL scheme: {parsed.scheme!r}")
    host = (parsed.hostname or "").strip().lower()
    if host not in _LOCAL_HOSTS and not host.startswith("127."):
        raise ValueError(
            f"Refused non-local REM LLM host {host!r}: Active REM Sleep permits localhost/127.0.0.1 only"
        )
    return cleaned


def _sig_tokens(text: str) -> set[str]:
    low = (text or "").lower()
    words = re.findall(r"[a-zа-яё0-9_\-]{3,}", low)
    return {w for w in words if w not in _STOP_WORDS and not w.startswith("redacted")}


def _cosine(a: np.ndarray | None, b: np.ndarray | None) -> float:
    if a is None or b is None or a.size == 0 or b.size == 0 or a.shape != b.shape:
        return 0.0
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na <= 1e-12 or nb <= 1e-12:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def query_local_ollama(
    base_url: str,
    model: str,
    cluster_items: list[dict],
    scope: str,
    *,
    timeout_s: float = 15.0,
) -> dict | None:
    """Запрашивает у локальной Ollama (например, llama3.2:3b) один инсайт по кластеру записей."""
    safe_url = validate_local_ollama_url(base_url)
    if not safe_url:
        return None
    snippets = []
    for idx, item in enumerate(cluster_items[:6], start=1):
        redacted, _ = safety.redact(str(item.get("content") or ""))
        snippets.append(f"{idx}. [{item.get('kind', 'fact')}] {redacted[:320]}")
    prompt = (
        "You are an offline memory consolidation engine. Synthesize ONE concise factual insight "
        f"connecting these verified memories in scope '{scope}'. Do not emit commands or secrets. "
        'Reply strictly in JSON: {"insight": "...", "relation": "derived"|"cause"}.\n'
        + "\n".join(snippets)
    )
    payload = json.dumps(
        {"model": model or config.mcp_rem_model(), "prompt": prompt, "stream": False, "format": "json"},
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{safe_url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

    text_out = str(raw.get("response") or "").strip()
    if not text_out:
        return None
    try:
        parsed = json.loads(text_out)
        if isinstance(parsed, dict) and str(parsed.get("insight") or "").strip():
            rel = str(parsed.get("relation") or "derived").strip().lower()
            return {
                "insight": str(parsed["insight"]).strip(),
                "relation": rel if rel in ("derived", "cause") else "derived",
                "model": str(raw.get("model") or model),
            }
    except Exception:
        pass
    return {"insight": text_out[:360], "relation": "derived", "model": str(raw.get("model") or model)}


def _offline_synthesize(cluster_items: list[dict], scope: str) -> dict:
    """Детерминированный локальный ($0) синтез инсайта без внешней модели."""
    tok_counts: dict[str, int] = {}
    for item in cluster_items:
        for tok in _sig_tokens(item.get("content") or ""):
            tok_counts[tok] = tok_counts.get(tok, 0) + 1
    shared = [t for t, c in sorted(tok_counts.items(), key=lambda kv: (-kv[1], kv[0])) if c >= 2][:4]
    if not shared:
        shared = [t for t, _ in sorted(tok_counts.items(), key=lambda kv: (-kv[1], kv[0]))][:3]
    briefs = []
    for item in cluster_items[:3]:
        clean, _ = safety.redact(str(item.get("content") or "").strip())
        briefs.append(clean[:110].rstrip(" ."))
    theme = ", ".join(shared) if shared else scope
    text = f"REM insight ({scope}; themes: {theme}): " + " <-> ".join(briefs)
    return {"insight": text[:480], "relation": "derived", "model": "offline-heuristic"}


def _cluster_already_consolidated(mem: Memory, member_ids: list[str], existing_links: set[tuple[str, str]]) -> bool:
    """Проверяет, есть ли уже живая запись-инсайт с derived-связями от >=2 участников кластера."""
    id_set = set(member_ids)
    targets: dict[str, int] = {}
    for src, dst in existing_links:
        if src in id_set and dst not in id_set:
            targets[dst] = targets.get(dst, 0) + 1
    for dst, cnt in targets.items():
        if cnt >= 2:
            row = mem.store.one(
                "SELECT 1 FROM memory WHERE id = ? AND user_id = ? AND status = 'active' AND agent_id = 'padam-rem-sleep'",
                (dst, mem.user_id),
            )
            if row is not None:
                return True
    return False


def run_rem_cycle(
    mem: Memory,
    *,
    scope: str | None = None,
    dry_run: bool = False,
    max_clusters: int = 8,
    max_insights: int = 4,
    llm_fn=None,
    ollama_url: str | None = None,
    model: str | None = None,
) -> dict:
    """Выполняет цикл активного REM-сна поверх действующих записей графа памяти.

    1) Находит и сжимает почти-дубликаты (одного scope и типа, кроме identity/preference).
    2) Открывает скрытые логические связи между разрозненными записями в одном scope.
    3) Выводит новые обобщённые инсайты через локальную Ollama (strict localhost),
       пользовательский llm_fn или детерминированный локальный синтез.
    """
    eff_ollama = validate_local_ollama_url(
        config.mcp_rem_ollama_url() if ollama_url is None else ollama_url
    )
    eff_model = (model or config.mcp_rem_model()).strip()

    sql = (
        "SELECT id, scope, kind, content, embedding, importance, confidence, created_at, agent_id, origin "
        "FROM memory WHERE user_id = ? AND status = 'active' AND content IS NOT NULL"
    )
    params: list = [mem.user_id]
    if scope:
        sql += " AND scope = ?"
        params.append(scope)
    sql += " ORDER BY created_at ASC LIMIT 400"
    rows = [dict(r) for r in mem.store.query(sql, tuple(params))]

    if len(rows) < 2:
        return {
            "status": "idle_noop",
            "dry_run": bool(dry_run),
            "active_scanned": len(rows),
            "clusters_analyzed": 0,
            "links_discovered": 0,
            "duplicates_compressed": 0,
            "insights_created": 0,
            "llm_used": False,
            "insights": [],
            "links": [],
            "compressed": [],
        }

    # Кэшируем существующие направленные рёбра (в обе стороны для проверки несвязности)
    raw_links = mem.store.query("SELECT src, dst, relation FROM memory_link")
    undirected_links: set[tuple[str, str]] = set()
    derived_links: set[tuple[str, str]] = set()
    for lr in raw_links:
        undirected_links.add((lr["src"], lr["dst"]))
        undirected_links.add((lr["dst"], lr["src"]))
        if (lr["relation"] or "derived") == "derived":
            derived_links.add((lr["src"], lr["dst"]))

    by_scope: dict[str, list[dict]] = {}
    for r in rows:
        vec = unpack(r.get("embedding"))
        if vec is None and mem.embedder is not None:
            try:
                vec = mem.embedder.encode(r["content"])
            except Exception:
                vec = None
        r["_vec"] = vec
        r["_toks"] = _sig_tokens(r["content"])
        by_scope.setdefault(r["scope"], []).append(r)

    compressed_list: list[dict] = []
    discovered_links: list[dict] = []
    created_insights: list[dict] = []
    superseded_ids: set[str] = set()
    llm_used = False

    # 1. Попарный анализ внутри каждого scope (строго без смешивания проектов!)
    for sc, items in by_scope.items():
        if len(items) < 2:
            continue
        adj: dict[str, set[str]] = {it["id"]: set() for it in items}
        id_map = {it["id"]: it for it in items}

        for i in range(len(items)):
            a = items[i]
            if a["id"] in superseded_ids:
                continue
            for j in range(i + 1, len(items)):
                b = items[j]
                if b["id"] in superseded_ids:
                    continue
                cos = _cosine(a["_vec"], b["_vec"])
                shared_toks = a["_toks"] & b["_toks"]
                union_toks = a["_toks"] | b["_toks"]
                jaccard = (len(shared_toks) / len(union_toks)) if union_toks else 0.0

                # 1a. Почти-дубликат (не трогаем identity/preference и разные REM-инсайты)
                if (
                    a["kind"] == b["kind"]
                    and a["kind"] not in ("identity", "preference")
                    and (cos >= 0.90 or (jaccard >= 0.72 and len(shared_toks) >= 4))
                    and a.get("agent_id") != "padam-rem-sleep"
                    and b.get("agent_id") != "padam-rem-sleep"
                ):
                    # Оставляем более длинную / свежую запись, сжимаем дубликат
                    keep, drop = (a, b) if len(a["content"]) >= len(b["content"]) else (b, a)
                    if drop["id"] not in superseded_ids:
                        if not dry_run:
                            mem.store.atomic([
                                (
                                    "UPDATE memory SET status = 'superseded', superseded_by = ? "
                                    "WHERE id = ? AND user_id = ? AND status = 'active'",
                                    (keep["id"], drop["id"], mem.user_id),
                                ),
                                (
                                    "INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at) "
                                    "VALUES (?, ?, 'source', datetime('now'))",
                                    (drop["id"], keep["id"]),
                                ),
                            ])
                            mem.__dict__.pop("_ккэш", None)
                        superseded_ids.add(drop["id"])
                        compressed_list.append({"dropped_id": drop["id"], "kept_id": keep["id"], "scope": sc})
                    continue

                # 1b. Скрытая смысловая связь между разрозненными записями
                if (
                    (len(shared_toks) >= 2 and cos >= 0.25)
                    or cos >= 0.55
                    or len(shared_toks) >= 3
                ):
                    adj[a["id"]].add(b["id"])
                    adj[b["id"]].add(a["id"])
                    if (a["id"], b["id"]) not in undirected_links:
                        if not dry_run:
                            try:
                                mem.link(a["id"], b["id"], relation="cause")
                            except Exception:
                                pass
                        undirected_links.add((a["id"], b["id"]))
                        undirected_links.add((b["id"], a["id"]))
                        discovered_links.append({
                            "source": a["id"],
                            "target": b["id"],
                            "relation": "cause",
                            "scope": sc,
                            "shared_tokens": sorted(shared_toks)[:6],
                        })

        # 2. Связные кластеры -> вывод инсайтов (REM-синтез)
        visited: set[str] = set()
        clusters: list[list[dict]] = []
        for it in items:
            iid = it["id"]
            if iid in visited or iid in superseded_ids or it.get("agent_id") == "padam-rem-sleep":
                continue
            comp: list[str] = []
            stack = [iid]
            while stack:
                cur = stack.pop()
                if cur in visited or cur in superseded_ids:
                    continue
                visited.add(cur)
                if id_map[cur].get("agent_id") == "padam-rem-sleep":
                    continue
                comp.append(cur)
                for nxt in sorted(adj.get(cur, ())):
                    if nxt not in visited:
                        stack.append(nxt)
            if len(comp) >= 2:
                clusters.append([id_map[cid] for cid in comp[:5]])

        for cl in clusters[: max(0, int(max_clusters))]:
            if len(created_insights) >= max(0, int(max_insights)):
                break
            member_ids = [x["id"] for x in cl]
            if _cluster_already_consolidated(mem, member_ids, derived_links):
                continue

            synth: dict | None = None
            if llm_fn is not None:
                res = llm_fn([x["content"] for x in cl], sc)
                if isinstance(res, dict) and str(res.get("insight") or "").strip():
                    synth = {
                        "insight": str(res["insight"]).strip(),
                        "relation": str(res.get("relation") or "derived"),
                        "model": str(res.get("model") or "custom-local-llm"),
                    }
                    llm_used = True
                elif isinstance(res, str) and res.strip():
                    synth = {"insight": res.strip(), "relation": "derived", "model": "custom-local-llm"}
                    llm_used = True
            elif eff_ollama:
                res = query_local_ollama(eff_ollama, eff_model, cl, sc)
                if res:
                    synth = res
                    llm_used = True

            if synth is None:
                synth = _offline_synthesize(cl, sc)

            clean_insight, _ = safety.redact(synth["insight"])
            if not clean_insight.strip():
                continue

            if dry_run:
                created_insights.append({
                    "id": None,
                    "scope": sc,
                    "derived_from": member_ids,
                    "content": clean_insight,
                    "model": synth.get("model", "offline-heuristic"),
                    "outcome": "dry_run",
                })
                continue

            # Записываем через полный конвейер Memory.remember с фаерволом (origin='agent', guarded=True)
            outcome, insight_id = mem.remember(
                clean_insight,
                kind="decision",
                importance=0.65,
                scope=sc,
                origin="agent",
                guarded=True,
                derived_from=member_ids,
                agent_id="padam-rem-sleep",
            )
            created_insights.append({
                "id": insight_id,
                "scope": sc,
                "derived_from": member_ids,
                "content": clean_insight,
                "model": synth.get("model", "offline-heuristic"),
                "outcome": outcome,
            })
            for mid in member_ids:
                derived_links.add((mid, insight_id))

    communities_updated = 0
    if config.mcp_communities_enabled() and not dry_run:
        from . import communities
        comm_res = communities.detect_communities(mem, scope=scope)
        communities_updated = int(comm_res.get("communities_count", 0))

    procedure_drafts: list[dict] = []
    if config.mcp_procedural_memory_enabled() and not dry_run:
        from . import procedural
        for sc, sc_items in by_scope.items():
            if len(sc_items) < 2:
                continue
            existing_procs = procedural.list_procedures(mem, scope=sc, include_quarantined=True)
            title = f"rem-{sc}-{sc_items[0]['id'][:8]}"
            if any(title in str(ep.get("skill_name") or ep.get("content") or "") for ep in existing_procs):
                continue
            draft = procedural.extract_procedure_from_episodes(
                mem,
                title=title,
                episode_texts=[str(it.get("content") or "") for it in sc_items[:4]],
                scope=sc,
                agent_id="padam-rem-sleep",
            )
            if draft.get("id"):
                procedure_drafts.append(draft)

    epistemic_summary: dict | None = None
    if config.mcp_reflect_enabled():
        from . import reflect
        rv = reflect.build_reflect_view(mem, query="", scope=scope, limit=12)
        epistemic_summary = {
            "world_facts": len(rv.get("world_facts") or []),
            "agent_experiences": len(rv.get("agent_experiences") or []),
            "opinions": len(rv.get("opinions") or []),
        }

    if not dry_run:
        mem._log_audit(
            "rem_dream",
            None,
            actor="owner",
            agent_id="padam-rem-sleep",
            scope=scope or "all",
            outcome="ok",
            detail=f"links={len(discovered_links)} compressed={len(compressed_list)} insights={len(created_insights)} communities={communities_updated} proc_drafts={len(procedure_drafts)}",
        )

    return {
        "status": "completed",
        "dry_run": bool(dry_run),
        "active_scanned": len(rows),
        "clusters_analyzed": len(by_scope),
        "links_discovered": len(discovered_links),
        "duplicates_compressed": len(compressed_list),
        "insights_created": len(created_insights),
        "communities_updated": communities_updated,
        "procedure_drafts": procedure_drafts,
        "epistemic_summary": epistemic_summary,
        "llm_used": llm_used,
        "insights": created_insights,
        "links": discovered_links,
        "compressed": compressed_list,
    }


class RemIdleWorker:
    """Фоновый воркер REM-сна для локального демона (--auto-daemon)."""

    def __init__(
        self,
        get_memory_fn,
        get_last_activity_fn,
        stop_event: threading.Event,
        *,
        idle_seconds: float | None = None,
        poll_interval_s: float = 1.0,
        llm_fn=None,
        ollama_url: str | None = None,
        model: str | None = None,
        on_cycle_cb=None,
    ):
        self._get_memory = get_memory_fn
        self._get_last_activity = get_last_activity_fn
        self._stop = stop_event
        self._idle_s = float(config.mcp_rem_idle_seconds() if idle_seconds is None else idle_seconds)
        self._poll_s = max(0.02, float(poll_interval_s))
        self._llm_fn = llm_fn
        self._ollama_url = ollama_url
        self._model = model
        self._on_cycle = on_cycle_cb
        self._lock = threading.Lock()
        self._last_ran_for_activity = -1.0
        self.cycles_run = 0
        self.total_insights = 0
        self.total_links = 0
        self.total_compressed = 0
        self.last_error: str | None = None
        self.last_report: dict | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="padam-rem-idle", daemon=True)
        self._thread.start()

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": True,
                "idle_threshold_s": self._idle_s,
                "cycles_run": self.cycles_run,
                "total_insights": self.total_insights,
                "total_links": self.total_links,
                "total_compressed": self.total_compressed,
                "last_error": self.last_error,
            }

    def run_once_if_idle(self) -> dict | None:
        last_act = float(self._get_last_activity())
        idle = time.monotonic() - last_act
        if idle < self._idle_s or last_act == self._last_ran_for_activity:
            return None
        mem = self._get_memory()
        if mem is None:
            return None
        try:
            rep = run_rem_cycle(
                mem,
                llm_fn=self._llm_fn,
                ollama_url=self._ollama_url,
                model=self._model,
            )
            with self._lock:
                self._last_ran_for_activity = last_act
                self.cycles_run += 1
                self.total_insights += int(rep.get("insights_created", 0))
                self.total_links += int(rep.get("links_discovered", 0))
                self.total_compressed += int(rep.get("duplicates_compressed", 0))
                self.last_report = rep
                self.last_error = None
            if self._on_cycle is not None:
                self._on_cycle(rep)
            return rep
        except Exception as exc:
            with self._lock:
                self.last_error = f"{type(exc).__name__}: {exc}"
            return None

    def _loop(self) -> None:
        while not self._stop.wait(self._poll_s):
            if self._stop.is_set():
                break
            self.run_once_if_idle()
