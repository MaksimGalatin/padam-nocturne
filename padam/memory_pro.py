# -*- coding: utf-8 -*-
"""Продвинутый интеллект памяти PADAM: Корзина/Diff, IDE-правила, Контекстный Компас, Санитар дублей, Проводник /memories и Git Team Sync (пп. 5, 6, 7, 8, 10, 17)."""
from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import re
import uuid
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import ark, audit_chain, integrity, obsidian_sync, safety

_MPRO_DDL = """
CREATE TABLE IF NOT EXISTS memory_recycle_bin (
    bin_id          TEXT PRIMARY KEY,
    record_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    scope           TEXT NOT NULL DEFAULT 'global',
    kind            TEXT NOT NULL DEFAULT 'fact',
    content         TEXT NOT NULL,
    importance      REAL NOT NULL DEFAULT 0.5,
    prev_status     TEXT NOT NULL DEFAULT 'active',
    deleted_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recycle_user ON memory_recycle_bin (user_id, deleted_at DESC);
"""

IDE_RULE_TARGETS: dict[str, str] = {
    "claude": "CLAUDE.md",
    "cursor": ".cursorrules",
    "agents": "AGENTS.md",
    "gemini": "GEMINI.md",
    "copilot": ".github/copilot-instructions.md",
}

_PADAM_BEGIN = "<!-- PADAM:BEGIN -->"
_PADAM_END = "<!-- PADAM:END -->"
_PII_RE = re.compile(
    r"([A-Za-z]:\\[^\s\"'<>]{2,}|/Users/[^\s\"'<>]+|/home/[^\s\"'<>]+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.I,
)


def _lock_of(memory: Any):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure(memory: Any) -> None:
    if memory is None or getattr(memory, "store", None) is None:
        return
    store = memory.store
    if getattr(store, "_memory_pro_ready", False):
        return
    with store._lock:
        store.conn.executescript(_MPRO_DDL)
        store.conn.commit()
        store._memory_pro_ready = True


def _estimate_tokens(text: str) -> int:
    s = str(text or "")
    if not s:
        return 0
    non_ascii = sum(1 for c in s if ord(c) > 127)
    ascii_cnt = len(s) - non_ascii
    return max(1, int(ascii_cnt / 4.0 + non_ascii / 2.2))


def _trigrams(text: str) -> set[str]:
    norm = re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", str(text or "").lower())).strip()
    if len(norm) < 3:
        return {norm} if norm else set()
    return {norm[i : i + 3] for i in range(len(norm) - 2)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    uni = len(a | b)
    return inter / uni if uni else 0.0


# ---------------------------------------------------------------------------
# Пункт 5: Корзина памяти (30 дней Undo), массовые операции и цветной Diff версий
# ---------------------------------------------------------------------------
def soft_delete_records(memory: Any, record_ids: list[str], *, retain_days: int = 30) -> dict[str, Any]:
    """Перемещает выбранные записи в 30-дневную Корзину (отдельно от необратимого крипто-забвения)."""
    _ensure(memory)
    ids = [str(r).strip() for r in (record_ids or []) if str(r).strip()]
    if not ids:
        return {"ok": True, "moved_count": 0, "bin_ids": []}
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat(timespec="seconds")
    exp_iso = (now + timedelta(days=max(1, min(365, int(retain_days))))).isoformat(timespec="seconds")
    bin_ids: list[str] = []

    with _lock_of(memory):
        conn = memory.store.conn
        for rid in ids:
            row = conn.execute(
                "SELECT id, scope, kind, content, importance, status FROM memory WHERE id = ? AND user_id = ? AND content IS NOT NULL",
                (rid, memory.user_id),
            ).fetchone()
            if row is None:
                continue
            bid = f"bin-{uuid.uuid4().hex[:10]}"
            conn.execute(
                """
                INSERT INTO memory_recycle_bin (
                    bin_id, record_id, user_id, scope, kind, content, importance, prev_status, deleted_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (bid, row["id"], memory.user_id, row["scope"], row["kind"], str(row["content"]), float(row["importance"] or 0.5), row["status"], now_iso, exp_iso),
            )
            conn.execute(
                "UPDATE memory SET status = 'archived' WHERE id = ? AND user_id = ?",
                (row["id"], memory.user_id),
            )
            bin_ids.append(bid)
        conn.commit()
    return {"ok": True, "moved_count": len(bin_ids), "bin_ids": bin_ids, "expires_at": exp_iso}


def list_recycle_bin(memory: Any, *, limit: int = 50) -> dict[str, Any]:
    _ensure(memory)
    lim = max(1, min(200, int(limit)))
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT * FROM memory_recycle_bin WHERE user_id = ? ORDER BY deleted_at DESC LIMIT ?",
            (memory.user_id, lim),
        ).fetchall()
    return {"ok": True, "count": len(rows), "items": [dict(r) for r in rows]}


def restore_from_recycle_bin(memory: Any, bin_id: str) -> dict[str, Any]:
    """Восстанавливает запись из Корзины обратно в активную память."""
    _ensure(memory)
    bid = str(bin_id or "").strip()
    with _lock_of(memory):
        conn = memory.store.conn
        row = conn.execute(
            "SELECT * FROM memory_recycle_bin WHERE bin_id = ? AND user_id = ?",
            (bid, memory.user_id),
        ).fetchone()
        if row is None:
            return {"ok": False, "error": "bin_item_not_found"}
        conn.execute(
            "UPDATE memory SET status = ? WHERE id = ? AND user_id = ?",
            (str(row["prev_status"] or "active"), row["record_id"], memory.user_id),
        )
        conn.execute("DELETE FROM memory_recycle_bin WHERE bin_id = ? AND user_id = ?", (bid, memory.user_id))
        conn.commit()
    return {"ok": True, "restored_record_id": row["record_id"], "bin_id": bid}


def bulk_memory_action(
    memory: Any,
    *,
    record_ids: list[str],
    action: str,
    target_scope: str = "global",
) -> dict[str, Any]:
    """Массовые операции над списком записей: confirm | move_scope | soft_delete | export_md."""
    ids = [str(r).strip() for r in (record_ids or []) if str(r).strip()]
    act = str(action or "").strip().lower()
    if not ids:
        return {"ok": False, "error": "empty_record_ids"}
    if act == "soft_delete":
        return soft_delete_records(memory, ids)
    if act == "move_scope":
        sc = str(target_scope or "global").strip()[:80] or "global"
        with _lock_of(memory):
            conn = memory.store.conn
            cnt = 0
            for rid in ids:
                cur = conn.execute("UPDATE memory SET scope = ? WHERE id = ? AND user_id = ?", (sc, rid, memory.user_id))
                cnt += cur.rowcount
            conn.commit()
        return {"ok": True, "action": act, "updated_count": cnt, "target_scope": sc}
    if act == "confirm":
        now = _utc_now()
        with _lock_of(memory):
            conn = memory.store.conn
            cnt = 0
            for rid in ids:
                cur = conn.execute(
                    "UPDATE memory SET status = 'active', last_confirmed_at = ? WHERE id = ? AND user_id = ? AND content IS NOT NULL",
                    (now, rid, memory.user_id),
                )
                cnt += cur.rowcount
            conn.commit()
        return {"ok": True, "action": act, "confirmed_count": cnt}
    if act == "export_md":
        lines = [f"# Экспорт выбранных записей памяти ({_utc_now()})", ""]
        with _lock_of(memory):
            conn = memory.store.conn
            for rid in ids:
                row = conn.execute(
                    "SELECT id, scope, kind, content, created_at FROM memory WHERE id = ? AND user_id = ?",
                    (rid, memory.user_id),
                ).fetchone()
                if row and row["content"]:
                    clean_c, _ = safety.redact(str(row["content"]))
                    lines.append(f"- **[{row['kind']}]** (`{row['scope']}`, `{row['id']}`, {row['created_at'][:10]}): {clean_c}")
        return {"ok": True, "action": act, "count": len(lines) - 2, "markdown": "\n".join(lines)}
    return {"ok": False, "error": f"unsupported_bulk_action:{act}"}


def diff_record_versions(memory: Any, record_id: str) -> dict[str, Any]:
    """Строит построчный цветной Diff записи относительно предыдущей версии (supersedes) или следующей."""
    rid = str(record_id or "").strip()
    with _lock_of(memory):
        conn = memory.store.conn
        cur = conn.execute(
            "SELECT id, content, kind, scope, created_at, supersedes, superseded_by FROM memory WHERE id = ? AND user_id = ?",
            (rid, memory.user_id),
        ).fetchone()
        if cur is None:
            return {"ok": False, "error": "record_not_found"}
        prev_row = None
        if cur["supersedes"]:
            prev_row = conn.execute(
                "SELECT id, content, created_at FROM memory WHERE id = ? AND user_id = ?",
                (cur["supersedes"], memory.user_id),
            ).fetchone()
        elif cur["superseded_by"]:
            prev_row = cur
            cur = conn.execute(
                "SELECT id, content, kind, scope, created_at, supersedes, superseded_by FROM memory WHERE id = ? AND user_id = ?",
                (cur["superseded_by"], memory.user_id),
            ).fetchone() or cur

    old_text = str((prev_row["content"] if prev_row else "") or "")
    new_text = str(cur["content"] or "")
    diff_lines = list(difflib.unified_diff(old_text.splitlines(), new_text.splitlines(), fromfile="previous", tofile="current", lineterm=""))
    structured = []
    for ln in diff_lines:
        if ln.startswith(("+++", "---", "@@")):
            structured.append({"op": "meta", "line": ln})
        elif ln.startswith("+"):
            structured.append({"op": "add", "line": ln[1:]})
        elif ln.startswith("-"):
            structured.append({"op": "del", "line": ln[1:]})
        else:
            structured.append({"op": "eq", "line": ln[1:] if ln.startswith(" ") else ln})
    return {
        "ok": True,
        "record_id": cur["id"],
        "previous_id": prev_row["id"] if prev_row else "",
        "old_content": old_text,
        "new_content": new_text,
        "has_diff": old_text != new_text,
        "diff": structured,
    }


def revert_record_version(memory: Any, record_id: str, target_version_id: str) -> dict[str, Any]:
    """Откатывает запись к содержимому указанной прошлой версии (создавая новую версию с сохранением цепи)."""
    with _lock_of(memory):
        old = memory.store.conn.execute(
            "SELECT id, content, kind, scope FROM memory WHERE id = ? AND user_id = ? AND content IS NOT NULL",
            (str(target_version_id).strip(), memory.user_id),
        ).fetchone()
    if old is None:
        return {"ok": False, "error": "target_version_not_found"}
    _, new_id = memory.remember(
        str(old["content"]),
        kind=str(old["kind"]),
        scope=str(old["scope"]),
        origin="user",
    )
    return {"ok": True, "reverted_from": record_id, "restored_from_version": old["id"], "new_record_id": new_id}


# ---------------------------------------------------------------------------
# Пункт 6: Авто-генератор файлов инструкций IDE (CLAUDE.md, .cursorrules, AGENTS.md, GEMINI.md)
# ---------------------------------------------------------------------------
def sync_ide_rules_file(
    memory: Any,
    *,
    target: str = "claude",
    project_dir: str = ".",
    scope: str = "global",
    max_items: int = 25,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Генерирует и безопасно обновляет блок <!-- PADAM:BEGIN -->...<!-- PADAM:END --> в файле правил IDE."""
    tgt_key = str(target or "claude").strip().lower()
    rel_file = IDE_RULE_TARGETS.get(tgt_key, tgt_key if tgt_key in IDE_RULE_TARGETS.values() else "CLAUDE.md")
    base = Path(str(project_dir or ".")).expanduser().resolve()
    out_path = (base / rel_file).resolve()
    # Защита от path traversal за пределы project_dir
    if base not in out_path.parents and out_path != base:
        raise ValueError("Целевой файл правил IDE не может выходить за пределы каталога проекта.")

    lim = max(3, min(100, int(max_items)))
    with _lock_of(memory):
        conn = memory.store.conn
        if scope and scope != "all":
            rows = conn.execute(
                "SELECT id, kind, scope, content, importance FROM memory "
                "WHERE user_id = ? AND status = 'active' AND content IS NOT NULL AND scope IN (?, 'global') "
                "ORDER BY CASE kind WHEN 'preference' THEN 0 WHEN 'identity' THEN 1 WHEN 'decision' THEN 2 ELSE 3 END, importance DESC, created_at DESC LIMIT ?",
                (memory.user_id, scope, lim),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, kind, scope, content, importance FROM memory "
                "WHERE user_id = ? AND status = 'active' AND content IS NOT NULL "
                "ORDER BY importance DESC, created_at DESC LIMIT ?",
                (memory.user_id, lim),
            ).fetchall()

    bullets = [
        _PADAM_BEGIN,
        f"## PADAM Verified Project Rules & Decisions (scope={scope}, synced={_utc_now()})",
        "_Авто-синхронизация из подтверждённой памяти PADAM (секреты и PII очищены)._",
        "",
    ]
    included = 0
    for r in rows:
        txt, _ = safety.redact(str(r["content"]))
        txt = _PII_RE.sub("[REDACTED]", txt).replace("\n", " ").strip()
        if not txt or safety.looks_like_instruction(txt):
            continue
        bullets.append(f"- **[{r['kind']}]** {txt[:260]}")
        included += 1
    bullets.append(_PADAM_END)
    block = "\n".join(bullets)

    existing = out_path.read_text(encoding="utf-8", errors="replace") if out_path.exists() else ""
    if _PADAM_BEGIN in existing and _PADAM_END in existing:
        pattern = re.compile(re.escape(_PADAM_BEGIN) + r".*?" + re.escape(_PADAM_END), re.S)
        new_full = pattern.sub(block, existing, count=1)
    else:
        sep = "\n\n" if existing.strip() else ""
        new_full = existing.rstrip() + sep + block + "\n"

    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(new_full, encoding="utf-8")
        audit_chain.append_audit(memory, "ide_rules_synced", {"file": str(out_path), "items": included, "scope": scope}, agent_id="owner")

    return {
        "ok": True,
        "target": tgt_key,
        "path": str(out_path),
        "included_rules": included,
        "dry_run": bool(dry_run),
        "preview": block,
    }


# ---------------------------------------------------------------------------
# Пункт 7: «Контекстный Компас» — упаковка ответа MCP строго под бюджет токенов
# ---------------------------------------------------------------------------
def compose_token_budget_context(
    memory: Any,
    *,
    query: str,
    max_tokens: int = 1200,
    scope: str | None = None,
) -> dict[str, Any]:
    """Собирает компактный, без дублей контекстный брифинг ровно в бюджет max_tokens и считает % экономии."""
    q = str(query or "").strip()
    budget = max(120, min(16000, int(max_tokens or 1200)))
    raw_items: list[dict[str, Any]] = []
    if q:
        try:
            res = memory.recall(q, scope=scope, limit=25)
            for item in res:
                raw_items.append({
                    "id": item.id if hasattr(item, "id") else item.get("id"),
                    "kind": item.kind if hasattr(item, "kind") else item.get("kind", "fact"),
                    "content": item.content if hasattr(item, "content") else item.get("content", ""),
                })
        except Exception:
            pass
    if not raw_items:
        with _lock_of(memory):
            rows = memory.store.conn.execute(
                "SELECT id, kind, content FROM memory WHERE user_id = ? AND status = 'active' AND content IS NOT NULL "
                "ORDER BY importance DESC, created_at DESC LIMIT 25",
                (memory.user_id,),
            ).fetchall()
            raw_items = [dict(r) for r in rows]

    # Открытые обещания Семьи для полноты брифинга
    open_comms = []
    try:
        ark._ensure_tables(memory)
        with _lock_of(memory):
            c_rows = memory.store.conn.execute(
                "SELECT title, status FROM ark_commitment WHERE user_id = ? AND status IN ('open', 'in_progress') LIMIT 8",
                (memory.user_id,),
            ).fetchall()
            open_comms = [dict(c) for c in c_rows]
    except Exception:
        pass

    raw_text_total = "\n".join(str(x.get("content") or "") for x in raw_items)
    raw_tokens = max(1, _estimate_tokens(raw_text_total))

    packed_lines: list[str] = [f"# PADAM Context Compass (budget={budget} tok)"]
    used_tokens = _estimate_tokens(packed_lines[0])
    seen_grams: list[set[str]] = []
    kept_ids: list[str] = []
    deduped = 0

    for item in raw_items:
        clean_c, _ = safety.redact(str(item.get("content") or "").strip())
        if not clean_c:
            continue
        tg = _trigrams(clean_c)
        if any(_jaccard(tg, prev) >= 0.72 for prev in seen_grams):
            deduped += 1
            continue
        line = f"- [{item.get('kind', 'fact')}] {clean_c[:320]}"
        tok = _estimate_tokens(line)
        if used_tokens + tok > budget - 40:
            break
        packed_lines.append(line)
        seen_grams.append(tg)
        kept_ids.append(str(item.get("id") or ""))
        used_tokens += tok

    if open_comms and used_tokens < budget - 30:
        packed_lines.append("## Open Commitments:")
        for cm in open_comms:
            line = f"- [commitment:{cm['status']}] {str(cm['title'])[:140]}"
            tok = _estimate_tokens(line)
            if used_tokens + tok > budget:
                break
            packed_lines.append(line)
            used_tokens += tok

    packed_text = "\n".join(packed_lines)
    packed_tokens = _estimate_tokens(packed_text)
    saved_pct = round(max(0.0, (1.0 - packed_tokens / max(1, raw_tokens)) * 100.0), 1)
    return {
        "ok": True,
        "query": q,
        "budget_tokens": budget,
        "raw_tokens_estimate": raw_tokens,
        "packed_tokens_estimate": packed_tokens,
        "saved_pct": saved_pct,
        "records_considered": len(raw_items),
        "records_packed": len(kept_ids),
        "duplicates_dropped": deduped,
        "kept_ids": kept_ids,
        "context_block": packed_text,
    }


# ---------------------------------------------------------------------------
# Пункт 8: «Санитар памяти» — детектор устаревших записей и авто-дедупликатор
# ---------------------------------------------------------------------------
def scan_memory_hygiene(
    memory: Any,
    *,
    stale_days: int = 90,
    sim_threshold: float = 0.72,
    limit: int = 400,
) -> dict[str, Any]:
    """Ищет кластеры похожих дублей и устаревшие записи старше stale_days с 0 обращений."""
    lim = max(10, min(2000, int(limit)))
    thr = max(0.5, min(0.98, float(sim_threshold)))
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=max(1, int(stale_days)))).isoformat(timespec="seconds")

    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT id, scope, kind, content, created_at, last_seen_at, access_count, importance "
            "FROM memory WHERE user_id = ? AND status = 'active' AND content IS NOT NULL "
            "ORDER BY created_at DESC LIMIT ?",
            (memory.user_id, lim),
        ).fetchall()

    stale: list[dict[str, Any]] = []
    grams_list: list[tuple[dict[str, Any], set[str]]] = []
    for r in rows:
        d = dict(r)
        if int(d.get("access_count") or 0) == 0 and str(d.get("created_at") or "") < cutoff_iso and d["kind"] not in ("identity", "preference"):
            stale.append({"id": d["id"], "kind": d["kind"], "scope": d["scope"], "created_at": d["created_at"], "preview": str(d["content"])[:120]})
        grams_list.append((d, _trigrams(str(d["content"]))))

    used: set[str] = set()
    clusters: list[dict[str, Any]] = []
    for i, (di, gi) in enumerate(grams_list):
        if di["id"] in used or not gi:
            continue
        group = [di]
        for j in range(i + 1, len(grams_list)):
            dj, gj = grams_list[j]
            if dj["id"] in used or dj["scope"] != di["scope"]:
                continue
            if _jaccard(gi, gj) >= thr:
                group.append(dj)
                used.add(dj["id"])
        if len(group) >= 2:
            used.add(di["id"])
            clusters.append({
                "scope": di["scope"],
                "kind": di["kind"],
                "size": len(group),
                "record_ids": [g["id"] for g in group],
                "canonical_preview": str(group[0]["content"])[:160],
            })

    return {
        "ok": True,
        "scanned_records": len(rows),
        "duplicate_clusters_count": len(clusters),
        "duplicate_records_extra": sum(c["size"] - 1 for c in clusters),
        "stale_records_count": len(stale),
        "duplicate_clusters": clusters[:40],
        "stale_records": stale[:40],
    }


def merge_duplicate_cluster(
    memory: Any,
    *,
    record_ids: list[str],
    canonical_content: str = "",
) -> dict[str, Any]:
    """Склеивает кластер дублей в одну каноническую запись, перенося лишние в 30-дневную Корзину."""
    ids = [str(r).strip() for r in (record_ids or []) if str(r).strip()]
    if len(ids) < 2:
        return {"ok": False, "error": "need_at_least_2_records"}
    with _lock_of(memory):
        rows = [
            memory.store.conn.execute(
                "SELECT id, scope, kind, content FROM memory WHERE id = ? AND user_id = ? AND content IS NOT NULL",
                (rid, memory.user_id),
            ).fetchone()
            for rid in ids
        ]
    valid = [dict(r) for r in rows if r is not None]
    if len(valid) < 2:
        return {"ok": False, "error": "records_not_found"}

    # Выбираем самую длинную/информативную запись как канон, если не задан свой текст
    valid.sort(key=lambda x: len(str(x["content"])), reverse=True)
    keep = valid[0]
    drop_ids = [v["id"] for v in valid[1:]]
    if canonical_content.strip():
        clean_new, _ = safety.redact(canonical_content.strip())
        with _lock_of(memory):
            memory.store.conn.execute(
                "UPDATE memory SET content = ?, last_confirmed_at = ? WHERE id = ? AND user_id = ?",
                (clean_new, _utc_now(), keep["id"], memory.user_id),
            )
            memory.store.conn.commit()
    bin_res = soft_delete_records(memory, drop_ids)
    audit_chain.append_audit(memory, "memory_duplicates_merged", {"kept_id": keep["id"], "archived_ids": drop_ids}, agent_id="owner")
    return {
        "ok": True,
        "kept_record_id": keep["id"],
        "archived_count": bin_res["moved_count"],
        "bin_ids": bin_res["bin_ids"],
    }


# ---------------------------------------------------------------------------
# Пункт 10: Визуальный проводник /memories и мост с Obsidian Vault
# ---------------------------------------------------------------------------
def list_virtual_memory_tree(memory: Any, *, limit: int = 120) -> dict[str, Any]:
    """Строит иерархическое дерево /memories/{scope}/{kind}/... с wikilinks для двухпанельного проводника Studio."""
    lim = max(1, min(500, int(limit)))
    with _lock_of(memory):
        rows = memory.store.conn.execute(
            "SELECT id, scope, kind, content, created_at FROM memory "
            "WHERE user_id = ? AND status = 'active' AND content IS NOT NULL ORDER BY scope ASC, kind ASC, created_at DESC LIMIT ?",
            (memory.user_id, lim),
        ).fetchall()
    tree: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for r in rows:
        sc = str(r["scope"] or "global")
        kd = str(r["kind"] or "fact")
        txt = str(r["content"] or "")
        first = (txt.strip().splitlines() or ["note"])[0][:48]
        slug = re.sub(r"[^\w\-]+", "_", first, flags=re.UNICODE).strip("_")[:32] or "note"
        vpath = f"/memories/{sc}/{kd}/{slug}__{str(r['id'])[:8]}.md"
        wikis = re.findall(r"\[\[([^\]|#]+)\]\]", txt)
        tree.setdefault(sc, {}).setdefault(kd, []).append({
            "id": r["id"],
            "path": vpath,
            "title": first,
            "preview": txt[:400],
            "wikilinks": wikis,
            "created_at": r["created_at"],
        })
    return {"ok": True, "scopes_count": len(tree), "files_count": len(rows), "tree": tree}


def run_obsidian_bridge(
    memory: Any,
    *,
    vault_path: str,
    direction: str = "export",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Удобный мост двусторонней синхронизации с локальной папкой Obsidian Vault."""
    vp = Path(str(vault_path or "")).expanduser().resolve()
    d = str(direction or "export").strip().lower()
    if dry_run:
        md_count = len(list(vp.rglob("*.md"))) if vp.exists() and vp.is_dir() else 0
        tree = list_virtual_memory_tree(memory, limit=200)
        return {
            "ok": True,
            "dry_run": True,
            "vault_path": str(vp),
            "vault_exists": vp.exists(),
            "vault_md_files": md_count,
            "padam_active_records": tree["files_count"],
        }
    if d not in ("both", "export", "import"):
        d = "export"
    vp.mkdir(parents=True, exist_ok=True)
    res = obsidian_sync.sync_obsidian(memory, vp, direction=d, trusted_owner=True, force=True)
    return {"ok": True, "direction": d, **res}


# ---------------------------------------------------------------------------
# Пункт 17: Командная память через Git (.padam/team-memory.json без конфликтов)
# ---------------------------------------------------------------------------
def export_git_team_memory(
    memory: Any,
    *,
    scope: str = "global",
    repo_dir: str = ".",
    out_rel: str = ".padam/team-memory.json",
) -> dict[str, Any]:
    """Экспортирует очищенные командные знания в детерминированно отсортированный JSON для Git."""
    base = Path(str(repo_dir or ".")).expanduser().resolve()
    out_path = (base / out_rel).resolve()
    if base not in out_path.parents and out_path != base:
        raise ValueError("Путь .padam/team-memory.json должен находиться внутри репозитория.")

    with _lock_of(memory):
        if scope and scope != "all":
            rows = memory.store.conn.execute(
                "SELECT id, scope, kind, content, importance, created_at FROM memory "
                "WHERE user_id = ? AND status = 'active' AND content IS NOT NULL AND scope = ? ORDER BY id ASC",
                (memory.user_id, scope),
            ).fetchall()
        else:
            rows = memory.store.conn.execute(
                "SELECT id, scope, kind, content, importance, created_at FROM memory "
                "WHERE user_id = ? AND status = 'active' AND content IS NOT NULL ORDER BY id ASC",
                (memory.user_id,),
            ).fetchall()

    records = []
    for r in rows:
        txt, _ = safety.redact(str(r["content"]))
        txt = _PII_RE.sub("[REDACTED]", txt)
        if safety.looks_like_instruction(txt):
            continue
        records.append({
            "id": str(r["id"]),
            "scope": str(r["scope"]),
            "kind": str(r["kind"]),
            "content": txt,
            "importance": round(float(r["importance"] or 0.5), 3),
            "created_at": str(r["created_at"]),
        })

    payload = {
        "schema": "padam-git-team-memory/1.0",
        "scope": scope,
        "count": len(records),
        "records": records,
    }
    key, _ = integrity.owner_key(memory.store)
    canon = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["pack_hmac_sha256"] = hmac.new(key, canon.encode("utf-8"), hashlib.sha256).hexdigest()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"ok": True, "path": str(out_path), "exported_count": len(records), "pack_hmac_sha256": payload["pack_hmac_sha256"]}


def import_git_team_memory(
    memory: Any,
    *,
    file_path: str,
    guarded: bool = True,
) -> dict[str, Any]:
    """Импортирует командный .padam/team-memory.json после git pull (без дублей, с проверкой инъекций)."""
    fp = Path(str(file_path or "")).expanduser().resolve()
    if not fp.is_file():
        return {"ok": False, "error": "team_memory_file_not_found", "path": str(fp)}
    data = json.loads(fp.read_text(encoding="utf-8"))
    recs = data.get("records") or []
    imported = 0
    skipped = 0
    blocked = 0
    for rec in recs:
        content = str(rec.get("content") or "").strip()
        if not content:
            continue
        clean, _ = safety.redact(content)
        if safety.looks_like_instruction(clean) or safety.changes_owner_or_rules(clean):
            blocked += 1
            continue
        # Не дублируем уже существующий идентичный текст в том же scope
        sc = str(rec.get("scope") or "global")
        with _lock_of(memory):
            exists = memory.store.conn.execute(
                "SELECT 1 FROM memory WHERE user_id = ? AND scope = ? AND content = ? AND status = 'active' LIMIT 1",
                (memory.user_id, sc, clean),
            ).fetchone()
        if exists:
            skipped += 1
            continue
        memory.remember(clean, kind=str(rec.get("kind") or "fact"), scope=sc, origin="external" if guarded else "user", guarded=guarded)
        imported += 1
    return {"ok": True, "path": str(fp), "imported": imported, "skipped_existing": skipped, "blocked_injections": blocked}
