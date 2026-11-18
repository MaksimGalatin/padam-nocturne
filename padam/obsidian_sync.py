"""Двусторонняя синхронизация с Markdown / Obsidian Vault.

Особенности:
- Экспорт активных (не карантинных) записей в `.md` файлы с frontmatter (`id`, `kind`, `scope`, `sha256`) и `[[wikilinks]]` по `memory_link`.
- Импорт новых и изменённых `.md` файлов через `guarded=True` (защита от инъекций).
- Защищённые виды (`identity`, `preference`, `rule`) без подтверждения владельца (`trusted_owner=True`) не перезаписываются напрямую, а отправляются в карантин/на подтверждение.
- Двусторонний парсинг `[[ссылок]]` <-> рёбра `memory_link`.
- Исчезновение `.md` файла НЕ приводит к молчаливому удалению из БД: запись помечается в списке `pending_delete_confirmation`.

По умолчанию выключено (PADAM_OBSIDIAN_SYNC=0).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config
from .memory import Memory

PROTECTED_KINDS = ("identity", "preference", "rule")
WIKILINK_RE = re.compile(r"\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")
FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n?", re.DOTALL)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _safe_filename(rec_id: str, content: str) -> str:
    first_line = (content.strip().splitlines() or ["note"])[0]
    slug = re.sub(r"[^\w\-]+", "_", first_line, flags=re.UNICODE).strip("_")[:40] or "note"
    return f"{slug}__{rec_id[:8]}.md"


def _parse_markdown(raw: str) -> tuple[dict[str, str], str]:
    m = FRONTMATTER_RE.match(raw)
    meta: dict[str, str] = {}
    body = raw
    if m:
        fm_block = m.group(1)
        body = raw[m.end():]
        for line in fm_block.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip().strip('"').strip("'")
    return meta, body.strip()


def _render_markdown(rec_id: str, kind: str, scope: str, body: str, links: list[str]) -> str:
    body_clean = body.strip()
    lines = [
        "---",
        f"id: {rec_id}",
        f"kind: {kind}",
        f"scope: {scope}",
        f"sha256: {_sha256(body_clean)}",
        "---",
        "",
        body_clean,
    ]
    existing_links = set(WIKILINK_RE.findall(body_clean))
    extra = [lnk for lnk in links if lnk not in existing_links]
    if extra:
        lines.append("")
        lines.append("Links: " + " ".join(f"[[{lnk}]]" for lnk in extra))
    return "\n".join(lines) + "\n"


def _ensure_state_table(mem: Memory) -> None:
    mem.store.execute(
        """CREATE TABLE IF NOT EXISTS obsidian_sync_state (
               rec_id TEXT PRIMARY KEY,
               rel_path TEXT NOT NULL,
               last_sha256 TEXT NOT NULL,
               synced_at TEXT NOT NULL
           )"""
    )


def sync_obsidian(
    mem: Memory,
    vault_dir: Path | str,
    *,
    scope: str | None = None,
    direction: str = "both",
    trusted_owner: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Синхронизирует папку Obsidian/Markdown с базой памяти PADAM."""
    if not force and not config.mcp_obsidian_sync_enabled():
        return {"enabled": False, "exported": 0, "imported": 0, "updated": 0, "links_added": 0, "pending_delete_confirmation": []}

    root = Path(vault_dir)
    root.mkdir(parents=True, exist_ok=True)
    _ensure_state_table(mem)

    clean_dir = (direction or "both").strip().lower()
    if clean_dir not in ("both", "export", "import"):
        raise ValueError(f"Unsupported sync direction: {direction}")

    exported = 0
    imported = 0
    updated = 0
    quarantined_protected = 0
    links_added = 0
    pending_deletes: list[dict[str, Any]] = []

    state_rows = {r["rec_id"]: dict(r) for r in mem.store.query("SELECT rec_id, rel_path, last_sha256 FROM obsidian_sync_state")}

    # 1. Импорт правок и новых файлов из папки .md
    md_files = sorted(p for p in root.rglob("*.md") if not p.name.startswith("."))
    seen_rec_ids: set[str] = set()
    title_to_id: dict[str, str] = {}
    parsed_docs: list[tuple[Path, dict[str, str], str, str]] = []

    if clean_dir in ("both", "import"):
        for md_path in md_files:
            raw = md_path.read_text(encoding="utf-8")
            meta, body = _parse_markdown(raw)
            if not body:
                continue
            stem_key = md_path.stem.split("__")[0].strip().lower()
            rec_id = (meta.get("id") or "").strip()
            rec_kind = (meta.get("kind") or "fact").strip().lower()
            rec_scope = (meta.get("scope") or scope or "global").strip()

            if rec_id:
                seen_rec_ids.add(rec_id)
                title_to_id[md_path.stem.lower()] = rec_id
                title_to_id[stem_key] = rec_id
                title_to_id[rec_id.lower()] = rec_id
                existing = mem.store.one(
                    "SELECT id, kind, scope, content, status FROM memory WHERE id = ? AND user_id = ?",
                    (rec_id, mem.user_id),
                )
                body_hash = _sha256(body)
                prev_hash = (state_rows.get(rec_id) or {}).get("last_sha256")
                if existing is not None and body_hash != _sha256(existing["content"].strip()) and body_hash != prev_hash:
                    if existing["kind"] in PROTECTED_KINDS and not trusted_owner:
                        _, qid = mem.remember(
                            body,
                            kind=existing["kind"],
                            scope=existing["scope"],
                            origin="obsidian",
                            guarded=True,
                            agent_id="obsidian-sync",
                        )
                        mem.store.execute(
                            "UPDATE memory SET status='quarantined', quarantine_reason='obsidian_protected_kind_needs_owner_sig' WHERE id=?",
                            (qid,),
                        )
                        quarantined_protected += 1
                    else:
                        # Фаза 2 аудита GLM, CONN-02: раньше UPDATE content ставил текст файла действующим без проверки.
                        # Теперь два пути. Заметка с признаками приказа или атаки (те же проверки, что у
                        # remember(guarded=True)) не трогает запись: новая версия идёт через охраняемый remember и
                        # оседает в карантине. Чистая правка обновляет ту же запись — секреты при этом маскируются.
                        from . import guard as _guard, safety as _safety
                        if not trusted_owner and (_safety.looks_like_instruction(body) or _guard.flags(body)):
                            mem.remember(body, kind=existing["kind"], scope=existing["scope"],
                                         origin="obsidian", guarded=True, agent_id="obsidian-sync")
                        else:
                            clean_body, _red = _safety.redact(body)
                            mem.store.execute(
                                "UPDATE memory SET content=?, content_hash=?, last_seen_at=? WHERE id=?",
                                (clean_body, _sha256(clean_body) if clean_body != body else body_hash, _utc_now(), rec_id),
                            )
                        mem.store.execute(
                            """INSERT INTO obsidian_sync_state (rec_id, rel_path, last_sha256, synced_at)
                               VALUES (?, ?, ?, ?)
                               ON CONFLICT(rec_id) DO UPDATE SET rel_path=excluded.rel_path, last_sha256=excluded.last_sha256, synced_at=excluded.synced_at""",
                            (rec_id, str(md_path.relative_to(root)), body_hash, _utc_now()),
                        )
                        updated += 1
                parsed_docs.append((md_path, meta, body, rec_id))
            else:
                # Новый файл без id в frontmatter
                if rec_kind in PROTECTED_KINDS and not trusted_owner:
                    _, new_id = mem.remember(
                        body,
                        kind=rec_kind,
                        scope=rec_scope,
                        origin="obsidian",
                        guarded=True,
                        agent_id="obsidian-sync",
                    )
                    mem.store.execute(
                        "UPDATE memory SET status='quarantined', quarantine_reason='obsidian_protected_kind_needs_owner_sig' WHERE id=?",
                        (new_id,),
                    )
                    quarantined_protected += 1
                else:
                    _, new_id = mem.remember(
                        body,
                        kind=rec_kind,
                        scope=rec_scope,
                        origin="obsidian",
                        guarded=True,
                        agent_id="obsidian-sync",
                    )
                    imported += 1
                seen_rec_ids.add(new_id)
                title_to_id[md_path.stem.lower()] = new_id
                title_to_id[stem_key] = new_id
                title_to_id[new_id.lower()] = new_id
                body_hash = _sha256(body)
                mem.store.execute(
                    """INSERT INTO obsidian_sync_state (rec_id, rel_path, last_sha256, synced_at)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(rec_id) DO UPDATE SET rel_path=excluded.rel_path, last_sha256=excluded.last_sha256, synced_at=excluded.synced_at""",
                    (new_id, str(md_path.relative_to(root)), body_hash, _utc_now()),
                )
                parsed_docs.append((md_path, meta, body, new_id))

        # Проверка исчезнувших файлов — НЕ удаляем молча из БД
        for rid, st in state_rows.items():
            if rid not in seen_rec_ids:
                expected_file = root / st["rel_path"]
                if not expected_file.exists():
                    pending_deletes.append({"id": rid, "missing_path": st["rel_path"], "action": "owner_confirm_required"})

        # Двусторонний разбор [[wikilinks]] -> рёбра memory_link
        for md_path, meta, body, src_id in parsed_docs:
            for target_raw in WIKILINK_RE.findall(body):
                key = target_raw.strip().lower()
                dst_id = title_to_id.get(key)
                if not dst_id and key.startswith("padam:"):
                    cand = key.split(":", 1)[1].strip()
                    row = mem.store.one("SELECT id FROM memory WHERE id = ? AND user_id = ?", (cand, mem.user_id))
                    if row:
                        dst_id = row["id"]
                if dst_id and dst_id != src_id:
                    exists = mem.store.one(
                        "SELECT 1 FROM memory_link WHERE src = ? AND dst = ? AND relation = 'wikilink'",
                        (src_id, dst_id),
                    )
                    if not exists:
                        mem.store.execute(
                            "INSERT OR IGNORE INTO memory_link (src, dst, relation, created_at) VALUES (?, ?, 'wikilink', ?)",
                            (src_id, dst_id, _utc_now()),
                        )
                        links_added += 1

    # 2. Экспорт активных записей в .md файлы
    if clean_dir in ("both", "export"):
        sql = (
            "SELECT id, kind, scope, content FROM memory "
            "WHERE user_id = ? AND status = 'active' AND (quarantine_reason IS NULL OR quarantine_reason = '') "
        )
        params: list[Any] = [mem.user_id]
        if scope is not None:
            sql += "AND scope = ? "
            params.append(scope)
        sql += "ORDER BY created_at ASC"
        rows = mem.store.query(sql, tuple(params))

        for row in rows:
            rid = row["id"]
            st = state_rows.get(rid)
            out_path = (root / st["rel_path"]) if st else (root / _safe_filename(rid, row["content"]))
            if not out_path.exists() and rid in state_rows:
                # Файл удалён пользователем в Obsidian — не воскрешаем молча, ждём подтверждения
                continue
            link_rows = mem.store.query("SELECT dst FROM memory_link WHERE src = ?", (rid,))
            link_targets = [f"padam:{lr['dst']}" for lr in link_rows]
            rendered = _render_markdown(rid, row["kind"], row["scope"], row["content"], link_targets)
            body_hash = _sha256(row["content"].strip())
            if not out_path.exists() or out_path.read_text(encoding="utf-8") != rendered:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(rendered, encoding="utf-8")
                exported += 1
            mem.store.execute(
                """INSERT INTO obsidian_sync_state (rec_id, rel_path, last_sha256, synced_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(rec_id) DO UPDATE SET rel_path=excluded.rel_path, last_sha256=excluded.last_sha256, synced_at=excluded.synced_at""",
                (rid, str(out_path.relative_to(root)), body_hash, _utc_now()),
            )

    return {
        "enabled": True,
        "vault_dir": str(root),
        "direction": clean_dir,
        "exported": exported,
        "imported": imported,
        "updated": updated,
        "quarantined_protected": quarantined_protected,
        "links_added": links_added,
        "pending_delete_confirmation": pending_deletes,
    }
