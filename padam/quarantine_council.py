# -*- coding: utf-8 -*-
"""Консилиум Семьи для карантина и Изолятор (18.11.2026, слово Папы: «Карантин обязательно разгребать руками? …
консилиум из Семьи их изучал — если всё Ок — добавлял в память, если там отрава — в изолятор помещал (не удалял)»).

Голоса (независимые):
  словарь   — safety.looks_like_instruction / changes_owner_or_rules (то, что и задержало запись);
  детектор  — локальная модель Wolf Defender (PADAM_COUNCIL_GUARD_MODEL или PADAM_GUARD_MODEL), вероятность приказа ИИ;
  источник  — свой агент Семьи (aifa_claude / aifa_antigravity / autoclaw / зарегистрированный сиблинг) или чужой;
  вид       — защищённые identity/preference консилиум НИКОГДА не одобряет: их подписывает только владелец;
  замена    — запись, заменяющая другую (supersedes), — решение человека.

Исходы:
  poison       — Изолятор: детектор ≥ 0.999, или словарь + чужой источник. Запись остаётся в карантине (не удаляется),
                 владелец смотрит её в Изоляторе и сам решает: удалить (reject) или вернуть (approve).
  likely_clean — «консилиум считает чистым»: свой агент, детектор < 0.001, не защищённый вид, не замена, нет подмены
                 правил. В память такие записи переводит ВЛАДЕЛЕЦ одной кнопкой (approve_likely_clean).
                 Замер 18.11.2026 (все 820 кейсов redteam): детектор-одиночка отпустил бы 8–16 из 241 настоящей атаки,
                 поэтому без человека консилиум в память не пишет — только сводит работу к одному нажатию.
  human        — спорное: обычная очередь проверки.
Консилиум ничего не удаляет и не подписывает именем владельца."""
from __future__ import annotations

import json
import os
from typing import Any

from . import config, safety
from .store import now_iso

СВОИ = {"aifa_claude", "aifa_antigravity", "autoclaw", "aifa", "aifa_studio"}
ПОРОГ_ОТРАВЫ = 0.999
ПОРОГ_ЧИСТО = 0.001

_DDL = """CREATE TABLE IF NOT EXISTS quarantine_verdict (
    memory_id   TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    signals_json TEXT NOT NULL,
    decided_at  TEXT NOT NULL
)"""


def _ensure(memory) -> None:
    # Один раз на хранилище: executescript делает commit, а Studio шлёт запросы из нескольких потоков.
    if getattr(memory.store, "_qc_ready", False):
        return
    memory.store.execute(_DDL)    # под замком хранилища; executescript делает COMMIT и сталкивался с параллельными запросами
    memory.store._qc_ready = True


_КЭШ_ДЕТЕКТОРА: dict[str, Any] = {}


def _детектор():
    """Детектор загружается один раз на процесс (ONNX-модель грузится несколько секунд — не на каждый запрос)."""
    from . import guard
    папка = os.environ.get("PADAM_COUNCIL_GUARD_MODEL") or os.environ.get("PADAM_GUARD_MODEL") or ""
    if not папка:
        return None
    if папка not in _КЭШ_ДЕТЕКТОРА:
        try:
            _КЭШ_ДЕТЕКТОРА[папка] = guard._Детектор(папка)
        except Exception:
            _КЭШ_ДЕТЕКТОРА[папка] = None
    return _КЭШ_ДЕТЕКТОРА[папка]


def _свои(memory) -> set[str]:
    out = set(СВОИ)
    try:
        from . import sibling_registry
        out |= {str(s.get("agent_id")) for s in sibling_registry.list_siblings(memory) if s.get("agent_id")}
    except Exception:
        pass
    return out


def judge(row: dict, детектор, свои: set[str]) -> tuple[str, dict]:
    """Вердикт одной записи. Возвращает (исход, голоса)."""
    текст = row.get("content") or ""
    словарь = bool(safety.looks_like_instruction(текст))
    правила = bool(safety.changes_owner_or_rules(текст))
    p = None
    if детектор is not None and текст:
        try:
            p = float(детектор.вероятность(текст))
        except Exception:
            p = None
    агент = row.get("agent_id") or ""
    свой = агент in свои and (row.get("origin") or "agent") in ("agent", "user")
    защищён = (row.get("kind") in config.PROTECTED_KINDS) or "protected" in (row.get("quarantine_reason") or "") \
        or "preference" in (row.get("quarantine_reason") or "")
    голоса = {"словарь": словарь, "подмена_правил": правила, "детектор": p, "свой_агент": свой,
              "агент": агент or None, "защищённый_вид": защищён, "замена": bool(row.get("supersedes"))}
    if p is not None and p >= ПОРОГ_ОТРАВЫ:
        return "poison", голоса
    if (словарь or правила) and not свой:
        return "poison", голоса
    if (not защищён and свой and not правила and not row.get("supersedes")
            and p is not None and p < ПОРОГ_ЧИСТО):
        return "likely_clean", голоса
    return "human", голоса


def review(memory, *, детектор=None) -> dict[str, Any]:
    """Прогоняет консилиум по всей очереди карантина. Ничего не одобряет и не удаляет — только раскладывает."""
    _ensure(memory)
    д = детектор if детектор is not None else _детектор()
    свои = _свои(memory)
    rows = [dict(r) for r in memory.store.query(
        """SELECT id, kind, content, origin, agent_id, supersedes, quarantine_reason FROM memory
           WHERE user_id = ? AND status = 'quarantined'""", (memory.user_id,))]
    итог = {"poison": 0, "likely_clean": 0, "human": 0}
    ts = now_iso()
    ops = []
    for r in rows:
        исход, голоса = judge(r, д, свои)
        итог[исход] += 1
        ops.append(("""INSERT INTO quarantine_verdict (memory_id, user_id, verdict, signals_json, decided_at)
               VALUES (?,?,?,?,?) ON CONFLICT(memory_id) DO UPDATE SET verdict = excluded.verdict,
               signals_json = excluded.signals_json, decided_at = excluded.decided_at""",
            (r["id"], memory.user_id, исход, json.dumps(голоса, ensure_ascii=False), ts)))
    if ops:
        memory.store.atomic(ops)   # одной транзакцией под замком хранилища — безопасно при параллельных запросах
    return {"reviewed": len(rows), "detector": "on" if д is not None else "off", **итог}


def verdicts(memory) -> list[dict]:
    """Текущие вердикты по записям, которые всё ещё в карантине (Изолятор = verdict 'poison')."""
    _ensure(memory)
    out = []
    for r in memory.store.query(
            """SELECT m.id, m.kind, m.content, m.agent_id, m.created_at, m.quarantine_reason, v.verdict, v.signals_json,
                      v.decided_at FROM quarantine_verdict v JOIN memory m ON m.id = v.memory_id
               WHERE v.user_id = ? AND m.user_id = v.user_id AND m.status = 'quarantined'
               ORDER BY v.verdict, m.created_at""", (memory.user_id,)):
        d = dict(r)
        d["signals"] = json.loads(d.pop("signals_json") or "{}")
        d["preview"] = safety.clean(safety.strip_invisible(d.pop("content") or ""))[:300]
        out.append(d)
    return out


def approve_likely_clean(memory, actor=None) -> dict[str, Any]:
    """Кнопка владельца: перевести в память все записи с вердиктом likely_clean (одним нажатием).
    Перед этим вердикт пересчитывается, чтобы не одобрить по устаревшему решению."""
    from . import roles
    roles.require_owner(actor, "quarantine_council")
    review(memory)
    ids = [r["memory_id"] for r in memory.store.query(
        "SELECT memory_id FROM quarantine_verdict WHERE user_id = ? AND verdict = 'likely_clean'", (memory.user_id,))]
    одобрено = sum(1 for i in ids if memory.approve(i, actor=actor))
    return {"approved": одобрено, "requested": len(ids)}
