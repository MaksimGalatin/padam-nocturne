"""NOCTURNE — консолидация L1 → L2.

Четыре ограничителя против переобучения на редких острых эпизодах:

  1. importance sampling — коррекция смещения приоритетной выборки
  2. cap             — потолок доли острых эпизодов в батче
  3. priority decay  — распад приоритета после переигрывания
  4. priority floor  — пол приоритета, чтобы рутина не исчезала
"""

from __future__ import annotations

import math
from collections import Counter

import numpy as np

from . import classify, config, safety
from .memory import Memory
from .store import new_id, now_iso


# --- вспомогательные функции ------------------------------------------

def apply_floor(p: np.ndarray) -> np.ndarray:
    """(4) Пол приоритета: обычное не исчезает из выборки совсем."""
    if p.size == 0:
        return p
    return np.maximum(p, config.P_FLOOR_RATIO * float(np.median(p)))


def probabilities(p: np.ndarray, alpha: float = config.ALPHA) -> np.ndarray:
    pa = np.power(np.maximum(p, 1e-12), alpha)
    s = pa.sum()
    return pa / s if s > 0 else np.full_like(pa, 1.0 / len(pa))


def importance_weights(probs: np.ndarray, n: int, beta: float) -> np.ndarray:
    """(1) w = (1/(N·P))^β, нормировано на максимум."""
    w = np.power(1.0 / (n * np.maximum(probs, 1e-12)), beta)
    m = w.max()
    return w / m if m > 0 else w


def beta_for(run_index: int, total: int = 100) -> float:
    frac = min(run_index / max(total, 1), 1.0)
    return config.BETA_START + (config.BETA_END - config.BETA_START) * frac


def entropy_ratio(counts: Counter) -> float:
    total = sum(counts.values())
    if total == 0 or len(counts) <= 1:
        return 0.0
    h = -sum((c / total) * math.log(c / total) for c in counts.values() if c)
    return h / math.log(len(counts))


def stratified(kinds: list[str], pool: np.ndarray, n: int,
               rng: np.random.Generator) -> list[int]:
    """Равномерно по типам, чтобы редкие не вымывались."""
    if n <= 0 or pool.size == 0:
        return []
    groups: dict[str, list[int]] = {}
    for i in pool:
        groups.setdefault(kinds[int(i)], []).append(int(i))

    picked: list[int] = []
    per = max(1, n // len(groups))
    for members in groups.values():
        take = min(per, len(members))
        picked += [int(x) for x in rng.choice(members, size=take, replace=False)]

    if len(picked) < n:
        rest = [int(i) for i in pool if int(i) not in set(picked)]
        if rest:
            extra = min(n - len(picked), len(rest))
            picked += [int(x) for x in rng.choice(rest, size=extra, replace=False)]
    return picked[:n]


# --- цикл --------------------------------------------------------------

class Nocturne:
    def __init__(self, memory: Memory, batch_size: int = 256,
                 dry_run: bool = False, seed: int | None = None,
                 cancel_event=None, progress_cb=None, sampling_fn=None):
        self.mem = memory
        self.store = memory.store
        self.batch_size = batch_size
        self.dry_run = dry_run
        self.rng = np.random.default_rng(seed)
        self.cancel_event = cancel_event
        self.progress_cb = progress_cb
        self.sampling_fn = sampling_fn

    def pending(self) -> list:
        return self.store.query(
            """SELECT id, content, role, priority, replay_count, scope, session_id
               FROM episode WHERE user_id = ? AND processed = 0
               ORDER BY created_at""", (self.mem.user_id,))

    def run_index(self) -> int:
        row = self.store.one(
            "SELECT COUNT(*) FROM nocturne_run WHERE user_id = ?",
            (self.mem.user_id,))
        return row[0] if row else 0

    def bridge(self) -> dict | None:
        """Мост поколений: порция записей со старыми векторами пересчитывается новой моделью.

        После смены модели эмбеддингов старые векторы несравнимы с новыми, и поиск по смыслу
        перестаёт находить прошлую память. Раньше это лечилось только ручным `padam reindex`;
        теперь каждый сон переводит SLEEP_REINDEX_BATCH записей, пока не переведёт все.
        """
        if self.dry_run or config.SLEEP_REINDEX_BATCH <= 0:
            return None
        итог = self.mem.reindex(limit=config.SLEEP_REINDEX_BATCH)
        return итог if итог["reindexed"] or итог["left"] else None

    def run(self) -> dict:
        мост = self.bridge()
        report = self._run()
        if мост:
            report["bridge"] = мост
        # Эпистемический аудит без модели: действующие записи об одном и том же с разными значениями.
        # Сон их не правит — называет; решает человек или следующее подтверждение.
        споры = self.mem.conflicts()
        if споры:
            report["conflicts"] = [{"key": с["key"], "scope": с["scope"],
                                    "ids": [з["id"] for з in с["records"]]} for с in споры]
        return report

    def _run(self) -> dict:
        episodes = self.pending()
        if not episodes:
            return {"episodes_sampled": 0, "note": "буфер пуст"}

        n = len(episodes)
        raw = np.array([e["priority"] for e in episodes], dtype=np.float64)
        kinds = [classify.infer_kind(e["content"]) for e in episodes]

        p = apply_floor(raw)                    # (4)
        probs = probabilities(p)

        # (2) потолок на долю острых.
        #
        # Потолок нужен только когда в буфере действительно есть выбросы.
        # Если приоритеты однородны, делить эпизоды на «острые» и «обычные»
        # бессмысленно: потолок в этом случае просто урезал бы батч.
        median = float(np.median(p))
        spread = (float(p.max()) / median) if median > 0 else 1.0
        heterogeneous = spread >= config.SPREAD_THRESHOLD

        if heterogeneous:
            cut = float(np.percentile(p, config.HI_PERCENTILE))
            hi = np.where(p >= cut)[0]
            lo = np.where(p < cut)[0]
            n_hi = min(int(self.batch_size * config.K_MAX), hi.size)
            n_lo = min(self.batch_size - n_hi, lo.size)
        else:
            hi = np.array([], dtype=int)
            lo = np.arange(n)
            n_hi = 0
            n_lo = min(self.batch_size, n)

        chosen: list[int] = []
        if n_hi > 0:
            hp = probs[hi] / probs[hi].sum()
            chosen += [int(i) for i in
                       self.rng.choice(hi, size=n_hi, replace=False, p=hp)]
        if n_lo > 0:
            chosen += stratified(kinds, lo, n_lo, self.rng)

        if not chosen:
            return {"episodes_sampled": 0, "note": "нечего выбрать"}

        beta = beta_for(self.run_index())
        w = importance_weights(probs[chosen], n, beta)   # (1)

        run_id = new_id()
        if not self.dry_run:
            self.store.execute(
                """INSERT INTO nocturne_run (id, user_id, started_at)
                   VALUES (?,?,?)""", (run_id, self.mem.user_id, now_iso()))

        outcomes, kind_counts = Counter(), Counter()
        total_chosen = len(chosen)
        ep_snapshots: dict[str, tuple[float, int, int]] = {}
        created_mids: list[str] = []
        sampling_clusters = 0

        def _rollback_run() -> dict:
            for mid in reversed(created_mids):
                self.store.execute(
                    "UPDATE memory SET status = 'active', superseded_by = NULL WHERE superseded_by = ?",
                    (mid,),
                )
                self.store.execute("DELETE FROM anchor_key WHERE memory_id = ?", (mid,))
                self.store.execute("DELETE FROM memory_link WHERE src = ? OR dst = ?", (mid, mid))
                self.store.execute("DELETE FROM memory WHERE id = ? AND user_id = ?", (mid, self.mem.user_id))
            for eid, (orig_pri, orig_rc, orig_proc) in ep_snapshots.items():
                self.store.execute(
                    "UPDATE episode SET priority = ?, replay_count = ?, processed = ? WHERE id = ?",
                    (orig_pri, orig_rc, orig_proc, eid),
                )
            if not self.dry_run:
                self.store.execute("DELETE FROM nocturne_run WHERE id = ?", (run_id,))
            self.mem.__dict__.pop("_ккэш", None)
            return {
                "episodes_sampled": total_chosen,
                "cancelled": True,
                "rolled_back": True,
                "outcomes": {},
                "kinds": dict(kind_counts),
                "note": "cancelled",
            }

        if self.progress_cb is not None:
            self.progress_cb(0, total_chosen, "consolidation started")

        done_count = 0
        handled_positions: set[int] = set()
        if self.sampling_fn is not None and not self.dry_run:
            clusters: dict[tuple[str, str], list[int]] = {}
            for pos, idx in enumerate(chosen):
                key = (kinds[idx], episodes[idx]["scope"])
                clusters.setdefault(key, []).append(pos)
            for (ckind, cscope), pos_list in clusters.items():
                if len(pos_list) < 2:
                    continue
                if self.cancel_event is not None and self.cancel_event.is_set():
                    return _rollback_run()
                texts = [episodes[chosen[p]]["content"] for p in pos_list]
                summary = self.sampling_fn(texts, ckind, cscope)
                if not summary or not str(summary).strip():
                    continue
                if self.cancel_event is not None and self.cancel_event.is_set():
                    return _rollback_run()
                clean_summary, _ = safety.redact(str(summary).strip())
                avg_weight = float(sum(w[p] for p in pos_list) / len(pos_list))
                outcome, mid = self.mem.remember(
                    content=clean_summary,
                    kind=ckind,
                    importance=min(1.0, 0.5 * avg_weight + 0.3),
                    scope=cscope,
                    source_episode_id=episodes[chosen[pos_list[0]]]["id"],
                    origin="agent",
                    guarded=True,
                )
                if outcome != "duplicate":
                    created_mids.append(mid)
                outcomes[outcome] += 1
                sampling_clusters += 1
                for p in pos_list:
                    handled_positions.add(p)
                    ep = episodes[chosen[p]]
                    kind_counts[kinds[chosen[p]]] += 1
                    ep_snapshots[ep["id"]] = (float(ep["priority"]), int(ep["replay_count"]), 0)
                    self.store.execute(
                        """UPDATE episode SET priority = priority * ?,
                           replay_count = replay_count + 1, processed = 1
                           WHERE id = ?""",
                        (config.GAMMA_REPLAY, ep["id"]),
                    )
                    done_count += 1
                    if self.progress_cb is not None:
                        self.progress_cb(done_count, total_chosen, f"sampled cluster {ckind}/{cscope}")

        for pos, idx in enumerate(chosen):
            if pos in handled_positions:
                continue
            if self.cancel_event is not None and self.cancel_event.is_set():
                return _rollback_run()

            ep = episodes[idx]
            kind = kinds[idx]
            kind_counts[kind] += 1
            weight = float(w[pos])

            if self.dry_run:
                outcomes["dry"] += 1
                done_count += 1
                if self.progress_cb is not None:
                    self.progress_cb(done_count, total_chosen, f"dry {ep['id']}")
                continue

            ep_snapshots[ep["id"]] = (float(ep["priority"]), int(ep["replay_count"]), 0)
            # Реплика модели или чужой текст из буфера не становятся словами человека:
            # у них меньше начальная уверенность, и защищённое они сами не заменят.
            откуда = {"user": "user", "assistant": "agent"}.get(ep["role"], "external")
            outcome, mid = self.mem.remember(
                content=ep["content"], kind=kind,
                importance=min(1.0, 0.5 * weight + 0.25),
                scope=ep["scope"], source_episode_id=ep["id"],
                origin=откуда, guarded=откуда != "user")
            if outcome != "duplicate":
                created_mids.append(mid)
            outcomes[outcome] += 1

            # (3) распад приоритета после переигрывания
            self.store.execute(
                """UPDATE episode SET priority = priority * ?,
                   replay_count = replay_count + 1, processed = 1
                   WHERE id = ?""", (config.GAMMA_REPLAY, ep["id"]))
            done_count += 1
            if self.progress_cb is not None:
                self.progress_cb(done_count, total_chosen, f"processed {ep['id']}")

        row = self.store.one(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN replay_count > ? THEN 1 ELSE 0 END) AS over
               FROM episode WHERE user_id = ?""",
            (config.OVERREPLAY_COUNT, self.mem.user_id))
        total = row["total"] or 0
        over = row["over"] or 0
        overreplay = (over / total) if total else 0.0

        report = {
            "episodes_sampled": len(chosen),
            "high_priority_share": round(n_hi / len(chosen), 3),
            "kind_entropy_ratio": round(entropy_ratio(kind_counts), 3),
            "overreplay_share": round(overreplay, 4),
            "beta": round(beta, 3),
            "outcomes": dict(outcomes),
            "kinds": dict(kind_counts),
            "sampling_clusters": sampling_clusters,
        }

        if not self.dry_run:
            self.store.execute(
                """UPDATE nocturne_run SET finished_at = ?, episodes_sampled = ?,
                   high_priority_share = ?, kind_entropy = ?, records_created = ?,
                   records_merged = ?, records_superseded = ? WHERE id = ?""",
                (now_iso(), len(chosen), report["high_priority_share"],
                 report["kind_entropy_ratio"], outcomes.get("created", 0),
                 outcomes.get("merged", 0), outcomes.get("superseded", 0), run_id))

        report["checks"] = self.checks(report)
        return report

    @staticmethod
    def checks(r: dict) -> list[tuple[str, bool, str]]:
        return [
            ("Доля острых эпизодов", r["high_priority_share"] <= config.MAX_HI_SHARE,
             f'{r["high_priority_share"]} (цель ≤ {config.MAX_HI_SHARE})'),
            ("Разнообразие по типам",
             r["kind_entropy_ratio"] >= config.MIN_KIND_ENTROPY_RATIO,
             f'{r["kind_entropy_ratio"]} (цель ≥ {config.MIN_KIND_ENTROPY_RATIO})'),
            ("Переигранных > 5 раз",
             r["overreplay_share"] <= config.MAX_OVERREPLAY_SHARE,
             f'{r["overreplay_share"]} (цель ≤ {config.MAX_OVERREPLAY_SHARE})'),
        ]
