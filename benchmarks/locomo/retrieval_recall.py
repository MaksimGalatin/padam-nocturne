# -*- coding: utf-8 -*-
"""LoCoMo benchmark (retrieval stage only): насколько точно PADAM находит опорные реплики и сессии.

Не использует языковые модели, платные API или локальный Ollama (принудительно работает
встроенный детерминированный эмбеддер `builtin` за $0). Для каждого из 10 длинных диалогов
(`locomo10.json`) все реплики с временными метками сессий записываются через `Memory.remember`,
после чего для каждого вопроса вызывается `Memory.recall(question, limit=50)` и вычисляются
метрики извлечения на двух уровнях:
  - turn-level (`dia_id`, напр. `D1:3`): `turn_any@5`, `turn_any@10`, `turn_all@5`, `turn_all@10`;
  - session-level (`session_id`, напр. `D1`): `sess_any@5`, `sess_any@10`, `sess_all@5`, `sess_all@10`.

Итоги разделяются на основные QA-категории 1–4 (`multi-hop`, `temporal`, `open-domain`,
`single-hop`), категорию 5 (`adversarial`) и суммарную сводку по всем вопросам с `evidence`.

Запуск:
  python -I -X utf8 benchmarks/locomo/retrieval_recall.py <locomo10.json> <out_dir> [--limit N] [--rerank]
"""

import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"
os.environ["PADAM_EMBEDDER"] = "builtin"

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from padam import config, embeddings  # noqa: E402
from padam.memory import Memory  # noqa: E402
from padam.store import Store  # noqa: E402

if "--rerank" in sys.argv:
    config.RERANK = True

config.OLLAMA_URL = "http://127.0.0.1:9"
embeddings._check_ollama = lambda: False
sys.stdout.reconfigure(encoding="utf-8")

CATEGORY_NAMES = {
    1: "multi-hop",
    2: "temporal",
    3: "open-domain",
    4: "single-hop",
    5: "adversarial",
}
KS = (5, 10)
RETRIEVE = 50
_SESSION_RE = re.compile(r"^session_(\d+)$")


def ordered_sessions(conv: dict) -> list[tuple[int, str, list[dict]]]:
    """Возвращает сессии диалога в хронологическом порядке [(num, date_time, turns), ...]."""
    nums: list[int] = []
    for key, val in conv.items():
        m = _SESSION_RE.match(key)
        if m and isinstance(val, list):
            nums.append(int(m.group(1)))
    nums.sort()
    out: list[tuple[int, str, list[dict]]] = []
    for n in nums:
        dt = str(conv.get(f"session_{n}_date_time") or "").strip()
        out.append((n, dt, conv[f"session_{n}"]))
    return out


def format_turn(turn: dict, session_dt: str) -> str:
    """Форматирует реплику LoCoMo с отметкой времени сессии и подписью изображения (если есть)."""
    speaker = str(turn.get("speaker") or "speaker").strip()
    text = str(turn.get("text") or "").strip()
    caption = str(turn.get("blip_caption") or "").strip()
    body = f"[{session_dt}] {speaker}: {text}" if session_dt else f"{speaker}: {text}"
    if caption:
        body = f"{body} [image: {caption}]"
    return body[: config.MAX_CONTENT_CHARS]


def dia_to_session(dia_id: str) -> str:
    return dia_id.split(":", 1)[0] if ":" in dia_id else dia_id


def _share(rows: list[dict], key: str) -> float | None:
    return round(sum(1 for r in rows if r[key]) / len(rows), 4) if rows else None


def _metrics_block(rows: list[dict]) -> dict:
    block: dict[str, object] = {"n": len(rows)}
    for level in ("turn", "sess"):
        for m in ("any", "all"):
            for k in KS:
                key = f"{level}_{m}@{k}"
                block[key] = _share(rows, key)
    return block


def score_question(mem: Memory, q: dict, sample_id: str, record_dids: dict[str, set[str]]) -> dict:
    """Выполняет поиск по одному вопросу и считает turn/session-попадания."""
    found = mem.recall(q["question"], limit=RETRIEVE)
    ranked_dids: list[str] = []
    ranked_sids: list[str] = []
    for rec in found:
        for did in sorted(record_dids.get(rec.id, ())):
            if did not in ranked_dids:
                ranked_dids.append(did)
            sid = dia_to_session(did)
            if sid not in ranked_sids:
                ranked_sids.append(sid)

    gold_dids = {str(e) for e in (q.get("evidence") or []) if str(e).strip()}
    gold_sids = {dia_to_session(e) for e in gold_dids}
    cat = int(q.get("category") or 0)
    row: dict[str, object] = {
        "sample_id": sample_id,
        "category": cat,
        "category_name": CATEGORY_NAMES.get(cat, str(cat)),
        "question": q["question"],
        "records_found": len(found),
        "gold_dids": sorted(gold_dids),
        "gold_sids": sorted(gold_sids),
    }
    for k in KS:
        top_d = set(ranked_dids[:k])
        top_s = set(ranked_sids[:k])
        row[f"turn_any@{k}"] = bool(gold_dids & top_d)
        row[f"turn_all@{k}"] = bool(gold_dids) and (gold_dids <= top_d)
        row[f"sess_any@{k}"] = bool(gold_sids & top_s)
        row[f"sess_all@{k}"] = bool(gold_sids) and (gold_sids <= top_s)
    return row


def run_benchmark(data_path: Path, out_dir: Path, limit: int | None = None) -> dict:
    """Прогоняет LoCoMo retrieval benchmark по всем диалогам из `data_path` и сохраняет отчёты."""
    out_dir.mkdir(parents=True, exist_ok=True)
    dialogs = json.loads(data_path.read_text(encoding="utf-8"))

    per_question: list[dict] = []
    skipped_no_evidence = 0
    started = time.time()
    total_turns_written = 0

    for d_idx, sample in enumerate(dialogs, 1):
        if limit is not None and len(per_question) >= limit:
            break
        sample_id = str(sample.get("sample_id") or f"sample_{d_idx}")
        conv = sample.get("conversation") or {}

        with tempfile.TemporaryDirectory() as tmp:
            mem = Memory(user_id=f"locomo_{sample_id}", store=Store(Path(tmp) / "m.db"))
            record_dids: dict[str, set[str]] = {}
            written = 0
            try:
                for _, session_dt, turns in ordered_sessions(conv):
                    for turn in turns:
                        did = str(turn.get("dia_id") or "").strip()
                        if not did:
                            continue
                        text = format_turn(turn, session_dt)
                        if not text.strip():
                            continue
                        _, mid = mem.remember(text, kind="event", origin="user")
                        record_dids.setdefault(mid, set()).add(did)
                        written += 1
                total_turns_written += written

                for q in sample.get("qa", []):
                    if limit is not None and len(per_question) >= limit:
                        break
                    if not (q.get("evidence") or []):
                        skipped_no_evidence += 1
                        continue
                    row = score_question(mem, q, sample_id, record_dids)
                    per_question.append(row)
            finally:
                mem.close()

        elapsed = time.time() - started
        qa14_so_far = [r for r in per_question if r["category"] in (1, 2, 3, 4)]
        acc5 = _share(qa14_so_far, "turn_any@5") if qa14_so_far else 0.0
        sacc5 = _share(qa14_so_far, "sess_any@5") if qa14_so_far else 0.0
        print(
            f"Dialog {d_idx}/{len(dialogs)} ({sample_id}): {written} turns, "
            f"{len(per_question)} QA scored, qa1-4 turn_any@5={acc5} sess_any@5={sacc5} ({elapsed:.1f}s)",
            flush=True,
        )

    (out_dir / "per_question.json").write_text(
        json.dumps(per_question, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )

    qa_main = [r for r in per_question if r["category"] in (1, 2, 3, 4)]
    qa_adv = [r for r in per_question if r["category"] == 5]
    by_category = {}
    for cat in sorted({int(r["category"]) for r in per_question}):
        rs = [r for r in per_question if r["category"] == cat]
        by_category[CATEGORY_NAMES.get(cat, str(cat))] = _metrics_block(rs)

    summary = {
        "dataset": "LoCoMo (locomo10.json)",
        "dialogs": len(dialogs),
        "turns_written": total_turns_written,
        "questions_scored": len(per_question),
        "skipped_no_evidence": skipped_no_evidence,
        "method": (
            f"PADAM Memory.remember per turn, Memory.recall(question, limit={RETRIEVE}), "
            f"embedding=builtin, rerank={config.RERANK}, no LLM"
        ),
        "rerank": config.RERANK,
        "rerank_top_k": config.RERANK_TOP_K if config.RERANK else 0,
        "padam_version": __import__("padam").__version__,
        "qa_categories_1_4": _metrics_block(qa_main),
        "adversarial_category_5": _metrics_block(qa_adv),
        "all_with_evidence": _metrics_block(per_question),
        "by_category": by_category,
        "seconds": round(time.time() - started, 1),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Usage: retrieval_recall.py <locomo10.json> <out_dir> [--limit N] [--rerank]")
    lim = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else None
    run_benchmark(Path(sys.argv[1]), Path(sys.argv[2]), limit=lim)
