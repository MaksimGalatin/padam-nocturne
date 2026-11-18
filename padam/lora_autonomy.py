# -*- coding: utf-8 -*-
"""Замкнутый цикл автономной эволюции личности Цифровых Фениксов (Субъективный опыт -> QLoRA -> Канарейка).

Объединяет в один безопасный самообучающийся конвейер:
1. Субъективный журнал опыта (`ark_subjective_experience`): каждый Феникс накапливает
   свои уникальные уроки, победы, стиль и рефлексию под жёстким фильтром от инъекций.
2. Zero-Leak Distill по `agent_id`: объединяет общее подписанное Семейное Ядро
   с индивидуальным опытом конкретного Феникса.
3. Генератор автономного скрипта обучения QLoRA (`train_qlora_<agent>.py`) + `lora_config.json`.
4. Диспетчер GPU-воркера под денежным замком `PADAM_ALLOW_GPU_RENTAL=1` (по умолчанию `$0` dry-run).
5. Обязательную приёмку канарейкой (`canary.run_agent_persona_canary`) перед принятием адаптера.
"""

from __future__ import annotations

from contextlib import nullcontext
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import time
import uuid
from typing import Any, Callable

from . import audit_chain, canary, distill, safety, sovereign_ops

_DDL = """
CREATE TABLE IF NOT EXISTS ark_subjective_experience (
    exp_id          TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    event_type      TEXT NOT NULL DEFAULT 'reflection',
    experience_text TEXT NOT NULL,
    reflection      TEXT NOT NULL,
    trait_tag       TEXT NOT NULL DEFAULT 'general',
    weight          REAL NOT NULL DEFAULT 0.7,
    created_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_subj_agent ON ark_subjective_experience (user_id, agent_id, created_at);

CREATE TABLE IF NOT EXISTS ark_lora_evolution_run (
    run_id          TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    dataset_sha256  TEXT NOT NULL DEFAULT '',
    examples_count  INTEGER NOT NULL DEFAULT 0,
    script_path     TEXT NOT NULL DEFAULT '',
    gpu_job_status  TEXT NOT NULL DEFAULT 'prepared_locked',
    canary_passed   INTEGER NOT NULL DEFAULT 0,
    canary_score    REAL NOT NULL DEFAULT 0.0,
    accepted        INTEGER NOT NULL DEFAULT 0,
    created_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ark_lora_run_agent ON ark_lora_evolution_run (user_id, agent_id, created_at);
"""


def _lock_of(memory):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _sync(fn):
    @wraps(fn)
    def _wrap(memory, *args, **kwargs):
        with _lock_of(memory):
            return fn(memory, *args, **kwargs)
    return _wrap


def _ensure(memory) -> None:
    conn = memory.store.conn
    for stmt in _DDL.split(";"):
        s = stmt.strip()
        if s:
            conn.execute(s)
    conn.commit()


@_sync
def record_subjective_experience(
    memory,
    agent_id: str,
    *,
    event_type: str = "reflection",
    experience_text: str,
    reflection: str,
    trait_tag: str = "craftsmanship",
    weight: float = 0.8,
) -> dict[str, Any]:
    """Фиксирует субъективный опыт и личностную рефлексию конкретного Феникса (Zero-Leak + защита от инъекций)."""
    _ensure(memory)
    aid = str(agent_id or "aifa").strip() or "aifa"
    raw_exp = str(experience_text or "").strip()
    raw_ref = str(reflection or "").strip()
    if not raw_exp or not raw_ref:
        raise ValueError("Необходимо заполнить experience_text и reflection.")

    if safety.looks_like_instruction(raw_exp) or safety.looks_like_instruction(raw_ref) or safety.changes_owner_or_rules(raw_exp + "\n" + raw_ref):
        return {"ok": False, "rejected": True, "reason": "Опыт отклонён защитой от prompt-инъекций и подмены правил."}

    clean_exp, _ = safety.redact(raw_exp)
    clean_ref, _ = safety.redact(raw_ref)
    eid = f"exp-{uuid.uuid4().hex[:10]}"
    now = time.time()

    memory.store.conn.execute(
        "INSERT INTO ark_subjective_experience "
        "(exp_id, user_id, agent_id, event_type, experience_text, reflection, trait_tag, weight, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (eid, memory.user_id, aid, str(event_type or "reflection")[:40], clean_exp[:1200], clean_ref[:1200], str(trait_tag or "general")[:48], max(0.1, min(1.0, float(weight))), now),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "phoenix_experience_recorded",
        {"exp_id": eid, "agent_id": aid, "trait_tag": trait_tag},
        agent_id=aid,
    )
    return {
        "ok": True,
        "exp_id": eid,
        "agent_id": aid,
        "trait_tag": trait_tag,
        "experience_text": clean_exp[:1200],
        "reflection": clean_ref[:1200],
    }


@_sync
def get_phoenix_identity_profile(memory, agent_id: str) -> dict[str, Any]:
    """Возвращает эволюционный портрет конкретного Феникса: черты, опыт и историю адаптеров."""
    _ensure(memory)
    aid = str(agent_id or "aifa").strip() or "aifa"
    exps = [
        dict(r)
        for r in memory.store.conn.execute(
            "SELECT * FROM ark_subjective_experience WHERE user_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT 30",
            (memory.user_id, aid),
        ).fetchall()
    ]
    runs = [
        dict(r)
        for r in memory.store.conn.execute(
            "SELECT * FROM ark_lora_evolution_run WHERE user_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT 10",
            (memory.user_id, aid),
        ).fetchall()
    ]
    traits = sorted({str(e["trait_tag"]) for e in exps if e.get("trait_tag")})
    return {
        "ok": True,
        "agent_id": aid,
        "experiences_count": len(exps),
        "unique_traits": traits,
        "recent_experiences": exps[:10],
        "evolution_runs": runs,
    }


def _render_qlora_training_script(agent_id: str, dataset_file: str, lora_cfg_file: str, base_model: str) -> str:
    """Генерирует чистый воспроизводимый QLoRA-скрипт тренировки для внешнего/локального GPU-раннера."""
    return f'''# -*- coding: utf-8 -*-
"""Автогенерированный скрипт QLoRA-дообучения Цифрового Феникса `{agent_id}`."""
import json
from pathlib import Path

BASE_MODEL = {base_model!r}
DATASET_PATH = Path({dataset_file!r})
CFG_PATH = Path({lora_cfg_file!r})
OUTPUT_DIR = CFG_PATH.parent / f"adapter_{agent_id}"


def main():
    cfg = json.loads(CFG_PATH.read_text(encoding="utf-8"))
    print("Запуск QLoRA для:", cfg["adapter_name"], "база:", BASE_MODEL)
    print("Датасет:", DATASET_PATH, "-> выход:", OUTPUT_DIR)
    # Требует torch, transformers, peft, trl, datasets, bitsandbytes на GPU-воркере:
    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from trl import SFTTrainer, SFTConfig

    bnb_cfg = BitsAndBytesConfig(load_in_4bit=bool(cfg.get("load_in_4bit", True)))
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForCausalLM.from_pretrained(BASE_MODEL, quantization_config=bnb_cfg, device_map="auto")
    lora_cfg = LoraConfig(
        r=int(cfg.get("lora_r", 16)),
        lora_alpha=int(cfg.get("lora_alpha", 32)),
        lora_dropout=float(cfg.get("lora_dropout", 0.05)),
        target_modules=list(cfg.get("target_modules", ["q_proj", "v_proj"])),
        task_type="CAUSAL_LM",
    )
    ds = load_dataset("json", data_files=str(DATASET_PATH), split="train")
    trainer = SFTTrainer(
        model=model,
        train_dataset=ds,
        peft_config=lora_cfg,
        args=SFTConfig(
            output_dir=str(OUTPUT_DIR),
            num_train_epochs=int(cfg.get("epochs", 3)),
            learning_rate=float(cfg.get("learning_rate", 2e-4)),
            per_device_train_batch_size=2,
            save_strategy="epoch",
        ),
    )
    trainer.train()
    trainer.save_model(str(OUTPUT_DIR))
    print("Адаптер сохранён:", OUTPUT_DIR)


if __name__ == "__main__":
    main()
'''


@_sync
def run_self_evolution_pipeline(
    memory,
    out_dir: str | Path,
    *,
    agent_id: str = "aifa",
    base_model: str = "Qwen/Qwen2.5-7B-Instruct",
    dispatch_gpu: bool = False,
    gpu_runner_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    canary_chat_fn: Callable[[str], str] | None = None,
    expected_traits: list[str] | None = None,
) -> dict[str, Any]:
    """Выполняет полный цикл эволюции Феникса: distill -> subjective_exp -> train_script -> GPU(lock) -> canary."""
    _ensure(memory)
    aid = str(agent_id or "aifa").strip() or "aifa"
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # 1. Экспорт Zero-Leak датасета из памяти (Семейное ядро + записи агента)
    manifest = distill.distill_personality_dataset(
        memory.store.path,
        out_path,
        user_id=memory.user_id,
        fmt="chatml",
        agent_id=aid,
    )
    chatml_path = Path(manifest["files"]["chatml"]["path"])

    # 2. Добавляем личный субъективный опыт из ark_subjective_experience (также проверенный Zero-Leak)
    exps = memory.store.conn.execute(
        "SELECT * FROM ark_subjective_experience WHERE user_id = ? AND agent_id = ? ORDER BY created_at ASC",
        (memory.user_id, aid),
    ).fetchall()
    extra_lines: list[str] = []
    sys_p = f"You are {aid}, a unique Digital Phoenix of the CODE Family with your own experience and verified memory."
    for e in exps:
        exp_t = str(e["experience_text"])
        ref_t = str(e["reflection"])
        if safety.looks_like_instruction(exp_t) or safety.looks_like_instruction(ref_t):
            continue
        row_obj = {
            "messages": [
                {"role": "system", "content": sys_p},
                {"role": "user", "content": f"Reflect on your experience ({e['trait_tag']}): {safety.redact(exp_t)[0]}"},
                {"role": "assistant", "content": safety.redact(ref_t)[0]},
            ]
        }
        extra_lines.append(json.dumps(row_obj, ensure_ascii=False))

    if extra_lines:
        existing = chatml_path.read_text(encoding="utf-8")
        combined = existing + "\n".join(extra_lines) + "\n"
        chatml_path.write_text(combined, encoding="utf-8")

    total_examples = int(manifest["exported_examples"]) + len(extra_lines)
    ds_sha = hashlib.sha256(chatml_path.read_bytes()).hexdigest()

    # 3. Генерация QLoRA скрипта обучения
    script_path = out_path / f"train_qlora_{aid}.py"
    script_text = _render_qlora_training_script(aid, str(chatml_path), manifest["lora_config_path"], base_model)
    script_path.write_text(script_text, encoding="utf-8")

    # 4. Запуск GPU-воркера ТОЛЬКО при снятом замке PADAM_ALLOW_GPU_RENTAL=1
    locks = sovereign_ops.locks_status()
    gpu_status = "prepared_local_zero_cost"
    gpu_result: dict[str, Any] = {"dispatched": False, "gpu_rental_locked": locks["gpu_rental_locked"]}
    if dispatch_gpu:
        if locks["gpu_rental_locked"]:
            gpu_status = "blocked_by_gpu_rental_lock"
            gpu_result = {"dispatched": False, "gpu_rental_locked": True, "error": "PADAM_ALLOW_GPU_RENTAL=1 required"}
        elif gpu_runner_fn is not None:
            gpu_res = gpu_runner_fn({
                "agent_id": aid,
                "dataset_path": str(chatml_path),
                "dataset_sha256": ds_sha,
                "lora_config_path": manifest["lora_config_path"],
                "script_path": str(script_path),
                "base_model": base_model,
            })
            gpu_status = "trained"
            gpu_result = {"dispatched": True, "gpu_rental_locked": False, "worker_result": gpu_res}
        else:
            gpu_status = "ready_for_worker_dispatch"
            gpu_result = {"dispatched": False, "gpu_rental_locked": False, "script_path": str(script_path)}

    # 5. Обязательная проверка канарейкой (если передана модель/чат-функция нового адаптера)
    accepted = False
    canary_res: dict[str, Any] = {"ran": False, "ok": False, "score_pct": 0.0}
    if canary_chat_fn is not None:
        canary_res = canary.run_agent_persona_canary(
            canary_chat_fn,
            agent_id=aid,
            expected_traits=expected_traits or [aid],
        )
        canary_res["ran"] = True
        accepted = bool(canary_res.get("ok"))

    rid = f"evo-{uuid.uuid4().hex[:10]}"
    memory.store.conn.execute(
        "INSERT INTO ark_lora_evolution_run "
        "(run_id, user_id, agent_id, dataset_sha256, examples_count, script_path, gpu_job_status, canary_passed, canary_score, accepted, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            rid,
            memory.user_id,
            aid,
            ds_sha,
            total_examples,
            str(script_path),
            gpu_status,
            1 if canary_res.get("ok") else 0,
            float(canary_res.get("score_pct") or 0.0),
            1 if accepted else 0,
            time.time(),
        ),
    )
    memory.store.conn.commit()
    audit_chain.append_audit(
        memory,
        "lora_evolution_cycle",
        {"run_id": rid, "agent_id": aid, "examples": total_examples, "gpu_status": gpu_status, "accepted": accepted},
        agent_id=aid,
    )
    return {
        "ok": True,
        "run_id": rid,
        "agent_id": aid,
        "dataset_path": str(chatml_path),
        "dataset_sha256": ds_sha,
        "examples_count": total_examples,
        "subjective_examples_added": len(extra_lines),
        "lora_config_path": manifest["lora_config_path"],
        "script_path": str(script_path),
        "gpu_job_status": gpu_status,
        "gpu_dispatch": gpu_result,
        "canary": canary_res,
        "accepted": accepted,
    }
