#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Подготовка и запуск дообучения LoRA-адаптера личности (Unsloth / QLoRA 4-bit).

По умолчанию безопасен для локальной проверки: `--dry-run` валидирует датасет
(ChatML / ShareGPT), оценивает доступную VRAM через `nvidia-smi` (если есть),
и выдаёт конфигурацию LoRA (r=32, lora_alpha=64, 3 эпохи) без запуска GPU-обучения
и без каких-либо облачных/платных вызовов ($0).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def detect_local_gpu_vram_mib() -> dict[str, Any]:
    smi = shutil.which("nvidia-smi")
    if not smi:
        return {"available": False, "name": None, "total_mib": 0, "free_mib": 0}
    try:
        out = subprocess.check_output(
            [smi, "--query-gpu=name,memory.total,memory.free", "--format=csv,noheader,nounits"],
            text=True,
            timeout=5,
        ).strip()
        if not out:
            return {"available": False, "name": None, "total_mib": 0, "free_mib": 0}
        first = out.splitlines()[0].split(",")
        return {
            "available": True,
            "name": first[0].strip(),
            "total_mib": int(float(first[1].strip())),
            "free_mib": int(float(first[2].strip())),
        }
    except Exception:
        return {"available": False, "name": None, "total_mib": 0, "free_mib": 0}


def validate_dataset(dataset_path: Path) -> dict[str, Any]:
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")
    count = 0
    detected_format = None
    total_chars = 0
    with dataset_path.open("r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "messages" in obj and isinstance(obj["messages"], list):
                detected_format = detected_format or "chatml"
                total_chars += sum(len(str(m.get("content") or "")) for m in obj["messages"])
            elif "conversations" in obj and isinstance(obj["conversations"], list):
                detected_format = detected_format or "sharegpt"
                total_chars += sum(len(str(m.get("value") or "")) for m in obj["conversations"])
            else:
                raise ValueError(f"Line {line_no}: expected ChatML 'messages' or ShareGPT 'conversations'")
            count += 1
    if count == 0:
        raise ValueError("Dataset has 0 examples")
    return {
        "examples": count,
        "format": detected_format or "unknown",
        "approx_tokens": max(1, total_chars // 4),
    }


def recommend_local_model_tier(free_mib: int) -> str:
    if free_mib >= 20000:
        return "32B-4bit (local/rented GPU 24GB+)"
    if free_mib >= 10000:
        return "7B-14B-4bit (local 12GB+)"
    if free_mib >= 4000:
        return "1B-3B-4bit (safe for 6GB GTX 1060)"
    return "CPU / dry-run only (insufficient VRAM for QLoRA)"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="PADAM Sovereign Brain LoRA trainer (Unsloth QLoRA 4-bit)")
    p.add_argument("--dataset", required=True, help="Path to personality_chatml.jsonl or personality_sharegpt.jsonl")
    p.add_argument("--model", default="unsloth/Qwen2.5-3B-Instruct-bnb-4bit")
    p.add_argument("--out", default="persona_adapter")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--rank", type=int, default=32)
    p.add_argument("--lora-alpha", type=int, default=64)
    p.add_argument("--batch-size", type=int, default=2)
    p.add_argument("--max-seq-len", type=int, default=2048)
    p.add_argument("--dry-run", action="store_true", help="Validate dataset, GPU VRAM and print plan ($0, no training)")
    args = p.parse_args(argv)

    ds_info = validate_dataset(Path(args.dataset))
    gpu = detect_local_gpu_vram_mib()
    plan = {
        "status": "dry_run_ok" if args.dry_run else "ready",
        "cost_usd": 0.0,
        "dataset": str(args.dataset),
        "dataset_stats": ds_info,
        "gpu": gpu,
        "recommended_tier": recommend_local_model_tier(gpu["free_mib"]),
        "lora_config": {
            "base_model": args.model,
            "load_in_4bit": True,
            "r": args.rank,
            "lora_alpha": args.lora_alpha,
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "max_seq_len": args.max_seq_len,
            "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            "output_adapter": str(Path(args.out) / "persona_adapter.safetensors"),
        },
    }

    if args.dry_run:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 0

    try:
        from unsloth import FastLanguageModel  # type: ignore
        from trl import SFTTrainer  # type: ignore
        from transformers import TrainingArguments  # type: ignore
        from datasets import load_dataset  # type: ignore
    except ImportError as exc:
        print(json.dumps({
            "error": f"Unsloth/TRL dependencies not installed: {exc}",
            "hint": "Run with --dry-run on this machine or install unsloth/trl/transformers on target GPU host.",
            "plan": plan,
        }, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.max_seq_len,
        dtype=None,
        load_in_4bit=True,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.rank,
        target_modules=plan["lora_config"]["target_modules"],
        lora_alpha=args.lora_alpha,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
    )
    dataset = load_dataset("json", data_files=str(args.dataset), split="train")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        max_seq_length=args.max_seq_len,
        args=TrainingArguments(
            per_device_train_batch_size=args.batch_size,
            gradient_accumulation_steps=4,
            num_train_epochs=args.epochs,
            learning_rate=2e-4,
            fp16=True,
            logging_steps=10,
            output_dir=str(out_dir),
            report_to="none",
        ),
    )
    trainer.train()
    model.save_pretrained(str(out_dir))
    print(json.dumps({"status": "trained", "output_dir": str(out_dir)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
