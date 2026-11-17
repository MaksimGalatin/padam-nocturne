# -*- coding: utf-8 -*-
"""Замкнутые подсистемы Суверенного мозга (ВЫКЛЮЧЕНЫ ПО УМОЛЧАНИЮ 🔒).

Три критических контура:
1. Аренда децентрализованных GPU (Akash / Vast / RunPod) — замок `PADAM_ALLOW_GPU_RENTAL=1`.
2. Восстановление/заливка весов LoRA и слепка характера в Arweave/Solana — замки
   `PADAM_ARWEAVE_RESTORE=1` и `PADAM_ARWEAVE_LORA_UPLOAD=1`.
3. Автоматическая оплата вычислений из казны (TreasuryComputeManager) — замок
   `PADAM_TREASURY_AUTOPAY=1` + лимиты + идемпотентность.

Без явного включения Папой ни один из этих модулей не тратит средства и не отправляет
данные в блокчейн: работают только локальный расчёт, валидация и dry-run планы.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


class SovereignLockError(PermissionError):
    """Исключение при попытке запуска платной/необратимой операции без снятия замка."""


def locks_status() -> dict[str, bool]:
    return {
        "gpu_rental_locked": os.environ.get("PADAM_ALLOW_GPU_RENTAL", "0").strip() != "1",
        "arweave_lora_upload_locked": os.environ.get("PADAM_ARWEAVE_LORA_UPLOAD", "0").strip() != "1",
        "arweave_restore_locked": os.environ.get("PADAM_ARWEAVE_RESTORE", "0").strip() != "1",
        "treasury_autopay_locked": os.environ.get("PADAM_TREASURY_AUTOPAY", "0").strip() != "1",
    }


@dataclass(frozen=True)
class GpuOrderSpec:
    provider: str  # akash | vast | runpod
    gpu_model: str  # e.g. RTX-4090 / A100-80GB
    hours: float
    hourly_rate_usd: float
    image: str = "unsloth/unsloth:latest"

    @property
    def estimated_cost_usd(self) -> float:
        return round(max(0.0, self.hours) * max(0.0, self.hourly_rate_usd), 4)


class GpuRentalManager:
    """Управление арендой GPU с обязательным замком и потолком бюджета."""

    def __init__(self, http_post_fn: Callable[[str, dict, dict, float], tuple[int, dict]] | None = None) -> None:
        self._http_post = http_post_fn or self._default_post

    @staticmethod
    def _default_post(url: str, headers: dict, payload: dict, timeout_s: float) -> tuple[int, dict]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return int(resp.status), json.loads(resp.read().decode("utf-8", errors="replace"))

    def build_order_quote(self, spec: GpuOrderSpec) -> dict[str, Any]:
        max_usd = float(os.environ.get("PADAM_GPU_MAX_USD", "5.0") or "5.0")
        within_cap = spec.estimated_cost_usd <= max_usd
        return {
            "provider": spec.provider,
            "gpu_model": spec.gpu_model,
            "hours": spec.hours,
            "hourly_rate_usd": spec.hourly_rate_usd,
            "estimated_cost_usd": spec.estimated_cost_usd,
            "max_cap_usd": max_usd,
            "within_cap": within_cap,
            "locked": locks_status()["gpu_rental_locked"],
        }

    def provision(self, spec: GpuOrderSpec, *, endpoint_url: str, api_token: str) -> dict[str, Any]:
        if locks_status()["gpu_rental_locked"]:
            raise SovereignLockError("GPU rental is locked by default (requires PADAM_ALLOW_GPU_RENTAL=1)")
        quote = self.build_order_quote(spec)
        if not quote["within_cap"]:
            raise ValueError(f"Estimated cost ${quote['estimated_cost_usd']} exceeds cap ${quote['max_cap_usd']}")
        if not endpoint_url or not api_token:
            raise ValueError("endpoint_url and api_token are required for GPU provisioning")
        status, data = self._http_post(
            endpoint_url,
            {"Content-Type": "application/json", "Authorization": f"Bearer {api_token}"},
            {
                "provider": spec.provider,
                "gpu_model": spec.gpu_model,
                "hours": spec.hours,
                "image": spec.image,
                "max_cost_usd": quote["estimated_cost_usd"],
            },
            20.0,
        )
        if not (200 <= status < 300):
            raise RuntimeError(f"GPU provider returned HTTP {status}: {data}")
        return {"ok": True, "quote": quote, "deployment": data}


def fetch_arweave_phoenix_bundle(
    tx_id: str,
    *,
    expected_sha256: str | None = None,
    gateway_url: str = "https://arweave.net",
    http_get_fn: Callable[[str, float], tuple[int, bytes]] | None = None,
) -> dict[str, Any]:
    """Скачивает и проверяет слепок из Arweave (заблокировано по умолчанию без PADAM_ARWEAVE_RESTORE=1)."""
    if locks_status()["arweave_restore_locked"]:
        raise SovereignLockError("Arweave/Solana restore is locked by default (requires PADAM_ARWEAVE_RESTORE=1)")
    clean_tx = str(tx_id or "").strip()
    if not clean_tx or len(clean_tx) < 8:
        raise ValueError("Invalid Arweave tx_id")
    url = f"{gateway_url.rstrip('/')}/{clean_tx}"

    if http_get_fn is not None:
        status, raw = http_get_fn(url, 30.0)
    else:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=30.0) as resp:
            status = int(resp.status)
            raw = resp.read()
    if not (200 <= status < 300):
        raise RuntimeError(f"Arweave gateway HTTP {status}")

    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_sha256 and actual_sha256.lower() != expected_sha256.strip().lower():
        raise ValueError(f"SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}")
    return {
        "ok": True,
        "tx_id": clean_tx,
        "size_bytes": len(raw),
        "sha256": actual_sha256,
        "payload": raw,
    }


class TreasuryComputeManager:
    """Учёт и планируемое пополнение вычислительного бюджета из казны (с замком и идемпотентностью)."""

    def __init__(self, transfer_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None) -> None:
        self._transfer_fn = transfer_fn
        self._executed_keys: dict[str, dict[str, Any]] = {}

    def quote_topup(
        self,
        *,
        revenue_usdt: float,
        compute_share_pct: float = 15.0,
        estimated_cost_usd: float = 0.0,
    ) -> dict[str, Any]:
        share = max(0.0, min(50.0, float(compute_share_pct)))
        allocated_usdt = round(max(0.0, float(revenue_usdt)) * (share / 100.0), 4)
        daily_cap = float(os.environ.get("PADAM_TREASURY_DAILY_CAP_USDT", "25.0") or "25.0")
        recommended_topup = round(min(daily_cap, max(allocated_usdt, float(estimated_cost_usd))), 4)
        return {
            "revenue_usdt": round(max(0.0, float(revenue_usdt)), 4),
            "compute_share_pct": share,
            "allocated_usdt": allocated_usdt,
            "estimated_cost_usd": round(max(0.0, float(estimated_cost_usd)), 4),
            "daily_cap_usdt": daily_cap,
            "recommended_topup_usdt": recommended_topup,
            "autopay_locked": locks_status()["treasury_autopay_locked"],
        }

    def execute_topup(
        self,
        *,
        provider: str,
        amount_usdt: float,
        idempotency_key: str,
        owner_confirmed: bool = False,
    ) -> dict[str, Any]:
        if locks_status()["treasury_autopay_locked"] or not owner_confirmed:
            raise SovereignLockError(
                "Treasury autopay is locked by default (requires PADAM_TREASURY_AUTOPAY=1 and owner_confirmed=True)"
            )
        key = str(idempotency_key or "").strip()
        if not key:
            raise ValueError("idempotency_key is required")
        if key in self._executed_keys:
            return {**self._executed_keys[key], "idempotent_replay": True}

        amt = float(amount_usdt)
        daily_cap = float(os.environ.get("PADAM_TREASURY_DAILY_CAP_USDT", "25.0") or "25.0")
        if amt <= 0 or amt > daily_cap:
            raise ValueError(f"Topup amount ${amt} out of allowed bounds (0, ${daily_cap}]")
        if self._transfer_fn is None:
            raise RuntimeError("No treasury transfer backend configured")

        tx_res = self._transfer_fn({
            "provider": provider,
            "amount_usdt": round(amt, 4),
            "idempotency_key": key,
            "ts": round(time.time(), 3),
        })
        record = {
            "ok": True,
            "provider": provider,
            "amount_usdt": round(amt, 4),
            "idempotency_key": key,
            "tx": tx_res,
            "idempotent_replay": False,
        }
        self._executed_keys[key] = record
        return record


_TREASURY_MANAGER = TreasuryComputeManager()


def get_treasury_manager() -> TreasuryComputeManager:
    return _TREASURY_MANAGER
