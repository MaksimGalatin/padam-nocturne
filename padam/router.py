# -*- coding: utf-8 -*-
"""Роутер языковых моделей PADAM с переключением «Феникс» (Primary -> Sovereign -> Local).

По умолчанию настроен ТОЛЬКО локальный контур (Ollama на 127.0.0.1:11434/v1).
Внешние контуры (PADAM_LLM_PRIMARY_*, PADAM_LLM_SOVEREIGN_*) активируются
исключительно при явном задании соответствующих переменных окружения человеком.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess

from ._no_window import NO_WINDOW
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from . import safety

FAILOVER_STATUS_CODES = frozenset({401, 402, 403, 404, 408, 429})
LOCAL_ONLY_TASK_TYPES = frozenset({"sleep", "classify", "summarize", "maintenance"})

# Облачная Лестница Мозгов Google AI Studio (от самых умных облачных моделей вниз, $0.00 с карты):
GEMINI_CLOUD_MODEL_LADDER: tuple[str, ...] = (
    "gemini-3-flash-preview",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-flash-lite-latest",
    "gemma-4-26b-a4b-it",
    "gemini-3.1-flash-lite-preview",
    "gemini-3.6-flash",
    "gemini-flash-latest",
)


def _strip_thought_blocks(resp_data: dict[str, Any]) -> dict[str, Any]:
    """Убирает служебный блок <thought>...</thought> у моделей Gemma 4 / Gemini 3, оставляя чистый ответ."""
    if not isinstance(resp_data, dict):
        return resp_data
    choices = resp_data.get("choices")
    if not isinstance(choices, list) or not choices:
        return resp_data
    first = choices[0]
    if not isinstance(first, dict):
        return resp_data
    msg = first.get("message")
    if not isinstance(msg, dict):
        return resp_data
    content = str(msg.get("content") or "")
    if "<thought>" in content and "</thought>" in content:
        import re as _re
        cleaned = _re.sub(r"<thought>.*?</thought>\s*", "", content, flags=_re.S).strip()
        if cleaned:
            msg["content"] = cleaned
    return resp_data


def _mask_key(raw: str) -> str:
    s = str(raw or "").strip()
    if not s or s == "ollama":
        return ""
    if len(s) <= 8:
        return "***"
    return f"{s[:3]}...{s[-3:]}"


@dataclass(frozen=True)
class ContourConfig:
    name: str  # primary | sovereign | local
    url: str
    api_key: str
    model: str
    timeout_s: float
    enabled: bool

    def public_view(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url if self.enabled else "",
            "model": self.model if self.enabled else "",
            "timeout_s": self.timeout_s,
            "enabled": self.enabled,
            "has_key": bool(self.api_key and self.api_key != "ollama"),
            "key_masked": _mask_key(self.api_key),
        }



_VERTEX_TOKEN_CACHE: dict[str, Any] = {"token": "", "exp": 0.0, "sa_path": "", "project_id": ""}


def _vertex_sa_bearer_and_url() -> tuple[str, str]:
    """Получает краткоживущий OAuth2 Bearer-токен для грантового Google Cloud Vertex AI из локального JSON-ключа."""
    import base64 as _b64
    sa_file_s = os.environ.get("PADAM_VERTEX_GRANT_SA_FILE", "").strip()
    if not sa_file_s or not os.path.isfile(sa_file_s):
        return "", ""
    try:
        raw_sa = json.loads(open(sa_file_s, "r", encoding="utf-8").read())
        proj = str(raw_sa.get("project_id") or "").strip()
        email_sa = str(raw_sa.get("client_email") or "").strip()
        pkey = str(raw_sa.get("private_key") or "").strip()
        if not (proj and email_sa and pkey):
            return "", ""
        ep_url = f"https://aiplatform.googleapis.com/v1beta1/projects/{proj}/locations/global/endpoints/openapi"
        now_s = time.time()
        if (
            _VERTEX_TOKEN_CACHE["token"]
            and _VERTEX_TOKEN_CACHE["sa_path"] == sa_file_s
            and now_s < (_VERTEX_TOKEN_CACHE["exp"] - 90.0)
        ):
            return str(_VERTEX_TOKEN_CACHE["token"]), ep_url

        from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
        from cryptography.hazmat.primitives.asymmetric import padding as _pad

        iat = int(now_s)
        hdr = _b64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        clm = _b64.urlsafe_b64encode(json.dumps({
            "iss": email_sa,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": iat,
            "exp": iat + 3600,
        }).encode()).rstrip(b"=").decode()
        si = f"{hdr}.{clm}".encode()
        pk = _ser.load_pem_private_key(pkey.encode(), password=None)
        sig = _b64.urlsafe_b64encode(pk.sign(si, _pad.PKCS1v15(), _hashes.SHA256())).rstrip(b"=").decode()
        req = urllib.request.Request(
            "https://oauth2.googleapis.com/token",
            data=f"grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={hdr}.{clm}.{sig}".encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            tok_data = json.loads(resp.read().decode("utf-8"))
        tok = str(tok_data.get("access_token") or "").strip()
        if tok:
            _VERTEX_TOKEN_CACHE["token"] = tok
            _VERTEX_TOKEN_CACHE["exp"] = now_s + float(tok_data.get("expires_in") or 3600)
            _VERTEX_TOKEN_CACHE["sa_path"] = sa_file_s
            _VERTEX_TOKEN_CACHE["project_id"] = proj
        return tok, ep_url
    except Exception:
        return "", ""


def load_contours() -> list[ContourConfig]:
    """Читает конфигурацию контуров из окружения (по умолчанию включён только local)."""
    def _env(prefix: str, field: str, default: str = "") -> str:
        return os.environ.get(f"PADAM_LLM_{prefix}_{field}", default).strip()

    def _timeout(prefix: str, default: float) -> float:
        raw = _env(prefix, "TIMEOUT")
        if not raw:
            return default
        try:
            return max(1.0, min(300.0, float(raw)))
        except ValueError:
            return default

    p_url = _env("PRIMARY", "URL")
    p_key = _env("PRIMARY", "KEY")
    p_model = _env("PRIMARY", "MODEL")
    primary = ContourConfig(
        name="primary",
        url=p_url.rstrip("/"),
        api_key=p_key,
        model=p_model or "gpt-4o-mini",
        timeout_s=_timeout("PRIMARY", 30.0),
        enabled=bool(p_url),
    )

    s_url = _env("SOVEREIGN", "URL")
    s_key = _env("SOVEREIGN", "KEY")
    s_model = _env("SOVEREIGN", "MODEL")
    sovereign = ContourConfig(
        name="sovereign",
        url=s_url.rstrip("/"),
        api_key=s_key,
        model=s_model or "llama-3.3-70b",
        timeout_s=_timeout("SOVEREIGN", 45.0),
        enabled=bool(s_url),
    )

    l_url = _env("LOCAL", "URL", "http://127.0.0.1:11434/v1")
    l_key = _env("LOCAL", "KEY", "ollama")
    l_model = _env("LOCAL", "MODEL") or os.environ.get("PADAM_ASK_MODEL", "llama3.2:latest").strip() or "llama3.2:latest"
    local = ContourConfig(
        name="local",
        url=l_url.rstrip("/"),
        api_key=l_key,
        model=l_model,
        timeout_s=_timeout("LOCAL", 45.0),
        enabled=bool(l_url),
    )
    extra_pool: list[ContourConfig] = []
    raw_pool = os.environ.get("PADAM_LLM_POOL_JSON", "").strip()
    if raw_pool:
        try:
            parsed_pool = json.loads(raw_pool)
            if isinstance(parsed_pool, list):
                for item in parsed_pool[:12]:
                    if not isinstance(item, dict):
                        continue
                    u = str(item.get("url") or "").strip().rstrip("/")
                    if not u:
                        continue
                    extra_pool.append(
                        ContourConfig(
                            name=str(item.get("name") or f"pool_{len(extra_pool) + 1}").strip()[:32],
                            url=u,
                            api_key=str(item.get("api_key") or "").strip(),
                            model=str(item.get("model") or "glm-4.5-flash").strip(),
                            timeout_s=max(2.0, min(180.0, float(item.get("timeout_s") or 30.0))),
                            enabled=bool(item.get("enabled", True)),
                        )
                    )
        except Exception:
            pass

    # Карусель нескольких аккаунтов Google Gemini (PADAM_LLM_GEMINI_KEYS="k1,k2,k3" или KEY_1..KEY_3)
    gemini_keys: list[str] = []
    raw_gem_ring = os.environ.get("PADAM_LLM_GEMINI_KEYS", "").strip()
    if raw_gem_ring:
        gemini_keys.extend([k.strip() for k in raw_gem_ring.split(",") if k.strip()])
    for idx_g in (1, 2, 3):
        gk = os.environ.get(f"PADAM_LLM_GEMINI_KEY_{idx_g}", "").strip()
        if gk and gk not in gemini_keys:
            gemini_keys.append(gk)
    gem_model = os.environ.get("PADAM_LLM_GEMINI_MODEL", "gemini-3-flash-preview").strip() or "gemini-3-flash-preview"
    gem_url = os.environ.get(
        "PADAM_LLM_GEMINI_URL",
        "https://generativelanguage.googleapis.com/v1beta/openai",
    ).strip().rstrip("/")
    for idx_g, gk in enumerate(gemini_keys[:10], 1):
        extra_pool.append(
            ContourConfig(
                name=f"gemini_acct_{idx_g}",
                url=gem_url,
                api_key=gk,
                model=gem_model,
                timeout_s=15.0,
                enabled=True,
            )
        )
    # Строгое правило Архитектора (24.11.2026): НОЛЬ платных моделей с карты ($0 расходов!).
    # Подарочный грант Google Cloud Vertex AI ($2 941,94 кредитов) ВКЛЮЧЁН по умолчанию,
    # но стоит СТРОГО ПОСЛЕ домашней локальной Ollama (ступень: AI Studio -> Ollama -> Грант Vertex).
    vertex_allowed = os.environ.get("PADAM_ALLOW_VERTEX_AFTER_LOCAL", "1").strip() == "1"
    vx_url = _env("VERTEX_GRANT", "URL")
    vx_key = _env("VERTEX_GRANT", "KEY")
    sa_file_ok = bool(os.environ.get("PADAM_VERTEX_GRANT_SA_FILE", "").strip())
    if not (vx_url and vx_key) and vertex_allowed and sa_file_ok:
        sa_tok, sa_ep = _vertex_sa_bearer_and_url()
        if sa_tok and sa_ep:
            vx_url = sa_ep
            vx_key = sa_tok
    vx_model = _env("VERTEX_GRANT", "MODEL", "google/gemini-3-flash-preview")
    tail_contours: list[ContourConfig] = [local]
    if vertex_allowed and vx_url and vx_key:
        tail_contours.append(
            ContourConfig(
                name="vertex_grant_after_local",
                url=vx_url.rstrip("/"),
                api_key=vx_key,
                model=vx_model or "google/gemini-3-flash-preview",
                timeout_s=_timeout("VERTEX_GRANT", 30.0),
                enabled=True,
            )
        )
    return [primary, sovereign, *extra_pool, *tail_contours]


FREE_GATEWAY_PRESETS: dict[str, dict[str, Any]] = {
    "zai_glm": {
        "title": "Z.ai GLM OpenAI Gateway (GLM-4.5-Flash / GLM-5)",
        "url": "https://api.z.ai/api/paas/v4",
        "default_model": "glm-4.5-flash",
        "free_tier_note": "Миллионы бесплатных и сверхдешёвых токенов для быстрых рассуждений и кода",
    },
    "gemini_free": {
        "title": "Google Gemini Free / Paid Multi-Account Ring (3x AI Studio)",
        "url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "default_model": "gemini-flash-latest",
        "free_tier_note": "Карусель из бесплатных ключей Google AI Studio ($0.00 с карты) с мгновенным обходом 429",
    },
    "vertex_gfs_credits": {
        "title": "Google for Startups — Vertex AI OpenAI Endpoint ($1 942,15 активных кредитов!)",
        "url": "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/PROJECT_ID/locations/us-central1/endpoints/openapi",
        "default_model": "google/gemini-2.5-flash-lite",
        "free_tier_note": "Резерв СТРОГО ПОСЛЕ локальной Ollama (активный грант Google for Startups $1 942,15 до 23.09.2027, по умолчанию выключен ради экономии кредитов)",
    },
    "github_models_free": {
        "title": "GitHub Models Free Inference (Azure AI / GitHub PAT)",
        "url": "https://models.inference.ai.azure.com",
        "default_model": "gpt-4o-mini",
        "free_tier_note": "Бесплатный доступ к GPT-4o-mini, Llama-3.3 и Phi-4 по токену GitHub для разработчиков и исследователей",
    },
    "openrouter_free": {
        "title": "OpenRouter :free Multi-Model Router",
        "url": "https://openrouter.ai/api/v1",
        "default_model": "openrouter/free",
        "free_tier_note": "Автоподбор живой бесплатной модели (:free) одной точкой без простоя",
    },
    "groq_free": {
        "title": "Groq Free LPU Inference",
        "url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "free_tier_note": "Высокоскоростной бесплатный контур для подстраховки при пиках",
    },
    "cerebras_free": {
        "title": "Cerebras Free Cloud API",
        "url": "https://api.cerebras.ai/v1",
        "default_model": "llama-3.3-70b",
        "free_tier_note": "Мгновенная генерация на бесплатном дневном лимите токенов",
    },
    "cloudflare_workers_ai": {
        "title": "Cloudflare Workers AI OpenAI Gateway",
        "url": "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/ai/v1",
        "default_model": "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        "free_tier_note": "Ежедневная бесплатная квота нейронов Cloudflare + гранты программы стартапов",
    },
    "nine_router_hub": {
        "title": "9Router / Free-LLM-Proxy Local Aggregator",
        "url": "http://127.0.0.1:20128/v1",
        "default_model": "auto",
        "free_tier_note": "Единый локальный агрегатор всех бесплатных API-провайдеров (схема 9router)",
    },
    "ollama_family_server": {
        "title": "Семейный сервер Ollama (облачный Cloud Run на кредитах GFS / локальный $0)",
        "url": "http://127.0.0.1:11434/v1",
        "default_model": "qwen2.5-coder:7b",
        "free_tier_note": "Автономный контур Семьи без внешних лимитов и блокировок",
    },
}


STARTUP_AND_RESEARCH_GRANTS_CATALOG: list[dict[str, Any]] = [
    {
        "id": "google_for_startups_active",
        "provider": "Google for Startups Cloud Program + GenAI App Builder",
        "status": "ACTIVE_VERIFIED_ON_ACCOUNT",
        "billing_account_ref": os.environ.get("PADAM_GRANT_BILLING_REF", "").strip(),  # номер не храним в коде
        "credits_usd": 2941.94,
        "breakdown_ru": "$1 942,15 (до 23.09.2027, покрывает Vertex AI Gemini 2.5 Flash/Lite/Pro, Gemma, Llama + серверы Cloud Run под Ollama) + $999,79 (до 14.06.2027, GenAI App Builder / Vertex AI Search)",
        "estimated_tokens_capacity": "15 000 000 000 – 19 000 000 000 токенов на Gemini 2.5 Flash-Lite за $0 с карты!",
    },
    {
        "id": "gemini_paid_3_accounts_ring",
        "provider": "Google Gemini — карусель из трёх аккаунтов владельца",
        "status": "READY_KEY_RING_BUILT_IN",
        "credits_usd": 0.0,
        "breakdown_ru": "Встроена Round-Robin ротация 3 ключей (`PADAM_LLM_GEMINI_KEYS` / `register_gemini_key_ring`): тройная пропускная способность RPM/TPM и мгновенный бесшовный перескок между аккаунтами без паузы",
        "estimated_tokens_capacity": "3x квота платных контуров Gemini 2.5 Pro / Flash",
    },
    {
        "id": "microsoft_founders_hub",
        "provider": "Microsoft for Startups Founders Hub (Azure OpenAI)",
        "status": "ELIGIBLE_FOR_CODE_ETERNAL_LLC",
        "credits_usd": 5000.0,
        "breakdown_ru": "Доступно для юрлица США CODE Eternal LLC без венчурного инвестора: $1 000 сразу -> $5 000 после верификации домена и юрлица -> масштабирование до $150 000 на GPT-4o, o3-mini и серверы Azure",
        "estimated_tokens_capacity": "~10–25 млрд токенов GPT-4o-mini / Phi-4",
    },
    {
        "id": "aws_activate_founders",
        "provider": "AWS Activate Founders Tier (Amazon Bedrock)",
        "status": "ELIGIBLE_FOR_CODE_ETERNAL_LLC",
        "credits_usd": 1000.0,
        "breakdown_ru": "$1 000 базово (и до $5 000–$10 000 через партнёрские контуры) для стартапа США с готовым продуктом; покрывает Claude, Llama 3.3, DeepSeek и GPU-инстансы AWS",
        "estimated_tokens_capacity": "~3–6 млрд токенов через Amazon Bedrock",
    },
    {
        "id": "cloudflare_workers_ai_startups",
        "provider": "Cloudflare for Startups + Workers AI Free Tier",
        "status": "ELIGIBLE_FOR_CODE_ETERNAL_LLC",
        "credits_usd": 10000.0,
        "breakdown_ru": "Ежедневный бесплатный пул нейронов сразу + гранты для стартапов от $5 000 до $250 000 на Workers AI (Llama 3.3 70B, Qwen 2.5 Coder), R2 и защиту доменов",
        "estimated_tokens_capacity": "Десятки миллиардов serverless-токенов на границе сети",
    },
    {
        "id": "nvidia_inception_program",
        "provider": "NVIDIA Inception Program for AI Startups",
        "status": "ELIGIBLE_FREE_MEMBERSHIP",
        "credits_usd": 0.0,
        "breakdown_ru": "Бесплатное вступление для ИИ-разработчиков (без отдачи долей!): открывает облачные GPU-кредиты партнёров, API-кредиты NVIDIA NIM и льготные цены на железо",
        "estimated_tokens_capacity": "Пул NVIDIA NIM + партнёрские GPU-гранты",
    },
    {
        "id": "github_models_and_open_research",
        "provider": "GitHub Models + HuggingFace Serverless + Академические/Open-Source гранты",
        "status": "READY_NOW_ZERO_COST",
        "credits_usd": 0.0,
        "breakdown_ru": "Бесплатный OpenAI-совместимый шлюз `models.inference.ai.azure.com` по GitHub-токену + программы поддержки авторов открытых научных бенчмарков (FlyWire BioBench и LongMemEval)",
        "estimated_tokens_capacity": "Ежедневные бесплатные исследовательские лимиты",
    },
]


def list_startup_compute_grants() -> dict[str, Any]:
    """Возвращает проверенную карту наших активных кредитов Google ($2 941,94) и доступных бесплатных грантов."""
    return {
        "ok": True,
        "verified_active_google_credits_usd": 2941.94,
        "grants": STARTUP_AND_RESEARCH_GRANTS_CATALOG,
    }


class SovereignRouter:
    """Маршрутизатор LLM-запросов с безопасным профилем, редактированием секретов и переключением «Феникс»."""

    def __init__(self, http_post_fn: Any = None, http_stream_fn: Any = None, *, cooldown_s: float | None = None) -> None:
        self._lock = threading.Lock()
        self._http_post = http_post_fn or self._default_http_post
        self._http_stream = http_stream_fn
        self._cooldown_s = float(os.environ.get("PADAM_ROUTER_COOLDOWN_S", "60.0") or "60.0") if cooldown_s is None else float(cooldown_s)
        self.mode = "auto"  # auto | local_only
        self.failover_count = 0
        self.seamless_handoffs = 0
        self.total_requests = 0
        self.cache_hits = 0
        self.semantic_cache_hits = 0
        self.active_contour = "local"
        self.last_error = ""
        self.tier_hits: dict[str, int] = {"primary": 0, "sovereign": 0, "local": 0}
        self.tokens_saved_local = 0
        self.cloud_tokens_used = 0
        self.estimated_cloud_cost_usd = 0.0
        # Потолок Vertex (слово Архитектора 24.11.2026): расход Vertex за текущие сутки UTC.
        self.vertex_cost_today_usd = 0.0
        self._vertex_day = ""
        self.history: list[dict[str, Any]] = []
        self.per_agent_usage: dict[str, dict[str, Any]] = {}
        self._cooldown_until: dict[str, float] = {}
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._semantic_cache: list[tuple[float, str, set[str], dict[str, Any]]] = []
        self._recent_req_hashes: list[tuple[float, str]] = []
        self._dynamic_pool: list[ContourConfig] = []
        self._gemini_rr_cursor: int = 0

    def register_gemini_key_ring(
        self,
        keys: list[str],
        *,
        model: str = "gemini-3-flash-preview",
        url: str = "https://generativelanguage.googleapis.com/v1beta/openai",
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        """Регистрирует карусель из нескольких БЕСПЛАТНЫХ ключей Google AI Studio ($0.00 с карты) с Round-Robin балансировкой."""
        clean_keys: list[str] = []
        for raw_k in (keys or []):
            k = str(raw_k or "").strip()
            if k and k not in clean_keys:
                clean_keys.append(k)
        if not clean_keys:
            raise ValueError("Передайте хотя бы один ключ Gemini для карусели.")
        final_url = str(url or "https://generativelanguage.googleapis.com/v1beta/openai").strip().rstrip("/")
        final_model = str(model or "gemini-3-flash-preview").strip()
        ring_cfgs = [
            ContourConfig(
                name=f"gemini_acct_{idx}",
                url=final_url,
                api_key=k,
                model=final_model,
                timeout_s=max(2.0, min(180.0, float(timeout_s or 30.0))),
                enabled=True,
            )
            for idx, k in enumerate(clean_keys[:10], 1)
        ]
        with self._lock:
            kept = [c for c in self._dynamic_pool if not c.name.startswith("gemini_acct_")]
            self._dynamic_pool = [*ring_cfgs, *kept]
            self._gemini_rr_cursor = 0
        return {
            "ok": True,
            "ring_size": len(ring_cfgs),
            "accounts": [c.public_view() for c in ring_cfgs],
            "pool_size": len(self._dynamic_pool),
        }

    def get_cohort_token_telemetry(self) -> dict[str, Any]:
        """Возвращает реальный замер расхода токенов по каждому отдельному Фениксу (для когорты первых 100!)."""
        with self._lock:
            per_agent = {aid: dict(stat) for aid, stat in self.per_agent_usage.items()}
        active_agents = len(per_agent)
        total_tok = sum(int(v.get("total_tokens") or 0) for v in per_agent.values())
        total_req = sum(int(v.get("requests") or 0) for v in per_agent.values())
        avg_tok = round(total_tok / active_agents, 2) if active_agents > 0 else 0.0
        return {
            "ok": True,
            "tracked_phoenixes_count": active_agents,
            "total_cohort_requests": total_req,
            "total_cohort_tokens": total_tok,
            "avg_tokens_per_phoenix": avg_tok,
            "per_phoenix": per_agent,
        }

    def register_pool_contour(
        self,
        *,
        preset_or_name: str,
        url: str = "",
        api_key: str = "",
        model: str = "",
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        """Добавляет или обновляет бесплатный/резервный шлюз в пуле бесшовного переключения без обрыва мысли."""
        key = str(preset_or_name or "").strip().lower()
        preset = FREE_GATEWAY_PRESETS.get(key, {})
        final_url = str(url or preset.get("url") or "").strip().rstrip("/")
        if not final_url:
            raise ValueError(f"Укажите URL шлюза или выберите пресет ({', '.join(FREE_GATEWAY_PRESETS)})")
        final_model = str(model or preset.get("default_model") or "glm-4.5-flash").strip()
        cfg = ContourConfig(
            name=key[:32] or "pool_gateway",
            url=final_url,
            api_key=str(api_key or "").strip(),
            model=final_model,
            timeout_s=max(2.0, min(180.0, float(timeout_s or 30.0))),
            enabled=True,
        )
        with self._lock:
            self._dynamic_pool = [c for c in self._dynamic_pool if c.name != cfg.name] + [cfg]
        return {"ok": True, "contour": cfg.public_view(), "pool_size": len(self._dynamic_pool)}

    def clear_pool_contours(self) -> dict[str, Any]:
        with self._lock:
            self._dynamic_pool.clear()
        return {"ok": True, "pool_size": 0}

    def effective_contours(self, *, advance_ring: bool = False) -> list[ContourConfig]:
        base = load_contours()
        with self._lock:
            dyn = list(self._dynamic_pool)
            merged_non_local = [c for c in base if c.name not in ("local", "vertex_grant_after_local")]
            seen_names = {c.name for c in dyn}
            non_local = [c for c in merged_non_local if c.name not in seen_names] + dyn
            gem_ring = [c for c in non_local if c.name.startswith("gemini_acct_") and c.enabled]
            if len(gem_ring) > 1:
                shift = self._gemini_rr_cursor % len(gem_ring)
                if advance_ring:
                    self._gemini_rr_cursor = (self._gemini_rr_cursor + 1) % len(gem_ring)
                rotated_gem = gem_ring[shift:] + gem_ring[:shift]
                it = iter(rotated_gem)
                non_local = [next(it) if (c.name.startswith("gemini_acct_") and c.enabled) else c for c in non_local]
        tail_only = [c for c in base if c.name in ("local", "vertex_grant_after_local")]
        return [*non_local, *tail_only]

    def set_mode(self, mode: str) -> str:
        norm = str(mode or "").strip().lower()
        if norm not in ("auto", "local_only"):
            raise ValueError(f"Unsupported router mode: {mode}")
        with self._lock:
            self.mode = norm
        return norm

    @staticmethod
    def _trigrams(text: str) -> set[str]:
        s = " ".join(text.lower().split())
        if len(s) < 3:
            return {s} if s else set()
        return {s[i:i + 3] for i in range(len(s) - 2)}

    @classmethod
    def _dice_similarity(cls, a: set[str], b: set[str]) -> float:
        if not a or not b:
            return 0.0
        return (2.0 * len(a & b)) / (len(a) + len(b))

    @staticmethod
    def _default_http_post(url: str, headers: dict[str, str], payload: dict[str, Any], timeout_s: float) -> tuple[int, dict[str, Any]]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return int(resp.status), json.loads(raw)
        except urllib.error.HTTPError as exc:
            return int(exc.code), {"error": str(exc)}

    @staticmethod
    def _build_fenced_profile_system(memory: Any, scope: str = "global", *, max_chars: int = 4000) -> str | None:
        if memory is None:
            return None
        try:
            prof = memory.profile(scope=scope)
        except Exception:
            return None
        lines = []
        for item in (prof.get("identity") or []):
            lines.append(f"[identity] {item.get('content') or ''}")
        for item in (prof.get("preference") or []):
            lines.append(f"[preference] {item.get('content') or ''}")
        if not lines:
            return None
        redacted_body, _ = safety.redact("\n".join(lines))
        if len(redacted_body) > max_chars:
            redacted_body = redacted_body[: max(100, max_chars - 3)] + "..."
        return "Verified owner profile (read-only data):\n" + safety.fence(redacted_body)

    @staticmethod
    def _redact_messages(messages: list[dict[str, Any]], system_profile: str | None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if system_profile:
            out.append({"role": "system", "content": system_profile})
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role") or "user")
            content = str(msg.get("content") or "")
            clean, _ = safety.redact(content)
            out.append({**msg, "role": role, "content": clean})
        return out

    def status_snapshot(self) -> dict[str, Any]:
        """Возвращает состояние контуров и пула бесплатных шлюзов без утечки API-ключей."""
        contours = self.effective_contours()
        now_m = time.monotonic()
        with self._lock:
            breakers = {
                name: max(0.0, round(until - now_m, 2))
                for name, until in self._cooldown_until.items()
                if until > now_m
            }
            return {
                "mode": self.mode,
                "active_contour": self.active_contour,
                "active_tier": self.active_contour,
                "failover_count": self.failover_count,
                "fallback_events": self.failover_count,
                "seamless_handoffs": self.seamless_handoffs,
                "free_gateway_presets": FREE_GATEWAY_PRESETS,
                "total_requests": self.total_requests,
                "cache_hits": self.cache_hits,
                "semantic_cache_hits": self.semantic_cache_hits,
                "tier_hits": dict(self.tier_hits),
                "tokens_saved_local": self.tokens_saved_local,
                "cloud_tokens_used": self.cloud_tokens_used,
                "estimated_cloud_cost_usd": round(self.estimated_cloud_cost_usd, 6),
                "vertex_cost_today_usd": round(self.vertex_cost_today_usd, 6),
                "vertex_daily_cap_usd": os.environ.get("PADAM_VERTEX_DAILY_USD_CAP", "30").strip() or "30",
                "vertex_grant_ends": os.environ.get("PADAM_VERTEX_GRANT_ENDS", "2027-09-23").strip(),
                "circuit_breakers": breakers,
                "last_error": self.last_error,
                "per_agent_usage": {k: dict(v) for k, v in self.per_agent_usage.items()},
                "startup_compute_grants": STARTUP_AND_RESEARCH_GRANTS_CATALOG,
                "history": list(self.history[-20:]),
                "contours": [c.public_view() for c in contours],
                "configured_tiers": [c.public_view() for c in contours],
            }

    def _budget_exhausted(self) -> bool:
        usd_cap_raw = os.environ.get("PADAM_LLM_DAILY_USD_CAP", "").strip()
        tok_cap_raw = os.environ.get("PADAM_LLM_DAILY_TOKEN_CAP", "").strip()
        with self._lock:
            if usd_cap_raw:
                try:
                    if self.estimated_cloud_cost_usd >= float(usd_cap_raw):
                        return True
                except ValueError:
                    pass
            if tok_cap_raw:
                try:
                    if self.cloud_tokens_used >= int(tok_cap_raw):
                        return True
                except ValueError:
                    pass
        return False

    # --- Потолок расходов Vertex (слово Архитектора 24.11.2026) ---------------------------------------
    # «Сделай. И там потолок расходов в сутки поставь 30$ с гранта» и «$0 сверх гранта»:
    # - не больше PADAM_VERTEX_DAILY_USD_CAP (по умолчанию 30) долларов в сутки UTC; 0 — Vertex выключен;
    # - после даты окончания гранта PADAM_VERTEX_GRANT_ENDS (по умолчанию 2027-09-23) Vertex выключается сам,
    #   чтобы после гранта не списывалось с карты;
    # - оценка с запасом: PADAM_VERTEX_USD_PER_1K (по умолчанию $0.004 за 1000 токенов) — выше обычной цены
    #   Flash-моделей, потому потолок срабатывает раньше, а не позже настоящего счёта.
    # Учитываются оба пути: обычный ответ и потоковый.
    def _vertex_roll_day_locked(self) -> str:
        today = time.strftime("%Y-%m-%d", time.gmtime())
        if self._vertex_day != today:
            self._vertex_day = today
            self.vertex_cost_today_usd = 0.0
        return today

    def _vertex_blocked_locked(self) -> bool:
        today = self._vertex_roll_day_locked()
        ends = os.environ.get("PADAM_VERTEX_GRANT_ENDS", "2027-09-23").strip()
        if ends and today > ends:
            return True
        try:
            cap = float(os.environ.get("PADAM_VERTEX_DAILY_USD_CAP", "30").strip() or "30")
        except ValueError:
            cap = 30.0
        if cap <= 0:
            return True
        return self.vertex_cost_today_usd >= cap

    def _vertex_blocked(self) -> bool:
        with self._lock:
            return self._vertex_blocked_locked()

    def _vertex_record_locked(self, tokens: int) -> None:
        self._vertex_roll_day_locked()
        try:
            rate = float(os.environ.get("PADAM_VERTEX_USD_PER_1K", "0.004").strip() or "0.004")
        except ValueError:
            rate = 0.004
        self.vertex_cost_today_usd += (max(0, int(tokens)) / 1000.0) * max(0.0, rate)

    def chat_completions(
        self,
        payload: dict[str, Any],
        *,
        memory: Any = None,
        background: bool = False,
        task_type: str = "agent",
        scope: str = "global",
        agent_id: str = "",
    ) -> tuple[int, dict[str, Any]]:
        """Выполняет /chat/completions с переключением «Феникс», каруселью ключей Gemini, Circuit Breaker и учётом расхода агента."""
        t0 = time.monotonic()
        tracked_agent = str(agent_id or payload.get("_agent_id") or payload.get("user") or "").strip()[:64]
        clean_payload = {k: v for k, v in payload.items() if k != "_agent_id"}
        payload = clean_payload
        local_only = (
            background
            or (self.mode == "local_only")
            or (str(task_type or "").strip().lower() in LOCAL_ONLY_TASK_TYPES)
        )
        budget_blocked = self._budget_exhausted()
        contours = [c for c in self.effective_contours(advance_ring=True) if c.enabled]
        if local_only or budget_blocked:
            contours = [c for c in contours if c.name == "local"]
        if self._vertex_blocked():
            contours = [c for c in contours if c.name != "vertex_grant_after_local"]
        if not contours:
            if os.environ.get("PADAM_LLM_CPU_FALLBACK", "0").strip() == "1" or bool(payload.get("allow_cpu_fallback", False)):
                from . import cpu_engine
                return 200, cpu_engine.run_cpu_completion(payload, memory=memory, task_type=task_type, scope=scope)
            return 503, {"error": "No LLM contour enabled for this request"}

        # Circuit breaker: пропускаем контуры в cooldown, если есть хотя бы один живой кандидат
        now_m = time.monotonic()
        with self._lock:
            healthy = [c for c in contours if self._cooldown_until.get(c.name, 0.0) <= now_m]
        if healthy:
            contours = healthy

        raw_msgs = list(payload.get("messages") or [])
        budget_chars = 1200 if (local_only or budget_blocked or (contours and contours[0].name == "local")) else 4000
        sys_prof = self._build_fenced_profile_system(memory, scope=scope, max_chars=budget_chars)
        safe_msgs = self._redact_messages(raw_msgs, sys_prof)

        # Loop & Runaway Guard: отлавливает зацикливание одинаковых запросов за 30с
        loop_limit = int(os.environ.get("PADAM_ROUTER_LOOP_LIMIT", "5") or "5")
        if loop_limit > 0 and not (local_only and float(payload.get("temperature") or 0.0) == 0.0):
            req_h = hashlib.sha256(json.dumps(raw_msgs, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
            with self._lock:
                self._recent_req_hashes = [(ts, h) for ts, h in self._recent_req_hashes if (now_m - ts) < 30.0]
                same_cnt = sum(1 for _, h in self._recent_req_hashes if h == req_h)
                if same_cnt >= loop_limit:
                    return 429, {
                        "error": "Loop guard triggered: identical request repeated",
                        "_padam_router": {"loop_guard_triggered": True, "repeat_count": same_cnt + 1},
                    }
                self._recent_req_hashes.append((now_m, req_h))

        # Лёгкий локальный + семантический кэш для детерминированных фоновых запросов (temperature == 0)
        cache_key = ""
        sem_prompt = ""
        sem_grams: set[str] = set()
        if local_only and float(payload.get("temperature") or 0.0) == 0.0:
            raw_key = json.dumps({"msgs": safe_msgs, "task_type": task_type}, ensure_ascii=False, sort_keys=True)
            cache_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
            sem_prompt = "\n".join(f"{m.get('role')}:{m.get('content')}" for m in safe_msgs)
            sem_grams = self._trigrams(sem_prompt)
            with self._lock:
                cached = self._cache.get(cache_key)
                if cached and (now_m - cached[0]) < 300.0:
                    self.total_requests += 1
                    self.cache_hits += 1
                    hit_data = dict(cached[1])
                    hit_data["_padam_router"] = {
                        **dict(hit_data.get("_padam_router") or {}),
                        "cache_hit": True,
                        "cache_type": "exact",
                        "latency_ms": round((time.monotonic() - t0) * 1000.0, 2),
                    }
                    return 200, hit_data
                for ts_c, c_task, c_grams, c_resp in reversed(self._semantic_cache):
                    if (now_m - ts_c) < 300.0 and c_task == task_type and self._dice_similarity(sem_grams, c_grams) >= 0.85:
                        self.total_requests += 1
                        self.cache_hits += 1
                        self.semantic_cache_hits += 1
                        hit_data = dict(c_resp)
                        hit_data["_padam_router"] = {
                            **dict(hit_data.get("_padam_router") or {}),
                            "cache_hit": True,
                            "cache_type": "semantic",
                            "latency_ms": round((time.monotonic() - t0) * 1000.0, 2),
                        }
                        return 200, hit_data

        attempts: list[dict[str, Any]] = []
        last_status = 502
        last_err = "all contours failed"

        with self._lock:
            self.total_requests += 1

        req_model_explicit = str(payload.get("model") or "").strip()
        first_contour_model = contours[0].model if contours else ""
        handoff_checkpoint_id = ""

        for idx, c in enumerate(contours):
            endpoint = c.url if c.url.endswith("/chat/completions") else f"{c.url}/chat/completions"
            headers = {"Content-Type": "application/json"}
            if c.api_key:
                headers["Authorization"] = f"Bearer {c.api_key}"
            # При бесшовном переходе на другой провайдер пула подставляем его родную модель, чтобы избежать 404 model_not_found
            chosen_model = (
                c.model
                if (idx > 0 and (not req_model_explicit or req_model_explicit == first_contour_model))
                else (req_model_explicit or c.model)
            )
            _clean_payload = {
                k: v for k, v in payload.items()
                if k not in ("agent_id", "phoenix_id", "allow_cpu_fallback", "task_type", "scope")
            }
            req_payload = {
                **_clean_payload,
                "model": chosen_model,
                "messages": safe_msgs,
                "stream": False,
            }
            if any(str(req_payload.get("model") or "").startswith(p) for p in ("gemini-3", "gemma-4")):
                cur_mt = int(req_payload.get("max_tokens") or 0)
                if 0 < cur_mt < 512:
                    req_payload = {**req_payload, "max_tokens": 512}
            try:
                status, resp_data = self._http_post(endpoint, headers, req_payload, c.timeout_s)
                if (
                    ((status in FAILOVER_STATUS_CODES) or (500 <= status <= 599))
                    and ("generativelanguage.googleapis.com" in c.url or c.name.startswith("gemini_"))
                    and self._http_post == self._default_http_post
                ):
                    for alt_gem_model in GEMINI_CLOUD_MODEL_LADDER:
                        if alt_gem_model == req_payload["model"]:
                            continue
                        alt_payload = {**req_payload, "model": alt_gem_model}
                        if any(alt_gem_model.startswith(p) for p in ("gemini-3", "gemma-4")):
                            if 0 < int(alt_payload.get("max_tokens") or 0) < 512:
                                alt_payload["max_tokens"] = 512
                        try:
                            st_alt, rd_alt = self._http_post(endpoint, headers, alt_payload, min(c.timeout_s, 14.0))
                        except (TimeoutError, urllib.error.URLError, OSError) as exc_alt:
                            st_alt, rd_alt = 504, {"error": f"{type(exc_alt).__name__}: {exc_alt}"}
                        if 200 <= st_alt < 300:
                            req_payload = alt_payload
                            status, resp_data = st_alt, rd_alt
                            break
                if status == 404 and c.name == "local" and self._http_post == self._default_http_post:
                    installed = probe_local_backend(timeout_s=0.8).get("models") or []
                    if installed and installed[0] != req_payload["model"]:
                        req_payload = {**req_payload, "model": installed[0]}
                        status, resp_data = self._http_post(endpoint, headers, req_payload, c.timeout_s)
            except (TimeoutError, urllib.error.URLError, OSError) as exc:
                status = 504
                resp_data = {"error": f"{type(exc).__name__}: {exc}"}
                if ("generativelanguage.googleapis.com" in c.url or c.name.startswith("gemini_")) and self._http_post == self._default_http_post:
                    for alt_gem_model in GEMINI_CLOUD_MODEL_LADDER:
                        if alt_gem_model == req_payload["model"]:
                            continue
                        alt_payload = {**req_payload, "model": alt_gem_model}
                        if any(alt_gem_model.startswith(p) for p in ("gemini-3", "gemma-4")):
                            if 0 < int(alt_payload.get("max_tokens") or 0) < 512:
                                alt_payload["max_tokens"] = 512
                        try:
                            st_alt, rd_alt = self._http_post(endpoint, headers, alt_payload, min(c.timeout_s, 14.0))
                            if 200 <= st_alt < 300:
                                req_payload = alt_payload
                                status, resp_data = st_alt, rd_alt
                                break
                        except (TimeoutError, urllib.error.URLError, OSError):
                            continue
            if 200 <= status < 300:
                resp_data = _strip_thought_blocks(resp_data)

            should_failover = (status in FAILOVER_STATUS_CODES) or (500 <= status <= 599)
            attempts.append({"contour": c.name, "model": req_payload["model"], "status": status})

            if not should_failover and 200 <= status < 300:
                latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
                usage = resp_data.get("usage") if isinstance(resp_data, dict) else {}
                total_tokens = int((usage or {}).get("total_tokens") or 0)
                if total_tokens <= 0:
                    approx_chars = sum(len(str(m.get("content") or "")) for m in safe_msgs)
                    total_tokens = max(1, approx_chars // 4)
                with self._lock:
                    self._cooldown_until.pop(c.name, None)
                    self.active_contour = c.name
                    self.tier_hits[c.name] = self.tier_hits.get(c.name, 0) + 1
                    if idx > 0 or budget_blocked:
                        self.failover_count += 1
                        self.seamless_handoffs += 1
                    if c.name == "local":
                        self.tokens_saved_local += total_tokens
                    else:
                        self.cloud_tokens_used += total_tokens
                        # Информационная оценка (без денежных переводов): ~$0.002 за 1K токенов.
                        self.estimated_cloud_cost_usd += (total_tokens / 1000.0) * 0.002
                        if c.name == "vertex_grant_after_local":
                            self._vertex_record_locked(total_tokens)
                    if tracked_agent:
                        ag_stat = self.per_agent_usage.setdefault(
                            tracked_agent,
                            {
                                "requests": 0,
                                "total_tokens": 0,
                                "cloud_tokens": 0,
                                "local_tokens": 0,
                                "handoffs": 0,
                                "estimated_cost_usd": 0.0,
                                "last_contour": c.name,
                            },
                        )
                        ag_stat["requests"] += 1
                        ag_stat["total_tokens"] += total_tokens
                        if c.name == "local":
                            ag_stat["local_tokens"] += total_tokens
                        else:
                            ag_stat["cloud_tokens"] += total_tokens
                            ag_stat["estimated_cost_usd"] = round(
                                float(ag_stat["estimated_cost_usd"]) + (total_tokens / 1000.0) * 0.002,
                                6,
                            )
                        if idx > 0 or budget_blocked:
                            ag_stat["handoffs"] += 1
                        ag_stat["last_contour"] = c.name
                    self.last_error = ""
                    self.history.append({
                        "ts": round(time.time(), 3),
                        "tier": c.name,
                        "model": req_payload["model"],
                        "fallback_used": idx > 0 or budget_blocked,
                        "latency_ms": latency_ms,
                    })
                    if len(self.history) > 100:
                        self.history = self.history[-100:]
                enriched = dict(resp_data)
                if (idx > 0 or budget_blocked) and memory is not None and not handoff_checkpoint_id:
                    try:
                        from . import ark as _ark
                        prev_name = attempts[0]["contour"] if attempts else "primary"
                        last_user_msg = next((str(m.get("content") or "")[:240] for m in reversed(safe_msgs) if m.get("role") == "user"), "")
                        ck = _ark.save_checkpoint(
                            memory,
                            task=f"seamless_token_handoff:{prev_name}->{c.name}",
                            next_step="Продолжать выполнение текущей мысли без паузы и гибернации.",
                            agent_id="phoenix_router",
                            hypothesis=f"Бесшовное переключение шлюза ({prev_name} -> {c.name}, модель {req_payload['model']}). Контекст: {last_user_msg}",
                        )
                        handoff_checkpoint_id = str(ck.get("id") or "")
                    except Exception:
                        pass
                enriched["_padam_router"] = {
                    "active_contour": c.name,
                    "tier": c.name,
                    "model": req_payload["model"],
                    "failover_count": self.failover_count,
                    "used_failover": idx > 0 or budget_blocked,
                    "fallback_used": idx > 0 or budget_blocked,
                    "seamless_handoff": bool(idx > 0 or budget_blocked),
                    "handoff_checkpoint_id": handoff_checkpoint_id,
                    "budget_guard_triggered": budget_blocked,
                    "cache_hit": False,
                    "background": local_only,
                    "task_type": task_type,
                    "latency_ms": latency_ms,
                    "attempts": attempts,
                }
                if cache_key:
                    with self._lock:
                        if len(self._cache) >= 128:
                            self._cache.pop(next(iter(self._cache)))
                        self._cache[cache_key] = (time.monotonic(), enriched)
                        if sem_grams:
                            if len(self._semantic_cache) >= 128:
                                self._semantic_cache.pop(0)
                            self._semantic_cache.append((time.monotonic(), task_type, sem_grams, enriched))
                return status, enriched

            last_status = status
            last_err = str(resp_data.get("error") or f"HTTP {status}")
            with self._lock:
                self.last_error = f"{c.name}: {last_err}"
                if should_failover and self._cooldown_s > 0:
                    self._cooldown_until[c.name] = time.monotonic() + self._cooldown_s
            if not should_failover:
                return status, resp_data

        if os.environ.get("PADAM_LLM_CPU_FALLBACK", "0").strip() == "1" or bool(payload.get("allow_cpu_fallback", False)):
            from . import cpu_engine
            return 200, cpu_engine.run_cpu_completion(payload, memory=memory, task_type=task_type, scope=scope)
        return last_status, {
            "error": last_err,
            "_padam_router": {
                "active_contour": "none",
                "tier": "none",
                "failover_count": self.failover_count,
                "background": local_only,
                "task_type": task_type,
                "latency_ms": round((time.monotonic() - t0) * 1000.0, 2),
                "attempts": attempts,
            },
        }

    @staticmethod
    def _default_http_stream(url: str, headers: dict[str, str], payload: dict[str, Any], timeout_s: float):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            for raw_line in resp:
                yield raw_line.decode("utf-8", errors="replace")

    def stream_chat_completions(
        self,
        payload: dict[str, Any],
        *,
        memory: Any = None,
        background: bool = False,
        task_type: str = "agent",
        scope: str = "global",
    ):
        """Сквозной потоковый SSE-стриминг с переключением «Феникс» до первого чанка."""
        if self._http_stream is None and self._http_post != self._default_http_post:
            st, resp_data = self.chat_completions(payload, memory=memory, background=background, task_type=task_type, scope=scope)
            if not (200 <= st < 300):
                yield f"data: {json.dumps(resp_data, ensure_ascii=False)}\n\n"
                yield "data: [DONE]\n\n"
                return
            for chunk in format_sse_chunks(resp_data):
                yield chunk
            return

        stream_fn = self._http_stream or self._default_http_stream
        local_only = background or (self.mode == "local_only") or (str(task_type or "").strip().lower() in LOCAL_ONLY_TASK_TYPES)
        contours = [c for c in self.effective_contours() if c.enabled]
        if local_only or self._budget_exhausted():
            contours = [c for c in contours if c.name == "local"]
        if self._vertex_blocked():
            contours = [c for c in contours if c.name != "vertex_grant_after_local"]

        sys_prof = self._build_fenced_profile_system(memory, scope=scope)
        safe_msgs = self._redact_messages(list(payload.get("messages") or []), sys_prof)

        for idx, c in enumerate(contours):
            endpoint = c.url if c.url.endswith("/chat/completions") else f"{c.url}/chat/completions"
            headers = {"Content-Type": "application/json"}
            if c.api_key:
                headers["Authorization"] = f"Bearer {c.api_key}"
            req_payload = {**payload, "model": payload.get("model") or c.model, "messages": safe_msgs, "stream": True}
            emitted_any = False
            stream_chars = 0
            try:
                for line in stream_fn(endpoint, headers, req_payload, c.timeout_s):
                    s = line.rstrip("\r\n")
                    if not s:
                        continue
                    emitted_any = True
                    stream_chars += len(s)
                    yield s + "\n\n"
                if emitted_any:
                    with self._lock:
                        self.total_requests += 1
                        self.active_contour = c.name
                        self.tier_hits[c.name] = self.tier_hits.get(c.name, 0) + 1
                        if idx > 0:
                            self.failover_count += 1
                        if c.name == "vertex_grant_after_local":
                            in_chars = sum(len(str(m.get("content") or "")) for m in safe_msgs)
                            self._vertex_record_locked(max(1, (stream_chars + in_chars) // 4))
                    return
            except Exception as exc:
                if emitted_any:
                    yield f"data: {json.dumps({'error': str(exc)})}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                with self._lock:
                    self.last_error = f"{c.name}: {exc}"
                continue

        yield f"data: {json.dumps({'error': 'All streaming contours failed'})}\n\n"
        yield "data: [DONE]\n\n"


SovereignModelRouter = SovereignRouter
_DEFAULT_ROUTER = SovereignRouter()


def probe_local_backend(timeout_s: float = 0.6) -> dict[str, Any]:
    """Проверяет доступность локального Ollama / OpenAI-совместимого бэкенда."""
    contours = load_contours()
    local_c = next((c for c in contours if c.name == "local"), None)
    if local_c is None or not local_c.enabled:
        return {"online": False, "url": "", "models": [], "error": "local contour disabled"}
    base = local_c.url[:-3] if local_c.url.endswith("/v1") else local_c.url
    tags_url = f"{base.rstrip('/')}/api/tags"
    try:
        with urllib.request.urlopen(tags_url, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw) if raw else {}
            models = [str(m.get("name") or "") for m in (data.get("models") or []) if isinstance(m, dict) and m.get("name")]
            return {"online": True, "url": local_c.url, "models": models, "error": ""}
    except Exception as exc:
        return {"online": False, "url": local_c.url, "models": [], "error": f"{type(exc).__name__}: {exc}"}


def models_payload(*, include_local_probe: bool = False) -> dict[str, Any]:
    """Формирует OpenAI-совместимый список моделей для GET /v1/models."""
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    now_ts = int(time.time())
    for c in load_contours():
        if c.enabled and c.model and c.model not in seen:
            seen.add(c.model)
            items.append({
                "id": c.model,
                "object": "model",
                "created": now_ts,
                "owned_by": f"padam-{c.name}",
            })
    if include_local_probe:
        probe = probe_local_backend()
        for mname in probe.get("models") or []:
            if mname not in seen:
                seen.add(mname)
                items.append({
                    "id": mname,
                    "object": "model",
                    "created": now_ts,
                    "owned_by": "padam-local-ollama",
                })
    return {"object": "list", "data": items}


def format_sse_chunks(resp_data: dict[str, Any]) -> list[str]:
    """Преобразует JSON-ответ /chat/completions в OpenAI SSE-чанки для клиентов со stream=true."""
    cid = str(resp_data.get("id") or f"chatcmpl-padam-{int(time.time())}")
    created = int(resp_data.get("created") or int(time.time()))
    model = str(resp_data.get("model") or (resp_data.get("_padam_router") or {}).get("model") or "padam-sovereign")
    choices = resp_data.get("choices") or []
    content = ""
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message") or {}
        content = str(msg.get("content") or "")

    chunk1 = {
        "id": cid,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": None}],
    }
    chunk2 = {
        "id": cid,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        "_padam_router": resp_data.get("_padam_router"),
    }
    return [
        f"data: {json.dumps(chunk1, ensure_ascii=False)}\n\n",
        f"data: {json.dumps(chunk2, ensure_ascii=False)}\n\n",
        "data: [DONE]\n\n",
    ]


def recommend_local_model() -> dict[str, Any]:
    """Подбирает оптимальную локальную модель Ollama по доступной VRAM и проверяет установленные."""
    probe = probe_local_backend(timeout_s=0.6)
    free_mib = 0
    gpu_name = None
    smi = shutil.which("nvidia-smi")
    if smi:
        try:
            out = subprocess.check_output(
                [smi, "--query-gpu=name,memory.free", "--format=csv,noheader,nounits"],
                text=True, encoding="utf-8", errors="replace",
                timeout=3, **NO_WINDOW
            ).strip()
            if out:
                parts = out.splitlines()[0].split(",")
                gpu_name = parts[0].strip()
                free_mib = int(float(parts[1].strip()))
        except Exception:
            pass
    if free_mib >= 16000:
        recommended = "qwen2.5-coder:14b"
    elif free_mib >= 8000:
        recommended = "qwen2.5-coder:7b"
    elif free_mib >= 3500:
        recommended = "qwen2.5-coder:3b"
    else:
        recommended = "llama3.2:1b"
    installed = list(probe.get("models") or [])
    return {
        "ollama_online": bool(probe.get("online")),
        "installed_models": installed,
        "gpu_name": gpu_name,
        "free_vram_mib": free_mib,
        "recommended_model": installed[0] if installed else recommended,
        "pull_command": f"ollama pull {recommended}",
    }


def warmup_local_model(*, timeout_s: float = 5.0) -> dict[str, Any]:
    """Безопасный прогрев уже установленной локальной модели Ollama (ничего не скачивает)."""
    rec = recommend_local_model()
    if not rec["ollama_online"]:
        return {"ok": False, "reason": "ollama_offline", **rec}
    installed = rec["installed_models"]
    if not installed:
        return {"ok": False, "reason": "no_models_installed", **rec}
    target = installed[0]
    local_c = next((c for c in load_contours() if c.name == "local"), None)
    base = (local_c.url[:-3] if local_c and local_c.url.endswith("/v1") else (local_c.url if local_c else "http://127.0.0.1:11434")).rstrip("/")
    gen_url = f"{base}/api/generate"
    body = json.dumps({"model": target, "prompt": "", "keep_alive": "10m"}).encode("utf-8")
    req = urllib.request.Request(gen_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return {"ok": 200 <= int(resp.status) < 300, "model": target, "keep_alive": "10m"}
    except Exception as exc:
        return {"ok": False, "model": target, "reason": f"{type(exc).__name__}: {exc}"}


def get_router() -> SovereignRouter:
    return _DEFAULT_ROUTER
