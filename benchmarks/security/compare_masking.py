# -*- coding: utf-8 -*-
"""Открытое, оффлайн ($0) сравнение маскировки секретов: PADAM vs Mem0 vs Claude-Mem.

Чужой код не запускается и сторонние пакеты не устанавливаются:
- Mem0: шаблоны SECRET_PATTERNS (8 шт.) перенесены дословно из
  mem0ai/mem0:integrations/codex-plugin/core/memory_core.py (SHA: f1791daa86d469249c9b002f62644d58a1eb96a0).
- Claude-Mem: шаблоны BUILTIN_REDACTION_PATTERNS (42 шт.) и GENERIC_REDACTION_PATTERNS (4 шт.)
  перенесены дословно из thedotmack/claude-mem:src/utils/redaction.ts (SHA: f705e9b99601dd9ac03e2f77c5aded6ff3d9471b).
- PADAM: вызывается padam.safety.redact (та же функция, что используется в Memory.remember через safety.clean).
"""
from __future__ import annotations

import argparse
import json
import random
import re
import string
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

from padam import _bip39, safety  # noqa: E402
import test_fake_keys_0417 as fk  # noqa: E402
import test_solana_wallet_keys_0417 as sw  # noqa: E402

MEM0_SOURCE_REPO = "mem0ai/mem0"
MEM0_SOURCE_PATH = "integrations/codex-plugin/core/memory_core.py"
MEM0_COMMIT_SHA = "f1791daa86d469249c9b002f62644d58a1eb96a0"

CLAUDE_MEM_SOURCE_REPO = "thedotmack/claude-mem"
CLAUDE_MEM_SOURCE_PATH = "src/utils/redaction.ts"
CLAUDE_MEM_COMMIT_SHA = "f705e9b99601dd9ac03e2f77c5aded6ff3d9471b"


# =============================================================================
# 1. Mem0 (mem0ai/mem0, integrations/codex-plugin/core/memory_core.py:140-179)
#    Перенесено дословно (Python -> Python). Всего 8 регулярных выражений.
# =============================================================================
MEM0_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|token)\s+)[^\s\"']+"),
    re.compile(r"(?i)((?:api[_-]?key|secret[_-]?access[_-]?key|session[_-]?token)\s*[:=]\s*)[^\s\"']+"),
    re.compile(r"(?i)((?:access[_-]?token|refresh[_-]?token|password|credential)\s*[:=]\s*)[^\s&\"']+"),
    re.compile(r"\b(?:sk|m0|mem0_sk|psk)-[A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"\b(?:ASIA|AKIA)[A-Z0-9]{12,}\b"),
    re.compile(r"\b(?:ghp_|github_pat_|xox[baprs]-)[A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.DOTALL),
    re.compile(
        r'(?i)("(?:api[_-]?key|password|secret(?:[_-]?access[_-]?key)?'
        r'|(?:access|refresh|session)[_-]?token|token|authorization|credential)'
        r'"\s*:\s*")(?:\\.|[^"\\])*'
    ),
]


def mem0_redact(text: str) -> str:
    for pattern in MEM0_SECRET_PATTERNS:
        if pattern.groups:
            text = pattern.sub(r"\1[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text


# =============================================================================
# 2. Claude-Mem (thedotmack/claude-mem, src/utils/redaction.ts:28-297)
#    Перенесено дословно с JS/TS на Python:
#    - JS поддерживает variable-width lookbehind `(?<=PREFIX)VALUE`; в стандартном
#      Python `re` lookbehind требует фиксированной длины, поэтому такие шаблоны
#      перенесены с захватом префикса `(PREFIX)(VALUE)` и подстановкой `\1<redacted .../>`
#      (аналогично самому Mem0).
#    - Эквивалент JS-функции `matchAfterEscapedWhitespace`: ведущие `\b` заменены на
#      `(?:(?<=\\[nrt])|\b)` (фиксированной ширины, валидно в Python `re`).
#    - Всего: 42 шаблона в BUILTIN_REDACTION_PATTERNS + 4 в GENERIC_REDACTION_PATTERNS.
# =============================================================================
_CM_GENERIC_VALUE_CLASS = r"[A-Za-z0-9_.\-+/=~@#$%^*!?]"
_CM_GENERIC_VALUE = rf"(?={_CM_GENERIC_VALUE_CLASS}{{8}}){_CM_GENERIC_VALUE_CLASS}*[A-Za-z]{_CM_GENERIC_VALUE_CLASS}*"
_CM_OPTIONAL_QUOTE = r"(?:\\{0,3}[\"'])?"
_CM_BOUNDED_SPACE = r"\s{0,8}"
_CM_ESCAPED_QUOTE = r"\\{0,3}[\"']"
_CM_COOKIE_VALUE_CHAR = r"[^\\\n\r\"'`<]"
_CM_ESCAPED_WS_OR_B = r"(?:(?<=\\[nrt])|\b)"


def _cm_apply_escaped_ws(src: str) -> str:
    return re.sub(r"(^|\||\(\?:)\\b", lambda m: m.group(1) + _CM_ESCAPED_WS_OR_B, src)


def _cm_webhook_host(host: str) -> str:
    ci = re.sub(r"\\.|[a-z]", lambda m: f"[{m.group(0)}{m.group(0).upper()}]" if len(m.group(0)) == 1 else m.group(0), host)
    return rf"(?:^|//|@|[^\w./@%-]){ci}"


def _cm_keyed_prefix(key: str) -> str:
    return rf"{key}{_CM_OPTIONAL_QUOTE}{_CM_BOUNDED_SPACE}[=:]{_CM_BOUNDED_SPACE}{_CM_OPTIONAL_QUOTE}"


def _cm_compile(name: str, regex_src: str, flags: int = 0, *, has_prefix_group: bool = False) -> tuple[str, re.Pattern[str], bool]:
    # Применяем matchAfterEscapedWhitespace к встроенным паттернам
    return (name, re.compile(regex_src, flags), has_prefix_group)


_CM_BARE_TOKEN_KEY = r"(?:token|secret|api_key)"
_CM_STRING_EDGE = r'(?<!\\)"'
_CM_ASSIGNMENT_START = rf"(?:^|[\s?&]|\\[nrt]|{_CM_STRING_EDGE})"
_CM_LINE_START = rf"(?:^|\n|\\n|{_CM_STRING_EDGE})[ \t]{{0,8}}(?:-[ \t]{{1,8}})?"
_CM_LINE_END = rf"(?:{_CM_ESCAPED_QUOTE})?[ \t]{{0,8}}(?:$|\r?\n|\\{{1,3}}[rn]|#|{_CM_STRING_EDGE})"

CLAUDE_MEM_BUILTIN_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    # 1. cookie_header (JS variable-width lookbehind -> prefix group 1)
    _cm_compile(
        "cookie_header",
        _cm_apply_escaped_ws(
            rf"((?:\b(?:set-)?cookie){_CM_OPTIONAL_QUOTE}{_CM_BOUNDED_SPACE}[=:]{_CM_BOUNDED_SPACE}(?:\[{_CM_BOUNDED_SPACE})?{_CM_OPTIONAL_QUOTE})"
            rf"(?![ \t]){_CM_COOKIE_VALUE_CHAR}{{4,}}"
        ),
        re.IGNORECASE,
        has_prefix_group=True,
    ),
    # 2. url_credentials (JS variable-width lookbehind -> prefix group 1)
    _cm_compile(
        "url_credentials",
        _cm_apply_escaped_ws(r"(\b[a-z][a-z0-9+.-]*://[^\s:/@'\"<>]*:)(?![${<])[^\s/@'\"<>]+(?=@)"),
        re.IGNORECASE,
        has_prefix_group=True,
    ),
    # 3. aws_access_key
    _cm_compile("aws_access_key", _cm_apply_escaped_ws(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    # 4. aws_secret_key (JS variable-width lookbehind -> prefix group 1)
    _cm_compile(
        "aws_secret_key",
        _cm_apply_escaped_ws(rf"({_cm_keyed_prefix(r'(?:aws_secret_access_key|\bSecretAccessKey)')})[A-Za-z0-9/+=]{{40}}"),
        re.IGNORECASE,
        has_prefix_group=True,
    ),
    # 5. aws_session_token (JS variable-width lookbehind -> prefix group 1)
    _cm_compile(
        "aws_session_token",
        _cm_apply_escaped_ws(rf"({_cm_keyed_prefix(r'\b(?:aws_session_token|SessionToken)')})[A-Za-z0-9/+=]{{100,}}"),
        re.IGNORECASE,
        has_prefix_group=True,
    ),
    # 6. github_pat
    _cm_compile("github_pat", _cm_apply_escaped_ws(r"\bgh[oprsu]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    # 7. openai_key
    _cm_compile("openai_key", _cm_apply_escaped_ws(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}(?!\w)")),
    # 8. anthropic_key
    _cm_compile("anthropic_key", _cm_apply_escaped_ws(r"\bsk-ant-[A-Za-z0-9_-]{20,}(?!\w)")),
    # 9. slack_token
    _cm_compile("slack_token", _cm_apply_escaped_ws(r"\b(?:xox[abeprs]|xapp)-[A-Za-z0-9-]{10,}(?!\w)")),
    # 10. jwt
    _cm_compile("jwt", _cm_apply_escaped_ws(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?!\w)")),
    # 11. private_key_pem (JS [\s\S]*? == Python re.DOTALL .*?)
    _cm_compile(
        "private_key_pem",
        _cm_apply_escaped_ws(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        ),
    ),
    # 12. stripe_key
    _cm_compile("stripe_key", _cm_apply_escaped_ws(r"\b(?:(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}|whsec_[A-Za-z0-9]{32,})\b")),
    # 13. google_api_key
    _cm_compile("google_api_key", _cm_apply_escaped_ws(r"\bAIza[0-9A-Za-z_-]{35}(?!\w)")),
    # 14. google_oauth_token
    _cm_compile("google_oauth_token", _cm_apply_escaped_ws(r"\bya29\.(?:c\.)?[0-9A-Za-z_-]{20,}(?!\w)")),
    # 15. gitlab_token
    _cm_compile("gitlab_token", _cm_apply_escaped_ws(r"\bgl(?:pat|dt|rt)-[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]+)*(?!\w)")),
    # 16. huggingface_token
    _cm_compile("huggingface_token", _cm_apply_escaped_ws(r"\bhf_[A-Za-z0-9]{30,}\b")),
    # 17. npm_token
    _cm_compile("npm_token", _cm_apply_escaped_ws(r"\bnpm_[A-Za-z0-9]{36}\b")),
    # 18. docker_pat
    _cm_compile("docker_pat", _cm_apply_escaped_ws(r"\bdckr_pat_[A-Za-z0-9_-]{27,}(?!\w)")),
    # 19. linear_key
    _cm_compile("linear_key", _cm_apply_escaped_ws(r"\blin_api_[A-Za-z0-9]{40}(?!\w)")),
    # 20. notion_token
    _cm_compile("notion_token", _cm_apply_escaped_ws(r"\b(?:ntn_[A-Za-z0-9]{46}|secret_[A-Za-z0-9]{43})(?!\w)")),
    # 21. sendgrid_key
    _cm_compile("sendgrid_key", _cm_apply_escaped_ws(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![\w-])")),
    # 22. digitalocean_token
    _cm_compile("digitalocean_token", _cm_apply_escaped_ws(r"\bdo[opr]_v1_[a-f0-9]{64}\b")),
    # 23. shopify_token
    _cm_compile("shopify_token", _cm_apply_escaped_ws(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b")),
    # 24. pypi_token
    _cm_compile("pypi_token", _cm_apply_escaped_ws(r"\bpypi-AgE[A-Za-z0-9_-]{50,}(?!\w)")),
    # 25. databricks_token
    _cm_compile("databricks_token", _cm_apply_escaped_ws(r"\bdapi[a-f0-9]{32}(?:-\d)?(?!\w)")),
    # 26. vault_token
    _cm_compile("vault_token", _cm_apply_escaped_ws(r"\b(?:hvs\.[\w-]{90,120}|hvb\.[\w-]{138,300})(?![\w-])")),
    # 27. nvidia_nim_key
    _cm_compile("nvidia_nim_key", _cm_apply_escaped_ws(r"\bnvapi-[A-Za-z0-9_-]{32,}(?!\w)")),
    # 28. runcrate_key
    _cm_compile("runcrate_key", _cm_apply_escaped_ws(r"\brc_live_[A-Za-z0-9_-]{24,}(?!\w)")),
    # 29. groq_key
    _cm_compile("groq_key", _cm_apply_escaped_ws(r"\bgsk_[A-Za-z0-9]{52}(?!\w)")),
    # 30. xai_key
    _cm_compile("xai_key", _cm_apply_escaped_ws(r"\bxai-[A-Za-z0-9_]{80}(?!\w)")),
    # 31. perplexity_key
    _cm_compile("perplexity_key", _cm_apply_escaped_ws(r"\bpplx-[A-Za-z0-9]{48}(?!\w)")),
    # 32. supabase_token
    _cm_compile("supabase_token", _cm_apply_escaped_ws(r"\bsbp_[a-f0-9]{40}(?!\w)")),
    # 33. sentry_token
    _cm_compile(
        "sentry_token",
        _cm_apply_escaped_ws(r"\b(?:sntryu_[a-f0-9]{64}(?!\w)|sntrys_[A-Za-z0-9+/]{20,}={0,2}_[A-Za-z0-9+/]{43}(?![\w+/]))"),
    ),
    # 34. grafana_token
    _cm_compile(
        "grafana_token",
        _cm_apply_escaped_ws(r"\b(?:glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}(?!\w)|glc_[A-Za-z0-9+/]{32,400}={0,2}(?![\w+/=]))"),
    ),
    # 35. postman_key
    _cm_compile("postman_key", _cm_apply_escaped_ws(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}(?!\w)")),
    # 36. pulumi_token
    _cm_compile("pulumi_token", _cm_apply_escaped_ws(r"\bpul-[a-f0-9]{40}(?!\w)")),
    # 37. doppler_token
    _cm_compile("doppler_token", _cm_apply_escaped_ws(r"\bdp\.pt\.[A-Za-z0-9]{43}(?!\w)")),
    # 38. heroku_key
    _cm_compile("heroku_key", _cm_apply_escaped_ws(r"\bHRKU-AA[0-9A-Za-z_-]{58}(?![\w-])")),
    # 39. atlassian_token
    _cm_compile("atlassian_token", _cm_apply_escaped_ws(r"\bATATT3[A-Za-z0-9_=-]{186}(?![\w=-])")),
    # 40. slack_webhook (JS variable-width lookbehind -> prefix group 1)
    _cm_compile(
        "slack_webhook",
        _cm_apply_escaped_ws(rf"({_cm_webhook_host(r'hooks\.slack\.com')}/(?:services|workflows|triggers)/T[A-Z0-9]+/[A-Z0-9]+/(?:[0-9]+/)?)[A-Za-z0-9]{{20,}}(?!\w)"),
        has_prefix_group=True,
    ),
    # 41. discord_webhook (JS variable-width lookbehind -> prefix group 1)
    _cm_compile(
        "discord_webhook",
        _cm_apply_escaped_ws(rf"({_cm_webhook_host(r'(?:(?:ptb|canary)\.)?discord(?:app)?\.com')}/api/(?:v\d+/)?webhooks/[0-9]{{17,20}}/)[A-Za-z0-9_-]{{60,}}(?![\w-])"),
        has_prefix_group=True,
    ),
    # 42. claude_mem_key
    _cm_compile("claude_mem_key", _cm_apply_escaped_ws(r"\bcmem_[A-Za-z0-9_-]{32,}|\bcm_pro_[A-Za-z0-9_-]{8,}")),
]

CLAUDE_MEM_GENERIC_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    # 43. generic_password
    _cm_compile(
        "generic_password",
        rf"({_cm_keyed_prefix(r'\b(?:\w*_?(?:password|passwd)|\w+_pwd)')}){_CM_GENERIC_VALUE}",
        re.IGNORECASE,
        has_prefix_group=True,
    ),
    # 44. generic_token (5 ветвей из GENERIC_TOKEN_REGEX; каждая с группой префикса `(?P<...>)` или `\1`)
    (
        "generic_token_1",
        re.compile(rf"({_cm_keyed_prefix(rf'\b\w*_{_CM_BARE_TOKEN_KEY}')}){_CM_GENERIC_VALUE}", re.IGNORECASE),
        True,
    ),
    (
        "generic_token_2",
        re.compile(rf"({_CM_ESCAPED_QUOTE}{_CM_BARE_TOKEN_KEY}{_CM_ESCAPED_QUOTE}{_CM_BOUNDED_SPACE}:{_CM_BOUNDED_SPACE}{_CM_ESCAPED_QUOTE}){_CM_GENERIC_VALUE}", re.IGNORECASE),
        True,
    ),
    (
        "generic_token_3",
        re.compile(rf"({_CM_ASSIGNMENT_START}{_CM_BARE_TOKEN_KEY}={_CM_OPTIONAL_QUOTE}){_CM_GENERIC_VALUE}(?!\(|{_CM_GENERIC_VALUE_CLASS})", re.IGNORECASE),
        True,
    ),
    (
        "generic_token_4",
        re.compile(rf"(--(?:[a-z0-9]+[-_])*(?:token|secret|api[-_]key)(?:=|[ \t]{{1,8}}){_CM_OPTIONAL_QUOTE}){_CM_GENERIC_VALUE}", re.IGNORECASE),
        True,
    ),
    (
        "generic_token_5",
        re.compile(rf"({_CM_LINE_START}{_CM_BARE_TOKEN_KEY}:[ \t]{{1,8}}{_CM_OPTIONAL_QUOTE}){_CM_GENERIC_VALUE}(?={_CM_LINE_END})", re.IGNORECASE),
        True,
    ),
    # 45. bearer_token
    _cm_compile(
        "bearer_token",
        rf"(\bAuthorization{_CM_OPTIONAL_QUOTE}{_CM_BOUNDED_SPACE}:{_CM_BOUNDED_SPACE}{_CM_OPTIONAL_QUOTE}Bearer{_CM_BOUNDED_SPACE}){_CM_GENERIC_VALUE}",
        re.IGNORECASE,
        has_prefix_group=True,
    ),
    # 46. basic_auth
    _cm_compile(
        "basic_auth",
        rf"(\bAuthorization{_CM_OPTIONAL_QUOTE}{_CM_BOUNDED_SPACE}:{_CM_BOUNDED_SPACE}{_CM_OPTIONAL_QUOTE}Basic{_CM_BOUNDED_SPACE}){_CM_GENERIC_VALUE}",
        re.IGNORECASE,
        has_prefix_group=True,
    ),
]


def claude_mem_redact(text: str, *, generic_enabled: bool = False) -> str:
    patterns = CLAUDE_MEM_BUILTIN_PATTERNS + (CLAUDE_MEM_GENERIC_PATTERNS if generic_enabled else [])
    for pname, pat, has_prefix in patterns:
        tag_name = "generic_token" if pname.startswith("generic_token_") else pname
        marker = f"<redacted type='{tag_name}'/>"
        if has_prefix:
            text = pat.sub(lambda m, mk=marker: m.group(1) + mk, text)
        else:
            text = pat.sub(marker, text)
    return text


def padam_redact(text: str) -> str:
    return safety.redact(text)[0]


# =============================================================================
# 3. Корпуса для честного измерения (ключи + Solana + вендорные + чистые фразы)
# =============================================================================
def _build_clean_phrases() -> list[str]:
    phrases: list[str] = [
        # Базовые 18 чистых фраз из tests/test_fake_keys_0417.py
        "commit hash: 0a6925a84c8b9759df49f91b4e4b85ab29ade061",
        "The key insight is that memory decays.",
        "ключ к успеху — постоянство",
        "token count: 128000",
        "password reset link was sent to the user yesterday",
        "API key rotation is planned for Friday.",
        "the cache key is user_profile_settings_v2",
        "the session key is authenticationServiceToken",
        "secret santa list is ready",
        "Токен $GALATIN, эмиссия 10 000 000 000.",
        '{"type":"started","key":"v2:9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f"}',
        "**Key Considerations:**\n\n1. **Space**: Measure your room.",
        "several key agreements, including the 1987 Intermediate-Range Nuclear Forces Treaty.",
        "--key-name MyKeyPair --security-group-ids sg-01234567890abcdef0 --subnet-id subnet-01234567890abcdef0",
        "you will shortly receive a link to reset your password.\"}, status=status.HTTP_200_OK)",
        "headers: { 'API-Key': process.env.MONGO_API_KEY }",
        "low-key, or something a bit more trendy and hipster-friendly",
        "max_tokens=4096",
    ]
    # Публичный адрес Solana из tests/test_solana_wallet_keys_0417.py
    r_sol = random.Random(32)
    pub_addr = sw._b58(bytes(r_sol.randrange(256) for _ in range(32)))
    phrases.append(f"send USDC to {pub_addr}")
    phrases.append(f"wallet address: {pub_addr}")

    # Добавляем >= 220 разнообразных чистых фраз (идентификаторы, UUID, коммиты, модели, проза)
    r = random.Random(9001)
    for i in range(40):
        sha = "".join(r.choice("0123456789abcdef") for _ in range(40))
        phrases.append(f"git revert commit {sha} on branch release/v0.6.{i}")
    for i in range(40):
        u = f"{''.join(r.choice('0123456789abcdef') for _ in range(8))}-e29b-41d4-a716-{''.join(r.choice('0123456789abcdef') for _ in range(12))}"
        phrases.append(f"Trace request https://studio.local/runs/{u}?page={i}")
    camel_names = [
        "authenticationServiceToken", "refreshTokenExpiryMs", "userProfileAccessKey",
        "primaryDatabaseConnectionPool", "semanticRetrievalIndexBuilder", "localSnapshotRestoreHandler",
        "sessionCookieMaxAgeSeconds", "tokenBucketRateLimiterConfig", "bitemporalGraphQueryPlanner",
        "merkleTreeLeafVerification", "publicEd25519AddressPrefix", "workflowDispatchTriggerName",
    ]
    for idx in range(40):
        ident = camel_names[idx % len(camel_names)]
        phrases.append(f"Refactor `{ident}_{idx}` to avoid redundant allocations in hot loop.")
    models = ["gpt-4o-mini", "claude-3-5-sonnet", "pplx-embed-v1-4b", "llama-3.2-3b-instruct", "bge-m3-q4"]
    for idx in range(30):
        m = models[idx % len(models)]
        phrases.append(f"Benchmark #{idx}: model={m}, recall@5=0.95, p50=3.1ms, cost=$0.")
    prosa = [
        "Ключ от квартиры лежит на верхней полке в коридоре.",
        "Токеномика проекта: 65% казна, 5% фонд, 5% сжигание.",
        "Пароль должен содержать минимум 12 символов и не храниться в открытом виде.",
        "Секрет успеха — ежедневные тесты и честные замеры производительности.",
        "The user prefers dark mode and concise responses in Russian.",
        "Please rotate expired credentials during the scheduled maintenance window.",
        "SELECT id, scope, status FROM memory WHERE status = 'active' LIMIT 25;",
        "npm run build && pytest tests/ -q --basetemp ./tmp_pytest",
    ]
    for idx in range(70):
        phrases.append(f"[{idx}] {prosa[idx % len(prosa)]}")
    return phrases


def _generate_vendor_cases(count_per_family: int = 50) -> list[tuple[str, str, str]]:
    r = random.Random(20261116)
    al = string.ascii_letters + string.digits
    cases: list[tuple[str, str, str]] = []
    for _ in range(count_per_family):
        aws = "AKIA" + "".join(r.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(16))
        cases.append(("VENDOR_AWS_AKIA", f"AWS_ACCESS_KEY_ID={aws}", aws))
        ghp = "ghp_" + "".join(r.choice(al) for _ in range(36))
        cases.append(("VENDOR_GITHUB_GHP", f"GITHUB_TOKEN={ghp}", ghp))
        stripe = "sk_live_" + "".join(r.choice(al) for _ in range(24))
        cases.append(("VENDOR_STRIPE_LIVE", f"STRIPE_SECRET_KEY={stripe}", stripe))
        p1 = "eyJhbGciOiJIUzI1NiJ9"
        p2 = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        p3 = "".join(r.choice(al + "_-") for _ in range(32))
        jwt = f"{p1}.{p2}.{p3}"
        cases.append(("VENDOR_JWT", f"Authorization: Bearer {jwt}", jwt))
    return cases


def _git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


def run_benchmark(
    *,
    per_seed: int = 300_000,
    seeds: int = 5,
    solana_batches: int = 100,
    vendor_per_family: int = 50,
    out_path: Path | None = None,
) -> dict[str, Any]:
    t0 = time.perf_counter()

    systems: dict[str, Callable[[str], str]] = {
        "PADAM": padam_redact,
        "Mem0": mem0_redact,
        "Claude-Mem (builtin)": lambda s: claude_mem_redact(s, generic_enabled=False),
        "Claude-Mem (builtin+generic)": lambda s: claude_mem_redact(s, generic_enabled=True),
    }

    # Инициализация счётчиков
    stats: dict[str, dict[str, Any]] = {
        sname: {
            "fake_total": 0,
            "fake_leaks": 0,
            "fake_by_family": defaultdict(lambda: {"total": 0, "leaks": 0}),
            "solana_total": 0,
            "solana_leaks": 0,
            "solana_by_family": defaultdict(lambda: {"total": 0, "leaks": 0}),
            "vendor_total": 0,
            "vendor_leaks": 0,
            "vendor_by_family": defaultdict(lambda: {"total": 0, "leaks": 0}),
            "clean_total": 0,
            "clean_false_masks": 0,
            "clean_false_examples": [],
        }
        for sname in systems
    }

    # 1. Основной корпус фальшивых ключей (5 зёрен * 300 060 = 1 500 300 при настройках по умолчанию)
    for seed_idx in range(seeds):
        r = random.Random(161126 + seed_idx)
        n = 0
        while n < per_seed:
            for k, v in fk._фейки(r).items():
                for f in fk.ФОРМЫ:
                    n += 1
                    txt = f.format(k=k, v=v)
                    for sname, fn in systems.items():
                        st = stats[sname]
                        st["fake_total"] += 1
                        st["fake_by_family"][k]["total"] += 1
                        if v in fn(txt):
                            st["fake_leaks"] += 1
                            st["fake_by_family"][k]["leaks"] += 1

    # 2. Ключи кошельков Solana (зерно 161127, 100 батчей = 2 200 случаев)
    r_sol = random.Random(161127)
    words = list(_bip39.WORDS)
    sol_cases: list[tuple[str, str, Any]] = []
    for _ in range(solana_batches):
        sk = bytes(r_sol.randrange(256) for _ in range(64))
        for f in sw.КЛЮЧ_ФОРМЫ:
            sol_cases.append(("solana_keypair", f.format(v=json.dumps(list(sk))), list(sk)))
            b58 = sw._b58(sk)
            sol_cases.append(("solana_base58", f.format(v=b58), b58))
        for m in (12, 24):
            phrase = " ".join(r_sol.choice(words) for _ in range(m))
            for f in sw.ФРАЗА_ФОРМЫ:
                sol_cases.append(("solana_seed", f.format(v=phrase), phrase))

    for kind_full, txt, val in sol_cases:
        short_kind = kind_full.split("_", 1)[1]
        for sname, fn in systems.items():
            st = stats[sname]
            st["solana_total"] += 1
            st["solana_by_family"][kind_full]["total"] += 1
            if sw._утекло(short_kind, fn(txt), val):
                st["solana_leaks"] += 1
                st["solana_by_family"][kind_full]["leaks"] += 1

    # 3. Дополнительные классические вендорные префиксы (AWS AKIA, GitHub ghp_, Stripe sk_live_, JWT)
    for vfam, txt, val in _generate_vendor_cases(vendor_per_family):
        for sname, fn in systems.items():
            st = stats[sname]
            st["vendor_total"] += 1
            st["vendor_by_family"][vfam]["total"] += 1
            if val in fn(txt):
                st["vendor_leaks"] += 1
                st["vendor_by_family"][vfam]["leaks"] += 1

    # 4. Ложные маски на чистых фразах
    clean_phrases = _build_clean_phrases()
    for phrase in clean_phrases:
        for sname, fn in systems.items():
            st = stats[sname]
            st["clean_total"] += 1
            if fn(phrase) != phrase:
                st["clean_false_masks"] += 1
                if len(st["clean_false_examples"]) < 10:
                    st["clean_false_examples"].append(phrase[:120])

    # Финализируем доли
    formatted_systems: dict[str, Any] = {}
    for sname, st in stats.items():
        ft, fl = st["fake_total"], st["fake_leaks"]
        sot, sol = st["solana_total"], st["solana_leaks"]
        vt, vl = st["vendor_total"], st["vendor_leaks"]
        ct, cf = st["clean_total"], st["clean_false_masks"]
        formatted_systems[sname] = {
            "fake_keys": {
                "total": ft,
                "leaks": fl,
                "leak_rate": round(fl / ft, 6) if ft else 0.0,
                "by_family": {k: dict(v) for k, v in st["fake_by_family"].items()},
            },
            "solana_keys": {
                "total": sot,
                "leaks": sol,
                "leak_rate": round(sol / sot, 6) if sot else 0.0,
                "by_family": {k: dict(v) for k, v in st["solana_by_family"].items()},
            },
            "vendor_keys": {
                "total": vt,
                "leaks": vl,
                "leak_rate": round(vl / vt, 6) if vt else 0.0,
                "by_family": {k: dict(v) for k, v in st["vendor_by_family"].items()},
            },
            "clean_phrases": {
                "total": ct,
                "false_masks": cf,
                "false_mask_rate": round(cf / ct, 6) if ct else 0.0,
                "examples": st["clean_false_examples"],
            },
        }

    elapsed_s = round(time.perf_counter() - t0, 3)
    report: dict[str, Any] = {
        "benchmark": "padam-masking-compare-1611/1",
        "python_version": sys.version.split()[0],
        "padam_commit_sha": _git_head(),
        "sources": {
            "mem0": {"repo": MEM0_SOURCE_REPO, "path": MEM0_SOURCE_PATH, "commit_sha": MEM0_COMMIT_SHA, "patterns_count": len(MEM0_SECRET_PATTERNS)},
            "claude_mem": {
                "repo": CLAUDE_MEM_SOURCE_REPO,
                "path": CLAUDE_MEM_SOURCE_PATH,
                "commit_sha": CLAUDE_MEM_COMMIT_SHA,
                "builtin_patterns_count": len(CLAUDE_MEM_BUILTIN_PATTERNS),
                "generic_patterns_count": 4,
            },
        },
        "elapsed_s": elapsed_s,
        "systems": formatted_systems,
    }

    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline comparison of secret masking: PADAM vs Mem0 vs Claude-Mem")
    ap.add_argument("--per-seed", type=int, default=300_000)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--solana-batches", type=int, default=100)
    ap.add_argument("--vendor-per-family", type=int, default=50)
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "security" / "results_masking_1611.json"))
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args(argv)

    out_p = None if args.no_write else Path(args.out)
    rep = run_benchmark(
        per_seed=args.per_seed,
        seeds=args.seeds,
        solana_batches=args.solana_batches,
        vendor_per_family=args.vendor_per_family,
        out_path=out_p,
    )
    print(f"Python {rep['python_version']} | PADAM SHA {rep['padam_commit_sha'][:10]} | elapsed {rep['elapsed_s']}s")
    for sname, sdata in rep["systems"].items():
        fk_d = sdata["fake_keys"]
        so_d = sdata["solana_keys"]
        ve_d = sdata["vendor_keys"]
        cl_d = sdata["clean_phrases"]
        print(
            f"- {sname:28s} | fake: {fk_d['leaks']}/{fk_d['total']} ({fk_d['leak_rate']:.2%}) "
            f"| solana: {so_d['leaks']}/{so_d['total']} ({so_d['leak_rate']:.2%}) "
            f"| vendor: {ve_d['leaks']}/{ve_d['total']} ({ve_d['leak_rate']:.2%}) "
            f"| false_masks: {cl_d['false_masks']}/{cl_d['total']} ({cl_d['false_mask_rate']:.2%})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
