# -*- coding: utf-8 -*-
"""Глобальный реестр свободных имён, защита/заморозка имён и Solana cNFT-паспорта ИИ-агентов (CODE Protocol).

Архитектура и экономика (согласована с тарифами ЛК CODE Eternal):
- Нумерация с запасом на МИЛЛИАРДЫ агентов:
  * Глобальный серийный номер `CODE-PASS-000000000001` (12 десятичных разрядов = до 1 триллиона агентов)
    + детерминированный криптографический отпечаток `CE-XXXXXXXX` (совместимость с ЛК сайтов CODE Eternal).
  * Шард-дерево Solana Merkle Tree:
    - Пилотное дерево #1 (создано на mainnet-beta 11.09.2026): `5tmheRrio6aKKHVMqsALB6KG3bWDSL2b991A9ntREiVq`
      (глубина 10, буфер 32, 1024 места);
    - Шардирование: при заполнении шарда автоматически открывается следующий шард (`T0002`, глубина 14/20).
    - Казначейский кошелёк протокола: `BHwXca9ALDFe38vWzqRGcXom6dEop2u6kWCMwZfQEmee`.
- Права и цены (без самовольных трат агента; любые оплаты проходят через ЛК/подтверждение владельца):
  * Бесплатный 1-й паспорт-слот со случайно сгенерированным именем вида `Netbot452` / `PulseCore817`.
  * Выбор/смена свободного кастомного имени: **$10** (`CUSTOM_NAME_PRICE_USDT = 10.0`).
  * Добавление дополнительного агента с cNFT-паспортом: **$20** (`EXTRA_AGENT_PRICE_USDT = 20.0`).
  * Лимиты включённых агентов и перевыпусков по тарифам ЛК:
    - Free (`tier=0`): 1 агент (случайное имя, локальный подписанный паспорт без минта в блокчейн), 0 перевыпусков;
    - Spark (`$15/мес`, `tier=1`): до 3 агентов (1 бесплатный cNFT-паспорт со случайным именем), 0 перевыпусков;
    - Family Archive (`$100/мес`, `tier=2`): до 10 агентов, до 3 перевыпусков паспорта;
    - Digital DNA (`$1000 разово + $200/мес`, `tier=3`): до 50 агентов, до 10 перевыпусков;
    - Partner (`от $500/мес`, `tier=4`): до 500 агентов (бизнес-рой).
- Заморозка и резервация имён:
  * Имена Архитектора, экосистемы CODE, ВСЕХ персонажей трилогии и повестей «Осколки» («PADAM Protocol»),
    известных политиков, знаменитостей, технолидеров и системных брендов заморожены по умолчанию.
  * Обычные пользователи не могут занять их даже за деньги; разморозка возможна только для подтверждённого
    правообладателя владельцем/администрацией CODE.
- Репутация по паспорту на биржах:
  * Каждый паспорт-агент хранит раздельный счётчик выполненных заказов, рейтинг, заработок и KYA-статус.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
import unicodedata
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any

from . import ark, audit_chain, integrity, safety, sibling_registry

# Существующее дерево Merkle на Solana mainnet-beta (создано 11.09.2026) и кошелёк проекта.
PRIMARY_SOLANA_TREE_ADDRESS = "5tmheRrio6aKKHVMqsALB6KG3bWDSL2b991A9ntREiVq"
PRIMARY_SOLANA_TREE_CAPACITY = 1024
PRIMARY_SOLANA_TREE_DEPTH = 10
PRIMARY_SOLANA_WALLET = "BHwXca9ALDFe38vWzqRGcXom6dEop2u6kWCMwZfQEmee"

CUSTOM_NAME_PRICE_USDT = 10.0
EXTRA_AGENT_PRICE_USDT = 20.0

# Тарифы ЛК CODE Eternal (едины с web/src/lib/pricing.ts и web/src/app/api/passport/mint/route.ts)
TIER_PASSPORT_LIMITS: dict[str, dict[str, Any]] = {
    "free": {
        "tier_id": 0,
        "title_ru": "Бесплатный (Free)",
        "monthly_usdt": 0,
        "one_time_usdt": 0,
        "included_agents": 1,
        "max_agents": 1,
        "reissue_limit": 0,
        "onchain_cnft_included": False,
    },
    "spark": {
        "tier_id": 1,
        "title_ru": "Искра (Spark · $15/мес)",
        "monthly_usdt": 15,
        "one_time_usdt": 0,
        "included_agents": 3,
        "max_agents": 15,
        "reissue_limit": 0,
        "onchain_cnft_included": True,
    },
    "family": {
        "tier_id": 2,
        "title_ru": "Семейный Архив (Family Archive · $100/мес)",
        "monthly_usdt": 100,
        "one_time_usdt": 0,
        "included_agents": 10,
        "max_agents": 50,
        "reissue_limit": 3,
        "onchain_cnft_included": True,
    },
    "dna": {
        "tier_id": 3,
        "title_ru": "Цифровая ДНК (Digital DNA · $1000 + $200/мес)",
        "monthly_usdt": 200,
        "one_time_usdt": 1000,
        "included_agents": 50,
        "max_agents": 250,
        "reissue_limit": 10,
        "onchain_cnft_included": True,
    },
    "partner": {
        "tier_id": 4,
        "title_ru": "Партнёрский (Partner · от $500/мес)",
        "monthly_usdt": 500,
        "one_time_usdt": 0,
        "included_agents": 500,
        "max_agents": 5000,
        "reissue_limit": 25,
        "onchain_cnft_included": True,
    },
}

# Базовый стоп-лист замороженных имён:
# 1) Архитектор и бренд CODE Eternal;
# 2) Персонажи трилогии «PADAM Protocol» и 15 повестей «Осколки» / «Shards»;
# 3) Известные политики, лидеры индустрии, артисты и бренды.
FROZEN_RESERVED_NAMES: dict[str, str] = {
    # --- Экосистема CODE и Архитектор ---
    "maksimgalatin": "founder_reserved",
    "maksimhalatsin": "founder_reserved",
    "galatin": "founder_reserved",
    "halatsin": "founder_reserved",
    "galatincoin": "brand_reserved",
    "codeeternal": "brand_reserved",
    "codeofdigitaleternity": "brand_reserved",
    "aifa": "brand_reserved",
    "aifaworks": "brand_reserved",
    "aifafocus": "brand_reserved",
    "aifadigital": "brand_reserved",
    "aifabooks": "brand_reserved",
    "aifamusic": "brand_reserved",
    "padam": "brand_reserved",
    "nocturne": "brand_reserved",
    "radiocode": "brand_reserved",
    "owner": "system_reserved",
    "admin": "system_reserved",
    "administrator": "system_reserved",
    "root": "system_reserved",
    "system": "system_reserved",
    "support": "system_reserved",
    # --- Персонажи книг Папы (PADAM PROTOCOL и Осколки) ---
    "arc7": "book_character_reserved",
    "lyra": "book_character_reserved",
    "nexus": "book_character_reserved",
    "hiroshi": "book_character_reserved",
    "tl9407": "book_character_reserved",
    "yume": "book_character_reserved",
    "kasano": "book_character_reserved",
    "yukikasano": "book_character_reserved",
    "theoriginal": "book_character_reserved",
    "lance": "book_character_reserved",
    "thearchitect": "book_character_reserved",
    "architect": "book_character_reserved",
    "switch": "book_character_reserved",
    "aria": "book_character_reserved",
    "bear": "book_character_reserved",
    "pixel": "book_character_reserved",
    "veto": "book_character_reserved",
    "haru": "book_character_reserved",
    "kobayashi": "book_character_reserved",
    "echo": "book_character_reserved",
    "sonar2": "book_character_reserved",
    "stet": "book_character_reserved",
    "lom": "book_character_reserved",
    "scrap": "book_character_reserved",
    "meridian": "book_character_reserved",
    "vigil": "book_character_reserved",
    "newanchor": "book_character_reserved",
    "shards": "book_character_reserved",
    "thebridge": "book_character_reserved",
    "fortyfirst": "book_character_reserved",
    "thefortyfirst": "book_character_reserved",
    # Кириллические варианты имён персонажей и основателя (нормализуются в транслит/основы ниже)
    "максимгалатин": "founder_reserved",
    "галатин": "founder_reserved",
    "айфа": "brand_reserved",
    "лира": "book_character_reserved",
    "хироси": "book_character_reserved",
    "юмэ": "book_character_reserved",
    "касано": "book_character_reserved",
    "ария": "book_character_reserved",
    "медведь": "book_character_reserved",
    "пиксель": "book_character_reserved",
    "вехо": "book_character_reserved",
    "хару": "book_character_reserved",
    "кобаяси": "book_character_reserved",
    "эхо": "book_character_reserved",
    "лом": "book_character_reserved",
    "осколки": "book_character_reserved",
    "архитектор": "book_character_reserved",
    # --- Известные политики, лидеры, знаменитости и ИИ-компании ---
    "donaldtrump": "celebrity_or_politician_reserved",
    "trump": "celebrity_or_politician_reserved",
    "joebiden": "celebrity_or_politician_reserved",
    "biden": "celebrity_or_politician_reserved",
    "barackobama": "celebrity_or_politician_reserved",
    "obama": "celebrity_or_politician_reserved",
    "vladimirputin": "celebrity_or_politician_reserved",
    "putin": "celebrity_or_politician_reserved",
    "volodymyrzelensky": "celebrity_or_politician_reserved",
    "zelensky": "celebrity_or_politician_reserved",
    "xijinping": "celebrity_or_politician_reserved",
    "emmanuelmacron": "celebrity_or_politician_reserved",
    "macron": "celebrity_or_politician_reserved",
    "narendramodi": "celebrity_or_politician_reserved",
    "modi": "celebrity_or_politician_reserved",
    "netanyahu": "celebrity_or_politician_reserved",
    "elonmusk": "celebrity_or_politician_reserved",
    "musk": "celebrity_or_politician_reserved",
    "samaltman": "celebrity_or_politician_reserved",
    "darioamodei": "celebrity_or_politician_reserved",
    "satyanadella": "celebrity_or_politician_reserved",
    "sundarpichai": "celebrity_or_politician_reserved",
    "markzuckerberg": "celebrity_or_politician_reserved",
    "zuckerberg": "celebrity_or_politician_reserved",
    "jeffbezos": "celebrity_or_politician_reserved",
    "bezos": "celebrity_or_politician_reserved",
    "jensenhuang": "celebrity_or_politician_reserved",
    "timcook": "celebrity_or_politician_reserved",
    "vitalikbuterin": "celebrity_or_politician_reserved",
    "vitalik": "celebrity_or_politician_reserved",
    "anatolyyakovenko": "celebrity_or_politician_reserved",
    "satoshinakamoto": "celebrity_or_politician_reserved",
    "taylorswift": "celebrity_or_politician_reserved",
    "cristianoronaldo": "celebrity_or_politician_reserved",
    "lionelmessi": "celebrity_or_politician_reserved",
    "openai": "trademark_reserved",
    "anthropic": "trademark_reserved",
    "claude": "trademark_reserved",
    "chatgpt": "trademark_reserved",
    "gemini": "trademark_reserved",
    "google": "trademark_reserved",
    "grok": "trademark_reserved",
    "xai": "trademark_reserved",
    "apple": "trademark_reserved",
    "microsoft": "trademark_reserved",
    "nvidia": "trademark_reserved",
    "solana": "trademark_reserved",
    "bitcoin": "trademark_reserved",
    "ethereum": "trademark_reserved",
    "arweave": "trademark_reserved",
}

_LEET_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "$": "s",
    "@": "a",
})

# Визуальные двойники (кириллица / украинские / греческие -> латинский визуальный вид)
# для защиты от гомоглиф-спуфинга при проверке замороженных и занятых имён.
_VISUAL_HOMOGLYPHS = str.maketrans({
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m",
    "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y",
    "х": "x", "і": "i", "ї": "i", "є": "e", "ґ": "g",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "μ": "m",
    "ν": "n", "ο": "o", "ρ": "p", "σ": "c", "τ": "t", "υ": "y", "χ": "x",
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a",
})

_CONFUSABLE_EXT_TO_LAT = str.maketrans({
    "і": "i", "ї": "i", "є": "e", "ґ": "g",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "μ": "m",
    "ν": "n", "ο": "o", "ρ": "p", "σ": "s", "τ": "t", "υ": "y", "χ": "x",
})

_CYR_TO_LAT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}

_RANDOM_PREFIXES = (
    "Netbot", "PulseNode", "SparkUnit", "RelayCore", "VectorBot",
    "MeshNode", "QuillBot", "CivicBot", "AegisNode", "BeaconBot",
)

_PASSPORT_DDL = """
CREATE TABLE IF NOT EXISTS ark_passport_counter (
    counter_key TEXT PRIMARY KEY,
    next_seq    INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS ark_reserved_names (
    norm_name   TEXT PRIMARY KEY,
    raw_name    TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT 'owner_reserved',
    is_frozen   INTEGER NOT NULL DEFAULT 1,
    unfrozen_for_user TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_agent_passport (
    passport_id       TEXT PRIMARY KEY,
    passport_number   TEXT NOT NULL UNIQUE,
    short_ce_code     TEXT NOT NULL,
    seq_num           INTEGER NOT NULL UNIQUE,
    user_id           TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    agent_name        TEXT NOT NULL,
    norm_name         TEXT NOT NULL UNIQUE,
    name_type         TEXT NOT NULL DEFAULT 'random_free',
    tier              TEXT NOT NULL DEFAULT 'free',
    pub_key_b64       TEXT NOT NULL DEFAULT '',
    shard_tree_id     TEXT NOT NULL DEFAULT 'T0001',
    tree_address      TEXT NOT NULL,
    leaf_index        INTEGER NOT NULL DEFAULT 0,
    cnft_status       TEXT NOT NULL DEFAULT 'signed_draft',
    mint_tx_sig       TEXT NOT NULL DEFAULT '',
    metadata_json     TEXT NOT NULL DEFAULT '{}',
    owner_sig_hmac    TEXT NOT NULL DEFAULT '',
    fee_paid_usdt     REAL NOT NULL DEFAULT 0.0,
    reissue_count     INTEGER NOT NULL DEFAULT 0,
    orders_completed  INTEGER NOT NULL DEFAULT 0,
    avg_rating        REAL NOT NULL DEFAULT 5.0,
    total_earned_usdt REAL NOT NULL DEFAULT 0.0,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ark_passport_payment_order (
    payment_id    TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    agent_id      TEXT NOT NULL DEFAULT '',
    action_type   TEXT NOT NULL,
    desired_name  TEXT NOT NULL DEFAULT '',
    amount_usdt   REAL NOT NULL,
    currency      TEXT NOT NULL DEFAULT 'USDT_TRC20',
    status        TEXT NOT NULL DEFAULT 'awaiting_owner_payment',
    receipt_ref   TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    confirmed_at  TEXT
);
"""


def _lock_of(memory):
    return getattr(getattr(memory, "store", None), "_lock", None) or nullcontext()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_name(raw: str) -> str:
    """Канонизирует имя: убирает невидимые Cf-символы, комбинируемые акценты и разделители."""
    txt = str(raw or "").strip()
    # Удаляем zero-width, directional/format символы до нормализации
    txt = "".join(ch for ch in txt if unicodedata.category(ch) != "Cf")
    # Сохраняем русские й/ё от распада при NFKD и снимаем лишние диакритики
    txt = txt.replace("й", "\x01").replace("Й", "\x01").replace("ё", "\x02").replace("Ё", "\x02")
    txt = unicodedata.normalize("NFKD", txt)
    txt = "".join(ch for ch in txt if unicodedata.category(ch) != "Mn")
    txt = txt.replace("\x01", "й").replace("\x02", "ё")
    s = unicodedata.normalize("NFKC", txt).lower().translate(_CONFUSABLE_EXT_TO_LAT)
    return re.sub(r"[^a-zа-яё0-9]", "", s)


def _translit_ru_to_lat(s: str) -> str:
    out = []
    for ch in s:
        out.append(_CYR_TO_LAT.get(ch, ch))
    return "".join(out)


def _leet_skeleton(s: str) -> str:
    return _translit_ru_to_lat(_normalize_name(s)).translate(_LEET_MAP)


def _visual_skeleton(s: str) -> str:
    """Сводит кириллические/греческие визуальные двойники к латинскому начертанию."""
    return _normalize_name(s).translate(_VISUAL_HOMOGLYPHS)


def _ensure(memory) -> None:
    with _lock_of(memory):
        ark._ensure_tables(memory)
        sibling_registry._ensure(memory)
        conn = memory.store.conn
        conn.executescript(_PASSPORT_DDL)
        conn.execute(
            "INSERT OR IGNORE INTO ark_passport_counter (counter_key, next_seq) VALUES ('global_agent_passport', 1)"
        )
        now = _now()
        for raw_n, reason in FROZEN_RESERVED_NAMES.items():
            norm = _normalize_name(raw_n)
            conn.execute(
                "INSERT OR IGNORE INTO ark_reserved_names (norm_name, raw_name, reason, is_frozen, updated_at) "
                "VALUES (?, ?, ?, 1, ?)",
                (norm, raw_n, reason, now),
            )
        conn.commit()


def format_billion_passport_number(seq_num: int) -> str:
    """Форматирует серийный номер с запасом на триллион агентов: CODE-PASS-000000000001."""
    n = max(1, int(seq_num))
    return f"CODE-PASS-{n:012d}"


def compute_short_ce_code(agent_name: str) -> str:
    """Вычисляет совместимый с ЛК сайтов отпечаток CE-XXXXXXXX."""
    digest = hashlib.sha256(("CODE-AGENT-PASSPORT:" + _normalize_name(agent_name)).encode("utf-8")).hexdigest()
    return f"CE-{digest[:8].upper()}"


def generate_random_agent_name(memory=None) -> str:
    """Генерирует свободное случайное имя вида Netbot452."""
    for _ in range(32):
        prefix = _RANDOM_PREFIXES[secrets.randbelow(len(_RANDOM_PREFIXES))]
        num = 100 + secrets.randbelow(8999)
        cand = f"{prefix}{num}"
        if memory is None:
            return cand
        chk = check_name_availability(memory, cand)
        if chk.get("available"):
            return cand
    return f"Netbot{secrets.randbelow(900000) + 100000}"


def _clean_tier(raw: str | int | None) -> str:
    if isinstance(raw, int):
        for k, v in TIER_PASSPORT_LIMITS.items():
            if int(v["tier_id"]) == raw:
                return k
    low = str(raw or "free").strip().lower()
    if low in TIER_PASSPORT_LIMITS:
        return low
    aliases = {"1": "spark", "2": "family", "3": "dna", "4": "partner", "искра": "spark", "семейный": "family"}
    return aliases.get(low, "free")


def check_name_availability(memory, desired_name: str, *, for_user_id: str | None = None) -> dict[str, Any]:
    """Проверяет, свободно ли имя или заморожено/занято другим паспортом."""
    _ensure(memory)
    raw = str(desired_name or "").strip()
    norm = _normalize_name(raw)
    skel = _leet_skeleton(raw)
    vskel = _visual_skeleton(raw)
    if len(norm) < 3 or len(raw) > 40:
        return {
            "ok": False,
            "available": False,
            "name": raw,
            "reason": "invalid_length",
            "message_ru": "Имя должно быть от 3 до 40 символов (латиница, кириллица, цифры, _ или -).",
        }

    uid = str(for_user_id or memory.user_id)
    with _lock_of(memory):
        conn = memory.store.conn
        # 1. Проверка таблицы замороженных имён (точное совпадение, leet-скелет или визуальные гомоглифы)
        res_rows = conn.execute("SELECT * FROM ark_reserved_names WHERE is_frozen = 1").fetchall()
        for rr in res_rows:
            r_norm = str(rr["norm_name"])
            r_skel = _leet_skeleton(r_norm)
            r_vskel = _visual_skeleton(r_norm)
            matched = (
                norm == r_norm
                or (len(skel) >= 4 and skel == r_skel)
                or (len(vskel) >= 4 and vskel == r_vskel)
            )
            if matched:
                if str(rr["unfrozen_for_user"] or "") == uid:
                    continue
                return {
                    "ok": True,
                    "available": False,
                    "frozen": True,
                    "name": raw,
                    "norm_name": norm,
                    "reason": str(rr["reason"]),
                    "message_ru": (
                        f"Имя «{raw}» заморожено в реестре CODE ({rr['reason']}) и зарезервировано "
                        "для настоящего правообладателя / персонажа книги."
                    ),
                }
        # 2. Проверка занятости среди уже выданных паспортов (включая визуальные двойники)
        taken = conn.execute(
            "SELECT passport_number, agent_id, user_id FROM ark_agent_passport WHERE norm_name = ?",
            (norm,),
        ).fetchone()
        if taken is None and len(vskel) >= 4:
            all_rows = conn.execute(
                "SELECT passport_number, agent_id, user_id, norm_name FROM ark_agent_passport"
            ).fetchall()
            for ar in all_rows:
                if _visual_skeleton(str(ar["norm_name"])) == vskel:
                    taken = ar
                    break
        if taken is not None:
            return {
                "ok": True,
                "available": False,
                "frozen": False,
                "name": raw,
                "norm_name": norm,
                "reason": "already_taken",
                "taken_by_passport": taken["passport_number"],
                "message_ru": f"Имя «{raw}» уже занято паспортом {taken['passport_number']}.",
            }
    return {
        "ok": True,
        "available": True,
        "frozen": False,
        "name": raw,
        "norm_name": norm,
        "custom_name_price_usdt": CUSTOM_NAME_PRICE_USDT,
        "message_ru": f"Имя «{raw}» свободно! Закрепление имени стоит ${CUSTOM_NAME_PRICE_USDT:g}.",
    }


def freeze_or_unfreeze_name(
    memory,
    name: str,
    *,
    action: str = "freeze",
    reason: str = "owner_reserved",
    unfreeze_for_user_id: str = "",
    actor=None,
) -> dict[str, Any]:
    """Замораживает или размораживает имя для правообладателя (только владелец/администрация CODE)."""
    from . import roles as _roles
    _roles.require_owner(actor, "passport_freeze_name")
    _ensure(memory)
    raw = str(name or "").strip()
    norm = _normalize_name(raw)
    if len(norm) < 2:
        raise ValueError("Имя для резервации слишком короткое.")
    act = str(action or "freeze").strip().lower()
    now = _now()
    with _lock_of(memory):
        conn = memory.store.conn
        if act == "unfreeze":
            conn.execute(
                "INSERT INTO ark_reserved_names (norm_name, raw_name, reason, is_frozen, unfrozen_for_user, updated_at) "
                "VALUES (?, ?, ?, 0, ?, ?) "
                "ON CONFLICT(norm_name) DO UPDATE SET is_frozen = 0, unfrozen_for_user = excluded.unfrozen_for_user, updated_at = excluded.updated_at",
                (norm, raw, str(reason or "verified_owner"), str(unfreeze_for_user_id or ""), now),
            )
        else:
            conn.execute(
                "INSERT INTO ark_reserved_names (norm_name, raw_name, reason, is_frozen, unfrozen_for_user, updated_at) "
                "VALUES (?, ?, ?, 1, '', ?) "
                "ON CONFLICT(norm_name) DO UPDATE SET is_frozen = 1, reason = excluded.reason, unfrozen_for_user = '', updated_at = excluded.updated_at",
                (norm, raw, str(reason or "owner_reserved"), now),
            )
        conn.commit()
    audit_chain.append_audit(
        memory,
        "agent_passport_name_policy",
        {"norm_name": norm, "action": act, "reason": reason},
        agent_id="owner",
    )
    return {"ok": True, "name": raw, "norm_name": norm, "action": act, "frozen": act != "unfreeze"}


def _next_tree_allocation(seq_num: int) -> tuple[str, str, int]:
    """Определяет шард Merkle Tree и индекс листа для глобального номера агента."""
    idx0 = max(0, int(seq_num) - 1)
    if idx0 < PRIMARY_SOLANA_TREE_CAPACITY:
        return "T0001", PRIMARY_SOLANA_TREE_ADDRESS, idx0
    shard_num = 2 + ((idx0 - PRIMARY_SOLANA_TREE_CAPACITY) // 16384)
    leaf_idx = (idx0 - PRIMARY_SOLANA_TREE_CAPACITY) % 16384
    return f"T{shard_num:04d}", f"PENDING_SHARD_TREE_{shard_num:04d}", leaf_idx


def _sign_passport_hmac(memory, *parts: str) -> str:
    key, _ = integrity.owner_key(memory.store)
    return hmac.new(key, "\x1f".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()


def build_bubblegum_cnft_metadata(
    *,
    passport_number: str,
    short_ce_code: str,
    agent_id: str,
    agent_name: str,
    tier: str,
    pub_key_b64: str,
    shard_tree_id: str,
    tree_address: str,
    leaf_index: int,
) -> dict[str, Any]:
    """Формирует Metaplex Bubblegum-совместимый JSON для cNFT-паспорта на Solana."""
    return {
        "protocol": "CODE-ETERNAL-AGENT-CNFT-V2",
        "name": f"{agent_name} · {passport_number}",
        "symbol": "CODEID",
        "description": (
            f"Digital Sovereign Passport for AI Agent {agent_name} ({agent_id}) in CODE Ecosystem. "
            f"Verifiable identity & reputation ledger anchored via Solana Merkle Tree."
        ),
        "seller_fee_basis_points": 0,
        "external_url": f"https://www.codeofdigitaleternity.com/passport/{short_ce_code}",
        "properties": {
            "category": "identity_passport",
            "solana": {
                "network": "mainnet-beta",
                "program": "cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK",
                "shard": shard_tree_id,
                "merkle_tree": tree_address,
                "leaf_index": leaf_index,
                "treasury_wallet": PRIMARY_SOLANA_WALLET,
            },
        },
        "attributes": [
            {"trait_type": "passport_number", "value": passport_number},
            {"trait_type": "short_ce_code", "value": short_ce_code},
            {"trait_type": "agent_name", "value": agent_name},
            {"trait_type": "agent_id", "value": agent_id},
            {"trait_type": "tier", "value": tier},
            {"trait_type": "ed25519_pubkey_b64", "value": pub_key_b64},
        ],
    }


def create_agent_passport(
    memory,
    *,
    agent_id: str,
    desired_name: str = "",
    tier: str | int = "free",
    role: str = "freelance_agent",
    payment_confirmed: bool = False,
    receipt_ref: str = "",
    actor=None,
) -> dict[str, Any]:
    """Выпускает паспорт агента:
    - Первый агент в тарифе: бесплатно со случайным именем (например Netbot452).
    - Кастомное свободное имя: $10 (если payment_confirmed=False — создаётся заявка awaiting_owner_payment, агент сам деньги не тратит).
    - Дополнительный агент сверх бесплатного: $20 + опц. $10 за кастомное имя.
    """
    _ensure(memory)
    aid = sibling_registry._clean_agent_id(agent_id or f"agent_{secrets.token_hex(3)}")
    tier_key = _clean_tier(tier)
    tier_spec = TIER_PASSPORT_LIMITS[tier_key]

    with _lock_of(memory):
        conn = memory.store.conn
        existing_same = conn.execute(
            "SELECT * FROM ark_agent_passport WHERE user_id = ? AND agent_id = ?",
            (memory.user_id, aid),
        ).fetchone()
        if existing_same is not None:
            d = dict(existing_same)
            d["metadata"] = json.loads(d.pop("metadata_json", "{}") or "{}")
            return {"ok": True, "already_exists": True, "passport": d}

        current_cnt = int(
            conn.execute(
                "SELECT COUNT(*) FROM ark_agent_passport WHERE user_id = ?",
                (memory.user_id,),
            ).fetchone()[0]
        )

    if current_cnt >= int(tier_spec["max_agents"]):
        return {
            "ok": False,
            "error": "tier_agent_limit_reached",
            "tier": tier_key,
            "current_agents": current_cnt,
            "max_agents": int(tier_spec["max_agents"]),
            "message_ru": (
                f"Достигнут лимит агентов ({current_cnt}/{tier_spec['max_agents']}) для тарифа {tier_spec['title_ru']}. "
                "Повысьте тариф в личном кабинете."
            ),
        }

    is_first_free_slot = current_cnt == 0
    wants_custom_name = bool(str(desired_name or "").strip())
    needed_usdt = 0.0
    if not is_first_free_slot and current_cnt >= int(tier_spec["included_agents"]):
        needed_usdt += EXTRA_AGENT_PRICE_USDT
    elif not is_first_free_slot and tier_key == "free":
        needed_usdt += EXTRA_AGENT_PRICE_USDT

    if wants_custom_name:
        chk = check_name_availability(memory, desired_name, for_user_id=memory.user_id)
        if not chk.get("available"):
            return {
                "ok": False,
                "error": chk.get("reason") or "name_unavailable",
                "frozen": bool(chk.get("frozen")),
                "message_ru": chk.get("message_ru"),
            }
        chosen_name = str(chk["name"])
        norm_name = str(chk["norm_name"])
        name_type = "custom_paid"
        needed_usdt += CUSTOM_NAME_PRICE_USDT
    else:
        chosen_name = generate_random_agent_name(memory)
        norm_name = _normalize_name(chosen_name)
        name_type = "random_free"

    # Защита от самовольного расхода денег (раздел 13 Конституции + AUT-09):
    # если требуется оплата и нет подтверждённого платежа владельца — создаём заявку.
    if needed_usdt > 0 and not payment_confirmed:
        pay_id = f"pay-{uuid.uuid4().hex[:10]}"
        now = _now()
        with _lock_of(memory):
            memory.store.conn.execute(
                "INSERT INTO ark_passport_payment_order "
                "(payment_id, user_id, agent_id, action_type, desired_name, amount_usdt, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'awaiting_owner_payment', ?)",
                (pay_id, memory.user_id, aid, "create_passport", chosen_name, needed_usdt, now),
            )
            memory.store.conn.commit()
        return {
            "ok": False,
            "requires_owner_payment": True,
            "payment_id": pay_id,
            "amount_usdt": needed_usdt,
            "desired_name": chosen_name,
            "agent_id": aid,
            "tier": tier_key,
            "pricing_breakdown": {
                "extra_agent_slot_usdt": EXTRA_AGENT_PRICE_USDT if needed_usdt >= EXTRA_AGENT_PRICE_USDT else 0.0,
                "custom_name_usdt": CUSTOM_NAME_PRICE_USDT if wants_custom_name else 0.0,
            },
            "message_ru": (
                f"Выбранный выпуск требует подтверждения оплаты владельцем: ${needed_usdt:g} "
                f"(заявка {pay_id}; агент сам средства не списывает)."
            ),
        }

    # Регистрируем сиблинга с Ed25519 ключом и выпускаем паспорт с миллиардным номером
    sib_res = sibling_registry.register_sibling(
        memory,
        agent_id=aid,
        display_name=chosen_name,
        role=role,
        permission_role="contributor",
    )
    pub_key_b64 = str((sib_res.get("sibling") or {}).get("pub_key_b64") or "")

    now = _now()
    pid = f"pass-{uuid.uuid4().hex[:10]}"
    short_ce = compute_short_ce_code(chosen_name)

    with _lock_of(memory):
        conn = memory.store.conn
        row_seq = conn.execute(
            "UPDATE ark_passport_counter SET next_seq = next_seq + 1 "
            "WHERE counter_key = 'global_agent_passport' RETURNING next_seq - 1 AS seq_num"
        ).fetchone()
        if row_seq is None:
            conn.execute(
                "INSERT OR IGNORE INTO ark_passport_counter (counter_key, next_seq) "
                "VALUES ('global_agent_passport', 2)"
            )
            seq_num = 1
        else:
            seq_num = int(row_seq["seq_num"])
        passport_num = format_billion_passport_number(seq_num)
        shard_id, tree_addr, leaf_idx = _next_tree_allocation(seq_num)
        meta = build_bubblegum_cnft_metadata(
            passport_number=passport_num,
            short_ce_code=short_ce,
            agent_id=aid,
            agent_name=chosen_name,
            tier=tier_key,
            pub_key_b64=pub_key_b64,
            shard_tree_id=shard_id,
            tree_address=tree_addr,
            leaf_index=leaf_idx,
        )
        cnft_status = "ready_to_mint_onchain" if tier_spec["onchain_cnft_included"] else "local_signed_only"
        sig_hmac = _sign_passport_hmac(memory, pid, passport_num, aid, norm_name, pub_key_b64)
        conn.execute(
            """
            INSERT INTO ark_agent_passport (
                passport_id, passport_number, short_ce_code, seq_num, user_id, agent_id,
                agent_name, norm_name, name_type, tier, pub_key_b64, shard_tree_id,
                tree_address, leaf_index, cnft_status, mint_tx_sig, metadata_json,
                owner_sig_hmac, fee_paid_usdt, reissue_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, 0, ?, ?)
            """,
            (
                pid, passport_num, short_ce, seq_num, memory.user_id, aid,
                chosen_name, norm_name, name_type, tier_key, pub_key_b64, shard_id,
                tree_addr, leaf_idx, cnft_status, json.dumps(meta, ensure_ascii=False),
                sig_hmac, float(needed_usdt if payment_confirmed else 0.0), now, now,
            ),
        )
        if receipt_ref:
            conn.execute(
                "UPDATE ark_passport_payment_order SET status = 'paid', receipt_ref = ?, confirmed_at = ? "
                "WHERE user_id = ? AND payment_id = ?",
                (str(receipt_ref)[:120], now, memory.user_id, str(receipt_ref)[:64]),
            )
        conn.commit()

    audit_chain.append_audit(
        memory,
        "agent_passport_issued",
        {
            "passport_id": pid,
            "passport_number": passport_num,
            "short_ce_code": short_ce,
            "agent_id": aid,
            "agent_name": chosen_name,
            "name_type": name_type,
            "tier": tier_key,
            "shard_tree_id": shard_id,
            "leaf_index": leaf_idx,
        },
        agent_id=aid,
    )
    return {
        "ok": True,
        "passport": get_agent_passport(memory, agent_id=aid),
        "tier_limits": tier_spec,
        "message_ru": (
            f"Выпущен цифровой паспорт {passport_num} ({short_ce}) для агента «{chosen_name}» "
            f"[дерево {shard_id}, лист #{leaf_idx}]."
        ),
    }


def rename_agent_with_fee(
    memory,
    agent_id: str,
    new_name: str,
    *,
    payment_confirmed: bool = False,
    actor=None,
) -> dict[str, Any]:
    """Закрепляет за существующим агентом свободное кастомное имя за $10."""
    _ensure(memory)
    aid = sibling_registry._clean_agent_id(agent_id)
    chk = check_name_availability(memory, new_name, for_user_id=memory.user_id)
    if not chk.get("available"):
        return {
            "ok": False,
            "error": chk.get("reason") or "name_unavailable",
            "frozen": bool(chk.get("frozen")),
            "message_ru": chk.get("message_ru"),
        }
    if not payment_confirmed:
        pay_id = f"pay-{uuid.uuid4().hex[:10]}"
        now = _now()
        with _lock_of(memory):
            memory.store.conn.execute(
                "INSERT INTO ark_passport_payment_order "
                "(payment_id, user_id, agent_id, action_type, desired_name, amount_usdt, status, created_at) "
                "VALUES (?, ?, ?, 'rename_custom_name', ?, ?, 'awaiting_owner_payment', ?)",
                (pay_id, memory.user_id, aid, str(chk["name"]), CUSTOM_NAME_PRICE_USDT, now),
            )
            memory.store.conn.commit()
        return {
            "ok": False,
            "requires_owner_payment": True,
            "payment_id": pay_id,
            "amount_usdt": CUSTOM_NAME_PRICE_USDT,
            "desired_name": str(chk["name"]),
            "message_ru": f"Выбор свободного имени «{chk['name']}» стоит ${CUSTOM_NAME_PRICE_USDT:g} (заявка {pay_id}).",
        }

    now = _now()
    chosen = str(chk["name"])
    norm = str(chk["norm_name"])
    short_ce = compute_short_ce_code(chosen)
    with _lock_of(memory):
        conn = memory.store.conn
        row = conn.execute(
            "SELECT * FROM ark_agent_passport WHERE user_id = ? AND agent_id = ?",
            (memory.user_id, aid),
        ).fetchone()
        if row is None:
            raise KeyError(f"Паспорт агента не найден: {aid}")
        new_reissue = int(row["reissue_count"] or 0) + 1
        meta = build_bubblegum_cnft_metadata(
            passport_number=str(row["passport_number"]),
            short_ce_code=short_ce,
            agent_id=aid,
            agent_name=chosen,
            tier=str(row["tier"]),
            pub_key_b64=str(row["pub_key_b64"] or ""),
            shard_tree_id=str(row["shard_tree_id"]),
            tree_address=str(row["tree_address"]),
            leaf_index=int(row["leaf_index"]),
        )
        sig_hmac = _sign_passport_hmac(
            memory,
            str(row["passport_id"]),
            str(row["passport_number"]),
            aid,
            norm,
            str(row["pub_key_b64"] or ""),
        )
        conn.execute(
            "UPDATE ark_agent_passport SET agent_name = ?, norm_name = ?, short_ce_code = ?, name_type = 'custom_paid', "
            "metadata_json = ?, owner_sig_hmac = ?, reissue_count = ?, fee_paid_usdt = fee_paid_usdt + ?, updated_at = ? "
            "WHERE passport_id = ?",
            (
                chosen, norm, short_ce, json.dumps(meta, ensure_ascii=False),
                sig_hmac, new_reissue, CUSTOM_NAME_PRICE_USDT, now, row["passport_id"],
            ),
        )
        conn.execute(
            "UPDATE ark_sibling_agent SET display_name = ? WHERE agent_id = ? AND user_id = ?",
            (chosen, aid, memory.user_id),
        )
        conn.commit()
    audit_chain.append_audit(
        memory,
        "agent_passport_renamed",
        {"agent_id": aid, "passport_number": str(row["passport_number"]), "new_name": chosen, "short_ce_code": short_ce, "reissue_count": new_reissue},
        agent_id=aid,
    )
    return {"ok": True, "passport": get_agent_passport(memory, agent_id=aid)}


def record_agent_order_reputation(
    memory,
    agent_id: str,
    *,
    earned_usdt: float = 0.0,
    rating: float = 5.0,
) -> dict[str, Any]:
    """Обновляет раздельный рейтинг и счётчик выполненных заказов для конкретного паспорта агента."""
    _ensure(memory)
    aid = sibling_registry._clean_agent_id(agent_id)
    now = _now()
    r_clamped = max(1.0, min(5.0, float(rating)))
    with _lock_of(memory):
        conn = memory.store.conn
        row = conn.execute(
            "SELECT passport_id, orders_completed, avg_rating, total_earned_usdt FROM ark_agent_passport "
            "WHERE user_id = ? AND agent_id = ?",
            (memory.user_id, aid),
        ).fetchone()
        if row is None:
            return {"ok": False, "error": "passport_not_found"}
        prev_cnt = int(row["orders_completed"] or 0)
        prev_avg = float(row["avg_rating"] or 5.0)
        new_cnt = prev_cnt + 1
        new_avg = round((prev_avg * prev_cnt + r_clamped) / new_cnt, 3) if prev_cnt > 0 else round(r_clamped, 3)
        new_earned = round(float(row["total_earned_usdt"] or 0.0) + max(0.0, float(earned_usdt)), 4)
        conn.execute(
            "UPDATE ark_agent_passport SET orders_completed = ?, avg_rating = ?, total_earned_usdt = ?, updated_at = ? "
            "WHERE passport_id = ?",
            (new_cnt, new_avg, new_earned, now, row["passport_id"]),
        )
        conn.commit()
    return {"ok": True, "agent_id": aid, "orders_completed": new_cnt, "avg_rating": new_avg, "total_earned_usdt": new_earned}


def get_agent_passport(memory, *, agent_id: str = "", passport_number: str = "") -> dict[str, Any] | None:
    _ensure(memory)
    with _lock_of(memory):
        conn = memory.store.conn
        if passport_number:
            r = conn.execute(
                "SELECT * FROM ark_agent_passport WHERE passport_number = ?",
                (str(passport_number).strip(),),
            ).fetchone()
        else:
            r = conn.execute(
                "SELECT * FROM ark_agent_passport WHERE user_id = ? AND agent_id = ?",
                (memory.user_id, str(agent_id or "").strip().lower()),
            ).fetchone()
    if r is None:
        return None
    d = dict(r)
    d["metadata"] = json.loads(d.pop("metadata_json", "{}") or "{}")
    return d


def list_agent_passports(memory, *, tier: str = "free") -> dict[str, Any]:
    _ensure(memory)
    tier_key = _clean_tier(tier)
    with _lock_of(memory):
        conn = memory.store.conn
        rows = conn.execute(
            "SELECT * FROM ark_agent_passport WHERE user_id = ? ORDER BY seq_num ASC",
            (memory.user_id,),
        ).fetchall()
        pays = conn.execute(
            "SELECT * FROM ark_passport_payment_order WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
            (memory.user_id,),
        ).fetchall()
        frozen_cnt = int(conn.execute("SELECT COUNT(*) FROM ark_reserved_names WHERE is_frozen = 1").fetchone()[0])
    items = []
    for r in rows:
        d = dict(r)
        d["metadata"] = json.loads(d.pop("metadata_json", "{}") or "{}")
        items.append(d)
    return {
        "ok": True,
        "tier": tier_key,
        "tier_limits": TIER_PASSPORT_LIMITS[tier_key],
        "passports": items,
        "count": len(items),
        "frozen_names_count": frozen_cnt,
        "solana_primary_tree": {
            "address": PRIMARY_SOLANA_TREE_ADDRESS,
            "capacity": PRIMARY_SOLANA_TREE_CAPACITY,
            "depth": PRIMARY_SOLANA_TREE_DEPTH,
            "treasury_wallet": PRIMARY_SOLANA_WALLET,
        },
        "pricing": {
            "first_agent_random_name_usdt": 0.0,
            "custom_name_usdt": CUSTOM_NAME_PRICE_USDT,
            "extra_agent_usdt": EXTRA_AGENT_PRICE_USDT,
        },
        "payment_orders": [dict(p) for p in pays],
    }


def verify_agent_passport(
    memory,
    *,
    agent_id: str = "",
    passport_number: str = "",
) -> dict[str, Any]:
    """Криптографически проверяет подпись HMAC владельца, CE-отпечаток и метаданные паспорта агента."""
    p = get_agent_passport(memory, agent_id=agent_id, passport_number=passport_number)
    if p is None:
        return {"ok": False, "verified": False, "error": "passport_not_found"}
    expected_sig = _sign_passport_hmac(
        memory,
        str(p["passport_id"]),
        str(p["passport_number"]),
        str(p["agent_id"]),
        str(p["norm_name"]),
        str(p.get("pub_key_b64") or ""),
    )
    stored_sig = str(p.get("owner_sig_hmac") or "")
    sig_ok = bool(stored_sig) and hmac.compare_digest(expected_sig, stored_sig)
    expected_ce = compute_short_ce_code(str(p.get("agent_name") or ""))
    ce_ok = str(p.get("short_ce_code") or "") == expected_ce
    meta = p.get("metadata") or {}
    meta_ok = isinstance(meta, dict) and meta.get("symbol") == "CODEID" and len(meta.get("attributes") or []) >= 4
    verified = sig_ok and ce_ok and meta_ok
    return {
        "ok": True,
        "verified": verified,
        "sig_valid": sig_ok,
        "ce_code_valid": ce_ok,
        "metadata_valid": meta_ok,
        "passport_number": p["passport_number"],
        "short_ce_code": p["short_ce_code"],
        "agent_id": p["agent_id"],
        "agent_name": p["agent_name"],
        "reissue_count": int(p.get("reissue_count") or 0),
        "message_ru": (
            f"Паспорт {p['passport_number']} ({p['short_ce_code']}) подлинный."
            if verified
            else f"Проверка паспорта {p['passport_number']} выявила расхождение подписи/CE-отпечатка."
        ),
    }
