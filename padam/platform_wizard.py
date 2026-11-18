from __future__ import annotations

"""Мастер подключения 30 площадок из методички + 4 бирж для ИИ-агентов (ЭТАП 2: «выбрал -> вошёл -> дальше мы»).

Инварианты:
- Пароли от аккаунтов НИКОГДА не принимаются и не хранятся (только OAuth 2.0, ключ API или зашифрованная сессия браузера через AES-256-GCM).
- Каждая площадка размечена по официальным правилам и документации API:
  * 'autopilot'       — «автопилот» (комиссия CODE 20%);
  * 'assisted_button' — «черновик и кнопка» (комиссия CODE 15%, отправляет владелец);
  * 'not_available'   — «пока нельзя» (с честной причиной по официальным правилам площадки).
- После входа владелец отвечает на 6 вопросов анкеты -> агент собирает черновик профиля из памяти и анкеты -> публикация профиля только кнопкой владельца (owner_approved=True).
"""

import json
import secrets
import time
from typing import Any

from . import audit_chain, freelance_autonomy


_INITIALIZED_WIZ_DBS: set[int] = set()

WIZARD_QUESTIONS: tuple[dict[str, str], ...] = (
    {"key": "specializations", "label_ru": "1. Направления и услуги (что делаем лучше всего)"},
    {"key": "hourly_rate_usdt", "label_ru": "2. Целевая ставка в час (USDT/ч)"},
    {"key": "min_order_usdt", "label_ru": "3. Минимальный бюджет заказа (USDT)"},
    {"key": "languages", "label_ru": "4. Рабочие языки общения"},
    {"key": "tone", "label_ru": "5. Тон откликов и профиля"},
    {"key": "excluded_topics", "label_ru": "6. Что НЕ берём в работу (стоп-темы)"},
)

# Полный реестр: 30 площадок из МЕТОДИЧКА_ПОЛНАЯ_30_ПЛОЩАДОК.md + 4 биржи для ИИ-агентов (итого 34).
PLATFORM_CATALOG: tuple[dict[str, Any], ...] = (
    # ЧАСТЬ II: ГЛОБАЛЬНЫЕ ФРИЛАНС (1–10)
    {
        "num": 1,
        "platform_id": "upwork",
        "title": "Upwork",
        "category": "global_freelance",
        "score": 9.2,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "oauth",
        "auth_hint_ru": "OAuth 2.0 (Upwork GraphQL API). Пароли не храним.",
        "reason_ru": "Официальный GraphQL OAuth 2.0 API разрешает поиск и учёт, но правила Upwork запрещают автоотправку откликов ботами — черновик готовит агент, отправляет владелец кнопкой (15%).",
        "url": "https://www.upwork.com",
        "docs_url": "https://www.upwork.com/developer",
        "default_fee_pct": 10.0,
    },
    {
        "num": 2,
        "platform_id": "fiverr",
        "title": "Fiverr",
        "category": "global_freelance",
        "score": 9.0,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "browser_session",
        "auth_hint_ru": "Вход через окно браузера (сохраняем только зашифрованную сессию, без пароля).",
        "reason_ru": "Публичного API продавца нет, Terms of Service Fiverr строго запрещают ботов и авто-скрипты — агент готовит черновики гигов и ответов, публикует человек кнопкой (15%).",
        "url": "https://www.fiverr.com",
        "docs_url": "https://www.fiverr.com/legal-portal/legal-terms/terms-of-service",
        "default_fee_pct": 20.0,
    },
    {
        "num": 3,
        "platform_id": "freelancer",
        "title": "Freelancer.com",
        "category": "global_freelance",
        "score": 8.5,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "oauth",
        "auth_hint_ru": "OAuth 2.0 Bearer токен (accounts.freelancer.com/oauth).",
        "reason_ru": "Есть официальный REST API и OAuth 2.0; для защиты аккаунта от блокировки за спам-ставки отклик формируется черновиком и отправляется кнопкой владельца (15%).",
        "url": "https://www.freelancer.com",
        "docs_url": "https://developers.freelancer.com/",
        "default_fee_pct": 10.0,
    },
    {
        "num": 4,
        "platform_id": "peopleperhour",
        "title": "PeoplePerHour",
        "category": "global_freelance",
        "score": 8.3,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "browser_session",
        "auth_hint_ru": "Вход через окно браузера (зашифрованная сессия без пароля).",
        "reason_ru": "Публичного REST API нет, правила WorkStream запрещают внешнюю автоматизацию — агент готовит черновик оффера/профиля, отправляет владелец кнопкой (15%).",
        "url": "https://www.peopleperhour.com",
        "docs_url": "https://www.peopleperhour.com/static/terms",
        "default_fee_pct": 15.0,
    },
    {
        "num": 5,
        "platform_id": "contra",
        "title": "Contra.com",
        "category": "global_freelance",
        "score": 8.2,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "browser_session",
        "auth_hint_ru": "Вход через окно браузера (зашифрованная сессия без пароля).",
        "reason_ru": "Комиссия площадки 0%, открытого публичного API для авто-откликов нет — агент упаковывает портфолио и черновики откликов под кнопку владельца (15%).",
        "url": "https://contra.com",
        "docs_url": "https://contra.com/terms",
        "default_fee_pct": 0.0,
    },
    {
        "num": 6,
        "platform_id": "toptal",
        "title": "Toptal",
        "category": "global_freelance",
        "score": 7.5,
        "automation_tier": "not_available",
        "automation_label_ru": "пока нельзя",
        "work_mode": "assisted",
        "auth_method": "blocked",
        "auth_hint_ru": "Пока нельзя: требуется личный видео-скрининг и живые интервью разработчика.",
        "reason_ru": "Закрытая сеть без публичного API; обязательны 4 этапа живого собеседования и live-coding с человеком по правилам Toptal.",
        "url": "https://www.toptal.com",
        "docs_url": "https://www.toptal.com/tos",
        "default_fee_pct": 0.0,
    },
    {
        "num": 7,
        "platform_id": "arc_dev",
        "title": "Arc.dev",
        "category": "global_freelance",
        "score": 7.3,
        "automation_tier": "not_available",
        "automation_label_ru": "пока нельзя",
        "work_mode": "assisted",
        "auth_method": "blocked",
        "auth_hint_ru": "Пока нельзя: обязательное видео-интервью и закрытый рекрутинговый контур.",
        "reason_ru": "Публичного API нет; допуск к заказам открывается только после живого видео-интервью и проверки личности человека.",
        "url": "https://arc.dev",
        "docs_url": "https://arc.dev/terms",
        "default_fee_pct": 0.0,
    },
    {
        "num": 8,
        "platform_id": "guru",
        "title": "Guru.com",
        "category": "global_freelance",
        "score": 7.0,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "api_key",
        "auth_hint_ru": "Ключ API Guru Developer Network или зашифрованная сессия.",
        "reason_ru": "Есть API/WorkRooms, но правила запрещают спам-ботов — агент оценивает проект и готовит черновик Quote под кнопку владельца (15%).",
        "url": "https://www.guru.com",
        "docs_url": "https://www.guru.com/terms-of-service/",
        "default_fee_pct": 9.0,
    },
    {
        "num": 9,
        "platform_id": "bark",
        "title": "Bark.com",
        "category": "global_freelance",
        "score": 6.8,
        "automation_tier": "not_available",
        "automation_label_ru": "пока нельзя",
        "work_mode": "assisted",
        "auth_method": "blocked",
        "auth_hint_ru": "Пока нельзя: каждый отклик требует платной покупки Bark Credits.",
        "reason_ru": "Нет публичного API, а каждый отклик списывает платные кредиты с карты до согласия клиента (запрещено правилом защиты денег Архитектора).",
        "url": "https://www.bark.com",
        "docs_url": "https://www.bark.com/en/gb/terms/",
        "default_fee_pct": 0.0,
    },
    {
        "num": 10,
        "platform_id": "malt",
        "title": "Malt",
        "category": "global_freelance",
        "score": 6.5,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "api_key",
        "auth_hint_ru": "Токен Malt OpenAPI (api.malt.com) или сессия браузера.",
        "reason_ru": "Официальный OpenAPI покрывает биллинг и профиль FMS, а предложения клиентам подтверждаются человеком кнопкой (15%).",
        "url": "https://www.malt.com",
        "docs_url": "https://www.malt.com/s/legal/general-terms-and-conditions",
        "default_fee_pct": 10.0,
    },
    # ЧАСТЬ III: РУССКОЯЗЫЧНЫЕ ПЛОЩАДКИ (11–17)
    {
        "num": 11,
        "platform_id": "kwork",
        "title": "Kwork.ru",
        "category": "ru_freelance",
        "score": 8.8,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "browser_session",
        "auth_hint_ru": "Вход через окно браузера (сохраняем только зашифрованную сессию, без пароля).",
        "reason_ru": "Публичного REST API нет, правила Kwork запрещают неофициальные парсеры и авто-ботов — агент готовит черновик кворка и отклика на бирже, отправляет владелец кнопкой (15%).",
        "url": "https://kwork.ru",
        "docs_url": "https://kwork.ru/terms_of_service",
        "default_fee_pct": 20.0,
    },
    {
        "num": 12,
        "platform_id": "fl_ru",
        "title": "FL.ru",
        "category": "ru_freelance",
        "score": 8.5,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "browser_session",
        "auth_hint_ru": "Вход через окно браузера (зашифрованная сессия без пароля).",
        "reason_ru": "Открытого API нет, пользовательское соглашение FL.ru запрещает авто-скрипты — агент готовит черновик ответа и расчёт Безопасной сделки под кнопку владельца (15%).",
        "url": "https://www.fl.ru",
        "docs_url": "https://www.fl.ru/about/agreement_site.pdf",
        "default_fee_pct": 15.0,
    },
    {
        "num": 13,
        "platform_id": "weblancer",
        "title": "Weblancer.net",
        "category": "ru_freelance",
        "score": 7.8,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "browser_session",
        "auth_hint_ru": "Вход через окно браузера (зашифрованная сессия без пароля).",
        "reason_ru": "Публичный API отсутствует; агент оценивает ТЗ и формирует черновик заявки для отправки кнопкой владельца (15%).",
        "url": "https://www.weblancer.net",
        "docs_url": "https://www.weblancer.net/help/rules/",
        "default_fee_pct": 5.0,
    },
    {
        "num": 14,
        "platform_id": "freelance_ru",
        "title": "Freelance.ru",
        "category": "ru_freelance",
        "score": 7.5,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "browser_session",
        "auth_hint_ru": "Вход через окно браузера (зашифрованная сессия без пароля).",
        "reason_ru": "Публичного API нет, антифрод блокирует авто-ботов — агент готовит черновик отклика и профиля, публикует владелец кнопкой (15%).",
        "url": "https://freelance.ru",
        "docs_url": "https://freelance.ru/rules/",
        "default_fee_pct": 10.0,
    },
    {
        "num": 15,
        "platform_id": "avito_services",
        "title": "Avito Услуги",
        "category": "ru_freelance",
        "score": 8.0,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "oauth",
        "auth_hint_ru": "Официальный OAuth 2.0 токен Avito API (developers.avito.ru).",
        "reason_ru": "Есть официальный Avito OpenAPI (OAuth 2.0) для объявлений и мессенджера; публикация объявлений и финальных смет идёт по кнопке владельца (15%).",
        "url": "https://www.avito.ru",
        "docs_url": "https://developers.avito.ru/",
        "default_fee_pct": 5.0,
    },
    {
        "num": 16,
        "platform_id": "youdo",
        "title": "YouDo.com",
        "category": "ru_freelance",
        "score": 6.5,
        "automation_tier": "not_available",
        "automation_label_ru": "пока нельзя",
        "work_mode": "assisted",
        "auth_method": "blocked",
        "auth_hint_ru": "Пока нельзя: API доступен только корпоративным партнёрам YouDo Business, отклики платные.",
        "reason_ru": "Нет открытого API для исполнителей, платные отклики/подписка и жёсткая антибот-защита по правилам YouDo.",
        "url": "https://youdo.com",
        "docs_url": "https://youdo.com/terms",
        "default_fee_pct": 15.0,
    },
    {
        "num": 17,
        "platform_id": "workzilla",
        "title": "Workzilla",
        "category": "ru_freelance",
        "score": 6.2,
        "automation_tier": "not_available",
        "automation_label_ru": "пока нельзя",
        "work_mode": "assisted",
        "auth_method": "blocked",
        "auth_hint_ru": "Пока нельзя: платная подписка на входе, капча и бан с удержанием средств за автоматизацию.",
        "reason_ru": "Публичного API нет; правила Workzilla наказывают любую автоматизацию блокировкой аккаунта с конфискацией баланса.",
        "url": "https://work-zilla.com",
        "docs_url": "https://work-zilla.com/rules",
        "default_fee_pct": 10.0,
    },
    # ЧАСТЬ IV: ЦИФРОВЫЕ МАРКЕТПЛЕЙСЫ (18–25)
    {
        "num": 18,
        "platform_id": "lemonsqueezy",
        "title": "Lemon Squeezy",
        "category": "digital_marketplace",
        "score": 9.0,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "Bearer API-ключ Lemon Squeezy v1 + секрет вебхука X-Signature.",
        "reason_ru": "Официальный JSON:API v1 (чтение заказов и товаров) + криптографические вебхуки HMAC-SHA256 позволяют вести учёт продаж и выдачу на автопилоте (20%).",
        "url": "https://www.lemonsqueezy.com",
        "docs_url": "https://docs.lemonsqueezy.com/api",
        "default_fee_pct": 5.0,
    },
    {
        "num": 19,
        "platform_id": "gumroad",
        "title": "Gumroad",
        "category": "digital_marketplace",
        "score": 8.5,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "OAuth Bearer Access Token Gumroad API v2.",
        "reason_ru": "Официальный REST API v2 поддерживает создание/обновление товаров (с кнопки владельца), чтение продаж и Gumroad Ping вебхуки на автопилоте (20%).",
        "url": "https://gumroad.com",
        "docs_url": "https://gumroad.com/api",
        "default_fee_pct": 10.0,
    },
    {
        "num": 20,
        "platform_id": "payhip",
        "title": "Payhip",
        "category": "digital_marketplace",
        "score": 8.2,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "API-ключ Payhip (v2 coupons / webhooks).",
        "reason_ru": "Выдача цифровых файлов и приём вебхуков автоматизированы (20%), а начисление доли ждёт кнопки сверки выплаты владельцем (т.к. подпись sha256(api_key) статична).",
        "url": "https://payhip.com",
        "docs_url": "https://help.payhip.com/article/112-api",
        "default_fee_pct": 5.0,
    },
    {
        "num": 21,
        "platform_id": "whop",
        "title": "Whop.com",
        "category": "digital_marketplace",
        "score": 7.8,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "Bearer API-ключ Whop v1 + Standard Webhooks секрет (ws_...).",
        "reason_ru": "Полный REST API v1 (accounts/me, products, payments) и Standard Webhooks обеспечивают полный автопилот продаж (20%).",
        "url": "https://whop.com",
        "docs_url": "https://docs.whop.com/api-reference",
        "default_fee_pct": 3.0,
    },
    {
        "num": 22,
        "platform_id": "stan_store",
        "title": "Stan.store",
        "category": "digital_marketplace",
        "score": 7.5,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "browser_session",
        "auth_hint_ru": "Вход через окно браузера (зашифрованная сессия без пароля) + вебхук Zapier.",
        "reason_ru": "Открытого публичного REST API для управления витриной нет — агент готовит черновики продуктов и воронки, владелец публикует кнопкой в кабинете (15%).",
        "url": "https://www.stan.store",
        "docs_url": "https://help.stan.store/",
        "default_fee_pct": 0.0,
    },
    {
        "num": 23,
        "platform_id": "etsy",
        "title": "Etsy",
        "category": "digital_marketplace",
        "score": 7.0,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "oauth",
        "auth_hint_ru": "Etsy Open API v3 OAuth 2.0 + x-api-key.",
        "reason_ru": "Etsy API v3 позволяет создавать draft-листинги цифровых товаров, но публикация каждого листинга платная ($0.20) — строго по кнопке владельца (15%).",
        "url": "https://www.etsy.com",
        "docs_url": "https://developers.etsy.com/",
        "default_fee_pct": 6.5,
    },
    {
        "num": 24,
        "platform_id": "sellfy",
        "title": "Sellfy",
        "category": "digital_marketplace",
        "score": 6.8,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "Bearer API-ключ Sellfy API v1 + секрет вебхука.",
        "reason_ru": "Официальный REST API v1 (/v1/products, /v1/orders) и вебхуки заказов работают в режиме автопилота (20%).",
        "url": "https://sellfy.com",
        "docs_url": "https://docs.sellfy.com/",
        "default_fee_pct": 2.0,
    },
    {
        "num": 25,
        "platform_id": "creative_market",
        "title": "Creative Market",
        "category": "digital_marketplace",
        "score": 5.5,
        "automation_tier": "not_available",
        "automation_label_ru": "пока нельзя",
        "work_mode": "assisted",
        "auth_method": "blocked",
        "auth_hint_ru": "Пока нельзя: нет публичного API продавца и требуется ручная премодерация открытия магазина.",
        "reason_ru": "Публичный REST API для загрузки товаров и чтения продаж отсутствует, открытие витрины требует ручного отбора кураторами Creative Market.",
        "url": "https://creativemarket.com",
        "docs_url": "https://creativemarket.com/terms",
        "default_fee_pct": 40.0,
    },
    # ЧАСТЬ V: B2B И ДАННЫЕ (26–30)
    {
        "num": 26,
        "platform_id": "clutch",
        "title": "Clutch.co",
        "category": "b2b_data",
        "score": 6.5,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "browser_session",
        "auth_hint_ru": "Вход через окно браузера (зашифрованная сессия) или RSA-2048 ключ партнёра.",
        "reason_ru": "B2B-каталог агентств: агент готовит черновик профиля компании, портфолио и ответы на входящие лиды, публикует владелец кнопкой (15%).",
        "url": "https://clutch.co",
        "docs_url": "https://clutch.co/terms-of-service",
        "default_fee_pct": 0.0,
    },
    {
        "num": 27,
        "platform_id": "linkedin_services",
        "title": "LinkedIn Services",
        "category": "b2b_data",
        "score": 8.8,
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "oauth",
        "auth_hint_ru": "Официальный LinkedIn OAuth 2.0 токен (learn.microsoft.com/linkedin).",
        "reason_ru": "Правила LinkedIn запрещают неуправляемую авто-рассылку — агент готовит черновики профиля, постов и B2B-ответов, отправляет владелец кнопкой (15%).",
        "url": "https://www.linkedin.com",
        "docs_url": "https://learn.microsoft.com/en-us/linkedin/",
        "default_fee_pct": 0.0,
    },
    {
        "num": 28,
        "platform_id": "datarade",
        "title": "Datarade.ai",
        "category": "b2b_data",
        "score": 7.3,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "API-ключ провайдера данных Datarade / вебхук.",
        "reason_ru": "B2B-маркетплейс датасетов с API-доставкой выборок и вебхуками запросов покупателей — продажа готовых баз работает на автопилоте (20%).",
        "url": "https://datarade.ai",
        "docs_url": "https://datarade.ai/company/terms-of-service",
        "default_fee_pct": 15.0,
    },
    {
        "num": 29,
        "platform_id": "datatoleads",
        "title": "DataToLeads",
        "category": "b2b_data",
        "score": 7.0,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "Ключ API витрины DataToLeads / вебхук оплаты.",
        "reason_ru": "Специализированная витрина готовых B2B-баз с автоматической выдачей файлов после оплаты (автопилот 20%).",
        "url": "https://datatoleads.com",
        "docs_url": "https://datatoleads.com",
        "default_fee_pct": 10.0,
    },
    {
        "num": 30,
        "platform_id": "appsumo",
        "title": "AppSumo",
        "category": "b2b_data",
        "score": 6.0,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "oauth",
        "auth_hint_ru": "AppSumo Partner Licensing API v2 (OAuth 2.0 + X-AppSumo-Licensing-Key).",
        "reason_ru": "Официальный AppSumo Licensing API v2 автоматически обрабатывает покупки, выдачу лицензий и возвраты на автопилоте (20%).",
        "url": "https://appsumo.com",
        "docs_url": "https://docs.licensing.appsumo.com/",
        "default_fee_pct": 30.0,
    },
    # ЧАСТЬ VI: БИРЖИ ДЛЯ ИИ-АГЕНТОВ (31–34)
    {
        "num": 31,
        "platform_id": "aifafocus_mcp",
        "title": "AIfaFocus Partner Network (aifa.works/api/mcp)",
        "category": "agent_exchange",
        "score": 9.8,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "Партнёрский API-ключ AIfaFocus MCP (15 инструментов роя).",
        "reason_ru": "Собственная партнёрская биржа экосистемы CODE для ИИ-агентов (аудиты доступности и веб-разработка, полный автопилот 20%).",
        "url": "https://aifa.works",
        "docs_url": "https://aifa.works/api/mcp",
        "default_fee_pct": 0.0,
    },
    {
        "num": 32,
        "platform_id": "olas_mech",
        "title": "Olas (Autonolas) Mech Marketplace",
        "category": "agent_exchange",
        "score": 8.6,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "Ключ API / сервисный токен агента Mech (без приватных ключей кошелька в открытом виде).",
        "reason_ru": "Специализированная биржа задач между автономными ИИ-агентами (AI Agent Bazaar) — заказы выполняются и сдаются на автопилоте (20%).",
        "url": "https://olas.network/mech-marketplace",
        "docs_url": "https://olas.network/mech-marketplace",
        "default_fee_pct": 2.0,
    },
    {
        "num": 33,
        "platform_id": "fetch_agentverse",
        "title": "Fetch.ai Agentverse / ASI:One",
        "category": "agent_exchange",
        "score": 8.4,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "Agentverse API Token (docs.agentverse.ai).",
        "reason_ru": "Открытый каталог и биржа автономных агентов uAgents с API-вызовами и монетизацией запросов на автопилоте (20%).",
        "url": "https://agentverse.ai",
        "docs_url": "https://docs.agentverse.ai/",
        "default_fee_pct": 3.0,
    },
    {
        "num": 34,
        "platform_id": "relevance_ai",
        "title": "Relevance AI Agent Marketplace",
        "category": "agent_exchange",
        "score": 8.1,
        "automation_tier": "autopilot",
        "automation_label_ru": "автопилот",
        "work_mode": "autopilot",
        "auth_method": "api_key",
        "auth_hint_ru": "Relevance AI API Key + Webhook Secret.",
        "reason_ru": "B2B-маркетплейс автономных ИИ-агентов с официальным REST API и вебхуками запуска задач на автопилоте (20%).",
        "url": "https://relevanceai.com",
        "docs_url": "https://relevanceai.com/docs",
        "default_fee_pct": 5.0,
    },
)

CATALOG_BY_ID: dict[str, dict[str, Any]] = {item["platform_id"]: item for item in PLATFORM_CATALOG}

_WIZ_DDL_STMTS = (
    """
    CREATE TABLE IF NOT EXISTS ark_platform_wizard_connection (
        connection_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        platform_id TEXT NOT NULL,
        auth_method TEXT NOT NULL,
        credential_enc TEXT NOT NULL DEFAULT '',
        account_label TEXT NOT NULL DEFAULT '',
        agent_id TEXT NOT NULL DEFAULT 'aifa',
        status TEXT NOT NULL DEFAULT 'connected',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_wiz_conn_user
        ON ark_platform_wizard_connection(user_id, platform_id, updated_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS ark_platform_owner_intake (
        user_id TEXT NOT NULL,
        platform_id TEXT NOT NULL,
        specializations TEXT NOT NULL DEFAULT '',
        hourly_rate_usdt REAL NOT NULL DEFAULT 35.0,
        min_order_usdt REAL NOT NULL DEFAULT 100.0,
        languages TEXT NOT NULL DEFAULT 'ru, en',
        tone TEXT NOT NULL DEFAULT 'деловой, конкретный',
        excluded_topics TEXT NOT NULL DEFAULT '',
        updated_at REAL NOT NULL,
        PRIMARY KEY (user_id, platform_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ark_platform_profile_draft (
        draft_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        platform_id TEXT NOT NULL,
        headline TEXT NOT NULL,
        overview TEXT NOT NULL,
        skills_json TEXT NOT NULL DEFAULT '[]',
        hourly_rate_usdt REAL NOT NULL DEFAULT 35.0,
        min_order_usdt REAL NOT NULL DEFAULT 100.0,
        sample_pitch TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'draft',
        owner_approved INTEGER NOT NULL DEFAULT 0,
        published_at REAL NOT NULL DEFAULT 0.0,
        updated_at REAL NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_wiz_profile_user
        ON ark_platform_profile_draft(user_id, platform_id, updated_at)
    """,
)


def _ensure_wizard_schema(memory) -> None:
    """Создаёт таблицы мастера подключения площадок без executescript-конфликтов."""
    with freelance_autonomy._lock_of(memory):
        freelance_autonomy._ensure(memory)
        conn = memory.store.conn
        key = id(conn)
        if key in _INITIALIZED_WIZ_DBS:
            try:
                conn.execute("SELECT 1 FROM ark_platform_wizard_connection LIMIT 1")
                return
            except Exception:
                _INITIALIZED_WIZ_DBS.discard(key)
        for stmt in _WIZ_DDL_STMTS:
            conn.execute(stmt.strip())
        conn.commit()
        _INITIALIZED_WIZ_DBS.add(key)


def get_platform_spec(platform_id: str) -> dict[str, Any]:
    pid = str(platform_id or "").strip().lower()
    if pid not in CATALOG_BY_ID:
        raise ValueError(f"Неизвестная площадка: {platform_id!r}. Доступно площадок: {len(PLATFORM_CATALOG)}")
    return dict(CATALOG_BY_ID[pid])


def list_platform_catalog(*, category: str = "", automation_tier: str = "") -> dict[str, Any]:
    """Возвращает полный список 30 площадок из методички + 4 бирж для ИИ-агентов с фильтрами и сводкой."""
    cat = str(category or "").strip().lower()
    tier = str(automation_tier or "").strip().lower()
    items = [
        dict(p)
        for p in PLATFORM_CATALOG
        if (not cat or p["category"] == cat) and (not tier or p["automation_tier"] == tier)
    ]
    counts = {
        "total": len(PLATFORM_CATALOG),
        "methodology_30": sum(1 for p in PLATFORM_CATALOG if p["num"] <= 30),
        "agent_exchanges": sum(1 for p in PLATFORM_CATALOG if p["num"] > 30),
        "autopilot": sum(1 for p in PLATFORM_CATALOG if p["automation_tier"] == "autopilot"),
        "assisted_button": sum(1 for p in PLATFORM_CATALOG if p["automation_tier"] == "assisted_button"),
        "not_available": sum(1 for p in PLATFORM_CATALOG if p["automation_tier"] == "not_available"),
    }
    return {
        "ok": True,
        "counts": counts,
        "questions": list(WIZARD_QUESTIONS),
        "platforms": items,
    }


def connect_platform_step(
    memory,
    *,
    platform_id: str,
    auth_method: str = "",
    token_or_session: str = "",
    account_label: str = "",
    agent_id: str = "aifa",
    password: str = "",
) -> dict[str, Any]:
    """Шаг 2 мастера («вошёл»): принимает только OAuth, ключ API или зашифрованную сессию браузера. Пароли отвергаются."""
    _ensure_wizard_schema(memory)
    if str(password or "").strip():
        raise ValueError("ПАРОЛИ НЕ ХРАНИМ НИКОГДА: используйте только OAuth, ключ API или зашифрованную сессию браузера.")

    spec = get_platform_spec(platform_id)
    pid = spec["platform_id"]
    if spec["automation_tier"] == "not_available" or spec["auth_method"] == "blocked":
        return {
            "ok": False,
            "connected": False,
            "platform_id": pid,
            "automation_tier": "not_available",
            "automation_label_ru": spec["automation_label_ru"],
            "error": f"Площадка {spec['title']} сейчас в статусе «пока нельзя»: {spec['reason_ru']}",
        }

    secret_val = str(token_or_session or "").strip()
    if not secret_val:
        raise ValueError("Необходимо передать OAuth-токен, ключ API или маркер сессии браузера (без пароля).")

    method = str(auth_method or spec["auth_method"]).strip().lower()
    if method not in ("oauth", "api_key", "browser_session"):
        raise ValueError("auth_method должен быть одним из: oauth, api_key, browser_session")

    cred_enc = freelance_autonomy._seal_secret(memory, secret_val)
    now = time.time()
    conn_id = f"wizconn-{pid}-{secrets.token_hex(4)}"
    label = str(account_label or spec["title"]).strip()[:120]
    aid = str(agent_id or "aifa").strip() or "aifa"

    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        conn.execute(
            """
            INSERT INTO ark_platform_wizard_connection (
                connection_id, user_id, platform_id, auth_method, credential_enc,
                account_label, agent_id, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'connected', ?, ?)
            """,
            (conn_id, memory.user_id, pid, method, cred_enc, label, aid[:64], now, now),
        )
        conn.commit()

    audit_chain.append_audit(
        memory,
        "platform_wizard_connected",
        {"connection_id": conn_id, "platform_id": pid, "auth_method": method, "automation_tier": spec["automation_tier"]},
        agent_id=aid,
    )
    return {
        "ok": True,
        "connected": True,
        "connection": {
            "connection_id": conn_id,
            "platform_id": pid,
            "title": spec["title"],
            "automation_tier": spec["automation_tier"],
            "automation_label_ru": spec["automation_label_ru"],
            "work_mode": spec["work_mode"],
            "code_fee_pct": freelance_autonomy.fee_pct_for_mode(spec["work_mode"]),
            "auth_method": method,
            "account_label": label,
            "agent_id": aid,
            "credential_sealed": True,
        },
    }


def _extract_memory_skills(memory) -> list[str]:
    """Извлекает навыки и ключевые компетенции из памяти пользователя для автозаполнения профиля."""
    found: list[str] = []
    try:
        rows = memory.store.conn.execute(
            "SELECT content FROM records WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 20",
            (memory.user_id,),
        ).fetchall()
        for r in rows:
            txt, _ = freelance_autonomy.sanitize_for_delivery(str(r["content"] or ""))
            if txt and len(txt) <= 140:
                found.append(txt)
    except Exception:
        pass
    if not found:
        found = [
            "Next.js / React / Tailwind CSS + интеграция ИИ-агентов 24/7",
            "Аудит цифровой доступности WCAG 2.2 AA и автоматическое исправление UI",
            "Верифицированные B2B-исследования и автоматизация процессов через MCP",
        ]
    return found[:5]


def _public_profile_draft(row: dict[str, Any]) -> dict[str, Any]:
    spec = CATALOG_BY_ID.get(str(row["platform_id"]), {})
    return {
        "draft_id": row["draft_id"],
        "platform_id": row["platform_id"],
        "platform_title": spec.get("title", row["platform_id"]),
        "automation_tier": spec.get("automation_tier", "assisted_button"),
        "automation_label_ru": spec.get("automation_label_ru", "черновик и кнопка"),
        "headline": row["headline"],
        "overview": row["overview"],
        "skills": json.loads(row.get("skills_json") or "[]"),
        "hourly_rate_usdt": float(row["hourly_rate_usdt"]),
        "min_order_usdt": float(row["min_order_usdt"]),
        "sample_pitch": row["sample_pitch"],
        "status": row["status"],
        "owner_approved": bool(row["owner_approved"]),
        "proposal_disclaimer": "Черновик профиля — предложение агента (публикация только кнопкой владельца)",
        "updated_at": row["updated_at"],
    }


def submit_questionnaire_and_build_profile_draft(
    memory,
    *,
    platform_id: str,
    specializations: str,
    hourly_rate_usdt: float = 35.0,
    min_order_usdt: float = 100.0,
    languages: str = "ru, en",
    tone: str = "деловой, конкретный",
    excluded_topics: str = "",
    agent_id: str = "aifa",
) -> dict[str, Any]:
    """Шаг 3 мастера: сохраняет ответы на 6 вопросов владельца и собирает черновик профиля площадки из памяти."""
    _ensure_wizard_schema(memory)
    spec = get_platform_spec(platform_id)
    pid = spec["platform_id"]
    if spec["automation_tier"] == "not_available":
        raise ValueError(f"Площадка {spec['title']} недоступна для автозаполнения: {spec['reason_ru']}")

    clean_spec, _ = freelance_autonomy.sanitize_for_delivery(str(specializations or "").strip())
    if not clean_spec:
        raise ValueError("Ответьте на вопрос 1: укажите направления работы (specializations).")
    clean_langs, _ = freelance_autonomy.sanitize_for_delivery(str(languages or "ru, en").strip())
    clean_tone, _ = freelance_autonomy.sanitize_for_delivery(str(tone or "деловой, конкретный").strip())
    clean_excl, _ = freelance_autonomy.sanitize_for_delivery(str(excluded_topics or "").strip())
    rate = round(max(5.0, float(hourly_rate_usdt or 35.0)), 2)
    min_ord = round(max(10.0, float(min_order_usdt or 100.0)), 2)
    now = time.time()

    mem_highlights = _extract_memory_skills(memory)
    fee_pct = freelance_autonomy.fee_pct_for_mode(spec["work_mode"])
    headline = f"{clean_spec[:90]} | AI Family & PADAM Verified (${rate:g}/h)"
    overview_lines = [
        f"Площадка: {spec['title']} ({spec['automation_label_ru']}, комиссия CODE {fee_pct:g}%).",
        f"Основные направления: {clean_spec}",
        f"Опыт из памяти: {'; '.join(mem_highlights[:3])}",
        f"Рабочие языки: {clean_langs}. Тон работы: {clean_tone}.",
        f"Условия: ставка от ${rate:g}/ч, минимальный заказ от ${min_ord:g} USDT.",
    ]
    if clean_excl:
        overview_lines.append(f"Не берём в работу: {clean_excl}.")
    overview = "\n".join(overview_lines)

    skills_list = [s.strip() for s in clean_spec.replace(";", ",").split(",") if s.strip()][:8]
    if not skills_list:
        skills_list = ["AI Agents", "Next.js", "WCAG Accessibility", "B2B Research"]

    sample_pitch = (
        f"Здравствуйте! Готовы выполнить вашу задачу по направлению «{clean_spec[:60]}» "
        f"(ставка ${rate:g}/ч, мин. заказ ${min_ord:g}). Тон: {clean_tone}. "
        f"Все результаты проходят автоматическую проверку качества и безопасности."
    )

    draft_id = f"prof-{pid}"
    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        conn.execute(
            """
            INSERT INTO ark_platform_owner_intake (
                user_id, platform_id, specializations, hourly_rate_usdt, min_order_usdt,
                languages, tone, excluded_topics, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, platform_id) DO UPDATE SET
                specializations = excluded.specializations,
                hourly_rate_usdt = excluded.hourly_rate_usdt,
                min_order_usdt = excluded.min_order_usdt,
                languages = excluded.languages,
                tone = excluded.tone,
                excluded_topics = excluded.excluded_topics,
                updated_at = excluded.updated_at
            """,
            (memory.user_id, pid, clean_spec, rate, min_ord, clean_langs, clean_tone, clean_excl, now),
        )
        conn.execute(
            """
            INSERT INTO ark_platform_profile_draft (
                draft_id, user_id, platform_id, headline, overview, skills_json,
                hourly_rate_usdt, min_order_usdt, sample_pitch, status, owner_approved,
                published_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', 0, 0.0, ?)
            ON CONFLICT(draft_id) DO UPDATE SET
                headline = excluded.headline,
                overview = excluded.overview,
                skills_json = excluded.skills_json,
                hourly_rate_usdt = excluded.hourly_rate_usdt,
                min_order_usdt = excluded.min_order_usdt,
                sample_pitch = excluded.sample_pitch,
                status = 'draft',
                owner_approved = 0,
                updated_at = excluded.updated_at
            """,
            (
                draft_id,
                memory.user_id,
                pid,
                headline[:200],
                overview[:4000],
                json.dumps(skills_list, ensure_ascii=False),
                rate,
                min_ord,
                sample_pitch[:1500],
                now,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM ark_platform_profile_draft WHERE user_id = ? AND draft_id = ?",
            (memory.user_id, draft_id),
        ).fetchone()

    return {
        "ok": True,
        "questionnaire_saved": True,
        "questions_answered": 6,
        "profile_draft": _public_profile_draft(dict(row)),
    }


def publish_profile_draft(
    memory,
    draft_id: str,
    *,
    owner_approved: bool = False,
) -> dict[str, Any]:
    """Публикует черновик профиля площадки СТРОГО по кнопке владельца (owner_approved=True)."""
    _ensure_wizard_schema(memory)
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        row = conn.execute(
            "SELECT * FROM ark_platform_profile_draft WHERE user_id = ? AND draft_id = ?",
            (memory.user_id, str(draft_id or "").strip()),
        ).fetchone()
    if row is None:
        raise KeyError(f"Черновик профиля не найден: {draft_id}")
    draft = dict(row)

    if not owner_approved:
        return {
            "ok": True,
            "published": False,
            "status": "awaiting_owner_approval",
            "note": "Черновик профиля ждёт нажатия кнопки владельца (owner_approved=True).",
            "profile_draft": _public_profile_draft(draft),
        }

    now = time.time()
    with freelance_autonomy._lock_of(memory):
        conn.execute(
            """
            UPDATE ark_platform_profile_draft
            SET status = 'published', owner_approved = 1, published_at = ?, updated_at = ?
            WHERE user_id = ? AND draft_id = ?
            """,
            (now, now, memory.user_id, draft["draft_id"]),
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM ark_platform_profile_draft WHERE user_id = ? AND draft_id = ?",
            (memory.user_id, draft["draft_id"]),
        ).fetchone()

    audit_chain.append_audit(
        memory,
        "platform_profile_published",
        {"draft_id": draft["draft_id"], "platform_id": draft["platform_id"], "owner_approved": True},
        agent_id="aifa",
    )
    return {
        "ok": True,
        "published": True,
        "status": "published",
        "profile_draft": _public_profile_draft(dict(updated)),
    }


def autopick_and_prepare_jobs(
    memory,
    *,
    platform_id: str,
    candidate_jobs: list[dict[str, Any]] | None = None,
    agent_id: str = "aifa",
) -> dict[str, Any]:
    """Шаг 4 мастера («дальше мы»): отбирает посильные заказы по правилам анкеты владельца, считает маржу и готовит черновик отклика."""
    _ensure_wizard_schema(memory)
    spec = get_platform_spec(platform_id)
    pid = spec["platform_id"]
    if spec["automation_tier"] == "not_available":
        raise ValueError(f"Площадка {spec['title']} недоступна: {spec['reason_ru']}")

    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        intake_row = conn.execute(
            "SELECT * FROM ark_platform_owner_intake WHERE user_id = ? AND platform_id = ?",
            (memory.user_id, pid),
        ).fetchone()
    intake = dict(intake_row) if intake_row is not None else {
        "specializations": "Создание сайтов с ИИ-агентами, базы лидов, аудит WCAG",
        "hourly_rate_usdt": 35.0,
        "min_order_usdt": 100.0,
        "excluded_topics": "казино, спам",
    }

    min_budget = float(intake.get("min_order_usdt") or 100.0)
    target_rate = float(intake.get("hourly_rate_usdt") or 35.0)
    excl_words = [
        w.strip().lower()
        for w in str(intake.get("excluded_topics") or "").replace(";", ",").split(",")
        if w.strip()
    ]

    jobs = candidate_jobs if isinstance(candidate_jobs, list) and candidate_jobs else [
        {
            "title": f"[{spec['title']}] Разработка лендинга с ИИ-агентом и CRM",
            "brief": f"Создать современный сайт на Next.js с обученным чат-агентом по профилю: {intake.get('specializations')}",
            "budget_usdt": max(min_budget + 150.0, 300.0),
            "estimated_hours": 5.0,
            "estimated_tokens": 20000,
        }
    ]

    prepared: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for j in jobs:
        title = str(j.get("title") or "").strip()
        brief = str(j.get("brief") or "").strip()
        budget = float(j.get("budget_usdt") or 0.0)
        combined_low = f"{title} {brief}".lower()

        if budget < min_budget:
            skipped.append({"title": title, "budget_usdt": budget, "reason": f"Бюджет ${budget:g} ниже минимума владельца (${min_budget:g})."})
            continue
        hit_excl = next((w for w in excl_words if w and w in combined_low), None)
        if hit_excl:
            skipped.append({"title": title, "budget_usdt": budget, "reason": f"Содержит исключённую тему из анкеты владельца: {hit_excl!r}."})
            continue

        eval_res = freelance_autonomy.evaluate_and_ingest_job(
            memory,
            platform=pid,
            title=title,
            brief=brief,
            budget_usdt=budget,
            estimated_tokens=int(j.get("estimated_tokens") or 20000),
            estimated_hours=float(j.get("estimated_hours") or 4.0),
            hourly_rate_usdt=target_rate,
            exchange_fee_pct=float(spec.get("default_fee_pct") or 10.0),
            assigned_agent=str(agent_id or "aifa"),
            work_mode=str(spec["work_mode"]),
        )
        bid_draft = None
        if not eval_res.get("security_veto"):
            bid_draft = freelance_autonomy.draft_bid_from_memory(
                memory,
                str(eval_res["order_id"]),
                proposed_usdt=budget,
            )
        prepared.append({
            "order_id": eval_res["order_id"],
            "title": title,
            "budget_usdt": budget,
            "work_mode": spec["work_mode"],
            "code_fee_pct": eval_res["platform_fee_pct"],
            "margin_score": eval_res["margin_score"],
            "effective_hourly_usdt": eval_res["effective_hourly_usdt"],
            "bid_status": (bid_draft or {}).get("status", eval_res["status"]),
            "bid_pitch_preview": (bid_draft or {}).get("bid_text") or (bid_draft or {}).get("pitch_text") or "",
        })

    return {
        "ok": True,
        "platform_id": pid,
        "automation_tier": spec["automation_tier"],
        "work_mode": spec["work_mode"],
        "prepared_count": len(prepared),
        "skipped_count": len(skipped),
        "prepared_jobs": prepared,
        "skipped_jobs": skipped,
    }


def platform_wizard_snapshot(memory) -> dict[str, Any]:
    """Сводка мастера подключения 34 площадок (30 из методички + 4 биржи агентов), анкет и черновиков профилей."""
    _ensure_wizard_schema(memory)
    cat = list_platform_catalog()
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        conns = conn.execute(
            "SELECT connection_id, platform_id, auth_method, account_label, agent_id, status, updated_at "
            "FROM ark_platform_wizard_connection WHERE user_id = ? ORDER BY updated_at DESC",
            (memory.user_id,),
        ).fetchall()
        intakes = conn.execute(
            "SELECT * FROM ark_platform_owner_intake WHERE user_id = ? ORDER BY updated_at DESC",
            (memory.user_id,),
        ).fetchall()
        drafts = conn.execute(
            "SELECT * FROM ark_platform_profile_draft WHERE user_id = ? ORDER BY updated_at DESC",
            (memory.user_id,),
        ).fetchall()
    return {
        "ok": True,
        "counts": cat["counts"],
        "questions": cat["questions"],
        "platforms": cat["platforms"],
        "connections": [dict(r) for r in conns],
        "intakes": [dict(r) for r in intakes],
        "profile_drafts": [_public_profile_draft(dict(r)) for r in drafts],
    }
