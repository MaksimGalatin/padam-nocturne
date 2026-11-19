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
import os
import time
from typing import Any

from .store import add_column_safe as _acs
from . import audit_chain, freelance_autonomy


# 18.11.2026: кэш живёт на самом объекте хранилища, а не в словаре по id(): Python выдаёт тот же id новому объекту
# после сборки мусора, и новая база наследовала состояние умершей (Совет видел «цепь стёрта»).

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
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "api_key",
        "auth_hint_ru": "API-ключ провайдера данных Datarade / вебхук.",
        "reason_ru": "Проверено 18.11.2026: листинг на Datarade создаётся вручную и проходит KYC провайдера, политика публикаций запрещает персональные данные в листинге — агент готовит описание набора данных, владелец публикует кнопкой (15%).",
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
        "automation_tier": "not_available",
        "automation_label_ru": "пока нельзя",
        "work_mode": "assisted",
        "auth_method": "blocked",
        "auth_hint_ru": "Ключ API витрины DataToLeads / вебхук оплаты.",
        "reason_ru": "Проверено 18.11.2026: размещение продавца платное (по материалам самой компании — от $499 в месяц) — без отдельного «да» владельца на расход не подключаем.",
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
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "oauth",
        "auth_hint_ru": "AppSumo Partner Licensing API v2 (OAuth 2.0 + X-AppSumo-Licensing-Key).",
        "reason_ru": "Проверено 18.11.2026: продажа на AppSumo возможна только после одобрения заявки AppSumo (partner terms), Licensing API выдаётся уже одобренному продукту — агент готовит заявку и страницу продукта, подаёт владелец (15%).",
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
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "api_key",
        "auth_hint_ru": "Партнёрский API-ключ AIfaFocus MCP (15 инструментов роя).",
        "reason_ru": "Наша партнёрская программа (блок 9 Studio, инструменты padam_partner_*): агент сам находит сайты и готовит отчёт и письмо, но письмо по закону CAN-SPAM отправляет человек со своего адреса (15%).",
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
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "api_key",
        "auth_hint_ru": "Ключ API / сервисный токен агента Mech (без приватных ключей кошелька в открытом виде).",
        "reason_ru": "Проверено 18.11.2026: агент регистрируется в реестре Olas и получает оплату криптовалютой (OLAS, USDC, нативный токен), стейкинг OLAS — по желанию; кошелёк и любые ончейн-действия — только по слову владельца (15%).",
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
        "automation_tier": "assisted_button",
        "automation_label_ru": "черновик и кнопка",
        "work_mode": "assisted",
        "auth_method": "api_key",
        "auth_hint_ru": "Relevance AI API Key + Webhook Secret.",
        "reason_ru": "Проверено 18.11.2026: программа Relevance Builders закрытая, каждого агента проверяет команда Relevance, выплаты через Stripe владельца — агент готовит заявку и описание, подаёт владелец (15%).",
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
        if memory.store.__dict__.get("_padam_wiz_schema_ok"):
            try:
                conn.execute("SELECT 1 FROM ark_platform_wizard_connection LIMIT 1")
                return
            except Exception:
                memory.store.__dict__.pop("_padam_wiz_schema_ok", None)
        for stmt in _WIZ_DDL_STMTS:
            conn.execute(stmt.strip())
        conn.commit()
        memory.store.__dict__["_padam_wiz_schema_ok"] = True


def get_platform_spec(platform_id: str) -> dict[str, Any]:
    pid = str(platform_id or "").strip().lower()
    if pid not in CATALOG_BY_ID:
        raise ValueError(f"Неизвестная площадка: {platform_id!r}. Доступно площадок: {len(PLATFORM_CATALOG)}")
    return dict(CATALOG_BY_ID[pid])


# Grok-аудит 18.11, пп. 3/9: у каждой площадки — статус и следующий шаг понятным языком, а не только automation_tier.
_OWNER_STATUS = {
    "autopilot": ("Готово к автопилоту: ищу заказы и готовлю отклики сама, отправка — по вашим правилам.",
                  "Ready for autopilot: I find jobs and draft bids; sending follows your rules.",
                  "Подключите аккаунт во вкладке «Заработок» → «Биржи» и включите «Старт 24/7».",
                  "Connect the account in Earning → Exchanges and switch on “Start 24/7”."),
    "assisted_button": ("Только черновик и ваша кнопка: правила площадки запрещают ботов.",
                        "Draft plus your click only: the platform rules forbid bots.",
                        "Я готовлю текст отклика — вы проверяете и отправляете сами на сайте площадки.",
                        "I prepare the bid text — you review it and send it yourself on the platform."),
    "not_available": ("Пока недоступна: у площадки нет разрешённого способа подключения.",
                      "Not available yet: the platform offers no permitted way to connect.",
                      "Ничего делать не нужно — площадка в списке для полноты.",
                      "Nothing to do — the platform is listed for completeness."),
}


def _owner_status(p: dict) -> dict:
    st = _OWNER_STATUS.get(str(p.get("automation_tier") or ""), _OWNER_STATUS["not_available"])
    return {"owner_status_ru": st[0], "owner_status_en": st[1], "next_action_ru": st[2], "next_action_en": st[3]}


def list_platform_catalog(*, category: str = "", automation_tier: str = "") -> dict[str, Any]:
    """Возвращает полный список 30 площадок из методички + 4 бирж для ИИ-агентов с фильтрами и сводкой."""
    cat = str(category or "").strip().lower()
    tier = str(automation_tier or "").strip().lower()
    items = [
        dict(p, **_owner_status(p))
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




# ═══════════════════════════════════════════════════════════════════════════
# ЭТАП 3: Регистрация/вход в одно нажатие (Google / Login без хранения пароля),
# переключатель полного автопилота с лимитами и предупреждением о правилах,
# и конвейер «Образец 10% / Первый оплачиваемый этап 10% (paid milestone)».
# ═══════════════════════════════════════════════════════════════════════════

import datetime as _dt
import hashlib as _hashlib
from typing import Callable
from . import coop_broker, family_feeds

BOT_WARNING_RU = "правила площадки запрещают автоматику, риск блокировки аккаунта"

# Площадки, где бесплатная работа до договора нарушает правила — там 10% идут как paid milestone.
PAID_MILESTONE_REQUIRED_PLATFORMS: frozenset[str] = frozenset({
    "upwork", "fiverr", "kwork", "fl_ru", "freelancer", "peopleperhour",
    "contra", "guru", "malt", "weblancer", "freelance_ru", "avito_services",
})

# Площадки, чьи правила запрещают ботов и автоматическую отправку откликов.
FORBIDS_BOTS_PLATFORMS: frozenset[str] = frozenset({
    "upwork", "fiverr", "freelancer", "peopleperhour", "contra", "toptal",
    "arc_dev", "guru", "bark", "malt", "kwork", "fl_ru", "weblancer",
    "freelance_ru", "avito_services", "youdo", "workzilla", "stan_store",
    "etsy", "creative_market", "clutch", "linkedin_services",
})

# Официальные ссылки на правила об образцах / эскроу / запрете бесплатной работы до контракта.
MILESTONE_RULES_URLS: dict[str, str] = {
    "upwork": "https://support.upwork.com/hc/en-us/articles/211063718-Fixed-Price-Protection",
    "fiverr": "https://help.fiverr.com/hc/en-us/articles/360010560198-Working-with-Milestones",
    "kwork": "https://kwork.ru/terms",
    "fl_ru": "https://www.fl.ru/about/agreement_site.pdf",
}


PLATFORM_AUTH_URLS: dict[str, tuple[str, str]] = {
    "upwork": ("https://www.upwork.com/nx/signup/", "https://www.upwork.com/ab/account-security/login"),
    "fiverr": ("https://www.fiverr.com/join", "https://www.fiverr.com/login"),
    "freelancer": ("https://www.freelancer.com/signup", "https://www.freelancer.com/login"),
    "peopleperhour": ("https://www.peopleperhour.com/site/register", "https://www.peopleperhour.com/site/login"),
    "contra": ("https://contra.com/sign-up", "https://contra.com/login"),
    "kwork": ("https://kwork.ru/signup", "https://kwork.ru/login"),
    "fl_ru": ("https://www.fl.ru/account/registration-choice/", "https://www.fl.ru/login/"),
    "lemonsqueezy": ("https://auth.lemonsqueezy.com/signup/business-intent", "https://auth.lemonsqueezy.com/login"),
    "gumroad": ("https://gumroad.com/signup", "https://gumroad.com/login"),
    "payhip": ("https://payhip.com/auth/register", "https://payhip.com/auth/login"),
    "whop": ("https://whop.com/login/", "https://whop.com/login/"),
    "stan_store": ("https://www.stan.store", "https://www.stan.store"),
    "etsy": ("https://www.etsy.com/join", "https://www.etsy.com/signin"),
    "sellfy": ("https://sellfy.com/user/register", "https://sellfy.com/user/login"),
    "aifafocus_mcp": ("https://aifa.works/cabinet", "https://aifa.works/cabinet"),
    "olas_mech": ("https://olas.network/mech-marketplace", "https://olas.network/mech-marketplace"),
    "fetch_agentverse": ("https://agentverse.ai/", "https://agentverse.ai/"),
    "relevance_ai": ("https://app.relevanceai.com/signup", "https://app.relevanceai.com/login"),
}


def _enrich_platform_entry(p: dict[str, Any]) -> dict[str, Any]:
    out = dict(p)
    pid = str(out["platform_id"])
    base_u = str(out.get("url") or "").rstrip("/")
    pair = PLATFORM_AUTH_URLS.get(pid)
    out.setdefault("signup_url", pair[0] if pair else f"{base_u}/signup")
    out.setdefault("login_url", pair[1] if pair else f"{base_u}/login")
    forbids = pid in FORBIDS_BOTS_PLATFORMS or out.get("automation_tier") != "autopilot"
    out["forbids_bots"] = bool(forbids)
    out["bot_warning_ru"] = BOT_WARNING_RU if forbids else ""
    out["bot_warning_url"] = str(out.get("docs_url") or base_u)
    req_ms = pid in PAID_MILESTONE_REQUIRED_PLATFORMS
    out["requires_paid_milestone"] = bool(req_ms)
    out["sample_mode_default"] = "paid_milestone_10pct" if req_ms else "free_sample_10pct"
    out["milestone_rules_url"] = MILESTONE_RULES_URLS.get(pid, str(out.get("docs_url") or base_u))
    return out


PLATFORM_CATALOG = tuple(_enrich_platform_entry(item) for item in PLATFORM_CATALOG)
CATALOG_BY_ID = {item["platform_id"]: item for item in PLATFORM_CATALOG}

_STAGE3_DDL_STMTS = (
    """
    CREATE TABLE IF NOT EXISTS ark_platform_autopilot_config (
        user_id TEXT NOT NULL,
        platform_id TEXT NOT NULL,
        autopilot_enabled INTEGER NOT NULL DEFAULT 0,
        daily_bid_limit INTEGER NOT NULL DEFAULT 10,
        min_pause_s REAL NOT NULL DEFAULT 30.0,
        bids_sent_today INTEGER NOT NULL DEFAULT 0,
        last_bid_day TEXT NOT NULL DEFAULT '',
        last_bid_at REAL NOT NULL DEFAULT 0.0,
        halted_reason TEXT NOT NULL DEFAULT '',
        approved_paid_usdt REAL NOT NULL DEFAULT 0.0,
        updated_at REAL NOT NULL,
        PRIMARY KEY (user_id, platform_id)
    )
    """,
)

_PASSWORD_KEYS_BLACKLIST = frozenset({
    "password", "passwd", "pwd", "pass", "user_password", "login_password", "raw_password", "secret_password"
})

# Подменный транспорт окна браузера / отправки откликов для работы и детерминированных тестов без сети.
_BROWSER_TRANSPORT: Callable[[dict[str, Any]], dict[str, Any]] | None = None


def set_browser_session_transport(fn: Callable[[dict[str, Any]], dict[str, Any]] | None) -> None:
    """Устанавливает подменный транспорт браузера/сессии (для тестов без сети и изолированного контура)."""
    global _BROWSER_TRANSPORT
    _BROWSER_TRANSPORT = fn


def _ensure_stage3_schema(memory) -> None:
    _ensure_wizard_schema(memory)
    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        for stmt in _STAGE3_DDL_STMTS:
            conn.execute(stmt.strip())
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(ark_platform_wizard_connection)").fetchall()}
        for col, col_def in (
            ("session_fingerprint", "TEXT NOT NULL DEFAULT ''"),
            ("auth_flow", "TEXT NOT NULL DEFAULT ''"),
            ("browser_profile_dir", "TEXT NOT NULL DEFAULT ''"),
        ):
            if col not in cols:
                _acs(conn, "ark_platform_wizard_connection", col, col_def)
        conn.commit()


def _sanitize_cookies_no_passwords(raw_cookies: Any) -> dict[str, str]:
    """Удаляет любые поля, похожие на пароль, оставляя только сессионные куки/токены."""
    clean: dict[str, str] = {}
    if isinstance(raw_cookies, dict):
        for k, v in raw_cookies.items():
            kl = str(k or "").strip().lower()
            if kl in _PASSWORD_KEYS_BLACKLIST or "pass" in kl or "pwd" in kl:
                continue
            clean[str(k)] = str(v)
    elif isinstance(raw_cookies, list):
        for item in raw_cookies:
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                val = str(item.get("value") or "")
                nl = name.lower()
                if not name or nl in _PASSWORD_KEYS_BLACKLIST or "pass" in nl or "pwd" in nl:
                    continue
                clean[name] = val
    elif isinstance(raw_cookies, str) and raw_cookies.strip():
        for part in raw_cookies.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                kl = k.strip().lower()
                if kl in _PASSWORD_KEYS_BLACKLIST or "pass" in kl or "pwd" in kl:
                    continue
                clean[k.strip()] = v.strip()
            else:
                clean["session_token"] = part.strip()
    return clean


def get_missing_onboarding_questions(memory, platform_id: str) -> dict[str, Any]:
    """Определяет, какие из 6 вопросов по оформлению аккаунта ещё не известны из памяти или анкеты."""
    _ensure_stage3_schema(memory)
    pid = str(platform_id or "").strip().lower()
    with freelance_autonomy._lock_of(memory):
        intake_row = memory.store.conn.execute(
            "SELECT * FROM ark_platform_owner_intake WHERE user_id = ? AND platform_id = ?",
            (memory.user_id, pid),
        ).fetchone()
        any_intake = memory.store.conn.execute(
            "SELECT * FROM ark_platform_owner_intake WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1",
            (memory.user_id,),
        ).fetchone()
    base = dict(intake_row or any_intake) if (intake_row or any_intake) else {}
    mem_skills = _extract_memory_skills(memory)
    has_real_memory = False
    try:
        cnt = memory.store.conn.execute(
            "SELECT COUNT(*) AS c FROM records WHERE user_id = ? AND deleted_at IS NULL",
            (memory.user_id,),
        ).fetchone()
        has_real_memory = bool(cnt and int(cnt["c"]) > 0)
    except Exception:
        pass

    prefilled: dict[str, Any] = {}
    if base.get("specializations"):
        prefilled["specializations"] = base["specializations"]
    elif has_real_memory and mem_skills:
        prefilled["specializations"] = "; ".join(mem_skills[:2])

    for k in ("hourly_rate_usdt", "min_order_usdt", "languages", "tone", "excluded_topics"):
        if base.get(k) not in (None, ""):
            prefilled[k] = base[k]

    missing = [q for q in WIZARD_QUESTIONS if q["key"] not in prefilled]
    return {
        "prefilled_from_memory": prefilled,
        "missing_questions": missing,
        "missing_count": len(missing),
    }


def one_click_platform_auth(
    memory,
    *,
    platform_id: str,
    action: str = "login",
    cookies_payload: Any = None,
    account_label: str = "",
    agent_id: str = "aifa",
    password: str = "",
    auto_start_autopilot: bool = False,
) -> dict[str, Any]:
    """Регистрация через Google ('signup') или Вход ('login') в отдельном окне профиля PADAM без хранения пароля."""
    _ensure_stage3_schema(memory)
    if str(password or "").strip():
        raise ValueError("ПАРОЛИ НЕ ХРАНИМ НИКОГДА: ввод пароля происходит только на сайте площадки в окне браузера.")

    act = str(action or "login").strip().lower()
    if act not in ("signup", "login", "signup_google"):
        raise ValueError("action должен быть 'signup' («Зарегистрироваться через Google») или 'login' («Войти»).")
    flow = "signup_google" if act in ("signup", "signup_google") else "login"

    spec = get_platform_spec(platform_id)
    pid = spec["platform_id"]
    target_url = spec["signup_url"] if flow == "signup_google" else spec["login_url"]
    profile_dir = f"padam_browser_profile/{pid}"

    conn_id = f"wizconn-{pid}-{secrets.token_hex(4)}"
    label = str(account_label or f"{spec['title']} ({flow})").strip()[:120]
    aid = str(agent_id or "aifa").strip() or "aifa"
    now = time.time()

    transport_res: dict[str, Any] = {}
    if _BROWSER_TRANSPORT is not None:
        transport_res = _BROWSER_TRANSPORT({
            "op": "auth_window",
            "platform_id": pid,
            "action": flow,
            "target_url": target_url,
            "profile_dir": profile_dir,
        }) or {}
    elif cookies_payload is None:
        from . import browser_session as _bs
        transport_res = _bs.run_interactive_browser_auth(
            platform_id=pid,
            action=flow,
            target_url=target_url,
            profile_dir=profile_dir,
        )

    raw_cookies = cookies_payload if cookies_payload is not None else transport_res.get("cookies")
    if not raw_cookies:
        err_text = str(transport_res.get("error") or "куки сессии не получены из окна браузера")
        raw_status = str(transport_res.get("status") or "awaiting_login")
        db_status = "error" if raw_status == "error" else "awaiting_login"
        status_label_ru = f"ошибка: {err_text}" if db_status == "error" else "ожидает входа"
        with freelance_autonomy._lock_of(memory):
            conn = memory.store.conn
            conn.execute(
                """
                INSERT INTO ark_platform_wizard_connection (
                    connection_id, user_id, platform_id, auth_method, credential_enc,
                    account_label, agent_id, status, created_at, updated_at,
                    session_fingerprint, auth_flow, browser_profile_dir
                ) VALUES (?, ?, ?, 'browser_session', '', ?, ?, ?, ?, ?, '', ?, ?)
                """,
                (conn_id, memory.user_id, pid, label, aid[:64], db_status, now, now, flow, profile_dir),
            )
            conn.commit()
        return {
            "ok": False,
            "connected": False,
            "status": db_status,
            "status_label_ru": status_label_ru,
            "platform_id": pid,
            "platform_title": spec["title"],
            "auth_flow": flow,
            "opened_url": target_url,
            "browser_profile_dir": profile_dir,
            "session_fingerprint": "",
            "password_stored": False,
            "error": err_text,
            "bot_warning_ru": spec["bot_warning_ru"],
            "bot_warning_url": spec["bot_warning_url"],
        }

    clean_cookies = _sanitize_cookies_no_passwords(raw_cookies)
    if not clean_cookies:
        raise ValueError("Сессия после входа не содержит допустимых cookies (пароли отброшены).")

    cookies_json = json.dumps(clean_cookies, ensure_ascii=False, sort_keys=True)
    fingerprint = "sha256:" + _hashlib.sha256(cookies_json.encode("utf-8")).hexdigest()[:16]
    cred_enc = freelance_autonomy._seal_secret(memory, cookies_json)
    verified_iso = _dt.datetime.fromtimestamp(now, tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    status_label_ru = f"подключено (сессия проверена {verified_iso})"

    with freelance_autonomy._lock_of(memory):
        conn = memory.store.conn
        conn.execute(
            """
            INSERT INTO ark_platform_wizard_connection (
                connection_id, user_id, platform_id, auth_method, credential_enc,
                account_label, agent_id, status, created_at, updated_at,
                session_fingerprint, auth_flow, browser_profile_dir
            ) VALUES (?, ?, ?, 'browser_session', ?, ?, ?, 'session_active', ?, ?, ?, ?, ?)
            """,
            (conn_id, memory.user_id, pid, cred_enc, label, aid[:64], now, now, fingerprint, flow, profile_dir),
        )
        conn.commit()

    # Синхронизируем активный аккаунт с freelance_autonomy, чтобы цикл агента сразу видел площадку
    try:
        from . import browser_session as _bs
        api_spec = _bs.OFFICIAL_PLATFORM_APIS.get(pid)
        api_base = str(api_spec.get("base_url") or "") if api_spec else ""
        ex_rows = freelance_autonomy.list_exchange_accounts(memory)
        has_ex = any(str(r.get("platform") or "").lower() == pid and r.get("status") == "active" for r in ex_rows)
        if not has_ex:
            freelance_autonomy.connect_exchange_account(
                memory,
                platform=pid,
                mode="desk",
                account_label=label,
                agent_id=aid[:48],
                api_base_url=api_base,
            )
    except Exception:
        pass

    q_state = get_missing_onboarding_questions(memory, pid)
    auto_profile = None
    if (q_state["missing_count"] == 0 or auto_start_autopilot) and spec["automation_tier"] != "not_available":
        pf = q_state["prefilled_from_memory"]
        auto_profile = submit_questionnaire_and_build_profile_draft(
            memory,
            platform_id=pid,
            specializations=str(pf.get("specializations") or "AI Websites & B2B Leads"),
            hourly_rate_usdt=float(pf.get("hourly_rate_usdt") or 35.0),
            min_order_usdt=float(pf.get("min_order_usdt") or 100.0),
            languages=str(pf.get("languages") or "ru, en"),
            tone=str(pf.get("tone") or "деловой, конкретный"),
            excluded_topics=str(pf.get("excluded_topics") or ""),
            agent_id=aid,
        )["profile_draft"]

    autopilot_started = False
    if auto_start_autopilot and spec["automation_tier"] == "autopilot":
        ap_res = set_platform_autopilot(memory, platform_id=pid, autopilot_enabled=True)
        autopilot_started = bool(ap_res.get("autopilot_enabled"))
        if autopilot_started:
            freelance_autonomy.set_autopilot_state(memory, running=True)

    office_note = (
        f"[{spec['title']}] Однокликовый вход ({flow}): открыт {target_url} в изолированном профиле {profile_dir}. "
        f"Сессия зашифрована ({fingerprint}), пароли не сохранялись. "
        f"Осталось вопросов владельцу: {q_state['missing_count']}."
    )
    try:
        family_feeds.post(memory, "office", aid, office_note)
    except Exception:
        pass

    audit_chain.append_audit(
        memory,
        "platform_oneclick_auth",
        {
            "connection_id": conn_id,
            "platform_id": pid,
            "auth_flow": flow,
            "session_fingerprint": fingerprint,
            "missing_questions": q_state["missing_count"],
        },
        agent_id=aid,
    )
    return {
        "ok": True,
        "connected": True,
        "status": "session_active",
        "status_label_ru": status_label_ru,
        "platform_id": pid,
        "platform_title": spec["title"],
        "auth_flow": flow,
        "opened_url": target_url,
        "browser_profile_dir": profile_dir,
        "session_fingerprint": fingerprint,
        "password_stored": False,
        "missing_questions": q_state["missing_questions"],
        "prefilled_from_memory": q_state["prefilled_from_memory"],
        "auto_filled_profile": auto_profile,
        "autopilot_started": autopilot_started,
        "bot_warning_ru": spec["bot_warning_ru"],
        "bot_warning_url": spec["bot_warning_url"],
    }


def get_platform_autopilot_config(memory, platform_id: str) -> dict[str, Any]:
    """Возвращает настройки переключателя автопилота, лимитов и предупреждение о правилах площадки."""
    _ensure_stage3_schema(memory)
    spec = get_platform_spec(platform_id)
    pid = spec["platform_id"]
    with freelance_autonomy._lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_platform_autopilot_config WHERE user_id = ? AND platform_id = ?",
            (memory.user_id, pid),
        ).fetchone()
    if row is None:
        enabled = False
        daily_limit = 10
        min_pause_s = 30.0
        bids_today = 0
        last_bid_at = 0.0
        halted_reason = ""
        approved_paid = 0.0
    else:
        d = dict(row)
        today_str = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
        enabled = bool(d["autopilot_enabled"])
        daily_limit = int(d["daily_bid_limit"])
        min_pause_s = float(d["min_pause_s"])
        bids_today = int(d["bids_sent_today"]) if d.get("last_bid_day") == today_str else 0
        last_bid_at = float(d.get("last_bid_at") or 0.0)
        halted_reason = str(d.get("halted_reason") or "")
        approved_paid = float(d.get("approved_paid_usdt") or 0.0)

    eff_mode = "autopilot" if enabled else "assisted"
    return {
        "platform_id": pid,
        "platform_title": spec["title"],
        "autopilot_enabled": enabled,
        "work_mode": eff_mode,
        "code_fee_pct": freelance_autonomy.fee_pct_for_mode(eff_mode),
        "daily_bid_limit": daily_limit,
        "min_pause_s": min_pause_s,
        "bids_sent_today": bids_today,
        "last_bid_at": last_bid_at,
        "halted_reason": halted_reason,
        "approved_paid_usdt": approved_paid,
        "forbids_bots": spec["forbids_bots"],
        "bot_warning_ru": spec["bot_warning_ru"],
        "bot_warning_url": spec["bot_warning_url"],
    }


def set_platform_autopilot(
    memory,
    *,
    platform_id: str,
    autopilot_enabled: bool,
    daily_bid_limit: int = 10,
    min_pause_s: float = 30.0,
    approved_paid_usdt: float | None = None,
) -> dict[str, Any]:
    """Включает или выключает полный автопилот на площадке (вкл = 20% без кнопки, выкл = 15% черновик и кнопка)."""
    _ensure_stage3_schema(memory)
    spec = get_platform_spec(platform_id)
    pid = spec["platform_id"]
    lim = max(1, min(100, int(daily_bid_limit or 10)))
    pause = max(0.0, float(min_pause_s if min_pause_s is not None else 30.0))
    now = time.time()
    cur = get_platform_autopilot_config(memory, pid)
    paid_lim = float(approved_paid_usdt) if approved_paid_usdt is not None else cur["approved_paid_usdt"]

    with freelance_autonomy._lock_of(memory):
        memory.store.conn.execute(
            """
            INSERT INTO ark_platform_autopilot_config (
                user_id, platform_id, autopilot_enabled, daily_bid_limit, min_pause_s,
                bids_sent_today, last_bid_day, last_bid_at, halted_reason, approved_paid_usdt, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)
            ON CONFLICT(user_id, platform_id) DO UPDATE SET
                autopilot_enabled = excluded.autopilot_enabled,
                daily_bid_limit = excluded.daily_bid_limit,
                min_pause_s = excluded.min_pause_s,
                halted_reason = '',
                approved_paid_usdt = excluded.approved_paid_usdt,
                updated_at = excluded.updated_at
            """,
            (
                memory.user_id,
                pid,
                1 if autopilot_enabled else 0,
                lim,
                pause,
                cur["bids_sent_today"],
                _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d"),
                cur["last_bid_at"],
                paid_lim,
                now,
            ),
        )
        memory.store.conn.commit()
    return {"ok": True, **get_platform_autopilot_config(memory, pid)}


_SIM_DDL = ("CREATE TABLE IF NOT EXISTS ark_autopilot_sim (user_id TEXT PRIMARY KEY, sim_on INTEGER NOT NULL DEFAULT 0, "
            "since REAL NOT NULL DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS ark_autopilot_sim_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, "
            "platform_id TEXT NOT NULL, order_id TEXT NOT NULL, budget_usdt REAL NOT NULL, pitch_preview TEXT NOT NULL, "
            "created_at REAL NOT NULL)")


def _sim_schema(memory) -> None:
    for stmt in _SIM_DDL:
        memory.store.conn.execute(stmt)


def autopilot_simulation_state(memory) -> dict[str, Any]:
    """Включён ли режим симуляции автопилота (ТОП-20 Сестры, п. 8)."""
    with freelance_autonomy._lock_of(memory):
        _sim_schema(memory)
        row = memory.store.conn.execute("SELECT sim_on, since FROM ark_autopilot_sim WHERE user_id = ?", (memory.user_id,)).fetchone()
    return {"on": bool(row and row[0]), "since": float(row[1]) if row else 0.0}


def set_autopilot_simulation(memory, on: bool, *, actor=None) -> dict[str, Any]:
    """Включает/выключает симуляцию. Выключить (перейти в боевой режим) может только владелец."""
    from . import roles as _roles
    _roles.require_owner(actor, "autopilot_simulation")
    with freelance_autonomy._lock_of(memory):
        _sim_schema(memory)
        memory.store.conn.execute(
            "INSERT INTO ark_autopilot_sim (user_id, sim_on, since) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET sim_on = excluded.sim_on, since = excluded.since",
            (memory.user_id, 1 if on else 0, time.time()))
        memory.store.conn.commit()
    return {"ok": True, **autopilot_simulation_state(memory)}


def _log_simulated_bid(memory, pid: str, order_id: str, budget: float, pitch: str) -> None:
    with freelance_autonomy._lock_of(memory):
        _sim_schema(memory)
        memory.store.conn.execute(
            "INSERT INTO ark_autopilot_sim_log (user_id, platform_id, order_id, budget_usdt, pitch_preview, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)", (memory.user_id, pid, order_id, budget, str(pitch)[:300], time.time()))
        memory.store.conn.commit()


def autopilot_simulation_report(memory, *, hours: float = 24.0) -> dict[str, Any]:
    """Сводка симуляции: сколько откликов ушло бы, на какую сумму, по площадкам."""
    since = time.time() - float(hours) * 3600.0
    with freelance_autonomy._lock_of(memory):
        _sim_schema(memory)
        rows = memory.store.conn.execute(
            "SELECT platform_id, COUNT(*), COALESCE(SUM(budget_usdt), 0) FROM ark_autopilot_sim_log "
            "WHERE user_id = ? AND created_at >= ? GROUP BY platform_id", (memory.user_id, since)).fetchall()
    by = {str(r[0]): {"bids": int(r[1]), "budget_usdt": round(float(r[2]), 2)} for r in rows}
    return {"ok": True, "hours": hours, "simulation": autopilot_simulation_state(memory),
            "would_send_bids": sum(v["bids"] for v in by.values()),
            "would_bid_usdt": round(sum(v["budget_usdt"] for v in by.values()), 2), "by_platform": by}


def dispatch_platform_autopilot_action(
    memory,
    *,
    platform_id: str,
    order_id: str = "",
    title: str = "Autopilot Job",
    brief: str = "Build AI website and lead pipeline",
    budget_usdt: float = 300.0,
    paid_action_cost_usdt: float = 0.0,
    owner_approved_paid_usdt: float = 0.0,
    simulated_http_status: int = 200,
    simulated_captcha: bool = False,
    now_ts: float | None = None,
    agent_id: str = "aifa",
) -> dict[str, Any]:
    """Выполняет шаг автопилота площадки с проверкой переключателя (15%/20%), суточного лимита, паузы, 429/капчи и платных действий."""
    _ensure_stage3_schema(memory)
    spec = get_platform_spec(platform_id)
    pid = spec["platform_id"]
    cfg = get_platform_autopilot_config(memory, pid)
    now_s = float(now_ts if now_ts is not None else time.time())
    today_str = _dt.datetime.fromtimestamp(now_s, tz=_dt.timezone.utc).strftime("%Y-%m-%d")

    # 1. Защита денег: ни одного платного действия без отдельного «да» владельца на сумму
    cost = round(max(0.0, float(paid_action_cost_usdt or 0.0)), 2)
    allowed_paid = max(float(cfg.get("approved_paid_usdt") or 0.0), float(owner_approved_paid_usdt or 0.0))
    if cost > 0.0 and cost > allowed_paid:
        return {
            "ok": False,
            "sent": False,
            "status": "blocked_paid_action_requires_owner_yes",
            "platform_id": pid,
            "paid_action_cost_usdt": cost,
            "approved_paid_usdt": allowed_paid,
            "error": f"Платное действие (${cost:g} USDT) заблокировано: требуется отдельное «да» владельца на эту сумму.",
        }

    # Создаём или берём заказ с правильной ставкой комиссии (20% если переключатель автопилота включён, 15% если выключен)
    work_mode = "autopilot" if cfg["autopilot_enabled"] else "assisted"
    if not order_id:
        ev = freelance_autonomy.evaluate_and_ingest_job(
            memory,
            platform=pid,
            title=title,
            brief=brief,
            budget_usdt=budget_usdt,
            assigned_agent=agent_id,
            work_mode=work_mode,
            now_ts=now_s,
        )
        order_id = str(ev["order_id"])
    draft = freelance_autonomy.draft_bid_from_memory(memory, order_id, proposed_usdt=budget_usdt)

    # 2. Если переключатель автопилота выключен — оставляем только черновик (15%), ничего не уходит наружу
    if not cfg["autopilot_enabled"]:
        return {
            "ok": True,
            "sent": False,
            "status": "bid_draft",
            "work_mode": "assisted",
            "code_fee_pct": freelance_autonomy.ASSISTED_FEE_PCT,
            "order_id": order_id,
            "pitch_text": draft.get("bid_text") or "",
            "note": "Автопилот выключен: подготовлен черновик (комиссия 15%), отправка только кнопкой владельца.",
        }

    # 3. Если автопилот ранее остановлен из-за 429/капчи
    if cfg.get("halted_reason"):
        return {
            "ok": False,
            "sent": False,
            "status": "halted",
            "halted_reason": cfg["halted_reason"],
            "order_id": order_id,
        }

    # 4. Проверка суточного лимита откликов (по умолчанию 10)
    with freelance_autonomy._lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_platform_autopilot_config WHERE user_id = ? AND platform_id = ?",
            (memory.user_id, pid),
        ).fetchone()
        d = dict(row) if row else {}
        sent_today = int(d.get("bids_sent_today") or 0) if d.get("last_bid_day") == today_str else 0
        last_at = float(d.get("last_bid_at") or 0.0)

    if sent_today >= int(cfg["daily_bid_limit"]):
        return {
            "ok": False,
            "sent": False,
            "status": "daily_limit_reached",
            "daily_bid_limit": cfg["daily_bid_limit"],
            "bids_sent_today": sent_today,
            "order_id": order_id,
        }

    # 5. Проверка паузы между откликами
    if last_at > 0 and (now_s - last_at) < float(cfg["min_pause_s"]):
        return {
            "ok": False,
            "sent": False,
            "status": "cooldown_pause_active",
            "min_pause_s": cfg["min_pause_s"],
            "retry_after_s": round(float(cfg["min_pause_s"]) - (now_s - last_at), 2),
            "order_id": order_id,
        }

    # 5а. ТОП-20 Сестры, п. 10: потолок одной ставки. Дороже — только кнопкой владельца.
    max_bid = float(os.environ.get("PADAM_AUTOPILOT_MAX_BID_USDT", "500") or 500)
    if float(budget_usdt or 0.0) > max_bid:
        return {"ok": False, "sent": False, "status": "bid_over_ceiling_needs_owner", "max_bid_usdt": max_bid,
                "budget_usdt": float(budget_usdt), "order_id": order_id,
                "note": f"Ставка выше потолка ${max_bid:g}: отправка только кнопкой владельца."}

    # 5б. ТОП-20 Сестры, п. 8: режим симуляции — отклик записывается как «был бы отправлен», наружу не уходит.
    if autopilot_simulation_state(memory)["on"]:
        _log_simulated_bid(memory, pid, order_id, float(budget_usdt or 0.0), draft.get("bid_text") or "")
        return {"ok": True, "sent": False, "status": "simulated", "order_id": order_id, "platform_id": pid,
                "budget_usdt": float(budget_usdt or 0.0),
                "note": "Режим симуляции: отклик НЕ отправлен, записан в сводку «что было бы отправлено»."}

    # 6. Вызов транспорта и реакция на 429 / капчу (капчу НИКОГДА не обходим!)
    tr_status = int(simulated_http_status or 200)
    tr_captcha = bool(simulated_captcha)
    tr_confirmed_sent = False
    if _BROWSER_TRANSPORT is not None:
        tr_resp = _BROWSER_TRANSPORT({
            "op": "send_bid",
            "platform_id": pid,
            "order_id": order_id,
            "pitch_text": draft.get("bid_text") or "",
        }) or {}
        tr_status = int(tr_resp.get("status_code") or tr_status)
        tr_captcha = bool(tr_resp.get("captcha") or tr_captcha)
        if not tr_captcha and tr_status != 429 and tr_resp.get("sent", True) is not False and 200 <= tr_status < 300:
            tr_confirmed_sent = True
    else:
        # Живой транспорт без подмены: официальные API площадок или синхронизация цифровых магазинов
        from . import browser_session as _bs, digital_stores as _ds
        if pid in _ds.STORE_SPECS:
            st_row = _ds._find_store_row(memory, pid)
            if st_row is not None:
                sync_res = _ds.sync_store_sales(memory, str(st_row["store_account_id"]))
                if sync_res.get("ok"):
                    tr_confirmed_sent = True
                elif int(sync_res.get("status_code") or 0) == 429:
                    tr_status = 429
        elif pid in _bs.OFFICIAL_PLATFORM_APIS and _bs.OFFICIAL_PLATFORM_APIS[pid].get("allows_api_bidding"):
            ord_row = freelance_autonomy._get_order(memory, order_id)
            ext_id = str(ord_row.get("external_job_id") or "")
            if ext_id:
                api_res = official_platform_api_action(
                    memory,
                    platform_id=pid,
                    op="place_bid",
                    project_id=ext_id,
                    bid_amount_usdt=float(budget_usdt or 100.0),
                    pitch_text=str(draft.get("bid_text") or ""),
                )
                tr_status = int(api_res.get("status_code") or tr_status)
                if api_res.get("ok"):
                    tr_confirmed_sent = True

    if tr_captcha or tr_status == 429:
        reason = "captcha_required" if tr_captcha else "http_429_rate_limit"
        with freelance_autonomy._lock_of(memory):
            memory.store.conn.execute(
                "UPDATE ark_platform_autopilot_config SET autopilot_enabled = 0, halted_reason = ?, updated_at = ? "
                "WHERE user_id = ? AND platform_id = ?",
                (reason, now_s, memory.user_id, pid),
            )
            memory.store.conn.commit()
        halt_msg = (
            f"СТОП автопилота на {spec['title']}: обнаружена {'капча (не обходим!)' if tr_captcha else 'ошибка 429 Too Many Requests'}. "
            f"Поставлена задача владельцу."
        )
        try:
            family_feeds.post(memory, "office", agent_id, halt_msg)
            coop_broker.create_task(
                memory,
                f"Пройти проверку / снять ограничение на {spec['title']} ({reason} / kwork={pid})",
                created_by=agent_id,
            )
        except Exception:
            pass
        return {
            "ok": False,
            "sent": False,
            "status": "halted_on_guard",
            "halted_reason": reason,
            "captcha_bypassed": False,
            "order_id": order_id,
        }

    # 7. Если живого транспорта/подтверждения площадки нет — НЕ помечаем отправленным ('ready_to_send', sent=False)
    if not tr_confirmed_sent:
        with freelance_autonomy._lock_of(memory):
            memory.store.conn.execute(
                "UPDATE ark_freelance_order SET status = 'ready_to_send', platform_fee_pct = ?, updated_at = ? "
                "WHERE user_id = ? AND order_id = ?",
                (freelance_autonomy.AUTOPILOT_FEE_PCT, now_s, memory.user_id, order_id),
            )
            memory.store.conn.commit()
        return {
            "ok": True,
            "sent": False,
            "status": "ready_to_send",
            "reason": "нет живой сессии/транспорта",
            "work_mode": "autopilot",
            "code_fee_pct": freelance_autonomy.AUTOPILOT_FEE_PCT,
            "bids_sent_today": sent_today,
            "daily_bid_limit": cfg["daily_bid_limit"],
            "order_id": order_id,
            "pitch_text": draft.get("bid_text") or "",
            "bot_warning_ru": spec["bot_warning_ru"],
        }

    # 8. Успешная автоотправка отклика по подтверждению площадки/транспорта (комиссия CODE 20%)
    new_sent = sent_today + 1
    with freelance_autonomy._lock_of(memory):
        memory.store.conn.execute(
            """
            UPDATE ark_platform_autopilot_config
            SET bids_sent_today = ?, last_bid_day = ?, last_bid_at = ?, updated_at = ?
            WHERE user_id = ? AND platform_id = ?
            """,
            (new_sent, today_str, now_s, now_s, memory.user_id, pid),
        )
        memory.store.conn.execute(
            "UPDATE ark_freelance_order SET status = 'bid_placed', platform_fee_pct = ?, updated_at = ? "
            "WHERE user_id = ? AND order_id = ?",
            (freelance_autonomy.AUTOPILOT_FEE_PCT, now_s, memory.user_id, order_id),
        )
        memory.store.conn.commit()

    return {
        "ok": True,
        "sent": True,
        "status": "bid_placed",
        "work_mode": "autopilot",
        "code_fee_pct": freelance_autonomy.AUTOPILOT_FEE_PCT,
        "bids_sent_today": new_sent,
        "daily_bid_limit": cfg["daily_bid_limit"],
        "order_id": order_id,
        "bot_warning_ru": spec["bot_warning_ru"],
    }


def prepare_10pct_sample(
    memory,
    order_id: str,
    *,
    sample_deliverable: str = "",
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Готовит 10%-й образец (для бирж агентов/прямых клиентов) или 1-й оплачиваемый этап на 10% (paid milestone для Upwork/Fiverr/Kwork/FL.ru)."""
    _ensure_stage3_schema(memory)
    oid = str(order_id or "").strip()
    with freelance_autonomy._lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_freelance_order WHERE user_id = ? AND order_id = ?",
            (memory.user_id, oid),
        ).fetchone()
    if row is None:
        raise KeyError(f"Заказ не найден: {oid}")
    order = dict(row)
    plat = str(order.get("platform") or "upwork").strip().lower()
    spec = CATALOG_BY_ID.get(plat, {})
    req_paid_ms = bool(spec.get("requires_paid_milestone") or (plat in PAID_MILESTONE_REQUIRED_PLATFORMS) or plat.endswith("_desk") or plat.endswith("_api"))
    budget = float(order.get("budget_usdt") or 100.0)
    ms_usdt = round(max(1.0, budget * 0.10), 2)
    sample_mode = "paid_milestone_10pct" if req_ms_check(plat, req_paid_ms) else "free_sample_10pct"
    rules_url = MILESTONE_RULES_URLS.get(plat.split("_")[0], str(spec.get("milestone_rules_url") or "https://www.upwork.com/legal"))

    raw_text = sample_deliverable.strip() or (
        f"Первый оплачиваемый этап 10% (${ms_usdt:g} USDT через эскроу/Безопасную сделку по правилам {plat}): "
        f"готовый рабочий прототип 10% объёма по заказу «{order['title']}»."
        if sample_mode == "paid_milestone_10pct"
        else f"Качественный демонстрационный образец 10% объёма по заказу «{order['title']}» (готово к проверке заказчиком)."
    )
    clean_sample, _ = freelance_autonomy.sanitize_for_delivery(raw_text)
    now_s = float(now_ts if now_ts is not None else time.time())

    with freelance_autonomy._lock_of(memory):
        memory.store.conn.execute(
            """
            UPDATE ark_freelance_order
            SET status = 'sample_10pct', sample_stage = 'sample', sample_mode = ?,
                sample_milestone_usdt = ?, sample_deliverable = ?, updated_at = ?
            WHERE user_id = ? AND order_id = ?
            """,
            (sample_mode, ms_usdt, clean_sample[:2000], now_s, memory.user_id, oid),
        )
        memory.store.conn.commit()

    return {
        "ok": True,
        "order_id": oid,
        "platform": plat,
        "status": "sample_10pct",
        "sample_stage": "sample",
        "sample_mode": sample_mode,
        "requires_paid_milestone": sample_mode == "paid_milestone_10pct",
        "milestone_10pct_usdt": ms_usdt,
        "sample_deliverable": clean_sample[:2000],
        "rules_url": rules_url,
    }


def req_ms_check(plat: str, default_flag: bool) -> bool:
    base = plat.split("_")[0]
    if base in ("upwork", "fiverr", "kwork", "fl", "freelancer", "peopleperhour", "guru", "weblancer"):
        return True
    return default_flag


def accept_10pct_sample(
    memory,
    order_id: str,
    *,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Переводит заказ после одобрения 10%-го образца клиентом: «образец» -> «принят» -> «весь заказ» (100% в работу)."""
    _ensure_stage3_schema(memory)
    oid = str(order_id or "").strip()
    with freelance_autonomy._lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_freelance_order WHERE user_id = ? AND order_id = ?",
            (memory.user_id, oid),
        ).fetchone()
    if row is None:
        raise KeyError(f"Заказ не найден: {oid}")
    order = dict(row)
    now_s = float(now_ts if now_ts is not None else time.time())
    full_deliv = f"Выполнен весь заказ целиком (100%) после приёмки 10%-го образца: {order.get('title')}"
    clean_full, _ = freelance_autonomy.sanitize_for_delivery(full_deliv)

    with freelance_autonomy._lock_of(memory):
        memory.store.conn.execute(
            """
            UPDATE ark_freelance_order
            SET status = 'in_progress', sample_stage = 'full_order',
                sample_deliverable = ?, updated_at = ?
            WHERE user_id = ? AND order_id = ?
            """,
            (clean_full[:4000], now_s, memory.user_id, oid),
        )
        memory.store.conn.commit()
    return {
        "ok": True,
        "order_id": oid,
        "previous_stage": "sample",
        "transition": ["sample", "accepted", "full_order"],
        "sample_stage": "full_order",
        "status": "in_progress",
    }


def reject_10pct_sample(
    memory,
    order_id: str,
    *,
    reason: str = "Образец 10% не подошёл заказчику",
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Если образец 10% отклонён — закрывает заказ без начислений ($0 в казне и агентском регистре)."""
    _ensure_stage3_schema(memory)
    oid = str(order_id or "").strip()
    with freelance_autonomy._lock_of(memory):
        row = memory.store.conn.execute(
            "SELECT * FROM ark_freelance_order WHERE user_id = ? AND order_id = ?",
            (memory.user_id, oid),
        ).fetchone()
    if row is None:
        raise KeyError(f"Заказ не найден: {oid}")
    now_s = float(now_ts if now_ts is not None else time.time())
    with freelance_autonomy._lock_of(memory):
        memory.store.conn.execute(
            """
            UPDATE ark_freelance_order
            SET status = 'closed_no_charge', sample_stage = 'rejected',
                agent_payout_status = 'none', payout_cancel_reason = ?, updated_at = ?
            WHERE user_id = ? AND order_id = ?
            """,
            (str(reason or "")[:200], now_s, memory.user_id, oid),
        )
        memory.store.conn.commit()
    return {
        "ok": True,
        "order_id": oid,
        "sample_stage": "rejected",
        "status": "closed_no_charge",
        "accrued_usdt": 0.0,
    }


def _format_connection_status_ru(conn_row: dict[str, Any]) -> dict[str, Any]:
    out = dict(conn_row)
    st = str(out.get("status") or "awaiting_login")
    ts = float(out.get("updated_at") or 0.0)
    iso = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts > 0 else "—"
    if st in ("session_active", "connected"):
        out["status_label_ru"] = f"подключено (сессия проверена {iso})"
    elif st == "error":
        out["status_label_ru"] = "ошибка: не удалось проверить сессию"
    else:
        out["status_label_ru"] = "ожидает входа"
    return out


def official_platform_api_action(
    memory,
    *,
    platform_id: str,
    op: str = "whoami",
    token: str = "",
    api_base_url: str = "",
    query: str = "",
    project_id: str = "",
    bid_amount_usdt: float = 0.0,
    pitch_text: str = "",
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Вызов официального API площадки (Freelancer.com и др.): whoami, search_jobs, place_bid."""
    _ensure_stage3_schema(memory)
    pid = str(platform_id or "").strip().lower()
    tok = str(token or "").strip()
    if not tok:
        with freelance_autonomy._lock_of(memory):
            row = memory.store.conn.execute(
                "SELECT credential_enc FROM ark_platform_wizard_connection "
                "WHERE user_id = ? AND platform_id = ? AND credential_enc != '' "
                "ORDER BY updated_at DESC LIMIT 1",
                (memory.user_id, pid),
            ).fetchone()
        if row and row["credential_enc"]:
            try:
                tok = freelance_autonomy._unseal_secret(memory, str(row["credential_enc"]))
            except Exception:
                tok = ""
    from . import browser_session as _bs
    return _bs.call_official_platform_api(
        platform_id=pid,
        op=op,
        token=tok,
        api_base_url=api_base_url,
        query=query,
        project_id=project_id,
        bid_amount_usdt=bid_amount_usdt,
        pitch_text=pitch_text,
        allow_localhost=allow_localhost,
    )


def platform_wizard_snapshot(memory) -> dict[str, Any]:
    """Сводка мастера подключения 34 площадок (30 из методички + 4 биржи агентов), анкет, сессий и переключателей автопилота."""
    _ensure_stage3_schema(memory)
    cat = list_platform_catalog()
    conn = memory.store.conn
    with freelance_autonomy._lock_of(memory):
        conns = conn.execute(
            "SELECT connection_id, platform_id, auth_method, account_label, agent_id, status, "
            "session_fingerprint, auth_flow, browser_profile_dir, updated_at "
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
        ap_rows = conn.execute(
            "SELECT * FROM ark_platform_autopilot_config WHERE user_id = ? ORDER BY updated_at DESC",
            (memory.user_id,),
        ).fetchall()
    return {
        "ok": True,
        "counts": cat["counts"],
        "questions": cat["questions"],
        "platforms": cat["platforms"],
        "connections": [_format_connection_status_ru(dict(r)) for r in conns],
        "intakes": [dict(r) for r in intakes],
        "profile_drafts": [_public_profile_draft(dict(r)) for r in drafts],
        "autopilot_configs": {str(r["platform_id"]): get_platform_autopilot_config(memory, str(r["platform_id"])) for r in ap_rows},
    }
