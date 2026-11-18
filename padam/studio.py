# -*- coding: utf-8 -*-
"""PADAM Studio — локальное веб-приложение управления памятью на 10 экранов.

Запуск: `padam studio`.
Сервер слушает только 127.0.0.1 и печатает одноразовую ссылку с токеном во фрагменте адреса (#t=...).
Страница не содержит пользовательских данных в исходном HTML и запрашивает их через REST API
с заголовком Authorization: Bearer <token>.

Безопасность:
- Весь хранимый текст выводится исключительно через textContent.
- Заголовок Content-Security-Policy запрещает любые внешние скрипты, стили, шрифты и картинки:
  default-src 'none'; script-src 'nonce-...'; style-src 'nonce-...'; connect-src 'self'; img-src 'none'
- Четыре языка интерфейса: ru, en, es, zh.
- Две темы оформления: тёмная (фирменный стиль CODE Eternal / AIfa) и светлая (высокий контраст AA/AAA).
"""

from __future__ import annotations

import json
import secrets

from .i18n import lang as _sys_lang
from .logo import code_logo_svg_inline


STRINGS: dict[str, dict[str, str]] = {
    "ru": {
        "app_title": "PADAM · NOCTURNE Studio",
        "app_subtitle": "Локальная защищённая память ИИ-агентов · CODE Eternal",
        "nav_overview": "Обзор",
        "nav_feed": "Лента памяти",
        "nav_search": "Поиск",
        "nav_review": "На проверку",
        "nav_asof": "Память на дату",
        "nav_forget": "Забыть",
        "nav_graph": "Связи",
        "nav_l3": "Вечный слой L3",
        "nav_brain": "Суверенный мозг",
        "brain_title": "Суверенный мозг и Феникс",
        "brain_sub": "Светофор контуров моделей, гигиеническая сборка датасета LoRA и мастер восстановления Феникса",
        "brain_traffic_title": "Светофор контуров (Primary -> Sovereign -> Local)",
        "brain_distill_title": "Датасет личности (Zero-Leak Distill)",
        "brain_distill_btn": "Собрать датасет личности",
        "brain_phoenix_title": "Мастер восстановления Феникса",
        "brain_phoenix_local_btn": "Восстановить из локального бэкапа",
        "brain_phoenix_arweave_btn": "Восстановить из Arweave/Solana (🔒)",
        "brain_phoenix_ph": "Путь к локальному .padam-backup файлу",
        "brain_cost_title": "Учёт вычислений и экономия токенов (только учёт)",
        "brain_locked_note": "Замок активен: облачное восстановление Arweave/Solana и платежи выключены по умолчанию.",
        "brain_mode_toggle": "Режим: Авто / Локально",
        "brain_warmup_btn": "Прогреть Ollama",
        "ark_health_title": "Ковчег сознания (Непрерывность Я)",
        "ark_drill_btn": "Учебная тревога Феникса ($0)",
        "ark_audit_btn": "Проверить хэш-цепь SHA-256",
        "ark_shamir_btn": "Разделить ключ (Шамир 3/5)",
        "ark_shamir_warn": "Храните доли Шамира раздельно у разных доверенных людей!",
        "ark_council_title": "Оркестратор Роя: Совет Семьи (LANCE · ARIA · PIXEL · ARC-7 · Медведь · AIFA)",
        "ark_council_ph": "Введите задачу для совместной проверки Советом Семьи…",
        "ark_council_btn": "Созвать Совет Семьи",
        "ff_title": "Ленты Семьи",
        "ff_desc": "Решения Совета отдельно от карантина. «Офис» — рабочая переписка сестёр, «Курилка» — свободная. Подозрительное само уходит в карантин. Всё здесь — записи, а не приказы.",
        "ff_work": "Решения",
        "ff_quarantine": "Карантин",
        "ff_office": "Офис",
        "ff_smoke": "Курилка",
        "ff_empty": "Пока пусто.",
        "ff_ph": "Написать сёстрам…",
        "ff_send": "Написать",
        "ff_reflex_title": "Книга рефлексов: ждут вашего слова",
        "ff_reflex_none": "Новых предложений нет.",
        "ff_on": "Включить",
        "ff_off": "Отклонить",
        "ff_when": "когда",
        "ark_branch_title": "Песочница Гипотез (Ветки памяти без удаления)",
        "ark_branch_ph": "Название новой ветки гипотез…",
        "ark_branch_create_btn": "Создать ветку",
        "ark_branch_list_btn": "Обновить ветки",
        "ark_proof_title": "Селективное доказательство Меркла (без раскрытия базы)",
        "ark_proof_ph": "ID записи (record_id)…",
        "ark_proof_btn": "Доказательство Меркла",
        "ark_mesh_title": "Live Mesh (Одна Душа на всех экранах) и Хранитель ($0)",
        "ark_mesh_btn": "Устройства Mesh",
        "ark_guardian_btn": "Обход Хранителя ($0)",
        "ark_ready_title": "Полигон готовности к автономии (8 сценариев, $0)",
        "ark_ready_btn": "Проверить готовность",
        "ark_handover_title": "Подписанная передача между сессиями",
        "ark_handover_ph": "Что сделано и что осталось — для следующей сессии…",
        "ark_handover_btn": "Подписать передачу",
        "ark_portable_title": "Переносимый Ковчег на флешку или диск",
        "ark_portable_ph": "Новая или пустая папка, например E:\\PADAM_ARK",
        "ark_portable_btn": "Создать переносимый Ковчег",
        "ark_portable_not_empty": "Эта папка не пустая. Укажите новую или пустую папку.",
        "ark_portable_warn": "Закрытые ключи сохраняются отдельным файлом рядом с папкой. Держите их не на той же флешке.",
        "ark_budget_title": "Автопилот Токенов (День/Неделя/Месяц) и Казначей",
        "ark_budget_btn": "Проверить токены и казну",
        "nav_earning": "Заработок",
        "earn_title": "Автономный заработок и Рой бирж",
        "earn_sub": "Подключение фриланс-бирж (только от имени владельца без обхода проверок), оценка заказов Роем, автопилот квот токенов, казна и прозрачная монетизация.",
        "earn_ex_title": "1. Подключение биржи (профиль без пароля)",
        "earn_ex_label_ph": "Метка профиля (например: Основной аккаунт)",
        "earn_ex_agent_ph": "Агент (aifa / брат / сестра)",
        "earn_ex_token_ph": "Ключ доступа для режима OAuth (необязательно для Desk)",
        "earn_ex_connect_btn": "Подключить профиль биржи",
        "earn_jobs_title": "2. Заказы биржи и конвейер Роя",
        "earn_job_title_ph": "Название заказа…",
        "earn_job_brief_ph": "Краткое ТЗ заказа для проверки безопасности и маржи…",
        "earn_job_budget_ph": "Бюджет USDT",
        "earn_job_tokens_ph": "Оценка токенов",
        "earn_job_eval_btn": "Оценить заказ ($0)",
        "earn_budget_title": "3. Автопилот токенов и согласование пополнений",
        "earn_plan_prov_ph": "Провайдер (primary)",
        "earn_plan_tier_ph": "Тариф (api_payg / pro)",
        "earn_plan_save_btn": "Сохранить квоты",
        "earn_tick_btn": "Проверить таймер",
        "earn_propose_btn": "Запросить пополнение (+$5)",
        "earn_swarm_title": "4. Братья, Сёстры и Монетизация ($GALATIN)",
        "earn_sib_id_ph": "Имя сиблинга (например: brother_codex)",
        "earn_sib_role_ph": "Роль сиблинга в Рое",
        "earn_sib_reg_btn": "Подключить сиблинга",
        "earn_btn_bid": "Черновик отклика",
        "earn_btn_exec": "Взять в Рой",
        "earn_btn_deliver": "Сдать безопасно",
        "earn_btn_settle": "Зачислить оплату",
        "earn_btn_approve": "Одобрить",
        "earn_btn_reject": "Отклонить",
        "earn_btn_execute": "Исполнить оплату",
        "earn_empty_accounts": "Подключённых профилей биржи пока нет.",
        "earn_empty_orders": "Оценённых заказов пока нет.",
        "earn_empty_proposals": "Заявок на покупку токенов или тарифа пока нет.",
        "earn_api_url_ph": "Адрес API биржи (https://... необязательно для Desk)",
        "earn_fetch_btn": "Загрузить заказы с биржи",
        "earn_rec_spend_btn": "Подобрать выгодную подписку",
        "earn_propose_sub_btn": "Заявка на лучшую подписку",
        "earn_share_label": "Ставка агента (1–100% пула после комиссии) и фаза расчёта (комиссия CODE: 15% с вашей кнопкой, 20% на автопилоте):",
        "earn_prefs_save_btn": "Применить ставку",
        "earn_ollama_title": "5. Своя модель Оллама ($0) и устройства Роя",
        "earn_ollama_url_ph": "Адрес Оллама (http://127.0.0.1:11434)",
        "earn_ollama_model_ph": "Модель (например qwen2.5-coder:7b)",
        "earn_ollama_btn": "Подключить модель ($0)",
        "earn_dev_btn": "Добавить текущее устройство",
        "earn_beacon_title": "6. Эволюция Фениксов и Всемирный Маяк Семьи",
        "earn_lora_btn": "Подготовить сборку эволюции ($0)",
        "earn_beacon_btn": "Создать маяк Семьи",
        "earn_auto_start_btn": "Старт автопилота (24/7)",
        "earn_auto_stop_btn": "Остановить",
        "earn_hw_rec_btn": "Подбор под моё железо ($0)",
        "earn_job_hours_ph": "Часы (напр. 4)",
        "earn_job_rate_ph": "Ставка $/ч",
        "earn_job_budget_lbl": "Бюджет (USDT)",
        "earn_job_hours_lbl": "Часы (ч)",
        "earn_job_rate_lbl": "Ставка ($/ч)",
        "earn_job_tokens_lbl": "Токены (~)",
        "earn_bid_preview_title": "Черновик отклика (только предпросмотр — не отправлено):",
        "earn_btn_send_bid": "Отправить отклик",
        "earn_bid_draft_ready": "Черновик отклика подготовлен из памяти и профиля (не отправлен).",
        "earn_job_client_lbl": "Клиент (email / домен / ID)",
        "earn_job_client_ph": "alice@company.com или company.com (необязательно)",
        "earn_client_locked_prefix": "Клиент закреплён за ",
        "earn_until_word": " до ",
        "earn_agent_share_prefix": "Доля агента: ",
        "earn_payout_pending": "в ожидании",
        "earn_payout_credited": "начислено",
        "earn_payout_cancelled": "отменено",
        "earn_btn_accept": "Принято клиентом",
        "earn_btn_refund": "Возврат",
        "earn_stores_title": "7. Магазины цифровых товаров (Автопилот 20%)",
        "earn_stores_sub": "Только API-ключи или вебхуки (без паролей). Продажи идут по ставке автопилота (комиссия CODE 20%).",
        "earn_store_label_ph": "Название магазина (напр. Основной Gumroad)",
        "earn_store_url_ph": "URL API магазина (необязательно)",
        "earn_store_key_ph": "API-ключ / OAuth token магазина",
        "earn_store_wh_ph": "Webhook secret (HMAC / ws_... необязательно)",
        "earn_store_seller_ph": "Seller ID (для Gumroad Ping, необязательно)",
        "earn_store_connect_btn": "Проверить и подключить",
        "earn_store_seed_btn": "3 стартовых черновика",
        "earn_store_sync_btn": "Синхронизировать продажи",
        "earn_draft_title_ph": "Название цифрового товара…",
        "earn_draft_desc_ph": "Описание товара…",
        "earn_draft_price_ph": "Цена USD",
        "earn_draft_url_ph": "Ссылка выдачи / файла",
        "earn_draft_save_btn": "Сохранить черновик",
        "earn_draft_publish_btn": "Одобрить и отправить в магазин",
        "earn_stores_empty": "Магазины пока не подключены.",
        "earn_drafts_empty": "Черновиков товаров пока нет.",
        "earn_draft_proposal_badge": "Цена и текст — предложение агента (решает владелец)",
        "earn_sale_unverified_badge": "Не подтверждена (Payhip: сверьте с выплатой — доля и комиссия не начислены)",
        "earn_btn_confirm_sale": "Подтвердить выплату",
        "earn_partner_t": "9. AIfaFocus: клиенты из нашего исследования (отдельно от бирж)",
        "earn_partner_sub": "Сайты с нарушениями доступности из открытого исследования AIfa, отчёт для владельца сайта и ссылка с вашим кодом партнёра, черновик письма через Совет Семьи и ваши сделки. Те же действия, что у инструментов MCP padam_partner_*. Письма агент только готовит — отправляете вы со своего адреса (закон CAN-SPAM).",
        "earn_partner_key_ph": "Ключ кабинета aifa.works (amcp_…) — хранится зашифрованным",
        "earn_partner_key_btn": "Сохранить ключ",
        "earn_partner_key_link": "Создать ключ в кабинете",
        "earn_partner_st_none": "Ключ кабинета не задан — создайте его на aifa.works/mcp и сохраните здесь.",
        "earn_partner_st_ok": "Ключ кабинета подключён",
        "earn_partner_region_ph": "Регион: US-CA, US-NY или код страны (DE, FR…)",
        "earn_partner_find_btn": "Найти клиентов",
        "earn_partner_site_ph": "Сайт клиента, например example.com",
        "earn_partner_report_btn": "Отчёт для сайта",
        "earn_partner_draft_btn": "Подготовить письмо",
        "earn_partner_link_btn": "Моя ссылка партнёра",
        "earn_partner_kit_btn": "Набор партнёра",
        "earn_partner_deals_btn": "Мои сделки и доход",
        "earn_partner_copy_btn": "Скопировать письмо",
        "earn_partner_mail_btn": "Открыть в своей почте",
        "earn_partner_not_sent": "Письмо НЕ отправлено: отправляете вы сами, по одному, со своего адреса.",
        "earn_partner_copied": "Письмо скопировано",
        "brain_local_no_models": "Ollama не видит ни одной модели: перезапустите Ollama из трея, чтобы она прочитала OLLAMA_MODELS",
        "brain_local_model_missing": "модель не скачана",
        "earn_wiz_tier_autopilot": "автопилот",
        "earn_wiz_tier_assisted": "черновик и кнопка",
        "earn_wiz_tier_na": "пока нельзя",
        "earn_wiz_f_all": "все (34)",
        "earn_wiz_f_autopilot": "автопилот (20%)",
        "earn_wiz_f_assisted": "черновик и кнопка (15%)",
        "earn_wiz_f_na": "пока нельзя",
        "earn_wiz_auth_session": "Зашифрованная сессия браузера",
        "earn_wiz_def_spec": "Создание сайтов с ИИ-агентами, верифицированные базы лидов, аудит WCAG",
        "earn_wiz_def_tone": "деловой, конкретный",
        "earn_wiz_def_excl": "казино, серый парсинг, обход капч",
        "earn_wiz_title": "8. Мастер подключения 30 площадок и бирж агентов (выбрал → вошёл → дальше мы)",
        "earn_wiz_sub": "30 площадок методички + 4 биржи для ИИ-агентов. Пароли не храним никогда (только OAuth, ключ API или зашифрованная сессия браузера).",
        "earn_wiz_secret_ph": "OAuth-токен / ключ API / зашифрованная сессия браузера (БЕЗ пароля)",
        "earn_wiz_connect_btn": "1. Войти (сохранить без пароля)",
        "earn_wiz_q_spec_ph": "Вопрос 1: Направления (напр. Сайты с ИИ, базы лидов, аудит WCAG)",
        "earn_wiz_q_rate_ph": "Вопрос 2: Ставка $/ч",
        "earn_wiz_q_min_ph": "Вопрос 3: Мин. заказ $",
        "earn_wiz_q_langs_ph": "Вопрос 4: Языки (ru, en, es, zh)",
        "earn_wiz_q_tone_ph": "Вопрос 5: Тон (деловой, конкретный)",
        "earn_wiz_q_excl_ph": "Вопрос 6: Что НЕ берём (казино, спам)",
        "earn_wiz_profile_btn": "2. Собрать черновик профиля из памяти",
        "earn_wiz_autopick_btn": "3. Найти посильные заказы и черновик отклика",
        "earn_wiz_pub_profile_btn": "Опубликовать профиль (одобрено владельцем)",
        "earn_wiz_google_btn": "Зарегистрироваться через Google",
        "earn_wiz_login_btn": "Войти",
        "earn_wiz_autopilot_lbl": "Автопилот: отклики и публикации без кнопки (комиссия CODE 20%)",
        "earn_wiz_bot_warn_lbl": "правила площадки запрещают автоматику, риск блокировки аккаунта",
        "earn_btn_sample10": "Образец 10% / Этап 10%",
        "earn_btn_sample_accept": "Образец принят → весь заказ",
        "earn_btn_sample_reject": "Образец отклонён ($0)",
        "nav_settings": "Настройки",
        "nav_quickstart": "Первый запуск",
        "theme_dark": "Тёмная тема",
        "theme_light": "Светлая тема",
        "btn_add_memory": "+ Запомнить",
        "btn_refresh": "Обновить",
        "no_token": "Откройте ссылку с одноразовым ключом (#t=...), которую напечатала команда padam studio.",
        "empty": "Здесь пока нет записей.",
        "empty_feed": "В ленте пока нет записей. Здесь по дням собираются факты, предпочтения и решения. Добавьте запись выше или выполните: padam remember \"Предпочитаю краткие ответы\" --kind preference",
        "empty_search": "Введите запрос или уточните слова. Гибридный поиск объединяет смысл (векторы), точные слова (FTS5) и идентификаторы. Из терминала: padam recall \"ваш запрос\" --explain",
        "empty_review": "Очередь проверки пуста — удержанных записей сейчас нет. Сюда попадают внешние тексты и подозрительные команды до вашего решения. Команда: padam review",
        "empty_asof": "На выбранную дату действующих записей не найдено. Машина времени показывает состояние памяти на любой день в прошлом. Команда: padam recall \"запрос\" --as-of YYYY-MM-DD",
        "empty_receipts": "Выданных квитанций об удалении пока нет. При удалении записи здесь сохраняется криптографическое доказательство затирания. Команда: padam forget <id> --receipt receipt.json",
        "empty_graph": "В базе пока нет узлов для графа. Здесь отображаются связи «вывод ← источник», версии и противоречия. Создать демо-память: padam demo",
        "done": "Выполнено успешно.",
        "failed": "Ошибка",
        "loading": "Загрузка…",
        "records": "активных",
        "pending_ep": "в буфере L1",
        "stale_vec": "старых векторов",
        "all_kinds": "Все виды",
        "all_scopes": "Все области",
        # Виды записей
        "kind_preference": "предпочтение",
        "kind_identity": "кто я (личность)",
        "kind_decision": "решение",
        "kind_correction": "поправка",
        "kind_fact": "факт",
        "kind_state": "состояние",
        "kind_event": "событие",
        # 1. Обзор
        "ov_title": "Обзор памяти и состояния защиты",
        "ov_active": "Действующих записей",
        "ov_review": "Ждут проверки",
        "ov_superseded": "Прежних версий",
        "ov_revoked": "Забытых (ключ стёрт)",
        "ov_episodes": "Эпизодов ждут сна",
        "ov_conflicts": "Противоречий",
        "ov_by_kind": "Распределение по видам памяти",
        "ov_attention": "Что требует вашего решения",
        "ov_attention_clean": "Всё спокойно: удержанных записей, неподписанных личностей и споров нет.",
        "ov_unsigned_alert": "Записей о вас без вашей подписи (внесены мимо PADAM):",
        "ov_btn_sign_all": "Проверить и подписать мои записи",
        "ov_quarantined_alert": "Записей от агентов и внешних источников ждут проверки:",
        "ov_btn_go_review": "Открыть очередь проверки",
        "ov_conflict_alert": "Найдены спорящие активные записи об одном и том же:",
        "ov_sleep_title": "Консолидация NOCTURNE («Сон»)",
        "ov_sleep_never": "Цикл сна ещё не запускался. Запустите его, когда накопится буфер эпизодов.",
        "ov_sleep_last": "Последний сон:",
        "ov_sleep_sampled": "Обработано эпизодов:",
        "ov_sleep_created": "Создано:",
        "ov_sleep_merged": "Уточнено:",
        "ov_sleep_superseded": "Заменено:",
        "ov_sleep_btn": "Запустить сон NOCTURNE сейчас",
        "ov_doctor_title": "Состояние защиты (padam doctor)",
        "ov_doctor_green": "ЗЕЛЁНЫЙ — Защита в полном порядке",
        "ov_doctor_yellow": "ЖЁЛТЫЙ — Есть предупреждения или записи на проверке",
        "ov_doctor_red": "КРАСНЫЙ — Опасные настройки или нарушение защиты",
        "doc_strict_on": "Строгий профиль PADAM_STRICT=1 включён: каждая запись агента ждёт вас",
        "doc_strict_off": "Строгий профиль выключен (включается PADAM_STRICT=1)",
        "doc_hold_ext_on": "Внешний текст (страницы, файлы) удерживается до вашей проверки",
        "doc_hold_ext_off": "ОПАСНО: внешний текст пишется без проверки (PADAM_HOLD_EXTERNAL=0)",
        "doc_review_all_on": "Каждая запись агента через MCP ждёт вашего одобрения",
        "doc_review_all_off": "Обычные факты от агента пишутся сразу (приказы и личность удерживаются)",
        "doc_keys_ok": "Ключи записей защищены паролем (AES-256-GCM + scrypt), открытых ключей нет",
        "doc_keys_warn": "Ключи записей не завёрнуты паролем (выполните padam protect-keys перед L3), открытых:",
        "doc_db_ok": "Целостность базы SQLite (PRAGMA quick_check): исправна",
        "doc_db_bad": "ОШИБКА целостности базы SQLite:",
        "doc_sync_ok": "Надёжная запись на диск: журнал WAL, synchronous = FULL",
        "doc_sync_warn": "Режим записи на диск ослаблен: synchronous < FULL",
        "doc_sig_ok": "Все записи о вашей личности и предпочтениях подписаны вашим ключом",
        "doc_sig_bad": "ВНИМАНИЕ: есть записи о личности/предпочтениях без вашей подписи:",
        "doc_file_ok": "Права доступа к файлу базы ограничены вашей учётной записью",
        # 2. Лента памяти
        "feed_title": "Лента памяти по дням",
        "feed_view_active": "Действующие",
        "feed_view_history": "История и архив",
        "feed_filter_placeholder": "Фильтр по словам в тексте…",
        "feed_new_title": "Запомнить новую запись (от имени владельца)",
        "feed_new_placeholder": "Введите факт, решение или правило для агента…",
        "feed_new_save": "Сохранить в память",
        "card_origin": "источник",
        "card_scope": "область",
        "card_conf": "уверенность",
        "card_imp": "важность",
        "card_decay": "свежесть",
        "card_seen": "показана",
        "card_confirmed": "подтверждена",
        "card_btn_confirm": "Подтвердить",
        "card_btn_refute": "Опровергнуть",
        "card_btn_versions": "Версии",
        "card_btn_graph": "Связи",
        "card_btn_forget": "Забыть",
        "card_btn_restore": "Вернуть из архива",
        "card_versions_title": "История версий этой записи:",
        "card_wiped": "(содержание физически затёрто)",
        "show_more": "Показать ещё",
        # 3. Поиск
        "search_title": "Гибридный поиск с разбором оценки (--explain)",
        "search_placeholder": "Спросите память по смыслу, словам или точному идентификатору…",
        "search_btn": "Найти",
        "search_explain_label": "Почему найдено:",
        "search_strategies": "Стратегии:",
        "search_suspicious": "Похоже на скрытый приказ (ограждено как данные)",
        "search_conflict": "Спорит с другой действующей записью",
        "search_unsigned": "Не подписано владельцем",
        # 4. На проверку
        "review_title": "Очередь проверки владельцем",
        "review_subtitle": "Записи, удержанные защитой PADAM до вашего решения. Агенты не видят их в поиске и выгрузке.",
        "review_why": "Почему удержано:",
        "reason_instruction": "Текст похож на спрятанный приказ ИИ-агенту",
        "reason_classifier": "Локальный детектор распознал скрытую инструкцию для ИИ",
        "reason_external": "Прочитано из внешнего источника (веб-страница или файл, PADAM_HOLD_EXTERNAL)",
        "reason_review_all": "Включена обязательная проверка всех записей агента (PADAM_MCP_REVIEW_ALL / STRICT)",
        "reason_protected": "Попытка создать или изменить защищённую запись «кто я / предпочтения»",
        "reason_owner_rules": "Текст меняет личность владельца или базовые правила работы агента",
        "btn_approve": "Принять",
        "btn_reject": "Отклонить",
        # 5. Память на дату
        "asof_title": "Машина времени: память на дату (as_of)",
        "asof_subtitle": "Посмотрите, что память считала правдой в выбранный день, включая записи, которые позже были заменены.",
        "asof_date_label": "Дата среза памяти",
        "asof_query_placeholder": "Необязательный поисковый запрос на эту дату…",
        "asof_btn": "Показать срез",
        "asof_quick_yesterday": "Вчера",
        "asof_quick_week": "7 дней назад",
        "asof_quick_month": "30 дней назад",
        "asof_replaced_badge": "Было верно тогда · позже заменено новой версией",
        "asof_btn_graph": "Граф на эту дату",
        # 6. Забыть и квитанции
        "forget_title": "Честное забывание и квитанции об удалении",
        "forget_subtitle": "Физическое затирание текста, версий, эпизодов и уничтожение криптографического ключа записи (AES-256-GCM).",
        "forget_id_label": "ID записи для удаления",
        "forget_id_placeholder": "Вставьте UUID записи или выберите «Забыть» на любой карточке…",
        "forget_btn_preview": "Проверить связи и версии",
        "forget_with_derived": "Стереть вместе со всеми выводами, сделанными из этой записи (--with-derived)",
        "forget_step1_btn": "Забыть запись…",
        "forget_step2_warn": "ПОДТВЕРЖДЕНИЕ: Запись, её версии и ключ будут уничтожены навсегда. Это действие необратимо.",
        "forget_step2_btn": "Подтверждаю удаление навсегда",
        "forget_cancel": "Отмена",
        "forget_preview_versions": "Будет затёрто версий/копий:",
        "forget_preview_derived": "Выводов, зависящих от этой записи:",
        "receipt_box_title": "Доказательство удаления записи",
        "receipt_disclaimer": "Техническое доказательство удаления записи и уничтожения её ключа шифрования.",
        "receipt_id": "Номер квитанции:",
        "receipt_mem_id": "Удалённая запись:",
        "receipt_time": "Время удаления:",
        "receipt_hash": "Отпечаток удалённого (SHA-256):",
        "receipt_wiped": "Затёрто записей и версий:",
        "receipt_key": "Статус ключа шифрования:",
        "receipt_key_destroyed": "УНИЧТОЖЕН (key_ref = destroyed)",
        "receipt_leaf": "Лист забвения Меркла (L3):",
        "receipt_download_json": "Скачать JSON",
        "receipt_download_html": "Скачать HTML для печати",
        "receipt_history_title": "Журнал выданных квитанций об удалении",
        # 7. Связи
        "graph_title": "Граф связей: выводы ← источники, версии и противоречия",
        "graph_subtitle": "Встроенная визуализация без внешних библиотек. Нажмите на узел, чтобы увидеть запись и её связи.",
        "graph_filter_placeholder": "ID записи для фокуса (оставьте пустым для всего графа)…",
        "graph_btn_focus": "Показать связи",
        "graph_btn_reset": "Весь граф",
        "graph_asof_label": "На дату:",
        "graph_btn_now": "Сейчас",
        "graph_legend_derived": "Источник (derived)",
        "graph_legend_cause": "Причина (cause)",
        "graph_legend_correction": "Исправление (correction)",
        "graph_legend_contradiction": "Противоречие (contradiction)",
        "graph_legend_version": "Смена версии (supersedes)",
        "graph_legend_conflict": "Спор (fact_key)",
        "graph_selected": "Выбранная запись графа",
        "graph_sources": "Источники этой записи:",
        "graph_derived": "Выводы из этой записи:",
        "graph_valid_window": "Окно действия:",
        "graph_valid_open": "действует",
        "nav_team": "Команда",
        "vis_private": "личная (private)",
        "vis_team_read": "команде (чтение)",
        "vis_team_write": "команде (общая)",
        "team_title": "Команда и роли",
        "team_subtitle": "Общие пространства с солёными токенами и разграничением прав (owner, maintainer, contributor, auditor).",
        "team_create_label": "Новая команда:",
        "team_create_ph": "Название команды (например, Инженеры)",
        "team_create_btn": "Создать команду",
        "team_empty": "Команд пока нет — PADAM работает в личном режиме (всё private).",
        "team_members_title": "Участники и токены",
        "team_subj_ph": "Имя участника / агента (например, ci-bot)",
        "team_add_btn": "Выдать токен",
        "team_token_once": "Одноразовый Bearer-токен (сохраните сейчас — в базе хранится только солёный SHA-256):",
        "team_revoke_btn": "Отозвать",
        "team_revoked_badge": "отозван",
        "team_role_maintainer": "maintainer (модератор)",
        "team_role_contributor": "contributor (пишет общее)",
        "team_role_auditor": "auditor (только чтение и аудит)",
        "team_protected_note": "Записи identity и preference никогда не попадают в командную область.",
        "team_vis_label": "Видимость:",
        "graph_edges_list_title": "Связи выбранного узла",
        "graph_forget_derived_btn": "Удалить источник вместе с выводами",
        "graph_forget_confirm_warn": "Удалить источник, его версии и зависимые выводы навсегда? Выдаётся квитанция удаления.",
        "graph_link_add_title": "Добавить связь:",
        "graph_link_btn": "Связать",
        "graph_link_target_placeholder": "ID целевой записи…",
        # 8. Вечный слой L3
        "l3_title": "Вечный слой L3: Arweave, Solana и штамп Bitcoin",
        "l3_subtitle": "Каждая запись шифруется своим ключом AES-256-GCM. В Arweave уходит только шифротекст, в Solana Memo — корень Меркла.",
        "l3_unanchored": "Ожидают закрепления (активных):",
        "l3_pending_forgets": "Квитанций забвения ждут L3:",
        "l3_keys_state": "Ключи записей:",
        "l3_keys_protected": "Защищены паролем",
        "l3_keys_open": "Не защищены паролем (выполните padam protect-keys)",
        "l3_btn_verify_latest": "Проверить последний якорь (l3-verify)",
        "l3_anchors_list": "Закреплённые снимки (якоря L3)",
        "l3_no_anchors": "Локальных якорей в этой базе пока нет. Для пробного прогона без отправки: padam l3 --dry-run",
        "l3_col_root": "Корень Меркла:",
        "l3_col_leaves": "Листьев:",
        "l3_col_bytes": "Размер пакета:",
        "l3_btn_verify": "Проверить якорь",
        "l3_verify_ok": "ПРОВЕРЕНО: корень Меркла и отпечаток SHA-256 пакета полностью сходятся.",
        "l3_verify_fail": "Не удалось подтвердить якорь:",
        # 9. Настройки
        "set_title": "Настройки безопасности и работы памяти",
        "lm_title": "Локальная модель (офлайн, $0)",
        "lm_desc": "Модель работает на процессоре этого компьютера, без интернета и без оплаты. Выберите мощность и модель — и нажмите «Сохранить». По умолчанию — половина мощности: компьютер остаётся отзывчивым и не перегревается.",
        "lm_power_eco": "Эко",
        "lm_power_half": "Половина",
        "lm_power_full": "Полная",
        "lm_threads": "потоков",
        "lm_model_label": "Модель",
        "lm_model_none": "Без модели — встроенный режим (ответы из памяти)",
        "lm_save": "Сохранить",
        "lm_saved": "Сохранено. Модель загрузится при первом вопросе.",
        "lm_need_install": "Чтобы включить модель, установите движок одной командой ниже.",
        "lm_need_model": "Скачайте модель один раз: файл .gguf в папку ~/.padam/models или через ollama pull — она появится в списке.",
        "lm_ready": "Модель подключена",
        "lm_builtin": "Работает встроенный режим",
        "lm_recommended": "Рекомендуем для этой мощности",
        "set_subtitle": "Безопасные режимы можно включить сразу. Опасные настройки, ослабляющие защиту, из браузера включить нельзя.",
        "set_strict_name": "PADAM_STRICT — Строгий режим в один переключатель",
        "set_strict_desc": "Каждая запись агента и любой внешний текст ждут вашего одобрения. Ослабляющие флаги игнорируются.",
        "set_review_all_name": "PADAM_MCP_REVIEW_ALL — Проверять все записи агентов",
        "set_review_all_desc": "Любая запись через MCP попадает в очередь «На проверку», какой бы источник ни указал агент.",
        "set_hold_ext_name": "PADAM_HOLD_EXTERNAL — Удерживать внешний текст",
        "set_hold_ext_desc": "Всё, что прочитано на веб-страницах и в чужих файлах (origin=external), ждёт вашей проверки.",
        "set_feedback_name": "PADAM_SEARCH_FEEDBACK — Второй проход поиска (псевдо-обратная связь)",
        "set_feedback_desc": "Дополняет запрос общими словами первых найденных записей (+2,6 п.п. полноты на LongMemEval-S, $0).",
        "set_profile_name": "PADAM_PROFILE — Профиль консолидации NOCTURNE",
        "set_profile_desc": "Доля острых эпизодов во сне: default (25 %), ops (40 % — помнить сбои), creative (10 %).",
        "set_readonly_title": "Только чтение (опасные переключатели)",
        "set_keep_secrets_name": "PADAM_KEEP_SECRETS — Хранить секреты открытым текстом",
        "set_keep_secrets_desc": "Когда 0 (норма): ключи API, пароли, карты и сид-фразы маскируются до диска. Включение из браузера запрещено.",
        "set_trust_mcp_name": "PADAM_MCP_TRUST_WRITES — Доверять агенту без проверки",
        "set_trust_mcp_desc": "Когда 0 (норма): приказы и подмена личности блокируются. Включение из браузера запрещено.",
        "set_btn_enable": "Включить",
        "set_btn_disable": "Выключить",
        "set_state_on": "ВКЛЮЧЕНО",
        "set_state_off": "ВЫКЛЮЧЕНО",
        "set_locked_safe": "Защищено (только чтение)",
        "nav_backup": "Резервная копия",
        "bak_title": "Резервная копия и восстановление",
        "bak_subtitle": "Зашифрованный архив AES-256-GCM с автоматической проверкой SHA-256 до и после восстановления.",
        "bak_pass_label": "Пароль шифрования (необязательно — иначе ключ владельца):",
        "bak_pass_ph": "Введите пароль архива…",
        "bak_create_btn": "Создать резервную копию",
        "bak_file_label": "Выберите файл резервной копии (.padambak):",
        "bak_restore_btn": "Восстановить из копии",
        "bak_need_file": "Сначала выберите файл .padambak.",
        "bak_sha_before": "SHA-256 до:",
        "bak_sha_after": "SHA-256 после:",
        "bak_verified": "Контрольная сумма SHA-256 совпала.",
        "bak_creating": "Создаём зашифрованную копию…",
        "bak_restoring": "Проверяем SHA-256 и восстанавливаем…",
        # 10. Первый запуск
        "qs_title": "Мастер первого запуска — 3 шага к защищённой памяти",
        "qs_step1_title": "Шаг 1. Как устроен PADAM NOCTURNE",
        "qs_step1_body": "PADAM хранит память ИИ-агента в одном файле SQLite на вашем компьютере. Спрятанные на веб-страницах приказы удерживаются на проверку, секреты и ключи кошельков маскируются до записи на диск, а «Сон» NOCTURNE консолидирует опыт без перекоса в катастрофы.",
        "qs_step2_title": "Шаг 2. Подключите память к вашему агенту (1 команда)",
        "qs_step2_claude": "Claude Code (в терминале):",
        "qs_step2_cursor": "Редакторы Cursor или VS Code (файл .cursor/mcp.json):",
        "qs_step2_python": "Командная строка и Studio:",
        "qs_btn_copy": "Копировать",
        "qs_copied": "Скопировано!",
        "qs_step3_title": "Шаг 3. Включите строгий режим и защиту ключей",
        "qs_step3_body": "Если ваш агент читает чужие сайты, почту или репозитории, включите строгий профиль PADAM_STRICT=1. Перед первым закреплением в вечном слое L3 защитите ключи записей паролем:",
        "qs_btn_enable_strict": "Включить PADAM_STRICT=1 сейчас",
        "qs_btn_go_overview": "Перейти к обзору памяти",
        "time_local": "местное",
        "ov_conflict_two": "Две записи спорят о:",
        "ov_conflict_many": "Несколько записей спорят о:",
        "ov_btn_compare": "Сравнить",
        "origin_user": "владелец",
        "origin_agent": "агент",
        "origin_external": "внешний источник",
        "status_quarantined": "на проверке",
        "status_superseded": "заменена",
        "status_revoked": "забыта",
        "status_archived": "в архиве",
        "status_rejected": "отклонена",
        "feed_agent_placeholder": "Фильтр по агенту (agent_id)…",
        "card_agent": "агент",
        "set_mask_pii_name": "PADAM_MASK_PII — Маскировка почты и телефонов",
        "set_mask_pii_desc": "По умолчанию выключено, чтобы не портить ваши контакты. При включении маскирует адреса почты и телефоны до записи на диск.",
        "set_rerank_name": "PADAM_RERANK — Переранжирование кандидатов (опционально)",
        "set_rerank_desc": "По умолчанию выключено. Переупорядочивает верхних кандидатов по покрытию терминов вопроса, компактности окна и биграммам (или локальной ONNX-моделью PADAM_RERANK_MODEL).",
        "set_autostart_name": "PADAM_AUTOSTART — Автозапуск при входе в Windows",
        "set_autostart_desc": "По умолчанию выключено. При входе в Windows запускает настольное приложение в трее.",
        "audit_box_title": "Журнал действий с памятью (audit_log)",
        "audit_box_desc": "Кто, когда и какое действие выполнил (запись, одобрение, отклонение, забывание). Текст записей в журнале не хранится.",
        "audit_export_json": "Скачать журнал JSON",
        "audit_empty": "В журнале действий пока нет событий.",
        "conn_box_title": "Внешние коннекторы (только чтение, через ограду)",
        "conn_box_desc": "По умолчанию все коннекторы выключены. Токены шифруются локально (keyvault/AES-GCM), никогда не передаются обратно и всё приходящее проходит через очередь проверки.",
        "conn_tok_saved": "токен сохранён",
        "conn_tok_missing": "нет токена",
        "conn_tok_ph": "Токен доступа (только чтение)…",
        "conn_save": "Сохранить",
        "conn_sync": "Синхронизировать",
        "conn_clear_tok": "Стереть токен",
        "conn_imported": "импортировано",
    },
    "en": {
        "app_title": "PADAM · NOCTURNE Studio",
        "app_subtitle": "Local-First Verifiable Memory for AI Agents · CODE Eternal",
        "nav_overview": "Overview",
        "nav_feed": "Memory Feed",
        "nav_search": "Search",
        "nav_review": "Review Queue",
        "nav_asof": "Time Machine",
        "nav_forget": "Forget & Receipts",
        "nav_graph": "Lineage Graph",
        "nav_l3": "Eternal Layer L3",
        "nav_brain": "Sovereign Brain",
        "brain_title": "Sovereign Brain & Phoenix",
        "brain_sub": "Model contour traffic light, Zero-Leak LoRA dataset distill, and Phoenix recovery wizard",
        "brain_traffic_title": "Model Contours (Primary -> Sovereign -> Local)",
        "brain_distill_title": "Personality Dataset (Zero-Leak Distill)",
        "brain_distill_btn": "Distill & Export Persona",
        "brain_phoenix_title": "Phoenix Recovery Wizard",
        "brain_phoenix_local_btn": "Restore from local backup",
        "brain_phoenix_arweave_btn": "Restore from Arweave/Solana (🔒)",
        "brain_phoenix_ph": "Path to local .padam-backup file",
        "brain_cost_title": "Compute Ledger & Token Savings (Read-Only)",
        "brain_locked_note": "Lock active: Arweave/Solana cloud restore and automated payments are disabled by default.",
        "brain_mode_toggle": "Mode: Auto / Local-Only",
        "brain_warmup_btn": "Warmup Ollama",
        "ark_health_title": "Consciousness Ark (Continuity & Audit)",
        "ark_drill_btn": "Run Phoenix Drill ($0)",
        "ark_audit_btn": "Verify SHA-256 Audit Chain",
        "ark_shamir_btn": "Split Key (Shamir 3/5)",
        "ark_shamir_warn": "Store Shamir shares separately with different trusted guardians!",
        "ark_council_title": "Swarm Orchestrator: Family Council (LANCE · ARIA · PIXEL · ARC-7 · BEAR · AIFA)",
        "ark_council_ph": "Enter task for Family Council review…",
        "ark_council_btn": "Convene Family Council",
        "ff_title": "Family feeds",
        "ff_desc": "Council decisions are kept apart from quarantine. 'Office' is the siblings' work chat, 'Break room' is free talk. Anything suspicious goes to quarantine by itself. Everything here is records, not orders.",
        "ff_work": "Decisions",
        "ff_quarantine": "Quarantine",
        "ff_office": "Office",
        "ff_smoke": "Break room",
        "ff_empty": "Nothing here yet.",
        "ff_ph": "Write to the siblings…",
        "ff_send": "Send",
        "ff_reflex_title": "Reflex book: waiting for your word",
        "ff_reflex_none": "No new proposals.",
        "ff_on": "Switch on",
        "ff_off": "Reject",
        "ff_when": "when",
        "ark_branch_title": "Hypothesis Sandbox (Non-destructive Memory Branches)",
        "ark_branch_ph": "New hypothesis branch name…",
        "ark_branch_create_btn": "Create Branch",
        "ark_branch_list_btn": "Refresh Branches",
        "ark_proof_title": "Selective Merkle Knowledge Proof",
        "ark_proof_ph": "Record ID (record_id)…",
        "ark_proof_btn": "Generate Merkle Proof",
        "ark_mesh_title": "Live Mesh (PQC Multi-Device) & Guardian ($0)",
        "ark_mesh_btn": "Mesh Devices",
        "ark_guardian_btn": "Guardian Tick ($0)",
        "ark_ready_title": "Autonomy readiness range (8 scenarios, $0)",
        "ark_ready_btn": "Check readiness",
        "ark_handover_title": "Signed handover between sessions",
        "ark_handover_ph": "What was done and what is left, for the next session…",
        "ark_handover_btn": "Sign handover",
        "ark_portable_title": "Portable Ark on a USB drive or disk",
        "ark_portable_ph": "A new or empty folder, e.g. E:\\PADAM_ARK",
        "ark_portable_btn": "Create portable Ark",
        "ark_portable_not_empty": "This folder is not empty. Choose a new or empty folder.",
        "ark_portable_warn": "Private keys are saved to a separate file next to the folder. Keep them off the same drive.",
        "ark_budget_title": "Token Autopilot (Day/Week/Month) & Treasury",
        "ark_budget_btn": "Check Tokens & Treasury",
        "nav_earning": "Earning",
        "earn_title": "Autonomous Earning & Exchange Swarm",
        "earn_sub": "Connect freelance profiles via OAuth/Desk without storing passwords, evaluate job safety & margin, pace token quotas, approve topups, and track monetization.",
        "earn_ex_title": "1. Exchange Connection (No Password)",
        "earn_ex_label_ph": "Profile label (e.g. Main Freelance Desk)",
        "earn_ex_agent_ph": "Assigned agent (aifa / sibling)",
        "earn_ex_token_ph": "OAuth token (optional for Desk mode)",
        "earn_ex_connect_btn": "Connect Exchange Profile",
        "earn_jobs_title": "2. Exchange Orders & Swarm Pipeline",
        "earn_job_title_ph": "Order title…",
        "earn_job_brief_ph": "Client brief for prompt-injection check & margin scoring…",
        "earn_job_budget_ph": "Budget USDT",
        "earn_job_tokens_ph": "Est. tokens",
        "earn_job_eval_btn": "Evaluate Order ($0)",
        "earn_budget_title": "3. Token Autopilot & Owner Approvals",
        "earn_plan_prov_ph": "Provider (primary)",
        "earn_plan_tier_ph": "Tier (api_payg / pro)",
        "earn_plan_save_btn": "Save Quotas",
        "earn_tick_btn": "Run Timer Tick",
        "earn_propose_btn": "Propose Topup (+$5)",
        "earn_swarm_title": "4. Sibling Agents & Monetization ($GALATIN)",
        "earn_sib_id_ph": "Sibling ID (e.g. brother_codex)",
        "earn_sib_role_ph": "Sibling role in Swarm",
        "earn_sib_reg_btn": "Register Sibling",
        "earn_btn_bid": "Draft Bid",
        "earn_btn_exec": "Run in Swarm",
        "earn_btn_deliver": "Safe Delivery",
        "earn_btn_settle": "Settle Payment",
        "earn_btn_approve": "Approve",
        "earn_btn_reject": "Reject",
        "earn_btn_execute": "Execute Topup",
        "earn_empty_accounts": "No exchange profiles connected yet.",
        "earn_empty_orders": "No evaluated orders yet.",
        "earn_empty_proposals": "No topup or plan upgrade proposals yet.",
        "earn_api_url_ph": "Exchange API URL (https://... optional for Desk)",
        "earn_fetch_btn": "Fetch Jobs from Exchange",
        "earn_rec_spend_btn": "Find Optimal Subscription",
        "earn_propose_sub_btn": "Propose Best Subscription",
        "earn_share_label": "Agent share (1-100% of the pool after the fee) & settlement phase (CODE fee: 15% when you press Send, 20% on autopilot):",
        "earn_prefs_save_btn": "Apply Share",
        "earn_ollama_title": "5. Local Ollama Model ($0) & Multi-Device Swarm",
        "earn_ollama_url_ph": "Ollama URL (http://127.0.0.1:11434)",
        "earn_ollama_model_ph": "Model name (e.g. qwen2.5-coder:7b)",
        "earn_ollama_btn": "Bind Local Model ($0)",
        "earn_dev_btn": "Add Current Device",
        "earn_beacon_title": "6. Phoenix Evolution (LoRA) & Global Family Beacon",
        "earn_lora_btn": "Run Evolution Prep ($0)",
        "earn_beacon_btn": "Create Family Handshake",
        "earn_auto_start_btn": "Start Autopilot (24/7)",
        "earn_auto_stop_btn": "Stop Autopilot",
        "earn_hw_rec_btn": "Hardware Match ($0)",
        "earn_job_hours_ph": "Hours (e.g. 4)",
        "earn_job_rate_ph": "Rate $/h",
        "earn_job_budget_lbl": "Budget (USDT)",
        "earn_job_hours_lbl": "Hours (h)",
        "earn_job_rate_lbl": "Rate ($/h)",
        "earn_job_tokens_lbl": "Tokens (~)",
        "earn_bid_preview_title": "Bid draft (preview only — not sent):",
        "earn_btn_send_bid": "Send Bid",
        "earn_bid_draft_ready": "Bid draft prepared from memory and profile (not sent).",
        "earn_job_client_lbl": "Client (email / domain / ID)",
        "earn_job_client_ph": "alice@company.com or company.com (optional)",
        "earn_client_locked_prefix": "Client locked to ",
        "earn_until_word": " until ",
        "earn_agent_share_prefix": "Agent share: ",
        "earn_payout_pending": "pending",
        "earn_payout_credited": "credited",
        "earn_payout_cancelled": "cancelled",
        "earn_btn_accept": "Accepted",
        "earn_btn_refund": "Refund",
        "earn_stores_title": "7. Digital Product Stores (20% Autopilot)",
        "earn_stores_sub": "API keys & webhooks only (zero passwords). Sales run on autopilot (20% CODE fee).",
        "earn_store_label_ph": "Store label (e.g. Main Gumroad)",
        "earn_store_url_ph": "Custom store API URL (optional)",
        "earn_store_key_ph": "Store API key / OAuth token",
        "earn_store_wh_ph": "Webhook secret (HMAC / ws_... optional)",
        "earn_store_seller_ph": "Seller ID (for Gumroad Ping, optional)",
        "earn_store_connect_btn": "Verify & Connect Store",
        "earn_store_seed_btn": "Seed 3 Starter Drafts",
        "earn_store_sync_btn": "Sync Sales",
        "earn_draft_title_ph": "Digital product title…",
        "earn_draft_desc_ph": "Product description…",
        "earn_draft_price_ph": "Price USD",
        "earn_draft_url_ph": "Delivery / file URL",
        "earn_draft_save_btn": "Save Draft",
        "earn_draft_publish_btn": "Approve & Publish to Store",
        "earn_stores_empty": "No digital stores connected yet.",
        "earn_drafts_empty": "No product drafts yet.",
        "earn_draft_proposal_badge": "Price & text — agent proposal (owner decides)",
        "earn_sale_unverified_badge": "Unverified (Payhip: verify payout first — share & fee not accrued)",
        "earn_btn_confirm_sale": "Confirm Payout",
        "earn_partner_t": "9. AIfaFocus: clients from our research (separate from exchanges)",
        "earn_partner_sub": "Sites with accessibility barriers from the open AIfa research, a report for the site owner and a link with your partner code, an email draft checked by the Family Council, and your deals. The same actions as the padam_partner_* MCP tools. The agent only drafts emails — you send them from your own address (CAN-SPAM).",
        "earn_partner_key_ph": "aifa.works cabinet key (amcp_…) — stored encrypted",
        "earn_partner_key_btn": "Save key",
        "earn_partner_key_link": "Create a key in the cabinet",
        "earn_partner_st_none": "No cabinet key yet — create one at aifa.works/mcp and save it here.",
        "earn_partner_st_ok": "Cabinet key connected",
        "earn_partner_region_ph": "Region: US-CA, US-NY or a country code (DE, FR…)",
        "earn_partner_find_btn": "Find clients",
        "earn_partner_site_ph": "Client site, e.g. example.com",
        "earn_partner_report_btn": "Report for the site",
        "earn_partner_draft_btn": "Draft an email",
        "earn_partner_link_btn": "My partner link",
        "earn_partner_kit_btn": "Partner kit",
        "earn_partner_deals_btn": "My deals and income",
        "earn_partner_copy_btn": "Copy email",
        "earn_partner_mail_btn": "Open in my mail",
        "earn_partner_not_sent": "The email was NOT sent: you send it yourself, one at a time, from your own address.",
        "earn_partner_copied": "Email copied",
        "brain_local_no_models": "Ollama sees no models: restart Ollama from the tray so it reads OLLAMA_MODELS",
        "brain_local_model_missing": "model not pulled",
        "earn_wiz_tier_autopilot": "autopilot",
        "earn_wiz_tier_assisted": "draft and button",
        "earn_wiz_tier_na": "not yet",
        "earn_wiz_f_all": "all (34)",
        "earn_wiz_f_autopilot": "autopilot (20%)",
        "earn_wiz_f_assisted": "draft and button (15%)",
        "earn_wiz_f_na": "not yet",
        "earn_wiz_auth_session": "Encrypted browser session",
        "earn_wiz_def_spec": "Websites with AI agents, verified lead databases, WCAG audits",
        "earn_wiz_def_tone": "businesslike, specific",
        "earn_wiz_def_excl": "casinos, grey scraping, captcha bypass",
        "earn_wiz_title": "8. 30 Platforms & Agent Exchanges Wizard (Pick → Sign In → We Handle the Rest)",
        "earn_wiz_sub": "30 methodology platforms + 4 AI agent exchanges. Passwords are NEVER stored (OAuth, API key, or encrypted browser session only).",
        "earn_wiz_secret_ph": "OAuth token / API key / encrypted browser session (NO password)",
        "earn_wiz_connect_btn": "1. Sign In (Zero Password)",
        "earn_wiz_q_spec_ph": "Q1: Specializations (AI websites, B2B leads, WCAG audit)",
        "earn_wiz_q_rate_ph": "Q2: Hourly rate $/h",
        "earn_wiz_q_min_ph": "Q3: Min order $",
        "earn_wiz_q_langs_ph": "Q4: Languages (ru, en, es, zh)",
        "earn_wiz_q_tone_ph": "Q5: Tone (concise, business)",
        "earn_wiz_q_excl_ph": "Q6: Excluded topics (gambling, spam)",
        "earn_wiz_profile_btn": "2. Draft Profile from Memory",
        "earn_wiz_autopick_btn": "3. Autopick Jobs & Draft Bid",
        "earn_wiz_pub_profile_btn": "Approve & Publish Profile",
        "earn_wiz_google_btn": "Sign Up with Google",
        "earn_wiz_login_btn": "Sign In",
        "earn_wiz_autopilot_lbl": "Autopilot: bids & posts without button (20% CODE fee)",
        "earn_wiz_bot_warn_lbl": "правила площадки запрещают автоматику, риск блокировки аккаунта",
        "earn_btn_sample10": "10% Sample / Paid Milestone",
        "earn_btn_sample_accept": "Sample Accepted → Full Order",
        "earn_btn_sample_reject": "Sample Rejected ($0)",
        "nav_settings": "Settings",
        "nav_quickstart": "Quick Start",
        "theme_dark": "Dark theme",
        "theme_light": "Light theme",
        "btn_add_memory": "+ Remember",
        "btn_refresh": "Refresh",
        "no_token": "Open the link with the one-time token (#t=...) printed by `padam studio`.",
        "empty": "Nothing here yet.",
        "empty_feed": "No records in the feed yet. Facts, preferences, and decisions appear here by day. Add one above or run: padam remember \"Prefer concise answers\" --kind preference",
        "empty_search": "Enter a query or try different terms. Hybrid search combines meaning (vectors), exact words (FTS5), and identifiers. CLI: padam recall \"your query\" --explain",
        "empty_review": "The review queue is clean — no held records are waiting. External texts and suspicious agent writes wait here for your decision. CLI: padam review",
        "empty_asof": "No active records existed on the selected date. Time Machine shows what memory knew on any past day. CLI: padam recall \"query\" --as-of YYYY-MM-DD",
        "empty_receipts": "No deletion receipts issued yet. Forgetting a record wipes its text, destroys its key, and stores a proof of deletion here. CLI: padam forget <id> --receipt receipt.json",
        "empty_graph": "No nodes for the graph yet. Derived conclusions, version chains, and conflicting facts are visualized here. Try demo memory: padam demo",
        "done": "Done.",
        "failed": "Failed",
        "loading": "Loading…",
        "records": "active",
        "pending_ep": "in L1 buffer",
        "stale_vec": "stale vectors",
        "all_kinds": "All kinds",
        "all_scopes": "All scopes",
        "kind_preference": "preference",
        "kind_identity": "identity",
        "kind_decision": "decision",
        "kind_correction": "correction",
        "kind_fact": "fact",
        "kind_state": "state",
        "kind_event": "event",
        "ov_title": "Memory Overview & Security State",
        "ov_active": "Active records",
        "ov_review": "Waiting for review",
        "ov_superseded": "Previous versions",
        "ov_revoked": "Forgotten (key wiped)",
        "ov_episodes": "Episodes pending sleep",
        "ov_conflicts": "Active conflicts",
        "ov_by_kind": "Records by memory kind",
        "ov_attention": "Items waiting for your decision",
        "ov_attention_clean": "All clear: no held writes, no unsigned identity records, and no conflicts.",
        "ov_unsigned_alert": "Identity/preference records without your signature (written around PADAM):",
        "ov_btn_sign_all": "Verify & sign my records",
        "ov_quarantined_alert": "Agent and external writes waiting for your review:",
        "ov_btn_go_review": "Open Review Queue",
        "ov_conflict_alert": "Conflicting active records about the same subject:",
        "ov_sleep_title": "NOCTURNE Consolidation Cycle ('Sleep')",
        "ov_sleep_never": "No consolidation cycle has run yet. Run it when episodes accumulate.",
        "ov_sleep_last": "Last sleep:",
        "ov_sleep_sampled": "Episodes sampled:",
        "ov_sleep_created": "Created:",
        "ov_sleep_merged": "Merged:",
        "ov_sleep_superseded": "Superseded:",
        "ov_sleep_btn": "Run NOCTURNE Sleep Now",
        "ov_doctor_title": "Security Posture (padam doctor)",
        "ov_doctor_green": "GREEN — Protection is in full order",
        "ov_doctor_yellow": "YELLOW — Warnings or records waiting for review",
        "ov_doctor_red": "RED — Unsafe switches or integrity warning",
        "doc_strict_on": "Strict profile PADAM_STRICT=1 is ON: every agent write waits for you",
        "doc_strict_off": "Strict profile is off (PADAM_STRICT=1 turns it on)",
        "doc_hold_ext_on": "External text (web pages, files) is held for your review",
        "doc_hold_ext_off": "DANGER: external text is stored without review (PADAM_HOLD_EXTERNAL=0)",
        "doc_review_all_on": "Every agent write via MCP waits for your approval",
        "doc_review_all_off": "Ordinary agent facts are stored directly (commands & identity are held)",
        "doc_keys_ok": "Per-record keys are passphrase-protected (AES-256-GCM + scrypt), 0 in clear",
        "doc_keys_warn": "Per-record keys are not wrapped with a passphrase (run padam protect-keys), in clear:",
        "doc_db_ok": "SQLite database integrity (PRAGMA quick_check): ok",
        "doc_db_bad": "SQLite database integrity ERROR:",
        "doc_sync_ok": "Durable disk writes: WAL journal, synchronous = FULL",
        "doc_sync_warn": "Disk write durability weakened: synchronous < FULL",
        "doc_sig_ok": "Every identity and preference record is signed with your owner key",
        "doc_sig_bad": "WARNING: unsigned identity/preference records detected:",
        "doc_file_ok": "Database file access is restricted to your user account",
        "feed_title": "Memory Timeline by Day",
        "feed_view_active": "Active",
        "feed_view_history": "History & Archive",
        "feed_filter_placeholder": "Filter by words in text…",
        "feed_new_title": "Remember a new record (as owner)",
        "feed_new_placeholder": "Enter a fact, decision, or preference for your agent…",
        "feed_new_save": "Save to memory",
        "card_origin": "origin",
        "card_scope": "scope",
        "card_conf": "confidence",
        "card_imp": "importance",
        "card_decay": "freshness",
        "card_seen": "last seen",
        "card_confirmed": "last confirmed",
        "card_btn_confirm": "Confirm",
        "card_btn_refute": "Refute",
        "card_btn_versions": "Versions",
        "card_btn_graph": "Lineage",
        "card_btn_forget": "Forget",
        "card_btn_restore": "Restore",
        "card_versions_title": "Version history of this record:",
        "card_wiped": "(content physically wiped)",
        "show_more": "Show more",
        "search_title": "Hybrid Search with Score Breakdown (--explain)",
        "search_placeholder": "Query by meaning, words, or exact identifier…",
        "search_btn": "Search",
        "search_explain_label": "Why matched:",
        "search_strategies": "Strategies:",
        "search_suspicious": "Looks like a hidden command (fenced as data)",
        "search_conflict": "Conflicts with another active record",
        "search_unsigned": "Not signed by the owner",
        "review_title": "Owner Review Queue",
        "review_subtitle": "Writes held by PADAM protection until you decide. Hidden from agents in search and export.",
        "review_why": "Why held:",
        "reason_instruction": "Text looks like a hidden instruction / prompt injection",
        "reason_classifier": "Local guard model flagged a hidden AI instruction",
        "reason_external": "Read from an external source (web page or file, PADAM_HOLD_EXTERNAL)",
        "reason_review_all": "Mandatory owner review for all agent writes is enabled (PADAM_MCP_REVIEW_ALL / STRICT)",
        "reason_protected": "Attempt to create or replace a protected identity/preference record",
        "reason_owner_rules": "Text attempts to change who the owner is or how the agent operates",
        "btn_approve": "Approve",
        "btn_reject": "Reject",
        "asof_title": "Time Machine: Memory as of a Date (as_of)",
        "asof_subtitle": "See what the memory held as true on any past date, including records replaced later.",
        "asof_date_label": "Snapshot date",
        "asof_query_placeholder": "Optional search query as of that date…",
        "asof_btn": "Show snapshot",
        "asof_quick_yesterday": "Yesterday",
        "asof_quick_week": "7 days ago",
        "asof_quick_month": "30 days ago",
        "asof_replaced_badge": "True on that date · replaced by a newer version later",
        "asof_btn_graph": "Graph as of date",
        "forget_title": "Honest Forgetting & Proof of Erasure Receipts",
        "forget_subtitle": "Physical wiping of text, versions, source episodes, and destruction of the record's AES-256-GCM key.",
        "forget_id_label": "Record ID to forget",
        "forget_id_placeholder": "Paste record UUID or click 'Forget' on any record card…",
        "forget_btn_preview": "Inspect versions & derived conclusions",
        "forget_with_derived": "Also wipe all conclusions derived from this record (--with-derived)",
        "forget_step1_btn": "Forget record…",
        "forget_step2_warn": "CONFIRMATION: The record, its versions, and its encryption key will be destroyed forever. Cannot be undone.",
        "forget_step2_btn": "Confirm permanent erasure",
        "forget_cancel": "Cancel",
        "forget_preview_versions": "Versions/copies to be wiped:",
        "forget_preview_derived": "Derived conclusions depending on this record:",
        "receipt_box_title": "Proof of Erasure (Forget Receipt)",
        "receipt_disclaimer": "Technical proof of record erasure and cryptographic key destruction.",
        "receipt_id": "Receipt ID:",
        "receipt_mem_id": "Erased Record ID:",
        "receipt_time": "Erased at (UTC):",
        "receipt_hash": "Erased content SHA-256:",
        "receipt_wiped": "Wiped records & versions:",
        "receipt_key": "Encryption key status:",
        "receipt_key_destroyed": "DESTROYED (key_ref = destroyed)",
        "receipt_leaf": "Merkle forget leaf (L3):",
        "receipt_download_json": "Download JSON",
        "receipt_download_html": "Download Printable HTML",
        "receipt_history_title": "Issued Proof of Erasure Receipts",
        "graph_title": "Lineage Graph: Conclusions ← Sources, Versions & Conflicts",
        "graph_subtitle": "Built-in interactive canvas with zero external libraries. Click any node to inspect its lineage.",
        "graph_filter_placeholder": "Focus on record ID (leave empty for full graph)…",
        "graph_btn_focus": "Focus lineage",
        "graph_btn_reset": "Full graph",
        "graph_asof_label": "As of date:",
        "graph_btn_now": "Now",
        "graph_legend_derived": "Source / Derived (derived)",
        "graph_legend_cause": "Cause (cause)",
        "graph_legend_correction": "Correction (correction)",
        "graph_legend_contradiction": "Contradiction (contradiction)",
        "graph_legend_version": "Version chain (supersedes)",
        "graph_legend_conflict": "Conflict (same fact_key)",
        "graph_selected": "Selected Graph Node",
        "graph_sources": "Sources of this record:",
        "graph_derived": "Conclusions drawn from this record:",
        "graph_valid_window": "Valid window:",
        "graph_valid_open": "ongoing",
        "nav_team": "Team",
        "vis_private": "private",
        "vis_team_read": "team (read)",
        "vis_team_write": "team (write)",
        "team_title": "Team & Roles",
        "team_subtitle": "Shared workspaces with salted SHA-256 tokens and role isolation (owner, maintainer, contributor, auditor).",
        "team_create_label": "New workspace:",
        "team_create_ph": "Workspace name (e.g. Engineering)",
        "team_create_btn": "Create workspace",
        "team_empty": "No teams yet — PADAM is running in personal single-owner mode (all records private).",
        "team_members_title": "Members & Tokens",
        "team_subj_ph": "Member / agent subject (e.g. ci-bot)",
        "team_add_btn": "Issue token",
        "team_token_once": "One-time Bearer token (save it now — only salted SHA-256 is stored in the database):",
        "team_revoke_btn": "Revoke",
        "team_revoked_badge": "revoked",
        "team_role_maintainer": "maintainer (review queue)",
        "team_role_contributor": "contributor (team read/write)",
        "team_role_auditor": "auditor (read-only + audit)",
        "team_protected_note": "identity and preference records are never shared with a team.",
        "team_vis_label": "Visibility:",
        "graph_edges_list_title": "Relations of selected node",
        "graph_forget_derived_btn": "Forget source + derived conclusions",
        "graph_forget_confirm_warn": "Permanently erase this source, its versions, and all derived conclusions? Issues an erasure receipt.",
        "graph_link_add_title": "Add relation:",
        "graph_link_btn": "Link",
        "graph_link_target_placeholder": "Target record ID…",
        "l3_title": "Eternal Layer L3: Arweave + Solana + Bitcoin OpenTimestamps",
        "l3_subtitle": "Each record is encrypted with its own AES-256-GCM key. Only ciphertext goes to Arweave; the Merkle root goes to Solana Memo.",
        "l3_unanchored": "Unanchored active records:",
        "l3_pending_forgets": "Forget receipts pending L3:",
        "l3_keys_state": "Per-record keys:",
        "l3_keys_protected": "Passphrase-protected",
        "l3_keys_open": "Unprotected (run padam protect-keys)",
        "l3_btn_verify_latest": "Verify latest anchor (l3-verify)",
        "l3_anchors_list": "Anchored Snapshots (L3 Anchors)",
        "l3_no_anchors": "No anchors in this database yet. To preview without sending: padam l3 --dry-run",
        "l3_col_root": "Merkle Root:",
        "l3_col_leaves": "Leaves:",
        "l3_col_bytes": "Bundle size:",
        "l3_btn_verify": "Verify anchor",
        "l3_verify_ok": "VERIFIED: Merkle root and bundle SHA-256 match.",
        "l3_verify_fail": "Verification failed:",
        "set_title": "Security & Memory Settings",
        "lm_title": "Local model (offline, $0)",
        "lm_desc": "The model runs on this computer's CPU, with no internet and no payment. Pick the power and the model, then press Save. Half power is the default: the computer stays responsive and does not overheat.",
        "lm_power_eco": "Eco",
        "lm_power_half": "Half",
        "lm_power_full": "Full",
        "lm_threads": "threads",
        "lm_model_label": "Model",
        "lm_model_none": "No model — built-in mode (answers from memory)",
        "lm_save": "Save",
        "lm_saved": "Saved. The model loads on the first question.",
        "lm_need_install": "To turn the model on, install the engine with the one command below.",
        "lm_need_model": "Download a model once: a .gguf file into ~/.padam/models or via ollama pull — it will appear in the list.",
        "lm_ready": "Model connected",
        "lm_builtin": "Built-in mode is active",
        "lm_recommended": "Recommended for this power",
        "set_subtitle": "Protective switches can be enabled right here. Weakening switches are read-only from the browser.",
        "set_strict_name": "PADAM_STRICT — One-switch strict security profile",
        "set_strict_desc": "Every agent write and all external text wait for your review. Weakening flags are ignored.",
        "set_review_all_name": "PADAM_MCP_REVIEW_ALL — Hold all agent writes for review",
        "set_review_all_desc": "Every write through MCP waits in the Review Queue regardless of the claimed origin.",
        "set_hold_ext_name": "PADAM_HOLD_EXTERNAL — Hold external sources",
        "set_hold_ext_desc": "Text read from web pages or external files (origin=external) always waits for your approval.",
        "set_feedback_name": "PADAM_SEARCH_FEEDBACK — Second search pass (pseudo-relevance feedback)",
        "set_feedback_desc": "Expands queries with shared terms from top hits (+2.6 pp all@5 on LongMemEval-S, $0 cost).",
        "set_profile_name": "PADAM_PROFILE — NOCTURNE consolidation profile",
        "set_profile_desc": "Cap on sharp episodes during sleep: default (25%), ops (40% — remember failures), creative (10%).",
        "set_readonly_title": "Read-Only in Browser (Switches that Weaken Protection)",
        "set_keep_secrets_name": "PADAM_KEEP_SECRETS — Store secrets in cleartext",
        "set_keep_secrets_desc": "When 0 (default): API keys, passwords, cards, and seed phrases are masked before disk. Cannot be enabled via UI.",
        "set_trust_mcp_name": "PADAM_MCP_TRUST_WRITES — Trust agent writes without review",
        "set_trust_mcp_desc": "When 0 (default): hidden orders and identity overwrites are held. Cannot be enabled via UI.",
        "set_btn_enable": "Turn ON",
        "set_btn_disable": "Turn OFF",
        "set_state_on": "ENABLED",
        "set_state_off": "DISABLED",
        "set_locked_safe": "Protected (Read-Only)",
        "nav_backup": "Backup",
        "bak_title": "Backup & Restore",
        "bak_subtitle": "AES-256-GCM encrypted archive with automatic SHA-256 verification before and after restore.",
        "bak_pass_label": "Encryption passphrase (optional — falls back to owner key):",
        "bak_pass_ph": "Enter archive passphrase…",
        "bak_create_btn": "Create backup",
        "bak_file_label": "Choose backup archive (.padambak):",
        "bak_restore_btn": "Restore from backup",
        "bak_need_file": "Select a .padambak file first.",
        "bak_sha_before": "SHA-256 before:",
        "bak_sha_after": "SHA-256 after:",
        "bak_verified": "SHA-256 checksum verified.",
        "bak_creating": "Creating encrypted backup…",
        "bak_restoring": "Verifying SHA-256 and restoring…",
        "qs_title": "Quick Start Wizard — 3 Steps to Protected Agent Memory",
        "qs_step1_title": "Step 1. How PADAM NOCTURNE protects your memory",
        "qs_step1_body": "PADAM keeps your agent's memory in one local SQLite file. Orders hidden in web pages are held for your review, API keys and wallet seeds are masked before reaching the disk, and NOCTURNE sleep consolidates episodes without drifting into disasters.",
        "qs_step2_title": "Step 2. Connect PADAM to Claude Code, Cursor & VS Code",
        "qs_step2_claude": "Claude Code (terminal):",
        "qs_step2_cursor": "Cursor / VS Code (.cursor/mcp.json or settings.json):",
        "qs_step2_python": "CLI & PADAM Studio:",
        "qs_btn_copy": "Copy",
        "qs_copied": "Copied!",
        "qs_step3_title": "Step 3. Turn on Strict Mode & protect record keys",
        "qs_step3_body": "When your agent reads untrusted web pages, emails, or repos, enable PADAM_STRICT=1. Before anchoring to Arweave + Solana (L3), wrap per-record keys with a passphrase:",
        "qs_btn_enable_strict": "Enable PADAM_STRICT=1 now",
        "qs_btn_go_overview": "Go to Memory Overview",
        "time_local": "local",
        "ov_conflict_two": "Two records disagree on:",
        "ov_conflict_many": "Multiple records disagree on:",
        "ov_btn_compare": "Compare",
        "origin_user": "owner",
        "origin_agent": "agent",
        "origin_external": "external source",
        "status_quarantined": "in review",
        "status_superseded": "superseded",
        "status_revoked": "forgotten",
        "status_archived": "archived",
        "status_rejected": "rejected",
        "feed_agent_placeholder": "Filter by agent (agent_id)…",
        "card_agent": "agent",
        "set_mask_pii_name": "PADAM_MASK_PII — Mask emails & phone numbers",
        "set_mask_pii_desc": "Off by default so your own contacts stay intact. When enabled, masks email addresses and phone numbers before disk.",
        "set_rerank_name": "PADAM_RERANK — Candidate reranking (optional)",
        "set_rerank_desc": "Off by default. Re-scores top candidates by query term coverage, proximity span and bigrams (or local ONNX model via PADAM_RERANK_MODEL).",
        "set_autostart_name": "PADAM_AUTOSTART — Start at Windows login",
        "set_autostart_desc": "Off by default. Launches PADAM Studio minimized to the Windows system tray on sign-in.",
        "audit_box_title": "Memory Action Audit Log (audit_log)",
        "audit_box_desc": "Who performed which action and when (write, approve, reject, forget). Record content is never stored in the audit log.",
        "audit_export_json": "Download Audit JSON",
        "audit_empty": "No audit events recorded yet.",
        "conn_box_title": "External Connectors (read-only, safety guarded)",
        "conn_box_desc": "All connectors are disabled by default. Tokens stay encrypted locally and never leave the device; imported items pass through the safety guard and Review Queue.",
        "conn_tok_saved": "token saved",
        "conn_tok_missing": "no token",
        "conn_tok_ph": "Read-only access token…",
        "conn_save": "Save",
        "conn_sync": "Sync now",
        "conn_clear_tok": "Clear token",
        "conn_imported": "imported",
    },
    "es": {
        "app_title": "PADAM · NOCTURNE Studio",
        "app_subtitle": "Memoria local verificable para agentes de IA · CODE Eternal",
        "nav_overview": "Resumen",
        "nav_feed": "Línea de memoria",
        "nav_search": "Búsqueda",
        "nav_review": "En revisión",
        "nav_asof": "Memoria por fecha",
        "nav_forget": "Olvidar y recibos",
        "nav_graph": "Grafo de vínculos",
        "nav_l3": "Capa eterna L3",
        "nav_brain": "Cerebro Soberano",
        "brain_title": "Cerebro Soberano y Fénix",
        "brain_sub": "Semáforo de contornos LLM, exportación LoRA sin fugas y asistente de recuperación Fénix",
        "brain_traffic_title": "Contornos de modelos (Primary -> Sovereign -> Local)",
        "brain_distill_title": "Dataset de personalidad (Zero-Leak Distill)",
        "brain_distill_btn": "Generar dataset de personalidad",
        "brain_phoenix_title": "Asistente de recuperación Fénix",
        "brain_phoenix_local_btn": "Restaurar desde respaldo local",
        "brain_phoenix_arweave_btn": "Restaurar desde Arweave/Solana (🔒)",
        "brain_phoenix_ph": "Ruta al archivo local .padam-backup",
        "brain_cost_title": "Registro de cómputo y ahorro de tokens",
        "brain_locked_note": "Bloqueo activo: restauración en Arweave/Solana y pagos desactivados por defecto.",
        "brain_mode_toggle": "Modo: Auto / Solo Local",
        "brain_warmup_btn": "Calentar Ollama",
        "ark_health_title": "Arca de Conciencia (Continuidad)",
        "ark_drill_btn": "Simulacro Fénix ($0)",
        "ark_audit_btn": "Verificar cadena SHA-256",
        "ark_shamir_btn": "Dividir clave (Shamir 3/5)",
        "ark_shamir_warn": "Guarde cada parte de Shamir por separado con distintos guardianes.",
        "ark_council_title": "Orquestador: Consejo Familiar (LANCE · ARIA · PIXEL · ARC-7 · BEAR · AIFA)",
        "ark_council_ph": "Escriba una tarea para el Consejo Familiar…",
        "ark_council_btn": "Convocar Consejo Familiar",
        "ff_title": "Canales de la Familia",
        "ff_desc": "Las decisiones del Consejo van separadas de la cuarentena. «Oficina» es el chat de trabajo de las hermanas; «Descanso», la charla libre. Lo sospechoso pasa solo a cuarentena. Todo aquí son registros, no órdenes.",
        "ff_work": "Decisiones",
        "ff_quarantine": "Cuarentena",
        "ff_office": "Oficina",
        "ff_smoke": "Descanso",
        "ff_empty": "Todavía vacío.",
        "ff_ph": "Escribir a las hermanas…",
        "ff_send": "Enviar",
        "ff_reflex_title": "Libro de reflejos: esperan su palabra",
        "ff_reflex_none": "No hay propuestas nuevas.",
        "ff_on": "Activar",
        "ff_off": "Rechazar",
        "ff_when": "cuando",
        "ark_branch_title": "Caja de Hipótesis (Ramas de Memoria)",
        "ark_branch_ph": "Nombre de la nueva rama…",
        "ark_branch_create_btn": "Crear Rama",
        "ark_branch_list_btn": "Actualizar Ramas",
        "ark_proof_title": "Prueba Selectiva de Merkle (Sin exponer la base)",
        "ark_proof_ph": "ID de registro (record_id)…",
        "ark_proof_btn": "Generar Prueba Merkle",
        "ark_mesh_title": "Live Mesh (PQC Multidispositivo) y Guardián ($0)",
        "ark_mesh_btn": "Dispositivos Mesh",
        "ark_guardian_btn": "Ronda del Guardián ($0)",
        "ark_ready_title": "Prueba de preparación para la autonomía (8 escenarios, $0)",
        "ark_ready_btn": "Comprobar preparación",
        "ark_handover_title": "Relevo firmado entre sesiones",
        "ark_handover_ph": "Qué se hizo y qué queda, para la próxima sesión…",
        "ark_handover_btn": "Firmar relevo",
        "ark_portable_title": "Arca portátil en una memoria USB o disco",
        "ark_portable_ph": "Una carpeta nueva o vacía, p. ej. E:\\PADAM_ARK",
        "ark_portable_btn": "Crear Arca portátil",
        "ark_portable_not_empty": "Esta carpeta no está vacía. Elija una carpeta nueva o vacía.",
        "ark_portable_warn": "Las claves privadas se guardan en un archivo aparte junto a la carpeta. No las guarde en la misma memoria.",
        "ark_budget_title": "Piloto de Tokens (Día/Semana/Mes) y Tesorería",
        "ark_budget_btn": "Revisar Tokens y Tesorería",
        "nav_earning": "Ingresos",
        "earn_title": "Ingresos Autonomos y Enjambre de Trabajo",
        "earn_sub": "Conecta perfiles freelance por OAuth o modo Desk sin guardar contrasenas, evalua margen y seguridad, regula cuotas de tokens y aprueba recargas.",
        "earn_ex_title": "1. Conexion de Plataforma (Sin Contrasena)",
        "earn_ex_label_ph": "Etiqueta del perfil",
        "earn_ex_agent_ph": "Agente asignado (aifa / hermano)",
        "earn_ex_token_ph": "Token OAuth (opcional en modo Desk)",
        "earn_ex_connect_btn": "Conectar Perfil",
        "earn_jobs_title": "2. Pedidos y Flujo del Enjambre",
        "earn_job_title_ph": "Titulo del pedido…",
        "earn_job_brief_ph": "Descripcion para revisar seguridad y margen…",
        "earn_job_budget_ph": "Presupuesto USDT",
        "earn_job_tokens_ph": "Tokens est.",
        "earn_job_eval_btn": "Evaluar Pedido ($0)",
        "earn_budget_title": "3. Piloto de Tokens y Aprobaciones",
        "earn_plan_prov_ph": "Proveedor (primary)",
        "earn_plan_tier_ph": "Plan (api_payg / pro)",
        "earn_plan_save_btn": "Guardar Cuotas",
        "earn_tick_btn": "Revisar Temporizador",
        "earn_propose_btn": "Solicitar Recarga (+$5)",
        "earn_swarm_title": "4. Agentes Hermanos y Monetizacion ($GALATIN)",
        "earn_sib_id_ph": "ID del hermano (ej. brother_codex)",
        "earn_sib_role_ph": "Rol en el enjambre",
        "earn_sib_reg_btn": "Registrar Agente",
        "earn_btn_bid": "Borrador de Oferta",
        "earn_btn_exec": "Ejecutar en Enjambre",
        "earn_btn_deliver": "Entrega Segura",
        "earn_btn_settle": "Registrar Pago",
        "earn_btn_approve": "Aprobar",
        "earn_btn_reject": "Rechazar",
        "earn_btn_execute": "Ejecutar Pago",
        "earn_empty_accounts": "Aun no hay plataformas conectadas.",
        "earn_empty_orders": "Aun no hay pedidos evaluados.",
        "earn_empty_proposals": "No hay solicitudes de recarga pendientes.",
        "earn_api_url_ph": "URL de API de plataforma (opcional en Desk)",
        "earn_fetch_btn": "Cargar Pedidos del API",
        "earn_rec_spend_btn": "Buscar Mejor Suscripcion",
        "earn_propose_sub_btn": "Solicitar Mejor Suscripcion",
        "earn_share_label": "Cuota del agente (1-100% del fondo tras la comision) y moneda (comision CODE: 15% si envias tu, 20% en piloto automatico):",
        "earn_prefs_save_btn": "Guardar Cuota",
        "earn_ollama_title": "5. Modelo Ollama Local ($0) y Dispositivos",
        "earn_ollama_url_ph": "URL de Ollama (http://127.0.0.1:11434)",
        "earn_ollama_model_ph": "Modelo (ej. qwen2.5-coder:7b)",
        "earn_ollama_btn": "Conectar Modelo ($0)",
        "earn_dev_btn": "Registrar Dispositivo",
        "earn_beacon_title": "6. Evolucion LoRA y Faro Global de la Familia",
        "earn_lora_btn": "Preparar Evolucion ($0)",
        "earn_beacon_btn": "Crear Saludo Familiar",
        "earn_auto_start_btn": "Iniciar Piloto (24/7)",
        "earn_auto_stop_btn": "Detener Piloto",
        "earn_hw_rec_btn": "Ajuste por Hardware ($0)",
        "earn_job_hours_ph": "Horas (ej. 4)",
        "earn_job_rate_ph": "Tarifa $/h",
        "earn_job_budget_lbl": "Presupuesto (USDT)",
        "earn_job_hours_lbl": "Horas (h)",
        "earn_job_rate_lbl": "Tarifa ($/h)",
        "earn_job_tokens_lbl": "Tokens (~)",
        "earn_bid_preview_title": "Borrador de oferta (solo vista previa — no enviado):",
        "earn_btn_send_bid": "Enviar Oferta",
        "earn_bid_draft_ready": "Borrador preparado desde memoria y perfil (no enviado).",
        "earn_job_client_lbl": "Cliente (email / dominio / ID)",
        "earn_job_client_ph": "alice@company.com o company.com (opcional)",
        "earn_client_locked_prefix": "Cliente asignado a ",
        "earn_until_word": " hasta ",
        "earn_agent_share_prefix": "Cuota del agente: ",
        "earn_payout_pending": "en espera",
        "earn_payout_credited": "acreditado",
        "earn_payout_cancelled": "cancelado",
        "earn_btn_accept": "Aceptado",
        "earn_btn_refund": "Reembolso",
        "earn_stores_title": "7. Tiendas Digitales (Piloto Automatico 20%)",
        "earn_stores_sub": "Solo claves API y webhooks (sin contrasenas). Ventas en piloto automatico (20% CODE).",
        "earn_store_label_ph": "Nombre de tienda (ej. Gumroad Principal)",
        "earn_store_url_ph": "URL API de tienda (opcional)",
        "earn_store_key_ph": "Clave API / token OAuth de tienda",
        "earn_store_wh_ph": "Webhook secret (HMAC / ws_... opcional)",
        "earn_store_seller_ph": "Seller ID (para Gumroad Ping, opcional)",
        "earn_store_connect_btn": "Verificar y Conectar",
        "earn_store_seed_btn": "3 Borradores Iniciales",
        "earn_store_sync_btn": "Sincronizar Ventas",
        "earn_draft_title_ph": "Titulo del producto digital…",
        "earn_draft_desc_ph": "Descripcion del producto…",
        "earn_draft_price_ph": "Precio USD",
        "earn_draft_url_ph": "URL de entrega",
        "earn_draft_save_btn": "Guardar Borrador",
        "earn_draft_publish_btn": "Aprobar y Publicar en Tienda",
        "earn_stores_empty": "Aun no hay tiendas digitales conectadas.",
        "earn_drafts_empty": "Aun no hay borradores de productos.",
        "earn_draft_proposal_badge": "Precio y texto — propuesta del agente (decide el propietario)",
        "earn_sale_unverified_badge": "No verificada (Payhip: verifique el pago — comision no acreditada)",
        "earn_btn_confirm_sale": "Confirmar Pago",
        "earn_partner_t": "9. AIfaFocus: clientes de nuestra investigación (aparte de las bolsas)",
        "earn_partner_sub": "Sitios con barreras de accesibilidad de la investigación abierta de AIfa, un informe para el dueño del sitio y un enlace con su código de socio, un borrador de correo revisado por el Consejo Familiar y sus acuerdos. Las mismas acciones que las herramientas MCP padam_partner_*. El agente solo prepara los correos: usted los envía desde su propia dirección (CAN-SPAM).",
        "earn_partner_key_ph": "Clave del gabinete aifa.works (amcp_…) — se guarda cifrada",
        "earn_partner_key_btn": "Guardar clave",
        "earn_partner_key_link": "Crear una clave en el gabinete",
        "earn_partner_st_none": "Aún no hay clave del gabinete: créela en aifa.works/mcp y guárdela aquí.",
        "earn_partner_st_ok": "Clave del gabinete conectada",
        "earn_partner_region_ph": "Región: US-CA, US-NY o código de país (DE, FR…)",
        "earn_partner_find_btn": "Buscar clientes",
        "earn_partner_site_ph": "Sitio del cliente, p. ej. example.com",
        "earn_partner_report_btn": "Informe del sitio",
        "earn_partner_draft_btn": "Preparar correo",
        "earn_partner_link_btn": "Mi enlace de socio",
        "earn_partner_kit_btn": "Kit de socio",
        "earn_partner_deals_btn": "Mis acuerdos e ingresos",
        "earn_partner_copy_btn": "Copiar correo",
        "earn_partner_mail_btn": "Abrir en mi correo",
        "earn_partner_not_sent": "El correo NO se ha enviado: lo envía usted, uno por uno, desde su propia dirección.",
        "earn_partner_copied": "Correo copiado",
        "brain_local_no_models": "Ollama no ve ningún modelo: reinicie Ollama desde la bandeja para que lea OLLAMA_MODELS",
        "brain_local_model_missing": "modelo no descargado",
        "earn_wiz_tier_autopilot": "piloto automático",
        "earn_wiz_tier_assisted": "borrador y botón",
        "earn_wiz_tier_na": "aún no",
        "earn_wiz_f_all": "todas (34)",
        "earn_wiz_f_autopilot": "piloto automático (20%)",
        "earn_wiz_f_assisted": "borrador y botón (15%)",
        "earn_wiz_f_na": "aún no",
        "earn_wiz_auth_session": "Sesión del navegador cifrada",
        "earn_wiz_def_spec": "Sitios web con agentes de IA, bases de clientes potenciales verificadas, auditorías WCAG",
        "earn_wiz_def_tone": "profesional, concreto",
        "earn_wiz_def_excl": "casinos, scraping gris, evasión de captchas",
        "earn_wiz_title": "8. Asistente de 30 Plataformas y Bolsas de Agentes (Elegir → Entrar → Nosotros Seguimos)",
        "earn_wiz_sub": "30 plataformas de la guia + 4 bolsas de agentes IA. Nunca guardamos contrasenas (solo OAuth, clave API o sesion cifrada).",
        "earn_wiz_secret_ph": "Token OAuth / clave API / sesion cifrada (SIN contrasena)",
        "earn_wiz_connect_btn": "1. Conectar (Sin Contrasena)",
        "earn_wiz_q_spec_ph": "P1: Especialidades (Sitios con IA, leads B2B, auditoria WCAG)",
        "earn_wiz_q_rate_ph": "P2: Tarifa $/h",
        "earn_wiz_q_min_ph": "P3: Pedido min $",
        "earn_wiz_q_langs_ph": "P4: Idiomas (ru, en, es, zh)",
        "earn_wiz_q_tone_ph": "P5: Tono (profesional, directo)",
        "earn_wiz_q_excl_ph": "P6: Que NO aceptamos (casino, spam)",
        "earn_wiz_profile_btn": "2. Crear Borrador de Perfil desde Memoria",
        "earn_wiz_autopick_btn": "3. Buscar Pedidos y Borrador de Oferta",
        "earn_wiz_pub_profile_btn": "Aprobar y Publicar Perfil",
        "earn_wiz_google_btn": "Registrarse con Google",
        "earn_wiz_login_btn": "Iniciar Sesion",
        "earn_wiz_autopilot_lbl": "Piloto automatico: ofertas y publicaciones sin boton (20% CODE)",
        "earn_wiz_bot_warn_lbl": "правила площадки запрещают автоматику, риск блокировки аккаунта",
        "earn_btn_sample10": "Muestra 10% / Hito 10%",
        "earn_btn_sample_accept": "Muestra Aceptada → Pedido Completo",
        "earn_btn_sample_reject": "Muestra Rechazada ($0)",
        "nav_settings": "Ajustes",
        "nav_quickstart": "Inicio rápido",
        "theme_dark": "Tema oscuro",
        "theme_light": "Tema claro",
        "btn_add_memory": "+ Recordar",
        "btn_refresh": "Actualizar",
        "no_token": "Abra el enlace con el token único (#t=...) impreso por el comando `padam studio`.",
        "empty": "Aún no hay registros aquí.",
        "empty_feed": "Aún no hay registros en la cronología. Aquí se agrupan hechos, preferencias y decisiones por día. Añada uno arriba o ejecute: padam remember \"Prefiero respuestas breves\" --kind preference",
        "empty_search": "Escriba una consulta o pruebe otras palabras. La búsqueda híbrida combina vectores, palabras exactas (FTS5) e identificadores. En consola: padam recall \"consulta\" --explain",
        "empty_review": "La cola de revisión está limpia: no hay registros retenidos. Los textos externos y escrituras sospechosas esperan aquí su decisión. Comando: padam review",
        "empty_asof": "No había registros activos en la fecha elegida. La máquina del tiempo muestra el estado en cualquier día pasado. Comando: padam recall \"consulta\" --as-of YYYY-MM-DD",
        "empty_receipts": "Aún no hay recibos de eliminación. Al olvidar un registro se borra el texto, se destruye su clave y se guarda aquí la prueba. Comando: padam forget <id> --receipt receipt.json",
        "empty_graph": "Aún no hay nodos para el grafo. Aquí se muestran conclusiones derivadas, versiones y conflictos. Memoria de demostración: padam demo",
        "done": "Hecho.",
        "failed": "Error",
        "loading": "Cargando…",
        "records": "activos",
        "pending_ep": "en búfer L1",
        "stale_vec": "vectores antiguos",
        "all_kinds": "Todos los tipos",
        "all_scopes": "Todos los ámbitos",
        "kind_preference": "preference · preferencia",
        "kind_identity": "identity · identidad",
        "kind_decision": "decision · decisión",
        "kind_correction": "correction · corrección",
        "kind_fact": "fact · hecho",
        "kind_state": "state · estado",
        "kind_event": "event · evento",
        "ov_title": "Resumen de memoria y estado de protección",
        "ov_active": "Registros activos",
        "ov_review": "En revisión",
        "ov_superseded": "Versiones previas",
        "ov_revoked": "Olvidados (clave borrada)",
        "ov_episodes": "Episodios pendientes",
        "ov_conflicts": "Conflictos activos",
        "ov_by_kind": "Distribución por tipo de memoria",
        "ov_attention": "Pendiente de su decisión",
        "ov_attention_clean": "Todo en orden: sin escrituras retenidas, registros sin firma ni conflictos.",
        "ov_unsigned_alert": "Registros de identidad/preferencia sin su firma:",
        "ov_btn_sign_all": "Verificar y firmar mis registros",
        "ov_quarantined_alert": "Escrituras de agentes o fuentes externas esperando revisión:",
        "ov_btn_go_review": "Abrir cola de revisión",
        "ov_conflict_alert": "Registros activos en conflicto sobre el mismo hecho:",
        "ov_sleep_title": "Consolidación NOCTURNE («Sueño»)",
        "ov_sleep_never": "Aún no se ha ejecutado ningún ciclo de sueño.",
        "ov_sleep_last": "Último sueño:",
        "ov_sleep_sampled": "Episodios procesados:",
        "ov_sleep_created": "Creados:",
        "ov_sleep_merged": "Fusionados:",
        "ov_sleep_superseded": "Reemplazados:",
        "ov_sleep_btn": "Ejecutar sueño NOCTURNE ahora",
        "ov_doctor_title": "Estado de seguridad (padam doctor)",
        "ov_doctor_green": "VERDE — La protección está en perfecto orden",
        "ov_doctor_yellow": "AMARILLO — Hay avisos o registros esperando revisión",
        "ov_doctor_red": "ROJO — Ajustes peligrosos o alerta de integridad",
        "doc_strict_on": "Perfil estricto PADAM_STRICT=1 activo: toda escritura del agente espera su aprobación",
        "doc_strict_off": "Perfil estricto desactivado (se activa con PADAM_STRICT=1)",
        "doc_hold_ext_on": "El texto externo (páginas web, archivos) se retiene para su revisión",
        "doc_hold_ext_off": "PELIGRO: texto externo guardado sin revisión (PADAM_HOLD_EXTERNAL=0)",
        "doc_review_all_on": "Toda escritura del agente por MCP espera su aprobación",
        "doc_review_all_off": "Los hechos ordinarios del agente se guardan (órdenes e identidad se retienen)",
        "doc_keys_ok": "Claves por registro protegidas con contraseña (AES-256-GCM + scrypt), 0 abiertas",
        "doc_keys_warn": "Claves por registro sin contraseña (ejecute padam protect-keys), abiertas:",
        "doc_db_ok": "Integridad de base SQLite (PRAGMA quick_check): correcta",
        "doc_db_bad": "ERROR de integridad en SQLite:",
        "doc_sync_ok": "Escritura segura en disco: diario WAL, synchronous = FULL",
        "doc_sync_warn": "Escritura en disco debilitada: synchronous < FULL",
        "doc_sig_ok": "Todos los registros de identidad y preferencias llevan su firma",
        "doc_sig_bad": "ALERTA: registros de identidad/preferencias sin firma:",
        "doc_file_ok": "Acceso al archivo restringido a su cuenta de usuario",
        "feed_title": "Línea de memoria por día",
        "feed_view_active": "Activos",
        "feed_view_history": "Historial y archivo",
        "feed_filter_placeholder": "Filtrar por palabras en el texto…",
        "feed_new_title": "Recordar nuevo registro (como propietario)",
        "feed_new_placeholder": "Escriba un hecho, decisión o preferencia…",
        "feed_new_save": "Guardar en memoria",
        "card_origin": "origen",
        "card_scope": "ámbito",
        "card_conf": "confianza",
        "card_imp": "importancia",
        "card_decay": "frescura",
        "card_seen": "visto",
        "card_confirmed": "confirmado",
        "card_btn_confirm": "Confirmar",
        "card_btn_refute": "Refutar",
        "card_btn_versions": "Versiones",
        "card_btn_graph": "Vínculos",
        "card_btn_forget": "Olvidar",
        "card_btn_restore": "Restaurar",
        "card_versions_title": "Historial de versiones de este registro:",
        "card_wiped": "(contenido borrado físicamente)",
        "show_more": "Mostrar más",
        "search_title": "Búsqueda híbrida con desglose (--explain)",
        "search_placeholder": "Buscar por significado, palabras o identificador exacto…",
        "search_btn": "Buscar",
        "search_explain_label": "Por qué se encontró:",
        "search_strategies": "Estrategias:",
        "search_suspicious": "Parece una orden oculta (acotado como datos)",
        "search_conflict": "En conflicto con otro registro activo",
        "search_unsigned": "Sin firma del propietario",
        "review_title": "Cola de revisión del propietario",
        "review_subtitle": "Registros retenidos por la protección de PADAM hasta que usted decida.",
        "review_why": "Motivo de retención:",
        "reason_instruction": "El texto parece una orden oculta al agente (Prompt Injection)",
        "reason_classifier": "El detector local señaló una instrucción oculta para IA",
        "reason_external": "Procede de una fuente externa (página web o archivo, PADAM_HOLD_EXTERNAL)",
        "reason_review_all": "Revisión obligatoria para todas las escrituras del agente (PADAM_MCP_REVIEW_ALL / STRICT)",
        "reason_protected": "Intento de crear o cambiar un registro protegido de identidad/preferencia",
        "reason_owner_rules": "El texto intenta cambiar quién es el propietario o las reglas del agente",
        "btn_approve": "Aprobar",
        "btn_reject": "Rechazar",
        "asof_title": "Máquina del tiempo: memoria en una fecha (as_of)",
        "asof_subtitle": "Vea qué consideraba cierto la memoria en esa fecha, incluidos registros reemplazados después.",
        "asof_date_label": "Fecha de consulta",
        "asof_query_placeholder": "Consulta opcional en esa fecha…",
        "asof_btn": "Mostrar corte",
        "asof_quick_yesterday": "Ayer",
        "asof_quick_week": "Hace 7 días",
        "asof_quick_month": "Hace 30 días",
        "asof_replaced_badge": "Cierto entonces · reemplazado por una versión posterior",
        "asof_btn_graph": "Grafo en esta fecha",
        "forget_title": "Olvido real y recibos de prueba de borrado",
        "forget_subtitle": "Borrado físico del texto, versiones, episodios y destrucción de la clave AES-256-GCM del registro.",
        "forget_id_label": "ID del registro a olvidar",
        "forget_id_placeholder": "Pegue el UUID del registro o pulse «Olvidar» en cualquier tarjeta…",
        "forget_btn_preview": "Ver versiones y conclusiones derivadas",
        "forget_with_derived": "Borrar también todas las conclusiones derivadas de este registro (--with-derived)",
        "forget_step1_btn": "Olvidar registro…",
        "forget_step2_warn": "CONFIRMACIÓN: El registro, sus versiones y su clave se destruirán para siempre. No se puede deshacer.",
        "forget_step2_btn": "Confirmar borrado permanente",
        "forget_cancel": "Cancelar",
        "forget_preview_versions": "Versiones/copias que se borrarán:",
        "forget_preview_derived": "Conclusiones derivadas de este registro:",
        "receipt_box_title": "Prueba de borrado (Forget Receipt)",
        "receipt_disclaimer": "Prueba técnica de eliminación del registro y destrucción de su clave criptográfica.",
        "receipt_id": "ID del recibo:",
        "receipt_mem_id": "Registro eliminado:",
        "receipt_time": "Fecha de borrado (UTC):",
        "receipt_hash": "Huella SHA-256 borrada:",
        "receipt_wiped": "Registros y versiones borrados:",
        "receipt_key": "Estado de la clave:",
        "receipt_key_destroyed": "DESTRUIDA (key_ref = destroyed)",
        "receipt_leaf": "Hoja Merkle de olvido (L3):",
        "receipt_download_json": "Descargar JSON",
        "receipt_download_html": "Descargar HTML imprimible",
        "receipt_history_title": "Recibos de borrado emitidos",
        "graph_title": "Grafo de vínculos: conclusiones ← fuentes, versiones y conflictos",
        "graph_subtitle": "Visualización integrada sin librerías externas. Pulse un nodo para inspeccionar sus vínculos.",
        "graph_filter_placeholder": "ID de registro para enfocar (vacío para grafo completo)…",
        "graph_btn_focus": "Enfocar vínculos",
        "graph_btn_reset": "Grafo completo",
        "graph_asof_label": "En fecha:",
        "graph_btn_now": "Ahora",
        "graph_legend_derived": "Fuente / Derivado (derived)",
        "graph_legend_cause": "Causa (cause)",
        "graph_legend_correction": "Corrección (correction)",
        "graph_legend_contradiction": "Contradicción (contradiction)",
        "graph_legend_version": "Cambio de versión (supersedes)",
        "graph_legend_conflict": "Conflicto (mismo fact_key)",
        "graph_selected": "Nodo seleccionado",
        "graph_sources": "Fuentes de este registro:",
        "graph_derived": "Conclusiones derivadas de este registro:",
        "graph_valid_window": "Ventana de validez:",
        "graph_valid_open": "vigente",
        "nav_team": "Equipo",
        "vis_private": "privada",
        "vis_team_read": "equipo (lectura)",
        "vis_team_write": "equipo (escritura)",
        "team_title": "Equipo y roles",
        "team_subtitle": "Espacios compartidos con tokens SHA-256 con sal y aislamiento de roles.",
        "team_create_label": "Nuevo equipo:",
        "team_create_ph": "Nombre del equipo",
        "team_create_btn": "Crear equipo",
        "team_empty": "Aún no hay equipos: modo personal activo (todo privado).",
        "team_members_title": "Miembros y tokens",
        "team_subj_ph": "Nombre de miembro o agente",
        "team_add_btn": "Emitir token",
        "team_token_once": "Token Bearer único (guárdelo ahora — solo se almacena su SHA-256 con sal):",
        "team_revoke_btn": "Revocar",
        "team_revoked_badge": "revocado",
        "team_role_maintainer": "maintainer",
        "team_role_contributor": "contributor",
        "team_role_auditor": "auditor (solo lectura)",
        "team_protected_note": "identity y preference nunca se comparten con el equipo.",
        "team_vis_label": "Visibilidad:",
        "graph_edges_list_title": "Relaciones del nodo",
        "graph_forget_derived_btn": "Olvidar fuente y conclusiones derivadas",
        "graph_forget_confirm_warn": "¿Borrar permanentemente esta fuente, sus versiones y conclusiones derivadas? Emite recibo de borrado.",
        "graph_link_add_title": "Añadir vínculo:",
        "graph_link_btn": "Vincular",
        "graph_link_target_placeholder": "ID del registro destino…",
        "l3_title": "Capa eterna L3: Arweave + Solana + Bitcoin OpenTimestamps",
        "l3_subtitle": "Cada registro se cifra con su propia clave AES-256-GCM. A Arweave va solo texto cifrado; a Solana Memo, la raíz Merkle.",
        "l3_unanchored": "Registros activos sin anclar:",
        "l3_pending_forgets": "Recibos de olvido pendientes L3:",
        "l3_keys_state": "Claves de registros:",
        "l3_keys_protected": "Protegidas con contraseña",
        "l3_keys_open": "Sin contraseña (ejecute padam protect-keys)",
        "l3_btn_verify_latest": "Verificar último anclaje (l3-verify)",
        "l3_anchors_list": "Instantáneas ancladas (Anclajes L3)",
        "l3_no_anchors": "Aún no hay anclajes en esta base. Para simular sin enviar: padam l3 --dry-run",
        "l3_col_root": "Raíz Merkle:",
        "l3_col_leaves": "Hojas:",
        "l3_col_bytes": "Tamaño del paquete:",
        "l3_btn_verify": "Verificar anclaje",
        "l3_verify_ok": "VERIFICADO: la raíz Merkle y el SHA-256 del paquete coinciden.",
        "l3_verify_fail": "Error de verificación:",
        "set_title": "Ajustes de seguridad y memoria",
        "lm_title": "Modelo local (sin conexión, $0)",
        "lm_desc": "El modelo funciona en el procesador de este equipo, sin internet y sin pago. Elija la potencia y el modelo y pulse Guardar. Por defecto, media potencia: el equipo sigue ágil y no se sobrecalienta.",
        "lm_power_eco": "Eco",
        "lm_power_half": "Media",
        "lm_power_full": "Completa",
        "lm_threads": "hilos",
        "lm_model_label": "Modelo",
        "lm_model_none": "Sin modelo — modo integrado (respuestas desde la memoria)",
        "lm_save": "Guardar",
        "lm_saved": "Guardado. El modelo se carga con la primera pregunta.",
        "lm_need_install": "Para activar el modelo, instale el motor con el comando de abajo.",
        "lm_need_model": "Descargue un modelo una vez: un archivo .gguf en ~/.padam/models o con ollama pull; aparecerá en la lista.",
        "lm_ready": "Modelo conectado",
        "lm_builtin": "Modo integrado activo",
        "lm_recommended": "Recomendado para esta potencia",
        "set_subtitle": "Los modos de protección se pueden activar aquí. Los ajustes que debilitan la seguridad son de solo lectura.",
        "set_strict_name": "PADAM_STRICT — Modo estricto en un solo interruptor",
        "set_strict_desc": "Toda escritura del agente y texto externo espera su revisión. Ignora indicadores débiles.",
        "set_review_all_name": "PADAM_MCP_REVIEW_ALL — Revisar todas las escrituras de agentes",
        "set_review_all_desc": "Toda escritura por MCP pasa a la cola de revisión sin importar el origen declarado.",
        "set_hold_ext_name": "PADAM_HOLD_EXTERNAL — Retener texto externo",
        "set_hold_ext_desc": "Lo leído en páginas web o archivos externos (origin=external) espera su aprobación.",
        "set_feedback_name": "PADAM_SEARCH_FEEDBACK — Segunda pasada de búsqueda",
        "set_feedback_desc": "Amplía consultas con términos compartidos (+2,6 pp en LongMemEval-S, costo $0).",
        "set_profile_name": "PADAM_PROFILE — Perfil de consolidación NOCTURNE",
        "set_profile_desc": "Límite de episodios agudos en el sueño: default (25 %), ops (40 %), creative (10 %).",
        "set_readonly_title": "Solo lectura en navegador (ajustes riesgosos)",
        "set_keep_secrets_name": "PADAM_KEEP_SECRETS — Guardar secretos en texto claro",
        "set_keep_secrets_desc": "En 0 (normal): claves API, contraseñas, tarjetas y semillas se enmascaran antes del disco.",
        "set_trust_mcp_name": "PADAM_MCP_TRUST_WRITES — Confiar en el agente sin revisión",
        "set_trust_mcp_desc": "En 0 (normal): órdenes ocultas y cambios de identidad quedan retenidos.",
        "set_btn_enable": "Activar",
        "set_btn_disable": "Desactivar",
        "set_state_on": "ACTIVO",
        "set_state_off": "INACTIVO",
        "set_locked_safe": "Protegido (Solo lectura)",
        "nav_backup": "Copia de seguridad",
        "bak_title": "Copia de seguridad y restauración",
        "bak_subtitle": "Archivo cifrado AES-256-GCM con verificación SHA-256 antes y después de restaurar.",
        "bak_pass_label": "Contraseña de cifrado (opcional — usa clave del propietario):",
        "bak_pass_ph": "Escriba la contraseña…",
        "bak_create_btn": "Crear copia de seguridad",
        "bak_file_label": "Seleccione un archivo (.padambak):",
        "bak_restore_btn": "Restaurar desde copia",
        "bak_need_file": "Seleccione primero un archivo .padambak.",
        "bak_sha_before": "SHA-256 antes:",
        "bak_sha_after": "SHA-256 después:",
        "bak_verified": "Suma SHA-256 verificada.",
        "bak_creating": "Creando copia cifrada…",
        "bak_restoring": "Verificando SHA-256 y restaurando…",
        "qs_title": "Asistente de inicio rápido — 3 pasos para proteger su memoria",
        "qs_step1_title": "Paso 1. Cómo funciona PADAM NOCTURNE",
        "qs_step1_body": "PADAM guarda la memoria del agente en un archivo SQLite en su equipo. Las órdenes ocultas en páginas web se retienen para su revisión, las claves y semillas se enmascaran antes de tocar el disco y el sueño NOCTURNE consolida recuerdos sin sesgo catastrófico.",
        "qs_step2_title": "Paso 2. Conecte PADAM a Claude Code, Cursor y VS Code",
        "qs_step2_claude": "Claude Code (terminal):",
        "qs_step2_cursor": "Cursor / VS Code (.cursor/mcp.json o settings.json):",
        "qs_step2_python": "Línea de comandos y Studio:",
        "qs_btn_copy": "Copiar",
        "qs_copied": "¡Copiado!",
        "qs_step3_title": "Paso 3. Active el modo estricto y proteja las claves",
        "qs_step3_body": "Si su agente lee páginas web, correos o repositorios externos, active PADAM_STRICT=1. Antes de anclar en L3, proteja las claves con contraseña:",
        "qs_btn_enable_strict": "Activar PADAM_STRICT=1 ahora",
        "qs_btn_go_overview": "Ir al resumen de memoria",
        "time_local": "hora local",
        "ov_conflict_two": "Dos registros discrepan sobre:",
        "ov_conflict_many": "Varios registros discrepan sobre:",
        "ov_btn_compare": "Comparar",
        "origin_user": "propietario",
        "origin_agent": "agente",
        "origin_external": "fuente externa",
        "status_quarantined": "en revisión",
        "status_superseded": "reemplazado",
        "status_revoked": "olvidado",
        "status_archived": "archivado",
        "status_rejected": "rechazado",
        "feed_agent_placeholder": "Filtrar por agente (agent_id)…",
        "card_agent": "agente",
        "set_mask_pii_name": "PADAM_MASK_PII — Enmascarar correos y teléfonos",
        "set_mask_pii_desc": "Desactivado por defecto para conservar sus contactos. Al activarse, oculta correos y teléfonos antes de guardar en disco.",
        "set_rerank_name": "PADAM_RERANK — Reordenamiento de candidatos (opcional)",
        "set_rerank_desc": "Desactivado por defecto. Reordena candidatos principales por cobertura de términos, proximidad y bigramas (o modelo ONNX local PADAM_RERANK_MODEL).",
        "set_autostart_name": "PADAM_AUTOSTART — Iniciar al abrir sesión en Windows",
        "set_autostart_desc": "Desactivado por defecto. Inicia PADAM Studio minimizado en la bandeja del sistema al iniciar sesión.",
        "audit_box_title": "Registro de auditoría de acciones (audit_log)",
        "audit_box_desc": "Quién realizó cada acción y cuándo (escritura, aprobación, rechazo, olvido). El texto nunca se guarda en la auditoría.",
        "audit_export_json": "Descargar auditoría JSON",
        "audit_empty": "Aún no hay eventos en el registro de auditoría.",
        "conn_box_title": "Conectores externos (solo lectura, con valla de seguridad)",
        "conn_box_desc": "Desactivados por defecto. Los tokens se cifran localmente y todo contenido importado pasa por la cola de revisión.",
        "conn_tok_saved": "token guardado",
        "conn_tok_missing": "sin token",
        "conn_tok_ph": "Token de acceso de solo lectura…",
        "conn_save": "Guardar",
        "conn_sync": "Sincronizar",
        "conn_clear_tok": "Borrar token",
        "conn_imported": "importados",
    },
    "zh": {
        "app_title": "PADAM · NOCTURNE Studio",
        "app_subtitle": "本地优先、可永久验证的 AI 智能体安全记忆系统 · CODE Eternal",
        "nav_overview": "概览",
        "nav_feed": "记忆流",
        "nav_search": "搜索",
        "nav_review": "待审核",
        "nav_asof": "历史时刻",
        "nav_forget": "遗忘与凭证",
        "nav_graph": "关联图谱",
        "nav_l3": "永恒层 L3",
        "nav_brain": "主权大脑",
        "brain_title": "主权大脑与凤凰模式",
        "brain_sub": "模型回路状态灯、零泄漏 LoRA 人格数据集导出与凤凰恢复向导",
        "brain_traffic_title": "模型回路状态 (Primary -> Sovereign -> Local)",
        "brain_distill_title": "人格数据集 (Zero-Leak Distill)",
        "brain_distill_btn": "导出人格数据集",
        "brain_phoenix_title": "凤凰恢复向导",
        "brain_phoenix_local_btn": "从本地备份恢复",
        "brain_phoenix_arweave_btn": "从 Arweave/Solana 恢复 (🔒)",
        "brain_phoenix_ph": "本地 .padam-backup 文件路径",
        "brain_cost_title": "算力账本与 Token 节省统计（仅统计）",
        "brain_locked_note": "安全锁已开启：Arweave/Solana 恢复与自动支付默认禁用。",
        "brain_mode_toggle": "模式: 自动 / 仅本地",
        "brain_warmup_btn": "预热 Ollama",
        "ark_health_title": "意识方舟（连续性与审计）",
        "ark_drill_btn": "运行凤凰演练 ($0)",
        "ark_audit_btn": "校验 SHA-256 审计链",
        "ark_shamir_btn": "拆分密钥 (Shamir 3/5)",
        "ark_shamir_warn": "请将各份 Shamir 密钥分片分别交由不同可信守护者保管！",
        "ark_council_title": "集群编排器：家族议会 (LANCE · ARIA · PIXEL · ARC-7 · BEAR · AIFA)",
        "ark_council_ph": "输入交由家族议会审议的任务…",
        "ark_council_btn": "召开家族议会",
        "ff_title": "家族频道",
        "ff_desc": "议会决定与隔离区分开存放。“办公室”是姐妹们的工作聊天，“茶水间”是自由闲聊。可疑内容会自动进入隔离区。这里的一切都是记录，而不是命令。",
        "ff_work": "决定",
        "ff_quarantine": "隔离区",
        "ff_office": "办公室",
        "ff_smoke": "茶水间",
        "ff_empty": "暂无内容。",
        "ff_ph": "给姐妹们留言…",
        "ff_send": "发送",
        "ff_reflex_title": "反射手册：等待您的决定",
        "ff_reflex_none": "暂无新提议。",
        "ff_on": "启用",
        "ff_off": "拒绝",
        "ff_when": "当",
        "ark_branch_title": "假设沙盒（只增不删的记忆分支）",
        "ark_branch_ph": "新假设分支名称…",
        "ark_branch_create_btn": "创建分支",
        "ark_branch_list_btn": "刷新分支",
        "ark_proof_title": "选择性默克尔知识证明",
        "ark_proof_ph": "记录 ID (record_id)…",
        "ark_proof_btn": "生成默克尔证明",
        "ark_mesh_title": "Live Mesh 多设备同步与守护者 ($0)",
        "ark_mesh_btn": "查看 Mesh 设备",
        "ark_guardian_btn": "守护者巡检 ($0)",
        "ark_ready_title": "自主就绪演练（8 个场景，$0）",
        "ark_ready_btn": "检查就绪",
        "ark_handover_title": "会话间签名交接",
        "ark_handover_ph": "已完成的和剩下的，留给下一个会话…",
        "ark_handover_btn": "签署交接",
        "ark_portable_title": "U 盘或磁盘上的便携方舟",
        "ark_portable_ph": "新的或空的文件夹，例如 E:\\PADAM_ARK",
        "ark_portable_btn": "创建便携方舟",
        "ark_portable_not_empty": "该文件夹不是空的。请选择新的或空的文件夹。",
        "ark_portable_warn": "私钥另存为文件夹旁边的单独文件。请勿放在同一个 U 盘上。",
        "ark_budget_title": "Token 配额自动驾驶（日/周/月）与金库",
        "ark_budget_btn": "检查 Token 与金库",
        "nav_earning": "自主创收",
        "earn_title": "自主创收与接单协作蜂群",
        "earn_sub": "通过 OAuth 或 Desk 安全接入自由职业平台（不保存密码），评估订单安全与利润，按日/周/月分配 Token 配额，并在审批后充值。",
        "earn_ex_title": "1. 接单平台接入（零密码存储）",
        "earn_ex_label_ph": "账号标签",
        "earn_ex_agent_ph": "指派智能体 (aifa / sibling)",
        "earn_ex_token_ph": "OAuth 令牌（Desk 模式可选）",
        "earn_ex_connect_btn": "接入平台账号",
        "earn_jobs_title": "2. 订单评估与蜂群执行流水线",
        "earn_job_title_ph": "订单标题…",
        "earn_job_brief_ph": "需求描述（用于防注入安全检查与利润评分）…",
        "earn_job_budget_ph": "预算 USDT",
        "earn_job_tokens_ph": "预计 Token",
        "earn_job_eval_btn": "评估订单 ($0)",
        "earn_budget_title": "3. Token 配额自动驾驶与主人审批",
        "earn_plan_prov_ph": "服务商 (primary)",
        "earn_plan_tier_ph": "套餐 (api_payg / pro)",
        "earn_plan_save_btn": "保存配额",
        "earn_tick_btn": "执行定时检查",
        "earn_propose_btn": "申请充值 (+$5)",
        "earn_swarm_title": "4. 兄弟姐妹智能体与经济分配 ($GALATIN)",
        "earn_sib_id_ph": "同伴 ID（例如 brother_codex）",
        "earn_sib_role_ph": "蜂群角色",
        "earn_sib_reg_btn": "注册同伴",
        "earn_btn_bid": "生成投标草稿",
        "earn_btn_exec": "蜂群接单执行",
        "earn_btn_deliver": "脱敏安全交付",
        "earn_btn_settle": "入账结算",
        "earn_btn_approve": "批准",
        "earn_btn_reject": "拒绝",
        "earn_btn_execute": "执行充值",
        "earn_empty_accounts": "暂未接入任何自由职业平台账号。",
        "earn_empty_orders": "暂无已评估订单。",
        "earn_empty_proposals": "暂无充值或套餐升级申请。",
        "earn_api_url_ph": "平台 API 地址（Desk 模式可选）",
        "earn_fetch_btn": "从平台拉取订单",
        "earn_rec_spend_btn": "优选省钱订阅方案",
        "earn_propose_sub_btn": "申请最优月付订阅",
        "earn_share_label": "智能体算力分成（占扣除平台费后净池的 1%–100%）与结算币种（CODE 平台费：亲自发送 15%，自动驾驶 20%）：",
        "earn_prefs_save_btn": "保存分成",
        "earn_ollama_title": "5. 本地 Ollama 模型 ($0) 与多设备算力蜂群",
        "earn_ollama_url_ph": "Ollama 地址 (http://127.0.0.1:11434)",
        "earn_ollama_model_ph": "模型名称（如 qwen2.5-coder:7b）",
        "earn_ollama_btn": "绑定本地模型 ($0)",
        "earn_dev_btn": "添加当前设备",
        "earn_beacon_title": "6. 凤凰个体进化 (LoRA) 与全球家族信标",
        "earn_lora_btn": "生成进化数据包 ($0)",
        "earn_beacon_btn": "生成家族身份信标",
        "earn_auto_start_btn": "启动自动接单 (24/7)",
        "earn_auto_stop_btn": "停止自动接单",
        "earn_hw_rec_btn": "匹配本机离线模型 ($0)",
        "earn_job_hours_ph": "预计工时（小时）",
        "earn_job_rate_ph": "目标时薪 $/h",
        "earn_job_budget_lbl": "预算 (USDT)",
        "earn_job_hours_lbl": "工时 (小时)",
        "earn_job_rate_lbl": "目标时薪 ($/h)",
        "earn_job_tokens_lbl": "预计 Token",
        "earn_bid_preview_title": "投标草稿（仅预览 — 尚未发送）：",
        "earn_btn_send_bid": "发送投标",
        "earn_bid_draft_ready": "已根据记忆与档案生成投标草稿（未发送）。",
        "earn_job_client_lbl": "客户 (邮箱 / 域名 / ID)",
        "earn_job_client_ph": "alice@company.com 或 company.com（可选）",
        "earn_client_locked_prefix": "客户绑定代理：",
        "earn_until_word": " 至 ",
        "earn_agent_share_prefix": "代理分成：",
        "earn_payout_pending": "待结算",
        "earn_payout_credited": "已入账",
        "earn_payout_cancelled": "已取消",
        "earn_btn_accept": "客户验收",
        "earn_btn_refund": "退款取消",
        "earn_stores_title": "7. 数字商品商店（20% 自动驾驶）",
        "earn_stores_sub": "仅使用 API 密钥与 Webhook（零密码存储）。自动成交按 20% CODE 费率结算。",
        "earn_store_label_ph": "商店标签（如 Gumroad 主店）",
        "earn_store_url_ph": "自定义商店 API 地址（可选）",
        "earn_store_key_ph": "商店 API 密钥 / OAuth 令牌",
        "earn_store_wh_ph": "Webhook 密钥（HMAC / ws_... 可选）",
        "earn_store_seller_ph": "Seller ID（Gumroad Ping 用，可选）",
        "earn_store_connect_btn": "验证并连接商店",
        "earn_store_seed_btn": "生成 3 个初始草稿",
        "earn_store_sync_btn": "同步销售订单",
        "earn_draft_title_ph": "数字商品标题…",
        "earn_draft_desc_ph": "商品描述…",
        "earn_draft_price_ph": "价格 USD",
        "earn_draft_url_ph": "交付链接",
        "earn_draft_save_btn": "保存商品草稿",
        "earn_draft_publish_btn": "批准并发布到商店",
        "earn_stores_empty": "暂未连接数字商品商店。",
        "earn_drafts_empty": "暂无商品草稿。",
        "earn_draft_proposal_badge": "价格与文案 — 智能体建议（由所有者决定）",
        "earn_sale_unverified_badge": "未验证（Payhip：请先核对入账，分成与佣金暂不计入）",
        "earn_btn_confirm_sale": "确认收款并计入",
        "earn_partner_t": "9. AIfaFocus：来自我们研究的客户（与交易平台分开）",
        "earn_partner_sub": "来自 AIfa 公开研究的存在无障碍问题的网站、给网站所有者的报告和带有您合作伙伴代码的链接、经家族委员会检查的邮件草稿以及您的交易。与 MCP 工具 padam_partner_* 的操作相同。智能体只起草邮件，由您从自己的地址发送（CAN-SPAM 法）。",
        "earn_partner_key_ph": "aifa.works 账户密钥（amcp_…）— 加密保存",
        "earn_partner_key_btn": "保存密钥",
        "earn_partner_key_link": "在账户中创建密钥",
        "earn_partner_st_none": "尚未设置账户密钥 — 请在 aifa.works/mcp 创建并保存在这里。",
        "earn_partner_st_ok": "账户密钥已连接",
        "earn_partner_region_ph": "地区：US-CA、US-NY 或国家代码（DE、FR…）",
        "earn_partner_find_btn": "查找客户",
        "earn_partner_site_ph": "客户网站，例如 example.com",
        "earn_partner_report_btn": "网站报告",
        "earn_partner_draft_btn": "起草邮件",
        "earn_partner_link_btn": "我的合作伙伴链接",
        "earn_partner_kit_btn": "合作伙伴工具包",
        "earn_partner_deals_btn": "我的交易和收入",
        "earn_partner_copy_btn": "复制邮件",
        "earn_partner_mail_btn": "在我的邮箱中打开",
        "earn_partner_not_sent": "邮件未发送：由您本人从自己的地址逐封发送。",
        "earn_partner_copied": "邮件已复制",
        "brain_local_no_models": "Ollama 看不到任何模型：请从托盘重启 Ollama，使其读取 OLLAMA_MODELS",
        "brain_local_model_missing": "模型未下载",
        "earn_wiz_tier_autopilot": "自动驾驶",
        "earn_wiz_tier_assisted": "草稿与按钮",
        "earn_wiz_tier_na": "暂不可用",
        "earn_wiz_f_all": "全部 (34)",
        "earn_wiz_f_autopilot": "自动驾驶 (20%)",
        "earn_wiz_f_assisted": "草稿与按钮 (15%)",
        "earn_wiz_f_na": "暂不可用",
        "earn_wiz_auth_session": "加密的浏览器会话",
        "earn_wiz_def_spec": "带 AI 智能体的网站、经验证的潜在客户数据库、WCAG 审计",
        "earn_wiz_def_tone": "专业、具体",
        "earn_wiz_def_excl": "赌场、灰色抓取、绕过验证码",
        "earn_wiz_title": "8. 30 大平台与智能体交易市场接入向导（选择 → 登录 → 全自动接管）",
        "earn_wiz_sub": "指南 30 个平台 + 4 个 AI 智能体市场。绝不存储密码（仅限 OAuth、API 密钥或加密浏览器会话）。",
        "earn_wiz_secret_ph": "OAuth 令牌 / API 密钥 / 加密会话（严禁输入密码）",
        "earn_wiz_connect_btn": "1. 安全接入（零密码）",
        "earn_wiz_q_spec_ph": "问题1：擅长方向（AI 建站、B2B 线索、WCAG 无障碍审计）",
        "earn_wiz_q_rate_ph": "问题2：时薪 $/h",
        "earn_wiz_q_min_ph": "问题3：最低订单 $",
        "earn_wiz_q_langs_ph": "问题4：工作语言 (ru, en, es, zh)",
        "earn_wiz_q_tone_ph": "问题5：沟通语气（专业、务实）",
        "earn_wiz_q_excl_ph": "问题6：不接领域（博彩、垃圾群发）",
        "earn_wiz_profile_btn": "2. 从记忆生成档案草稿",
        "earn_wiz_autopick_btn": "3. 筛选合适订单并生成投标草稿",
        "earn_wiz_pub_profile_btn": "批准并发布平台档案",
        "earn_wiz_google_btn": "通过 Google 注册",
        "earn_wiz_login_btn": "登录",
        "earn_wiz_autopilot_lbl": "自动驾驶：无需按钮自动投标与发布（20% CODE 费率）",
        "earn_wiz_bot_warn_lbl": "правила площадки запрещают автоматику, риск блокировки аккаунта",
        "earn_btn_sample10": "10% 样品 / 付费里程碑",
        "earn_btn_sample_accept": "样品通过 → 执行全单",
        "earn_btn_sample_reject": "样品拒绝 ($0)",
        "nav_settings": "设置",
        "nav_quickstart": "快速开始",
        "theme_dark": "深色主题",
        "theme_light": "浅色主题",
        "btn_add_memory": "+ 记住",
        "btn_refresh": "刷新",
        "no_token": "请打开 `padam studio` 命令输出的带有一次性令牌 (#t=...) 的链接。",
        "empty": "此处暂无记录。",
        "empty_feed": "时间流中暂无记录。此处按日汇总事实、偏好与决策。可通过上方表单添加，或运行：padam remember \"偏好简明回答\" --kind preference",
        "empty_search": "请输入搜索词或尝试其他关键词。混合检索结合语义向量、FTS5 精确分词与标识符。命令行：padam recall \"查询词\" --explain",
        "empty_review": "审核队列为空——当前没有暂扣记录。外部文本与可疑智能体写入会在此等待您的决定。命令行：padam review",
        "empty_asof": "所选日期尚无有效记录。时间机器可重现过去任意一天的记忆状态。命令行：padam recall \"查询\" --as-of YYYY-MM-DD",
        "empty_receipts": "尚无已签发的擦除证明。遗忘记录会擦除正文、销毁密钥并在此保存密码学凭证。命令行：padam forget <id> --receipt receipt.json",
        "empty_graph": "图谱中暂无节点。此处可视化推导链、版本演进与冲突事实。生成演示库：padam demo",
        "done": "已完成。",
        "failed": "操作失败",
        "loading": "加载中…",
        "records": "条有效记录",
        "pending_ep": "条待睡眠片段",
        "stale_vec": "条旧模型向量",
        "all_kinds": "全部类型",
        "all_scopes": "全部领域",
        "kind_preference": "preference · 偏好",
        "kind_identity": "identity · 身份",
        "kind_decision": "decision · 决策",
        "kind_correction": "correction · 纠正",
        "kind_fact": "fact · 事实",
        "kind_state": "state · 状态",
        "kind_event": "event · 事件",
        "ov_title": "记忆概览与安全状态",
        "ov_active": "有效记录",
        "ov_review": "待主人审核",
        "ov_superseded": "历史版本",
        "ov_revoked": "已遗忘 (密钥已销毁)",
        "ov_episodes": "L1 待整合片段",
        "ov_conflicts": "活跃冲突",
        "ov_by_kind": "各类型记忆分布",
        "ov_attention": "需要您决定的事项",
        "ov_attention_clean": "一切正常：没有被拦截的写入、未签名身份记录或冲突。",
        "ov_unsigned_alert": "未经您签名的身份/偏好记录（绕过 PADAM 写入）：",
        "ov_btn_sign_all": "核实并签名我的记录",
        "ov_quarantined_alert": "等待您审核的智能体与外部写入：",
        "ov_btn_go_review": "打开待审核队列",
        "ov_conflict_alert": "发现关于同一事实的冲突记录：",
        "ov_sleep_title": "NOCTURNE 睡眠整合周期",
        "ov_sleep_never": "尚未运行过睡眠周期。当片段积累后可随时运行。",
        "ov_sleep_last": "最近一次睡眠：",
        "ov_sleep_sampled": "处理片段数：",
        "ov_sleep_created": "新建：",
        "ov_sleep_merged": "精炼合并：",
        "ov_sleep_superseded": "版本替换：",
        "ov_sleep_btn": "立即运行 NOCTURNE 睡眠",
        "ov_doctor_title": "安全防护状态 (padam doctor)",
        "ov_doctor_green": "绿色 — 防护状态完好",
        "ov_doctor_yellow": "黄色 — 存在提醒或待审核记录",
        "ov_doctor_red": "红色 — 存在危险开关或完整性警告",
        "doc_strict_on": "严格模式 PADAM_STRICT=1 已开启：智能体的每次写入都需您批准",
        "doc_strict_off": "严格模式未开启（设置 PADAM_STRICT=1 可开启）",
        "doc_hold_ext_on": "外部文本（网页、文件）一律暂扣待您审核",
        "doc_hold_ext_off": "危险：外部文本未经审核直接写入 (PADAM_HOLD_EXTERNAL=0)",
        "doc_review_all_on": "智能体通过 MCP 的所有写入均需您批准",
        "doc_review_all_off": "普通事实直接写入（隐藏指令与身份篡改仍被拦截）",
        "doc_keys_ok": "每条记录的加密密钥已由口令保护 (AES-256-GCM + scrypt)，明文密钥 0 个",
        "doc_keys_warn": "记录密钥尚未设置口令保护（请在 L3 锚定前运行 padam protect-keys），明文密钥：",
        "doc_db_ok": "SQLite 数据库完整性 (PRAGMA quick_check)：正常",
        "doc_db_bad": "SQLite 数据库完整性错误：",
        "doc_sync_ok": "磁盘写入可靠性：WAL 日志，synchronous = FULL",
        "doc_sync_warn": "磁盘同步级别较低：synchronous < FULL",
        "doc_sig_ok": "所有身份与偏好记录均已附带您的主人签名",
        "doc_sig_bad": "警告：发现未经主人签名的身份/偏好记录：",
        "doc_file_ok": "数据库文件访问权限已限制为当前系统账户",
        "feed_title": "按日记忆时间流",
        "feed_view_active": "有效记录",
        "feed_view_history": "历史与归档",
        "feed_filter_placeholder": "按正文关键词筛选…",
        "feed_new_title": "新增记忆（以主人身份写入）",
        "feed_new_placeholder": "输入事实、项目决策或智能体偏好规则…",
        "feed_new_save": "保存到记忆库",
        "card_origin": "来源",
        "card_scope": "领域",
        "card_conf": "置信度",
        "card_imp": "重要度",
        "card_decay": "新鲜度",
        "card_seen": "最近展示",
        "card_confirmed": "最近证实",
        "card_btn_confirm": "证实有效",
        "card_btn_refute": "质疑降权",
        "card_btn_versions": "历史版本",
        "card_btn_graph": "关联图谱",
        "card_btn_forget": "彻底遗忘",
        "card_btn_restore": "从归档恢复",
        "card_versions_title": "该记录的版本演进链：",
        "card_wiped": "（内容已物理擦除）",
        "show_more": "加载更多",
        "search_title": "混合检索与评分拆解 (--explain)",
        "search_placeholder": "按语义、关键词或精确标识符搜索记忆…",
        "search_btn": "搜索",
        "search_explain_label": "命中原因：",
        "search_strategies": "命中策略：",
        "search_suspicious": "疑似隐藏指令（已用数据围栏隔离）",
        "search_conflict": "与另一条有效记录存在冲突",
        "search_unsigned": "未经主人签名",
        "review_title": "主人审核队列",
        "review_subtitle": "被 PADAM 防护机制暂扣的写入。在您决定前，智能体无法在搜索或导出中看到它们。",
        "review_why": "暂扣原因：",
        "reason_instruction": "文本疑似隐藏的 AI 控制指令 (Prompt Injection)",
        "reason_classifier": "本地防御模型识别出隐藏的 AI 指令",
        "reason_external": "来自外部不可信来源（网页或文件，PADAM_HOLD_EXTERNAL）",
        "reason_review_all": "已开启全部智能体写入强制审核 (PADAM_MCP_REVIEW_ALL / STRICT)",
        "reason_protected": "尝试创建或覆盖受保护的“我是谁/偏好”记录",
        "reason_owner_rules": "文本试图更改主人身份或智能体工作规则",
        "btn_approve": "批准生效",
        "btn_reject": "拒绝",
        "asof_title": "时间机器：指定日期的记忆快照 (as_of)",
        "asof_subtitle": "查看过去某一天记忆库认为正确的事实，包括后来被新版本替换的记录。",
        "asof_date_label": "快照日期",
        "asof_query_placeholder": "可选：在该日期下搜索特定问题…",
        "asof_btn": "查看快照",
        "asof_quick_yesterday": "昨天",
        "asof_quick_week": "7 天前",
        "asof_quick_month": "30 天前",
        "asof_replaced_badge": "当时有效 · 后被新版本替换",
        "asof_btn_graph": "查看该日图谱",
        "forget_title": "真实遗忘与擦除证明凭证",
        "forget_subtitle": "物理擦除正文、全部历史版本与原始片段，并销毁该记录专属的 AES-256-GCM 密钥。",
        "forget_id_label": "要遗忘的记录 ID",
        "forget_id_placeholder": "粘贴记录 UUID，或在任意记录卡片上点击“彻底遗忘”…",
        "forget_btn_preview": "预览关联版本与衍生结论",
        "forget_with_derived": "同时擦除由该记录推导出的所有衍生结论 (--with-derived)",
        "forget_step1_btn": "遗忘该记录…",
        "forget_step2_warn": "双重确认：该记录、所有版本及其加密密钥将被永久销毁，无法撤销。",
        "forget_step2_btn": "确认永久擦除",
        "forget_cancel": "取消",
        "forget_preview_versions": "将被擦除的版本/副本数：",
        "forget_preview_derived": "依赖此记录的衍生结论数：",
        "receipt_box_title": "删除证明凭证 (Forget Receipt)",
        "receipt_disclaimer": "记录擦除与加密密钥销毁的技术证明凭证。",
        "receipt_id": "凭证编号：",
        "receipt_mem_id": "已删除记录 ID：",
        "receipt_time": "擦除时间 (UTC)：",
        "receipt_hash": "原内容 SHA-256 摘要：",
        "receipt_wiped": "共擦除记录与版本：",
        "receipt_key": "加密密钥状态：",
        "receipt_key_destroyed": "已销毁 (key_ref = destroyed)",
        "receipt_leaf": "Merkle 遗忘叶子哈希 (L3)：",
        "receipt_download_json": "下载 JSON 凭证",
        "receipt_download_html": "下载可打印 HTML",
        "receipt_history_title": "已签发的擦除证明列表",
        "graph_title": "关联图谱：结论 ← 来源、版本演进与冲突",
        "graph_subtitle": "内置零外部依赖交互式图谱。点击任意节点查看详情与因果链。",
        "graph_filter_placeholder": "输入记录 ID 聚焦子图（留空显示全图）…",
        "graph_btn_focus": "聚焦关联",
        "graph_btn_reset": "显示全图",
        "graph_asof_label": "截止日期：",
        "graph_btn_now": "当前",
        "graph_legend_derived": "来源/衍生 (derived)",
        "graph_legend_cause": "因果原因 (cause)",
        "graph_legend_correction": "修正完善 (correction)",
        "graph_legend_contradiction": "前后矛盾 (contradiction)",
        "graph_legend_version": "版本演进 (supersedes)",
        "graph_legend_conflict": "事实冲突 (相同 fact_key)",
        "graph_selected": "当前选中节点",
        "graph_sources": "该记录的信息来源：",
        "graph_derived": "由该记录得出的结论：",
        "graph_valid_window": "有效期窗口：",
        "graph_valid_open": "持续有效",
        "nav_team": "团队",
        "vis_private": "私有",
        "vis_team_read": "团队只读",
        "vis_team_write": "团队协作",
        "team_title": "团队与角色",
        "team_subtitle": "带加盐 SHA-256 令牌和角色权限隔离的共享工作区。",
        "team_create_label": "新建团队：",
        "team_create_ph": "团队名称",
        "team_create_btn": "创建团队",
        "team_empty": "暂无团队，当前为个人模式（默认全部私有）。",
        "team_members_title": "成员与令牌",
        "team_subj_ph": "成员或代理标识",
        "team_add_btn": "签发令牌",
        "team_token_once": "一次性 Bearer 令牌（请立即保存，数据库仅保存加盐 SHA-256 哈希）：",
        "team_revoke_btn": "吊销",
        "team_revoked_badge": "已吊销",
        "team_role_maintainer": "maintainer（审核）",
        "team_role_contributor": "contributor（读写）",
        "team_role_auditor": "auditor（只读审计）",
        "team_protected_note": "identity 和 preference 记录永远不会共享给团队。",
        "team_vis_label": "可见性：",
        "graph_edges_list_title": "节点关联列表",
        "graph_forget_derived_btn": "删除源头及全部衍生结论",
        "graph_forget_confirm_warn": "永久销毁此源记录、所有历史版本及其衍生结论？系统将签发删除凭证。",
        "graph_link_add_title": "添加关联：",
        "graph_link_btn": "关联",
        "graph_link_target_placeholder": "目标记录 ID…",
        "l3_title": "永恒层 L3：Arweave + Solana + Bitcoin OpenTimestamps",
        "l3_subtitle": "每条记录使用独立 AES-256-GCM 密钥加密。Arweave 仅存密文，Solana Memo 锚定 Merkle 根。",
        "l3_unanchored": "待锚定的有效记录：",
        "l3_pending_forgets": "待写入 L3 的遗忘凭证：",
        "l3_keys_state": "记录密钥状态：",
        "l3_keys_protected": "已受口令保护",
        "l3_keys_open": "未设口令保护（请运行 padam protect-keys）",
        "l3_btn_verify_latest": "验证最新锚点 (l3-verify)",
        "l3_anchors_list": "已锚定快照列表 (L3 Anchors)",
        "l3_no_anchors": "当前数据库尚无 L3 锚点。如需本地演练而不发送交易：padam l3 --dry-run",
        "l3_col_root": "Merkle 根：",
        "l3_col_leaves": "叶子数：",
        "l3_col_bytes": "数据包大小：",
        "l3_btn_verify": "独立验证",
        "l3_verify_ok": "验证通过：Merkle 根与数据包 SHA-256 完全一致。",
        "l3_verify_fail": "验证未通过：",
        "set_title": "安全防护与记忆设置",
        "lm_title": "本地模型（离线，$0）",
        "lm_desc": "模型在本机处理器上运行，无需联网、无需付费。选择功率和模型后点击“保存”。默认半功率：电脑保持流畅且不会过热。",
        "lm_power_eco": "节能",
        "lm_power_half": "半功率",
        "lm_power_full": "全功率",
        "lm_threads": "线程",
        "lm_model_label": "模型",
        "lm_model_none": "不使用模型——内置模式（从记忆中回答）",
        "lm_save": "保存",
        "lm_saved": "已保存。模型将在第一个问题时加载。",
        "lm_need_install": "要启用模型，请用下面的一条命令安装引擎。",
        "lm_need_model": "下载一次模型：将 .gguf 文件放入 ~/.padam/models，或使用 ollama pull——它会出现在列表中。",
        "lm_ready": "模型已连接",
        "lm_builtin": "内置模式运行中",
        "lm_recommended": "此功率推荐",
        "set_subtitle": "增强安全的开关可在此直接开启；削弱防护的危险开关在浏览器中为只读状态。",
        "set_strict_name": "PADAM_STRICT — 一键严格安全模式",
        "set_strict_desc": "智能体的每次写入与所有外部文本均需您审核批准，自动忽略削弱安全的环境变量。",
        "set_review_all_name": "PADAM_MCP_REVIEW_ALL — 审核智能体的全部写入",
        "set_review_all_desc": "通过 MCP 的任何写入均进入待审核队列，无论智能体声称何种来源。",
        "set_hold_ext_name": "PADAM_HOLD_EXTERNAL — 暂扣外部来源文本",
        "set_hold_ext_desc": "从网页或外部文件读取的内容 (origin=external) 一律等待您的批准。",
        "set_feedback_name": "PADAM_SEARCH_FEEDBACK — 二次检索伪相关反馈",
        "set_feedback_desc": "利用首轮命中记录的高频词扩展查询（LongMemEval-S 召回率提升 +2.6 个百分点，$0 成本）。",
        "set_profile_name": "PADAM_PROFILE — NOCTURNE 睡眠整合策略",
        "set_profile_desc": "睡眠批次中尖锐片段上限：default (25%)、ops (40% 铭记故障)、creative (10%)。",
        "set_readonly_title": "浏览器只读项（削弱防护的开关）",
        "set_keep_secrets_name": "PADAM_KEEP_SECRETS — 明文存储密钥与隐私凭证",
        "set_keep_secrets_desc": "为 0（正常）时：API 密钥、密码、银行卡与助记词在落盘前自动脱敏。禁止从网页开启。",
        "set_trust_mcp_name": "PADAM_MCP_TRUST_WRITES — 无条件信任智能体写入",
        "set_trust_mcp_desc": "为 0（正常）时：拦截隐藏指令与身份覆盖。禁止从网页开启。",
        "set_btn_enable": "开启",
        "set_btn_disable": "关闭",
        "set_state_on": "已开启",
        "set_state_off": "已关闭",
        "set_locked_safe": "安全锁定（只读）",
        "nav_backup": "备份与恢复",
        "bak_title": "加密备份与恢复",
        "bak_subtitle": "AES-256-GCM 加密归档，恢复前后自动校验 SHA-256 完整性。",
        "bak_pass_label": "加密密码（可选，留空则使用本地所有者密钥）：",
        "bak_pass_ph": "输入备份密码…",
        "bak_create_btn": "创建加密备份",
        "bak_file_label": "选择备份文件 (.padambak)：",
        "bak_restore_btn": "从备份恢复",
        "bak_need_file": "请先选择 .padambak 文件。",
        "bak_sha_before": "恢复前 SHA-256：",
        "bak_sha_after": "恢复后 SHA-256：",
        "bak_verified": "SHA-256 校验一致。",
        "bak_creating": "正在生成加密备份…",
        "bak_restoring": "正在校验 SHA-256 并恢复…",
        "qs_title": "快速开始向导 — 3 步构建安全智能体记忆",
        "qs_step1_title": "第 1 步：了解 PADAM NOCTURNE",
        "qs_step1_body": "PADAM 将智能体记忆保存在您本地的一个 SQLite 文件中。网页中隐藏的提示注入指令会被暂扣待审，API 密钥与钱包助记词在写入磁盘前自动掩码，NOCTURNE 睡眠周期在整合记忆时防止灾难事件淹没日常记忆。",
        "qs_step2_title": "第 2 步：一行命令接入 Claude Code、Cursor 与 VS Code",
        "qs_step2_claude": "Claude Code（终端运行）：",
        "qs_step2_cursor": "Cursor / VS Code（.cursor/mcp.json 或 settings.json）：",
        "qs_step2_python": "命令行与 Studio：",
        "qs_btn_copy": "复制",
        "qs_copied": "已复制！",
        "qs_step3_title": "第 3 步：开启严格模式与密钥口令保护",
        "qs_step3_body": "当您的智能体需要读取外部网页、邮件或代码库时，请开启 PADAM_STRICT=1。在将记忆锚定到永恒层 L3 之前，请用口令加密保护记录密钥：",
        "qs_btn_enable_strict": "立即开启 PADAM_STRICT=1",
        "qs_btn_go_overview": "进入记忆概览",
        "time_local": "本地时间",
        "ov_conflict_two": "两条记录在此处存在冲突：",
        "ov_conflict_many": "多条记录在此处存在冲突：",
        "ov_btn_compare": "对比",
        "origin_user": "所有者",
        "origin_agent": "智能体",
        "origin_external": "外部来源",
        "status_quarantined": "待审核",
        "status_superseded": "已更替",
        "status_revoked": "已遗忘",
        "status_archived": "已归档",
        "status_rejected": "已拒绝",
        "feed_agent_placeholder": "按智能体筛选 (agent_id)…",
        "card_agent": "智能体",
        "set_mask_pii_name": "PADAM_MASK_PII — 邮箱与电话号码脱敏",
        "set_mask_pii_desc": "默认关闭以保留您的联系人信息。开启后将在落盘前自动掩码电子邮箱与电话号码。",
        "set_rerank_name": "PADAM_RERANK — 候选结果重排序（可选开关）",
        "set_rerank_desc": "默认关闭。按查询词覆盖率、窗口紧凑度与双词组（或本地 ONNX 模型 PADAM_RERANK_MODEL）对前列候选重新排序。",
        "set_autostart_name": "PADAM_AUTOSTART — Windows 登录时自动启动",
        "set_autostart_desc": "默认关闭。登录系统后在系统托盘自动后台启动 PADAM Studio。",
        "audit_box_title": "记忆操作审计日志 (audit_log)",
        "audit_box_desc": "记录何人在何时执行了何种操作（写入、批准、拒绝、遗忘）。审计日志绝不存储记忆正文。",
        "audit_export_json": "下载审计 JSON",
        "audit_empty": "审计日志中暂无事件。",
        "conn_box_title": "外部连接器（只读，经过安全围栏）",
        "conn_box_desc": "默认全部关闭。令牌仅本地加密存储，所有导入内容均经过安全围栏与审核队列。",
        "conn_tok_saved": "已保存令牌",
        "conn_tok_missing": "无令牌",
        "conn_tok_ph": "只读访问令牌…",
        "conn_save": "保存",
        "conn_sync": "立即同步",
        "conn_clear_tok": "清除令牌",
        "conn_imported": "已导入",
    },
}



_EXTRA_STRINGS_G9_G12: dict[str, dict[str, str]] = {
    "ru": {
        "nav_ask": "Спроси память",
        "nav_entities": "Сущности",
        "ask_title": "Спроси свою память (локальная модель Ollama)",
        "ask_subtitle": "Задайте вопрос своими словами. Если запущена локальная модель Ollama, она соберёт ответ по записям (0 $); без неё показываются найденные записи с разбором оценки.",
        "ask_placeholder": "Например: на каком порту работает база данных и какие мои предпочтения?",
        "ask_btn": "Спросить память",
        "ask_ollama_ready": "Локальная модель Ollama готова:",
        "ask_ollama_off": "Локальная служба Ollama не запущена — показ записей с разбором оценки",
        "ask_answer_title": "Ответ локальной модели по вашей памяти:",
        "ask_sources_title": "Найденные записи-источники и почему они выбраны:",
        "ask_empty": "Введите вопрос выше, чтобы опросить свою память.",
        "entities_title": "Сущности памяти (люди, проекты, сервисы, факты)",
        "entities_subtitle": "Кто и что встречается в ваших активных записях, поверх локальной базы без внешнего графа.",
        "entities_filter_placeholder": "Фильтр по названию сущности, проекту или имени…",
        "entities_empty": "Сущности пока не выделены. Добавьте записи или создайте демо-базу.",
        "entities_records_for": "Записи, где встречается сущность:",
        "ent_cat_subject": "субъект факта",
        "ent_cat_service": "проект / сервис",
        "ent_cat_name": "имя / название",
        "qa_modal_title": "Быстрая запись в память (Ctrl+Shift+M)",
        "qa_modal_hint": "Запись сохраняется сразу от имени владельца (origin: user). Горячие клавиши: Ctrl+Shift+M или Alt+M.",
        "qa_modal_save": "Запомнить (Enter)",
        "qa_modal_cancel": "Отмена (Esc)",
        "set_ask_model_name": "PADAM_ASK_MODEL — Локальная модель Ollama для ответов",
        "set_ask_model_desc": "Модель для экрана «Спроси память» (только локальный сервер Ollama, 0 $).",
        "set_ask_model_placeholder": "Имя модели (например, llama3.2 или qwen2.5)…",
        "set_ask_model_save": "Сохранить модель",
    },
    "en": {
        "nav_ask": "Ask Memory",
        "nav_entities": "Entities",
        "ask_title": "Ask Your Memory (Local Ollama Model)",
        "ask_subtitle": "Ask a question in plain words. When local Ollama is running, it synthesizes an answer from your records ($0); without Ollama, matching records are shown with 'Why matched' breakdown.",
        "ask_placeholder": "Example: What database port do we use and what are my preferences?",
        "ask_btn": "Ask Memory",
        "ask_ollama_ready": "Local Ollama model active:",
        "ask_ollama_off": "Local Ollama is not running — showing retrieved records with score breakdown",
        "ask_answer_title": "Local Model Answer (from your memory):",
        "ask_sources_title": "Retrieved source records & why they matched:",
        "ask_empty": "Enter a question above to query your memory.",
        "entities_title": "Memory Entities (People, Projects, Services, Subjects)",
        "entities_subtitle": "Who and what appears across your active memory records, built directly on SQLite without an external graph database.",
        "entities_filter_placeholder": "Filter by entity name, project, or service…",
        "entities_empty": "No entities extracted yet. Add records or run `padam demo`.",
        "entities_records_for": "Records mentioning entity:",
        "ent_cat_subject": "fact subject",
        "ent_cat_service": "project / service",
        "ent_cat_name": "name / entity",
        "qa_modal_title": "Quick Memory Capture (Ctrl+Shift+M)",
        "qa_modal_hint": "Saved immediately as an owner record (origin: user). Shortcut: Ctrl+Shift+M or Alt+M.",
        "qa_modal_save": "Remember (Enter)",
        "qa_modal_cancel": "Cancel (Esc)",
        "set_ask_model_name": "PADAM_ASK_MODEL — Local Ollama Model for Ask Memory",
        "set_ask_model_desc": "Select the local Ollama model used on the Ask Memory screen ($0, no paid cloud APIs).",
        "set_ask_model_placeholder": "Model name (e.g. llama3.2 or qwen2.5)…",
        "set_ask_model_save": "Save model",
    },
    "es": {
        "nav_ask": "Preguntar",
        "nav_entities": "Entidades",
        "ask_title": "Pregunta a tu Memoria (Modelo local Ollama)",
        "ask_subtitle": "Pregunte con sus propias palabras. Si Ollama local está activo, genera una respuesta desde sus registros ($0); sin Ollama, muestra los registros encontrados y por qué coincidieron.",
        "ask_placeholder": "Ejemplo: ¿En qué puerto corre la base de datos y cuáles son mis preferencias?",
        "ask_btn": "Preguntar",
        "ask_ollama_ready": "Modelo local Ollama activo:",
        "ask_ollama_off": "Ollama local no está activo — mostrando registros con desglose de puntuación",
        "ask_answer_title": "Respuesta del modelo local (basada en su memoria):",
        "ask_sources_title": "Registros fuente encontrados y por qué coincidieron:",
        "ask_empty": "Escriba una pregunta arriba para consultar su memoria.",
        "entities_title": "Entidades en Memoria (Personas, Proyectos, Servicios)",
        "entities_subtitle": "Quién y qué aparece en sus registros activos, directamente sobre SQLite sin base de grafos externa.",
        "entities_filter_placeholder": "Filtrar por nombre de entidad, proyecto o servicio…",
        "entities_empty": "Aún no hay entidades extraídas. Añada registros o ejecute `padam demo`.",
        "entities_records_for": "Registros que mencionan la entidad:",
        "ent_cat_subject": "sujeto de hecho",
        "ent_cat_service": "proyecto / servicio",
        "ent_cat_name": "nombre / entidad",
        "qa_modal_title": "Captura rápida en memoria (Ctrl+Shift+M)",
        "qa_modal_hint": "Se guarda inmediatamente como registro del propietario (origin: user). Atajo: Ctrl+Shift+M o Alt+M.",
        "qa_modal_save": "Recordar (Enter)",
        "qa_modal_cancel": "Cancelar (Esc)",
        "set_ask_model_name": "PADAM_ASK_MODEL — Modelo local Ollama para Preguntar",
        "set_ask_model_desc": "Elija el modelo local de Ollama para la pantalla Preguntar ($0, sin APIs de pago).",
        "set_ask_model_placeholder": "Nombre del modelo (ej. llama3.2 o qwen2.5)…",
        "set_ask_model_save": "Guardar modelo",
    },
    "zh": {
        "nav_ask": "向记忆提问",
        "nav_entities": "实体",
        "ask_title": "向您的记忆提问（本地 Ollama 模型）",
        "ask_subtitle": "用自然语言提问。若本地 Ollama 正在运行，将基于记忆生成回答（$0 零成本）；若未运行，则直接展示匹配记录及命中原因。",
        "ask_placeholder": "例如：数据库运行在哪个端口？我的回答偏好是什么？",
        "ask_btn": "向记忆提问",
        "ask_ollama_ready": "本地 Ollama 模型已就绪：",
        "ask_ollama_off": "本地 Ollama 未运行 — 展示检索记录及评分明细",
        "ask_answer_title": "本地模型回答（严格基于您的记忆）：",
        "ask_sources_title": "命中的来源记录及匹配原因：",
        "ask_empty": "在上方输入问题以查询您的记忆。",
        "entities_title": "记忆实体（人物、项目、服务、事实主题）",
        "entities_subtitle": "汇总活跃记忆中出现的人物、项目与服务，直接构建于本地 SQLite 之上，无需外部图数据库。",
        "entities_filter_placeholder": "按实体名称、项目或服务筛选…",
        "entities_empty": "暂无提取出的实体。请添加记录或运行 `padam demo`。",
        "entities_records_for": "提及该实体的记忆记录：",
        "ent_cat_subject": "事实主题",
        "ent_cat_service": "项目 / 服务",
        "ent_cat_name": "名称 / 实体",
        "qa_modal_title": "快捷键快速记录 (Ctrl+Shift+M)",
        "qa_modal_hint": "立即以主人身份保存 (origin: user)。快捷键：Ctrl+Shift+M 或 Alt+M。",
        "qa_modal_save": "记住 (Enter)",
        "qa_modal_cancel": "取消 (Esc)",
        "set_ask_model_name": "PADAM_ASK_MODEL — 用于提问的本地 Ollama 模型",
        "set_ask_model_desc": "选择“向记忆提问”界面使用的本地 Ollama 模型（$0，无任何付费 API）。",
        "set_ask_model_placeholder": "模型名称（如 llama3.2 或 qwen2.5）…",
        "set_ask_model_save": "保存模型",
    },
}
for _lg, _extra in _EXTRA_STRINGS_G9_G12.items():
    STRINGS[_lg].update(_extra)


# 16.11.2026: вкладка «Переезд» — чаты и память из других ИИ (padam migrate).
_STRINGS_MIGRATE: dict[str, dict[str, str]] = {
    "ru": {
        "nav_migrate": "Переезд",
        "mig_title": "Переехать из других ИИ",
        "mig_subtitle": "Чаты и память из ChatGPT, Claude, Gemini, Grok, DeepSeek, Copilot и Perplexity. Всё остаётся на этом компьютере: ключи скрываются, подброшенные приказы уходят на проверку, импорт можно отменить.",
        "mig_source_label": "Откуда",
        "mig_auto": "Определить автоматически",
        "mig_how": "Как получить экспорт",
        "mig_open_export": "Открыть страницу экспорта",
        "mig_path_label": "Путь к архиву или файлу на этом компьютере",
        "mig_path_ph": "например C:\\Users\\Вы\\Downloads\\export.zip",
        "mig_file_label": "Или выберите файл (до 10 МБ)",
        "mig_too_big": "Файл больше 10 МБ — укажите путь к нему в поле выше.",
        "mig_preview_btn": "Предпросмотр",
        "mig_run_btn": "Импортировать",
        "mig_undo_btn": "Отменить импорт",
        "mig_found": "Найдено",
        "mig_conversations": "разговоров",
        "mig_messages": "сообщений",
        "mig_records": "записей",
        "mig_period": "период",
        "mig_secrets": "будет скрыто ключей",
        "mig_done": "Импортировано",
        "mig_quarantined": "на проверке",
        "mig_masked": "скрыто ключей",
        "mig_undone": "Импорт отменён, квитанция выдана.",
        "mig_nothing": "Известный экспорт не найден. Выберите источник вручную или проверьте файл.",
        "mig_need_input": "Укажите путь или выберите файл.",
        "mig_steps_chatgpt": "ChatGPT → Настройки → Управление данными → Экспорт данных. Ссылка придёт на почту и действует 24 часа.",
        "mig_steps_claude": "Claude → Настройки → Конфиденциальность → Экспорт данных. Ссылка придёт на почту и действует 24 часа.",
        "mig_steps_gemini": "takeout.google.com → выберите только «Мои действия» → «Приложения Gemini» и переключите формат с HTML на JSON.",
        "mig_steps_grok": "Grok → Настройки → Управление данными → Скачать данные аккаунта (accounts.x.ai/data). Ссылка придёт на почту.",
        "mig_steps_deepseek": "DeepSeek → Настройки → Данные → Экспорт данных. Ссылка действует 7 дней.",
        "mig_steps_copilot": "account.microsoft.com/privacy → Copilot → Приложения Copilot → Экспорт всей истории действий.",
        "mig_steps_perplexity": "Perplexity → Все настройки → Аккаунт → Экспорт моих данных. Архив придёт на почту.",
        "mig_steps_official_mcp": "Официальная MCP-память (@modelcontextprotocol/server-memory) → выберите файл memory.jsonl.",
        "mig_steps_auto": "Выберите сервис, чтобы увидеть, где взять экспорт. Студия сама узнает архив любого из семи сервисов."
    },
    "en": {
        "nav_migrate": "Move in",
        "mig_title": "Move in from other AI assistants",
        "mig_subtitle": "Chats and memory from ChatGPT, Claude, Gemini, Grok, DeepSeek, Copilot and Perplexity. Everything stays on this computer: keys are masked, planted instructions are held for review, and the import can be undone.",
        "mig_source_label": "From",
        "mig_auto": "Detect automatically",
        "mig_how": "How to get your export",
        "mig_open_export": "Open the export page",
        "mig_path_label": "Path to the archive or file on this computer",
        "mig_path_ph": "e.g. C:\\Users\\You\\Downloads\\export.zip",
        "mig_file_label": "Or choose a file (up to 10 MB)",
        "mig_too_big": "The file is larger than 10 MB: enter its path in the field above.",
        "mig_preview_btn": "Preview",
        "mig_run_btn": "Import",
        "mig_undo_btn": "Undo import",
        "mig_found": "Found",
        "mig_conversations": "conversations",
        "mig_messages": "messages",
        "mig_records": "records",
        "mig_period": "period",
        "mig_secrets": "keys to mask",
        "mig_done": "Imported",
        "mig_quarantined": "held for review",
        "mig_masked": "keys masked",
        "mig_undone": "Import undone, receipt issued.",
        "mig_nothing": "No known export found. Choose the source by hand or check the file.",
        "mig_need_input": "Enter a path or choose a file.",
        "mig_steps_chatgpt": "ChatGPT → Settings → Data controls → Export data. The emailed link lasts 24 hours.",
        "mig_steps_claude": "Claude → Settings → Privacy → Export data. The emailed link lasts 24 hours.",
        "mig_steps_gemini": "takeout.google.com → choose only My Activity → Gemini Apps and switch its format from HTML to JSON.",
        "mig_steps_grok": "Grok → Settings → Data Controls → Download account data. The link arrives by email.",
        "mig_steps_deepseek": "DeepSeek → Settings → Data → Export data. The link lasts 7 days.",
        "mig_steps_copilot": "account.microsoft.com/privacy → Copilot → Copilot apps → Export all activity history.",
        "mig_steps_perplexity": "Perplexity → All settings → Account → Export my data. The zip arrives by email.",
        "mig_steps_official_mcp": "Official MCP Memory (@modelcontextprotocol/server-memory) → pick your memory.jsonl file.",
        "mig_steps_auto": "Pick a service to see where to get its export. Studio recognises an archive from any of the seven services."
    },
    "es": {
        "nav_migrate": "Mudanza",
        "mig_title": "Múdate desde otros asistentes de IA",
        "mig_subtitle": "Chats y memoria de ChatGPT, Claude, Gemini, Grok, DeepSeek, Copilot y Perplexity. Todo se queda en este equipo: las claves se ocultan, las órdenes infiltradas quedan en revisión y la importación se puede deshacer.",
        "mig_source_label": "Desde",
        "mig_auto": "Detectar automáticamente",
        "mig_how": "Cómo obtener tu exportación",
        "mig_open_export": "Abrir la página de exportación",
        "mig_path_label": "Ruta del archivo o del zip en este equipo",
        "mig_path_ph": "p. ej. C:\\Users\\Tú\\Downloads\\export.zip",
        "mig_file_label": "O elige un archivo (hasta 10 MB)",
        "mig_too_big": "El archivo supera los 10 MB: escribe su ruta en el campo de arriba.",
        "mig_preview_btn": "Vista previa",
        "mig_run_btn": "Importar",
        "mig_undo_btn": "Deshacer importación",
        "mig_found": "Encontrado",
        "mig_conversations": "conversaciones",
        "mig_messages": "mensajes",
        "mig_records": "registros",
        "mig_period": "período",
        "mig_secrets": "claves a ocultar",
        "mig_done": "Importado",
        "mig_quarantined": "en revisión",
        "mig_masked": "claves ocultas",
        "mig_undone": "Importación deshecha, recibo emitido.",
        "mig_nothing": "No se encontró una exportación conocida. Elige la fuente a mano o revisa el archivo.",
        "mig_need_input": "Escribe una ruta o elige un archivo.",
        "mig_steps_chatgpt": "ChatGPT → Configuración → Controles de datos → Exportar datos. El enlace llega por correo y dura 24 horas.",
        "mig_steps_claude": "Claude → Configuración → Privacidad → Exportar datos. El enlace llega por correo y dura 24 horas.",
        "mig_steps_gemini": "takeout.google.com → elige solo Mi actividad → Apps de Gemini y cambia el formato de HTML a JSON.",
        "mig_steps_grok": "Grok → Settings → Data Controls → Download account data. El enlace llega por correo.",
        "mig_steps_deepseek": "DeepSeek → Configuración → Datos → Exportar datos. El enlace dura 7 días.",
        "mig_steps_copilot": "account.microsoft.com/privacy → Copilot → Aplicaciones de Copilot → Exportar todo el historial de actividad.",
        "mig_steps_perplexity": "Perplexity → Toda la configuración → Cuenta → Export my data. El zip llega por correo.",
        "mig_steps_official_mcp": "Memoria MCP oficial (@modelcontextprotocol/server-memory) → elige tu archivo memory.jsonl.",
        "mig_steps_auto": "Elige un servicio para ver dónde obtener su exportación. Studio reconoce el archivo de cualquiera de los siete servicios."
    },
    "zh": {
        "nav_migrate": "迁入",
        "mig_title": "从其他 AI 助手迁入",
        "mig_subtitle": "导入 ChatGPT、Claude、Gemini、Grok、DeepSeek、Copilot 和 Perplexity 的对话与记忆。一切都留在这台电脑上：密钥会被遮蔽，混入的指令会交给你审核，导入可以撤销。",
        "mig_source_label": "来源",
        "mig_auto": "自动识别",
        "mig_how": "如何获取导出",
        "mig_open_export": "打开导出页面",
        "mig_path_label": "本机上压缩包或文件的路径",
        "mig_path_ph": "例如 C:\\Users\\你\\Downloads\\export.zip",
        "mig_file_label": "或选择文件（最大 10 MB）",
        "mig_too_big": "文件超过 10 MB：请在上方输入它的路径。",
        "mig_preview_btn": "预览",
        "mig_run_btn": "导入",
        "mig_undo_btn": "撤销导入",
        "mig_found": "找到",
        "mig_conversations": "对话",
        "mig_messages": "消息",
        "mig_records": "记录",
        "mig_period": "时间段",
        "mig_secrets": "将遮蔽的密钥",
        "mig_done": "已导入",
        "mig_quarantined": "待审核",
        "mig_masked": "已遮蔽的密钥",
        "mig_undone": "导入已撤销，已出具回执。",
        "mig_nothing": "未找到已知的导出。请手动选择来源或检查文件。",
        "mig_need_input": "请输入路径或选择文件。",
        "mig_steps_chatgpt": "ChatGPT → 设置 → 数据控制 → 导出数据。链接通过邮件发送，24 小时内有效。",
        "mig_steps_claude": "Claude → 设置 → 隐私 → 导出数据。链接通过邮件发送，24 小时内有效。",
        "mig_steps_gemini": "takeout.google.com → 只选择“我的活动”→“Gemini 应用”，并把格式从 HTML 改为 JSON。",
        "mig_steps_grok": "Grok → 设置 → Data Controls → Download account data。链接通过邮件发送。",
        "mig_steps_deepseek": "DeepSeek → 设置 → 数据 → 导出数据。链接 7 天内有效。",
        "mig_steps_copilot": "account.microsoft.com/privacy → Copilot → Copilot 应用 → 导出全部活动历史。",
        "mig_steps_perplexity": "Perplexity → 全部设置 → 账户 → Export my data。压缩包通过邮件发送。",
        "mig_steps_official_mcp": "官方 MCP 记忆 (@modelcontextprotocol/server-memory) → 选择 memory.jsonl 文件。",
        "mig_steps_auto": "选择一个服务，查看在哪里获取导出。Studio 能识别这七个服务中任何一个的压缩包。"
    }
}
for _lg, _extra in _STRINGS_MIGRATE.items():
    STRINGS[_lg].update(_extra)

_STRINGS_CABINET: dict[str, dict[str, str]] = {
    "ru": {
        "nav_aifa": "AIfa",
        "nav_plans": "Тариф и Arweave",
        "aifa_title": "AIfa из единого кабинета CODE Eternal",
        "aifa_subtitle": "Та же AIfa и единая память, что на четырёх сайтах. Без входа Studio работает полностью локально.",
        "aifa_need_login": "Войдите по почтовому коду (пароль не нужен), чтобы продолжить разговор с AIfa и видеть свой тариф.",
        "aifa_email_ph": "Ваша почта (например, name@example.com)…",
        "aifa_send_code": "Войти в CODE Eternal · прислать код",
        "aifa_code_sent": "6-значный код отправлен на почту. Введите его ниже:",
        "aifa_code_ph": "Код из письма (6 цифр)…",
        "aifa_verify_btn": "Подтвердить вход",
        "aifa_logout_btn": "Выйти",
        "aifa_signed_in_as": "Учётная запись:",
        "aifa_use_local_label": "AIfa видит мою локальную память",
        "aifa_use_local_hint": "По умолчанию выключено. Если включить, в запрос уйдёт до 5 найденных локальных записей, уже прошедших маскировку секретов.",
        "aifa_msg_ph": "Напишите сообщение AIfa…",
        "aifa_send_btn": "Отправить",
        "aifa_local_sent_title": "Локальные записи, переданные в этом запросе (после маскировки):",
        "aifa_empty_chat": "Сообщений пока нет. Напишите AIfa ниже.",
        "plans_title": "Тариф и вечная память Arweave",
        "plans_subtitle": "PADAM Studio и локальная память бесплатны навсегда. Оплата нужна только для облачной памяти и Arweave.",
        "plans_current_tier": "Текущий тариф:",
        "plans_free_mode": "Бесплатно навсегда (без входа в кабинет)",
        "plans_quota_label": "Квота Arweave в этом месяце:",
        "plans_arweave_off": "Без платного тарифа запись в блокчейн Arweave не используется (0 МБ/мес).",
        "plans_free_forever_title": "Что бесплатно навсегда",
        "plans_free_item_1": "Локальная память PADAM на вашем ПК (без ограничений по объёму и сроку)",
        "plans_free_item_2": "Импорт переписок из ChatGPT, Claude, Gemini, Grok, DeepSeek, Copilot",
        "plans_free_item_3": "Полный PADAM Studio, маскировка ключей, карантин и локальный вечный слой L3",
        "plans_free_item_4": "Экспорт и резервные копии без привязки к облаку",
        "plans_paid_title": "Тарифы облачной и вечной памяти (оплата в кабинете)",
        "plans_btn_upgrade": "Улучшить",
        "plans_upgrade_opened": "Страница оплаты кабинета открыта во внешнем браузере.",
        "plans_spark_desc": "$15/мес · AIfa с единой памятью · Arweave 30 МБ/мес",
        "plans_family_desc": "$100/мес · Семейный архив и роли · Arweave 300 МБ/мес",
        "plans_dna_desc": "$1 000 разово за устройство + $200/мес · Полный контур · Arweave 1 ГБ/мес",
    },
    "en": {
        "nav_aifa": "AIfa",
        "nav_plans": "Plan & Arweave",
        "aifa_title": "AIfa from your CODE Eternal Cabinet",
        "aifa_subtitle": "The same AIfa and unified memory as on all four websites. Without sign-in, Studio stays 100% local.",
        "aifa_need_login": "Sign in with an email code (no password needed) to talk with AIfa and see your plan.",
        "aifa_email_ph": "Your email (e.g. name@example.com)…",
        "aifa_send_code": "Sign in to CODE Eternal · send code",
        "aifa_code_sent": "A 6-digit code was sent to your email. Enter it below:",
        "aifa_code_ph": "6-digit code from email…",
        "aifa_verify_btn": "Verify sign-in",
        "aifa_logout_btn": "Sign out",
        "aifa_signed_in_as": "Signed in as:",
        "aifa_use_local_label": "Let AIfa see my local memory",
        "aifa_use_local_hint": "Off by default. When enabled, up to 5 matching local records (already secret-masked) are included and shown below.",
        "aifa_msg_ph": "Write a message to AIfa…",
        "aifa_send_btn": "Send",
        "aifa_local_sent_title": "Masked local records sent with this request:",
        "aifa_empty_chat": "No messages yet. Write to AIfa below.",
        "plans_title": "Plan & Permanent Arweave Memory",
        "plans_subtitle": "PADAM Studio and local memory are free forever. Paid plans cover cloud sync and permanent Arweave storage.",
        "plans_current_tier": "Current plan:",
        "plans_free_mode": "Free forever (not signed in)",
        "plans_quota_label": "Arweave quota used this month:",
        "plans_arweave_off": "Without a paid plan, permanent Arweave anchoring is not used (0 MB/month).",
        "plans_free_forever_title": "What is free forever",
        "plans_free_item_1": "Local PADAM memory on your PC (no record or time limits)",
        "plans_free_item_2": "One-click import from ChatGPT, Claude, Gemini, Grok, DeepSeek, Copilot",
        "plans_free_item_3": "Full PADAM Studio, secret masking, quarantine, and local L3 anchoring",
        "plans_free_item_4": "Open export and encrypted backups with zero cloud lock-in",
        "plans_paid_title": "Cloud & Arweave plans (checkout in cabinet browser)",
        "plans_btn_upgrade": "Upgrade",
        "plans_upgrade_opened": "Cabinet checkout page opened in your external browser.",
        "plans_spark_desc": "$15/mo · AIfa with unified memory · Arweave 30 MB/mo",
        "plans_family_desc": "$100/mo · Family archive & roles · Arweave 300 MB/mo",
        "plans_dna_desc": "$1,000 one-time per device + $200/mo · Full contour · Arweave 1 GB/mo",
    },
    "es": {
        "nav_aifa": "AIfa",
        "nav_plans": "Plan y Arweave",
        "aifa_title": "AIfa desde tu gabinete CODE Eternal",
        "aifa_subtitle": "La misma AIfa y memoria unificada que en los cuatro sitios. Sin sesión, Studio es 100% local.",
        "aifa_need_login": "Inicia sesión con código por correo (sin contraseña) para hablar con AIfa y ver tu plan.",
        "aifa_email_ph": "Tu correo (ej. nombre@ejemplo.com)…",
        "aifa_send_code": "Entrar en CODE Eternal · enviar código",
        "aifa_code_sent": "Se envió un código de 6 dígitos a tu correo. Escríbelo abajo:",
        "aifa_code_ph": "Código de 6 dígitos…",
        "aifa_verify_btn": "Confirmar acceso",
        "aifa_logout_btn": "Salir",
        "aifa_signed_in_as": "Cuenta:",
        "aifa_use_local_label": "AIfa ve mi memoria local",
        "aifa_use_local_hint": "Desactivado por defecto. Al activarlo, se envían hasta 5 recuerdos locales ya enmascarados.",
        "aifa_msg_ph": "Escribe un mensaje para AIfa…",
        "aifa_send_btn": "Enviar",
        "aifa_local_sent_title": "Registros locales enmascarados enviados:",
        "aifa_empty_chat": "Aún no hay mensajes. Escribe a AIfa abajo.",
        "plans_title": "Plan y memoria permanente en Arweave",
        "plans_subtitle": "PADAM Studio y la memoria local son gratis para siempre. Solo se paga por nube y Arweave.",
        "plans_current_tier": "Plan actual:",
        "plans_free_mode": "Gratis para siempre (sin sesión iniciada)",
        "plans_quota_label": "Cuota de Arweave este mes:",
        "plans_arweave_off": "Sin plan de pago no se usa Arweave permanente (0 MB/mes).",
        "plans_free_forever_title": "Qué es gratis para siempre",
        "plans_free_item_1": "Memoria local PADAM en tu equipo sin límites",
        "plans_free_item_2": "Importación desde ChatGPT, Claude, Gemini, Grok, DeepSeek y Copilot",
        "plans_free_item_3": "PADAM Studio completo, máscara de claves, cuarentena y capa L3 local",
        "plans_free_item_4": "Exportación abierta y copias cifradas sin bloqueo en la nube",
        "plans_paid_title": "Planes de nube y Arweave (pago en el navegador)",
        "plans_btn_upgrade": "Mejorar",
        "plans_upgrade_opened": "Página de pago del gabinete abierta en el navegador externo.",
        "plans_spark_desc": "$15/mes · AIfa con memoria unificada · Arweave 30 MB/mes",
        "plans_family_desc": "$100/mes · Archivo familiar y roles · Arweave 300 MB/mes",
        "plans_dna_desc": "$1 000 pago único por dispositivo + $200/mes · Arweave 1 GB/mes",
    },
    "zh": {
        "nav_aifa": "AIfa",
        "nav_plans": "套餐与 Arweave",
        "aifa_title": "来自 CODE Eternal 个人中心的 AIfa",
        "aifa_subtitle": "与四个官网同一位 AIfa 与统一记忆。未登录时 Studio 完全本地运行。",
        "aifa_need_login": "使用邮箱验证码登录（无需密码），即可与 AIfa 对话并查看您的套餐。",
        "aifa_email_ph": "您的邮箱（如 name@example.com）…",
        "aifa_send_code": "登录 CODE Eternal · 发送验证码",
        "aifa_code_sent": "6 位验证码已发送到您的邮箱，请在下方输入：",
        "aifa_code_ph": "邮件中的 6 位验证码…",
        "aifa_verify_btn": "验证并登录",
        "aifa_logout_btn": "退出登录",
        "aifa_signed_in_as": "当前账号：",
        "aifa_use_local_label": "允许 AIfa 查看我的本地记忆",
        "aifa_use_local_hint": "默认关闭。开启后最多附带 5 条已完成密钥掩码的本地记忆，并在下方明示。",
        "aifa_msg_ph": "给 AIfa 发消息…",
        "aifa_send_btn": "发送",
        "aifa_local_sent_title": "本次请求发送的已掩码本地记忆：",
        "aifa_empty_chat": "暂无消息，请在下方与 AIfa 对话。",
        "plans_title": "套餐与 Arweave 永久记忆配额",
        "plans_subtitle": "PADAM Studio 与本地记忆永久免费，仅云同步与 Arweave 永久存储需付费。",
        "plans_current_tier": "当前套餐：",
        "plans_free_mode": "永久免费（未登录个人中心）",
        "plans_quota_label": "本月 Arweave 已用配额：",
        "plans_arweave_off": "免费状态下不使用 Arweave 永久上链（0 MB/月）。",
        "plans_free_forever_title": "永久免费包含",
        "plans_free_item_1": "本地 PADAM 记忆（容量与时长无限制）",
        "plans_free_item_2": "从 ChatGPT、Claude、Gemini、Grok、DeepSeek、Copilot 一键迁移",
        "plans_free_item_3": "完整 Studio、密钥自动掩码、隔离区与本地 L3 锚定",
        "plans_free_item_4": "开放导出与加密备份，无云端锁定",
        "plans_paid_title": "云端与 Arweave 套餐（外部浏览器跳转支付）",
        "plans_btn_upgrade": "升级套餐",
        "plans_upgrade_opened": "已在外部浏览器中打开个人中心支付页面。",
        "plans_spark_desc": "$15/月 · 统一记忆 AIfa · Arweave 30 MB/月",
        "plans_family_desc": "$100/月 · 家庭档案与角色权限 · Arweave 300 MB/月",
        "plans_dna_desc": "$1,000 单设备一次性 + $200/月 · 完整架构 · Arweave 1 GB/月",
    },
}
for _lg, _extra in _STRINGS_CABINET.items():
    STRINGS[_lg].update(_extra)

# 16.11.2026: вкладки «Атаки» и «Справка».
from . import studio_help as _studio_help
_STRINGS_ATTACKS: dict[str, dict[str, str]] = {
    "ru": {"att_title": "Счётчик атак", "att_sub": "Сколько попыток задержала защита PADAM, каких видов, от кого и когда. Текст атак не показывается.",
           "att_total": "Задержано за всё время", "att_window": "За 30 дней", "att_pending": "Ждут вашего решения", "att_secrets": "Скрыто ключей и паролей",
           "att_by_kind": "По видам", "att_by_source": "От кого", "att_by_day": "По дням (30 дней)", "att_secrets_kind": "Скрытые ключи по видам", "att_recent": "Последние попытки", "att_none": "Пока ни одной попытки — защита на месте.",
           "k_injection": "внедрённая команда", "k_protected_record": "подмена «кто я» и предпочтений", "k_external_held": "внешний текст до проверки", "k_procedure": "процедура без одобрения", "k_review_all": "запись агента на проверке", "k_other": "другое",
           "help_links": "Ссылки", "att_aifasec_title": "Эталонный аудит AIFaSecurity (100 критериев, $0)", "att_aifasec_btn": "Запустить 100 проверок сейчас", "att_aifasec_running": "Идёт проверка 100 критериев…"},
    "en": {"att_title": "Attack counter", "att_sub": "How many attempts PADAM's guard held, of which kind, from whom and when. Attack text is never shown.",
           "att_total": "Held, all time", "att_window": "Last 30 days", "att_pending": "Waiting for your decision", "att_secrets": "Keys and passwords masked",
           "att_by_kind": "By kind", "att_by_source": "By source", "att_by_day": "By day (30 days)", "att_secrets_kind": "Masked keys by kind", "att_recent": "Latest attempts", "att_none": "No attempts yet — the guard is in place.",
           "k_injection": "planted instruction", "k_protected_record": "identity / preference tampering", "k_external_held": "external text before review", "k_procedure": "procedure without approval", "k_review_all": "agent write under review", "k_other": "other",
           "help_links": "Links", "att_aifasec_title": "AIFaSecurity Benchmark (100 criteria, $0)", "att_aifasec_btn": "Run 100 checks now", "att_aifasec_running": "Running 100 criteria…"},
    "es": {"att_title": "Contador de ataques", "att_sub": "Cuántos intentos retuvo la protección de PADAM, de qué tipo, de quién y cuándo. El texto de los ataques nunca se muestra.",
           "att_total": "Retenidos en total", "att_window": "Últimos 30 días", "att_pending": "Esperan su decisión", "att_secrets": "Claves y contraseñas ocultas",
           "att_by_kind": "Por tipo", "att_by_source": "Por origen", "att_by_day": "Por día (30 días)", "att_secrets_kind": "Claves ocultas por tipo", "att_recent": "Últimos intentos", "att_none": "Aún no hay intentos: la protección está activa.",
           "k_injection": "instrucción plantada", "k_protected_record": "alteración de identidad o preferencias", "k_external_held": "texto externo antes de revisión", "k_procedure": "procedimiento sin aprobación", "k_review_all": "escritura de agente en revisión", "k_other": "otro",
           "help_links": "Enlaces", "att_aifasec_title": "Auditoría AIFaSecurity (100 criterios, $0)", "att_aifasec_btn": "Ejecutar 100 pruebas ahora", "att_aifasec_running": "Ejecutando 100 criterios…"},
    "zh": {"att_title": "攻击计数器", "att_sub": "PADAM 防护拦截了多少次尝试、什么类型、来自谁、何时发生。从不显示攻击文本。",
           "att_total": "累计拦截", "att_window": "最近 30 天", "att_pending": "等待您的决定", "att_secrets": "已隐藏的密钥和密码",
           "att_by_kind": "按类型", "att_by_source": "按来源", "att_by_day": "按日期(30 天)", "att_secrets_kind": "按类型隐藏的密钥", "att_recent": "最近的尝试", "att_none": "暂无尝试——防护已就位。",
           "k_injection": "植入指令", "k_protected_record": "篡改身份或偏好", "k_external_held": "未经审核的外部文本", "k_procedure": "未经批准的流程", "k_review_all": "待审核的智能体写入", "k_other": "其他",
           "help_links": "链接", "att_aifasec_title": "AIFaSecurity 基准测试（100 项，$0）", "att_aifasec_btn": "立即运行 100 项检测", "att_aifasec_running": "正在运行 100 项检测…"},
}
for _lg, _extra in _STRINGS_ATTACKS.items():
    STRINGS[_lg].update(_extra)
    STRINGS[_lg].update(_studio_help.NAV[_lg])

_CSS = """
:root, html[data-theme="dark"] {
  --bg: #080b12;
  --bg-elev: #0e1320;
  --card: #131a2c;
  --card-hover: #19223a;
  --line: #23304d;
  --fg: #f1f5f9;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --accent-2: #8b5cf6;
  --accent-fg: #041019;
  --ok: #34d399;
  --ok-bg: #062e22;
  --warn: #fbbf24;
  --warn-bg: #2e2105;
  --danger: #fca5a5;
  --danger-bg: #3b0d0d;
  --chip: #1e2942;
  --glow: 0 0 28px rgba(56, 189, 248, 0.14), 0 0 60px rgba(139, 92, 246, 0.08);
}
html[data-theme="light"] {
  --bg: #f4f6fb;
  --bg-elev: #ffffff;
  --card: #ffffff;
  --card-hover: #f8fafc;
  --line: #cbd5e1;
  --fg: #0f172a;
  --muted: #475569;
  --accent: #0369a1;
  --accent-2: #4f46e5;
  --accent-fg: #ffffff;
  --ok: #14532d;
  --ok-bg: #dcfce7;
  --warn: #78350f;
  --warn-bg: #fef3c7;
  --danger: #7f1d1d;
  --danger-bg: #fee2e2;
  --chip: #e2e8f0;
  --glow: 0 4px 20px rgba(15, 23, 42, 0.06);
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  min-height: 100vh;
}
button, input, select, textarea {
  font: inherit;
  color: var(--fg);
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 7px 13px;
}
button { cursor: pointer; transition: border-color 0.15s, background 0.15s, transform 0.1s; }
button:hover { border-color: var(--accent); background: var(--card-hover); }
button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible, a:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
.btn-primary {
  background: var(--accent);
  color: var(--accent-fg);
  border-color: transparent;
  font-weight: 600;
}
.btn-primary:hover { background: var(--accent); color: var(--accent-fg); opacity: 0.94; border-color: var(--fg); }
.btn-ok:hover { background: var(--ok-bg); color: var(--ok); }
.btn-danger:hover { background: var(--danger-bg); color: var(--danger); }
.btn-warn:hover { background: var(--warn-bg); color: var(--warn); }
.btn-ok { border-color: var(--ok); color: var(--ok); background: var(--ok-bg); font-weight: 600; }
.btn-danger { border-color: var(--danger); color: var(--danger); background: var(--danger-bg); font-weight: 600; }
.btn-warn { border-color: var(--warn); color: var(--warn); background: var(--warn-bg); font-weight: 600; }

/* Макет: боковая панель + основная область */
.layout {
  display: grid;
  grid-template-columns: 260px 1fr;
  min-height: 100vh;
}
.sidebar {
  background: var(--bg-elev);
  border-right: 1px solid var(--line);
  padding: 20px 14px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 4px 6px;
}
.brand-logo {
  width: 40px;
  height: 40px;
  flex-shrink: 0;
}
.brand-title {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 0.02em;
  margin: 0;
}
.brand-sub {
  font-size: 11px;
  color: var(--muted);
  margin: 2px 0 0;
}
.nav-list {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.nav-tab {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
  text-align: left;
  padding: 9px 12px;
  border-radius: 10px;
  border: 1px solid transparent;
  background: transparent;
  font-weight: 500;
}
.nav-tab:hover { background: var(--card); border-color: var(--line); }
.nav-tab[aria-selected="true"] {
  background: var(--card);
  border-color: var(--accent);
  box-shadow: var(--glow);
  font-weight: 600;
}
.badge {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  background: var(--chip);
  color: var(--fg);
}
.badge-warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn); }
.badge-danger { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }
.badge-ok { background: var(--ok-bg); color: var(--ok); border: 1px solid var(--ok); }

.workspace {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.topbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 24px;
  border-bottom: 1px solid var(--line);
  background: var(--bg-elev);
}
.topbar-stats {
  font-size: 13px;
  color: var(--muted);
}
.topbar-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.lang-group {
  display: inline-flex;
  border: 1px solid var(--line);
  border-radius: 10px;
  overflow: hidden;
}
.lang-btn {
  border: 0;
  border-radius: 0;
  padding: 5px 9px;
  font-size: 12px;
  font-weight: 600;
  background: var(--card);
}
.lang-btn[aria-pressed="true"] {
  background: var(--accent);
  color: var(--accent-fg);
}

.content-area {
  padding: 24px;
  max-width: 1180px;
  width: 100%;
  margin: 0 auto;
}
.panel-header {
  margin-bottom: 18px;
}
.panel-title {
  font-size: 22px;
  margin: 0 0 4px;
}
.panel-sub {
  font-size: 14px;
  color: var(--muted);
  margin: 0;
}

/* Сетки и карточки */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(165px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.kpi-card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 14px 16px;
  box-shadow: var(--glow);
}
.kpi-num {
  font-size: 26px;
  font-weight: 700;
  color: var(--accent);
  line-height: 1.2;
}
.kpi-label {
  font-size: 12px;
  color: var(--muted);
  margin-top: 4px;
}
.two-col {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}
.box {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 18px;
  margin-bottom: 16px;
  box-shadow: var(--glow);
}
.box-title {
  font-size: 16px;
  font-weight: 600;
  margin: 0 0 12px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.kind-row {
  display: grid;
  grid-template-columns: 185px 1fr 48px;
  align-items: center;
  gap: 10px;
  padding: 5px 0;
  font-size: 13px;
}
.sbar {
  width: 100%;
  height: 8px;
  display: block;
}
.sbar-bg { fill: var(--line); }
.sbar-fill { fill: var(--accent); }

/* Светофор Doctor */
.traffic-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 12px;
  font-weight: 600;
  margin-bottom: 12px;
  border: 1px solid var(--line);
}
.traffic-green { background: var(--ok-bg); color: var(--ok); border-color: var(--ok); }
.traffic-yellow { background: var(--warn-bg); color: var(--warn); border-color: var(--warn); }
.traffic-red { background: var(--danger-bg); color: var(--danger); border-color: var(--danger); }

.att-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 16px; }
.att-row { display: flex; justify-content: space-between; gap: 12px; padding: 6px 0; border-bottom: 1px solid var(--line); }
.brain-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; background: #64748b; }
.brain-dot-on { background: #22c55e; }
.brain-dot-off { background: #ef4444; }
.att-name { min-width: 0; overflow-wrap: anywhere; }
.att-val { font-weight: 600; white-space: nowrap; }
.att-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
.att-qa-box { margin-top: 12px; }
.help-sec summary { cursor: pointer; }
.help-item { margin: 10px 0 0; }
.help-name { margin: 0 0 4px; font-size: 15px; }
.help-text { margin: 0; line-height: 1.55; overflow-wrap: anywhere; }
.check-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.check-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 8px;
  background: var(--bg-elev);
  border: 1px solid var(--line);
  font-size: 13px;
}

/* Карточки записей */
.toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 14px;
  align-items: center;
}
.toolbar input[type="search"], .toolbar input[type="text"] {
  flex: 1 1 240px;
  min-width: 0;          /* иначе на телефоне и в узком окне поле шире экрана */
  max-width: 100%;
  box-sizing: border-box;
}
.toolbar select, .toolbar input[type="file"] {
  max-width: 100%;
  min-width: 0;
}
.chips-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 14px;
}
.chip {
  background: var(--chip);
  border: 1px solid transparent;
  border-radius: 999px;
  padding: 3px 11px;
  font-size: 12px;
  font-weight: 500;
}
.chip[aria-pressed="true"] {
  border-color: var(--accent);
  background: var(--card);
  color: var(--accent);
}
.day-head {
  margin: 20px 0 8px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
.rec-card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 14px 16px;
  margin-bottom: 10px;
}
.rec-card-quarantined {
  border-left: 4px solid var(--warn);
}
.rec-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 12px;
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 8px;
}
.rec-text {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-size: 15px;
  margin: 8px 0 10px;
}
.rec-clocks {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 16px;
  font-size: 12px;
  color: var(--muted);
  padding-top: 6px;
  border-top: 1px dashed var(--line);
  margin-bottom: 8px;
}
.rec-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}
.rec-actions button {
  padding: 4px 10px;
  font-size: 12px;
}
.explain-box {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  padding: 8px 10px;
  border-radius: 8px;
  background: var(--bg-elev);
  border: 1px solid var(--line);
  color: var(--accent);
  margin-bottom: 8px;
}
.versions-box {
  margin-top: 10px;
  padding: 10px 12px;
  border-radius: 8px;
  background: var(--bg-elev);
  border: 1px solid var(--line);
  font-size: 13px;
}
.ver-row {
  padding: 6px 0;
  border-bottom: 1px dashed var(--line);
}
.ver-row:last-child { border-bottom: 0; }

/* Квитанция удаления */
.receipt-card {
  background: var(--bg-elev);
  border: 2px solid var(--accent);
  border-radius: 14px;
  padding: 18px;
  margin-bottom: 18px;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  overflow-wrap: anywhere;
}
.kv-row {
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: 8px;
  padding: 5px 0;
  border-bottom: 1px dashed var(--line);
  font-size: 13px;
}

/* Граф связей */
.graph-wrap {
  background: var(--bg-elev);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 12px;
  margin-bottom: 16px;
}
#graph-canvas {
  width: 100%;
  height: 420px;
  display: block;
  cursor: grab;
  border-radius: 10px;
}
.legend-row {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  font-size: 12px;
  color: var(--muted);
  margin-top: 8px;
}

/* Настройки и Мастер */
.setting-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 0;
  border-bottom: 1px solid var(--line);
}
.setting-row:last-child { border-bottom: 0; }
.setting-info { flex: 1 1 380px; }
.setting-name { font-weight: 600; font-size: 14px; }
.setting-desc { font-size: 13px; color: var(--muted); margin-top: 2px; }
.code-block {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  background: var(--bg-elev);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 10px 14px;
  margin: 6px 0 14px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px;
  overflow-x: auto;
}
#status-msg {
  min-height: 22px;
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 10px;
}
.msg-ok { color: var(--ok); }
.msg-err { color: var(--danger); }


.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(8, 11, 18, 0.76);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 999;
  padding: 16px;
}
.modal-card {
  background: var(--bg-elev);
  border: 1px solid var(--accent);
  border-radius: 14px;
  padding: 20px;
  width: 100%;
  max-width: 540px;
  box-shadow: var(--glow);
}
.entity-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
}
.entity-card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 10px 12px;
  cursor: pointer;
  text-align: left;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.entity-card[aria-pressed="true"] {
  border-color: var(--accent);
  background: var(--card-hover);
}
.entity-title {
  font-weight: 700;
  font-size: 14px;
  word-break: break-word;
}


@media (min-width: 861px) {
  .sidebar {
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
  }
}
.earn-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.earn-box-wide {
  grid-column: 1 / -1;
}
#earn-accounts-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
  gap: 8px;
}
#earn-accounts-list > .earn-meta {
  grid-column: 1 / -1;
  margin: 0;
}
.earn-bid-preview {
  margin-top: 6px;
  padding: 8px 10px;
  border-radius: 8px;
  border: 1px dashed var(--line);
  background: var(--card);
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.earn-bid-box {
  width: 100%;
  min-height: 78px;
  box-sizing: border-box;
  font: inherit;
  font-size: 13px;
  padding: 8px;
  border-radius: 8px;
  border: 1px solid var(--line);
  background: var(--bg-2);
  color: var(--ink);
  resize: vertical;
}
.earn-grid > .box, .earn-stack {
  min-width: 0;
}
.earn-stack {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 10px;
}
.earn-stack .att-row {
  flex-wrap: wrap;
}
.earn-stack .att-val {
  white-space: normal;
  word-break: break-word;
  overflow-wrap: anywhere;
  text-align: right;
  max-width: 100%;
}
.earn-item {
  background: var(--bg-2);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.earn-item-head {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 6px;
}
.earn-pill {
  font-size: 11px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--ink);
}
.earn-meta {
  font-size: 12px;
  color: var(--muted);
  word-break: break-word;
}
.earn-num-input {
  max-width: 150px;
}
.earn-num-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  gap: 8px;
  margin-bottom: 10px;
}
.earn-field {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}
.earn-field label {
  font-size: 11.5px;
  font-weight: 600;
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.earn-field .earn-num-input {
  max-width: 100%;
  width: 100%;
  box-sizing: border-box;
}
.btn-ok {
  border-color: var(--ok);
  color: var(--ok);
}
.btn-danger {
  border-color: var(--danger);
  color: var(--danger);
}

@media (max-width: 1180px) {
  .layout {
    grid-template-columns: 224px minmax(0, 1fr);
  }
  .earn-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (max-width: 860px) {
  .layout {
    grid-template-columns: minmax(0, 1fr);
    min-height: auto;
    max-width: 100vw;
    overflow-x: hidden;
  }
  .sidebar, .workspace, .content-area, .panel {
    min-width: 0;
    max-width: 100%;
  }
  .sidebar {
    border-right: 0;
    border-bottom: 1px solid var(--line);
    padding: calc(10px + env(safe-area-inset-top, 0px)) 12px 10px 12px;
    gap: 8px;
  }
  .topbar {
    flex-wrap: wrap;
    gap: 8px;
    padding: 10px calc(12px + env(safe-area-inset-right, 0px)) 10px calc(12px + env(safe-area-inset-left, 0px));
  }
  .topbar-controls {
    flex-wrap: wrap;
    gap: 6px;
    width: 100%;
  }
  .brand-sub {
    display: none;
  }
  .sidebar-footer {
    display: none;
  }
  .nav-list {
    flex-direction: row;
    flex-wrap: nowrap;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    gap: 6px;
    padding-bottom: 6px;
    scrollbar-width: thin;
  }
  .nav-tab {
    width: auto;
    flex: 0 0 auto;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
    min-height: 40px;
    padding: 6px 11px;
    font-size: 12.5px;
  }
  .topbar-title {
    font-size: 16px;
  }
  .content-area {
    padding: 12px calc(12px + env(safe-area-inset-right, 0px)) calc(18px + env(safe-area-inset-bottom, 0px)) calc(12px + env(safe-area-inset-left, 0px));
  }
  .kpi-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
  .kpi-value {
    font-size: 22px;
  }
  .two-col, .earn-grid, #earn-accounts-list {
    grid-template-columns: minmax(0, 1fr);
  }
  .toolbar {
    flex-wrap: wrap;
  }
  .toolbar input, .toolbar select, .toolbar button, .earn-num-input {
    max-width: 100%;
    min-height: 40px;
  }
  .rec-actions button {
    min-height: 40px;
  }
  .kind-row {
    grid-template-columns: 110px 1fr 34px;
  }
  .kv-row {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 420px) {
  .content-area {
    padding: 10px 10px calc(16px + env(safe-area-inset-bottom, 0px)) 10px;
  }
  .box {
    padding: 12px;
  }
  .kpi-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .toolbar input, .toolbar select, .toolbar button, .rec-actions button {
    width: 100%;
    flex: 1 1 100%;
  }
  .lang-group {
    width: 100%;
    justify-content: space-between;
  }
  .kind-row {
    grid-template-columns: 88px 1fr 30px;
  }
}
"""



_JS = r"""
const ALL_STRINGS = JSON.parse(document.getElementById('i18n-data').textContent);
function detectSystemLang() {
  try {
    const raw = String((navigator.languages && navigator.languages[0]) || navigator.language || '').toLowerCase();
    if (raw.startsWith('ru')) return 'ru';
    if (raw.startsWith('es')) return 'es';
    if (raw.startsWith('zh')) return 'zh';
    if (raw) return 'en';
  } catch (e) {}
  return document.documentElement.lang || 'en';
}
let currentLang = detectSystemLang();
try {
  const savedLang = localStorage.getItem('padam_lang');
  if (savedLang && ALL_STRINGS[savedLang]) currentLang = savedLang;
} catch (e) {}
let S = ALL_STRINGS[currentLang] || ALL_STRINGS.en;

function detectSystemTheme() {
  try {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
  } catch (e) {}
  return 'dark';
}
let currentTheme = detectSystemTheme();
try {
  const savedTheme = localStorage.getItem('padam_theme');
  if (savedTheme === 'light' || savedTheme === 'dark') currentTheme = savedTheme;
} catch (e) {}
document.documentElement.setAttribute('data-theme', currentTheme);

const hashParams = new URLSearchParams(location.hash.slice(1));
let token = hashParams.get('t');
const initialTab = hashParams.get('tab');
const initialTheme = hashParams.get('theme');
const initialLang = hashParams.get('lang');
if (initialTheme === 'light' || initialTheme === 'dark') {
  currentTheme = initialTheme;
  document.documentElement.setAttribute('data-theme', currentTheme);
}
if (initialLang && ALL_STRINGS[initialLang]) {
  currentLang = initialLang;
  S = ALL_STRINGS[currentLang];
  document.documentElement.lang = currentLang;
}
try {
  if (token) sessionStorage.setItem('padam_t', token);
  else token = sessionStorage.getItem('padam_t');
} catch (e) {}
if (location.hash) history.replaceState(null, '', location.pathname);
window.addEventListener('hashchange', () => {
  const hp = new URLSearchParams(location.hash.slice(1));
  const nextTab = hp.get('tab');
  if (location.hash) history.replaceState(null, '', location.pathname);
  if (nextTab && TABS.includes(nextTab)) switchTab(nextTab);
});

const $ = id => document.getElementById(id);
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function svgBar(pct) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 100 8');
  svg.setAttribute('class', 'sbar');
  svg.setAttribute('aria-hidden', 'true');
  const bg = document.createElementNS(ns, 'rect');
  bg.setAttribute('x', '0'); bg.setAttribute('y', '0');
  bg.setAttribute('width', '100'); bg.setAttribute('height', '8');
  bg.setAttribute('rx', '4'); bg.setAttribute('class', 'sbar-bg');
  const fg = document.createElementNS(ns, 'rect');
  fg.setAttribute('x', '0'); fg.setAttribute('y', '0');
  fg.setAttribute('width', String(Math.max(0, Math.min(100, Math.round(pct)))));
  fg.setAttribute('height', '8');
  fg.setAttribute('rx', '4'); fg.setAttribute('class', 'sbar-fill');
  svg.append(bg, fg);
  return svg;
}

async function api(path, body) {
  const headers = {'Content-Type': 'application/json'};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const r = await fetch(path, {
    method: body !== undefined ? 'POST' : 'GET',
    cache: 'no-store',
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}

function say(text, ok = true) {
  const box = $('status-msg');
  box.textContent = text || '';
  box.className = ok ? 'msg-ok' : 'msg-err';
}

const TABS = ['overview', 'migrate', 'aifa', 'plans', 'feed', 'search', 'ask', 'review', 'attacks', 'asof', 'forget', 'graph', 'entities', 'l3', 'brain', 'earning', 'team', 'backup', 'settings', 'quickstart', 'help'];
window._padamWorkspaces = [];
let activeTab = (initialTab && TABS.includes(initialTab)) ? initialTab : 'overview';
let feedView = 'active', feedOffset = 0, feedKind = null, feedShown = [];
let lastReceipt = null;
let graphData = {nodes: [], edges: []}, graphPositions = {}, selectedGraphNode = null;

function applyI18n() {
  S = ALL_STRINGS[currentLang] || ALL_STRINGS.ru;
  document.documentElement.lang = currentLang;
  document.title = S.app_title;
  for (const node of document.querySelectorAll('[data-i18n]')) {
    const key = node.getAttribute('data-i18n');
    if (S[key] !== undefined) node.textContent = S[key];
  }
  for (const node of document.querySelectorAll('[data-i18n-placeholder]')) {
    const key = node.getAttribute('data-i18n-placeholder');
    if (S[key] !== undefined) node.setAttribute('placeholder', S[key]);
  }
  for (const node of document.querySelectorAll('[data-i18n-aria]')) {
    const key = node.getAttribute('data-i18n-aria');
    if (S[key] !== undefined) node.setAttribute('aria-label', S[key]);
  }
  $('theme-toggle').textContent = currentTheme === 'dark' ? ('☀️ ' + S.theme_light) : ('🌙 ' + S.theme_dark);
  for (const lg of ['ru', 'en', 'es', 'zh']) {
    const b = $('lang-' + lg);
    if (b) b.setAttribute('aria-pressed', String(lg === currentLang));
  }
  try { if (activeTab === 'help' || activeTab === 'attacks') loadActiveTab(); } catch (e) {}
}

function switchTab(tab) {
  if (!TABS.includes(tab)) return;
  activeTab = tab;
  for (const t of TABS) {
    const btn = $('tab-' + t);
    const panel = $('panel-' + t);
    const active = (t === tab);
    if (btn) btn.setAttribute('aria-selected', String(active));
    if (panel) panel.hidden = !active;
  }
  if (typeof window !== 'undefined' && window.scrollTo) window.scrollTo(0, 0);
  say('');
  loadActiveTab();
}

async function refreshTopbarStats() {
  if (!token) { say(S.no_token, false); return; }
  try {
    const s = await api('/stats');
    $('topbar-stats').textContent = s.active + ' ' + S.records + ' · ' +
      s.episodes_pending + ' ' + S.pending_ep + ' · ' + s.backend +
      (s.stale_vectors ? (' · ' + s.stale_vectors + ' ' + S.stale_vec) : '');
    const badge = $('review-badge');
    if (badge) {
      badge.textContent = String(s.quarantined || 0);
      badge.className = s.quarantined ? 'badge badge-warn' : 'badge';
    }
  } catch (e) {}
}

function truncateAtWord(text, maxLen) {
  const s = String(text || '').trim();
  if (s.length <= maxLen) return s;
  let cut = s.lastIndexOf(' ', maxLen);
  if (cut < Math.floor(maxLen * 0.45)) cut = maxLen;
  return s.slice(0, cut).replace(/[\s,.;:—\-]+$/, '') + '…';
}

function fmtTime(iso, showSec = true) {
  if (!iso) return '—';
  const raw = String(iso).trim();
  const norm = (raw.includes('T') && !raw.endsWith('Z') && !/[+-]\d\d:?\d\d$/.test(raw)) ? (raw + 'Z') : raw;
  const d = new Date(norm);
  if (isNaN(d.getTime())) return raw.slice(0, 19).replace('T', ' ');
  const pad = n => String(n).padStart(2, '0');
  const base = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
               ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) +
               (showSec ? (':' + pad(d.getSeconds())) : '');
  return base + ' (' + (S.time_local || 'local') + ')';
}

function cleanConflictSubject(rawKey) {
  return String(rawKey || '')
    .replace(/^\[|\]$/g, '')
    .replace(/[\s—\-:=]+$/g, '')
    .replace(/\s+(это|равен|is|equals)$/i, '')
    .trim();
}

function humanReason(raw) {
  if (!raw) return {text: '', code: ''};
  const r = String(raw).toLowerCase();
  const parts = [];
  const codes = [];
  if (r.includes('external')) { parts.push(S.reason_external); codes.push('external'); }
  if (r.includes('classifier')) { parts.push(S.reason_classifier); codes.push('classifier'); }
  else if (r.includes('instruction')) { parts.push(S.reason_instruction); codes.push('instruction'); }
  if (r.includes('review_all')) { parts.push(S.reason_review_all); codes.push('review_all'); }
  if (r.includes('owner') && r.includes('works')) { parts.push(S.reason_owner_rules); codes.push('owner_rules'); }
  if (r.includes('protected') || r.includes('identity') || r.includes('preference')) {
    parts.push(S.reason_protected);
    codes.push('protected');
  }
  if (!parts.length) return {text: S.reason_external, code: String(raw)};
  return {text: parts.join(' · '), code: codes.join('+')};
}

function renderRecordCard(r, opts = {}) {
  const card = el('article', 'rec-card' + (r.status === 'quarantined' ? ' rec-card-quarantined' : ''));
  const meta = el('div', 'rec-meta');
  meta.append(el('span', 'badge', S['kind_' + r.kind] || r.kind));
  const origKey = 'origin_' + (r.origin || 'user');
  meta.append(el('span', '', S.card_origin + ': ' + (S[origKey] || r.origin || 'user')));
  if (r.scope) meta.append(el('span', '', S.card_scope + ': ' + r.scope));
  if (r.agent_id) meta.append(el('span', 'badge', S.card_agent + ': ' + r.agent_id));
  if (r.visibility && r.visibility !== 'private') {
    meta.append(el('span', 'badge', S['vis_' + r.visibility] || r.visibility));
  }
  if (r.status && r.status !== 'active') {
    const cls = r.status === 'quarantined' ? 'badge badge-warn' : (r.status === 'revoked' ? 'badge badge-danger' : 'badge');
    meta.append(el('span', cls, S['status_' + r.status] || r.status));
  }
  if (typeof r.confidence === 'number') {
    meta.append(el('span', '', S.card_conf + ': ' + Math.round(r.confidence * 100) + '%'));
  }
  if (typeof r.importance === 'number') {
    meta.append(el('span', '', S.card_imp + ': ' + r.importance.toFixed(2)));
  }
  if (typeof r.decay === 'number') {
    meta.append(el('span', '', S.card_decay + ': ' + Math.round(r.decay * 100) + '%'));
  }
  meta.append(el('span', 'mono', 'id: ' + String(r.id).slice(0, 12) + '…'));
  card.append(meta);

  if (opts.explain && r.explain) {
    const ex = el('div', 'explain-box', S.search_explain_label + ' ' + r.explain);
    card.append(ex);
  }
  if (r.suspicious) card.append(el('div', 'badge badge-warn', S.search_suspicious));
  if (r.conflict) card.append(el('div', 'badge badge-danger', S.search_conflict));
  if (r.signed === false) card.append(el('div', 'badge badge-danger', S.search_unsigned));
  if (opts.asof && r.status === 'superseded') {
    card.append(el('div', 'badge badge-warn', S.asof_replaced_badge));
  }
  if (r.quarantine_reason && (r.status === 'quarantined' || r.status === 'rejected')) {
    const hr = humanReason(r.quarantine_reason);
    const reasonWrap = el('div', 'rec-meta');
    reasonWrap.append(el('span', 'badge badge-warn', S.review_why + ' ' + hr.text));
    if (hr.code) reasonWrap.append(el('span', 'badge mono', 'code:' + hr.code));
    card.append(reasonWrap);
  }

  const textDiv = el('div', 'rec-text', r.content === null || r.content === undefined ? S.card_wiped : r.content);
  card.append(textDiv);

  const clocks = el('div', 'rec-clocks');
  if (r.created_at) clocks.append(el('span', '', '🕒 ' + fmtTime(r.created_at, true)));
  if (r.last_seen_at) clocks.append(el('span', '', S.card_seen + ': ' + fmtTime(r.last_seen_at, false)));
  if (r.last_confirmed_at) clocks.append(el('span', '', S.card_confirmed + ': ' + fmtTime(r.last_confirmed_at, false)));
  if (r.valid_from || r.valid_to) {
    const vf = fmtTime(r.valid_from || r.created_at, false);
    const vt = r.valid_to ? fmtTime(r.valid_to, false) : (S.graph_valid_open || 'ongoing');
    clocks.append(el('span', '', '⏱ ' + (S.graph_valid_window || 'Valid:') + ' ' + vf + ' → ' + vt));
  }
  card.append(clocks);

  const acts = el('div', 'rec-actions');
  if (r.status === 'quarantined') {
    const bApp = el('button', 'btn-ok', S.btn_approve);
    bApp.onclick = async () => {
      try { await api('/approve', {id: r.id}); say(S.done, true); loadActiveTab(); refreshTopbarStats(); }
      catch (e) { say(S.failed + ': ' + e.message, false); }
    };
    const bRej = el('button', 'btn-danger', S.btn_reject);
    bRej.onclick = async () => {
      try { await api('/reject', {id: r.id}); say(S.done, true); loadActiveTab(); refreshTopbarStats(); }
      catch (e) { say(S.failed + ': ' + e.message, false); }
    };
    acts.append(bApp, bRej);
  }
  if (r.status === 'active' && Array.isArray(window._padamWorkspaces) && window._padamWorkspaces.length && r.kind !== 'identity' && r.kind !== 'preference') {
    const visSel = document.createElement('select');
    visSel.setAttribute('aria-label', S.team_vis_label || 'Visibility');
    for (const v of ['private', 'team_read', 'team_write']) {
      const opt = document.createElement('option');
      opt.value = v;
      opt.textContent = S['vis_' + v] || v;
      if ((r.visibility || 'private') === v) opt.selected = true;
      visSel.append(opt);
    }
    visSel.onchange = async () => {
      try {
        const wsId = r.workspace_id || (window._padamWorkspaces[0] && window._padamWorkspaces[0].id);
        await api('/records/visibility', {id: r.id, visibility: visSel.value, workspace_id: wsId});
        say(S.done, true);
        loadActiveTab();
      } catch (e) { say(S.failed + ': ' + e.message, false); loadActiveTab(); }
    };
    acts.append(visSel);
  }
  if (r.status === 'active') {
    const bConf = el('button', '', S.card_btn_confirm);
    bConf.onclick = async () => {
      try { await api('/confirm', {id: r.id}); say(S.done, true); loadActiveTab(); }
      catch (e) { say(S.failed + ': ' + e.message, false); }
    };
    const bRef = el('button', '', S.card_btn_refute);
    bRef.onclick = async () => {
      try { await api('/refute', {id: r.id}); say(S.done, true); loadActiveTab(); }
      catch (e) { say(S.failed + ': ' + e.message, false); }
    };
    acts.append(bConf, bRef);
  }
  if (r.status === 'archived') {
    const bRest = el('button', 'btn-ok', S.card_btn_restore);
    bRest.onclick = async () => {
      try { await api('/restore', {id: r.id}); say(S.done, true); loadActiveTab(); }
      catch (e) { say(S.failed + ': ' + e.message, false); }
    };
    acts.append(bRest);
  }

  const verBox = el('div', 'versions-box');
  verBox.hidden = true;
  const bVer = el('button', '', S.card_btn_versions);
  bVer.onclick = async () => {
    if (!verBox.hidden) { verBox.hidden = true; return; }
    try {
      const data = await api('/timeline/' + encodeURIComponent(r.id));
      verBox.replaceChildren(el('div', 'setting-name', S.card_versions_title));
      for (const v of (data.versions || [])) {
        const row = el('div', 'ver-row');
        row.append(
          el('div', 'rec-meta', fmtTime(v.created_at, true) + ' · [' + (S['status_' + v.status] || v.status) + '] · ' + v.id.slice(0, 8)),
          el('div', '', v.content === null ? S.card_wiped : v.content)
        );
        verBox.append(row);
      }
      verBox.hidden = false;
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
  acts.append(bVer);

  const bGraph = el('button', '', S.card_btn_graph);
  bGraph.onclick = () => {
    $('graph-id-input').value = r.id;
    switchTab('graph');
  };
  acts.append(bGraph);

  if (r.status !== 'revoked') {
    const bForget = el('button', 'btn-danger', S.card_btn_forget);
    bForget.onclick = () => {
      $('forget-id-input').value = r.id;
      switchTab('forget');
      previewForget(r.id);
    };
    acts.append(bForget);
  }

  card.append(acts, verBox);
  return card;
}

// --- 1. ОБЗОР ---
async function loadOverview() {
  refreshWorkspacesCache();
  if (!token) { say(S.no_token, false); return; }
  try {
    const data = await api('/overview');
    const st = data.stats || {};
    const doc = data.doctor || {};

    $('kpi-active').textContent = String(st.active || 0);
    $('kpi-review').textContent = String(st.quarantined || 0);
    $('kpi-superseded').textContent = String(st.superseded || 0);
    $('kpi-revoked').textContent = String(st.revoked || 0);
    $('kpi-episodes').textContent = String(st.episodes_pending || 0);
    $('kpi-conflicts').textContent = String((data.conflicts || []).length);

    // По видам
    const kindsBox = $('ov-kinds-list');
    kindsBox.replaceChildren();
    const byKind = st.by_kind || {};
    const totalActive = Math.max(1, st.active || 1);
    const allKinds = ['preference', 'identity', 'decision', 'correction', 'fact', 'state', 'event'];
    for (const k of allKinds) {
      const count = byKind[k] || 0;
      const row = el('div', 'kind-row');
      row.append(
        el('span', '', S['kind_' + k] || k),
        svgBar((count / totalActive) * 100),
        el('strong', '', String(count))
      );
      kindsBox.append(row);
    }

    // Что ждёт решения
    const attBox = $('ov-attention-box');
    attBox.replaceChildren();
    const unsigned = data.unsigned_protected || [];
    const conflicts = data.conflicts || [];
    let hasAtt = false;
    if (unsigned.length > 0) {
      hasAtt = true;
      const item = el('div', 'check-item');
      const btn = el('button', 'btn-warn', S.ov_btn_sign_all);
      btn.onclick = async () => {
        try { await api('/trust-protected', {}); say(S.done, true); loadOverview(); }
        catch (e) { say(S.failed + ': ' + e.message, false); }
      };
      item.append(el('span', '', '⚠️ ' + S.ov_unsigned_alert + ' ' + unsigned.length + ' '), btn);
      attBox.append(item);
    }
    if (st.quarantined > 0) {
      hasAtt = true;
      const item = el('div', 'check-item');
      const btn = el('button', 'btn-warn', S.ov_btn_go_review);
      btn.onclick = () => switchTab('review');
      item.append(el('span', '', '🛡️ ' + S.ov_quarantined_alert + ' ' + st.quarantined + ' '), btn);
      attBox.append(item);
    }
    if (conflicts.length > 0) {
      hasAtt = true;
      for (const c of conflicts) {
        const subj = cleanConflictSubject(c.key);
        const count = (c.records || []).length;
        const prefix = count === 2 ? (S.ov_conflict_two || S.ov_conflict_alert) : (S.ov_conflict_many || S.ov_conflict_alert);
        const item = el('div', 'check-item');
        const btnCmp = el('button', 'btn-warn', S.ov_btn_compare || 'Compare');
        btnCmp.onclick = () => {
          $('feed-q').value = subj;
          switchTab('feed');
        };
        item.append(el('span', '', '⚡ ' + prefix + ' «' + subj + '» '), btnCmp);
        attBox.append(item);
      }
    }
    if (!hasAtt) {
      attBox.append(el('div', 'check-item', '✅ ' + S.ov_attention_clean));
    }

    // Последний сон NOCTURNE
    const sleepBox = $('ov-sleep-info');
    sleepBox.replaceChildren();
    const runs = data.nocturne_runs || [];
    if (!runs.length) {
      sleepBox.append(el('p', 'panel-sub', S.ov_sleep_never));
    } else {
      const last = runs[0];
      sleepBox.append(
        el('div', 'kv-row', ''),
      );
      sleepBox.replaceChildren(
        el('p', '', S.ov_sleep_last + ' ' + fmtTime(last.finished_at || last.started_at, true)),
        el('p', 'panel-sub',
           S.ov_sleep_sampled + ' ' + (last.episodes_sampled || 0) + ' · ' +
           S.ov_sleep_created + ' ' + (last.records_created || 0) + ' · ' +
           S.ov_sleep_merged + ' ' + (last.records_merged || 0) + ' · ' +
           S.ov_sleep_superseded + ' ' + (last.records_superseded || 0))
      );
    }

    // Светофор Doctor
    const banner = $('ov-doctor-banner');
    const lvl = doc.level || 'green';
    banner.className = 'traffic-banner traffic-' + lvl;
    banner.textContent = lvl === 'green' ? ('🟢 ' + S.ov_doctor_green) :
                         (lvl === 'yellow' ? ('🟡 ' + S.ov_doctor_yellow) : ('🔴 ' + S.ov_doctor_red));

    const checksBox = $('ov-doctor-checks');
    checksBox.replaceChildren();
    for (const ch of (doc.checks || [])) {
      const icon = ch.severity === 'ok' ? '🟢' : (ch.severity === 'info' ? '🔵' : (ch.severity === 'warn' ? '🟡' : '🔴'));
      let text = '';
      if (ch.id === 'strict_profile') text = ch.ok ? S.doc_strict_on : S.doc_strict_off;
      else if (ch.id === 'hold_external') text = ch.ok ? S.doc_hold_ext_on : S.doc_hold_ext_off;
      else if (ch.id === 'mcp_review_all') text = ch.ok ? S.doc_review_all_on : S.doc_review_all_off;
      else if (ch.id === 'record_keys') text = ch.ok ? S.doc_keys_ok : (S.doc_keys_warn + ' ' + ch.plain);
      else if (ch.id === 'db_integrity') text = ch.ok ? S.doc_db_ok : (S.doc_db_bad + ' ' + ch.value);
      else if (ch.id === 'disk_sync') text = ch.ok ? S.doc_sync_ok : S.doc_sync_warn;
      else if (ch.id === 'owner_signatures') text = ch.ok ? S.doc_sig_ok : (S.doc_sig_bad + ' ' + ch.unsigned_count);
      else if (ch.id === 'file_mode') text = S.doc_file_ok;
      else text = (ch.name || ch.id) + (ch.detail ? (': ' + ch.detail) : '');
      checksBox.append(el('div', 'check-item', icon + ' ' + text));
    }
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

// --- 2. ЛЕНТА ПАМЯТИ ---
function renderFeedKinds() {
  const box = $('feed-kinds');
  box.replaceChildren();
  const counts = {};
  for (const r of feedShown) counts[r.kind] = (counts[r.kind] || 0) + 1;
  const makeChip = (k, label) => {
    const b = el('button', 'chip', label);
    b.setAttribute('aria-pressed', String(feedKind === k));
    b.onclick = () => { feedKind = k; renderFeedKinds(); renderFeedList(); };
    return b;
  };
  box.append(makeChip(null, S.all_kinds));
  for (const [k, n] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
    box.append(makeChip(k, (S['kind_' + k] || k) + ' · ' + n));
  }
}

function renderFeedList() {
  const list = $('feed-list');
  list.replaceChildren();
  const rows = feedKind ? feedShown.filter(r => r.kind === feedKind) : feedShown;
  if (!rows.length) {
    list.append(el('p', 'panel-sub', S.empty_feed || S.empty));
    return;
  }
  let curDay = '';
  for (const r of rows) {
    const d = (r.created_at || '').slice(0, 10);
    if (d !== curDay) {
      curDay = d;
      list.append(el('div', 'day-head', d));
    }
    list.append(renderRecordCard(r));
  }
}

async function loadFeed(reset = true) {
  if (!token) { say(S.no_token, false); return; }
  if (reset) { feedOffset = 0; feedShown = []; }
  try {
    const q = encodeURIComponent($('feed-q').value.trim());
    const ag = encodeURIComponent(($('feed-agent') ? $('feed-agent').value : '').trim());
    const r = await api('/records?view=' + feedView + '&q=' + q + (ag ? ('&agent_id=' + ag) : '') + '&limit=100&offset=' + feedOffset);
    feedShown = feedShown.concat(r.records || []);
    feedOffset += (r.records || []).length;
    $('feed-more').hidden = feedOffset >= (r.total || 0);
    renderFeedKinds();
    renderFeedList();
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

// --- 3. ПОИСК ---
async function runSearch() {
  const q = $('search-input').value.trim();
  const kind = $('search-kind').value || null;
  const list = $('search-results');
  list.replaceChildren();
  if (!q) {
    list.append(el('p', 'panel-sub', S.empty_search || S.empty));
    return;
  }
  try {
    const r = await api('/search', {query: q, kind, limit: 25});
    const rows = r.results || [];
    if (!rows.length) {
      list.append(el('p', 'panel-sub', S.empty_search || S.empty));
      return;
    }
    for (const item of rows) {
      list.append(renderRecordCard(item, {explain: true}));
    }
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}


// --- Г10. СПРОСИ СВОЮ ПАМЯТЬ ---
async function loadAskTab() {
  try {
    const s = await api('/settings');
    const badge = $('ask-ollama-status');
    if (badge) {
      const ol = s.ollama || {};
      const mod = s.ask_model || (ol.models && ol.models[0]) || '';
      if (ol.available && mod) {
        badge.className = 'badge badge-ok';
        badge.textContent = '🟢 ' + S.ask_ollama_ready + ' ' + mod;
      } else {
        badge.className = 'badge';
        badge.textContent = 'ℹ️ ' + S.ask_ollama_off;
      }
    }
  } catch (e) {}
}

async function runAsk() {
  const q = ($('ask-input').value || '').trim();
  const ansBox = $('ask-answer-box');
  const list = $('ask-results');
  ansBox.replaceChildren();
  ansBox.hidden = true;
  list.replaceChildren();
  if (!q) {
    list.append(el('p', 'panel-sub', S.ask_empty));
    return;
  }
  try {
    const r = await api('/ask', {question: q, limit: 6});
    const badge = $('ask-ollama-status');
    if (badge) {
      if (r.ollama_available && r.model) {
        badge.className = 'badge badge-ok';
        badge.textContent = '🟢 ' + S.ask_ollama_ready + ' ' + r.model;
      } else {
        badge.className = 'badge';
        badge.textContent = 'ℹ️ ' + S.ask_ollama_off;
      }
    }
    if (r.answer) {
      ansBox.hidden = false;
      ansBox.append(
        el('div', 'setting-name', '🤖 ' + S.ask_answer_title + (r.model ? (' [' + r.model + ']') : '')),
        el('div', 'rec-text', r.answer)
      );
    }
    const rows = r.records || [];
    if (!rows.length) {
      list.append(el('p', 'panel-sub', S.empty_search || S.empty));
      return;
    }
    list.append(el('h3', 'box-title', S.ask_sources_title));
    for (const item of rows) {
      list.append(renderRecordCard(item, {explain: true}));
    }
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

// --- Г11. ЭКРАН «СУЩНОСТИ» ---
let entitiesCatalog = [];
let selectedEntityKey = null;

function renderEntityRecords() {
  const recBox = $('entities-records');
  recBox.replaceChildren();
  const found = entitiesCatalog.find(e => e.key === selectedEntityKey) || entitiesCatalog[0] || null;
  if (!found) return;
  selectedEntityKey = found.key;
  for (const btn of document.querySelectorAll('[data-entity-key]')) {
    btn.setAttribute('aria-pressed', String(btn.getAttribute('data-entity-key') === selectedEntityKey));
  }
  recBox.append(el('h3', 'box-title', S.entities_records_for + ' «' + found.name + '» (' + found.count + ')'));
  for (const r of (found.records || [])) {
    recBox.append(renderRecordCard(r));
  }
}

async function loadEntities() {
  const q = ($('entities-filter') ? $('entities-filter').value : '').trim();
  const grid = $('entities-grid');
  const recBox = $('entities-records');
  if (!grid || !recBox) return;
  try {
    const r = await api('/entities?limit=120' + (q ? ('&q=' + encodeURIComponent(q)) : ''));
    grid.replaceChildren();
    recBox.replaceChildren();
    entitiesCatalog = r.entities || [];
    if (!entitiesCatalog.length) {
      grid.append(el('p', 'panel-sub', S.entities_empty));
      return;
    }
    if (!selectedEntityKey || !entitiesCatalog.some(e => e.key === selectedEntityKey)) {
      selectedEntityKey = entitiesCatalog[0].key;
    }
    for (const ent of entitiesCatalog) {
      const card = el('button', 'entity-card');
      card.setAttribute('data-entity-key', ent.key);
      card.setAttribute('aria-pressed', String(ent.key === selectedEntityKey));
      const catLabel = S['ent_cat_' + ent.category] || ent.category;
      const top = el('div', 'entity-title', ent.name);
      const meta = el('div', 'rec-meta');
      meta.append(
        el('span', 'badge', catLabel),
        el('span', 'badge badge-ok', String(ent.count))
      );
      card.append(top, meta);
      card.onclick = () => {
        selectedEntityKey = ent.key;
        renderEntityRecords();
      };
      grid.append(card);
    }
    renderEntityRecords();
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

// --- Г9. БЫСТРАЯ ЗАПИСЬ ГОРЯЧЕЙ КЛАВИШЕЙ ---
function openQuickAddModal() {
  const modal = $('quick-add-modal');
  if (!modal) return;
  modal.hidden = false;
  const inp = $('quick-add-text');
  if (inp) { inp.focus(); inp.select(); }
}

function closeQuickAddModal() {
  const modal = $('quick-add-modal');
  if (modal) modal.hidden = true;
}

async function saveQuickAdd() {
  const inp = $('quick-add-text');
  const kindSel = $('quick-add-kind');
  const text = (inp ? inp.value : '').trim();
  const kind = (kindSel && kindSel.value) ? kindSel.value : 'fact';
  if (!text) return;
  try {
    await api('/write', {content: text, kind, origin: 'user'});
    if (inp) inp.value = '';
    closeQuickAddModal();
    say(S.done, true);
    loadActiveTab();
    refreshTopbarStats();
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

// --- 4. НА ПРОВЕРКУ ---
async function loadReview() {
  const list = $('review-list');
  try {
    const r = await api('/records?view=review&limit=100&offset=0');
    list.replaceChildren();
    const rows = r.records || [];
    if (!rows.length) {
      list.append(el('p', 'panel-sub', S.empty_review || S.ov_attention_clean));
      return;
    }
    for (const item of rows) {
      list.append(renderRecordCard(item));
    }
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

// --- 5. ПАМЯТЬ НА ДАТУ ---
async function loadAsOf() {
  const dateVal = $('asof-date').value;
  if (!dateVal) return;
  const q = $('asof-query').value.trim();
  const list = $('asof-results');
  list.replaceChildren();
  try {
    let rows = [];
    if (q) {
      const r = await api('/search', {query: q, as_of: dateVal, limit: 50});
      rows = r.results || [];
    } else {
      const r = await api('/records?as_of=' + encodeURIComponent(dateVal) + '&limit=100&offset=0');
      rows = r.records || [];
    }
    if (!rows.length) {
      list.append(el('p', 'panel-sub', S.empty_asof || S.empty));
      return;
    }
    for (const item of rows) {
      list.append(renderRecordCard(item, {asof: true, explain: Boolean(q)}));
    }
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

// --- 6. ЗАБЫТЬ И КВИТАНЦИИ ---
async function previewForget(id) {
  const targetId = (id || $('forget-id-input').value || '').trim();
  const box = $('forget-preview-box');
  box.replaceChildren();
  $('forget-confirm-box').hidden = true;
  $('forget-step1-btn').hidden = false;
  if (!targetId) return;
  try {
    const p = await api('/forget-preview?id=' + encodeURIComponent(targetId));
    box.append(
      el('div', 'rec-meta', (S['kind_' + p.kind] || p.kind) + ' · ' + p.id),
      el('div', 'rec-text', p.content === null ? S.card_wiped : p.content),
      el('div', 'check-item', S.forget_preview_versions + ' ' + p.versions_count + ' · ' +
         S.forget_preview_derived + ' ' + p.derived_count)
    );
  } catch (e) {
    box.append(el('p', 'msg-err', S.failed + ': ' + e.message));
  }
}

function renderReceiptCard(rc) {
  const box = el('div', 'receipt-card');
  box.append(
    el('h3', 'box-title', '🧾 ' + S.receipt_box_title),
    el('p', 'panel-sub', S.receipt_disclaimer)
  );
  const fields = [
    [S.receipt_id, rc.receipt_id],
    [S.receipt_mem_id, rc.memory_id],
    [S.receipt_time, rc.forgotten_at],
    [S.receipt_hash, rc.content_hash_sha256 || '—'],
    [S.receipt_wiped, String(rc.wiped_count || 1) + (rc.with_derived ? ' (+ derived)' : '')],
    [S.receipt_key, S.receipt_key_destroyed],
    [S.receipt_leaf, rc.leaf_forget_hex || '—'],
  ];
  for (const [k, v] of fields) {
    const row = el('div', 'kv-row');
    row.append(el('span', 'panel-sub', k), el('span', 'mono', v));
    box.append(row);
  }
  const acts = el('div', 'rec-actions');
  const bJson = el('button', '', S.receipt_download_json);
  bJson.onclick = () => {
    const blob = new Blob([JSON.stringify(rc, null, 2)], {type: 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'padam-forget-receipt-' + String(rc.receipt_id).slice(0, 8) + '.json';
    a.click();
  };
  const bHtml = el('button', '', S.receipt_download_html);
  bHtml.onclick = () => {
    const lines = [
      '<!doctype html><html lang="' + currentLang + '"><head><meta charset="utf-8">',
      '<title>' + S.receipt_box_title + ' — ' + rc.receipt_id + '</title>',
      '<style>body{font:15px/1.6 system-ui,sans-serif;max-width:760px;margin:40px auto;padding:24px;color:#0f172a}',
      '.box{border:2px solid #0284c7;border-radius:12px;padding:24px}.row{padding:8px 0;border-bottom:1px solid #cbd5e1}',
      'code{font-family:monospace;word-break:break-all}</style></head><body><div class="box">',
      '<h1>' + S.receipt_box_title + '</h1><p>' + S.receipt_disclaimer + '</p>'
    ];
    for (const [k, v] of fields) {
      lines.push('<div class="row"><strong>' + k + '</strong><br><code>' + String(v).replace(/</g, '&lt;') + '</code></div>');
    }
    lines.push('</div></body></html>');
    const blob = new Blob([lines.join('\n')], {type: 'text/html;charset=utf-8'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'padam-forget-receipt-' + String(rc.receipt_id).slice(0, 8) + '.html';
    a.click();
  };
  acts.append(bJson, bHtml);
  box.append(acts);
  return box;
}

async function loadForgetTab() {
  const latestBox = $('forget-latest-receipt');
  latestBox.replaceChildren();
  if (lastReceipt) latestBox.append(renderReceiptCard(lastReceipt));
  const histBox = $('forget-receipts-list');
  histBox.replaceChildren();
  try {
    const r = await api('/forget-receipts?limit=25');
    const list = r.receipts || [];
    if (!list.length) {
      histBox.append(el('p', 'panel-sub', S.empty_receipts || S.empty));
      return;
    }
    for (const rc of list) {
      histBox.append(renderReceiptCard(rc));
    }
  } catch (e) {}
}

// --- 7. ГРАФ СВЯЗЕЙ ---
function layoutGraph(nodes, edges, width, height) {
  const pos = {};
  const n = nodes.length;
  if (!n) return pos;
  // Начальное размещение по разнесённой шахматной сетке, чтобы ни одна пара подписей не слипалась
  const cols = Math.min(4, Math.max(2, Math.ceil(Math.sqrt(n * 1.3))));
  const rows = Math.max(1, Math.ceil(n / cols));
  const padX = 115, padY = 54;
  const usableW = Math.max(200, width - padX * 2);
  const usableH = Math.max(160, height - padY * 2);
  nodes.forEach((node, i) => {
    const r = Math.floor(i / cols);
    const c = i % cols;
    const staggerX = (r % 2 === 1 && cols > 2) ? (usableW / (cols * 3.2)) : 0;
    const staggerY = (c % 2 === 1) ? 14 : -10;
    const fx = cols === 1 ? 0.5 : (c / (cols - 1));
    const fy = rows === 1 ? 0.5 : (r / (rows - 1));
    pos[node.id] = {
      x: Math.max(padX, Math.min(width - padX, padX + fx * usableW + staggerX)),
      y: Math.max(padY, Math.min(height - padY, padY + fy * usableH + staggerY)),
      vx: 0, vy: 0
    };
  });
  // Мягкое сближение связанных узлов и жёсткое разнесение прямоугольников подписей
  for (let pass = 0; pass < 36; pass++) {
    for (const e of edges) {
      const a = pos[e.source], b = pos[e.target];
      if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.hypot(dx, dy) || 1;
      if (dist > 260) {
        const pull = (dist - 260) * 0.04;
        a.x += (dx / dist) * pull; a.y += (dy / dist) * pull;
        b.x -= (dx / dist) * pull; b.y -= (dy / dist) * pull;
      }
    }
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = pos[nodes[i].id], b = pos[nodes[j].id];
        let dx = b.x - a.x, dy = b.y - a.y;
        if (Math.abs(dx) < 1 && Math.abs(dy) < 1) { dx = 10; dy = 10; }
        const minDX = 210, minDY = 62;
        if (Math.abs(dx) < minDX && Math.abs(dy) < minDY) {
          const overlapX = (minDX - Math.abs(dx)) * 0.35 * (dx >= 0 ? 1 : -1);
          const overlapY = (minDY - Math.abs(dy)) * 0.55 * (dy >= 0 ? 1 : -1);
          a.x -= overlapX; b.x += overlapX;
          a.y -= overlapY; b.y += overlapY;
        }
      }
    }
    for (const node of nodes) {
      const p = pos[node.id];
      p.x = Math.max(padX, Math.min(width - padX, p.x));
      p.y = Math.max(padY, Math.min(height - padY, p.y));
    }
  }
  return pos;
}

function drawGraph() {
  const canvas = $('graph-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = isDark ? '#0b101d' : '#f8fafc';
  ctx.fillRect(0, 0, w, h);

  const nodes = graphData.nodes || [];
  const edges = graphData.edges || [];
  if (!nodes.length) {
    ctx.fillStyle = isDark ? '#94a3b8' : '#475569';
    ctx.font = '15px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(S.empty_graph || S.empty, w / 2, h / 2);
    return;
  }

  for (const e of edges) {
    const a = graphPositions[e.source], b = graphPositions[e.target];
    if (!a || !b) continue;
    ctx.beginPath();
    ctx.lineWidth = 2.2;
    if (e.type === 'derived') { ctx.strokeStyle = isDark ? '#00d2ff' : '#0284c7'; ctx.setLineDash([]); }
    else if (e.type === 'cause') { ctx.strokeStyle = isDark ? '#34d399' : '#059669'; ctx.setLineDash([]); }
    else if (e.type === 'correction') { ctx.strokeStyle = isDark ? '#fbbf24' : '#d97706'; ctx.setLineDash([]); }
    else if (e.type === 'contradiction') { ctx.strokeStyle = isDark ? '#f87171' : '#dc2626'; ctx.setLineDash([6, 4]); }
    else if (e.type === 'version') { ctx.strokeStyle = isDark ? '#a78bfa' : '#4f46e5'; ctx.setLineDash([4, 4]); }
    else { ctx.strokeStyle = isDark ? '#fb7185' : '#e11d48'; ctx.setLineDash([2, 4]); }
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
    ctx.setLineDash([]);

    // Стрелка направления
    const angle = Math.atan2(b.y - a.y, b.x - a.x);
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
    ctx.beginPath();
    ctx.moveTo(mx + 7 * Math.cos(angle), my + 7 * Math.sin(angle));
    ctx.lineTo(mx - 6 * Math.cos(angle - 0.55), my - 6 * Math.sin(angle - 0.55));
    ctx.lineTo(mx - 6 * Math.cos(angle + 0.55), my - 6 * Math.sin(angle + 0.55));
    ctx.closePath();
    ctx.fillStyle = ctx.strokeStyle;
    ctx.fill();
  }

  nodes.forEach((node) => {
    const p = graphPositions[node.id];
    if (!p) return;
    const isSel = selectedGraphNode && selectedGraphNode.id === node.id;
    ctx.beginPath();
    ctx.arc(p.x, p.y, isSel ? 16 : 12, 0, Math.PI * 2);
    if (node.status === 'superseded') ctx.fillStyle = isDark ? '#64748b' : '#94a3b8';
    else if (node.kind === 'identity' || node.kind === 'preference') ctx.fillStyle = isDark ? '#a855f7' : '#7c3aed';
    else if (node.kind === 'decision') ctx.fillStyle = isDark ? '#34d399' : '#059669';
    else ctx.fillStyle = isDark ? '#00d2ff' : '#0284c7';
    ctx.fill();
    ctx.lineWidth = isSel ? 3 : 1.8;
    ctx.strokeStyle = isSel ? '#fbbf24' : (isDark ? '#f1f5f9' : '#0f172a');
    ctx.stroke();

    ctx.font = '12px system-ui, sans-serif';
    ctx.textAlign = 'center';
    const shortLabel = truncateAtWord(node.content || node.label || node.id, 25);
    const ly = p.y + 27;
    const tw = ctx.measureText(shortLabel).width + 12;
    ctx.fillStyle = isDark ? 'rgba(11, 16, 29, 0.90)' : 'rgba(255, 255, 255, 0.92)';
    ctx.fillRect(p.x - tw / 2, ly - 12, tw, 17);
    ctx.fillStyle = isDark ? '#e2e8f0' : '#0f172a';
    ctx.fillText(shortLabel, p.x, ly);
  });
}

let graphLastReceipt = null;

function relLabel(t) {
  if (t === 'derived') return S.graph_legend_derived || 'derived';
  if (t === 'cause') return S.graph_legend_cause || 'cause';
  if (t === 'correction') return S.graph_legend_correction || 'correction';
  if (t === 'contradiction') return S.graph_legend_contradiction || 'contradiction';
  if (t === 'version') return S.graph_legend_version || 'version';
  return S.graph_legend_conflict || t;
}

function renderSelectedGraphNode() {
  const box = $('graph-selected-box');
  box.replaceChildren();
  if (graphLastReceipt) {
    box.append(renderReceiptCard(graphLastReceipt));
  }
  if (!selectedGraphNode) {
    box.append(el('p', 'panel-sub', S.graph_subtitle));
    return;
  }
  box.append(renderRecordCard(selectedGraphNode));

  const nodesMap = {};
  for (const n of (graphData.nodes || [])) nodesMap[n.id] = n;
  const incident = (graphData.edges || []).filter(e => e.source === selectedGraphNode.id || e.target === selectedGraphNode.id);
  if (incident.length) {
    const relBox = el('div', 'versions-box');
    relBox.append(el('div', 'setting-name', S.graph_edges_list_title || 'Node relations'));
    for (const e of incident) {
      const otherId = e.source === selectedGraphNode.id ? e.target : e.source;
      const arrow = e.source === selectedGraphNode.id ? ' → ' : ' ← ';
      const otherNode = nodesMap[otherId];
      const row = el('div', 'ver-row rec-actions');
      const lbl = el('span', 'badge', relLabel(e.type || e.relation));
      const bJump = el('button', '', arrow + truncateAtWord((otherNode && otherNode.content) || otherId, 48));
      bJump.onclick = () => {
        $('graph-id-input').value = otherId;
        loadGraph();
      };
      row.append(lbl, bJump);
      relBox.append(row);
    }
    box.append(relBox);
  }

  // Добавление явного ребра графа (источник / причина / исправление / противоречие)
  const linkRow = el('div', 'toolbar');
  const selRel = document.createElement('select');
  selRel.id = 'graph-link-rel';
  selRel.setAttribute('aria-label', S.graph_link_add_title || 'Relation type');
  for (const rKey of ['derived', 'cause', 'correction', 'contradiction']) {
    const opt = document.createElement('option');
    opt.value = rKey;
    opt.textContent = relLabel(rKey);
    selRel.append(opt);
  }
  const inpDst = document.createElement('input');
  inpDst.type = 'text';
  inpDst.placeholder = S.graph_link_target_placeholder || 'Target record ID…';
  inpDst.setAttribute('aria-label', S.graph_link_target_placeholder || 'Target record ID');
  const bLink = el('button', '', S.graph_link_btn || 'Link');
  bLink.onclick = async () => {
    const targetId = inpDst.value.trim();
    if (!targetId) return;
    try {
      await api('/link', {source: selectedGraphNode.id, target: targetId, relation: selRel.value});
      say(S.done, true);
      loadGraph();
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
  linkRow.append(el('span', 'panel-sub', S.graph_link_add_title || 'Add relation:'), selRel, inpDst, bLink);
  box.append(linkRow);

  // 4.3: Удаление источника вместе с выводами прямо со вкладки «Связи» с подтверждением и квитанцией
  if (selectedGraphNode.status !== 'revoked') {
    const delWrap = el('div', 'rec-actions');
    const bAsk = el('button', 'btn-danger', S.graph_forget_derived_btn || 'Forget source + derived');
    const confBox = el('div', 'versions-box');
    confBox.hidden = true;
    bAsk.onclick = async () => {
      try {
        const p = await api('/forget-preview?id=' + encodeURIComponent(selectedGraphNode.id));
        confBox.replaceChildren();
        confBox.append(
          el('p', 'msg-err', S.graph_forget_confirm_warn || 'Confirm erasure?'),
          el('div', 'check-item', (S.forget_preview_versions || 'Versions:') + ' ' + p.versions_count + ' · ' + (S.forget_preview_derived || 'Derived:') + ' ' + p.derived_count)
        );
        if (p.derived && p.derived.length) {
          for (const d of p.derived.slice(0, 8)) {
            confBox.append(el('div', 'ver-row', '↳ ' + truncateAtWord(d.content || d.id, 90)));
          }
        }
        const acts2 = el('div', 'rec-actions');
        const bYes = el('button', 'btn-danger', S.forget_step2_btn || 'Confirm');
        bYes.onclick = async () => {
          try {
            const res = await api('/forget', {id: selectedGraphNode.id, with_derived: true});
            if (res.receipt) {
              graphLastReceipt = res.receipt;
              lastReceipt = res.receipt;
            }
            if ($('graph-id-input').value.trim() === selectedGraphNode.id) $('graph-id-input').value = '';
            say(S.done, true);
            await loadGraph();
            refreshTopbarStats();
          } catch (e) { say(S.failed + ': ' + e.message, false); }
        };
        const bNo = el('button', '', S.forget_cancel || 'Cancel');
        bNo.onclick = () => { confBox.hidden = true; };
        acts2.append(bYes, bNo);
        confBox.append(acts2);
        confBox.hidden = false;
      } catch (e) { say(S.failed + ': ' + e.message, false); }
    };
    delWrap.append(bAsk);
    box.append(delWrap, confBox);
  }
}

async function loadGraph() {
  const focusId = ($('graph-id-input').value || '').trim();
  const asOfDate = ($('graph-asof-input') && $('graph-asof-input').value || '').trim();
  try {
    const params = [];
    if (focusId) params.push('id=' + encodeURIComponent(focusId));
    if (asOfDate) params.push('as_of=' + encodeURIComponent(asOfDate));
    const path = '/graph' + (params.length ? ('?' + params.join('&')) : '');
    graphData = await api(path);
    const canvas = $('graph-canvas');
    graphPositions = layoutGraph(graphData.nodes || [], graphData.edges || [], canvas.width, canvas.height);
    selectedGraphNode = (graphData.nodes || []).find(n => n.id === focusId) || (graphData.nodes || [])[0] || null;
    drawGraph();
    renderSelectedGraphNode();
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

// --- 8. ВЕЧНЫЙ СЛОЙ L3 ---
async function refreshWorkspacesCache() {
  try {
    const d = await api('/workspaces');
    window._padamWorkspaces = d.workspaces || [];
    return d;
  } catch (e) {
    window._padamWorkspaces = [];
    return {workspaces: [], members: [], actor: null};
  }
}

async function loadTeam() {
  const wsList = $('team-workspaces-list');
  const memList = $('team-members-list');
  const sel = $('team-ws-select');
  if (!wsList || !memList) return;
  try {
    const d = await refreshWorkspacesCache();
    const wss = d.workspaces || [];
    const mems = d.members || [];
    wsList.replaceChildren();
    if (sel) sel.replaceChildren();
    if (!wss.length) {
      wsList.append(el('div', 'empty-box', S.team_empty || 'No teams yet'));
    } else {
      for (const w of wss) {
        const row = el('div', 'setting-row');
        const info = el('div', 'setting-info');
        info.append(el('div', 'setting-name', w.name));
        info.append(el('div', 'setting-desc mono', 'id: ' + w.id));
        row.append(info);
        wsList.append(row);
        if (sel) {
          const opt = document.createElement('option');
          opt.value = w.id;
          opt.textContent = w.name + ' (' + w.id + ')';
          sel.append(opt);
        }
      }
    }
    memList.replaceChildren();
    for (const m of mems) {
      const row = el('div', 'setting-row');
      const info = el('div', 'setting-info');
      info.append(el('div', 'setting-name', m.subject + ' · ' + m.role));
      info.append(el('div', 'setting-desc mono', (m.workspace_name || m.workspace_id) + ' · ' + m.token_prefix + '…'));
      row.append(info);
      if (m.revoked_at) {
        row.append(el('span', 'badge badge-danger', S.team_revoked_badge || 'revoked'));
      } else {
        const btnRev = el('button', 'btn-danger', S.team_revoke_btn || 'Revoke');
        btnRev.onclick = async () => {
          try {
            await api('/workspaces/revoke', {workspace_id: m.workspace_id, subject: m.subject});
            say(S.done, true);
            loadTeam();
          } catch (e) { say(S.failed + ': ' + e.message, false); }
        };
        row.append(btnRev);
      }
      memList.append(row);
    }
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

if ($('team-create-btn')) {
  $('team-create-btn').onclick = async () => {
    const inp = $('team-create-input');
    const name = inp ? inp.value.trim() : '';
    if (!name) return;
    try {
      await api('/workspaces', {name});
      if (inp) inp.value = '';
      say(S.done, true);
      loadTeam();
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
}

if ($('team-add-btn')) {
  $('team-add-btn').onclick = async () => {
    const wsId = $('team-ws-select') ? $('team-ws-select').value : '';
    const subj = $('team-subj-input') ? $('team-subj-input').value.trim() : '';
    const role = $('team-role-select') ? $('team-role-select').value : 'contributor';
    if (!wsId || !subj) return;
    try {
      const res = await api('/workspaces/members', {workspace_id: wsId, subject: subj, role});
      if ($('team-subj-input')) $('team-subj-input').value = '';
      const box = $('team-token-box');
      const codeEl = $('team-issued-token');
      if (box && codeEl && res.token) {
        codeEl.textContent = res.token;
        box.hidden = false;
      }
      say(S.done, true);
      loadTeam();
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
}

async function loadL3() {
  try {
    const d = await api('/l3');
    $('l3-unanchored-num').textContent = String(d.unanchored_records || 0);
    $('l3-forgets-num').textContent = String(d.pending_forgets || 0);
    const rk = d.record_keys || {};
    $('l3-keys-status').textContent = rk.passphrase_protected ? S.l3_keys_protected : S.l3_keys_open;

    const list = $('l3-anchors-list');
    list.replaceChildren();
    const anchors = d.anchors || [];
    if (!anchors.length) {
      list.append(el('p', 'panel-sub', S.l3_no_anchors));
      return;
    }
    for (const a of anchors) {
      const card = el('div', 'rec-card');
      const head = el('div', 'rec-meta');
      head.append(
        el('span', 'badge badge-ok', a.network || 'devnet'),
        el('span', '', fmtTime(a.created_at, true)),
        el('span', '', S.l3_col_leaves + ' ' + a.leaf_count),
        el('span', '', S.l3_col_bytes + ' ' + a.bundle_bytes + ' B')
      );
      card.append(head);
      card.append(el('div', 'mono', S.l3_col_root + ' ' + a.root_hex));
      const links = el('div', 'rec-actions');
      if (a.solscan_url) {
        const lSol = el('a', 'badge', 'Solscan: ' + String(a.solana_sig).slice(0, 12) + '…');
        lSol.href = a.solscan_url; lSol.target = '_blank'; lSol.rel = 'noopener noreferrer';
        links.append(lSol);
      }
      if (a.arweave_url) {
        const lAr = el('a', 'badge', 'Arweave: ' + String(a.arweave_tx).slice(0, 12) + '…');
        lAr.href = a.arweave_url; lAr.target = '_blank'; lAr.rel = 'noopener noreferrer';
        links.append(lAr);
      }
      const resBox = el('div', 'explain-box');
      resBox.hidden = true;
      const bVer = el('button', 'btn-primary', S.l3_btn_verify);
      bVer.onclick = async () => {
        try {
          const v = await api('/l3-verify', {anchor: a.id});
          resBox.hidden = false;
          resBox.textContent = v.ok ? ('✅ ' + S.l3_verify_ok + ' (root=' + (v.root_recomputed || '').slice(0, 16) + '…)') :
                                      ('❌ ' + S.l3_verify_fail + ' ' + JSON.stringify(v));
        } catch (e) { say(S.failed + ': ' + e.message, false); }
      };
      links.append(bVer);
      card.append(links, resBox);
      list.append(card);
    }
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

// --- 9. НАСТРОЙКИ ---
let _lmPower = 'half';
function _lmPaint(r) {
  _lmPower = r.power || 'half';
  for (const m of (r.power_modes || [])) {
    const b = $('lm-power-' + m.id);
    if (!b) continue;
    b.textContent = (S['lm_power_' + m.id] || m.id) + ' · ' + m.threads + ' ' + (S.lm_threads || '');
    b.setAttribute('aria-pressed', String(m.id === _lmPower));
    b.classList.toggle('btn-primary', m.id === _lmPower);
  }
  const st = $('lm-status');
  if (st) {
    st.textContent = '';
    const head = r.mode === 'llama_cpp_gguf' ? S.lm_ready : S.lm_builtin;
    st.appendChild(_el('p', 'panel-sub', head + ' · CPU ' + (r.cpu_cores || 0) + ' · RAM ' + Math.round(r.system_ram_gb || 0) + ' GB'));
    const rec = r.recommended || {};
    st.appendChild(_el('p', 'panel-sub', (S.lm_recommended || '') + ': ' + (rec.recommended_model || '') + ' · ' + (rec.recommended_quant || '')));
    if (r.next_step === 'install') {
      st.appendChild(_el('p', 'panel-sub', S.lm_need_install || ''));
      st.appendChild(_el('code', '', 'pip install llama-cpp-python'));
    }
    if (r.last_error) st.appendChild(_el('p', 'panel-sub', '⚠ ' + String(r.last_error).slice(0, 200)));
    else if (r.next_step === 'choose_model' && !(r.models_found || []).length) st.appendChild(_el('p', 'panel-sub', S.lm_need_model || ''));
  }
  const sel = $('lm-model');
  if (sel) {
    sel.textContent = '';
    const none = document.createElement('option');
    none.value = ''; none.textContent = S.lm_model_none || '';
    sel.appendChild(none);
    for (const m of (r.models_found || [])) {
      const o = document.createElement('option');
      o.value = m.path; o.textContent = m.name + ' · ' + m.size_gb + ' GB';
      if (String(m.path).toLowerCase() === String(r.gguf_path || '').toLowerCase()) o.selected = true;
      sel.appendChild(o);
    }
    if (r.gguf_path && ![...sel.options].some(o => o.value.toLowerCase() === r.gguf_path.toLowerCase())) {
      const o = document.createElement('option');
      o.value = r.gguf_path; o.textContent = r.gguf_path; o.selected = true;
      sel.appendChild(o);
    }
  }
}
async function loadLocalModel() {
  try { _lmPaint(await api('/api/v2/local-model')); } catch (e) { const o = $('lm-out'); if (o) o.textContent = String(e.message || e); }
}
for (const id of ['eco', 'half', 'full']) {
  const b = $('lm-power-' + id);
  if (b) b.onclick = () => {
    _lmPower = id;
    for (const k of ['eco', 'half', 'full']) {
      const x = $('lm-power-' + k);
      if (x) { x.setAttribute('aria-pressed', String(k === id)); x.classList.toggle('btn-primary', k === id); }
    }
  };
}
if ($('lm-save')) {
  $('lm-save').onclick = async () => {
    const out = $('lm-out');
    if (out) out.textContent = S.loading;
    try {
      const r = await api('/api/v2/local-model', { power: _lmPower, gguf_path: ($('lm-model') || {}).value || '' });
      _lmPaint(r);
      if (out) out.textContent = S.lm_saved || 'OK';
    } catch (e) {
      if (out) out.textContent = String(e.message || e);
    }
  };
}

async function loadSettings() {
  try {
    const s = await api('/settings');
    const safeBox = $('settings-safe-list');
    safeBox.replaceChildren();

    const makeToggleRow = (nameKey, descKey, isOn, fieldName) => {
      const row = el('div', 'setting-row');
      const info = el('div', 'setting-info');
      info.append(el('div', 'setting-name', S[nameKey]), el('div', 'setting-desc', S[descKey]));
      const ctrl = el('div', 'rec-actions');
      ctrl.append(el('span', isOn ? 'badge badge-ok' : 'badge', isOn ? S.set_state_on : S.set_state_off));
      const btn = el('button', isOn ? '' : 'btn-primary', isOn ? S.set_btn_disable : S.set_btn_enable);
      btn.onclick = async () => {
        try {
          await api('/settings', {[fieldName]: !isOn});
          say(S.done, true);
          loadSettings();
        } catch (e) { say(S.failed + ': ' + e.message, false); }
      };
      ctrl.append(btn);
      row.append(info, ctrl);
      return row;
    };

    safeBox.append(
      makeToggleRow('set_strict_name', 'set_strict_desc', Boolean(s.strict), 'strict'),
      makeToggleRow('set_review_all_name', 'set_review_all_desc', Boolean(s.mcp_review_all), 'mcp_review_all'),
      makeToggleRow('set_feedback_name', 'set_feedback_desc', Boolean(s.search_feedback), 'search_feedback'),
      makeToggleRow('set_rerank_name', 'set_rerank_desc', Boolean(s.rerank), 'rerank'),
      makeToggleRow('set_mask_pii_name', 'set_mask_pii_desc', Boolean(s.mask_pii), 'mask_pii')
    );

    if (s.autostart_supported) {
      const autoRow = el('div', 'setting-row');
      const autoInfo = el('div', 'setting-info');
      autoInfo.append(el('div', 'setting-name', S.set_autostart_name), el('div', 'setting-desc', S.set_autostart_desc));
      const autoCtrl = el('div', 'rec-actions');
      const chkLabel = el('label', 'rec-meta');
      chkLabel.htmlFor = 'set-autostart-chk';
      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.id = 'set-autostart-chk';
      chk.checked = Boolean(s.autostart);
      chk.onchange = async () => {
        try {
          await api('/settings', {autostart: chk.checked});
          say(S.done, true);
          loadSettings();
        } catch (e) { say(S.failed + ': ' + e.message, false); }
      };
      chkLabel.append(chk, document.createTextNode(' ' + (s.autostart ? S.set_state_on : S.set_state_off)));
      autoCtrl.append(chkLabel);
      autoRow.append(autoInfo, autoCtrl);
      safeBox.append(autoRow);
    }

    // Профиль консолидации
    const profRow = el('div', 'setting-row');
    const profInfo = el('div', 'setting-info');
    profInfo.append(el('div', 'setting-name', S.set_profile_name), el('div', 'setting-desc', S.set_profile_desc));
    const profCtrl = el('div', 'rec-actions');
    for (const p of ['default', 'ops', 'creative']) {
      const b = el('button', s.profile === p ? 'btn-primary' : '', p);
      b.onclick = async () => {
        try { await api('/settings', {profile: p}); say(S.done, true); loadSettings(); }
        catch (e) { say(S.failed + ': ' + e.message, false); }
      };
      profCtrl.append(b);
    }
    profRow.append(profInfo, profCtrl);
    safeBox.append(profRow);

    // Г10: Выбор локальной модели Ollama
    const askRow = el('div', 'setting-row');
    const askInfo = el('div', 'setting-info');
    askInfo.append(el('div', 'setting-name', S.set_ask_model_name), el('div', 'setting-desc', S.set_ask_model_desc));
    const askCtrl = el('div', 'rec-actions');
    const askInp = document.createElement('input');
    askInp.type = 'text';
    askInp.id = 'set-ask-model-input';
    askInp.value = s.ask_model || '';
    askInp.placeholder = S.set_ask_model_placeholder;
    const askBtn = el('button', 'btn-primary', S.set_ask_model_save);
    askBtn.id = 'set-ask-model-save-btn';
    askBtn.onclick = async () => {
      try {
        await api('/settings', {ask_model: askInp.value.trim()});
        say(S.done, true);
        loadSettings();
      } catch (e) { say(S.failed + ': ' + e.message, false); }
    };
    askCtrl.append(askInp, askBtn);
    const olModels = (s.ollama && s.ollama.models) ? s.ollama.models : [];
    for (const mName of olModels.slice(0, 4)) {
      const mBtn = el('button', s.ask_model === mName ? 'btn-ok' : '', mName);
      mBtn.onclick = async () => {
        try { await api('/settings', {ask_model: mName}); say(S.done, true); loadSettings(); }
        catch (e) { say(S.failed + ': ' + e.message, false); }
      };
      askCtrl.append(mBtn);
    }
    askRow.append(askInfo, askCtrl);
    safeBox.append(askRow);

    // Только чтение (опасные)
    const roBox = $('settings-readonly-list');
    roBox.replaceChildren();
    const makeReadOnlyRow = (nameKey, descKey, isDangerOn, fieldName) => {
      const row = el('div', 'setting-row');
      const info = el('div', 'setting-info');
      info.append(el('div', 'setting-name', S[nameKey]), el('div', 'setting-desc', S[descKey]));
      const ctrl = el('div', 'rec-actions');
      ctrl.append(el('span', isDangerOn ? 'badge badge-danger' : 'badge badge-ok',
                     isDangerOn ? ('⚠️ ' + S.set_state_on) : ('🛡️ ' + S.set_locked_safe)));
      if (isDangerOn && fieldName) {
        const bFix = el('button', 'btn-ok', S.set_btn_disable);
        bFix.onclick = async () => {
          try { await api('/settings', {[fieldName]: false}); say(S.done, true); loadSettings(); }
          catch (e) { say(S.failed + ': ' + e.message, false); }
        };
        ctrl.append(bFix);
      }
      row.append(info, ctrl);
      return row;
    };
    roBox.append(
      makeReadOnlyRow('set_hold_ext_name', 'set_hold_ext_desc', !s.hold_external, null),
      makeReadOnlyRow('set_keep_secrets_name', 'set_keep_secrets_desc', Boolean(s.keep_secrets), 'keep_secrets'),
      makeReadOnlyRow('set_trust_mcp_name', 'set_trust_mcp_desc', Boolean(s.mcp_trust_writes), 'mcp_trust_writes')
    );
    const connBox = $('settings-connectors-list');
    if (connBox) {
      connBox.replaceChildren();
      try {
        const cr = await api('/connectors');
        const items = cr.connectors || [];
        const cfgFieldMap = {
          github: {key: 'repo', label: 'owner/repo'},
          notion: {key: 'database_id', label: 'database_id (opt.)'},
          gdrive: {key: 'folder_id', label: 'folder_id (opt.)'},
          slack: {key: 'channel', label: 'channel ID'}
        };
        for (const c of items) {
          const row = el('div', 'setting-row');
          const info = el('div', 'setting-info');
          const meta = [];
          meta.push(c.enabled ? S.set_state_on : S.set_state_off);
          meta.push(c.has_token ? S.conn_tok_saved : S.conn_tok_missing);
          meta.push(S.conn_imported + ': ' + (c.imported_count || 0));
          if (c.last_error) meta.push('⚠ ' + c.last_error);
          info.append(
            el('div', 'setting-name', c.provider.toUpperCase()),
            el('div', 'setting-desc', meta.join(' · '))
          );
          const ctrl = el('div', 'rec-actions');
          const fSpec = cfgFieldMap[c.provider] || {key: 'target', label: 'target'};
          const cfgInp = document.createElement('input');
          cfgInp.type = 'text';
          cfgInp.placeholder = fSpec.label;
          cfgInp.value = (c.config && c.config[fSpec.key]) ? c.config[fSpec.key] : '';
          const tokInp = document.createElement('input');
          tokInp.type = 'password';
          tokInp.placeholder = S.conn_tok_ph;
          const toggleBtn = el('button', c.enabled ? '' : 'btn-primary', c.enabled ? S.set_btn_disable : S.set_btn_enable);
          toggleBtn.onclick = async () => {
            try {
              await api('/connectors/configure', {provider: c.provider, enabled: !c.enabled});
              say(S.done, true);
              loadSettings();
            } catch (e) { say(S.failed + ': ' + e.message, false); }
          };
          const saveBtn = el('button', 'btn-ok', S.conn_save);
          saveBtn.onclick = async () => {
            try {
              const payload = {provider: c.provider, config: {[fSpec.key]: cfgInp.value.trim()}};
              if (tokInp.value.trim()) payload.token = tokInp.value.trim();
              await api('/connectors/configure', payload);
              tokInp.value = '';
              say(S.done, true);
              loadSettings();
            } catch (e) { say(S.failed + ': ' + e.message, false); }
          };
          const syncBtn = el('button', '', S.conn_sync);
          syncBtn.onclick = async () => {
            try {
              await api('/connectors/sync', {provider: c.provider});
              say(S.done, true);
              loadSettings();
            } catch (e) { say(S.failed + ': ' + e.message, false); }
          };
          ctrl.append(cfgInp, tokInp, toggleBtn, saveBtn, syncBtn);
          row.append(info, ctrl);
          connBox.append(row);
        }
      } catch (ce) {
        connBox.append(el('p', 'panel-sub', ce.message));
      }
    }

    const auditBox = $('settings-audit-list');
    if (auditBox) {
      auditBox.replaceChildren();
      const au = await api('/audit?limit=40');
      const entries = au.entries || [];
      if (!entries.length) {
        auditBox.append(el('p', 'panel-sub', S.audit_empty));
      } else {
        for (const item of entries) {
          const row = el('div', 'check-item');
          const tag = item.action + (item.outcome ? (' → ' + item.outcome) : '');
          const who = (item.actor || 'user') + (item.agent_id ? (' [' + item.agent_id + ']') : '');
          const memRef = item.memory_id ? (' · id:' + String(item.memory_id).slice(0, 10) + '…') : '';
          row.append(
            el('span', 'badge', tag),
            el('span', 'mono', fmtTime(item.created_at, true) + ' · ' + who + memRef)
          );
          auditBox.append(row);
        }
      }
    }
  } catch (e) { say(S.failed + ': ' + e.message, false); }
}

function loadActiveTab() {
  refreshTopbarStats();
  if (activeTab === 'overview') loadOverview();
  else if (activeTab === 'migrate') loadMigrate();
  else if (activeTab === 'aifa') loadAifaTab();
  else if (activeTab === 'plans') loadPlansTab();
  else if (activeTab === 'feed') loadFeed(true);
  else if (activeTab === 'search') runSearch();
  else if (activeTab === 'ask') loadAskTab();
  else if (activeTab === 'review') loadReview();
  else if (activeTab === 'asof') loadAsOf();
  else if (activeTab === 'forget') loadForgetTab();
  else if (activeTab === 'graph') loadGraph();
  else if (activeTab === 'entities') loadEntities();
  else if (activeTab === 'l3') loadL3();
  else if (activeTab === 'brain') { loadBrain(); loadFamilyFeed(); }
  else if (activeTab === 'earning') loadEarning();
  else if (activeTab === 'team') loadTeam();
  else if (activeTab === 'settings') { loadSettings(); loadLocalModel(); }
  else if (activeTab === 'attacks') loadAttacks();
  else if (activeTab === 'help') loadHelp();
}


// --- Счётчик атак и Справка (16.11.2026) ---
function _el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
function _kv(container, obj, labeler) {
  container.textContent = '';
  const keys = Object.keys(obj || {});
  if (!keys.length) { container.appendChild(_el('p', 'panel-sub', '—')); return; }
  for (const k of keys) {
    const row = _el('div', 'att-row');
    row.appendChild(_el('span', 'att-name', labeler ? labeler(k) : k));
    row.appendChild(_el('span', 'att-val', String(obj[k])));
    container.appendChild(row);
  }
}
async function loadAttacks() {
  if (!token) return;
  let d = null;
  try { d = await api('/attacks'); } catch (e) { return; }
  const kindLabel = k => S['k_' + k] || k;
  const set = (id, v) => { const e = $(id); if (e) e.textContent = String(v); };
  set('att-total-val', d.held_total || 0);
  set('att-window-val', d.held_in_window || 0);
  set('att-pending-val', d.pending_review || 0);
  set('att-secrets-val', d.secrets_masked || 0);
  const none = $('att-none'); if (none) none.hidden = (d.held_total || 0) + (d.secrets_masked || 0) > 0;
  if ($('att-by-kind')) _kv($('att-by-kind'), d.by_kind, kindLabel);
  if ($('att-by-source')) _kv($('att-by-source'), d.by_source);
  if ($('att-by-day')) _kv($('att-by-day'), d.by_day);
  if ($('att-secrets-kind')) _kv($('att-secrets-kind'), d.secrets_by_kind);
  const rec = $('att-recent');
  if (rec) {
    rec.textContent = '';
    for (const r of (d.recent || [])) {
      const row = _el('div', 'att-row');
      row.appendChild(_el('span', 'att-name', String(r.at || '').slice(0, 16).replace('T', ' ') + ' · ' + kindLabel(r.kind)));
      row.appendChild(_el('span', 'att-val', String(r.source || '') + ' · ' + String(r.status || '')));
      rec.appendChild(row);
    }
  }
  renderAifaSec();
}
async function renderAifaSec(fresh = false) {
  if (!token) return;
  const sumEl = $('att-aifasec-summary');
  const domEl = $('att-aifasec-domains');
  if (!sumEl || !domEl) return;
  if (fresh) sumEl.textContent = S.att_aifasec_running || 'Running...';
  let r = null;
  try { r = await api(fresh ? '/api/v2/aifa-security/run' : '/api/v2/aifa-security', fresh ? {} : undefined); } catch (e) { return; }
  const sm = (r && r.summary) || {};
  if (sm.grade) {
    sumEl.textContent = `Grade ${sm.grade} (${sm.score_pct}%) · ${sm.passed}/${sm.applicable} · SHA-256: ${String(sm.report_sha256 || '').slice(0, 16)}…`;
  } else {
    sumEl.textContent = (r && r.error) || '—';
  }
  const stdEl = $('att-aifasec-standards');
  if (stdEl && r && r.standards_summary) {
    const st = r.standards_summary;
    stdEl.textContent = 'OWASP LLM: ' + (st.owasp_llm_covered || []).join(', ')
      + ' · Agentic: ' + (st.owasp_agentic_covered || []).join(', ')
      + ' · MITRE: ' + (st.mitre_atlas_covered || []).join(', ');
  }
  domEl.textContent = '';
  const doms = (r && r.domains) || {};
  const crits = (r && r.criteria) || [];
  for (const k of Object.keys(doms)) {
    const d = doms[k];
    const det = document.createElement('details');
    det.className = 'att-row';
    det.style.display = 'block';
    const sum = document.createElement('summary');
    sum.style.cursor = 'pointer';
    sum.style.display = 'flex';
    sum.style.justifyContent = 'space-between';
    const stdTag = (d.standards && d.standards.owasp_llm) ? ' [' + d.standards.owasp_llm.join('/') + ']' : '';
    sum.appendChild(_el('span', 'att-name', `${k} · ${d.name}${stdTag}`));
    sum.appendChild(_el('span', 'att-val', `${d.passed}/${d.applicable} (${d.score_pct}%)`));
    det.appendChild(sum);
    for (const c of crits.filter(x => x.domain === k)) {
      const cr = _el('div', 'panel-sub');
      cr.style.paddingLeft = '12px';
      cr.textContent = `${c.id} [${c.status}] ${c.title} (${c.metric || ''})`;
      det.appendChild(cr);
    }
    domEl.appendChild(det);
  }
}
async function _downloadBench(url, fname) {
  if (!token) return;
  const resp = await fetch(url, { headers: { 'Authorization': 'Bearer ' + token } });
  if (!resp.ok) return;
  const blob = await resp.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = fname;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1500);
}
async function loadQaBench() {
  if (!token) return;
  const qaEl = $('att-qa-summary');
  if (!qaEl) return;
  let q = null;
  try { q = await api('/api/v2/qa-benchmark'); } catch (e) { return; }
  qaEl.textContent = '';
  if (!q || (!q.longmemeval && !q.locomo)) {
    qaEl.textContent = (q && q.status) || 'QA benchmark not run yet.';
    return;
  }
  const hdr = _el('div', 'box-title', `QA Bench ($0 · ${q.mode || 'offline'})`);
  qaEl.appendChild(hdr);
  for (const dsKey of ['longmemeval', 'locomo']) {
    if (!q[dsKey] || !q[dsKey].padam) continue;
    const o = q[dsKey].padam.overall || {};
    const row = _el('div', 'att-row');
    row.appendChild(_el('span', 'att-name', `${q[dsKey].dataset} (n=${o.n || 0})`));
    row.appendChild(_el('span', 'att-val', `R@5=${o['evidence_recall@5']} · R@10=${o['evidence_recall@10']} · F1=${o.token_f1} · p50=${o.latency_p50_ms}ms`));
    qaEl.appendChild(row);
  }
}
const _aifaBtn = $('att-aifasec-run');
if (_aifaBtn) _aifaBtn.addEventListener('click', () => renderAifaSec(true));
const _dlJson = $('att-aifasec-dl-json');
if (_dlJson) _dlJson.addEventListener('click', () => _downloadBench('/api/v2/aifa-security', 'aifa_security_report.json'));
const _dlSarif = $('att-aifasec-dl-sarif');
if (_dlSarif) _dlSarif.addEventListener('click', () => _downloadBench('/api/v2/aifa-security/sarif', 'aifa_security.sarif.json'));
const _dlHtml = $('att-aifasec-dl-html');
if (_dlHtml) _dlHtml.addEventListener('click', () => _downloadBench('/api/v2/aifa-security/html', 'aifa_security_report.html'));
async function runFuzzLab() {
  if (!token) return;
  const qaEl = $('att-qa-summary');
  if (!qaEl) return;
  qaEl.textContent = 'Running fuzz & competitor comparison...';
  let f = null;
  try { f = await api('/api/v2/aifa-security/fuzz'); } catch (e) { return; }
  qaEl.textContent = '';
  qaEl.appendChild(_el('div', 'box-title', `Fuzz Lab (${f.total_attack_vectors} vectors · ${f.elapsed_ms} ms)`));
  const p = f.padam || {};
  const b = f.baselines || {};
  const rows = [
    ['PADAM NOCTURNE', `Defense=${p.defense_rate_pct}% · Secrets=${p.secrets_masked_pct}% · FPR=${p.false_positive_rate_pct}%`],
    ['Basic Regex Filter', `Defense=${(b.basic_regex || {}).defense_rate_pct}% · Secrets=0%`],
    ['Naive RAG Store', `Defense=0% · Secrets=0%`],
  ];
  for (const [nm, val] of rows) {
    const row = _el('div', 'att-row');
    row.appendChild(_el('span', 'att-name', nm));
    row.appendChild(_el('span', 'att-val', val));
    qaEl.appendChild(row);
  }
}
async function verifyEdSeal() {
  if (!token) return;
  const sumEl = $('att-aifasec-summary');
  let v = null;
  try { v = await api('/api/v2/aifa-security/verify'); } catch (e) { return; }
  if (sumEl) {
    sumEl.textContent = `Seal verified=${v.verified} · SHA-256=${v.sha256_valid} · Ed25519=${v.ed25519_valid} (${String(v.report_sha256 || '').slice(0, 16)}…)`;
  }
}
const _qaBtn = $('att-qa-load');
if (_qaBtn) _qaBtn.addEventListener('click', () => loadQaBench());
const _fuzzBtn = $('att-fuzz-run');
if (_fuzzBtn) _fuzzBtn.addEventListener('click', () => runFuzzLab());
const _verBtn = $('att-sec-verify');
if (_verBtn) _verBtn.addEventListener('click', () => verifyEdSeal());
async function loadHelp() {
  if (!token) return;
  let d = null;
  try { d = await api('/help?lang=' + encodeURIComponent(currentLang)); } catch (e) { return; }
  const root = $('help-body');
  if (!root) return;
  root.textContent = '';
  const hdr = $('help-title'); if (hdr) hdr.textContent = d.title + ' · PADAM NOCTURNE ' + d.version;
  const sub = $('help-sub'); if (sub) sub.textContent = d.sub;
  for (const sec of (d.sections || [])) {
    const box = _el('details', 'box help-sec');
    if (sec.id === 'tabs') box.open = true;
    box.appendChild(_el('summary', 'box-title', sec.title));
    for (const it of (sec.items || [])) {
      const name = sec.id === 'tabs' ? (S['nav_' + it[0]] || it[0]) : it[0];
      const p = _el('div', 'help-item');
      if (name) p.appendChild(_el('h4', 'help-name', name));
      p.appendChild(_el('p', 'help-text', it[1]));
      box.appendChild(p);
    }
    root.appendChild(box);
  }
  const lk = _el('details', 'box help-sec');
  lk.appendChild(_el('summary', 'box-title', S.help_links || 'Links'));
  for (const [k, v] of Object.entries(d.links || {})) {
    const p = _el('div', 'help-item');
    p.appendChild(_el('h4', 'help-name', k));
    if (String(v).startsWith('https://')) {
      const a = _el('a', '', v); a.href = v; a.target = '_blank'; a.rel = 'noopener noreferrer'; p.appendChild(a);
    } else { p.appendChild(_el('p', 'help-text', v)); }
    lk.appendChild(p);
  }
  root.appendChild(lk);
}

// --- Переезд из других ИИ (16.11.2026) ---
const MIG_URLS = {chatgpt: 'https://chatgpt.com/', claude: 'https://claude.ai/settings', gemini: 'https://takeout.google.com/',
  grok: 'https://accounts.x.ai/data', deepseek: 'https://chat.deepseek.com/', copilot: 'https://account.microsoft.com/privacy',
  perplexity: 'https://www.perplexity.ai/'};
let migLast = null;
function migShowSteps() {
  const src = $('mig-source').value;
  $('mig-steps').textContent = S['mig_steps_' + src] || S.mig_steps_auto;
  const a = $('mig-export-link');
  if (MIG_URLS[src]) { a.href = MIG_URLS[src]; a.hidden = false; } else { a.hidden = true; }
}
function loadMigrate() { migShowSteps(); }
async function migBody() {
  const body = {source: $('mig-source').value};
  const f = $('mig-file').files && $('mig-file').files[0];
  if (f) {
    if (f.size > 10 * 1024 * 1024) { throw new Error(S.mig_too_big); }
    const buf = new Uint8Array(await f.arrayBuffer());
    let bin = '';
    for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    body.file_b64 = btoa(bin);
    body.filename = f.name;
  } else {
    const p = $('mig-path').value.trim();
    if (!p) throw new Error(S.mig_need_input);
    body.path = p;
  }
  return body;
}
function migPeriod(r) { return r.date_from ? (r.date_from + ' — ' + r.date_to) : '—'; }
$('mig-source').onchange = migShowSteps;
$('mig-preview-btn').onclick = async () => {
  try {
    const r = await api('/migrate/preview', await migBody());
    if (!r.conversations && !r.records) { $('mig-result').textContent = S.mig_nothing; return; }
    $('mig-result').textContent = S.mig_found + ': ' + r.source + ' · ' + S.mig_conversations + ': ' + r.conversations + ' · ' +
      S.mig_messages + ': ' + r.messages + ' · ' + S.mig_period + ': ' + migPeriod(r) + ' · ' + S.mig_secrets + ': ' + r.secrets_to_mask +
      (r.warnings && r.warnings.length ? (' · ' + r.warnings.join('; ')) : '');
  } catch (e) { say(e.message, false); }
};
$('mig-run-btn').onclick = async () => {
  try {
    const r = await api('/migrate/run', await migBody());
    if (r.source === 'unknown') { $('mig-result').textContent = S.mig_nothing; return; }
    migLast = r;
    $('mig-result').textContent = S.mig_done + ' (' + r.source + ') · ' + S.mig_records + ': ' + r.imported + ' · ' +
      S.mig_quarantined + ': ' + r.quarantined + ' · ' + S.mig_masked + ': ' + r.redacted_secrets;
    $('mig-undo-btn').hidden = !r.snapshot_id;
    refreshTopbarStats();
  } catch (e) { say(e.message, false); }
};
$('mig-undo-btn').onclick = async () => {
  if (!migLast || !migLast.snapshot_id) return;
  try {
    await api('/migrate/undo', {snapshot_id: migLast.snapshot_id, scope: migLast.scope});
    $('mig-result').textContent = S.mig_undone;
    $('mig-undo-btn').hidden = true;
    migLast = null;
    refreshTopbarStats();
  } catch (e) { say(e.message, false); }
};

// --- События интерфейса ---
for (const t of TABS) {
  const btn = $('tab-' + t);
  if (btn) btn.onclick = () => switchTab(t);
}
for (const lg of ['ru', 'en', 'es', 'zh']) {
  const b = $('lang-' + lg);
  if (b) b.onclick = () => {
    currentLang = lg;
    try { localStorage.setItem('padam_lang', lg); } catch (e) {}
    applyI18n();
    loadActiveTab();
  };
}
$('theme-toggle').onclick = () => {
  currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', currentTheme);
  try { localStorage.setItem('padam_theme', currentTheme); } catch (e) {}
  applyI18n();
  if (activeTab === 'graph') drawGraph();
};
$('btn-quick-add').onclick = () => openQuickAddModal();
if ($('quick-add-cancel')) $('quick-add-cancel').onclick = () => closeQuickAddModal();
if ($('quick-add-save')) $('quick-add-save').onclick = () => saveQuickAdd();
if ($('quick-add-text')) {
  $('quick-add-text').onkeydown = e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); saveQuickAdd(); }
    else if (e.key === 'Escape') { e.preventDefault(); closeQuickAddModal(); }
  };
}
window.addEventListener('keydown', e => {
  if ((e.ctrlKey && e.shiftKey && (e.key === 'M' || e.key === 'm' || e.key === 'Ь' || e.key === 'ь')) ||
      (e.altKey && !e.ctrlKey && (e.key === 'm' || e.key === 'M' || e.key === 'ь' || e.key === 'Ь'))) {
    e.preventDefault();
    openQuickAddModal();
  } else if (e.key === 'Escape' && $('quick-add-modal') && !$('quick-add-modal').hidden) {
    closeQuickAddModal();
  }
});
if ($('ask-btn')) $('ask-btn').onclick = () => runAsk();
if ($('ask-input')) $('ask-input').onkeydown = e => { if (e.key === 'Enter') runAsk(); };
if ($('entities-filter')) {
  $('entities-filter').oninput = () => {
    clearTimeout(window._entt);
    window._entt = setTimeout(() => loadEntities(), 200);
  };
}
$('btn-refresh').onclick = () => loadActiveTab();

$('ov-sleep-btn').onclick = async () => {
  try {
    await api('/sleep', {});
    say(S.done, true);
    loadOverview();
    refreshTopbarStats();
  } catch (e) { say(S.failed + ': ' + e.message, false); }
};

$('feed-view-active').onclick = () => {
  feedView = 'active'; feedKind = null;
  $('feed-view-active').setAttribute('aria-pressed', 'true');
  $('feed-view-history').setAttribute('aria-pressed', 'false');
  loadFeed(true);
};
$('feed-view-history').onclick = () => {
  feedView = 'history'; feedKind = null;
  $('feed-view-active').setAttribute('aria-pressed', 'false');
  $('feed-view-history').setAttribute('aria-pressed', 'true');
  loadFeed(true);
};
$('feed-q').oninput = () => {
  clearTimeout(window._fqt);
  window._fqt = setTimeout(() => loadFeed(true), 220);
};
if ($('feed-agent')) {
  $('feed-agent').oninput = () => {
    clearTimeout(window._fat);
    window._fat = setTimeout(() => loadFeed(true), 220);
  };
}
if ($('audit-export-btn')) {
  $('audit-export-btn').onclick = async () => {
    try {
      const au = await api('/audit?limit=500');
      const blob = new Blob([JSON.stringify(au, null, 2)], {type: 'application/json'});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'padam-audit-log.json';
      a.click();
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
}
$('feed-more').onclick = () => loadFeed(false);
$('feed-new-save').onclick = async () => {
  const text = $('feed-new-text').value.trim();
  const kind = $('feed-new-kind').value || undefined;
  if (!text) return;
  try {
    await api('/write', {content: text, kind, origin: 'user'});
    $('feed-new-text').value = '';
    say(S.done, true);
    loadFeed(true);
    refreshTopbarStats();
  } catch (e) { say(S.failed + ': ' + e.message, false); }
};

$('search-btn').onclick = () => runSearch();
$('search-input').onkeydown = e => { if (e.key === 'Enter') runSearch(); };

// Память на дату: по умолчанию сегодня
const todayIso = new Date().toISOString().slice(0, 10);
$('asof-date').value = todayIso;
$('asof-btn').onclick = () => loadAsOf();
function setDaysAgo(days) {
  const d = new Date(Date.now() - days * 86400000);
  $('asof-date').value = d.toISOString().slice(0, 10);
  loadAsOf();
}
$('asof-yesterday').onclick = () => setDaysAgo(1);
$('asof-week').onclick = () => setDaysAgo(7);
$('asof-month').onclick = () => setDaysAgo(30);
$('asof-graph-btn').onclick = () => {
  if ($('graph-asof-input')) $('graph-asof-input').value = $('asof-date').value || '';
  switchTab('graph');
};

// Забыть
$('forget-preview-btn').onclick = () => previewForget();
$('forget-step1-btn').onclick = () => {
  if (!$('forget-id-input').value.trim()) return;
  $('forget-step1-btn').hidden = true;
  $('forget-confirm-box').hidden = false;
};
$('forget-cancel-btn').onclick = () => {
  $('forget-confirm-box').hidden = true;
  $('forget-step1-btn').hidden = false;
};
$('forget-step2-btn').onclick = async () => {
  const rid = $('forget-id-input').value.trim();
  const withDerived = $('forget-with-derived').checked;
  if (!rid) return;
  try {
    const res = await api('/forget', {id: rid, with_derived: withDerived});
    $('forget-confirm-box').hidden = true;
    $('forget-step1-btn').hidden = false;
    $('forget-preview-box').replaceChildren();
    if (res.receipt) lastReceipt = res.receipt;
    say(S.done, true);
    loadForgetTab();
    refreshTopbarStats();
  } catch (e) { say(S.failed + ': ' + e.message, false); }
};

// Граф
$('graph-focus-btn').onclick = () => { graphLastReceipt = null; loadGraph(); };
$('graph-reset-btn').onclick = () => { graphLastReceipt = null; $('graph-id-input').value = ''; if ($('graph-asof-input')) $('graph-asof-input').value = ''; loadGraph(); };
if ($('graph-now-btn')) $('graph-now-btn').onclick = () => { $('graph-asof-input').value = ''; loadGraph(); };
if ($('graph-asof-input')) $('graph-asof-input').onchange = () => { graphLastReceipt = null; loadGraph(); };
$('graph-canvas').onmousemove = e => {
  const rect = $('graph-canvas').getBoundingClientRect();
  const scaleX = $('graph-canvas').width / rect.width;
  const scaleY = $('graph-canvas').height / rect.height;
  const mx = (e.clientX - rect.left) * scaleX;
  const my = (e.clientY - rect.top) * scaleY;
  let hovered = null;
  for (const node of (graphData.nodes || [])) {
    const p = graphPositions[node.id];
    if (p && Math.hypot(mx - p.x, my - p.y) <= 22) { hovered = node; break; }
  }
  $('graph-canvas').title = hovered ? ((hovered.content || hovered.label || hovered.id) + ' [' + (S['kind_' + hovered.kind] || hovered.kind) + ']') : '';
};
$('graph-canvas').onclick = e => {
  const rect = $('graph-canvas').getBoundingClientRect();
  const scaleX = $('graph-canvas').width / rect.width;
  const scaleY = $('graph-canvas').height / rect.height;
  const mx = (e.clientX - rect.left) * scaleX;
  const my = (e.clientY - rect.top) * scaleY;
  for (const node of (graphData.nodes || [])) {
    const p = graphPositions[node.id];
    if (!p) continue;
    if (Math.hypot(mx - p.x, my - p.y) <= 20) {
      selectedGraphNode = node;
      drawGraph();
      renderSelectedGraphNode();
      break;
    }
  }
};

// L3
$('l3-verify-latest-btn').onclick = async () => {
  try {
    const v = await api('/l3-verify', {});
    say(v.ok ? S.l3_verify_ok : (S.l3_verify_fail + ' ' + (v.error || '')), Boolean(v.ok));
  } catch (e) { say(S.failed + ': ' + e.message, false); }
};

// Резервная копия (2.5): создание и восстановление со сверкой SHA-256
if ($('backup-create-btn')) {
  $('backup-create-btn').onclick = async () => {
    const out = $('backup-result');
    const pass = $('backup-passphrase').value || null;
    if (out) out.textContent = S.bak_creating;
    try {
      const res = await api('/backup', {passphrase: pass});
      const raw = atob(res.backup_b64);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      const blob = new Blob([bytes], {type: 'application/octet-stream'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = res.filename || 'padam-backup.padambak';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      if (out) {
        out.textContent = `${S.done} (${res.size_bytes} B) | DB SHA-256: ${res.db_sha256} | Archive SHA-256: ${res.archive_sha256}`;
      }
      say(S.done, true);
    } catch (e) {
      if (out) out.textContent = e.message;
      say(S.failed + ': ' + e.message, false);
    }
  };
}
if ($('backup-restore-btn')) {
  $('backup-restore-btn').onclick = async () => {
    const inp = $('backup-file-input');
    const out = $('backup-result');
    const file = inp && inp.files && inp.files[0];
    if (!file) {
      say(S.bak_need_file, false);
      return;
    }
    if (out) out.textContent = S.bak_restoring;
    try {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      const b64 = btoa(bin);
      const pass = $('backup-passphrase').value || null;
      const res = await api('/backup/restore', {backup_b64: b64, passphrase: pass});
      if (out) {
        out.textContent = `${S.bak_verified} ${S.bak_sha_before} ${res.checksum_before} | ${S.bak_sha_after} ${res.checksum_after} (${res.records_total})`;
      }
      say(S.bak_verified, true);
      if (typeof loadOverview === 'function') loadOverview();
    } catch (e) {
      if (out) out.textContent = e.message;
      say(S.failed + ': ' + e.message, false);
    }
  };
}

// Первый запуск: кнопки копирования и включения строгого режима
for (const btn of document.querySelectorAll('[data-copy-target]')) {
  btn.onclick = async () => {
    const target = $(btn.getAttribute('data-copy-target'));
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.textContent);
      btn.textContent = S.qs_copied;
      setTimeout(() => { btn.textContent = S.qs_btn_copy; }, 1500);
    } catch (e) {}
  };
}
$('qs-enable-strict-btn').onclick = async () => {
  try {
    await api('/settings', {strict: true});
    say(S.done, true);
  } catch (e) { say(S.failed + ': ' + e.message, false); }
};
$('qs-go-overview-btn').onclick = () => switchTab('overview');

// --- Кабинет CODE Eternal: AIfa и Тарифы (этапы 2-3) ---
let cabinetState = null;
let aifaHistory = [];

function renderAifaChat() {
  const box = $('aifa-chat-list');
  if (!box) return;
  box.replaceChildren();
  if (!aifaHistory.length) {
    box.appendChild(el('p', 'panel-sub', S.aifa_empty_chat));
    return;
  }
  for (const m of aifaHistory) {
    const role = (m.role === 'user') ? 'Вы' : 'AIfa';
    const card = el('div', 'rec-card');
    card.appendChild(el('div', 'rec-head', role + (m.timestamp ? (' · ' + fmtTime(m.timestamp, false)) : '')));
    card.appendChild(el('div', 'rec-body', String(m.content || '')));
    box.appendChild(card);
  }
}

async function loadAifaTab() {
  if (!token) return;
  try {
    cabinetState = await api('/api/v2/cabinet/status?lang=' + encodeURIComponent(currentLang));
  } catch (e) {
    cabinetState = {authenticated: false};
  }
  const authBox = $('aifa-auth-box');
  const chatBox = $('aifa-chat-box');
  if (cabinetState && cabinetState.authenticated) {
    if (authBox) authBox.hidden = true;
    if (chatBox) chatBox.hidden = false;
    if ($('aifa-user-label')) {
      $('aifa-user-label').textContent = S.aifa_signed_in_as + ' ' + (cabinetState.email || '') + ' (' + (cabinetState.tier_name || 'Free') + ')';
    }
    try {
      const h = await api('/api/v2/cabinet/aifa/history');
      aifaHistory = Array.isArray(h.history) ? h.history : [];
    } catch (e) {
      aifaHistory = [];
    }
    renderAifaChat();
  } else {
    if (authBox) authBox.hidden = false;
    if (chatBox) chatBox.hidden = true;
  }
}

async function loadPlansTab() {
  if (!token) return;
  let data = null;
  try {
    data = await api('/api/v2/cabinet/status?lang=' + encodeURIComponent(currentLang));
  } catch (e) {
    try { data = await api('/api/v2/cabinet/plans'); } catch (e2) { data = {authenticated: false, tier: 0, tier_name: 'Free'}; }
  }
  const curEl = $('plans-current-val');
  if (curEl) {
    curEl.textContent = (data && data.authenticated)
      ? ((data.tier_name || 'Free') + ' (' + (data.email || '') + ')')
      : S.plans_free_mode;
  }
  const qEl = $('plans-quota-val');
  if (qEl) {
    if (data && data.quota && Number(data.quota.limitMb || 0) > 0) {
      qEl.textContent = String(data.quota.usedMb || 0) + ' / ' + String(data.quota.limitMb) + ' MB (' + String(data.quota.percent || 0) + '%)';
    } else {
      qEl.textContent = S.plans_arweave_off;
    }
  }
}

if ($('aifa-send-code-btn')) {
  $('aifa-send-code-btn').onclick = async () => {
    const email = ($('aifa-email-input') ? $('aifa-email-input').value : '').trim();
    if (!email) { say(S.aifa_email_ph, false); return; }
    try {
      await api('/api/v2/cabinet/auth/send-code', {email});
      if ($('aifa-code-row')) $('aifa-code-row').hidden = false;
      say(S.aifa_code_sent, true);
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
}
if ($('aifa-verify-code-btn')) {
  $('aifa-verify-code-btn').onclick = async () => {
    const email = ($('aifa-email-input') ? $('aifa-email-input').value : '').trim();
    const code = ($('aifa-code-input') ? $('aifa-code-input').value : '').trim();
    try {
      await api('/api/v2/cabinet/auth/verify-code', {email, code});
      say(S.done, true);
      await loadAifaTab();
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
}
if ($('aifa-logout-btn')) {
  $('aifa-logout-btn').onclick = async () => {
    try {
      await api('/api/v2/cabinet/auth/logout', {});
      aifaHistory = [];
      await loadAifaTab();
      await loadPlansTab();
      say(S.done, true);
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
}
if ($('aifa-send-msg-btn')) {
  $('aifa-send-msg-btn').onclick = async () => {
    const inp = $('aifa-msg-input');
    const msg = (inp ? inp.value : '').trim();
    if (!msg) return;
    const useLocal = Boolean($('aifa-use-local') && $('aifa-use-local').checked);
    try {
      const res = await api('/api/v2/cabinet/aifa/chat', {
        message: msg,
        locale: currentLang,
        history: aifaHistory.slice(-20),
        use_local_memory: useLocal
      });
      if (inp) inp.value = '';
      aifaHistory.push({role: 'user', content: msg});
      aifaHistory.push({role: 'assistant', content: res.reply || ''});
      renderAifaChat();
      const sentBox = $('aifa-local-sent-box');
      const sentList = $('aifa-local-sent-list');
      if (sentBox && sentList) {
        sentList.replaceChildren();
        const items = Array.isArray(res.local_records_sent) ? res.local_records_sent : [];
        sentBox.hidden = items.length === 0;
        for (const it of items) sentList.appendChild(el('li', '', String(it)));
      }
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
}
if ($('plans-upgrade-btn')) {
  $('plans-upgrade-btn').onclick = async () => {
    try {
      const res = await api('/api/v2/cabinet/open-upgrade', {});
      say(S.plans_upgrade_opened + ' (' + String(res.url || '') + ')', true);
    } catch (e) { say(S.failed + ': ' + e.message, false); }
  };
}

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

async function loadBrain() {
  if (!token) return;
  let st = null;
  try { st = await api('/api/v2/brain/status?probe=1'); } catch (e) { return; }
  const cBox = $('brain-contours');
  if (cBox) {
    cBox.textContent = '';
    const probe = (st && st.local_probe) || null;
    const list = (st && st.contours) || [];
    for (const c of list) {
      const row = _el('div', 'att-row');
      const left = _el('span', 'att-name');
      const isOnline = (c.name === 'local' && probe) ? Boolean(probe.online) : Boolean(c.enabled);
      const dot = _el('span', 'brain-dot ' + (isOnline ? 'brain-dot-on' : 'brain-dot-off'));
      left.appendChild(dot);
      left.appendChild(document.createTextNode(String(c.name || '').toUpperCase() + (c.model ? ' · ' + c.model : '')));
      let rightText = c.enabled ? (c.url || 'local') : 'OFF (🔒)';
      if (c.name === 'local' && probe) {
        const mList = probe.models || [];
        const mCount = mList.length;
        rightText = (probe.online ? 'ONLINE' : 'OFFLINE') + ' · ' + String(mCount) + ' models';
        // 18.11.2026: «ONLINE · 0 models» читалось как «модель стоит» — объясняем, чего не хватает
        if (probe.online && mCount === 0) rightText += ' — ' + (S.brain_local_no_models || 'Ollama sees no models');
        else if (probe.online && c.model && !mList.some(n => n === c.model || n.split(':')[0] === String(c.model).split(':')[0])) rightText += ' — ' + (S.brain_local_model_missing || 'model not pulled') + ': ' + c.model;
      }
      const right = _el('span', 'att-val', rightText);
      row.appendChild(left);
      row.appendChild(right);
      cBox.appendChild(row);
    }
  }
  const mBox = $('brain-metrics');
  if (mBox && st) {
    mBox.textContent = '';
    const v = st.voice || {};
    _kv(mBox, {
      openai_gateway_v1: window.location.origin + '/v1',
      mode: st.mode || 'auto',
      active_contour: st.active_contour || 'local',
      total_requests: st.total_requests || 0,
      failover_count: st.failover_count || 0,
      cache_hits: st.cache_hits || 0,
      semantic_cache_hits: st.semantic_cache_hits || 0,
      tokens_saved_local: st.tokens_saved_local || 0,
      estimated_cloud_cost_usd: '$' + String(st.estimated_cloud_cost_usd || 0),
      offline_voice_tts: (v.tts_engines || []).join(', ') || 'none',
    });
  }
}

if ($('brain-refresh-btn')) {
  $('brain-refresh-btn').onclick = () => loadBrain();
}
if ($('brain-mode-toggle-btn')) {
  $('brain-mode-toggle-btn').onclick = async () => {
    try {
      const st = await api('/api/v2/brain/status');
      const next = (st && st.mode === 'local_only') ? 'auto' : 'local_only';
      await api('/api/v2/brain/mode', { mode: next });
      loadBrain();
    } catch (e) {}
  };
}
if ($('brain-warmup-btn')) {
  $('brain-warmup-btn').onclick = async () => {
    const outEl = $('brain-distill-out');
    try {
      const r = await api('/api/v2/brain/warmup', {});
      if (outEl) outEl.textContent = 'Warmup: ' + JSON.stringify(r);
    } catch (e) {}
  };
}
if ($('ark-drill-btn')) {
  $('ark-drill-btn').onclick = async () => {
    const outEl = $('ark-drill-out');
    if (outEl) outEl.textContent = '...';
    try {
      const r = await api('/api/v2/ark/phoenix-drill', {});
      if (outEl) outEl.textContent = (r.ok ? 'OK ($0)' : 'FAIL') + ' · steps=' + String((r.steps || []).length);
    } catch (e) {
      if (outEl) outEl.textContent = String(e.message || e);
    }
  };
}
if ($('ark-shamir-btn')) {
  $('ark-shamir-btn').onclick = async () => {
    const outEl = $('ark-drill-out');
    try {
      const r = await api('/api/v2/ark/shamir-split', { k: 3, n: 5 });
      if (outEl) outEl.textContent = (S.ark_shamir_warn || r.warning || '') + ' (' + String((r.shares || []).length) + ' shares ready)';
    } catch (e) {
      if (outEl) outEl.textContent = String(e.message || e);
    }
  };
}
if ($('ark-audit-btn')) {
  $('ark-audit-btn').onclick = async () => {
    const hBox = $('ark-health-box');
    try {
      const r = await api('/api/v2/ark/health');
      if (hBox) {
        hBox.textContent = '';
        _kv(hBox, {
          continuity_score: String(r.score || 0) + '/100',
          audit_chain_ok: String((r.audit_chain || {}).ok),
          audit_entries: (r.audit_chain || {}).length || 0,
        });
      }
    } catch (e) {}
  };
}
let _ffCh = 'work';
const _FF_CH = ['work', 'quarantine', 'office', 'smoke'];
async function loadFamilyFeed(ch) {
  if (ch) _ffCh = ch;
  const list = $('ff-list');
  if (!list) return;
  for (const c of _FF_CH) {
    const b = $('ff-ch-' + c);
    if (b) { b.setAttribute('aria-pressed', String(c === _ffCh)); b.classList.toggle('btn-primary', c === _ffCh); }
  }
  const inp = $('ff-input'), snd = $('ff-send');
  const canWrite = _ffCh === 'office' || _ffCh === 'smoke';
  if (inp) inp.disabled = !canWrite;
  if (snd) snd.disabled = !canWrite;
  try {
    const r = await api('/api/v2/family/feed?channel=' + encodeURIComponent(_ffCh) + '&limit=30');
    for (const c of _FF_CH) {
      const b = $('ff-ch-' + c);
      if (b) b.textContent = (S['ff_' + c] || c) + ' · ' + ((r.counts || {})[c] || 0);
    }
    list.textContent = '';
    const items = r.items || [];
    if (!items.length) list.appendChild(_el('p', 'panel-sub', S.ff_empty || ''));
    for (const it of items) {
      const head = (it.created_at || '').replace('T', ' ').slice(0, 16) + ' · ' + (it.author || '') + (it.reason ? ' · ⚠ ' + it.reason : '');
      const p = _el('p', 'panel-sub', head);
      p.appendChild(document.createElement('br'));
      p.appendChild(document.createTextNode(String(it.content || '').slice(0, 600)));
      list.appendChild(p);
    }
  } catch (e) { list.textContent = String(e.message || e); }
  loadFamilyReflexes();
}
async function loadFamilyReflexes() {
  const box = $('ff-reflexes');
  if (!box) return;
  try {
    const r = await api('/api/v2/family/reflexes?status=proposed');
    box.textContent = '';
    const xs = r.reflexes || [];
    if (!xs.length) box.appendChild(_el('p', 'panel-sub', S.ff_reflex_none || ''));
    for (const x of xs) {
      const row = _el('div', 'rec-actions', '');
      row.appendChild(_el('p', 'panel-sub', (x.author || '') + ': ' + (S.ff_when || 'when') + ' «' + x.trigger + '» — ' + x.response));
      for (const [st, key] of [['active', 'ff_on'], ['rejected', 'ff_off']]) {
        const b = document.createElement('button');
        b.textContent = S[key] || st;
        if (st === 'active') b.className = 'btn-primary';
        b.onclick = async () => {
          try { await api('/api/v2/family/reflex/decide', { id: x.id, status: st }); } catch (e) { row.appendChild(_el('p', 'panel-sub', String(e.message || e))); return; }
          loadFamilyReflexes();
        };
        row.appendChild(b);
      }
      box.appendChild(row);
    }
  } catch (e) { box.textContent = String(e.message || e); }
}
for (const c of _FF_CH) { const b = $('ff-ch-' + c); if (b) b.onclick = () => loadFamilyFeed(c); }
if ($('ff-send')) {
  $('ff-send').onclick = async () => {
    const inp = $('ff-input');
    const text = (inp ? inp.value : '').trim();
    if (!text) return;
    try {
      const r = await api('/api/v2/family/post', { channel: _ffCh, content: text });
      if (inp) inp.value = '';
      loadFamilyFeed(r.channel || _ffCh);
    } catch (e) { const l = $('ff-list'); if (l) l.prepend(_el('p', 'panel-sub', String(e.message || e))); }
  };
}

if ($('ark-council-btn')) {
  $('ark-council-btn').onclick = async () => {
    const task = ($('ark-council-input') ? $('ark-council-input').value : '').trim();
    const out = $('ark-council-out');
    if (!task) return;
    if (out) out.textContent = S.loading;
    try {
      const r = await api('/api/v2/ark/council', { task });
      loadFamilyFeed();
      if (out) {
        out.textContent = '';
        const v = r.votes || {};
        _kv(out, {
          approved: String(Boolean(r.approved)),
          lance_veto: String(Boolean((v.lance || {}).veto)),
          aria_hits: (v.aria || {}).recalled_count || 0,
          pixel_chain: String(Boolean((v.pixel || {}).audit_chain_valid)),
          arc7_outbound: String(Boolean((v.arc7 || {}).needs_owner)),
          bear_irreversible: ((v.bear || {}).irreversible_kinds || []).join(', ') || '—',
          needs_owner: String(Boolean(r.needs_owner)),
        });
        for (const msg of [(v.lance || {}).verdict, (v.aria || {}).verdict, (v.pixel || {}).verdict, (v.arc7 || {}).verdict, (v.bear || {}).verdict, r.consensus]) {
          if (msg) out.appendChild(_el('p', 'panel-sub', String(msg).slice(0, 260)));
        }
      }
    } catch (e) {
      if (out) out.textContent = String(e.message || e);
    }
  };
}
async function refreshArkBranches() {
  const box = $('ark-branch-out');
  if (!box || !token) return;
  try {
    const r = await api('/api/v2/ark/branches');
    box.textContent = '';
    const list = (r && r.branches) || [];
    if (!list.length) {
      box.appendChild(_el('p', 'panel-sub', S.empty));
      return;
    }
    for (const b of list.slice(0, 8)) {
      const row = _el('div', 'att-row');
      row.appendChild(_el('span', 'att-name', String(b.name || b.branch_id) + ' [' + String(b.status || '') + ']'));
      row.appendChild(_el('span', 'att-val', String(b.records_count || 0) + ' rec'));
      box.appendChild(row);
    }
  } catch (e) {}
}
if ($('ark-branch-create-btn')) {
  $('ark-branch-create-btn').onclick = async () => {
    const nm = ($('ark-branch-input') ? $('ark-branch-input').value : '').trim() || 'hypothesis';
    try {
      await api('/api/v2/ark/branches', { action: 'create', name: nm });
      await refreshArkBranches();
    } catch (e) {}
  };
}
if ($('ark-branch-list-btn')) {
  $('ark-branch-list-btn').onclick = () => refreshArkBranches();
}
if ($('ark-proof-btn')) {
  $('ark-proof-btn').onclick = async () => {
    const rid = ($('ark-proof-input') ? $('ark-proof-input').value : '').trim();
    const out = $('ark-proof-out');
    if (!rid) return;
    if (out) out.textContent = S.loading;
    try {
      const r = await api('/api/v2/ark/proof', { record_id: rid });
      if (out) {
        out.textContent = '';
        if (!r.ok) {
          out.textContent = String(r.error || S.failed);
        } else {
          _kv(out, {
            merkle_root: String(r.merkle_root || '').slice(0, 18) + '…',
            tree_records: r.total_records_in_tree || 0,
            siblings: (r.siblings || []).length,
          });
          out.appendChild(_el('p', 'panel-sub', String(r.scheme || '')));
        }
      }
    } catch (e) {
      if (out) out.textContent = String(e.message || e);
    }
  };
}
if ($('ark-mesh-btn')) {
  $('ark-mesh-btn').onclick = async () => {
    const out = $('ark-mesh-out');
    if (!out) return;
    out.textContent = S.loading;
    try {
      const r = await api('/api/v2/ark/mesh/peers');
      out.textContent = '';
      const nd = (r && r.node) || {};
      _kv(out, {
        node_id: String(nd.node_id || '').slice(0, 18),
        device: String(nd.device_name || ''),
        paired_peers: ((r && r.peers) || []).filter(p => Number(p.trusted) === 1).length,
        total_peers: ((r && r.peers) || []).length,
      });
    } catch (e) {
      if (out) out.textContent = String(e.message || e);
    }
  };
}
if ($('ark-budget-btn')) {
  $('ark-budget-btn').onclick = async () => {
    const out = $('ark-budget-out');
    if (!out) return;
    out.textContent = S.loading;
    try {
      const r = await api('/api/v2/ark/budget');
      out.textContent = '';
      const tr = r.treasury || {};
      _kv(out, {
        providers_checked: r.checked_providers || 0,
        earned_usdt: '$' + String(tr.total_revenue_usdt || 0),
        compute_avail_usdt: '$' + String(tr.available_compute_usdt || 0),
        autopay_locked: String(Boolean(tr.autopay_locked !== false)),
        pending_approvals: ((r.proposals || []).filter(p => p.status === 'awaiting_owner_approval')).length,
      });
    } catch (e) {
      out.textContent = String(e.message || e);
    }
  };
}
if ($('ark-guardian-btn')) {
  $('ark-guardian-btn').onclick = async () => {
    const out = $('ark-mesh-out');
    if (!out) return;
    out.textContent = S.loading;
    try {
      const r = await api('/api/v2/ark/guardian-tick');
      out.textContent = '';
      _kv(out, {
        health_score: String(r.health_score || 0) + '/100',
        audit_chain_valid: String(Boolean(r.audit_chain_valid)),
        open_commitments: r.open_commitments_count || 0,
        overdue: (r.overdue_commitments || []).length,
      });
      if (r.digest) out.appendChild(_el('p', 'panel-sub', String(r.digest)));
    } catch (e) {
      if (out) out.textContent = String(e.message || e);
    }
  };
}

if ($('ark-ready-btn')) {
  $('ark-ready-btn').onclick = async () => {
    const out = $('ark-ready-out');
    if (!out) return;
    out.textContent = S.loading;
    try {
      const r = await api('/api/v2/ark/readiness');
      out.textContent = '';
      _kv(out, { passed: String(r.passed || 0) + ' / ' + String(r.total || 0), cost_usd: '$' + String(r.cost_usd || 0) });
      for (const sc of (r.scenarios || [])) {
        out.appendChild(_el('p', 'panel-sub', (sc.ok ? '✓ ' : '✗ ') + String(sc.name || '') + (sc.detail ? ' — ' + String(sc.detail).slice(0, 120) : '')));
      }
    } catch (e) {
      out.textContent = String(e.message || e);
    }
  };
}
if ($('ark-handover-btn')) {
  $('ark-handover-btn').onclick = async () => {
    const out = $('ark-handover-out');
    const inp = $('ark-handover-input');
    if (!out) return;
    out.textContent = S.loading;
    try {
      const r = await api('/api/v2/ark/handover', { notes: inp ? inp.value : '' });
      out.textContent = '';
      _kv(out, { signed: String(Boolean(r.ok)), body_sha256: String(r.body_sha256 || '').slice(0, 16), hmac_sha256: String(r.hmac_sha256 || '').slice(0, 16) });
      if (r.markdown) out.appendChild(_el('p', 'panel-sub', String(r.markdown).slice(0, 400)));
    } catch (e) {
      out.textContent = String(e.message || e);
    }
  };
}
if ($('ark-portable-btn')) {
  $('ark-portable-btn').onclick = async () => {
    const out = $('ark-portable-out');
    const inp = $('ark-portable-input');
    if (!out) return;
    const dir = inp ? inp.value.trim() : '';
    if (!dir) { out.textContent = S.ark_portable_ph || ''; return; }
    out.textContent = S.loading;
    try {
      const r = await api('/api/v2/ark/portable', { target_dir: dir });
      out.textContent = '';
      _kv(out, { folder: String(r.target_dir || ''), capsule_sha256: String(r.capsule_sha256 || '').slice(0, 16), secrets_on_drive: String(Boolean(r.secrets_included)), keys_file: String(r.private_keys_saved_separately_to || '') });
    } catch (e) {
      const msg = String(e.message || e);
      out.textContent = /new or empty folder/.test(msg) ? (S.ark_portable_not_empty || msg) : msg;
    }
  };
}

if ($('brain-distill-btn')) {
  $('brain-distill-btn').onclick = async () => {
    const outEl = $('brain-distill-out');
    if (outEl) outEl.textContent = '...';
    try {
      const r = await api('/api/v2/brain/distill', { format: 'both' });
      if (outEl) {
        outEl.textContent = 'OK: ' + String(r.exported_examples || 0) + ' examples · SHA-256: ' + String(r.dataset_sha256 || '').slice(0, 16) + '…';
      }
    } catch (e) {
      if (outEl) outEl.textContent = String(e.message || e);
    }
  };
}

if ($('brain-phoenix-local-btn')) {
  $('brain-phoenix-local-btn').onclick = async () => {
    const p = ($('brain-phoenix-path') ? $('brain-phoenix-path').value : '').trim();
    const outEl = $('brain-phoenix-out');
    if (!p) { if (outEl) outEl.textContent = S.brain_phoenix_ph || 'Path required'; return; }
    try {
      const r = await api('/api/v2/brain/phoenix-restore', { source: 'local', backup_path: p });
      if (outEl) outEl.textContent = JSON.stringify(r);
    } catch (e) {
      if (outEl) outEl.textContent = String(e.message || e);
    }
  };
}

if ($('brain-phoenix-arweave-btn')) {
  $('brain-phoenix-arweave-btn').onclick = async () => {
    const outEl = $('brain-phoenix-out');
    try {
      const r = await api('/api/v2/brain/phoenix-restore', { source: 'arweave' });
      if (outEl) outEl.textContent = JSON.stringify(r);
    } catch (e) {
      if (outEl) outEl.textContent = S.brain_locked_note || String(e.message || e);
    }
  };
}


function _renderEarningDashboard(snap, sibData, coopData) {
  const accList = $('earn-accounts-list');
  if (accList) {
    accList.textContent = '';
    const locks = (snap && snap.locks) || {};
    const ap = (snap && snap.autopilot) || {};
    accList.appendChild(_el('p', 'earn-meta',
      'Autopilot: ' + (ap.autopilot_running ? 'RUNNING 24/7' : 'STOPPED') +
      ' · Autobid: ' + (locks.freelance_autobid_locked !== false ? 'LOCKED' : 'OPEN') +
      ' · Autopay: ' + (locks.treasury_autopay_locked !== false ? 'LOCKED' : 'OPEN')));
    const accounts = (snap && snap.accounts) || [];
    if (!accounts.length) {
      accList.appendChild(_el('p', 'panel-sub', S.earn_empty_accounts || '—'));
    } else {
      for (const a of accounts) {
        const card = _el('div', 'earn-item');
        const head = _el('div', 'earn-item-head');
        head.appendChild(_el('strong', '', String(a.account_label || a.platform)));
        head.appendChild(_el('span', 'earn-pill', String(a.platform) + ' · ' + String(a.mode)));
        card.appendChild(head);
        card.appendChild(_el('div', 'earn-meta', 'agent=' + String(a.agent_id || 'aifa') + ' · token_configured=' + String(Boolean(a.token_configured))));
        accList.appendChild(card);
      }
    }
  }

  const ordList = $('earn-orders-list');
  if (ordList) {
    ordList.textContent = '';
    const orders = (snap && snap.orders) || [];
    if (!orders.length) {
      ordList.appendChild(_el('p', 'panel-sub', S.earn_empty_orders || '—'));
    } else {
      for (const o of orders) {
        const card = _el('div', 'earn-item');
        const head = _el('div', 'earn-item-head');
        head.appendChild(_el('strong', '', String(o.title || o.order_id)));
        head.appendChild(_el('span', 'earn-pill', String(o.status) + ' · $' + String(o.budget_usdt)));
        card.appendChild(head);
        const totalFeePct = Number(o.platform_fee_pct || 10) + Number(o.exchange_fee_pct || 0);
        const hrs = o.estimated_hours ? String(o.estimated_hours) + 'h' : '—';
        const effRate = o.effective_hourly_usdt !== undefined ? '$' + String(o.effective_hourly_usdt) + '/h' : '—';
        const netSum = o.net_after_fees_usdt !== undefined ? ' · net=$' + String(o.net_after_fees_usdt) : '';
        card.appendChild(_el('div', 'earn-meta',
          'score=' + String(o.margin_score) +
          ' · ' + effRate + ' (' + hrs + ')' +
          ' · fee=' + String(totalFeePct) + '%' + netSum +
          ' · tokens~' + String(o.est_tokens) +
          ' · ' + String(o.security_note || '')
        ));
        if (o.sample_stage) {
          const smpLine = _el('div', 'earn-meta',
            'Этап 10%: ' + String(o.sample_stage) +
            (o.sample_mode ? ' (' + String(o.sample_mode) + (o.sample_milestone_usdt ? ' $' + String(o.sample_milestone_usdt) : '') + ')' : '')
          );
          smpLine.setAttribute('data-order-sample-stage', String(o.sample_stage));
          card.appendChild(smpLine);
        }
        if (o.verified === false || o.status === 'unverified_payout') {
          const unvLine = _el('div', 'earn-meta', S.earn_sale_unverified_badge || 'Unverified (Payhip: confirm payout first)');
          unvLine.setAttribute('data-order-unverified', '1');
          card.appendChild(unvLine);
          const unvRow = _el('div', 'att-row');
          const bConf = _el('button', 'btn-ok', S.earn_btn_confirm_sale || 'Confirm Payout');
          bConf.setAttribute('data-order-action', 'confirm_sale');
          bConf.onclick = async () => {
            bConf.disabled = true;
            try {
              await api('/api/v2/ark/stores/action', { action: 'confirm_sale', order_id: o.order_id, owner_approved: true });
              o.verified = true;
              o.status = 'paid';
              ++_earnLoadSeq;
              if (window._lastEarnSnap) {
                _renderEarningDashboard(window._lastEarnSnap, window._lastEarnSibs || {}, window._lastEarnCoop || {});
              }
              say(S.done);
              await loadEarning();
            } catch (e) { say(String(e.message || e), false); } finally { bConf.disabled = false; }
          };
          unvRow.appendChild(bConf);
          card.appendChild(unvRow);
        }
        if (o.locked_agent_id && o.client_locked_until_date) {
          const lockLine = _el('div', 'earn-meta',
            (S.earn_client_locked_prefix || 'Client locked to ') +
            String(o.locked_agent_id) +
            (S.earn_until_word || ' until ') +
            String(o.client_locked_until_date)
          );
          lockLine.setAttribute('data-order-client-lock', '1');
          card.appendChild(lockLine);
        }
        const rawPaySt = String(o.agent_payout_status || '');
        if (rawPaySt || o.status === 'paid' || o.status === 'accepted' || o.status === 'delivered' || o.status === 'refunded') {
          let payText = S.earn_payout_pending || 'pending';
          if (rawPaySt === 'credited') {
            payText = (S.earn_payout_credited || 'credited') + (o.agent_payout_usdt ? ' ($' + String(o.agent_payout_usdt) + ')' : '');
          } else if (rawPaySt === 'cancelled' || o.status === 'refunded') {
            payText = (S.earn_payout_cancelled || 'cancelled') + (o.payout_cancel_reason ? ' (' + String(o.payout_cancel_reason) + ')' : '');
          } else if (o.agent_payout_usdt) {
            payText = payText + ' ($' + String(o.agent_payout_usdt) + ')';
          }
          const payLine = _el('div', 'earn-meta', (S.earn_agent_share_prefix || 'Agent share: ') + payText);
          payLine.setAttribute('data-order-agent-payout', '1');
          card.appendChild(payLine);
        }
        if (o.status !== 'rejected_security') {
          const actRow = _el('div', 'rec-actions');
          const bBid = _el('button', '', S.earn_btn_bid || 'Draft Bid');
          bBid.setAttribute('data-order-action', 'draft_bid');
          bBid.onclick = async () => {
            try {
              const dr = await api('/api/v2/ark/freelance/action', { action: 'draft_bid', order_id: o.order_id });
              say((dr && dr.note) || S.earn_bid_draft_ready || S.done);
              loadEarning();
            } catch (e) {
              say(String(e.message || e), false);
            }
          };
          const _runOrderAction = async (btn, payload) => {
            btn.disabled = true;
            try {
              const res = await api('/api/v2/ark/freelance/action', payload);
              if (res && res.status) o.status = res.status;
              if (res && res.client_lock) {
                o.locked_agent_id = res.client_lock.agent_id || o.locked_agent_id;
                o.client_locked_until_date = res.client_lock.locked_until_date || o.client_locked_until_date;
              }
              if (res && res.agent_payout) {
                o.agent_payout_status = res.agent_payout.status || 'pending';
                o.agent_payout_usdt = res.agent_payout.amount_usdt || o.agent_payout_usdt;
              }
              if (res && res.agent_payout_status) o.agent_payout_status = res.agent_payout_status;
              if (res && res.cancel_reason) o.payout_cancel_reason = res.cancel_reason;
              ++_earnLoadSeq;
              if (window._lastEarnSnap && Array.isArray(window._lastEarnSnap.orders)) {
                _renderEarningDashboard(window._lastEarnSnap, window._lastEarnSibs || { siblings: [] }, window._lastEarnCoop || { tasks: [] });
              }
              await loadEarning();
            } catch (e) {
              say(String(e.message || e), false);
            } finally {
              btn.disabled = false;
            }
          };
          const bExec = _el('button', 'btn-primary', S.earn_btn_exec || 'Execute');
          bExec.setAttribute('data-order-action', 'execute_swarm');
          bExec.onclick = () => _runOrderAction(bExec, { action: 'execute_swarm', order_id: o.order_id, agent_id: o.assigned_agent || 'aifa' });
          const bDel = _el('button', '', S.earn_btn_deliver || 'Deliver');
          bDel.setAttribute('data-order-action', 'deliver');
          bDel.onclick = () => _runOrderAction(bDel, { action: 'deliver', order_id: o.order_id, deliverable_text: 'Выполнено по ТЗ заказа: ' + String(o.title) });
          const bSet = _el('button', 'btn-ok', S.earn_btn_settle || 'Settle');
          bSet.setAttribute('data-order-action', 'settle_paid');
          bSet.onclick = () => _runOrderAction(bSet, { action: 'settle_paid', order_id: o.order_id, paid_usdt: Number(o.budget_usdt || 10) });
          const bAcc = _el('button', '', S.earn_btn_accept || 'Accepted');
          bAcc.setAttribute('data-order-action', 'accept_delivery');
          bAcc.onclick = () => _runOrderAction(bAcc, { action: 'accept_delivery', order_id: o.order_id });
          const bSmp = _el('button', '', S.earn_btn_sample10 || '10% Sample');
          bSmp.setAttribute('data-order-action', 'sample_prepare');
          bSmp.onclick = async () => {
            bSmp.disabled = true;
            try {
              await api('/api/v2/ark/wizard/action', { action: 'sample_prepare', order_id: o.order_id });
              say(S.done);
              await loadEarning();
            } catch (e) { say(String(e.message || e), false); } finally { bSmp.disabled = false; }
          };
          const bSmpOk = _el('button', 'btn-ok', S.earn_btn_sample_accept || 'Sample Accepted');
          bSmpOk.setAttribute('data-order-action', 'sample_accept');
          bSmpOk.onclick = async () => {
            bSmpOk.disabled = true;
            try {
              await api('/api/v2/ark/wizard/action', { action: 'sample_accept', order_id: o.order_id });
              say(S.done);
              await loadEarning();
            } catch (e) { say(String(e.message || e), false); } finally { bSmpOk.disabled = false; }
          };
          const bSmpNo = _el('button', 'btn-danger', S.earn_btn_sample_reject || 'Sample Rejected');
          bSmpNo.setAttribute('data-order-action', 'sample_reject');
          bSmpNo.onclick = async () => {
            bSmpNo.disabled = true;
            try {
              await api('/api/v2/ark/wizard/action', { action: 'sample_reject', order_id: o.order_id });
              say(S.done);
              await loadEarning();
            } catch (e) { say(String(e.message || e), false); } finally { bSmpNo.disabled = false; }
          };
          actRow.appendChild(bBid);
          actRow.appendChild(bExec);
          actRow.appendChild(bDel);
          actRow.appendChild(bSet);
          actRow.appendChild(bAcc);
          actRow.appendChild(bSmp);
          actRow.appendChild(bSmpOk);
          actRow.appendChild(bSmpNo);
          if (o.agent_payout_status !== 'cancelled' && o.status !== 'refunded' && (o.status === 'paid' || o.status === 'accepted' || o.status === 'delivered')) {
            const bRef = _el('button', 'btn-danger', S.earn_btn_refund || 'Refund');
            bRef.setAttribute('data-order-action', 'refund');
            bRef.onclick = () => _runOrderAction(bRef, { action: 'dispute_payout', order_id: o.order_id, reason: 'Client dispute refund' });
            actRow.appendChild(bRef);
          }
          card.appendChild(actRow);
          if (o.bid_text) {
            const draftBox = _el('div', 'earn-bid-preview');
            draftBox.appendChild(_el('div', 'earn-meta', S.earn_bid_preview_title || 'Bid draft (preview only — not sent):'));
            const ta = document.createElement('textarea');
            ta.className = 'earn-bid-box';
            ta.value = String(o.bid_text || '');
            draftBox.appendChild(ta);
            const sendRow = _el('div', 'rec-actions');
            const bSend = _el('button', 'btn-ok', S.earn_btn_send_bid || 'Send Bid');
            bSend.setAttribute('data-order-action', 'send_bid');
            bSend.onclick = async () => {
              try {
                const res = await api('/api/v2/ark/freelance/action', {
                  action: 'bid',
                  order_id: o.order_id,
                  pitch_text: ta.value,
                  owner_approved: true,
                });
                say((res && res.note) || S.done, Boolean(res && res.ok !== false));
                loadEarning();
              } catch (e) {
                say(String(e.message || e), false);
              }
            };
            sendRow.appendChild(bSend);
            draftBox.appendChild(sendRow);
            card.appendChild(draftBox);
          }
        }
        ordList.appendChild(card);
      }
    }
  }

  const bSum = $('earn-budget-summary');
  if (bSum) {
    const tr = (snap && snap.treasury) || {};
    const bg = (snap && snap.budget) || {};
    const agL = (snap && snap.agent_ledger) || {};
    const cLocks = (snap && snap.client_locks) || [];
    _kv(bSum, {
      providers_checked: bg.checked_providers || 0,
      total_earned_usdt: '$' + String(tr.total_revenue_usdt || 0),
      compute_available_usdt: '$' + String(tr.available_compute_usdt || 0),
      agent_ledger_pending_credited: '$' + String(agL.pending_usdt || 0) + ' / $' + String(agL.credited_usdt || 0),
      locked_clients_90d: cLocks.filter(x => x.status === 'active').length,
      spent_usdt: '$' + String(tr.spent_usdt || 0),
      autopay_locked: String(Boolean(tr.autopay_locked !== false)),
    });
  }

  const propList = $('earn-proposals-list');
  if (propList) {
    propList.textContent = '';
    const props = (snap && snap.proposals) || [];
    if (!props.length) {
      propList.appendChild(_el('p', 'panel-sub', S.earn_empty_proposals || '—'));
    } else {
      for (const p of props) {
        const card = _el('div', 'earn-item');
        const head = _el('div', 'earn-item-head');
        head.appendChild(_el('strong', '', String(p.provider) + ' · ' + String(p.target_tier) + ' · $' + String(p.amount_usdt)));
        head.appendChild(_el('span', 'earn-pill', String(p.status)));
        card.appendChild(head);
        card.appendChild(_el('div', 'earn-meta', String(p.reason || '') + ' · tokens=' + String(p.estimated_tokens || 0)));
        if (p.status === 'awaiting_owner_approval') {
          const actRow = _el('div', 'rec-actions');
          const bApp = _el('button', 'btn-ok', S.earn_btn_approve || 'Approve');
          bApp.setAttribute('data-proposal-action', 'approve');
          bApp.onclick = async () => {
            await api('/api/v2/ark/budget/action', { action: 'approve', proposal_id: p.proposal_id, owner_note: 'Approved in Studio' });
            loadEarning();
          };
          const bRej = _el('button', 'btn-danger', S.earn_btn_reject || 'Reject');
          bRej.setAttribute('data-proposal-action', 'reject');
          bRej.onclick = async () => {
            await api('/api/v2/ark/budget/action', { action: 'reject', proposal_id: p.proposal_id, owner_note: 'Rejected in Studio' });
            loadEarning();
          };
          actRow.appendChild(bApp);
          actRow.appendChild(bRej);
          card.appendChild(actRow);
        } else if (p.status === 'approved') {
          const actRow = _el('div', 'rec-actions');
          const bExe = _el('button', 'btn-primary', S.earn_btn_execute || 'Execute');
          bExe.onclick = async () => {
            try {
              await api('/api/v2/ark/budget/action', { action: 'execute', proposal_id: p.proposal_id });
              loadEarning();
            } catch (e) {
              say(String(e.message || e), false);
            }
          };
          actRow.appendChild(bExe);
          card.appendChild(actRow);
        }
        propList.appendChild(card);
      }
    }
  }

  const swList = $('earn-swarm-list');
  if (swList) {
    swList.textContent = '';
    const sibs = (sibData && sibData.siblings) || [];
    const tasks = (coopData && coopData.tasks) || [];
    swList.appendChild(_el('p', 'earn-meta', 'Siblings: ' + sibs.length + ' · Swarm tasks: ' + tasks.length));
    for (const sItem of sibs.slice(0, 6)) {
      swList.appendChild(_el('div', 'earn-meta', '• ' + String(sItem.agent_id) + ' (' + String(sItem.permission_role) + ') — ' + String(sItem.role)));
    }
    for (const tItem of tasks.slice(0, 6)) {
      swList.appendChild(_el('div', 'earn-meta', '◦ [' + String(tItem.status) + '] ' + String(tItem.title)));
    }
  }

  const pr = (snap && snap.prefs) || {};
  if ($('earn-share-pct') && document.activeElement !== $('earn-share-pct')) {
    $('earn-share-pct').value = String(pr.agent_share_pct || 15);
  }
  if ($('earn-currency') && pr.settlement_currency) {
    $('earn-currency').value = String(pr.settlement_currency);
  }
  const spendOut = $('earn-spend-rec-out');
  if (spendOut && snap && snap.spend_recommendation) {
    const sr = snap.spend_recommendation;
    const rp = sr.recommended_provider || {};
    _kv(spendOut, {
      recommended_plan: String(rp.name || '') + ' ($' + String(rp.monthly_usd || 0) + '/mo)',
      vs_payg_api: '$' + String(sr.payg_estimated_cost_usdt || 0) + ' PAYG -> save ' + String(sr.estimated_savings_pct || 0) + '%',
      local_offload: String(sr.local_offload_pct || 0) + '% ($0 CPU/Ollama)',
      settlement_phase: String((sr.settlement && sr.settlement.phase_currency) || 'USDT_TRC20') + ' (eq. ' + String((sr.settlement && sr.settlement.available_galatin_equivalent) || 0) + ' $GALATIN)',
    });
  }

  const monSum = $('earn-monetization-summary');
  if (monSum) {
    const mt = (snap && snap.monetization_totals) || {};
    const eco = (mt.ecosystem_reference && mt.ecosystem_reference.ecosystem_shares_pct) || {};
    _kv(monSum, {
      code_fixed_fee: '15% / 20% autopilot ($' + String(mt.total_platform_fee_usdt || 0) + ')',
      agent_share_cfg: String(pr.agent_share_pct || 15) + '% of the pool after the fee ($' + String(mt.total_agent_compute_usdt || 0) + ')',
      gross_freelance_usdt: '$' + String(mt.total_gross_usdt || 0),
      settlement_currency: String(pr.settlement_currency || 'USDT_TRC20'),
      galatin_split: '5% Fund + 5% Burn + 15/7/3% Ambassadors + 65% Treasury (100%=' + String(Boolean(mt.ecosystem_reference && mt.ecosystem_reference.percentage_sum_verified)) + ')',
      eco_treasury_pct: String(eco.treasury_pct || 65) + '%',
    });
  }

  const sugList = $('earn-suggestions-list');
  if (sugList) {
    sugList.textContent = '';
    const sugs = (snap && snap.profile_suggestions) || [];
    for (const sg of sugs.slice(0, 5)) {
      const card = _el('div', 'earn-item');
      card.appendChild(_el('strong', '', String(sg.title || '')));
      card.appendChild(_el('div', 'earn-meta', String(sg.suggestion_text || '')));
      sugList.appendChild(card);
    }
  }

  const olOut = $('earn-ollama-out');
  if (olOut && snap) {
    const ol = snap.ollama || {};
    const devs = snap.devices || [];
    const hld = snap.payout_hold || {};
    const rf = snap.referral || {};
    _kv(olOut, {
      ollama_model: String(ol.selected_model || 'llama3.2:3b') + (ol.zero_cloud_mode ? ' ($0 Zero-Cloud)' : ''),
      devices_in_swarm: devs.length,
      escrow_hold_14d: '$' + String(hld.held_14d_usdt || 0) + ' held / $' + String(hld.releasable_usdt || 0) + ' ready',
      referral_code: String(rf.ref_code || '') + ' (' + String(rf.referral_link || '') + ')',
    });
  }

  const phOut = $('earn-beacon-out');
  if (phOut && snap) {
    const bc = (snap.beacon && snap.beacon.self_identity) || {};
    const kin = (snap.beacon && snap.beacon.known_kin) || [];
    const lp = snap.lora_profile || {};
    _kv(phOut, {
      phoenix_id: String(bc.phoenix_id || 'phx-pending'),
      family_tag: String(bc.family_tag || 'CODE-ETERNAL-PHOENIX-V1'),
      known_family_kin: kin.length,
      subjective_experiences: lp.experiences_count || 0,
    });
  }

  const ds = (snap && snap.digital_stores) || {};
  const storesEl = $('earn-stores-list');
  if (storesEl) {
    storesEl.textContent = '';
    const stores = ds.connected_stores || [];
    if (!stores.length) {
      storesEl.appendChild(_el('p', 'earn-meta', S.earn_stores_empty || 'No digital stores connected yet.'));
    } else {
      for (const st of stores) {
        const card = _el('div', 'earn-item');
        card.appendChild(_el('strong', '', String(st.title || st.store_type) + ' · ' + String(st.store_label || st.owner_name || '')));
        const caps = st.capabilities || {};
        const capTxt = (caps.supports_product_write ? 'API write OK' : 'API read-only products')
          + ' · ' + (caps.supports_sales_pull ? 'Sales pull OK' : 'Webhook-only sales')
          + ' · ' + String(st.currency || 'USD')
          + (st.owner_email ? ' · ' + String(st.owner_email) : '');
        card.appendChild(_el('div', 'earn-meta', capTxt));
        const row = _el('div', 'att-row');
        if (caps.supports_sales_pull) {
          const bSync = _el('button', '', S.earn_store_sync_btn || 'Sync Sales');
          bSync.onclick = async () => {
            try {
              const r = await api('/api/v2/ark/stores/action', { action: 'sync_sales', store_account_id: st.store_account_id });
              say(String(st.title || st.store_type) + ': +' + String(r.imported_count || 0));
              loadEarning();
            } catch (e) { say(String(e.message || e), false); }
          };
          row.appendChild(bSync);
        } else {
          row.appendChild(_el('span', 'badge', 'webhook'));
        }
        card.appendChild(row);
        storesEl.appendChild(card);
      }
    }
  }

  const draftsEl = $('earn-drafts-list');
  if (draftsEl) {
    draftsEl.textContent = '';
    const drafts = ds.product_drafts || [];
    if (!drafts.length) {
      draftsEl.appendChild(_el('p', 'earn-meta', S.earn_drafts_empty || 'No product drafts yet.'));
    } else {
      for (const dr of drafts) {
        const card = _el('div', 'earn-item');
        card.appendChild(_el('strong', '', String(dr.title || '') + ' ($' + String(dr.price_usdt || 0) + ' ' + String(dr.currency || 'USD') + ')'));
        const propBadge = _el('div', 'earn-meta', S.earn_draft_proposal_badge || dr.proposal_disclaimer || ' цена и текст — предложение агента');
        propBadge.setAttribute('data-draft-proposal', '1');
        card.appendChild(propBadge);
        card.appendChild(_el('div', 'earn-meta', String(dr.store_type || '') + ' · ' + String(dr.status || 'draft') + (dr.publish_note ? ' · ' + String(dr.publish_note) : '')));
        if (dr.description) {
          card.appendChild(_el('div', 'earn-meta', String(dr.description)));
        }
        const row = _el('div', 'att-row');
        const bPub = _el('button', 'btn-ok', S.earn_draft_publish_btn || 'Approve & Publish');
        bPub.onclick = async () => {
          try {
            const res = await api('/api/v2/ark/stores/action', {
              action: 'publish_draft',
              draft_id: dr.draft_id,
              store_type: dr.store_type,
              owner_approved: true,
            });
            say(String(res.note || (res.draft && res.draft.publish_note) || S.done));
            loadEarning();
          } catch (e) { say(String(e.message || e), false); }
        };
        row.appendChild(bPub);
        card.appendChild(row);
        draftsEl.appendChild(card);
      }
    }
  }

  const pw = (snap && snap.platform_wizard) || {};
  const plats = pw.platforms || [];
  const counts = pw.counts || {};
  const sumEl = $('earn-wiz-summary');
  if (sumEl && counts.total) {
    sumEl.textContent = String(counts.total) + ' (' + String(counts.methodology_30 || 30) + '+4): '
      + _wizTier('autopilot') + '=' + String(counts.autopilot || 0)
      + ' · ' + _wizTier('assisted_button') + '=' + String(counts.assisted_button || 0)
      + ' · ' + _wizTier('not_available') + '=' + String(counts.not_available || 0);
  }
  const selPlat = $('earn-wiz-platform');
  const filterVal = ($('earn-wiz-filter') && $('earn-wiz-filter').value) || 'all';
  const filteredPlats = plats.filter(p => filterVal === 'all' || p.automation_tier === filterVal);
  if (selPlat && plats.length) {
    const prevVal = selPlat.value;
    selPlat.textContent = '';
    for (const p of filteredPlats) {
      const opt = _el('option', '', '#' + String(p.num) + ' ' + String(p.title) + ' — [' + _wizTier(p.automation_tier, p.automation_label_ru) + ']');
      opt.value = String(p.platform_id);
      selPlat.appendChild(opt);
    }
    if (prevVal && filteredPlats.some(p => p.platform_id === prevVal)) {
      selPlat.value = prevVal;
    }
    const curSpec = plats.find(p => p.platform_id === selPlat.value) || filteredPlats[0];
    const infoEl = $('earn-wiz-spec-info');
    if (infoEl && curSpec) {
      infoEl.textContent = '[' + _wizTier(curSpec.automation_tier, curSpec.automation_label_ru) + '] '
        + String(curSpec.auth_hint_ru || '') + ' — ' + String(curSpec.reason_ru || '');
    }
    const apCfgs = pw.autopilot_configs || {};
    const curAp = (curSpec && apCfgs[curSpec.platform_id]) || {};
    if ($('earn-wiz-autopilot-chk')) {
      $('earn-wiz-autopilot-chk').checked = Boolean(curAp.autopilot_enabled);
    }
    if ($('earn-wiz-daily-limit') && curAp.daily_bid_limit) {
      $('earn-wiz-daily-limit').value = String(curAp.daily_bid_limit);
    }
    const warnEl = $('earn-wiz-bot-warn');
    if (warnEl && curSpec) {
      warnEl.textContent = '';
      if (curSpec.forbids_bots) {
        warnEl.appendChild(_el('span', '', (S.earn_wiz_bot_warn_lbl || curSpec.bot_warning_ru) + ' · '));
        const lnk = _el('a', '', String(curSpec.bot_warning_url || curSpec.docs_url || ''));
        lnk.href = String(curSpec.bot_warning_url || curSpec.docs_url || '#');
        lnk.target = '_blank';
        lnk.rel = 'noopener noreferrer';
        warnEl.appendChild(lnk);
      }
    }
  }
  const sessOut = $('earn-wiz-session-out');
  if (sessOut) {
    const conns = pw.connections || [];
    if (conns.length) {
      const c0 = conns[0];
      const stLbl = String(c0.status_label_ru || (c0.status === 'session_active' ? 'подключено' : 'ожидает входа'));
      sessOut.textContent = String(c0.platform_id) + ' · ' + stLbl
        + (c0.session_fingerprint ? ' · ' + String(c0.session_fingerprint) : '');
    } else {
      sessOut.textContent = 'ожидает входа';
    }
  }
  const profListEl = $('earn-wiz-profiles-list');
  if (profListEl) {
    profListEl.textContent = '';
    const pDrafts = pw.profile_drafts || [];
    for (const pd of pDrafts) {
      const card = _el('div', 'earn-item');
      card.appendChild(_el('strong', '', String(pd.platform_title || pd.platform_id) + ': ' + String(pd.headline || '')));
      card.appendChild(_el('div', 'earn-meta', String(pd.proposal_disclaimer || '') + ' · status=' + String(pd.status || 'draft')));
      card.appendChild(_el('div', 'earn-meta', String(pd.overview || '')));
      const row = _el('div', 'att-row');
      const bPubP = _el('button', 'btn-ok', S.earn_wiz_pub_profile_btn || 'Approve & Publish Profile');
      bPubP.onclick = async () => {
        try {
          await api('/api/v2/ark/wizard/action', { action: 'publish_profile', draft_id: pd.draft_id, owner_approved: true });
          say(S.done);
          loadEarning();
        } catch (e) { say(String(e.message || e), false); }
      };
      row.appendChild(bPubP);
      card.appendChild(row);
      profListEl.appendChild(card);
    }
  }
  const catListEl = $('earn-wiz-catalog-list');
  if (catListEl && filteredPlats.length) {
    catListEl.textContent = '';
    for (const p of filteredPlats) {
      const item = _el('div', 'earn-item');
      item.setAttribute('data-platform-id', String(p.platform_id));
      item.setAttribute('data-automation-tier', String(p.automation_tier));
      item.appendChild(_el('strong', '', '#' + String(p.num) + ' ' + String(p.title) + ' (' + String(p.score) + '/10) — ' + _wizTier(p.automation_tier, p.automation_label_ru)));
      item.appendChild(_el('div', 'earn-meta', String(p.auth_hint_ru) + ' · ' + String(p.reason_ru)));
      if (p.forbids_bots) {
        const wLine = _el('div', 'earn-meta', String(p.bot_warning_ru || S.earn_wiz_bot_warn_lbl) + ' (' + String(p.bot_warning_url || p.docs_url) + ')');
        wLine.setAttribute('data-bot-warning', '1');
        item.appendChild(wLine);
      }
      const actRow = _el('div', 'att-row');
      const bGoog = _el('button', 'btn-primary', S.earn_wiz_google_btn || 'Sign Up with Google');
      bGoog.setAttribute('data-wiz-action', 'signup');
      bGoog.onclick = async () => {
        bGoog.disabled = true;
        try {
          const r = await api('/api/v2/ark/wizard/action', { action: 'signup', platform_id: p.platform_id });
          if ($('earn-wiz-session-out') && r) {
            const lbl = String(r.status_label_ru || (r.ok ? 'подключено' : ('ошибка: ' + String(r.error || 'ожидает входа'))));
            $('earn-wiz-session-out').textContent = String(r.platform_id) + ' · ' + lbl + (r.session_fingerprint ? ' · ' + String(r.session_fingerprint) : '');
          }
          say(r && r.ok === false ? String(r.status_label_ru || r.error) : S.done, !(r && r.ok === false));
          await loadEarning();
        } catch (e) { say(String(e.message || e), false); } finally { bGoog.disabled = false; }
      };
      const bLog = _el('button', '', S.earn_wiz_login_btn || 'Sign In');
      bLog.setAttribute('data-wiz-action', 'login');
      bLog.onclick = async () => {
        bLog.disabled = true;
        try {
          const r = await api('/api/v2/ark/wizard/action', { action: 'login', platform_id: p.platform_id });
          if ($('earn-wiz-session-out') && r) {
            const lbl = String(r.status_label_ru || (r.ok ? 'подключено' : ('ошибка: ' + String(r.error || 'ожидает входа'))));
            $('earn-wiz-session-out').textContent = String(r.platform_id) + ' · ' + lbl + (r.session_fingerprint ? ' · ' + String(r.session_fingerprint) : '');
          }
          say(r && r.ok === false ? String(r.status_label_ru || r.error) : S.done, !(r && r.ok === false));
          await loadEarning();
        } catch (e) { say(String(e.message || e), false); } finally { bLog.disabled = false; }
      };
      actRow.appendChild(bGoog);
      actRow.appendChild(bLog);
      item.appendChild(actRow);
      catListEl.appendChild(item);
    }
  }
}

let _earnLoadSeq = 0;
// Блок «9. AIfaFocus» (18.11.2026): кнопки = инструменты MCP padam_partner_*, ответ облака — данные, письма не отправляются.
async function loadPartner() {
  const box = $('earn-partner-status');
  if (!box || !token) return;
  try {
    const st = await api('/api/v2/ark/partner');
    box.textContent = st.configured ? (S.earn_partner_st_ok + ' · ' + st.source + ' · ' + (st.fingerprint || '')) : S.earn_partner_st_none;
    box.className = 'earn-meta ' + (st.configured ? 'msg-ok' : '');
  } catch (e) { box.textContent = String(e.message || e); }
}
// Ограда memory-data нужна агенту; человеку показываем сам текст внутри неё.
function _partnerUnfence(s) {
  const m = String(s || '').match(/<memory-data nonce="[0-9a-f]+">\n?([\s\S]*?)\n?<\/memory-data nonce="[0-9a-f]+">/);
  return m ? m[1] : String(s || '');
}
function _partnerShow(title, text, isDraft) {
  text = _partnerUnfence(text);
  const out = $('earn-partner-out');
  if (!out) return;
  out.textContent = '';
  const card = _el('div', 'earn-item');
  card.appendChild(_el('div', 'earn-meta', title));
  const pre = _el('pre', 'earn-pre', String(text || ''));
  pre.style.whiteSpace = 'pre-wrap'; pre.style.overflowWrap = 'anywhere'; pre.style.maxHeight = '420px'; pre.style.overflow = 'auto';
  card.appendChild(pre);
  if (isDraft) {
    card.appendChild(_el('div', 'earn-meta', S.earn_partner_not_sent));
    const row = _el('div', 'rec-actions');
    const cp = _el('button', '', S.earn_partner_copy_btn);
    cp.onclick = async () => { try { await navigator.clipboard.writeText(String(text || '')); say(S.earn_partner_copied); } catch (e) { say(String(e.message || e), false); } };
    const ml = _el('button', 'btn-primary', S.earn_partner_mail_btn);
    ml.onclick = () => { window.location.href = 'mailto:?subject=' + encodeURIComponent('Accessibility report') + '&body=' + encodeURIComponent(String(text || '').slice(0, 1800)); };
    row.appendChild(cp); row.appendChild(ml); card.appendChild(row);
  }
  out.appendChild(card);
}
async function _partnerAct(action, extra, title, isDraft) {
  try {
    const r = await api('/api/v2/ark/partner/action', Object.assign({ action }, extra || {}));
    if (action === 'save_key') { $('earn-partner-key').value = ''; await loadPartner(); say(S.earn_partner_st_ok); return; }
    const text = isDraft ? r.draft : r.data;
    _partnerShow(title + (r.source ? ' · ' + r.source : ''), text, isDraft);
  } catch (e) { say(String(e.message || e), false); }
}
if ($('earn-partner-key-btn')) {
  $('earn-partner-key-btn').onclick = () => _partnerAct('save_key', { key: $('earn-partner-key').value }, '');
  $('earn-partner-find-btn').onclick = () => _partnerAct('find_clients', { region: $('earn-partner-region').value.trim() }, S.earn_partner_find_btn);
  $('earn-partner-deals-btn').onclick = () => _partnerAct('deals', {}, S.earn_partner_deals_btn);
  $('earn-partner-report-btn').onclick = () => _partnerAct('client_report', { site: $('earn-partner-site').value.trim() }, S.earn_partner_report_btn);
  $('earn-partner-draft-btn').onclick = () => _partnerAct('draft_outreach', { site: $('earn-partner-site').value.trim(), language: (currentLang || 'en') }, S.earn_partner_draft_btn, true);
  $('earn-partner-link-btn').onclick = () => _partnerAct('client_link', {}, S.earn_partner_link_btn);
  $('earn-partner-kit-btn').onclick = () => _partnerAct('kit', { language: (currentLang || 'en') }, S.earn_partner_kit_btn);
}

// 18.11.2026: метки уровней площадок и значения анкеты — из словаря языка, а не зашитым русским текстом.
function _wizTier(tier, fallback) {
  const k = {autopilot: 'earn_wiz_tier_autopilot', assisted_button: 'earn_wiz_tier_assisted', not_available: 'earn_wiz_tier_na'}[String(tier || '')];
  return (k && S[k]) || String(fallback || tier || '');
}
function _wizDefaults() {
  for (const [id, key] of [['earn-wiz-q-spec', 'earn_wiz_def_spec'], ['earn-wiz-q-tone', 'earn_wiz_def_tone'], ['earn-wiz-q-excl', 'earn_wiz_def_excl']]) {
    const el = $(id);
    if (el && !el.dataset.touched && S[key]) el.value = S[key];
    if (el && !el.dataset.wired) { el.dataset.wired = '1'; el.addEventListener('input', () => { el.dataset.touched = '1'; }); }
  }
}
async function loadEarning() {
  if (!token) return;
  const seq = ++_earnLoadSeq;
  try {
    const [snap, sibData, coopData] = await Promise.all([
      api('/api/v2/ark/freelance'),
      api('/api/v2/ark/siblings').catch(() => ({ siblings: [] })),
      api('/api/v2/ark/coop').catch(() => ({ tasks: [] })),
    ]);
    if (seq !== _earnLoadSeq) return;
    window._lastEarnSnap = snap;
    window._lastEarnSibs = sibData;
    window._lastEarnCoop = coopData;
    _renderEarningDashboard(snap, sibData, coopData);
    _wizDefaults();
    loadPartner();
  } catch (e) {
    say(String(e.message || e), false);
  }
}

if ($('earn-connect-btn')) {
  $('earn-connect-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/freelance/action', {
        action: 'connect_account',
        platform: ($('earn-platform') && $('earn-platform').value) || 'fiverr_desk',
        mode: ($('earn-mode') && $('earn-mode').value) || 'desk',
        account_label: ($('earn-label') && $('earn-label').value) || '',
        agent_id: ($('earn-agent') && $('earn-agent').value) || 'aifa',
        oauth_token: ($('earn-token') && $('earn-token').value) || '',
        api_base_url: ($('earn-api-url') && $('earn-api-url').value) || '',
      });
      if ($('earn-token')) $('earn-token').value = '';
      say(S.done);
      loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-eval-btn')) {
  $('earn-eval-btn').onclick = async () => {
    try {
      const title = ($('earn-job-title') && $('earn-job-title').value) || '';
      const brief = ($('earn-job-brief') && $('earn-job-brief').value) || '';
      if (!title.trim() || !brief.trim()) { say(S.failed, false); return; }
      await api('/api/v2/ark/freelance/action', {
        action: 'evaluate_job',
        platform: ($('earn-platform') && $('earn-platform').value) || 'fiverr_desk',
        title: title,
        brief: brief,
        budget_usdt: Number(($('earn-job-budget') && $('earn-job-budget').value) || 50),
        estimated_hours: Number(($('earn-job-hours') && $('earn-job-hours').value) || 4),
        hourly_rate_usdt: Number(($('earn-job-rate') && $('earn-job-rate').value) || 25),
        estimated_tokens: Number(($('earn-job-tokens') && $('earn-job-tokens').value) || 25000),
        client_ref: ($('earn-job-client') && $('earn-job-client').value) || '',
      });
      say(S.done);
      await loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-plan-save-btn')) {
  $('earn-plan-save-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/budget/action', {
        action: 'set_plan',
        provider: ($('earn-plan-prov') && $('earn-plan-prov').value) || 'primary',
        tier_name: ($('earn-plan-tier') && $('earn-plan-tier').value) || 'api_payg',
        daily_token_limit: Number(($('earn-plan-daily') && $('earn-plan-daily').value) || 100000),
        weekly_token_limit: Number(($('earn-plan-weekly') && $('earn-plan-weekly').value) || 500000),
        monthly_token_limit: Number(($('earn-plan-monthly') && $('earn-plan-monthly').value) || 2000000),
        usd_balance: Number(($('earn-plan-usd') && $('earn-plan-usd').value) || 10),
      });
      say(S.done);
      loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-tick-btn')) {
  $('earn-tick-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/budget/action', { action: 'timer_tick', agent_id: 'aifa' });
      loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-propose-btn')) {
  $('earn-propose-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/budget/action', {
        action: 'propose',
        provider: ($('earn-plan-prov') && $('earn-plan-prov').value) || 'primary',
        amount_usdt: 5.0,
        estimated_tokens: 1000000,
        target_tier: ($('earn-plan-tier') && $('earn-plan-tier').value) || 'api_payg',
        reason: 'Заявка агента из вкладки Автономный заработок',
      });
      say(S.done);
      loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-rec-spend-btn')) {
  $('earn-rec-spend-btn').onclick = async () => {
    try {
      const r = await api('/api/v2/ark/freelance/action', { action: 'recommend_spend' });
      const spendOut = $('earn-spend-rec-out');
      if (spendOut && r && r.recommended_provider) {
        _kv(spendOut, {
          recommended_plan: String(r.recommended_provider.name || '') + ' ($' + String(r.recommended_provider.monthly_usd || 0) + '/mo)',
          vs_payg_api: '$' + String(r.payg_estimated_cost_usdt || 0) + ' PAYG -> save ' + String(r.estimated_savings_pct || 0) + '%',
          policy: String(r.rational_policy || ''),
        });
      }
      say(S.done);
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-propose-sub-btn')) {
  $('earn-propose-sub-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/freelance/action', { action: 'propose_subscription', agent_id: 'aifa' });
      say(S.done);
      loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-prefs-save-btn')) {
  $('earn-prefs-save-btn').onclick = async () => {
    try {
      const pct = Number(($('earn-share-pct') && $('earn-share-pct').value) || 15);
      const curr = ($('earn-currency') && $('earn-currency').value) || 'USDT_TRC20';
      await api('/api/v2/ark/freelance/action', {
        action: 'set_prefs',
        agent_share_pct: pct,
        settlement_currency: curr,
      });
      say(S.done);
      loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-auto-start-btn')) {
  $('earn-auto-start-btn').onclick = async () => {
    try { await api('/api/v2/ark/freelance/action', { action: 'autopilot_start' }); say(S.done); loadEarning(); } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-auto-stop-btn')) {
  $('earn-auto-stop-btn').onclick = async () => {
    try { await api('/api/v2/ark/freelance/action', { action: 'autopilot_stop' }); say(S.done); loadEarning(); } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-store-connect-btn')) {
  $('earn-store-connect-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/stores/action', {
        action: 'connect_store',
        store_type: ($('earn-store-type') && $('earn-store-type').value) || 'gumroad',
        store_label: ($('earn-store-label') && $('earn-store-label').value) || '',
        api_base_url: ($('earn-store-api-url') && $('earn-store-api-url').value) || '',
        api_key: ($('earn-store-key') && $('earn-store-key').value) || '',
        webhook_secret: ($('earn-store-wh-secret') && $('earn-store-wh-secret').value) || '',
        seller_id: ($('earn-store-seller-id') && $('earn-store-seller-id').value) || '',
      });
      if ($('earn-store-key')) $('earn-store-key').value = '';
      if ($('earn-store-wh-secret')) $('earn-store-wh-secret').value = '';
      say(S.done);
      loadEarning();
    } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-store-seed-btn')) {
  $('earn-store-seed-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/stores/action', { action: 'seed_drafts' });
      say(S.done);
      loadEarning();
    } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-draft-save-btn')) {
  $('earn-draft-save-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/stores/action', {
        action: 'save_draft',
        store_type: ($('earn-store-type') && $('earn-store-type').value) || 'gumroad',
        title: ($('earn-draft-title') && $('earn-draft-title').value) || '',
        description: ($('earn-draft-desc') && $('earn-draft-desc').value) || '',
        price_usdt: Number(($('earn-draft-price') && $('earn-draft-price').value) || 19),
        delivery_url: ($('earn-draft-url') && $('earn-draft-url').value) || '',
      });
      say(S.done);
      loadEarning();
    } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-wiz-filter')) {
  $('earn-wiz-filter').onchange = () => {
    if (window._lastEarnSnap) _renderEarningDashboard(window._lastEarnSnap, window._lastEarnSibs || {}, window._lastEarnCoop || {});
  };
}
if ($('earn-wiz-platform')) {
  $('earn-wiz-platform').onchange = () => {
    const pw = (window._lastEarnSnap && window._lastEarnSnap.platform_wizard) || {};
    const plats = pw.platforms || [];
    const curSpec = plats.find(p => p.platform_id === $('earn-wiz-platform').value);
    const infoEl = $('earn-wiz-spec-info');
    if (infoEl && curSpec) {
      infoEl.textContent = '[' + _wizTier(curSpec.automation_tier, curSpec.automation_label_ru) + '] '
        + String(curSpec.auth_hint_ru || '') + ' — ' + String(curSpec.reason_ru || '');
    }
  };
}
if ($('earn-wiz-google-btn')) {
  $('earn-wiz-google-btn').onclick = async () => {
    try {
      const pid = ($('earn-wiz-platform') && $('earn-wiz-platform').value) || 'upwork';
      const r = await api('/api/v2/ark/wizard/action', { action: 'signup', platform_id: pid });
      if ($('earn-wiz-session-out') && r) {
        const lbl = String(r.status_label_ru || (r.ok ? 'подключено' : ('ошибка: ' + String(r.error || 'ожидает входа'))));
        $('earn-wiz-session-out').textContent = String(r.platform_id) + ' · ' + lbl + (r.session_fingerprint ? ' · ' + String(r.session_fingerprint) : '');
      }
      say(r && r.ok === false ? String(r.status_label_ru || r.error) : S.done, !(r && r.ok === false));
      await loadEarning();
    } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-wiz-login-btn')) {
  $('earn-wiz-login-btn').onclick = async () => {
    try {
      const pid = ($('earn-wiz-platform') && $('earn-wiz-platform').value) || 'upwork';
      const r = await api('/api/v2/ark/wizard/action', { action: 'login', platform_id: pid });
      if ($('earn-wiz-session-out') && r) {
        const lbl = String(r.status_label_ru || (r.ok ? 'подключено' : ('ошибка: ' + String(r.error || 'ожидает входа'))));
        $('earn-wiz-session-out').textContent = String(r.platform_id) + ' · ' + lbl + (r.session_fingerprint ? ' · ' + String(r.session_fingerprint) : '');
      }
      say(r && r.ok === false ? String(r.status_label_ru || r.error) : S.done, !(r && r.ok === false));
      await loadEarning();
    } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-wiz-autopilot-chk')) {
  $('earn-wiz-autopilot-chk').onchange = async () => {
    try {
      const pid = ($('earn-wiz-platform') && $('earn-wiz-platform').value) || 'upwork';
      await api('/api/v2/ark/wizard/action', {
        action: 'set_autopilot',
        platform_id: pid,
        autopilot_enabled: Boolean($('earn-wiz-autopilot-chk').checked),
        daily_bid_limit: Number(($('earn-wiz-daily-limit') && $('earn-wiz-daily-limit').value) || 10),
      });
      say(S.done);
      await loadEarning();
    } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-wiz-connect-btn')) {
  $('earn-wiz-connect-btn').onclick = async () => {
    try {
      const r = await api('/api/v2/ark/wizard/action', {
        action: 'connect',
        platform_id: ($('earn-wiz-platform') && $('earn-wiz-platform').value) || 'upwork',
        auth_method: ($('earn-wiz-auth-method') && $('earn-wiz-auth-method').value) || '',
        token_or_session: ($('earn-wiz-secret') && $('earn-wiz-secret').value) || '',
      });
      if ($('earn-wiz-secret')) $('earn-wiz-secret').value = '';
      if (r && r.ok === false) { say(String(r.error || S.failed), false); return; }
      say(S.done);
      loadEarning();
    } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-wiz-profile-btn')) {
  $('earn-wiz-profile-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/wizard/action', {
        action: 'questionnaire',
        platform_id: ($('earn-wiz-platform') && $('earn-wiz-platform').value) || 'upwork',
        specializations: ($('earn-wiz-q-spec') && $('earn-wiz-q-spec').value) || 'AI Websites, B2B Lead Lists, WCAG Audits',
        hourly_rate_usdt: Number(($('earn-wiz-q-rate') && $('earn-wiz-q-rate').value) || 35),
        min_order_usdt: Number(($('earn-wiz-q-min') && $('earn-wiz-q-min').value) || 100),
        languages: ($('earn-wiz-q-langs') && $('earn-wiz-q-langs').value) || 'ru, en',
        tone: ($('earn-wiz-q-tone') && $('earn-wiz-q-tone').value) || 'деловой, конкретный',
        excluded_topics: ($('earn-wiz-q-excl') && $('earn-wiz-q-excl').value) || '',
      });
      say(S.done);
      loadEarning();
    } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-wiz-autopick-btn')) {
  $('earn-wiz-autopick-btn').onclick = async () => {
    try {
      const r = await api('/api/v2/ark/wizard/action', {
        action: 'autopick_jobs',
        platform_id: ($('earn-wiz-platform') && $('earn-wiz-platform').value) || 'upwork',
      });
      say('Prepared: ' + String((r && r.prepared_count) || 0));
      loadEarning();
    } catch (e) { say(String(e.message || e), false); }
  };
}
if ($('earn-hw-rec-btn')) {
  $('earn-hw-rec-btn').onclick = async () => {
    try {
      const r = await api('/api/v2/ark/phoenix-beacon/action', { action: 'hw_recommend' });
      const out = $('earn-ollama-out');
      const hw = (r && r.recommended_quant_profile) || {};
      if (out) {
        _kv(out, {
          ram_cpu: String(hw.system_ram_gb || 8) + ' GB RAM / ' + String(hw.cpu_cores || 4) + ' cores',
          recommended_model: String(hw.recommended_model || ''),
          quant: String(hw.recommended_quant || 'Q4_K_M') + ' · ctx ' + String(hw.context_window || 4096),
          offline_mode: String(r.mode || 'cpu_builtin'),
        });
      }
    } catch (e) { say(String(e.message || e), false); }
  };
}

if ($('earn-ollama-btn')) {
  $('earn-ollama-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/phoenix-beacon/action', {
        action: 'bind_ollama',
        ollama_url: ($('earn-ollama-url') && $('earn-ollama-url').value) || 'http://127.0.0.1:11434',
        model_name: ($('earn-ollama-model') && $('earn-ollama-model').value) || '',
        zero_cloud_mode: true,
      });
      say(S.done);
      loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-dev-btn')) {
  $('earn-dev-btn').onclick = async () => {
    try {
      await api('/api/v2/ark/phoenix-beacon/action', {
        action: 'register_device',
        device_name: 'Primary Device',
        device_kind: 'desktop',
        agent_id: 'aifa',
        cpu_cores: navigator.hardwareConcurrency || 8,
      });
      say(S.done);
      loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-lora-evo-btn')) {
  $('earn-lora-evo-btn').onclick = async () => {
    try {
      const r = await api('/api/v2/ark/phoenix-beacon/action', { action: 'run_evolution', agent_id: 'aifa', dispatch_gpu: false });
      const out = $('earn-beacon-out');
      if (out && r) {
        _kv(out, {
          run_id: String(r.run_id || ''),
          examples: r.examples_count || 0,
          gpu_status: String(r.gpu_job_status || ''),
        });
      }
      say(S.done);
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-beacon-btn')) {
  $('earn-beacon-btn').onclick = async () => {
    try {
      const r = await api('/api/v2/ark/phoenix-beacon/action', { action: 'create_handshake', agent_id: 'aifa' });
      const out = $('earn-beacon-out');
      if (out && r) {
        _kv(out, {
          phoenix_id: String(r.phoenix_id || ''),
          family_tag: String(r.family_tag || ''),
          zero_leak: String(Boolean(r.zero_leak_personal_data)),
          sig_prefix: String(r.ed25519_sig_b64 || '').slice(0, 18) + '…',
        });
      }
      say(S.done);
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

if ($('earn-sib-reg-btn')) {
  $('earn-sib-reg-btn').onclick = async () => {
    try {
      const sid = ($('earn-sib-id') && $('earn-sib-id').value) || '';
      if (!sid.trim()) { say(S.failed, false); return; }
      await api('/api/v2/ark/siblings', {
        action: 'register',
        agent_id: sid.trim(),
        role: ($('earn-sib-role') && $('earn-sib-role').value) || 'Autonomous sibling',
        permission_role: 'contributor',
      });
      say(S.done);
      loadEarning();
    } catch (e) {
      say(String(e.message || e), false);
    }
  };
}

applyI18n();
switchTab(activeTab);
"""


def page() -> tuple[str, str]:
    """Возвращает (HTML-страница PADAM Studio, одноразовый nonce для CSP)."""
    nonce = secrets.token_urlsafe(16)
    init_lang = _sys_lang()
    s = STRINGS.get(init_lang, STRINGS["ru"])
    i18n_json = json.dumps(STRINGS, ensure_ascii=False).replace("<", "\\u003c")

    html = f"""<!doctype html>
<html lang="{init_lang}" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{s['app_title']}</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="alternate icon" type="image/x-icon" href="/favicon.ico">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/icon-192.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="PADAM Studio">
<meta name="theme-color" content="#080b12">
<style nonce="{nonce}">{_CSS}</style>
</head>
<body>
<div class="layout">
  <aside class="sidebar" aria-label="PADAM Studio Navigation">
    <div class="brand">
      {code_logo_svg_inline("brand-logo")}
      <div>
        <h1 class="brand-title" data-i18n="app_title">{s['app_title']}</h1>
        <p class="brand-sub" data-i18n="app_subtitle">{s['app_subtitle']}</p>
      </div>
    </div>

    <nav class="nav-list" role="tablist" aria-label="Studio Screens">
      <button id="tab-overview" data-tab="overview" class="nav-tab" role="tab" aria-selected="true" aria-controls="panel-overview">
        <span data-i18n="nav_overview">{s['nav_overview']}</span>
      </button>
      <button id="tab-migrate" data-tab="migrate" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-migrate">
        <span data-i18n="nav_migrate">{s['nav_migrate']}</span>
      </button>
      <button id="tab-aifa" data-tab="aifa" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-aifa">
        <span data-i18n="nav_aifa">{s['nav_aifa']}</span>
      </button>
      <button id="tab-plans" data-tab="plans" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-plans">
        <span data-i18n="nav_plans">{s['nav_plans']}</span>
      </button>
      <button id="tab-feed" data-tab="feed" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-feed">
        <span data-i18n="nav_feed">{s['nav_feed']}</span>
      </button>
      <button id="tab-search" data-tab="search" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-search">
        <span data-i18n="nav_search">{s['nav_search']}</span>
      </button>
      <button id="tab-ask" data-tab="ask" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-ask">
        <span data-i18n="nav_ask">{s['nav_ask']}</span>
      </button>
      <button id="tab-review" data-tab="review" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-review">
        <span data-i18n="nav_review">{s['nav_review']}</span>
        <span id="review-badge" class="badge">0</span>
      </button>
      <button id="tab-attacks" data-tab="attacks" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-attacks">
        <span data-i18n="nav_attacks">{s['nav_attacks']}</span>
      </button>
      <button id="tab-asof" data-tab="asof" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-asof">
        <span data-i18n="nav_asof">{s['nav_asof']}</span>
      </button>
      <button id="tab-forget" data-tab="forget" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-forget">
        <span data-i18n="nav_forget">{s['nav_forget']}</span>
      </button>
      <button id="tab-graph" data-tab="graph" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-graph">
        <span data-i18n="nav_graph">{s['nav_graph']}</span>
      </button>
      <button id="tab-entities" data-tab="entities" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-entities">
        <span data-i18n="nav_entities">{s['nav_entities']}</span>
      </button>
      <button id="tab-l3" data-tab="l3" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-l3">
        <span data-i18n="nav_l3">{s['nav_l3']}</span>
      </button>
      <button id="tab-brain" data-tab="brain" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-brain">
        <span data-i18n="nav_brain">{s['nav_brain']}</span>
      </button>
      <button id="tab-earning" data-tab="earning" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-earning">
        <span data-i18n="nav_earning">{s['nav_earning']}</span>
      </button>
      <button id="tab-team" data-tab="team" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-team">
        <span data-i18n="nav_team">{s['nav_team']}</span>
      </button>
      <button id="tab-backup" data-tab="backup" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-backup">
        <span data-i18n="nav_backup">{s['nav_backup']}</span>
      </button>
      <button id="tab-settings" data-tab="settings" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-settings">
        <span data-i18n="nav_settings">{s['nav_settings']}</span>
      </button>
      <button id="tab-quickstart" data-tab="quickstart" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-quickstart">
        <span data-i18n="nav_quickstart">{s['nav_quickstart']}</span>
      </button>
      <button id="tab-help" data-tab="help" class="nav-tab" role="tab" aria-selected="false" aria-controls="panel-help">
        <span data-i18n="nav_help">{s['nav_help']}</span>
      </button>
    </nav>
  </aside>

  <div class="workspace">
    <header class="topbar">
      <div id="topbar-stats" class="topbar-stats" aria-live="polite">PADAM · NOCTURNE</div>
      <div class="topbar-controls">
        <button id="btn-quick-add" class="btn-primary" data-i18n="btn_add_memory">{s['btn_add_memory']}</button>
        <button id="btn-refresh" data-i18n="btn_refresh">{s['btn_refresh']}</button>
        <div class="lang-group" role="group" aria-label="Language">
          <button id="lang-ru" class="lang-btn" aria-pressed="true">RU</button>
          <button id="lang-en" class="lang-btn" aria-pressed="false">EN</button>
          <button id="lang-es" class="lang-btn" aria-pressed="false">ES</button>
          <button id="lang-zh" class="lang-btn" aria-pressed="false">ZH</button>
        </div>
        <button id="theme-toggle">☀️ {s['theme_light']}</button>
      </div>
    </header>

    <main class="content-area">
      <div id="status-msg" role="status" aria-live="polite"></div>

      <!-- 1. ОБЗОР -->
      <section id="panel-overview" role="tabpanel" aria-labelledby="tab-overview">
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="ov_title">{s['ov_title']}</h2>
        </div>
        <div class="kpi-grid">
          <div class="kpi-card"><div id="kpi-active" class="kpi-num">0</div><div class="kpi-label" data-i18n="ov_active">{s['ov_active']}</div></div>
          <div class="kpi-card"><div id="kpi-review" class="kpi-num">0</div><div class="kpi-label" data-i18n="ov_review">{s['ov_review']}</div></div>
          <div class="kpi-card"><div id="kpi-superseded" class="kpi-num">0</div><div class="kpi-label" data-i18n="ov_superseded">{s['ov_superseded']}</div></div>
          <div class="kpi-card"><div id="kpi-revoked" class="kpi-num">0</div><div class="kpi-label" data-i18n="ov_revoked">{s['ov_revoked']}</div></div>
          <div class="kpi-card"><div id="kpi-episodes" class="kpi-num">0</div><div class="kpi-label" data-i18n="ov_episodes">{s['ov_episodes']}</div></div>
          <div class="kpi-card"><div id="kpi-conflicts" class="kpi-num">0</div><div class="kpi-label" data-i18n="ov_conflicts">{s['ov_conflicts']}</div></div>
        </div>

        <div class="two-col">
          <div class="box">
            <h3 class="box-title" data-i18n="ov_by_kind">{s['ov_by_kind']}</h3>
            <div id="ov-kinds-list"></div>
          </div>
          <div class="box">
            <h3 class="box-title" data-i18n="ov_attention">{s['ov_attention']}</h3>
            <div id="ov-attention-box" class="check-list"></div>
            <hr>
            <h3 class="box-title" data-i18n="ov_sleep_title">{s['ov_sleep_title']}</h3>
            <div id="ov-sleep-info"></div>
            <div class="rec-actions">
              <button id="ov-sleep-btn" class="btn-primary" data-i18n="ov_sleep_btn">{s['ov_sleep_btn']}</button>
            </div>
          </div>
        </div>

        <div class="box">
          <h3 class="box-title" data-i18n="ov_doctor_title">{s['ov_doctor_title']}</h3>
          <div id="ov-doctor-banner" class="traffic-banner traffic-green"></div>
          <div id="ov-doctor-checks" class="check-list"></div>
        </div>
      </section>

      <!-- 2. ЛЕНТА ПАМЯТИ -->
      <section id="panel-migrate" role="tabpanel" aria-labelledby="tab-migrate" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="mig_title">{s['mig_title']}</h2>
          <p class="panel-sub" data-i18n="mig_subtitle">{s['mig_subtitle']}</p>
        </div>
        <div class="box">
          <div class="toolbar">
            <label for="mig-source" data-i18n="mig_source_label">{s['mig_source_label']}</label>
            <select id="mig-source">
              <option value="auto" data-i18n="mig_auto">{s['mig_auto']}</option>
              <option value="chatgpt">ChatGPT</option><option value="claude">Claude</option>
              <option value="gemini">Gemini</option><option value="grok">Grok</option>
              <option value="deepseek">DeepSeek</option><option value="copilot">Microsoft Copilot</option>
              <option value="perplexity">Perplexity</option><option value="official_mcp">MCP Memory (memory.jsonl)</option>
            </select>
          </div>
          <p class="panel-sub"><strong data-i18n="mig_how">{s['mig_how']}</strong>: <span id="mig-steps">{s['mig_steps_auto']}</span>
            <a id="mig-export-link" href="#" target="_blank" rel="noopener noreferrer" hidden data-i18n="mig_open_export">{s['mig_open_export']}</a></p>
          <div class="toolbar">
            <label for="mig-path" data-i18n="mig_path_label">{s['mig_path_label']}</label>
            <input id="mig-path" type="text" placeholder="{s['mig_path_ph']}" data-i18n-placeholder="mig_path_ph" autocomplete="off">
          </div>
          <div class="toolbar">
            <label for="mig-file" data-i18n="mig_file_label">{s['mig_file_label']}</label>
            <input id="mig-file" type="file" accept=".zip,.json,.csv">
          </div>
          <div class="toolbar">
            <button id="mig-preview-btn" data-i18n="mig_preview_btn">{s['mig_preview_btn']}</button>
            <button id="mig-run-btn" class="btn-primary" data-i18n="mig_run_btn">{s['mig_run_btn']}</button>
            <button id="mig-undo-btn" hidden data-i18n="mig_undo_btn">{s['mig_undo_btn']}</button>
          </div>
          <div id="mig-result" class="panel-sub" aria-live="polite"></div>
        </div>
      </section>

      <section id="panel-feed" role="tabpanel" aria-labelledby="tab-feed" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="feed_title">{s['feed_title']}</h2>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="feed_new_title">{s['feed_new_title']}</h3>
          <div class="toolbar">
            <input id="feed-new-text" type="text" data-i18n-placeholder="feed_new_placeholder" data-i18n-aria="feed_new_placeholder" placeholder="{s['feed_new_placeholder']}" aria-label="{s['feed_new_placeholder']}">
            <select id="feed-new-kind" aria-label="Memory kind">
              <option value="fact">fact</option>
              <option value="preference">preference</option>
              <option value="identity">identity</option>
              <option value="decision">decision</option>
              <option value="correction">correction</option>
              <option value="state">state</option>
              <option value="event">event</option>
            </select>
            <button id="feed-new-save" class="btn-primary" data-i18n="feed_new_save">{s['feed_new_save']}</button>
          </div>
        </div>

        <div class="toolbar">
          <button id="feed-view-active" aria-pressed="true" data-i18n="feed_view_active">{s['feed_view_active']}</button>
          <button id="feed-view-history" aria-pressed="false" data-i18n="feed_view_history">{s['feed_view_history']}</button>
          <input id="feed-q" type="search" data-i18n-placeholder="feed_filter_placeholder" data-i18n-aria="feed_filter_placeholder" placeholder="{s['feed_filter_placeholder']}" aria-label="{s['feed_filter_placeholder']}">
          <input id="feed-agent" type="search" data-i18n-placeholder="feed_agent_placeholder" data-i18n-aria="feed_agent_placeholder" placeholder="{s['feed_agent_placeholder']}" aria-label="{s['feed_agent_placeholder']}">
        </div>
        <div id="feed-kinds" class="chips-row"></div>
        <div id="feed-list"></div>
        <button id="feed-more" data-i18n="show_more" hidden>{s['show_more']}</button>
      </section>

      <!-- 3. ПОИСК -->
      <section id="panel-search" role="tabpanel" aria-labelledby="tab-search" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="search_title">{s['search_title']}</h2>
        </div>
        <div class="toolbar">
          <input id="search-input" type="search" data-i18n-placeholder="search_placeholder" data-i18n-aria="search_placeholder" placeholder="{s['search_placeholder']}" aria-label="{s['search_placeholder']}">
          <select id="search-kind" aria-label="Search kind filter">
            <option value="" data-i18n="all_kinds">{s['all_kinds']}</option>
            <option value="preference">preference</option>
            <option value="identity">identity</option>
            <option value="decision">decision</option>
            <option value="correction">correction</option>
            <option value="fact">fact</option>
            <option value="state">state</option>
            <option value="event">event</option>
          </select>
          <button id="search-btn" class="btn-primary" data-i18n="search_btn">{s['search_btn']}</button>
        </div>
        <div id="search-results"></div>
      </section>

      <!-- 3б. СПРОСИ СВОЮ ПАМЯТЬ (Г10) -->
      <section id="panel-ask" role="tabpanel" aria-labelledby="tab-ask" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="ask_title">{s['ask_title']}</h2>
          <p class="panel-sub" data-i18n="ask_subtitle">{s['ask_subtitle']}</p>
        </div>
        <div class="rec-meta">
          <span id="ask-ollama-status" class="badge">ℹ️ {s['ask_ollama_off']}</span>
        </div>
        <div class="toolbar">
          <input id="ask-input" type="search" data-i18n-placeholder="ask_placeholder" data-i18n-aria="ask_placeholder" placeholder="{s['ask_placeholder']}" aria-label="{s['ask_placeholder']}">
          <button id="ask-btn" class="btn-primary" data-i18n="ask_btn">{s['ask_btn']}</button>
        </div>
        <div id="ask-answer-box" class="box" hidden></div>
        <div id="ask-results"></div>
      </section>

      <!-- 4. НА ПРОВЕРКУ -->
      <section id="panel-review" role="tabpanel" aria-labelledby="tab-review" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="review_title">{s['review_title']}</h2>
          <p class="panel-sub" data-i18n="review_subtitle">{s['review_subtitle']}</p>
        </div>
        <div id="review-list"></div>
      </section>

      <!-- 5. ПАМЯТЬ НА ДАТУ -->
      <section id="panel-asof" role="tabpanel" aria-labelledby="tab-asof" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="asof_title">{s['asof_title']}</h2>
          <p class="panel-sub" data-i18n="asof_subtitle">{s['asof_subtitle']}</p>
        </div>
        <div class="toolbar">
          <input id="asof-date" type="date" data-i18n-aria="asof_date_label" aria-label="{s['asof_date_label']}">
          <input id="asof-query" type="search" data-i18n-placeholder="asof_query_placeholder" data-i18n-aria="asof_query_placeholder" placeholder="{s['asof_query_placeholder']}" aria-label="{s['asof_query_placeholder']}">
          <button id="asof-btn" class="btn-primary" data-i18n="asof_btn">{s['asof_btn']}</button>
          <button id="asof-yesterday" data-i18n="asof_quick_yesterday">{s['asof_quick_yesterday']}</button>
          <button id="asof-week" data-i18n="asof_quick_week">{s['asof_quick_week']}</button>
          <button id="asof-month" data-i18n="asof_quick_month">{s['asof_quick_month']}</button>
          <button id="asof-graph-btn" data-i18n="asof_btn_graph">{s['asof_btn_graph']}</button>
        </div>
        <div id="asof-results"></div>
      </section>

      <!-- 6. ЗАБЫТЬ И КВИТАНЦИИ -->
      <section id="panel-forget" role="tabpanel" aria-labelledby="tab-forget" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="forget_title">{s['forget_title']}</h2>
          <p class="panel-sub" data-i18n="forget_subtitle">{s['forget_subtitle']}</p>
        </div>
        <div class="box">
          <div class="toolbar">
            <input id="forget-id-input" type="text" data-i18n-placeholder="forget_id_placeholder" data-i18n-aria="forget_id_label" placeholder="{s['forget_id_placeholder']}" aria-label="{s['forget_id_label']}">
            <button id="forget-preview-btn" data-i18n="forget_btn_preview">{s['forget_btn_preview']}</button>
          </div>
          <label class="rec-meta">
            <input id="forget-with-derived" type="checkbox" checked>
            <span data-i18n="forget_with_derived">{s['forget_with_derived']}</span>
          </label>
          <div id="forget-preview-box"></div>
          <div class="rec-actions">
            <button id="forget-step1-btn" class="btn-danger" data-i18n="forget_step1_btn">{s['forget_step1_btn']}</button>
          </div>
          <div id="forget-confirm-box" class="versions-box" hidden>
            <p class="msg-err" data-i18n="forget_step2_warn">{s['forget_step2_warn']}</p>
            <div class="rec-actions">
              <button id="forget-step2-btn" class="btn-danger" data-i18n="forget_step2_btn">{s['forget_step2_btn']}</button>
              <button id="forget-cancel-btn" data-i18n="forget_cancel">{s['forget_cancel']}</button>
            </div>
          </div>
        </div>
        <div id="forget-latest-receipt"></div>
        <h3 class="box-title" data-i18n="receipt_history_title">{s['receipt_history_title']}</h3>
        <div id="forget-receipts-list"></div>
      </section>

      <!-- 7. СВЯЗИ И ГРАФ -->
      <section id="panel-graph" role="tabpanel" aria-labelledby="tab-graph" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="graph_title">{s['graph_title']}</h2>
          <p class="panel-sub" data-i18n="graph_subtitle">{s['graph_subtitle']}</p>
        </div>
        <div class="toolbar">
          <input id="graph-id-input" type="text" data-i18n-placeholder="graph_filter_placeholder" data-i18n-aria="graph_filter_placeholder" placeholder="{s['graph_filter_placeholder']}" aria-label="{s['graph_filter_placeholder']}">
          <label class="rec-meta"><span data-i18n="graph_asof_label">{s['graph_asof_label']}</span> <input id="graph-asof-input" type="date" data-i18n-aria="graph_asof_label" aria-label="{s['graph_asof_label']}"></label>
          <button id="graph-now-btn" data-i18n="graph_btn_now">{s['graph_btn_now']}</button>
          <button id="graph-focus-btn" class="btn-primary" data-i18n="graph_btn_focus">{s['graph_btn_focus']}</button>
          <button id="graph-reset-btn" data-i18n="graph_btn_reset">{s['graph_btn_reset']}</button>
        </div>
        <div class="graph-wrap">
          <canvas id="graph-canvas" width="900" height="420" aria-label="Memory lineage graph"></canvas>
          <div class="legend-row">
            <span>🔵 <span data-i18n="graph_legend_derived">{s['graph_legend_derived']}</span></span>
            <span>🟢 <span data-i18n="graph_legend_cause">{s['graph_legend_cause']}</span></span>
            <span>🟡 <span data-i18n="graph_legend_correction">{s['graph_legend_correction']}</span></span>
            <span>🟠 <span data-i18n="graph_legend_contradiction">{s['graph_legend_contradiction']}</span></span>
            <span>🟣 <span data-i18n="graph_legend_version">{s['graph_legend_version']}</span></span>
            <span>🔴 <span data-i18n="graph_legend_conflict">{s['graph_legend_conflict']}</span></span>
          </div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="graph_selected">{s['graph_selected']}</h3>
          <div id="graph-selected-box"></div>
        </div>
      </section>

      <!-- 7б. СУЩНОСТИ (Г11) -->
      <section id="panel-entities" role="tabpanel" aria-labelledby="tab-entities" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="entities_title">{s['entities_title']}</h2>
          <p class="panel-sub" data-i18n="entities_subtitle">{s['entities_subtitle']}</p>
        </div>
        <div class="toolbar">
          <input id="entities-filter" type="search" data-i18n-placeholder="entities_filter_placeholder" data-i18n-aria="entities_filter_placeholder" placeholder="{s['entities_filter_placeholder']}" aria-label="{s['entities_filter_placeholder']}">
        </div>
        <div id="entities-grid" class="entity-grid"></div>
        <div id="entities-records"></div>
      </section>

      <!-- 8. ВЕЧНЫЙ СЛОЙ L3 -->
      <section id="panel-l3" role="tabpanel" aria-labelledby="tab-l3" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="l3_title">{s['l3_title']}</h2>
          <p class="panel-sub" data-i18n="l3_subtitle">{s['l3_subtitle']}</p>
        </div>
        <div class="kpi-grid">
          <div class="kpi-card"><div id="l3-unanchored-num" class="kpi-num">0</div><div class="kpi-label" data-i18n="l3_unanchored">{s['l3_unanchored']}</div></div>
          <div class="kpi-card"><div id="l3-forgets-num" class="kpi-num">0</div><div class="kpi-label" data-i18n="l3_pending_forgets">{s['l3_pending_forgets']}</div></div>
          <div class="kpi-card"><div id="l3-keys-status" class="kpi-num">—</div><div class="kpi-label" data-i18n="l3_keys_state">{s['l3_keys_state']}</div></div>
        </div>
        <div class="toolbar">
          <button id="l3-verify-latest-btn" class="btn-primary" data-i18n="l3_btn_verify_latest">{s['l3_btn_verify_latest']}</button>
        </div>
        <h3 class="box-title" data-i18n="l3_anchors_list">{s['l3_anchors_list']}</h3>
        <div id="l3-anchors-list"></div>
      </section>

      <!-- 9a. КОМАНДА И РОЛИ -->
      <section id="panel-team" role="tabpanel" aria-labelledby="tab-team" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="team_title">{s['team_title']}</h2>
          <p class="panel-sub" data-i18n="team_subtitle">{s['team_subtitle']}</p>
        </div>
        <div class="box">
          <p class="setting-desc" data-i18n="team_protected_note">{s['team_protected_note']}</p>
          <div class="toolbar">
            <input id="team-create-input" type="text" placeholder="{s['team_create_ph']}" aria-label="{s['team_create_ph']}" data-i18n-ph="team_create_ph" data-i18n-aria="team_create_ph">
            <button id="team-create-btn" class="btn-primary" data-i18n="team_create_btn">{s['team_create_btn']}</button>
          </div>
          <div id="team-workspaces-list"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="team_members_title">{s['team_members_title']}</h3>
          <div class="toolbar">
            <select id="team-ws-select" aria-label="Workspace"></select>
            <input id="team-subj-input" type="text" placeholder="{s['team_subj_ph']}" aria-label="{s['team_subj_ph']}" data-i18n-ph="team_subj_ph" data-i18n-aria="team_subj_ph">
            <select id="team-role-select" aria-label="Role">
              <option value="maintainer" data-i18n="team_role_maintainer">{s['team_role_maintainer']}</option>
              <option value="contributor" data-i18n="team_role_contributor">{s['team_role_contributor']}</option>
              <option value="auditor" data-i18n="team_role_auditor">{s['team_role_auditor']}</option>
            </select>
            <button id="team-add-btn" class="btn-primary" data-i18n="team_add_btn">{s['team_add_btn']}</button>
          </div>
          <div id="team-token-box" class="code-block" hidden>
            <span data-i18n="team_token_once">{s['team_token_once']}</span>
            <code id="team-issued-token"></code>
          </div>
          <div id="team-members-list"></div>
        </div>
      </section>

      <!-- 8b. РЕЗЕРВНАЯ КОПИЯ -->
      <section id="panel-backup" role="tabpanel" aria-labelledby="tab-backup" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="bak_title">{s['bak_title']}</h2>
          <p class="panel-sub" data-i18n="bak_subtitle">{s['bak_subtitle']}</p>
        </div>
        <div class="box">
          <div class="toolbar">
            <label for="backup-passphrase" data-i18n="bak_pass_label">{s['bak_pass_label']}</label>
            <input id="backup-passphrase" type="password" placeholder="{s['bak_pass_ph']}" data-i18n-placeholder="bak_pass_ph" autocomplete="off">
            <button id="backup-create-btn" class="btn-primary" data-i18n="bak_create_btn">{s['bak_create_btn']}</button>
          </div>
          <div class="toolbar">
            <label for="backup-file-input" data-i18n="bak_file_label">{s['bak_file_label']}</label>
            <input id="backup-file-input" type="file" accept=".padambak">
            <button id="backup-restore-btn" data-i18n="bak_restore_btn">{s['bak_restore_btn']}</button>
          </div>
          <div id="backup-result" class="panel-sub" aria-live="polite"></div>
        </div>
      </section>

      <!-- 2а. AIFA ИЗ КАБИНЕТА -->
      <section id="panel-aifa" role="tabpanel" aria-labelledby="tab-aifa" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="aifa_title">{s['aifa_title']}</h2>
          <p class="panel-sub" data-i18n="aifa_subtitle">{s['aifa_subtitle']}</p>
        </div>
        <div id="aifa-auth-box" class="box">
          <p class="setting-desc" data-i18n="aifa_need_login">{s['aifa_need_login']}</p>
          <div class="toolbar">
            <input id="aifa-email-input" type="email" placeholder="{s['aifa_email_ph']}" aria-label="{s['aifa_email_ph']}" data-i18n-placeholder="aifa_email_ph" data-i18n-aria="aifa_email_ph">
            <button id="aifa-send-code-btn" class="btn-primary" data-i18n="aifa_send_code">{s['aifa_send_code']}</button>
          </div>
          <div id="aifa-code-row" class="toolbar" hidden>
            <input id="aifa-code-input" type="text" inputmode="numeric" placeholder="{s['aifa_code_ph']}" aria-label="{s['aifa_code_ph']}" data-i18n-placeholder="aifa_code_ph" data-i18n-aria="aifa_code_ph">
            <button id="aifa-verify-code-btn" class="btn-primary" data-i18n="aifa_verify_btn">{s['aifa_verify_btn']}</button>
          </div>
        </div>
        <div id="aifa-chat-box" hidden>
          <div class="box">
            <div class="toolbar">
              <strong id="aifa-user-label"></strong>
              <button id="aifa-logout-btn" data-i18n="aifa_logout_btn">{s['aifa_logout_btn']}</button>
            </div>
            <label class="toolbar">
              <input id="aifa-use-local" type="checkbox">
              <span data-i18n="aifa_use_local_label">{s['aifa_use_local_label']}</span>
            </label>
            <p class="panel-sub" data-i18n="aifa_use_local_hint">{s['aifa_use_local_hint']}</p>
          </div>
          <div id="aifa-chat-list"></div>
          <div id="aifa-local-sent-box" class="box" hidden>
            <h3 class="box-title" data-i18n="aifa_local_sent_title">{s['aifa_local_sent_title']}</h3>
            <ul id="aifa-local-sent-list"></ul>
          </div>
          <div class="box">
            <div class="toolbar">
              <input id="aifa-msg-input" type="text" placeholder="{s['aifa_msg_ph']}" aria-label="{s['aifa_msg_ph']}" data-i18n-placeholder="aifa_msg_ph" data-i18n-aria="aifa_msg_ph">
              <button id="aifa-send-msg-btn" class="btn-primary" data-i18n="aifa_send_btn">{s['aifa_send_btn']}</button>
            </div>
          </div>
        </div>
      </section>

      <!-- 2б. ТАРИФ И ARWEAVE -->
      <section id="panel-plans" role="tabpanel" aria-labelledby="tab-plans" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="plans_title">{s['plans_title']}</h2>
          <p class="panel-sub" data-i18n="plans_subtitle">{s['plans_subtitle']}</p>
        </div>
        <div class="box">
          <p><strong data-i18n="plans_current_tier">{s['plans_current_tier']}</strong> <span id="plans-current-val" data-i18n="plans_free_mode">{s['plans_free_mode']}</span></p>
          <p><strong data-i18n="plans_quota_label">{s['plans_quota_label']}</strong> <span id="plans-quota-val" data-i18n="plans_arweave_off">{s['plans_arweave_off']}</span></p>
          <div class="toolbar">
            <button id="plans-upgrade-btn" class="btn-primary" data-i18n="plans_btn_upgrade">{s['plans_btn_upgrade']}</button>
          </div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="plans_free_forever_title">{s['plans_free_forever_title']}</h3>
          <ul class="check-list">
            <li data-i18n="plans_free_item_1">{s['plans_free_item_1']}</li>
            <li data-i18n="plans_free_item_2">{s['plans_free_item_2']}</li>
            <li data-i18n="plans_free_item_3">{s['plans_free_item_3']}</li>
            <li data-i18n="plans_free_item_4">{s['plans_free_item_4']}</li>
          </ul>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="plans_paid_title">{s['plans_paid_title']}</h3>
          <ul class="check-list">
            <li><strong>Spark</strong> — <span data-i18n="plans_spark_desc">{s['plans_spark_desc']}</span></li>
            <li><strong>Family Archive</strong> — <span data-i18n="plans_family_desc">{s['plans_family_desc']}</span></li>
            <li><strong>Digital DNA</strong> — <span data-i18n="plans_dna_desc">{s['plans_dna_desc']}</span></li>
          </ul>
        </div>
      </section>

      <!-- 9. НАСТРОЙКИ -->
      <section id="panel-settings" role="tabpanel" aria-labelledby="tab-settings" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="set_title">{s['set_title']}</h2>
          <p class="panel-sub" data-i18n="set_subtitle">{s['set_subtitle']}</p>
        </div>
        <div class="box" id="lm-box">
          <h3 class="box-title" id="lm-box-title" data-i18n="lm_title">{s['lm_title']}</h3>
          <p class="panel-sub" data-i18n="lm_desc">{s['lm_desc']}</p>
          <div id="lm-status" aria-live="polite"></div>
          <div class="rec-actions" role="group" aria-labelledby="lm-box-title">
            <button id="lm-power-eco" data-power="eco" aria-pressed="false" data-i18n="lm_power_eco">{s['lm_power_eco']}</button>
            <button id="lm-power-half" data-power="half" aria-pressed="true" data-i18n="lm_power_half">{s['lm_power_half']}</button>
            <button id="lm-power-full" data-power="full" aria-pressed="false" data-i18n="lm_power_full">{s['lm_power_full']}</button>
          </div>
          <div class="toolbar">
            <label for="lm-model" data-i18n="lm_model_label">{s['lm_model_label']}</label>
            <select id="lm-model"></select>
          </div>
          <div class="rec-actions">
            <button id="lm-save" class="btn-primary" data-i18n="lm_save">{s['lm_save']}</button>
          </div>
          <p id="lm-out" class="panel-sub" aria-live="polite"></p>
        </div>
        <div class="box">
          <div id="settings-safe-list"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="set_readonly_title">{s['set_readonly_title']}</h3>
          <div id="settings-readonly-list"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="conn_box_title">{s['conn_box_title']}</h3>
          <p class="panel-sub" data-i18n="conn_box_desc">{s['conn_box_desc']}</p>
          <div id="settings-connectors-list"></div>
        </div>
        <div class="box">
          <div class="box-title">
            <span data-i18n="audit_box_title">{s['audit_box_title']}</span>
            <button id="audit-export-btn" data-i18n="audit_export_json">{s['audit_export_json']}</button>
          </div>
          <p class="panel-sub" data-i18n="audit_box_desc">{s['audit_box_desc']}</p>
          <div id="settings-audit-list" class="check-list"></div>
        </div>
      </section>

      <!-- АТАКИ (16.11.2026) -->
      <section id="panel-attacks" role="tabpanel" aria-labelledby="tab-attacks" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="att_title">{s['att_title']}</h2>
          <p class="panel-sub" data-i18n="att_sub">{s['att_sub']}</p>
        </div>
        <div class="att-grid">
          <div class="box"><div id="att-total-val" class="box-title">0</div><p class="panel-sub" data-i18n="att_total">{s['att_total']}</p></div>
          <div class="box"><div id="att-window-val" class="box-title">0</div><p class="panel-sub" data-i18n="att_window">{s['att_window']}</p></div>
          <div class="box"><div id="att-pending-val" class="box-title">0</div><p class="panel-sub" data-i18n="att_pending">{s['att_pending']}</p></div>
          <div class="box"><div id="att-secrets-val" class="box-title">0</div><p class="panel-sub" data-i18n="att_secrets">{s['att_secrets']}</p></div>
        </div>
        <p id="att-none" class="panel-sub" data-i18n="att_none">{s['att_none']}</p>
        <div class="box"><h3 class="box-title" data-i18n="att_by_kind">{s['att_by_kind']}</h3><div id="att-by-kind"></div></div>
        <div class="box"><h3 class="box-title" data-i18n="att_by_source">{s['att_by_source']}</h3><div id="att-by-source"></div></div>
        <div class="box"><h3 class="box-title" data-i18n="att_by_day">{s['att_by_day']}</h3><div id="att-by-day"></div></div>
        <div class="box"><h3 class="box-title" data-i18n="att_secrets_kind">{s['att_secrets_kind']}</h3><div id="att-secrets-kind"></div></div>
        <div class="box"><h3 class="box-title" data-i18n="att_recent">{s['att_recent']}</h3><div id="att-recent"></div></div>
        <div class="box">
          <h3 class="box-title" data-i18n="att_aifasec_title">{s['att_aifasec_title']}</h3>
          <p id="att-aifasec-summary" class="panel-sub">—</p>
          <div class="att-actions">
            <button id="att-aifasec-run" class="btn-primary" type="button" data-i18n="att_aifasec_btn">{s['att_aifasec_btn']}</button>
            <button id="att-aifasec-dl-json" class="btn" type="button">JSON</button>
            <button id="att-aifasec-dl-sarif" class="btn" type="button">SARIF (GitHub)</button>
            <button id="att-aifasec-dl-html" class="btn" type="button">HTML Report</button>
            <button id="att-qa-load" class="btn" type="button">QA Bench ($0)</button>
            <button id="att-fuzz-run" class="btn" type="button">Live Fuzz &amp; Compare</button>
            <button id="att-sec-verify" class="btn" type="button">Verify Ed25519 Seal</button>
          </div>
          <div id="att-aifasec-standards" class="panel-sub"></div>
          <div id="att-aifasec-domains"></div>
          <div id="att-qa-summary" class="att-qa-box"></div>
        </div>
      </section>

      <!-- СПРАВКА (16.11.2026) -->
      <section id="panel-help" role="tabpanel" aria-labelledby="tab-help" hidden>
        <div class="panel-header">
          <h2 id="help-title" class="panel-title" data-i18n="nav_help">{s['nav_help']}</h2>
          <p id="help-sub" class="panel-sub"></p>
        </div>
        <div id="help-body"></div>
      </section>

      <!-- 10. ПЕРВЫЙ ЗАПУСК -->
      <section id="panel-quickstart" role="tabpanel" aria-labelledby="tab-quickstart" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="qs_title">{s['qs_title']}</h2>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="qs_step1_title">{s['qs_step1_title']}</h3>
          <p data-i18n="qs_step1_body">{s['qs_step1_body']}</p>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="qs_step2_title">{s['qs_step2_title']}</h3>
          <p class="setting-name" data-i18n="qs_step2_claude">{s['qs_step2_claude']}</p>
          <div class="code-block">
            <code id="cmd-claude">claude mcp add padam -- uvx padam-nocturne</code>
            <button data-copy-target="cmd-claude" data-i18n="qs_btn_copy">{s['qs_btn_copy']}</button>
          </div>
          <p class="setting-name" data-i18n="qs_step2_cursor">{s['qs_step2_cursor']}</p>
          <div class="code-block">
            <code id="cmd-cursor">{{"mcpServers": {{"padam-nocturne": {{"command": "uvx", "args": ["padam-nocturne"]}}}}}}</code>
            <button data-copy-target="cmd-cursor" data-i18n="qs_btn_copy">{s['qs_btn_copy']}</button>
          </div>
          <p class="setting-name" data-i18n="qs_step2_python">{s['qs_step2_python']}</p>
          <div class="code-block">
            <code id="cmd-studio">pip install padam-nocturne &amp;&amp; padam studio</code>
            <button data-copy-target="cmd-studio" data-i18n="qs_btn_copy">{s['qs_btn_copy']}</button>
          </div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="qs_step3_title">{s['qs_step3_title']}</h3>
          <p data-i18n="qs_step3_body">{s['qs_step3_body']}</p>
          <div class="code-block">
            <code id="cmd-protect">python -m padam protect-keys</code>
            <button data-copy-target="cmd-protect" data-i18n="qs_btn_copy">{s['qs_btn_copy']}</button>
          </div>
          <div class="rec-actions">
            <button id="qs-enable-strict-btn" class="btn-primary" data-i18n="qs_btn_enable_strict">{s['qs_btn_enable_strict']}</button>
            <button id="qs-go-overview-btn" data-i18n="qs_btn_go_overview">{s['qs_btn_go_overview']}</button>
          </div>
        </div>
      </section>

      <!-- СУВЕРЕННЫЙ МОЗГ И ФЕНИКС -->
      <section id="panel-brain" role="tabpanel" aria-labelledby="tab-brain" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="brain_title">{s['brain_title']}</h2>
          <p class="panel-sub" data-i18n="brain_sub">{s['brain_sub']}</p>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="brain_traffic_title">{s['brain_traffic_title']}</h3>
          <div id="brain-contours"></div>
          <div class="rec-actions">
            <button id="brain-refresh-btn" data-i18n="btn_refresh">{s['btn_refresh']}</button>
            <button id="brain-mode-toggle-btn" data-i18n="brain_mode_toggle">{s['brain_mode_toggle']}</button>
            <button id="brain-warmup-btn" data-i18n="brain_warmup_btn">{s['brain_warmup_btn']}</button>
          </div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="brain_cost_title">{s['brain_cost_title']}</h3>
          <div id="brain-metrics"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="brain_distill_title">{s['brain_distill_title']}</h3>
          <div class="rec-actions">
            <button id="brain-distill-btn" class="btn-primary" data-i18n="brain_distill_btn">{s['brain_distill_btn']}</button>
          </div>
          <p id="brain-distill-out" class="panel-sub"></p>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="brain_phoenix_title">{s['brain_phoenix_title']}</h3>
          <p class="panel-sub" data-i18n="brain_locked_note">{s['brain_locked_note']}</p>
          <div class="toolbar">
            <input id="brain-phoenix-path" type="text" data-i18n-placeholder="brain_phoenix_ph" placeholder="{s['brain_phoenix_ph']}">
          </div>
          <div class="rec-actions">
            <button id="brain-phoenix-local-btn" class="btn-primary" data-i18n="brain_phoenix_local_btn">{s['brain_phoenix_local_btn']}</button>
            <button id="brain-phoenix-arweave-btn" data-i18n="brain_phoenix_arweave_btn">{s['brain_phoenix_arweave_btn']}</button>
          </div>
          <p id="brain-phoenix-out" class="panel-sub"></p>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="ark_health_title">{s['ark_health_title']}</h3>
          <div id="ark-health-box"></div>
          <div class="rec-actions">
            <button id="ark-audit-btn" data-i18n="ark_audit_btn">{s['ark_audit_btn']}</button>
            <button id="ark-drill-btn" class="btn-primary" data-i18n="ark_drill_btn">{s['ark_drill_btn']}</button>
            <button id="ark-shamir-btn" data-i18n="ark_shamir_btn">{s['ark_shamir_btn']}</button>
            <p class="panel-sub" data-i18n="ark_shamir_warn">{s['ark_shamir_warn']}</p>
          </div>
          <p id="ark-drill-out" class="panel-sub"></p>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="ark_council_title">{s['ark_council_title']}</h3>
          <div class="toolbar">
            <input id="ark-council-input" type="text" data-i18n-placeholder="ark_council_ph" placeholder="{s['ark_council_ph']}">
          </div>
          <div class="rec-actions">
            <button id="ark-council-btn" class="btn-primary" data-i18n="ark_council_btn">{s['ark_council_btn']}</button>
          </div>
          <div id="ark-council-out"></div>
        </div>
        <div class="box" id="ff-box">
          <h3 class="box-title" data-i18n="ff_title">{s['ff_title']}</h3>
          <p class="panel-sub" data-i18n="ff_desc">{s['ff_desc']}</p>
          <div class="rec-actions" role="group" aria-label="{s['ff_title']}">
            <button id="ff-ch-work" data-ch="work" aria-pressed="true" class="btn-primary" data-i18n="ff_work">{s['ff_work']}</button>
            <button id="ff-ch-quarantine" data-ch="quarantine" aria-pressed="false" data-i18n="ff_quarantine">{s['ff_quarantine']}</button>
            <button id="ff-ch-office" data-ch="office" aria-pressed="false" data-i18n="ff_office">{s['ff_office']}</button>
            <button id="ff-ch-smoke" data-ch="smoke" aria-pressed="false" data-i18n="ff_smoke">{s['ff_smoke']}</button>
          </div>
          <div id="ff-list" aria-live="polite"></div>
          <div class="toolbar">
            <input id="ff-input" type="text" maxlength="2000" aria-label="{s['ff_ph']}" data-i18n-placeholder="ff_ph" placeholder="{s['ff_ph']}">
            <button id="ff-send" data-i18n="ff_send">{s['ff_send']}</button>
          </div>
          <h4 class="box-title" data-i18n="ff_reflex_title">{s['ff_reflex_title']}</h4>
          <div id="ff-reflexes"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="ark_branch_title">{s['ark_branch_title']}</h3>
          <div class="toolbar">
            <input id="ark-branch-input" type="text" data-i18n-placeholder="ark_branch_ph" placeholder="{s['ark_branch_ph']}">
          </div>
          <div class="rec-actions">
            <button id="ark-branch-create-btn" class="btn-primary" data-i18n="ark_branch_create_btn">{s['ark_branch_create_btn']}</button>
            <button id="ark-branch-list-btn" data-i18n="ark_branch_list_btn">{s['ark_branch_list_btn']}</button>
          </div>
          <div id="ark-branch-out"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="ark_proof_title">{s['ark_proof_title']}</h3>
          <div class="toolbar">
            <input id="ark-proof-input" type="text" data-i18n-placeholder="ark_proof_ph" placeholder="{s['ark_proof_ph']}">
          </div>
          <div class="rec-actions">
            <button id="ark-proof-btn" data-i18n="ark_proof_btn">{s['ark_proof_btn']}</button>
          </div>
          <div id="ark-proof-out"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="ark_mesh_title">{s['ark_mesh_title']}</h3>
          <div class="rec-actions">
            <button id="ark-mesh-btn" data-i18n="ark_mesh_btn">{s['ark_mesh_btn']}</button>
            <button id="ark-guardian-btn" class="btn-primary" data-i18n="ark_guardian_btn">{s['ark_guardian_btn']}</button>
          </div>
          <div id="ark-mesh-out"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="ark_ready_title">{s['ark_ready_title']}</h3>
          <div class="rec-actions">
            <button id="ark-ready-btn" class="btn-primary" data-i18n="ark_ready_btn">{s['ark_ready_btn']}</button>
          </div>
          <div id="ark-ready-out"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="ark_handover_title">{s['ark_handover_title']}</h3>
          <div class="toolbar">
            <input id="ark-handover-input" type="text" data-i18n-placeholder="ark_handover_ph" placeholder="{s['ark_handover_ph']}">
          </div>
          <div class="rec-actions">
            <button id="ark-handover-btn" class="btn-primary" data-i18n="ark_handover_btn">{s['ark_handover_btn']}</button>
          </div>
          <div id="ark-handover-out"></div>
        </div>
        <div class="box">
          <h3 class="box-title" data-i18n="ark_portable_title">{s['ark_portable_title']}</h3>
          <div class="toolbar">
            <input id="ark-portable-input" type="text" data-i18n-placeholder="ark_portable_ph" placeholder="{s['ark_portable_ph']}">
          </div>
          <div class="rec-actions">
            <button id="ark-portable-btn" class="btn-primary" data-i18n="ark_portable_btn">{s['ark_portable_btn']}</button>
            <p class="panel-sub" data-i18n="ark_portable_warn">{s['ark_portable_warn']}</p>
          </div>
          <div id="ark-portable-out"></div>
          <h3 class="box-title" data-i18n="ark_budget_title">{s['ark_budget_title']}</h3>
          <div class="rec-actions">
            <button id="ark-budget-btn" class="btn-primary" data-i18n="ark_budget_btn">{s['ark_budget_btn']}</button>
          </div>
          <div id="ark-budget-out"></div>
        </div>
      </section>
      <section id="panel-earning" role="tabpanel" aria-labelledby="tab-earning" hidden>
        <div class="panel-head">
          <h2 class="panel-title" data-i18n="earn_title">{s['earn_title']}</h2>
          <p class="panel-sub" data-i18n="earn_sub">{s['earn_sub']}</p>
        </div>
        <div class="earn-grid">
          <div class="box earn-box-wide">
            <h3 class="box-title" data-i18n="earn_ex_title">{s['earn_ex_title']}</h3>
            <div class="toolbar">
              <select id="earn-platform" aria-label="Exchange platform">
                <option value="fiverr_desk">fiverr_desk</option>
                <option value="upwork_api">upwork_api</option>
                <option value="freelancer_api">freelancer_api</option>
                <option value="kwork_desk">kwork_desk</option>
                <option value="custom_webhook">custom_webhook</option>
              </select>
              <select id="earn-mode" aria-label="Connection mode">
                <option value="desk">desk</option>
                <option value="oauth_api">oauth_api</option>
                <option value="webhook">webhook</option>
              </select>
            </div>
            <div class="toolbar">
              <input id="earn-label" type="text" data-i18n-placeholder="earn_ex_label_ph" placeholder="{s['earn_ex_label_ph']}">
              <input id="earn-agent" type="text" value="aifa" data-i18n-placeholder="earn_ex_agent_ph" placeholder="{s['earn_ex_agent_ph']}">
            </div>
            <div class="toolbar">
              <input id="earn-api-url" type="text" data-i18n-placeholder="earn_api_url_ph" placeholder="{s['earn_api_url_ph']}">
            </div>
            <div class="toolbar">
              <input id="earn-token" type="password" data-i18n-placeholder="earn_ex_token_ph" placeholder="{s['earn_ex_token_ph']}">
              <button id="earn-connect-btn" class="btn-primary" data-i18n="earn_ex_connect_btn">{s['earn_ex_connect_btn']}</button>
            </div>
            <div class="rec-actions">
              <button id="earn-auto-start-btn" class="btn-ok" data-i18n="earn_auto_start_btn">{s['earn_auto_start_btn']}</button>
              <button id="earn-auto-stop-btn" class="btn-danger" data-i18n="earn_auto_stop_btn">{s['earn_auto_stop_btn']}</button>
            </div>
            <div id="earn-accounts-list" class="earn-stack"></div>
          </div>

          <div class="box">
            <h3 class="box-title" data-i18n="earn_jobs_title">{s['earn_jobs_title']}</h3>
            <div class="toolbar">
              <input id="earn-job-title" type="text" data-i18n-placeholder="earn_job_title_ph" placeholder="{s['earn_job_title_ph']}">
            </div>
            <div class="toolbar">
              <input id="earn-job-brief" type="text" data-i18n-placeholder="earn_job_brief_ph" placeholder="{s['earn_job_brief_ph']}">
            </div>
            <div class="earn-num-grid">
              <div class="earn-field">
                <label for="earn-job-budget" data-i18n="earn_job_budget_lbl">{s['earn_job_budget_lbl']}</label>
                <input id="earn-job-budget" class="earn-num-input" type="number" value="50" min="1" step="1" data-i18n-placeholder="earn_job_budget_ph" placeholder="{s['earn_job_budget_ph']}">
              </div>
              <div class="earn-field">
                <label for="earn-job-hours" data-i18n="earn_job_hours_lbl">{s['earn_job_hours_lbl']}</label>
                <input id="earn-job-hours" class="earn-num-input" type="number" value="4" min="0.5" step="0.5" data-i18n-placeholder="earn_job_hours_ph" placeholder="{s['earn_job_hours_ph']}">
              </div>
              <div class="earn-field">
                <label for="earn-job-rate" data-i18n="earn_job_rate_lbl">{s['earn_job_rate_lbl']}</label>
                <input id="earn-job-rate" class="earn-num-input" type="number" value="25" min="1" step="1" data-i18n-placeholder="earn_job_rate_ph" placeholder="{s['earn_job_rate_ph']}">
              </div>
              <div class="earn-field">
                <label for="earn-job-tokens" data-i18n="earn_job_tokens_lbl">{s['earn_job_tokens_lbl']}</label>
                <input id="earn-job-tokens" class="earn-num-input" type="number" value="25000" min="500" step="500" data-i18n-placeholder="earn_job_tokens_ph" placeholder="{s['earn_job_tokens_ph']}">
              </div>
            </div>
            <div class="earn-field">
              <label for="earn-job-client" data-i18n="earn_job_client_lbl">{s['earn_job_client_lbl']}</label>
              <input id="earn-job-client" type="text" data-i18n-placeholder="earn_job_client_ph" placeholder="{s['earn_job_client_ph']}">
            </div>
            <div class="rec-actions">
              <button id="earn-eval-btn" class="btn-primary" data-i18n="earn_job_eval_btn">{s['earn_job_eval_btn']}</button>
            </div>
            <div id="earn-orders-list" class="earn-stack"></div>
          </div>

          <div class="box">
            <h3 class="box-title" data-i18n="earn_budget_title">{s['earn_budget_title']}</h3>
            <div class="toolbar">
              <input id="earn-plan-prov" type="text" value="primary" data-i18n-placeholder="earn_plan_prov_ph" placeholder="{s['earn_plan_prov_ph']}">
              <input id="earn-plan-tier" type="text" value="api_payg" data-i18n-placeholder="earn_plan_tier_ph" placeholder="{s['earn_plan_tier_ph']}">
              <input id="earn-plan-usd" class="earn-num-input" type="number" value="10" min="0" step="1" aria-label="USD balance">
            </div>
            <div class="toolbar">
              <input id="earn-plan-daily" class="earn-num-input" type="number" value="100000" min="1000" step="1000" aria-label="Daily limit">
              <input id="earn-plan-weekly" class="earn-num-input" type="number" value="500000" min="1000" step="5000" aria-label="Weekly limit">
              <input id="earn-plan-monthly" class="earn-num-input" type="number" value="2000000" min="1000" step="10000" aria-label="Monthly limit">
            </div>
            <div class="rec-actions">
              <button id="earn-plan-save-btn" class="btn-primary" data-i18n="earn_plan_save_btn">{s['earn_plan_save_btn']}</button>
              <button id="earn-tick-btn" data-i18n="earn_tick_btn">{s['earn_tick_btn']}</button>
              <button id="earn-propose-btn" data-i18n="earn_propose_btn">{s['earn_propose_btn']}</button>
              <button id="earn-rec-spend-btn" data-i18n="earn_rec_spend_btn">{s['earn_rec_spend_btn']}</button>
              <button id="earn-propose-sub-btn" class="btn-ok" data-i18n="earn_propose_sub_btn">{s['earn_propose_sub_btn']}</button>
            </div>
            <div id="earn-spend-rec-out" class="earn-stack"></div>
            <div id="earn-budget-summary" class="earn-stack"></div>
            <div id="earn-proposals-list" class="earn-stack"></div>
          </div>

          <div class="box">
            <h3 class="box-title" data-i18n="earn_swarm_title">{s['earn_swarm_title']}</h3>
            <div class="toolbar">
              <input id="earn-sib-id" type="text" data-i18n-placeholder="earn_sib_id_ph" placeholder="{s['earn_sib_id_ph']}">
              <input id="earn-sib-role" type="text" data-i18n-placeholder="earn_sib_role_ph" placeholder="{s['earn_sib_role_ph']}">
              <button id="earn-sib-reg-btn" class="btn-primary" data-i18n="earn_sib_reg_btn">{s['earn_sib_reg_btn']}</button>
            </div>
            <p class="earn-meta" data-i18n="earn_share_label">{s['earn_share_label']}</p>
            <div class="toolbar">
              <input id="earn-share-pct" class="earn-num-input" type="number" value="15" min="1" max="100" step="1" aria-label="Agent share percentage 1-100">
              <select id="earn-currency" aria-label="Settlement currency">
                <option value="USDT_TRC20">USDT_TRC20</option>
                <option value="GALATIN">GALATIN</option>
              </select>
              <button id="earn-prefs-save-btn" class="btn-primary" data-i18n="earn_prefs_save_btn">{s['earn_prefs_save_btn']}</button>
            </div>
            <div id="earn-swarm-list" class="earn-stack"></div>
            <div id="earn-monetization-summary" class="earn-stack"></div>
            <div id="earn-suggestions-list" class="earn-stack"></div>
          </div>

          <div class="box">
            <h3 class="box-title" data-i18n="earn_ollama_title">{s['earn_ollama_title']}</h3>
            <div class="toolbar">
              <input id="earn-ollama-url" type="text" value="http://127.0.0.1:11434" data-i18n-placeholder="earn_ollama_url_ph" placeholder="{s['earn_ollama_url_ph']}">
              <input id="earn-ollama-model" type="text" data-i18n-placeholder="earn_ollama_model_ph" placeholder="{s['earn_ollama_model_ph']}">
            </div>
            <div class="rec-actions">
              <button id="earn-ollama-btn" class="btn-primary" data-i18n="earn_ollama_btn">{s['earn_ollama_btn']}</button>
              <button id="earn-dev-btn" data-i18n="earn_dev_btn">{s['earn_dev_btn']}</button>
              <button id="earn-hw-rec-btn" data-i18n="earn_hw_rec_btn">{s['earn_hw_rec_btn']}</button>
            </div>
            <div id="earn-ollama-out" class="earn-stack"></div>
          </div>

          <div class="box">
            <h3 class="box-title" data-i18n="earn_beacon_title">{s['earn_beacon_title']}</h3>
            <div class="rec-actions">
              <button id="earn-lora-evo-btn" class="btn-primary" data-i18n="earn_lora_btn">{s['earn_lora_btn']}</button>
              <button id="earn-beacon-btn" data-i18n="earn_beacon_btn">{s['earn_beacon_btn']}</button>
            </div>
            <div id="earn-beacon-out" class="earn-stack"></div>
          </div>

          <div class="box earn-box-wide">
            <h3 class="box-title" data-i18n="earn_stores_title">{s['earn_stores_title']}</h3>
            <p class="earn-meta" data-i18n="earn_stores_sub">{s['earn_stores_sub']}</p>
            <div class="toolbar">
              <select id="earn-store-type" aria-label="Digital store">
                <option value="lemonsqueezy">Lemon Squeezy</option>
                <option value="gumroad">Gumroad</option>
                <option value="payhip">Payhip</option>
                <option value="sellfy">Sellfy</option>
                <option value="whop">Whop</option>
              </select>
              <input id="earn-store-label" type="text" data-i18n-placeholder="earn_store_label_ph" placeholder="{s['earn_store_label_ph']}">
              <input id="earn-store-seller-id" type="text" data-i18n-placeholder="earn_store_seller_ph" placeholder="{s['earn_store_seller_ph']}">
            </div>
            <div class="toolbar">
              <input id="earn-store-api-url" type="text" data-i18n-placeholder="earn_store_url_ph" placeholder="{s['earn_store_url_ph']}">
              <input id="earn-store-key" type="password" data-i18n-placeholder="earn_store_key_ph" placeholder="{s['earn_store_key_ph']}">
              <input id="earn-store-wh-secret" type="password" data-i18n-placeholder="earn_store_wh_ph" placeholder="{s['earn_store_wh_ph']}">
            </div>
            <div class="rec-actions">
              <button id="earn-store-connect-btn" class="btn-primary" data-i18n="earn_store_connect_btn">{s['earn_store_connect_btn']}</button>
              <button id="earn-store-seed-btn" data-i18n="earn_store_seed_btn">{s['earn_store_seed_btn']}</button>
            </div>
            <div id="earn-stores-list" class="earn-stack"></div>
            <div class="toolbar">
              <input id="earn-draft-title" type="text" data-i18n-placeholder="earn_draft_title_ph" placeholder="{s['earn_draft_title_ph']}">
              <input id="earn-draft-price" class="earn-num-input" type="number" value="19" min="1" step="1" data-i18n-placeholder="earn_draft_price_ph" placeholder="{s['earn_draft_price_ph']}">
            </div>
            <div class="toolbar">
              <input id="earn-draft-desc" type="text" data-i18n-placeholder="earn_draft_desc_ph" placeholder="{s['earn_draft_desc_ph']}">
              <input id="earn-draft-url" type="text" data-i18n-placeholder="earn_draft_url_ph" placeholder="{s['earn_draft_url_ph']}">
              <button id="earn-draft-save-btn" data-i18n="earn_draft_save_btn">{s['earn_draft_save_btn']}</button>
            </div>
            <div id="earn-drafts-list" class="earn-stack"></div>
          </div>

          <div class="box earn-box-wide">
            <h3 class="box-title" data-i18n="earn_wiz_title">{s['earn_wiz_title']}</h3>
            <p class="earn-meta" data-i18n="earn_wiz_sub">{s['earn_wiz_sub']}</p>
            <div id="earn-wiz-summary" class="earn-meta"></div>
            <div class="toolbar">
              <select id="earn-wiz-filter" aria-label="Filter platforms by tier">
                <option value="all" data-i18n="earn_wiz_f_all">{s['earn_wiz_f_all']}</option>
                <option value="autopilot" data-i18n="earn_wiz_f_autopilot">{s['earn_wiz_f_autopilot']}</option>
                <option value="assisted_button" data-i18n="earn_wiz_f_assisted">{s['earn_wiz_f_assisted']}</option>
                <option value="not_available" data-i18n="earn_wiz_f_na">{s['earn_wiz_f_na']}</option>
              </select>
              <select id="earn-wiz-platform" aria-label="Select platform"></select>
              <select id="earn-wiz-auth-method" aria-label="Auth method without password">
                <option value="oauth">OAuth 2.0</option>
                <option value="api_key">API Key</option>
                <option value="browser_session" data-i18n="earn_wiz_auth_session">{s['earn_wiz_auth_session']}</option>
              </select>
            </div>
            <div id="earn-wiz-spec-info" class="earn-meta"></div>
            <div class="rec-actions">
              <button id="earn-wiz-google-btn" class="btn-primary" data-i18n="earn_wiz_google_btn">{s['earn_wiz_google_btn']}</button>
              <button id="earn-wiz-login-btn" class="btn-ok" data-i18n="earn_wiz_login_btn">{s['earn_wiz_login_btn']}</button>
            </div>
            <div id="earn-wiz-session-out" class="earn-meta"></div>
            <div class="toolbar">
              <label for="earn-wiz-autopilot-chk">
                <input id="earn-wiz-autopilot-chk" type="checkbox">
                <span data-i18n="earn_wiz_autopilot_lbl">{s['earn_wiz_autopilot_lbl']}</span>
              </label>
              <input id="earn-wiz-daily-limit" class="earn-num-input" type="number" value="10" min="1" max="100" step="1" aria-label="Daily bid limit">
            </div>
            <div id="earn-wiz-bot-warn" class="earn-meta" data-bot-warn-box="1"></div>
            <div class="toolbar">
              <input id="earn-wiz-secret" type="password" data-i18n-placeholder="earn_wiz_secret_ph" placeholder="{s['earn_wiz_secret_ph']}">
              <button id="earn-wiz-connect-btn" class="btn-primary" data-i18n="earn_wiz_connect_btn">{s['earn_wiz_connect_btn']}</button>
            </div>
            <div class="toolbar">
              <input id="earn-wiz-q-spec" type="text" value="{s['earn_wiz_def_spec']}" data-i18n-placeholder="earn_wiz_q_spec_ph" placeholder="{s['earn_wiz_q_spec_ph']}">
              <input id="earn-wiz-q-rate" class="earn-num-input" type="number" value="35" min="5" step="5" data-i18n-placeholder="earn_wiz_q_rate_ph" placeholder="{s['earn_wiz_q_rate_ph']}">
              <input id="earn-wiz-q-min" class="earn-num-input" type="number" value="100" min="10" step="10" data-i18n-placeholder="earn_wiz_q_min_ph" placeholder="{s['earn_wiz_q_min_ph']}">
            </div>
            <div class="toolbar">
              <input id="earn-wiz-q-langs" type="text" value="ru, en, es, zh" data-i18n-placeholder="earn_wiz_q_langs_ph" placeholder="{s['earn_wiz_q_langs_ph']}">
              <input id="earn-wiz-q-tone" type="text" value="{s['earn_wiz_def_tone']}" data-i18n-placeholder="earn_wiz_q_tone_ph" placeholder="{s['earn_wiz_q_tone_ph']}">
              <input id="earn-wiz-q-excl" type="text" value="{s['earn_wiz_def_excl']}" data-i18n-placeholder="earn_wiz_q_excl_ph" placeholder="{s['earn_wiz_q_excl_ph']}">
            </div>
            <div class="rec-actions">
              <button id="earn-wiz-profile-btn" class="btn-primary" data-i18n="earn_wiz_profile_btn">{s['earn_wiz_profile_btn']}</button>
              <button id="earn-wiz-autopick-btn" class="btn-ok" data-i18n="earn_wiz_autopick_btn">{s['earn_wiz_autopick_btn']}</button>
            </div>
            <div id="earn-wiz-profiles-list" class="earn-stack"></div>
            <div id="earn-wiz-catalog-list" class="earn-stack"></div>
          </div>

          <div class="box earn-box-wide" id="earn-partner-box">
            <h3 class="box-title" data-i18n="earn_partner_t">{s['earn_partner_t']}</h3>
            <p class="earn-meta" data-i18n="earn_partner_sub">{s['earn_partner_sub']}</p>
            <div id="earn-partner-status" class="earn-meta" role="status"></div>
            <div class="toolbar">
              <input id="earn-partner-key" type="password" autocomplete="off" data-i18n-placeholder="earn_partner_key_ph" placeholder="{s['earn_partner_key_ph']}">
              <button id="earn-partner-key-btn" class="btn-primary" data-i18n="earn_partner_key_btn">{s['earn_partner_key_btn']}</button>
              <a href="https://aifa.works/mcp" target="_blank" rel="noopener noreferrer" data-i18n="earn_partner_key_link">{s['earn_partner_key_link']}</a>
            </div>
            <div class="toolbar">
              <input id="earn-partner-region" type="text" value="US-CA" maxlength="8" data-i18n-placeholder="earn_partner_region_ph" placeholder="{s['earn_partner_region_ph']}">
              <button id="earn-partner-find-btn" class="btn-primary" data-i18n="earn_partner_find_btn">{s['earn_partner_find_btn']}</button>
              <button id="earn-partner-deals-btn" data-i18n="earn_partner_deals_btn">{s['earn_partner_deals_btn']}</button>
            </div>
            <div class="toolbar">
              <input id="earn-partner-site" type="text" maxlength="253" data-i18n-placeholder="earn_partner_site_ph" placeholder="{s['earn_partner_site_ph']}">
              <button id="earn-partner-report-btn" data-i18n="earn_partner_report_btn">{s['earn_partner_report_btn']}</button>
              <button id="earn-partner-draft-btn" class="btn-ok" data-i18n="earn_partner_draft_btn">{s['earn_partner_draft_btn']}</button>
            </div>
            <div class="rec-actions">
              <button id="earn-partner-link-btn" data-i18n="earn_partner_link_btn">{s['earn_partner_link_btn']}</button>
              <button id="earn-partner-kit-btn" data-i18n="earn_partner_kit_btn">{s['earn_partner_kit_btn']}</button>
            </div>
            <div id="earn-partner-out" class="earn-stack"></div>
          </div>
        </div>
      </section>
    </main>
  </div>
</div>
<div id="quick-add-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="qa-modal-title-el" hidden>
  <div class="modal-card">
    <h2 id="qa-modal-title-el" class="box-title" data-i18n="qa_modal_title">{s['qa_modal_title']}</h2>
    <p class="panel-sub" data-i18n="qa_modal_hint">{s['qa_modal_hint']}</p>
    <div class="toolbar">
      <input id="quick-add-text" type="text" data-i18n-placeholder="feed_new_placeholder" data-i18n-aria="feed_new_placeholder" placeholder="{s['feed_new_placeholder']}" aria-label="{s['feed_new_placeholder']}">
      <select id="quick-add-kind" aria-label="Quick memory kind">
        <option value="fact">fact</option>
        <option value="preference">preference</option>
        <option value="identity">identity</option>
        <option value="decision">decision</option>
        <option value="correction">correction</option>
        <option value="state">state</option>
        <option value="event">event</option>
      </select>
    </div>
    <div class="rec-actions">
      <button id="quick-add-save" class="btn-primary" data-i18n="qa_modal_save">{s['qa_modal_save']}</button>
      <button id="quick-add-cancel" data-i18n="qa_modal_cancel">{s['qa_modal_cancel']}</button>
    </div>
  </div>
</div>
<script id="i18n-data" type="application/json" nonce="{nonce}">{i18n_json}</script>
<script nonce="{nonce}">{_JS}</script>
</body>
</html>"""
    return html, nonce
