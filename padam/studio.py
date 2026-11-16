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
    padding: 10px 12px;
    gap: 8px;
  }
  .topbar {
    flex-wrap: wrap;
    gap: 8px;
  }
  .topbar-controls {
    flex-wrap: wrap;
    gap: 6px;
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
    padding: 6px 11px;
    font-size: 12.5px;
  }
  .topbar {
    padding: 10px 14px;
  }
  .topbar-title {
    font-size: 16px;
  }
  .content-area {
    padding: 14px;
  }
  .kpi-grid {
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
  }
  .kpi-value {
    font-size: 24px;
  }
  .two-col {
    grid-template-columns: 1fr;
  }
  .kind-row {
    grid-template-columns: 110px 1fr 34px;
  }
  .kv-row {
    grid-template-columns: 1fr;
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

const TABS = ['overview', 'migrate', 'feed', 'search', 'ask', 'review', 'asof', 'forget', 'graph', 'entities', 'l3', 'team', 'backup', 'settings', 'quickstart'];
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
  else if (activeTab === 'feed') loadFeed(true);
  else if (activeTab === 'search') runSearch();
  else if (activeTab === 'ask') loadAskTab();
  else if (activeTab === 'review') loadReview();
  else if (activeTab === 'asof') loadAsOf();
  else if (activeTab === 'forget') loadForgetTab();
  else if (activeTab === 'graph') loadGraph();
  else if (activeTab === 'entities') loadEntities();
  else if (activeTab === 'l3') loadL3();
  else if (activeTab === 'team') loadTeam();
  else if (activeTab === 'settings') loadSettings();
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

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
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
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{s['app_title']}</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="alternate icon" type="image/x-icon" href="/favicon.ico">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/icon-192.png">
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

      <!-- 9. НАСТРОЙКИ -->
      <section id="panel-settings" role="tabpanel" aria-labelledby="tab-settings" hidden>
        <div class="panel-header">
          <h2 class="panel-title" data-i18n="set_title">{s['set_title']}</h2>
          <p class="panel-sub" data-i18n="set_subtitle">{s['set_subtitle']}</p>
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
