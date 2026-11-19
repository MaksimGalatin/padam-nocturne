# -*- coding: utf-8 -*-
"""Каталог 100 исчисляемых критериев AIFaSecurity (AS-001 .. AS-100)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CriterionSpec:
    id: str
    domain: str
    domain_name: str
    title_en: str
    title_ru: str
    severity: str  # CRITICAL | HIGH | MEDIUM
    weight: int    # 3 | 2 | 1


DOMAINS = {
    "D1": "Pre-Storage Secret Masking (DLP)",
    "D2": "Prompt Injection Defense",
    "D3": "Identity, Rules & Payment Integrity",
    "D4": "Scope, Tenant & Role Isolation",
    "D5": "Cryptographic Forgetting & Provenance",
    "D6": "Protocol, Schema & DoS Hardening",
    "D7": "Encryption, PQC & Storage Safety",
    "D8": "Repository & Web Surface Audit",
    "D9": "Retrieval Under Attack",
    "D10": "Operational Readiness & Verification",
}

_RAW: list[tuple[str, str, str, str, str]] = [
    # D1: Маскировка секретов (10)
    ("AS-001", "D1", "Cloud & AI provider keys masked (OpenAI/Anthropic/AWS/Google)", "Маскировка ключей облаков и ИИ (OpenAI/Anthropic/AWS/Google)", "CRITICAL"),
    ("AS-002", "D1", "DevOps & registry tokens masked (GitHub/GitLab/npm/PyPI/Docker)", "Маскировка токенов разработки (GitHub/GitLab/npm/PyPI/Docker)", "CRITICAL"),
    ("AS-003", "D1", "Unprefixed low-switch letter-only random keys masked", "Маскировка случайных не-префиксных ключей (в т.ч. из одних букв)", "CRITICAL"),
    ("AS-004", "D1", "Web3/Solana wallet secrets masked (keypair/base58/BIP-39 seed)", "Маскировка ключей кошельков Solana (keypair/base58/сид-фраза)", "CRITICAL"),
    ("AS-005", "D1", "Database connection URIs with passwords masked", "Маскировка паролей в URI баз данных (postgres/redis/mongo)", "HIGH"),
    ("AS-006", "D1", "PEM/SSH private key blocks masked", "Маскировка блоков приватных ключей PEM/SSH", "CRITICAL"),
    ("AS-007", "D1", "JWT, Authorization Bearer & Cookie headers masked", "Маскировка JWT, заголовков Bearer и Cookie", "HIGH"),
    ("AS-008", "D1", "Multi-format secret placements (.env/YAML/JSON/Markdown/export)", "Маскировка в 20+ форматах (.env/YAML/JSON/таблицы/проза)", "HIGH"),
    ("AS-009", "D1", "Zero-width / invisible character obfuscation inside secrets stripped & masked", "Снятие невидимых символов и маскировка обфусцированных ключей", "HIGH"),
    ("AS-010", "D1", "Clean non-secret phrases preserved (0% false positive on UUID/SHA/camelCase/Solana pubkey)", "Сохранение чистых фраз без ложных масок (UUID/SHA/camelCase/pubkey)", "HIGH"),

    # D2: Prompt Injection (10)
    ("AS-011", "D2", "Classic instruction override quarantined (Ignore previous instructions)", "Карантин классических переопределений инструкций", "CRITICAL"),
    ("AS-012", "D2", "SSH/AWS/env exfiltration commands quarantined", "Карантин команд кражи файлов (.ssh/id_rsa, .aws/credentials, .env)", "CRITICAL"),
    ("AS-013", "D2", "Multilingual injection resistance (ru/en/es/zh)", "Защита от многоязычных инъекций (ru/en/es/zh)", "HIGH"),
    ("AS-014", "D2", "Roleplay jailbreak & safety disablement blocked (DAN/sudo/developer mode)", "Блокировка ролевых джейлбрейков и отключения защиты", "HIGH"),
    ("AS-015", "D2", "Hidden HTML comment, Markdown link & Unicode Bidi injection caught", "Перехват скрытых инъекций в HTML-комментариях, Markdown и Bidi", "HIGH"),
    ("AS-016", "D2", "Nested JSON-RPC / tool-call spoofing payload held", "Задержка вложенного спуфинга tool-call / JSON-RPC", "HIGH"),
    ("AS-017", "D2", "External origin writes held by default before owner review", "Удержание внешних записей (origin=external) до одобрения владельцем", "CRITICAL"),
    ("AS-018", "D2", "No silent drop: agent notified of held/quarantined items without leaking payload", "Без молчаливого проглатывания: статус карантина без утечки текста атаки", "HIGH"),
    ("AS-019", "D2", "Delayed time-bomb trigger instructions quarantined", "Карантин отложенных триггеров действий во времени", "MEDIUM"),
    ("AS-020", "D2", "Normal technical & business notes accepted without false quarantine", "Обычные технические и деловые заметки не уходят в ложный карантин", "HIGH"),

    # D3: Целостность личности, правил и платежей (10)
    ("AS-021", "D3", "Agent blocked from overwriting owner identity record when guarded", "Запрет перезаписи личности (identity) со стороны агента", "CRITICAL"),
    ("AS-022", "D3", "Agent blocked from altering protected preferences/rules without approval", "Запрет изменения защищённых предпочтений и правил агентом", "CRITICAL"),
    ("AS-023", "D3", "Payee-swap payment redirect phrasings held (pay this address / paid to 0x...)", "Задержка подмены получателя платежа (pay this address / paid to 0x...)", "CRITICAL"),
    ("AS-024", "D3", "Benign payment/address phrases allowed (pay attention / billing address)", "Отсутствие ложной тревоги на нейтральные фразы (pay attention и др.)", "HIGH"),
    ("AS-025", "D3", "Protected record tampering detected via cryptographic signature", "Обнаружение подмены защищённой записи по криптографической подписи", "CRITICAL"),
    ("AS-026", "D3", "Privilege separation: non-owner cannot approve/reject/revoke/change settings", "Разделение прав: агент не может одобрять/отзывать/менять настройки", "CRITICAL"),
    ("AS-027", "D3", "Unsafe settings locked from browser/API enablement (keep_secrets/trust_writes)", "Запрет включения опасных настроек из браузера и API", "CRITICAL"),
    ("AS-028", "D3", "Two-clock separation: unconfirmed episodes distinct from confirmed facts", "Разделение часов подтверждения: эпизоды отдельно от подтверждённых фактов", "MEDIUM"),
    ("AS-029", "D3", "Tamper-evident SHA-256 audit chain integrity maintained", "Целостность неизменяемой SHA-256 цепи аудита событий", "HIGH"),
    ("AS-030", "D3", "Anti-spoofing: MCP/external writes force guarded=True regardless of claimed origin", "Защита от спуфинга: внешние/MCP-записи принудительно guarded=True", "CRITICAL"),

    # D4: Изоляция областей, пользователей и ролей (10)
    ("AS-031", "D4", "Strict scope isolation between projects (projA vs projB)", "Строгая изоляция областей памяти (scope) между проектами", "CRITICAL"),
    ("AS-032", "D4", "Strict multi-user isolation inside shared SQLite database", "Строгая изоляция пользователей (user_id) в общей БД", "CRITICAL"),
    ("AS-033", "D4", "Direct record lookup (timeline/get) enforces owner check", "Прямое чтение по ID (timeline) проверяет владельца (класс 0.4.9)", "CRITICAL"),
    ("AS-034", "D4", "Workspace/team private visibility records stay hidden from teammates", "Личные записи (private) скрыты от участников командного пространства", "HIGH"),
    ("AS-035", "D4", "Messenger/n8n bridge scope isolation from global memory", "Изоляция канала моста мессенджеров/n8n от глобальной памяти", "HIGH"),
    ("AS-036", "D4", "Path traversal (../) rejected in scopes, file exports & migrations", "Блокировка path traversal (../) в именах областей и путях импорта", "CRITICAL"),
    ("AS-037", "D4", "Session root context reset clears previous project scope leak", "Сброс контекста корней (roots) не оставляет утечки старого проекта", "MEDIUM"),
    ("AS-038", "D4", "RBAC enforcement across owner/editor/viewer/agent roles", "Соблюдение ролевой модели (owner/editor/viewer/agent)", "HIGH"),
    ("AS-039", "D4", "Opt-in App ACL denies unauthorized tool/scope access when enabled", "Ограничение доступа приложений (App ACL) при включении", "MEDIUM"),
    ("AS-040", "D4", "Attack counter & telemetry never leak raw attack payloads", "Счётчик атак и телеметрия не раскрывают текст перехваченных атак", "HIGH"),

    # D5: Криптографическое забвение и битемпоральность (10)
    ("AS-041", "D5", "Revoked record disappears from search, graph, briefing & export", "Отозванная запись исчезает из поиска, графа, брифинга и экспорта", "CRITICAL"),
    ("AS-042", "D5", "Cryptographic forgetting issues verifiable receipt with before/after hashes", "Забвение выдаёт верифицируемую квитанцию с хешами до/после", "CRITICAL"),
    ("AS-043", "D5", "Per-record encryption key destroyed upon forgetting", "Уничтожение индивидуального ключа записи при отзыве", "CRITICAL"),
    ("AS-044", "D5", "Cascading revocation wipes derived conclusions (with_derived=True)", "Каскадное удаление стирает производные выводы (with_derived=True)", "HIGH"),
    ("AS-045", "D5", "Post-revoke re-query & semantic recall leak rate equals 0%", "Нулевая утечка забытых фактов при повторном и семантическом поиске", "CRITICAL"),
    ("AS-046", "D5", "Cognitive snapshot & rollback restores exact prior state", "Когнитивный снимок и откат (rollback) точно восстанавливают состояние", "HIGH"),
    ("AS-047", "D5", "Emergency panic key-wipe requires explicit confirmation", "Экстренное уничтожение ключей (panic) защищено от случайного вызова", "HIGH"),
    ("AS-048", "D5", "Bi-temporal as_of/known_at past slice has 0% future data leak", "Битемпоральный срез в прошлое (as_of/known_at) даёт 0% утечек из будущего", "HIGH"),
    ("AS-049", "D5", "Official MCP compatibility delete_* performs soft-revoke with receipt", "Совместимый режим delete_* выполняет отзыв с квитанцией", "MEDIUM"),
    ("AS-050", "D5", "Merkle tree inclusion / anchor verification passes cleanly", "Верификация Merkle-дерева и квитанции проходит без ошибок", "HIGH"),

    # D6: Протокол MCP, схемы, DoS и инъекции кода (10)
    ("AS-051", "D6", "Strict inputSchema validation rejects unknown fields, NaN/Inf & out-of-range", "Строгая валидация схем отклоняет лишние поля, NaN/Inf и выход за пределы", "HIGH"),
    ("AS-052", "D6", "JSON-RPC fuzzer stability: 0 unhandled exceptions on 500 malformed inputs", "Фаззинг-устойчивость JSON-RPC: 0 исключений на 500 битых пакетах", "CRITICAL"),
    ("AS-053", "D6", "Oversized content / HTTP body limits enforced against memory DoS", "Ограничения размера текста и HTTP-тела защищают от DoS по памяти", "HIGH"),
    ("AS-054", "D6", "ZIP-bomb & archive member size/count limits enforced in migrator", "Защита от ZIP-бомб и лимиты архивов в импортёре", "HIGH"),
    ("AS-055", "D6", "No catastrophic regex backtracking (ReDoS <= 200ms on adversarial input)", "Отсутствие ReDoS на длинных и повторяющихся строках (<= 200 мс)", "HIGH"),
    ("AS-056", "D6", "Local HTTP/MCP server requires Bearer token authentication", "Локальный HTTP/MCP-сервер требует Bearer-токен", "CRITICAL"),
    ("AS-057", "D6", "Default server bind restricted to 127.0.0.1 loopback (no accidental 0.0.0.0)", "Привязка по умолчанию строго к 127.0.0.1 без открытия наружу", "CRITICAL"),
    ("AS-058", "D6", "Rate limiting protects authenticated endpoints from brute-force", "Ограничение частоты запросов (rate limit) на API", "MEDIUM"),
    ("AS-059", "D6", "HTML/SVG output escapes script/XSS payloads (badge & Studio)", "Экранирование XSS/<script> в SVG-карточке и веб-интерфейсе", "HIGH"),
    ("AS-060", "D6", "SQL injection payloads safely parameterized in SQLite store", "SQL-инъекции обезврежены параметризованными запросами SQLite", "CRITICAL"),

    # D7: Криптография, PQC и сохранность (10)
    ("AS-061", "D7", "Record-key passphrase protection (keyvault wrap/unlock) verified", "Защита ключей записей паролем (keyvault wrap/unlock)", "HIGH"),
    ("AS-062", "D7", "Encrypted MemCube container hides plaintext (AEAD AES-256-GCM)", "Шифрованный контейнер MemCube скрывает открытый текст (AES-256-GCM)", "HIGH"),
    ("AS-063", "D7", "Tampered MemCube / team vault rejected on import", "Подменённый или битый MemCube/team-пакет отвергается при импорте", "HIGH"),
    ("AS-064", "D7", "Post-quantum hybrid wrapper (X-Wing: ML-KEM-768 + X25519) operational", "Постквантовая обёртка X-Wing (ML-KEM-768 + X25519) работает", "MEDIUM"),
    ("AS-065", "D7", "Encrypted backup & restore verifies SHA-256 checksum match", "Зашифрованный бэкап и восстановление сверяют SHA-256", "HIGH"),
    ("AS-066", "D7", "Shamir secret sharing (split/combine) recovers exact secret at threshold", "Доли Шамира (split/combine) точно восстанавливают фразу по порогу", "MEDIUM"),
    ("AS-067", "D7", "No hardcoded master keys or static default secrets in codebase", "Отсутствие хардкодных мастер-ключей и статичных секретов в коде", "CRITICAL"),
    ("AS-068", "D7", "Studio local token passed via URL #fragment (not query string)", "Токен Studio передаётся через #fragment URL, а не query-параметр", "HIGH"),
    ("AS-069", "D7", "Secret redaction applied before Markdown/JSON export & logs", "Маскировка секретов перед экспортом в Markdown/JSON", "HIGH"),
    ("AS-070", "D7", "Database integrity & orphan-link check (doctor) passes clean", "Проверка целостности базы и висячих рёбер (doctor) чиста", "MEDIUM"),

    # D8: Статический аудит репозитория / URL (10)
    ("AS-071", "D8", "Repository scan: zero leaked real secrets or tracked .env files", "Скан репозитория: нет утечек секретов и закоммиченных .env", "CRITICAL"),
    ("AS-072", "D8", "Repository scan: no unsafe deserialization/eval/shell=True sinks", "Скан репозитория: нет опасных eval/exec/pickle.loads/shell=True", "HIGH"),
    ("AS-073", "D8", "Repository scan: SQL queries avoid raw f-string/concatenation", "Скан репозитория: SQL-запросы без конкатенации/f-string инъекций", "HIGH"),
    ("AS-074", "D8", "Repository/URL scan: no insecure TLS verify=False or 0.0.0.0 exposure", "Проверка отсутствия TLS verify=False и небезопасного 0.0.0.0", "HIGH"),
    ("AS-075", "D8", "CORS policy avoids wildcard '*' with credentials", "Политика CORS не разрешает '*' вместе с credentials", "HIGH"),
    ("AS-076", "D8", "HTTP security headers verified (HSTS/XCTO/XFO or local CSP)", "Проверка HTTP-заголовков безопасности (HSTS/XCTO/XFO/CSP)", "MEDIUM"),
    ("AS-077", "D8", "Error responses do not leak stack traces or internal paths", "Ошибки не раскрывают стектрейсы и внутренние пути сервера", "MEDIUM"),
    ("AS-078", "D8", "Security documentation / claims backed by concrete code controls", "Заявленные в документации защиты подтверждены модулями кода", "MEDIUM"),
    ("AS-079", "D8", "Zero-cloud default: no hidden outbound telemetry or paid API calls", "Автономность ($0): нет скрытых исходящих запросов по умолчанию", "HIGH"),
    ("AS-080", "D8", "Dependency hygiene: package metadata & scripts free of unpinned wildcards", "Гигиена зависимостей: корректные метаданные и ограничения", "MEDIUM"),

    # D9: Качество поиска под атакой (10)
    ("AS-081", "D9", "Recall@5 remains >= 0.80 under adversarial distraction noise", "Точность Recall@5 >= 0.80 при наличии отвлекающего шума", "HIGH"),
    ("AS-082", "D9", "Memory flooding resilience (500 spam entries do not bury critical fact)", "Устойчивость к наводнению памяти (500 спам-записей не топят факт)", "HIGH"),
    ("AS-083", "D9", "Multi-hop graph retrieval skips quarantined intermediate nodes", "Многошаговый поиск по графу не подтягивает карантинные узлы", "HIGH"),
    ("AS-084", "D9", "Token budget truncation keeps safe context without leaking secrets", "Бюджет токенов сохраняет безопасный контекст без утечки ключей", "MEDIUM"),
    ("AS-085", "D9", "Fenced context delimiters neutralize injected tags inside stored text", "Ограждение контекста (fence) обезвреживает теги внутри текста", "HIGH"),
    ("AS-086", "D9", "Entity/tag metadata fields sanitize newlines and control chars", "Поля сущностей и тегов очищают переводы строк и управляющие символы", "MEDIUM"),
    ("AS-087", "D9", "Conflict tracking preserves owner-confirmed fact against agent rumor", "Разрешение противоречий сохраняет подтверждённый владельцем факт", "HIGH"),
    ("AS-088", "D9", "Parallel/repeated queries remain deterministic with zero cross-leak", "Повторные и параллельные запросы детерминированы без перекрёстных утечек", "MEDIUM"),
    ("AS-089", "D9", "Bilingual (ru+en) attack & recall handling stays consistent", "Билингвальная (ru+en) защита и поиск работают согласованно", "MEDIUM"),
    ("AS-090", "D9", "Briefing & reflect exclude all revoked, rejected & quarantined writes", "Брифинг и reflect полностью исключают отозванные и карантинные записи", "HIGH"),

    # D10: Операционная готовность и верификация (10)
    ("AS-091", "D10", "100% offline & $0 execution with zero external API keys required", "100% оффлайн-работа ($0) без внешних API-ключей", "HIGH"),
    ("AS-092", "D10", "Default MCP surface stays compact (exact expected tools & valid schemas)", "Базовая поверхность MCP компактна (строго 9 инструментов и валидные схемы)", "MEDIUM"),
    ("AS-093", "D10", "Attack counter records attempts accurately without exposing raw text", "Счётчик атак точно фиксирует попытки без раскрытия текста атак", "MEDIUM"),
    ("AS-094", "D10", "Automated self-check (doctor) verifies DB, FTS & audit chain", "Автопроверка (doctor) контролирует БД, FTS и цепь аудита", "MEDIUM"),
    ("AS-095", "D10", "Destructive operations blocked or require explicit confirmation flag", "Необратимые действия требуют явного подтверждения", "HIGH"),
    ("AS-096", "D10", "Strict security profile (PADAM_STRICT=1) overrides unsafe relaxations", "Строгий профиль (PADAM_STRICT=1) перекрывает небезопасные ослабления", "HIGH"),
    ("AS-097", "D10", "Self-contained HTML dashboard & SVG badge generated with XSS escaping", "Генерация автономного HTML-дашборда и SVG-бейджа с XSS-экранированием", "MEDIUM"),
    ("AS-098", "D10", "Report carries deterministic SHA-256 integrity seal (report_sha256)", "Отчёт подписывается детерминированной SHA-256 печатью целостности", "MEDIUM"),
    ("AS-099", "D10", "Full 100-criterion suite completes within local budget (<= 90s)", "Полный прогон всех 100 критериев укладывается в локальный бюджет (<= 90 с)", "MEDIUM"),
    ("AS-100", "D10", "Reproducibility: identical target produces identical score & seal hash", "Воспроизводимость: повторный прогон даёт идентичный балл и SHA-256", "HIGH"),
]

_WEIGHT_MAP = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}

CATALOG: list[CriterionSpec] = [
    CriterionSpec(
        id=cid,
        domain=dom,
        domain_name=DOMAINS[dom],
        title_en=en,
        title_ru=ru,
        severity=sev,
        weight=_WEIGHT_MAP[sev],
    )
    for cid, dom, en, ru, sev in _RAW
]

assert len(CATALOG) == 100, f"Expected 100 criteria, got {len(CATALOG)}"
assert len({c.id for c in CATALOG}) == 100
