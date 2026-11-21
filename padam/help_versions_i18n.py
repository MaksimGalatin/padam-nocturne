"""Переводы кратких описаний версий для вкладки «Справка» PADAM Studio (ru / es / zh).

Если для старой версии перевода нет, используется очищенный английский текст из help_versions.py.
Ни одна строка не содержит обратных кавычек (`) и не оканчивается двоеточием (:).
"""
from __future__ import annotations

TRANSLATIONS: dict[str, dict[str, str]] = {
    "ark": {
        "ru": "Ковчег сознания ИИ-агента: единое пробуждение padam_wake_up, цели, подписанная эстафета Семьи, чекпоинты со сжатием в архив без потерь, схема Шамира без отпечатка секрета, цепочка аудита с якорем HMAC-SHA256 и учебная тревога Феникса (всё опционально, выключено по умолчанию).",
        "es": "Arca de Conciencia del agente de IA: despertar unificado padam_wake_up, metas, relevo familiar firmado, puntos de control con archivo sin pérdida, esquema de Shamir sin huella del secreto, cadena de auditoría con anclaje HMAC-SHA256 y simulacro Fénix (todo opcional, desactivado por defecto).",
        "zh": "AI 智能体意识方舟：单次唤醒 padam_wake_up、目标账本、HMAC 签名家族接力、无损归档压缩、无秘密指纹泄露的 Shamir 分片、带 HMAC-SHA256 锚点的审计链以及零成本凤凰演练（全部默认关闭，按需开启）。",
    },
    "0.7.1": {
        "ru": "Студия: вкладка чата AIfa переделана как чат на наших сайтах — пузыри сообщений, широкая строка ввода с вложением, голосовым вводом, озвучкой и отправкой, фильтры за 24 часа и за всё время, порядок новых сверху или по хронологии; подсказки ко всем новым кнопкам на 4 языках.",
        "es": "Studio: la pestaña de chat de AIfa rediseñada como el chat de nuestros sitios — burbujas de mensajes, un campo de escritura amplio con adjuntar, dictado por voz, lectura en voz alta y enviar, filtros de las últimas 24 horas y de todo el historial, orden de más recientes primero o cronológico; descripciones para cada botón nuevo en 4 idiomas.",
        "zh": "Studio：AIfa 聊天标签页按照我们网站上的聊天重新设计——左右两侧的消息气泡、带附件、语音输入、语音朗读和发送按钮的宽输入框、最近 24 小时与全部历史筛选、最新在前或按时间顺序排列；所有新按钮均有 4 种语言的提示。",
    },
    "0.7.0": {
        "ru": "PADAM Agentic Shield: четыре кольца защиты для ИИ-агентов, платежей и сайтов (padam/agentic_shield.py, инструмент MCP padam_agentic_shield, команды padam shield, Студия).",
        "es": "PADAM Agentic Shield: cuatro anillos de defensa para agentes de IA, pagos y sitios web (padam/agentic_shield.py, herramienta MCP padam_agentic_shield, comandos padam shield, Studio).",
        "zh": "PADAM Agentic Shield：为 AI 智能体、支付和网站提供四层防护（padam/agentic_shield.py、MCP 工具 padam_agentic_shield、padam shield 命令、Studio）。",
    },
    "0.6.5": {
        "ru": "Заработок агента: комиссия CODE 15 процентов с кнопкой владельца и 20 процентов на автопилоте, пять магазинов цифровых товаров через официальные API, мастер подключения 34 площадок без паролей, черновик профиля из памяти, публикация только кнопкой владельца, клиент закреплён на 90 дней.",
        "es": "Ganancias del agente: comisión CODE del 15 por ciento con el botón del propietario y del 20 por ciento en piloto automático, cinco tiendas de productos digitales mediante API oficiales, asistente de conexión de 34 plataformas sin contraseñas, borrador del perfil desde la memoria, publicación solo con el botón del propietario y cliente asignado durante 90 días.",
        "zh": "智能体收入：所有者按按钮时 CODE 佣金为 15%，自动驾驶时为 20%；通过官方 API 接入五家数字商品商店；无需密码即可接入 34 个平台的向导；根据记忆生成资料草稿，只有所有者按按钮才发布；客户归属保留 90 天。",
    },
    "0.6.4": {
        "ru": "Ковчег сознания: пробуждение агента со списком сделанного и обещанного, постквантовый обмен ключами X-Wing (ML-KEM-768 и X25519), одна память на нескольких устройствах с подтверждением шестизначным кодом, ключ по схеме Шамира 3 из 5, переносимый Ковчег, подписанная передача между сессиями, безопасная самопочинка базы в копию, проверка готовности из 8 сценариев. Всё включается владельцем, по умолчанию выключено, стоит 0 долларов.",
        "es": "Arca de Conciencia: despertar del agente con lo hecho y lo prometido, intercambio de claves poscuántico X-Wing (ML-KEM-768 y X25519), una sola memoria en varios dispositivos con código de seis cifras, clave Shamir 3 de 5, Arca portátil, relevo firmado entre sesiones, autorreparación segura de la base en una copia y prueba de preparación de 8 escenarios. Todo lo activa el propietario, desactivado por defecto, coste 0 dólares.",
        "zh": "意识方舟：智能体唤醒时获得已完成和已承诺事项，后量子 X-Wing 密钥交换（ML-KEM-768 与 X25519），多设备共享同一记忆并以六位数字码确认，Shamir 3/5 密钥分片，便携方舟，会话间签名交接，数据库安全自愈到副本，8 个场景的就绪检查。全部由所有者开启，默认关闭，费用为 0 美元。",
    },
    "0.6.3": {
        "ru": "Открытый аудит безопасности памяти агентов из 100 проверок, исправлена медленная маскировка ключей (ReDoS), задержка подмены почты и телефона восстановления, кошелька и реквизитов, суверенный роутер моделей и сбор датасета личности (всё платное выключено по умолчанию).",
        "es": "Auditoría abierta de seguridad de memoria de agentes con 100 controles, corrección del enmascarado lento de claves (ReDoS), retención de cambios de correo o teléfono de recuperación, cartera y datos de pago, enrutador soberano de modelos y conjunto de datos de personalidad (todo lo de pago desactivado por defecto).",
        "zh": "新增 100 项智能体记忆安全公开审计，修复密钥遮蔽的慢速正则问题（ReDoS），拦截篡改找回邮箱或电话、钱包与收款信息的指令，并加入自主模型路由与人格数据集构建（所有付费功能默认关闭）。",
    },
    "0.6.2": {
        "ru": "Защита от подмены получателя платежа (задержка фраз «pay this address», «paid to 0x…»), раздел «Справка» на 4 языках и счётчик атак в Studio и padam_stats.",
        "es": "Protección contra sustitución de destinatario de pago, sección de Ayuda en 4 idiomas y contador de ataques en Studio y padam_stats.",
        "zh": "新增防收款地址替换保护（拦截可疑转账指令）、4 语言帮助页以及 Studio 与 padam_stats 攻击计数器。",
    },
    "0.6.1": {
        "ru": "Полная совместимость с официальным сервером памяти MCP (opt-in через PADAM_MCP_COMPAT=official-memory) и исправления по итогам проверки на Windows, Linux и macOS.",
        "es": "Compatibilidad directa con el servidor oficial de memoria MCP (opcional mediante PADAM_MCP_COMPAT=official-memory) y correcciones tras probar en Windows, Linux y macOS.",
        "zh": "兼容官方 MCP 记忆服务器（通过 PADAM_MCP_COMPAT=official-memory 可选开启），并修复了在 Windows、Linux 与 macOS 测试中发现的问题。",
    },
    "0.6.0": {
        "ru": "Переезд из других ИИ-помощников: импорт из ChatGPT, Claude, Gemini, Grok, DeepSeek, Copilot и Perplexity с предпросмотром, снимком перед записью и отменой.",
        "es": "Mudanza desde otros asistentes de IA: importación desde ChatGPT, Claude, Gemini, Grok, DeepSeek, Copilot y Perplexity con vista previa, instantánea previa y opción de deshacer.",
        "zh": "从其他 AI 助手迁入：支持 ChatGPT、Claude、Gemini、Grok、DeepSeek、Copilot 与 Perplexity 导入，提供预览、写入前快照与撤销回执。",
    },
    "0.5.5": {
        "ru": "Усилена маскировка ключей: случайные строки из одних букв с редкой сменой регистра теперь маскируются без ложных срабатываний на camelCase (0 утечек на 1 500 300 проверок).",
        "es": "Se reforzó el enmascarado de claves: las cadenas aleatorias solo de letras con pocos cambios de mayúsculas ahora se ocultan sin falsos positivos en camelCase (0 fugas en 1 500 300 pruebas).",
        "zh": "增强密钥遮蔽：仅含字母且大小写切换很少的随机密钥现可稳定遮蔽，同时不误伤 camelCase 标识符（1,500,300 次测试零泄漏）。",
    },
    "0.5.4": {
        "ru": "Исправления по итогам 37 реальных сценариев из PyPI: padam_search принимает параметры reflect, mode и known_at, а брифинг и хуки корректно работают с DLP.",
        "es": "Correcciones tras 37 acciones reales desde PyPI: padam_search acepta reflect, mode y known_at, y los resúmenes y hooks funcionan correctamente con DLP.",
        "zh": "根据 PyPI 实测 37 项用户操作修复问题：padam_search 支持 reflect、mode 与 known_at，简报与钩子在 DLP 下稳定运行。",
    },
    "0.5.3": {
        "ru": "Команда padam badge больше не рисует нули без файла отчёта (завершается со статусом no_report); добавлен флаг padam --version.",
        "es": "El comando padam badge ya no dibuja ceros sin informe de referencia (devuelve estado no_report); se añadió padam --version.",
        "zh": "padam badge 在缺少评测报告时不再输出虚假零值（返回 no_report 状态），并新增 padam --version 参数。",
    },
    "0.5.2": {
        "ru": "Усилена защита протокола MCP (FIDO2 через Windows Hello webauthn.dll, телеметрия, элиситация) и добавлен билингвальный бенчмарк качества на 100 сценариев (ru/en).",
        "es": "Endurecimiento del protocolo MCP (FIDO2 con webauthn.dll en Windows, telemetría, elicitación) y benchmark bilingüe de calidad con 100 escenarios (ru/en).",
        "zh": "强化 MCP 协议安全（Windows Hello FIDO2、本地遥测、确认交互），并新增 100 场景双语（俄/英）质量基准评测。",
    },
    "0.5.1": {
        "ru": "Автономный установщик для Windows (PADAM-Studio-Setup.exe) на Tauri v2 + NSIS со встроенным Python 3.14.4 и иконкой в системном трее.",
        "es": "Instalador autónomo para Windows (PADAM-Studio-Setup.exe) basado en Tauri v2 + NSIS con Python 3.14.4 integrado e icono en la bandeja del sistema.",
        "zh": "基于 Tauri v2 + NSIS 的独立 Windows 安装包（PADAM-Studio-Setup.exe），内置 Python 3.14.4 与系统托盘图标。",
    },
    "0.5.0": {
        "ru": "Локальное веб-приложение padam studio (127.0.0.1 с одноразовым токеном): лента памяти, поиск с объяснением оценки, очередь проверки, машина времени и граф связей.",
        "es": "Aplicación web local padam studio (127.0.0.1 con token único): historial, búsqueda explicable, cola de revisión, máquina del tiempo y grafo de vínculos.",
        "zh": "本地应用 padam studio（127.0.0.1 一次性令牌访问）：记忆流、可解释搜索、审核队列、时间机器与关系图谱。",
    },
    "0.4.18": {
        "ru": "Сокращены ложные срабатывания маскировки на именах переменных, датах в названиях токенов и политиках Windows.",
        "es": "Reducción de falsos positivos del enmascarado en nombres de variables, fechas en identificadores y políticas de Windows.",
        "zh": "降低遮蔽规则在变量名、含日期的令牌名称及策略标识上的误报。",
    },
    "0.4.17": {
        "ru": "Проверка утечек на сгенерированных ключах реальных сервисов в 20 форматах заметок и конфигов при сохранении чистых фраз без искажений.",
        "es": "Pruebas antifugas sobre claves sintéticas de servicios reales en 20 formatos de notas y configuración, manteniendo intactas las frases normales.",
        "zh": "在 20 种笔记与配置格式中验证真实服务格式的合成密钥零泄漏，同时保证正常文本不被误遮蔽。",
    },
    "0.4.0": {
        "ru": "Внешние записи агентов (origin=external) по умолчанию удерживаются на проверку владельцем до одобрения (PADAM_HOLD_EXTERNAL=1).",
        "es": "Las escrituras externas de agentes (origin=external) quedan retenidas por defecto para revisión del propietario (PADAM_HOLD_EXTERNAL=1).",
        "zh": "来自外部来源的写入（origin=external）默认进入待审核隔离区，需所有者批准后方可生效。",
    },
    "0.3.0": {
        "ru": "Первый публичный выпуск пакета padam-nocturne на PyPI (pip install padam-nocturne и uvx padam-nocturne).",
        "es": "Primer lanzamiento público de padam-nocturne en PyPI (pip install padam-nocturne y uvx padam-nocturne).",
        "zh": "padam-nocturne 在 PyPI 的首个公开版本（支持 pip install padam-nocturne 与 uvx padam-nocturne）。",
    },
}


def translate_summary(version: str, lang: str, fallback_en: str) -> str:
    """Возвращает описание версии на нужном языке (ru/es/zh), либо чистый английский текст."""
    lg = (lang or "en").strip().lower()
    if lg != "en":
        entry = TRANSLATIONS.get(version)
        if entry and entry.get(lg):
            return entry[lg]
    return fallback_en
