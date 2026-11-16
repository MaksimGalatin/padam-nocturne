"""Переводы кратких описаний версий для вкладки «Справка» PADAM Studio (ru / es / zh).

Если для старой версии перевода нет, используется очищенный английский текст из help_versions.py.
Ни одна строка не содержит обратных кавычек (`) и не оканчивается двоеточием (:).
"""
from __future__ import annotations

TRANSLATIONS: dict[str, dict[str, str]] = {
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
