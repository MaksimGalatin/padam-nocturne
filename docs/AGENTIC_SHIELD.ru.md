# PADAM Agentic Shield — Защита агентской памяти и веб-периметра ($0)

Локальная детерминированная система активной безопасности от атак ИИ-агентов на скорости машин, отравления памяти, атак MCP (`Tool Poisoning` и `Rug-Pull`), невидимой стеганографии Юникода, подмены реквизитов и взлома цепочек поставки фронтенд-скриптов (кейс Optimizely CDN). Работает **без облачной телеметрии**.

- **Лицензирование:** ядро под `AGPL-3.0-only`, CI/CD GitHub Action (`.github/actions/padam-agentic-shield/`) под `Apache-2.0`, корпоративная коммерческая лицензия от **CODE Eternal LLC** — см. [`COMMERCIAL-LICENSE.md`](../COMMERCIAL-LICENSE.md) и [`LICENSING.md`](LICENSING.md).
- **Стандарты и конкуренты:** [`COMPLIANCE_MAPPING.md`](COMPLIANCE_MAPPING.md) (OWASP ASI01–ASI10 и PCI DSS v4.0.1) и [`COMPETITIVE_COMPARISON.md`](COMPETITIVE_COMPARISON.md).

## 4 кольца обороны (фактически реализованные модули)

| Направление | Что защищает и как устроено | Модуль |
|---|---|---|
| **1. Инспекция Юникода и MCP-инструментов** | Декодирование скрытых инструкций из тегов Юникода (`U+E0020..U+E007E`), перехват Bidi Trojan Source, смешанных алфавитов и вложенного Base64/Hex; аудит описаний MCP-инструментов и SHA-256 пиннинг эталонов в `shield_mcp_tool_pins` против атак Rug-Pull | [`padam/agentic_shield.py`](../padam/agentic_shield.py) |
| **2. Аварийный Kill Switch на скорости машин** | Скользящее окно аномалий и ограничитель всплесков вызовов MCP мгновенно включают строгий режим (`PADAM_STRICT=1`), блокируют исходящие вызовы до ручного снятия владельцем в Studio/CLI | [`padam/agentic_shield.py`](../padam/agentic_shield.py) |
| **3. Гейт исходящих и Payee-Swap Firewall** | Проверка EVM/BTC/Solana/TRON кошельков, IBAN mod-97, карт (Luhn), typosquatting доменов (`Levenshtein <= 2`), высокоэнтропийных токенов, SSRF и shell-команд по профилям `balanced`, `strict_fin`, `paranoid_airgap` | [`padam/agentic_shield.py`](../padam/agentic_shield.py), [`padam/net_guard.py`](../padam/net_guard.py) |
| **4. JS Supply-Chain Guard, PCI DSS 4.0.1 и SIEM** | Проверка `<script>` на SRI (`sha384`), CSP, дрейф SHA-256 на CDN (`shield_js_baselines`), дрейф защитных HTTP-заголовков (`shield_header_baselines`, **PCI DSS 4.0.1 Req 6.4.3 & 11.6.1**), скрытые iframe, DOM-скиммеры, экспорт **SARIF 2.1.0**, корпоративные вебхуки **Slack / Teams / CEF / Splunk HEC / Elastic ECS** и **Proof Pack** | [`padam/supply_chain_guard.py`](../padam/supply_chain_guard.py), [`padam/siem_webhook.py`](../padam/siem_webhook.py), [`.github/actions/padam-agentic-shield/`](../.github/actions/padam-agentic-shield/action.yml) |

## Быстрый старт (CLI)

```bash
# Проверка сайта с генерацией 1-страничного HTML-чекапа и SARIF 2.1.0 для GitHub
padam shield scan-site https://example.com --out-html checkup.html --out-sarif shield.sarif

# Проверка MCP-конфига на Tool Poisoning и закрепление доверенных хэшей от Rug-Pull
padam shield scan-mcp ~/.claude.json --server claude --pin

# Тестовый предпросмотр корпоративного вебхука (Slack / Teams / CEF / Splunk / ECS)
padam shield webhook-test --format slack

# Чистые чаты по каждому агенту и построение хронологического графа
padam chats import-history
padam chats list
```
