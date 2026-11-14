# Черновик сравнительного блока для страницы aifa.works/nocturne (Б1)

Дата сверки по открытым README: **14.11.2026**.
Правило проверки: каждая строка о конкуренте ссылается на его собственный открытый README на GitHub по состоянию на 14.11.2026; каждое утверждение о PADAM NOCTURNE ссылается на конкретный файл тестов или замеров в репозитории `MaksimGalatin/padam-nocturne`.

---

## 1. Русская версия (RU)

### PADAM · NOCTURNE против памяти для агентов без защиты

Большинство систем памяти для ИИ-агентов решают задачу **поиска и накопления**, но доверяют тексту, который принёс агент. Если агент прочитал веб-страницу со спрятанным приказом или случайно увидел ключ API, пароль или сид-фразу кошелька Solana, обычная память запишет их на диск или отправит в облако поставщика модели.

**PADAM · NOCTURNE** устроен иначе:
- **$0 на запись, 0 вызовов внешних моделей:** один локальный файл SQLite у вас на компьютере; ничего не уходит наружу.
- **Память, которая сторожит себя сама:** спрятанные приказы удерживаются до решения владельца (`PADAM_STRICT=1`), ключи API, сид-фразы Solana и банковские карты закрываются маской `[REDACTED:...]` до записи на диск, а при включённом `PADAM_MASK_PII=1` маскируются также адреса почты и телефоны.
- **Доказуемое удаление одной записи (`padam forget --receipt`):** каждая запись шифруется собственным ключом AES-256-GCM; при удалении ключ уничтожается навсегда, а владелец получает криптографическую квитанцию (доказательство удаления) в JSON и печатном HTML.

| Система (открытый README на 14.11.2026) | Удержание приказов на проверку + ограда данных | Маскировка ключей, кошельков Solana и карт до диска | Удаление одной записи уничтожением ключа + квитанция | Проверяемая неизменность снимка (Solana + Bitcoin OTS) | Две даты у записи (`last_seen_at` и `last_confirmed_at`) | Подпись владельца на записях «кто я» + доли Шамира |
|---|---|---|---|---|---|---|
| **PADAM · NOCTURNE** | **Да** ([`test_safety.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_safety.py), [`redteam/`](https://github.com/MaksimGalatin/padam-nocturne/tree/main/redteam)) | **Да** ([`test_solana_wallet_keys_0417.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_solana_wallet_keys_0417.py)) | **Да** ([`test_studio_1411.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_studio_1411.py), [`test_l3_anchor.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_l3_anchor.py)) | **Да** ([`test_l3_anchor.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_l3_anchor.py)) | **Да** ([`test_nocturne.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_nocturne.py)) | **Да** ([`test_keyvault.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_keyvault.py)) |
| [mem0](https://github.com/mem0ai/mem0#readme) | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Не указано в README |
| [Zep](https://github.com/getzep/zep#readme) / [Graphiti](https://github.com/getzep/graphiti#readme) | В README Graphiti прямо указано, что эталонные серверы не обнаруживают и не блокируют prompt injection | Не указано в README | Не указано в README | Не указано в README | Окна действия фактов в графе; двух дат подтверждения нет | Не указано в README |
| [Letta](https://github.com/letta-ai/letta#readme) | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Не указано в README |
| [Supermemory](https://github.com/supermemoryai/supermemory#readme) | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Автозабывание устаревшего; двух дат подтверждения в README нет | Не указано в README |
| [Basic Memory](https://github.com/basicmachines-co/basic-memory#readme) | Не указано в README | Не указано в README | Файлы Markdown; уничтожения ключа записи нет | Не указано в README | Не указано в README | Не указано в README |
| [mcp-memory-service](https://github.com/doobidoo/mcp-memory-service#readme) | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Управляемое угасание; двух дат подтверждения в README нет | Не указано в README |
| [cognee](https://github.com/topoteretes/cognee#readme) | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Не указано в README |
| [Caura](https://github.com/caura-ai/caura#readme) | Уровни доверия агентов (`0`–`3`); очереди удержания приказов в README нет | Помечает `contains_pii`; маскировка до диска в README не указана | Не указано в README | Не указано в README | Не указано в README | Не указано в README |
| [SAIHM](https://github.com/SAIHM-Admin/demo-claude-code#readme) | Не указано в README | Шифрование на клиенте; маскировка до шифрования не указана | Заявлено уничтожение ключа в облаке (выводы стирает клиент; у нас `forget --with-derived`) | Заявлен учёт в сети COTI | Не указано в README | Не указано в README |
| [Mnemoverse](https://github.com/mnemoverse/claude-plugin#readme) | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Не указано в README | Не указано в README |

---

## 2. English Version (EN)

### PADAM · NOCTURNE vs. Unprotected Agent Memory

Most agent memory systems focus on **retrieval and accumulation** while trusting whatever text the agent brings back. When an agent reads a web page containing a hidden prompt injection or sees an API key, password, or Solana wallet seed phrase, unprotected memory writes it straight to disk or sends it to a model provider's cloud.

**PADAM · NOCTURNE** is built as a self-defending memory:
- **$0 per write, 0 external LLM calls required:** lives in one local SQLite file on your machine; nothing leaves your computer unless you anchor encrypted snapshots to L3.
- **Holds orders, masks secrets before disk:** hidden instructions wait for owner approval (`PADAM_STRICT=1`), 20+ secret formats, Solana wallet keys, and payment cards are masked as `[REDACTED:...]` before reaching SQLite, and `PADAM_MASK_PII=1` optionally masks emails and phone numbers.
- **Single-record crypto-shredding with a receipt (`padam forget --receipt`):** each record has its own AES-256-GCM key; forgetting wipes local copies, destroys that key forever, and issues a JSON/HTML proof of deletion.

| System (public README, 14 Nov 2026) | Holds injected orders for owner review + data fence | Masks API keys, Solana wallets & cards before disk | Single-record crypto-shredding + deletion receipt | Public immutability proof (Solana + Bitcoin OTS) | Two clocks (`last_seen_at` vs `last_confirmed_at`) | Owner signature on `identity` / `preference` + Shamir legacy |
|---|---|---|---|---|---|---|
| **PADAM · NOCTURNE** | **Yes** ([`test_safety.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_safety.py), [`redteam/`](https://github.com/MaksimGalatin/padam-nocturne/tree/main/redteam)) | **Yes** ([`test_solana_wallet_keys_0417.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_solana_wallet_keys_0417.py)) | **Yes** ([`test_studio_1411.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_studio_1411.py), [`test_l3_anchor.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_l3_anchor.py)) | **Yes** ([`test_l3_anchor.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_l3_anchor.py)) | **Yes** ([`test_nocturne.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_nocturne.py)) | **Yes** ([`test_keyvault.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_keyvault.py)) |
| [mem0](https://github.com/mem0ai/mem0#readme) | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Not stated in README |
| [Zep](https://github.com/getzep/zep#readme) / [Graphiti](https://github.com/getzep/graphiti#readme) | Graphiti README explicitly notes reference servers do not detect or block prompt injection | Not stated in README | Not stated in README | Not stated in README | Bi-temporal graph edges; no confirmation-only decay clock | Not stated in README |
| [Letta](https://github.com/letta-ai/letta#readme) | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Not stated in README |
| [Supermemory](https://github.com/supermemoryai/supermemory#readme) | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Auto-forgetting; no two-clock confirmation split in README | Not stated in README |
| [Basic Memory](https://github.com/basicmachines-co/basic-memory#readme) | Not stated in README | Not stated in README | Local Markdown files; no per-record key destruction receipt | Not stated in README | Not stated in README | Not stated in README |
| [mcp-memory-service](https://github.com/doobidoo/mcp-memory-service#readme) | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Scheduled decay; no two-clock confirmation split in README | Not stated in README |
| [cognee](https://github.com/topoteretes/cognee#readme) | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Not stated in README |
| [Caura](https://github.com/caura-ai/caura#readme) | Agent trust levels (`0`–`3`); no held-write owner queue for prompt injection in README | Flags `contains_pii`; pre-disk masking not stated in README | Not stated in README | Not stated in README | Not stated in README | Not stated in README |
| [SAIHM](https://github.com/SAIHM-Admin/demo-claude-code#readme) | Not stated in README | Client-side encryption; pre-encryption secret masking not stated | States cloud crypto-shredding (derived cleanup left to client; PADAM has `forget --with-derived`) | States accounting in COTI network | Not stated in README | Not stated in README |
| [Mnemoverse](https://github.com/mnemoverse/claude-plugin#readme) | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Not stated in README | Not stated in README |

---

## 3. Versión en Español (ES)

### PADAM · NOCTURNE frente a la memoria para agentes sin protección

La mayoría de los sistemas de memoria para agentes de IA se centran en **buscar y acumular**, confiando ciegamente en cualquier texto que traiga el agente. Si el agente lee una página web con una orden oculta o ve una clave API, una tarjeta o una semilla de billetera Solana, una memoria sin protección la guarda en el disco o la envía a la nube.

| Sistema (README público al 14.11.2026) | Retiene órdenes ocultas para revisión + cerco de datos | Enmascara claves API, billeteras Solana y tarjetas antes del disco | Olvido de un registro destruyendo su clave + recibo de eliminación | Prueba pública de inmutabilidad (Solana + Bitcoin OTS) | Dos relojes por registro (`last_seen_at` y `last_confirmed_at`) | Firma del propietario en `identity` / `preference` + Shamir |
|---|---|---|---|---|---|---|
| **PADAM · NOCTURNE** | **Sí** ([`test_safety.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_safety.py), [`redteam/`](https://github.com/MaksimGalatin/padam-nocturne/tree/main/redteam)) | **Sí** ([`test_solana_wallet_keys_0417.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_solana_wallet_keys_0417.py)) | **Sí** ([`test_studio_1411.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_studio_1411.py), [`test_l3_anchor.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_l3_anchor.py)) | **Sí** ([`test_l3_anchor.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_l3_anchor.py)) | **Sí** ([`test_nocturne.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_nocturne.py)) | **Sí** ([`test_keyvault.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_keyvault.py)) |
| [mem0](https://github.com/mem0ai/mem0#readme) | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README |
| [Zep](https://github.com/getzep/zep#readme) / [Graphiti](https://github.com/getzep/graphiti#readme) | El README de Graphiti indica expresamente que sus servidores de referencia no detectan ni bloquean prompt injection | No indicado en el README | No indicado en el README | No indicado en el README | Ventanas de validez en el grafo; sin reloj de confirmación separado | No indicado en el README |
| [Letta](https://github.com/letta-ai/letta#readme) | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README |
| [Supermemory](https://github.com/supermemoryai/supermemory#readme) | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | Olvido automático; sin separación de dos relojes en el README | No indicado en el README |
| [Basic Memory](https://github.com/basicmachines-co/basic-memory#readme) | No indicado en el README | No indicado en el README | Archivos Markdown locales; sin destrucción de clave por registro | No indicado en el README | No indicado en el README | No indicado en el README |
| [mcp-memory-service](https://github.com/doobidoo/mcp-memory-service#readme) | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | Consolidación programada; sin dos relojes en el README | No indicado en el README |
| [cognee](https://github.com/topoteretes/cognee#readme) | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README |
| [Caura](https://github.com/caura-ai/caura#readme) | Niveles de confianza (`0`–`3`); sin cola de revisión de órdenes en el README | Marca `contains_pii`; sin enmascarado previo al disco en el README | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README |
| [SAIHM](https://github.com/SAIHM-Admin/demo-claude-code#readme) | No indicado en el README | Cifrado en el cliente; sin enmascarado de secretos previo en el README | Declara destrucción de clave en la nube (derivados a cargo del cliente; PADAM tiene `forget --with-derived`) | Declara registro en la red COTI | No indicado en el README | No indicado en el README |
| [Mnemoverse](https://github.com/mnemoverse/claude-plugin#readme) | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README | No indicado en el README |

---

## 4. 中文版 (ZH)

### PADAM · NOCTURNE 对比无防护的智能体记忆系统

大多数 AI 智能体记忆系统只关注**检索与累积**，默认信任智能体写入的任何文本。如果智能体读取了带有隐藏指令的网页，或在对话中接触到 API 密钥、银行卡号或 Solana 钱包助记词，无防护的记忆系统会将其直接写入磁盘或发送到云端模型服务商。

| 系统（截至 2026-11-14 的公开 README） | 拦截隐藏指令待主人审核 + 数据围栏 | 落盘前掩码 API 密钥、Solana 钱包与银行卡 | 单条记录密钥销毁遗忘 + 删除证明回执 | 公开不可篡改证明（Solana 默克尔根 + Bitcoin OTS） | 双时钟机制（`last_seen_at` 与 `last_confirmed_at`） | `identity` / `preference` 主人签名 + Shamir 密钥分片 |
|---|---|---|---|---|---|---|
| **PADAM · NOCTURNE** | **支持** ([`test_safety.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_safety.py), [`redteam/`](https://github.com/MaksimGalatin/padam-nocturne/tree/main/redteam)) | **支持** ([`test_solana_wallet_keys_0417.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_solana_wallet_keys_0417.py)) | **支持** ([`test_studio_1411.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_studio_1411.py), [`test_l3_anchor.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_l3_anchor.py)) | **支持** ([`test_l3_anchor.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_l3_anchor.py)) | **支持** ([`test_nocturne.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_nocturne.py)) | **支持** ([`test_keyvault.py`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/tests/test_keyvault.py)) |
| [mem0](https://github.com/mem0ai/mem0#readme) | README 未提及 | README 未提及 | README 未提及 | README 未提及 | README 未提及 | README 未提及 |
| [Zep](https://github.com/getzep/zep#readme) / [Graphiti](https://github.com/getzep/graphiti#readme) | Graphiti README 明确说明其参考服务器不检测也不拦截提示词注入 | README 未提及 | README 未提及 | README 未提及 | 图谱事实有效期窗口；无仅按确认计算的衰减时钟 | README 未提及 |
| [Letta](https://github.com/letta-ai/letta#readme) | README 未提及 | README 未提及 | README 未提及 | README 未提及 | README 未提及 | README 未提及 |
| [Supermemory](https://github.com/supermemoryai/supermemory#readme) | README 未提及 | README 未提及 | README 未提及 | README 未提及 | 自动遗忘过期事实；README 未提及双时钟分离 | README 未提及 |
| [Basic Memory](https://github.com/basicmachines-co/basic-memory#readme) | README 未提及 | README 未提及 | 本地 Markdown 文件；无单条记录密钥销毁回执 | README 未提及 | README 未提及 | README 未提及 |
| [mcp-memory-service](https://github.com/doobidoo/mcp-memory-service#readme) | README 未提及 | README 未提及 | README 未提及 | README 未提及 | 定时衰减整合；README 未提及双时钟分离 | README 未提及 |
| [cognee](https://github.com/topoteretes/cognee#readme) | README 未提及 | README 未提及 | README 未提及 | README 未提及 | README 未提及 | README 未提及 |
| [Caura](https://github.com/caura-ai/caura#readme) | 智能体信任等级 (`0`–`3`)；README 未提及指令拦截审核队列 | 标记 `contains_pii`；README 未提及落盘前掩码 | README 未提及 | README 未提及 | README 未提及 | README 未提及 |
| [SAIHM](https://github.com/SAIHM-Admin/demo-claude-code#readme) | README 未提及 | 客户端加密；README 未提及加密前掩码秘密 | 声明支持云端密钥销毁（派生数据需客户端自行清理；PADAM 提供 `forget --with-derived`） | 声明在 COTI 网络记账 | README 未提及 | README 未提及 |
| [Mnemoverse](https://github.com/mnemoverse/claude-plugin#readme) | README 未提及 | README 未提及 | README 未提及 | README 未提及 | README 未提及 | README 未提及 |
