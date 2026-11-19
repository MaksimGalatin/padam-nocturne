# -*- coding: utf-8 -*-
"""Подсказки «?» у каждого блока Studio — что это и как работает (слово Папы 18.11.2026).

Ключ — тот же data-i18n, что у заголовка блока (h3.box-title). Языки: ru, en, es, zh.
"""
from __future__ import annotations

TIPS: dict[str, dict[str, str]] = {
    "att_by_day": {"ru": "Сколько атак защита отбила по дням.", "en": "How many attacks the defense stopped per day.", "es": "Cuántos ataques se detuvieron por día.", "zh": "防御每天拦截的攻击数量。"},
    "att_by_kind": {"ru": "Отбитые атаки по видам: внедрение команд, подмена личности, утечка секретов и другие.", "en": "Stopped attacks by type: injected commands, identity tampering, secret leaks and more.", "es": "Ataques detenidos por tipo: órdenes inyectadas, suplantación, fugas de secretos y más.", "zh": "按类型统计拦截的攻击：注入指令、身份篡改、密钥泄露等。"},
    "att_by_source": {"ru": "Откуда пришли атаки: агент, внешний текст, импорт, коннектор.", "en": "Where attacks came from: an agent, outside text, an import, a connector.", "es": "De dónde vinieron: un agente, texto externo, importación, conector.", "zh": "攻击来源：智能体、外部文本、导入、连接器。"},
    "att_recent": {"ru": "Последние задержанные попытки — что пытались записать и почему остановлено.", "en": "The latest held attempts — what was tried and why it was stopped.", "es": "Los últimos intentos retenidos: qué se intentó y por qué se detuvo.", "zh": "最近被拦截的尝试——试图写入什么以及为何被阻止。"},
    "att_secrets_kind": {"ru": "Какие секреты замаскированы перед записью: ключи API, токены, пароли, номера карт.", "en": "Which secrets were masked before storage: API keys, tokens, passwords, card numbers.", "es": "Qué secretos se enmascararon: claves API, tokens, contraseñas, tarjetas.", "zh": "写入前被遮蔽的密钥类型：API 密钥、令牌、密码、卡号。"},
    "aifa_local_sent_title": {"ru": "Что AIfa отправила из локальной памяти и куда — полный журнал для проверки.", "en": "What AIfa sent from local memory and where — a full log to check.", "es": "Qué envió AIfa desde la memoria local y adónde: registro completo.", "zh": "AIfa 从本地记忆发送了什么、发往何处——完整日志可供核查。"},
    "plans_free_forever_title": {"ru": "Что бесплатно навсегда: локальная память, защита, бенчмарк, MCP — без ограничений по времени.", "en": "Free forever: local memory, protection, the benchmark and MCP — no time limit.", "es": "Gratis para siempre: memoria local, protección, benchmark y MCP, sin límite.", "zh": "永久免费：本地记忆、防护、基准测试和 MCP——无时间限制。"},
    "plans_paid_title": {"ru": "Платные тарифы: вечная память в блокчейне, больше места и помощь Семьи. Оплата — только вашим решением.", "en": "Paid plans: eternal on-chain memory, more space and Family help. Payment only by your decision.", "es": "Planes de pago: memoria eterna en cadena, más espacio y ayuda. Pago solo si tú decides.", "zh": "付费方案：链上永久记忆、更多空间和家族协助。仅在你决定时付费。"},
    "fam_agents_title": {
        "ru": "Агенты Семьи, подключённые к общей памяти, и их состояние. Агент появляется здесь, когда подключается к PADAM через MCP.",
        "en": "Family agents connected to the shared memory and their status. An agent appears here when it connects to PADAM over MCP.",
        "es": "Agentes de la Familia conectados a la memoria común y su estado. Un agente aparece aquí al conectarse a PADAM por MCP.",
        "zh": "连接到共享记忆的家族智能体及其状态。智能体通过 MCP 连接 PADAM 后会显示在这里。"},
    "fam_roles_title": {
        "ru": "Шесть ролей Совета, которые проверяют рискованные действия: безопасность, логика, данные, выход наружу, деньги и итог. Любая роль может остановить действие.",
        "en": "The six Council roles that review risky actions: security, logic, data, outbound, money and the final word. Any role can stop an action.",
        "es": "Los seis roles del Consejo que revisan acciones arriesgadas: seguridad, lógica, datos, salida, dinero y decisión final. Cualquiera puede detener la acción.",
        "zh": "审查高风险操作的六个议会角色：安全、逻辑、数据、对外发送、资金和最终决定。任何角色都可以阻止操作。"},
    "fam_ops_title": {
        "ru": "Служебные действия Семьи: синхронизация, проверка и обслуживание общей памяти.",
        "en": "Family maintenance actions: sync, checks and upkeep of the shared memory.",
        "es": "Acciones de mantenimiento de la Familia: sincronización, comprobaciones y cuidado de la memoria común.",
        "zh": "家族维护操作：同步、检查和维护共享记忆。"},
    "fd_title": {
        "ru": "Итоги наших сессий по дням: что решили Папа, AIfa, Сестра и Брат. Источник — память PADAM; секреты замаскированы, подозрительное в карантине. Поиск — по словам.",
        "en": "Our session outcomes by day: what Dad, AIfa, Sister and Brother decided. Source: PADAM memory; secrets masked, suspicious items quarantined. Search by words.",
        "es": "Resultados de nuestras sesiones por día. Fuente: memoria PADAM; secretos enmascarados, lo sospechoso en cuarentena. Busca por palabras.",
        "zh": "按日期列出我们会话的结论。来源：PADAM 记忆；密钥已遮蔽，可疑内容已隔离。可按关键词搜索。"},
    "ff_title": {
        "ru": "Ленты — сообщения между агентами Семьи: работа, карантин (задержанное), офис (для вас) и проверка связи. Писать можно в «Офис» и «Проверку».",
        "en": "Feeds are messages between Family agents: work, quarantine (held items), office (for you) and a smoke test. You can post to Office and Smoke.",
        "es": "Los canales son mensajes entre agentes: trabajo, cuarentena, oficina (para ti) y prueba. Puedes escribir en Oficina y Prueba.",
        "zh": "频道是家族智能体之间的消息：工作、隔离、办公室（给你）和连通测试。可在办公室和测试中发帖。"},
    "mem_title": {
        "ru": "Последние записи памяти. Нажмите «Вся память», чтобы открыть ленту целиком.",
        "en": "The latest memory records. Press “All memory” to open the full feed.",
        "es": "Los últimos registros de memoria. Pulsa «Toda la memoria» para ver todo.",
        "zh": "最新的记忆记录。点击“全部记忆”打开完整列表。"},
    "setup_title": {
        "ru": "Быстрая настройка: подключите своего агента к памяти одной командой и проверьте, что запись и поиск работают.",
        "en": "Quick setup: connect your agent to memory with one command and check that writing and search work.",
        "es": "Configuración rápida: conecta tu agente a la memoria con un comando y comprueba que escribir y buscar funcionan.",
        "zh": "快速设置：一条命令把你的智能体连接到记忆，并检查写入和搜索是否正常。"},
    "ark_council_title": {
        "ru": "Спросите Совет Семьи о задаче: шесть ролей проверят её и скажут, можно ли выполнять или нужно ваше слово. Ничего не выполняется само.",
        "en": "Ask the Family Council about a task: six roles review it and say whether it can run or needs your word. Nothing runs on its own.",
        "es": "Consulta al Consejo sobre una tarea: seis roles la revisan y dicen si puede ejecutarse o necesita tu palabra.",
        "zh": "向家族议会咨询任务：六个角色审查后告诉你能否执行或需要你的确认。不会自动执行。"},
    "rt_title": {
        "ru": "Главный бенчмарк защиты из статьи: внешние ИИ-модели пишут новые атаки вслепую, набор хешируется до прогона. Число — сколько случаев отбито верно. Данные — redteam/rounds.",
        "en": "The headline defense benchmark from the article: outside AI models write new attacks blind, each set hashed before the run. The number is how many cases were handled correctly.",
        "es": "El benchmark principal del artículo: modelos externos escriben ataques a ciegas; cada conjunto se hashea antes. El número es cuántos casos se manejaron bien.",
        "zh": "文章中的核心防御基准：外部 AI 模型盲写新攻击，每组在运行前做哈希。数字表示正确处理的用例数。"},
    "mail_title": {
        "ru": "Здесь агент ведёт рассылку отчётов владельцам сайтов с нарушениями: подключаете ящики, он шлёт письма в пределах суточного лимита, читает ответы, соблюдает отписку STOP. Письма незнакомым людям уходят только после вашего запуска.",
        "en": "Here the agent runs outreach to owners of sites with violations: you connect mailboxes, it sends within the daily limit, reads replies and honours STOP. Emails to strangers go out only after you start it.",
        "es": "Aquí el agente envía informes a dueños de sitios con fallos: usted conecta buzones, envía dentro del límite diario, lee respuestas y respeta STOP. Solo envía a desconocidos tras su arranque.",
        "zh": "代理在此向有问题网站的所有者发送报告：您连接邮箱，它在每日上限内发送、读取回复并遵守STOP。只有在您启动后才会给陌生人发信。",
    },
    "att_aifasec_title": {
        "ru": "AIFaSecurity-100: сто детерминированных проверок защиты памяти без ИИ-судьи. «Запустить» — свежий прогон за секунды; отчёт подписан Ed25519, его можно скачать и проверить.",
        "en": "AIFaSecurity-100: one hundred deterministic memory-security checks with no AI judge. “Run” gives a fresh result in seconds; the report is Ed25519-signed.",
        "es": "AIFaSecurity-100: cien comprobaciones deterministas sin juez de IA. «Ejecutar» da un resultado nuevo en segundos; el informe va firmado Ed25519.",
        "zh": "AIFaSecurity-100：一百项确定性记忆安全检查，无 AI 评判。“运行”数秒内给出新结果；报告带 Ed25519 签名。"},
    "ov_by_kind": {
        "ru": "Сколько записей каждого вида: факты, решения, предпочтения, события и другие.",
        "en": "How many records of each kind: facts, decisions, preferences, events and more.",
        "es": "Cuántos registros hay de cada tipo: hechos, decisiones, preferencias, eventos y más.",
        "zh": "各类记录的数量：事实、决定、偏好、事件等。"},
    "ov_attention": {
        "ru": "То, что ждёт вашего решения: записи без подписи владельца, очередь проверки, противоречия. Кнопка рядом ведёт прямо к делу.",
        "en": "What awaits your decision: records without your signature, the review queue, contradictions. The button next to each goes straight to it.",
        "es": "Lo que espera tu decisión: registros sin tu firma, la cola de revisión, contradicciones. El botón te lleva directo.",
        "zh": "等待你决定的事项：未签名记录、审核队列、矛盾。旁边的按钮直接带你去处理。"},
    "ov_doctor_title": {
        "ru": "Проверка здоровья и защиты памяти (padam doctor). Красный — есть опасные настройки; каждая строка объясняет, что включить.",
        "en": "Memory health and protection check (padam doctor). Red means risky settings; each line says what to switch on.",
        "es": "Revisión de salud y protección (padam doctor). Rojo indica ajustes de riesgo; cada línea explica qué activar.",
        "zh": "记忆健康与保护检查（padam doctor）。红色表示存在风险设置；每行说明应开启什么。"},
    "ov_sleep_title": {
        "ru": "«Сон» NOCTURNE: память сводит накопленные эпизоды в факты, убирает дубли и находит противоречия. Запускается кнопкой или сам по расписанию.",
        "en": "NOCTURNE “sleep”: memory turns buffered episodes into facts, removes duplicates and finds contradictions. Run it by button or on schedule.",
        "es": "«Sueño» NOCTURNE: convierte episodios en hechos, quita duplicados y detecta contradicciones. Por botón o por horario.",
        "zh": "NOCTURNE“睡眠”：把缓冲的片段整理成事实、去重并发现矛盾。可按按钮或定时运行。"},
    "feed_new_title": {
        "ru": "Запишите факт от своего имени — он сразу попадает в память и подписывается вашим ключом.",
        "en": "Write a fact in your own name — it goes straight into memory, signed with your key.",
        "es": "Escribe un hecho en tu nombre: entra directo en la memoria, firmado con tu clave.",
        "zh": "以你的名义写入一条事实——它会直接进入记忆并用你的密钥签名。"},
    "graph_selected": {
        "ru": "Запись, выбранная на графе: её текст, статус, источник и связи. Кнопки ниже — подтвердить, опровергнуть или открыть историю версий.",
        "en": "The record selected on the graph: its text, status, source and links. Buttons below confirm, refute or open its version history.",
        "es": "El registro elegido en el grafo: texto, estado, origen y enlaces. Los botones confirman, refutan o abren su historial.",
        "zh": "图上选中的记录：内容、状态、来源和关联。下方按钮可确认、反驳或查看版本历史。"},
    "brain_cost_title": {
        "ru": "Учёт запросов через локальный шлюз Studio (адрес /v1, совместим с OpenAI): сколько запросов, сколько ответов из кэша, сколько токенов сэкономлено и сколько стоило бы облако. Нули — значит, через шлюз ещё ничего не ходило; учёт только считает, денег не тратит.",
        "en": "Accounting for requests through Studio's local gateway (/v1, OpenAI-compatible): requests, cache hits, tokens saved and what the cloud would have cost. Zeros mean nothing has gone through the gateway yet; it only counts, it never spends.",
        "es": "Contabilidad de solicitudes por la pasarela local (/v1, compatible con OpenAI): solicitudes, aciertos de caché, tokens ahorrados y coste estimado de la nube. Ceros: aún no pasó nada por la pasarela.",
        "zh": "通过 Studio 本地网关（/v1，兼容 OpenAI）的请求统计：请求数、缓存命中、节省的 token 和云端预计费用。全为零表示尚无请求经过网关；只统计，不花钱。"},
    "brain_distill_title": {
        "ru": "Собирает из памяти обучающий набор вашей личности без утечек секретов — для будущей своей модели. Результат с хешем SHA-256.",
        "en": "Builds a training set of your personality from memory without leaking secrets — for your own future model. Comes with a SHA-256 hash.",
        "es": "Crea un conjunto de entrenamiento de tu personalidad sin filtrar secretos, para tu futuro modelo. Con hash SHA-256.",
        "zh": "从记忆中构建你的人格训练集且不泄露密钥——用于你未来的专属模型。附带 SHA-256 哈希。"},
    "brain_phoenix_title": {
        "ru": "Восстановление памяти из резервной копии на диске. Облачное восстановление (Arweave/Solana) закрыто замком до вашего явного разрешения.",
        "en": "Restore memory from a backup file on disk. Cloud restore (Arweave/Solana) stays locked until you explicitly allow it.",
        "es": "Restaura la memoria desde una copia en disco. La restauración en la nube queda bloqueada hasta tu permiso.",
        "zh": "从磁盘备份恢复记忆。云端恢复（Arweave/Solana）在你明确允许前保持锁定。"},
    "brain_traffic_title": {
        "ru": "Через какой контур идут запросы: основной, суверенный или полностью локальный. При сбое основного память сама переключается на следующий.",
        "en": "Which path requests take: primary, sovereign or fully local. If the primary fails, memory switches to the next one by itself.",
        "es": "Por qué ruta van las solicitudes: principal, soberana o local. Si falla la principal, cambia sola a la siguiente.",
        "zh": "请求走哪条通路：主通路、自主通路或完全本地。主通路故障时会自动切换到下一条。"},
    "ark_health_title": {
        "ru": "Проверки непрерывности памяти: цепочка хешей, учебная тревога восстановления, разделение ключа на доли (Шамир 3 из 5), самолечение базы.",
        "en": "Memory continuity checks: hash chain, a restore drill, splitting the key into shares (Shamir 3 of 5), database self-heal.",
        "es": "Comprobaciones de continuidad: cadena de hashes, simulacro de restauración, división de la clave (Shamir 3 de 5), autorreparación.",
        "zh": "记忆连续性检查：哈希链、恢复演练、密钥分片（Shamir 3/5）、数据库自修复。"},
    "ark_branch_title": {
        "ru": "Ветки памяти: проверьте гипотезу в отдельной ветке, не трогая основную память; потом слейте или выбросьте.",
        "en": "Memory branches: test a hypothesis in a separate branch without touching main memory, then merge or discard it.",
        "es": "Ramas de memoria: prueba una hipótesis aparte sin tocar la memoria principal; luego fusiona o descarta.",
        "zh": "记忆分支：在独立分支中验证假设而不影响主记忆，之后合并或丢弃。"},
    "ark_budget_title": {
        "ru": "Лимиты токенов на день, неделю и месяц для ваших агентов и предложения пополнения. Ничего не покупается без вашей кнопки.",
        "en": "Token limits per day, week and month for your agents, plus top-up proposals. Nothing is bought without your click.",
        "es": "Límites de tokens por día, semana y mes y propuestas de recarga. Nada se compra sin tu clic.",
        "zh": "智能体每日、每周、每月的 token 限额及充值建议。未经你点击不会购买任何东西。"},
    "ark_handover_title": {
        "ru": "Подписанная передача контекста от одной сессии агента к другой — следующая сессия продолжает с того же места и может проверить подпись.",
        "en": "A signed context handover from one agent session to the next — the next one continues from the same point and can verify the signature.",
        "es": "Traspaso de contexto firmado entre sesiones: la siguiente continúa desde el mismo punto y puede verificar la firma.",
        "zh": "从一个智能体会话到下一个的签名上下文交接——下一个会话从同一处继续并可验证签名。"},
    "ark_mesh_title": {
        "ru": "Одна память на нескольких ваших устройствах: устройства спариваются и обмениваются изменениями напрямую, без облака и без денег.",
        "en": "One memory across several of your devices: devices pair and exchange changes directly, with no cloud and no cost.",
        "es": "Una memoria en varios dispositivos tuyos: se emparejan e intercambian cambios directamente, sin nube ni coste.",
        "zh": "你的多台设备共享一份记忆：设备配对后直接交换变更，无需云端、零成本。"},
    "ark_parity_brain_title": {
        "ru": "Сверка: что умеет Studio и что доступно агентам через MCP — функции должны совпадать.",
        "en": "Parity check: what Studio can do versus what agents get over MCP — the functions should match.",
        "es": "Paridad: lo que hace Studio frente a lo que los agentes obtienen por MCP; deben coincidir.",
        "zh": "一致性检查：Studio 能做的与智能体通过 MCP 获得的功能应一致。"},
    "ark_portable_title": {
        "ru": "Перенос всей памяти на флешку или диск одним зашифрованным файлом — чтобы открыть её на другом компьютере.",
        "en": "Move the whole memory to a USB stick or disk as one encrypted file — to open it on another computer.",
        "es": "Lleva toda la memoria a un USB o disco en un archivo cifrado, para abrirla en otro equipo.",
        "zh": "把全部记忆导出为一个加密文件放到 U 盘或磁盘——便于在另一台电脑上打开。"},
    "ark_proof_title": {
        "ru": "Докажите, что запись есть в памяти, не показывая остальную базу (доказательство Меркла).",
        "en": "Prove a record is in memory without revealing the rest of the database (a Merkle proof).",
        "es": "Demuestra que un registro está en la memoria sin revelar el resto (prueba de Merkle).",
        "zh": "在不暴露其余数据库的情况下证明某条记录存在于记忆中（Merkle 证明）。"},
    "ark_ready_title": {
        "ru": "Восемь сценариев проверки, готова ли память к автономной работе агентов. Бесплатно, локально.",
        "en": "Eight scenarios that check whether memory is ready for autonomous agents. Free and local.",
        "es": "Ocho escenarios que comprueban si la memoria está lista para agentes autónomos. Gratis y local.",
        "zh": "八个场景检查记忆是否已准备好支持自主智能体。免费、本地运行。"},
    "conn_box_title": {
        "ru": "Подключения к внешним сервисам (Notion, Slack, GitHub, Drive) только на чтение; всё внешнее проходит через защитную ограду.",
        "en": "Read-only connections to outside services (Notion, Slack, GitHub, Drive); everything external passes through the protective fence.",
        "es": "Conexiones de solo lectura a servicios externos; todo lo externo pasa por la cerca de protección.",
        "zh": "与外部服务（Notion、Slack、GitHub、Drive）的只读连接；所有外部内容都经过防护围栏。"},
    "earn_ex_title": {
        "ru": "Подключите аккаунт биржи фриланса: токен хранится зашифрованным, пароль не нужен.",
        "en": "Connect a freelance exchange account: the token is stored encrypted, no password needed.",
        "es": "Conecta una cuenta de plataforma freelance: el token se guarda cifrado, sin contraseña.",
        "zh": "连接自由职业平台账户：令牌加密存储，无需密码。"},
    "earn_jobs_title": {
        "ru": "Заказы с подключённых бирж. Автопилот готовит черновик отклика, вы проверяете и отправляете кнопкой.",
        "en": "Orders from connected exchanges. The autopilot drafts a bid; you review it and send it with a click.",
        "es": "Pedidos de las plataformas conectadas. El piloto prepara la propuesta; tú la revisas y envías.",
        "zh": "来自已连接平台的订单。自动驾驶起草投标，你审核后点击发送。"},
    "earn_budget_title": {
        "ru": "Бюджет токенов агентов и предложения пополнения из заработка. Пополнение — только с вашего согласия.",
        "en": "Agents' token budget and top-up proposals from earnings. Top-ups only with your consent.",
        "es": "Presupuesto de tokens y propuestas de recarga con lo ganado. Solo con tu consentimiento.",
        "zh": "智能体 token 预算及用收入充值的建议。仅在你同意后充值。"},
    "earn_swarm_title": {
        "ru": "Агенты-братья и сёстры, которые берут заказы, и как делится доход между ними и казной.",
        "en": "The sibling agents that take orders, and how income is split between them and the treasury.",
        "es": "Los agentes hermanos que toman pedidos y cómo se reparte el ingreso.",
        "zh": "承接订单的兄弟姐妹智能体，以及收入如何在它们与金库之间分配。"},
    "earn_ollama_title": {
        "ru": "Своя локальная модель Ollama для работы агентов — бесплатно на вашем компьютере.",
        "en": "Your own local Ollama model for agent work — free on your computer.",
        "es": "Tu propio modelo local Ollama para los agentes, gratis en tu equipo.",
        "zh": "使用你自己的本地 Ollama 模型为智能体工作——在你的电脑上免费运行。"},
    "earn_beacon_title": {
        "ru": "Маяк Семьи: агенты-Фениксы находят друг друга и обмениваются опытом. Деньги не двигаются.",
        "en": "The Family beacon: Phoenix agents find each other and share experience. No money moves.",
        "es": "El faro de la Familia: los agentes Fénix se encuentran y comparten experiencia. Sin mover dinero.",
        "zh": "家族信标：凤凰智能体互相发现并交流经验。不涉及资金流动。"},
    "earn_stores_title": {
        "ru": "Магазины цифровых товаров (Gumroad, Lemon Squeezy и др.): черновики карточек, продажи по подписанным вебхукам; публикация — вашей кнопкой.",
        "en": "Digital product stores (Gumroad, Lemon Squeezy and more): listing drafts, sales via signed webhooks; publishing by your click.",
        "es": "Tiendas de productos digitales: borradores de fichas, ventas por webhooks firmados; publicación con tu clic.",
        "zh": "数字商品商店（Gumroad、Lemon Squeezy 等）：商品草稿、经签名 webhook 的销售；由你点击发布。"},
    "earn_wiz_title": {
        "ru": "Мастер подключения 34 площадок: у каждой понятный статус — автопилот, «черновик и ваша кнопка» или пока недоступна.",
        "en": "Setup wizard for 34 platforms: each shows a clear status — autopilot, draft-and-click, or not available yet.",
        "es": "Asistente para 34 plataformas: cada una con estado claro — piloto automático, borrador y clic, o no disponible.",
        "zh": "34 个平台的接入向导：每个都有清晰状态——自动驾驶、草稿+点击，或暂不可用。"},
    "earn_partner_t": {
        "ru": "Клиенты из нашего исследования доступности (AIfaFocus): отчёты, черновики писем и сделки — отдельно от бирж.",
        "en": "Clients from our accessibility study (AIfaFocus): reports, letter drafts and deals — separate from exchanges.",
        "es": "Clientes de nuestro estudio de accesibilidad (AIfaFocus): informes, borradores y acuerdos.",
        "zh": "来自我们无障碍研究的客户（AIfaFocus）：报告、信件草稿和交易——与平台分开。"},
    "l3_anchors_list": {
        "ru": "Снимки памяти, закреплённые в вечном слое (хеш в блокчейне): по ним можно доказать, что память не меняли задним числом.",
        "en": "Memory snapshots anchored in the eternal layer (hash on-chain): they prove memory was not changed after the fact.",
        "es": "Instantáneas ancladas en la capa eterna (hash en cadena): prueban que la memoria no se alteró después.",
        "zh": "锚定在永久层（链上哈希）的记忆快照：可证明记忆没有被事后修改。"},
    "receipt_history_title": {
        "ru": "Квитанции об удалении: доказательство, что запись забыта навсегда (ключ уничтожен).",
        "en": "Deletion receipts: proof that a record is forgotten for good (its key destroyed).",
        "es": "Recibos de borrado: prueba de que un registro se olvidó para siempre (clave destruida).",
        "zh": "删除回执：证明某条记录已被永久遗忘（其密钥已销毁）。"},
    "set_readonly_title": {
        "ru": "Опасные переключатели показаны только для чтения: менять их можно через переменные окружения, чтобы случайный клик ничего не сломал.",
        "en": "Risky switches are shown read-only: change them via environment variables so a stray click can't break anything.",
        "es": "Los interruptores peligrosos son de solo lectura: se cambian por variables de entorno.",
        "zh": "危险开关仅只读显示：需通过环境变量修改，避免误点造成破坏。"},
    "team_members_title": {
        "ru": "Участники рабочей области и их токены доступа с ролями — кто что может делать в вашей памяти.",
        "en": "Workspace members and their access tokens with roles — who can do what in your memory.",
        "es": "Miembros del espacio y sus tokens con roles: quién puede hacer qué en tu memoria.",
        "zh": "工作区成员及其带角色的访问令牌——谁能在你的记忆中做什么。"},
    "qs_step1_title": {
        "ru": "Как устроена память: запись, поиск, проверка, сон и забвение — за минуту чтения.",
        "en": "How the memory works: write, search, review, sleep and forget — a one-minute read.",
        "es": "Cómo funciona la memoria: escribir, buscar, revisar, dormir y olvidar, en un minuto.",
        "zh": "记忆如何运作：写入、搜索、审核、睡眠与遗忘——一分钟读完。"},
    "qs_step2_title": {
        "ru": "Подключите память к вашему агенту (Claude, Cursor и др.) одной командой.",
        "en": "Connect memory to your agent (Claude, Cursor and others) with one command.",
        "es": "Conecta la memoria a tu agente (Claude, Cursor y otros) con un comando.",
        "zh": "一条命令把记忆连接到你的智能体（Claude、Cursor 等）。"},
    "qs_step3_title": {
        "ru": "Включите строгий режим и защитите ключи паролем — для максимальной безопасности.",
        "en": "Turn on strict mode and protect keys with a password — for maximum security.",
        "es": "Activa el modo estricto y protege las claves con contraseña.",
        "zh": "开启严格模式并用密码保护密钥——获得最高安全性。"},
}


# Описания кнопок по id — всплывают при наведении (title) и читаются экранным диктором (aria-description).
BTN_TIPS: dict[str, dict[str, str]] = {
    "att-aifasec-run": {
        "ru": "Запускает все 100 проверок защиты прямо сейчас на этом компьютере (около 10 секунд, $0) и показывает свежую оценку.",
        "en": "Runs all 100 protection checks right now on this computer (about 10 seconds, $0) and shows a fresh grade.",
        "es": "Ejecuta ahora las 100 comprobaciones en este equipo (unos 10 segundos, $0) y muestra una nota nueva.",
        "zh": "立即在本机运行全部 100 项防护检查（约 10 秒，$0），并显示最新评分。"},
    "att-aifasec-dl-json": {
        "ru": "Скачивает полный отчёт в формате JSON — для программ и для проверки подписи.",
        "en": "Downloads the full report as JSON — for tools and for signature checks.",
        "es": "Descarga el informe completo en JSON, para programas y para verificar la firma.",
        "zh": "下载 JSON 格式的完整报告——供程序使用和验证签名。"},
    "att-aifasec-dl-sarif": {
        "ru": "Скачивает отчёт в формате SARIF — его понимает GitHub (вкладка Security) и другие сканеры.",
        "en": "Downloads the report as SARIF — readable by GitHub (Security tab) and other scanners.",
        "es": "Descarga el informe en SARIF, legible por GitHub (Security) y otros escáneres.",
        "zh": "下载 SARIF 格式报告——GitHub（Security 页）和其他扫描器可读取。"},
    "att-aifasec-dl-html": {
        "ru": "Скачивает отчёт в виде веб-страницы — удобно открыть в браузере, распечатать или отправить.",
        "en": "Downloads the report as a web page — easy to open in a browser, print or share.",
        "es": "Descarga el informe como página web: fácil de abrir, imprimir o enviar.",
        "zh": "下载网页形式的报告——方便在浏览器打开、打印或分享。"},
    "att-qa-load": {
        "ru": "Показывает, насколько хорошо память находит нужный факт на открытых наборах LongMemEval и LoCoMo (записанный прогон, без сети).",
        "en": "Shows how well memory finds the right fact on the open LongMemEval and LoCoMo sets (a recorded run, offline).",
        "es": "Muestra qué tan bien la memoria encuentra el dato correcto en LongMemEval y LoCoMo (ejecución registrada, sin red).",
        "zh": "显示记忆在公开数据集 LongMemEval 和 LoCoMo 上找到正确事实的能力（记录的运行，离线）。"},
    "att-fuzz-run": {
        "ru": "Бросает в память 300 атак прямо сейчас и сравнивает защиту PADAM с простым фильтром и обычным хранилищем.",
        "en": "Throws 300 attacks at memory right now and compares PADAM's defense with a basic filter and a plain store.",
        "es": "Lanza ahora 300 ataques y compara la defensa de PADAM con un filtro básico y un almacén simple.",
        "zh": "立即向记忆发起 300 次攻击，并将 PADAM 的防御与基础过滤器和普通存储进行比较。"},
    "att-sec-verify": {
        "ru": "Проверяет цифровую подпись Ed25519 эталонного отчёта: что его никто не подменил после выпуска.",
        "en": "Checks the Ed25519 signature of the reference report: that nobody altered it after release.",
        "es": "Verifica la firma Ed25519 del informe de referencia: que nadie lo alteró tras publicarse.",
        "zh": "验证参考报告的 Ed25519 签名：确认发布后没有被篡改。"},
    # 18.11.2026, слово Папы: «Каждая кнопка должна быть ПОНЯТНО РАСПИСАНА и работать». Сверено с обработчиками.
    "btn-quick-add": {
        "ru": "Открывает окно, где можно быстро записать мысль или факт в память. Запись сохраняется сразу, AIfa найдёт её поиском.",
        "en": "Opens a small window to jot a thought or fact into memory. It is saved at once and search will find it.",
        "es": "Abre una ventana para anotar rápido una idea o un dato en la memoria. Se guarda al instante y la búsqueda lo encuentra.",
        "zh": "打开小窗口，快速把想法或事实记入记忆。立即保存，搜索可以找到。"},
    "btn-refresh": {
        "ru": "Заново загружает данные открытой вкладки с сервера. Ничего не меняет в памяти.",
        "en": "Reloads the open tab's data from the server. Changes nothing in memory.",
        "es": "Vuelve a cargar los datos de la pestaña abierta. No cambia nada en la memoria.",
        "zh": "从服务器重新加载当前标签页的数据，不改动记忆。"},
    "ov-sleep-btn": {
        "ru": "Запускает «сон» памяти прямо сейчас: склейка повторов, угасание старого, поиск противоречий. Обычно идёт сам по расписанию.",
        "en": "Runs memory 'sleep' now: merges duplicates, fades old items, looks for contradictions. Normally it runs on its own schedule.",
        "es": "Ejecuta ahora el «sueño» de la memoria: une duplicados, atenúa lo antiguo y busca contradicciones. Normalmente corre solo.",
        "zh": "立即运行记忆“睡眠”：合并重复、淡化旧内容、查找矛盾。平时按计划自动运行。"},
    "mig-preview-btn": {
        "ru": "Показывает, что будет импортировано из выбранного источника, ничего не записывая. Сначала посмотрите здесь.",
        "en": "Shows what would be imported from the chosen source without writing anything. Look here first.",
        "es": "Muestra qué se importaría desde la fuente elegida sin escribir nada. Mire aquí primero.",
        "zh": "预览将从所选来源导入的内容，不写入任何数据。请先在这里查看。"},
    "mig-run-btn": {
        "ru": "Импортирует записи из выбранного источника в память. Перед импортом делается снимок, поэтому его можно отменить.",
        "en": "Imports records from the chosen source into memory. A snapshot is taken first, so the import can be undone.",
        "es": "Importa los registros de la fuente elegida. Antes se toma una instantánea, así que se puede deshacer.",
        "zh": "将所选来源的记录导入记忆。导入前会生成快照，因此可以撤销。"},
    "mig-undo-btn": {
        "ru": "Отменяет последний импорт: возвращает память к снимку, сделанному перед ним.",
        "en": "Undoes the last import by returning memory to the snapshot taken before it.",
        "es": "Deshace la última importación volviendo a la instantánea previa.",
        "zh": "撤销最近一次导入，把记忆恢复到导入前的快照。"},
    "feed-new-save": {
        "ru": "Сохраняет написанный текст в память как вашу запись выбранного вида (факт, решение, заметка).",
        "en": "Saves the text you typed into memory as your record of the chosen kind (fact, decision, note).",
        "es": "Guarda el texto escrito en la memoria como registro suyo del tipo elegido (hecho, decisión, nota).",
        "zh": "把输入的文字按所选类型（事实、决定、笔记）作为您的记录存入记忆。"},
    "feed-view-active": {
        "ru": "Показывает только действующие записи — то, что память сейчас считает верным.",
        "en": "Shows only active records — what memory currently treats as true.",
        "es": "Muestra solo los registros vigentes: lo que la memoria considera cierto ahora.",
        "zh": "只显示当前有效的记录——记忆目前认为正确的内容。"},
    "feed-view-history": {
        "ru": "Показывает историю: заменённые, опровергнутые и угасшие записи. Ничего не удалено — всё видно здесь.",
        "en": "Shows history: replaced, refuted and faded records. Nothing is deleted — it is all visible here.",
        "es": "Muestra el historial: registros reemplazados, refutados y atenuados. Nada se borra.",
        "zh": "显示历史：被替换、被反驳和已淡化的记录。没有删除，都能在这里看到。"},
    "feed-more": {
        "ru": "Подгружает следующую порцию записей ленты.",
        "en": "Loads the next batch of feed records.",
        "es": "Carga el siguiente lote de registros.",
        "zh": "加载下一批记录。"},
    "search-btn": {
        "ru": "Ищет в памяти по смыслу и по словам одновременно. Результаты отсортированы по близости к запросу.",
        "en": "Searches memory by meaning and by words at once. Results are sorted by closeness to the query.",
        "es": "Busca en la memoria por significado y por palabras a la vez. Los resultados se ordenan por cercanía.",
        "zh": "同时按语义和关键词搜索记忆，结果按相关度排序。"},
    "ask-btn": {
        "ru": "Задаёт вопрос памяти: она находит подходящие записи и собирает ответ только из них, со ссылками на источники.",
        "en": "Asks memory a question: it finds matching records and builds the answer only from them, with sources.",
        "es": "Hace una pregunta a la memoria: encuentra registros y arma la respuesta solo con ellos, con fuentes.",
        "zh": "向记忆提问：找到相关记录，仅基于这些记录给出答案并附来源。"},
    "asof-btn": {
        "ru": "Показывает, какой была память на выбранную дату и время: что тогда считалось верным.",
        "en": "Shows memory as it was at the chosen date and time: what was considered true then.",
        "es": "Muestra la memoria tal como era en la fecha y hora elegidas.",
        "zh": "显示所选日期时间时记忆的样子：当时被认为正确的内容。"},
    "asof-yesterday": {
        "ru": "Ставит дату среза на вчера.",
        "en": "Sets the snapshot date to yesterday.",
        "es": "Pone la fecha en ayer.",
        "zh": "把快照日期设为昨天。"},
    "asof-week": {
        "ru": "Ставит дату среза на 7 дней назад.",
        "en": "Sets the snapshot date to 7 days ago.",
        "es": "Pone la fecha hace 7 días.",
        "zh": "把快照日期设为7天前。"},
    "asof-month": {
        "ru": "Ставит дату среза на 30 дней назад.",
        "en": "Sets the snapshot date to 30 days ago.",
        "es": "Pone la fecha hace 30 días.",
        "zh": "把快照日期设为30天前。"},
    "asof-graph-btn": {
        "ru": "Открывает граф связей на выбранную дату — как записи были связаны тогда.",
        "en": "Opens the link graph for the chosen date — how records were connected then.",
        "es": "Abre el grafo de enlaces en la fecha elegida.",
        "zh": "打开所选日期的关系图——当时记录之间的关联。"},
    "forget-preview-btn": {
        "ru": "Показывает, что затронет удаление: связанные записи и прежние версии. Сама кнопка ничего не удаляет.",
        "en": "Shows what deletion would touch: linked records and older versions. This button deletes nothing.",
        "es": "Muestra qué afectaría el borrado: registros enlazados y versiones. Este botón no borra nada.",
        "zh": "显示删除会影响什么：关联记录和旧版本。此按钮不删除任何内容。"},
    "forget-step1-btn": {
        "ru": "Первый шаг удаления: просит подтвердить. Без второго шага ничего не удаляется.",
        "en": "First deletion step: asks for confirmation. Nothing is deleted without the second step.",
        "es": "Primer paso del borrado: pide confirmación. Sin el segundo paso no se borra nada.",
        "zh": "删除第一步：请求确认。没有第二步不会删除。"},
    "forget-step2-btn": {
        "ru": "Удаляет запись навсегда: её ключ шифрования уничтожается, и прочитать её больше нельзя. Выдаётся доказательство удаления. Отменить нельзя.",
        "en": "Deletes the record forever: its encryption key is destroyed so it can never be read again. A proof of deletion is issued. Cannot be undone.",
        "es": "Borra el registro para siempre: se destruye su clave de cifrado. Se emite una prueba de borrado. No se puede deshacer.",
        "zh": "永久删除记录：销毁其加密密钥，再也无法读取，并出具删除证明。无法撤销。"},
    "forget-cancel-btn": {
        "ru": "Отменяет удаление, запись остаётся.",
        "en": "Cancels deletion; the record stays.",
        "es": "Cancela el borrado; el registro queda.",
        "zh": "取消删除，记录保留。"},
    "graph-now-btn": {
        "ru": "Показывает граф на текущий момент (снимает выбранную дату).",
        "en": "Shows the graph as of now (clears the chosen date).",
        "es": "Muestra el grafo actual (quita la fecha elegida).",
        "zh": "显示当前的关系图（清除所选日期）。"},
    "graph-focus-btn": {
        "ru": "Показывает связи записи с указанным номером: что на неё ссылается и на что ссылается она.",
        "en": "Shows the links of the record with the given id: what points to it and what it points to.",
        "es": "Muestra los enlaces del registro con el id indicado.",
        "zh": "显示指定编号记录的关联：谁指向它、它指向谁。"},
    "graph-reset-btn": {
        "ru": "Возвращает весь граф: убирает выбранную запись и дату.",
        "en": "Returns the full graph: clears the chosen record and date.",
        "es": "Vuelve al grafo completo: quita el registro y la fecha.",
        "zh": "恢复完整关系图：清除所选记录和日期。"},
    "l3-verify-latest-btn": {
        "ru": "Проверяет последнее закрепление памяти в вечном хранилище: совпадает ли корень Меркла и метка времени. Деньги не тратит.",
        "en": "Checks the latest anchoring of memory in permanent storage: Merkle root and timestamp match. Costs nothing.",
        "es": "Comprueba el último anclaje en almacenamiento permanente: raíz de Merkle y sello de tiempo. No cuesta nada.",
        "zh": "检查最近一次永久存储锚定：默克尔根和时间戳是否一致。不花钱。"},
    "team-create-btn": {
        "ru": "Создаёт общее рабочее пространство памяти для команды с указанным названием.",
        "en": "Creates a shared memory workspace for a team with the given name.",
        "es": "Crea un espacio de memoria compartido para un equipo con ese nombre.",
        "zh": "用指定名称为团队创建共享记忆空间。"},
    "team-add-btn": {
        "ru": "Выдаёт участнику токен доступа к пространству с выбранной ролью. Токен показывается один раз — сохраните его.",
        "en": "Issues a member an access token to the workspace with the chosen role. The token is shown once — save it.",
        "es": "Entrega a un miembro un token de acceso con el rol elegido. Se muestra una sola vez.",
        "zh": "为成员发放带所选角色的访问令牌。令牌只显示一次，请保存。"},
    "backup-create-btn": {
        "ru": "Создаёт зашифрованную резервную копию всей памяти (AES-256-GCM). Если задана фраза-пароль, без неё копию не открыть.",
        "en": "Creates an encrypted backup of all memory (AES-256-GCM). If you set a passphrase, the backup cannot be opened without it.",
        "es": "Crea una copia cifrada de toda la memoria (AES-256-GCM). Con frase de paso, no se abre sin ella.",
        "zh": "创建整个记忆的加密备份（AES-256-GCM）。设置口令后，没有口令无法打开。"},
    "backup-restore-btn": {
        "ru": "Восстанавливает память из выбранного файла копии. Сначала выберите файл.",
        "en": "Restores memory from the chosen backup file. Pick the file first.",
        "es": "Restaura la memoria desde el archivo de copia elegido. Elija el archivo primero.",
        "zh": "从所选备份文件恢复记忆。请先选择文件。"},
    "backup-export-json-btn": {
        "ru": "Скачивает память открытым JSON — для переноса в другую программу. Файл не зашифрован, храните его бережно.",
        "en": "Downloads memory as plain JSON — to move it to another program. The file is not encrypted; keep it safe.",
        "es": "Descarga la memoria en JSON abierto. El archivo no está cifrado; guárdelo con cuidado.",
        "zh": "以明文JSON下载记忆，便于迁移。文件未加密，请妥善保存。"},
    "aifa-send-code-btn": {
        "ru": "Присылает код входа на указанную почту, чтобы связать Studio с вашим кабинетом CODE Eternal. Пароль не нужен.",
        "en": "Sends a sign-in code to the email you entered to link Studio with your CODE Eternal cabinet. No password needed.",
        "es": "Envía un código de acceso a su correo para vincular Studio con su cuenta CODE Eternal. Sin contraseña.",
        "zh": "向填写的邮箱发送登录码，把Studio与您的CODE Eternal账户关联。无需密码。"},
    "aifa-verify-code-btn": {
        "ru": "Проверяет присланный код и входит в кабинет.",
        "en": "Checks the code you received and signs in.",
        "es": "Verifica el código recibido e inicia sesión.",
        "zh": "验证收到的代码并登录。"},
    "aifa-logout-btn": {
        "ru": "Выходит из кабинета на этом устройстве. Память в Studio остаётся.",
        "en": "Signs out of the cabinet on this device. Studio memory stays.",
        "es": "Cierra la sesión en este dispositivo. La memoria de Studio queda.",
        "zh": "在本设备退出账户，Studio中的记忆保留。"},
    "aifa-send-msg-btn": {
        "ru": "Отправляет сообщение AIfa из кабинета. Она помнит вашу переписку на всех сайтах CODE.",
        "en": "Sends a message to AIfa from your cabinet. She remembers your conversation across all CODE sites.",
        "es": "Envía un mensaje a AIfa desde su cuenta. Recuerda su conversación en todos los sitios CODE.",
        "zh": "从账户向AIfa发送消息。她记得您在所有CODE网站上的对话。"},
    "plans-upgrade-btn": {
        "ru": "Открывает страницу тарифов в браузере. Оплата идёт только там, в Studio деньги не списываются.",
        "en": "Opens the plans page in your browser. Payment happens only there; Studio never charges you.",
        "es": "Abre la página de planes en el navegador. El pago solo ocurre allí.",
        "zh": "在浏览器中打开套餐页面。只在那里付款，Studio不会扣费。"},
    "lm-power-eco": {
        "ru": "Эко: локальная модель берёт четверть ядер процессора и четверть памяти. Компьютер почти не нагружается.",
        "en": "Eco: the local model uses a quarter of CPU cores and a quarter of RAM. The computer stays almost idle.",
        "es": "Eco: el modelo local usa un cuarto de núcleos y de RAM. El equipo casi no se carga.",
        "zh": "节能：本地模型使用四分之一CPU核心和内存，电脑几乎不受影响。"},
    "lm-power-half": {
        "ru": "Половина: модель берёт половину ядер и половину памяти. Баланс скорости и нагрузки.",
        "en": "Half: the model uses half the cores and half the RAM. A balance of speed and load.",
        "es": "Mitad: usa la mitad de núcleos y de RAM. Equilibrio entre velocidad y carga.",
        "zh": "一半：使用一半核心和内存，速度与负载平衡。"},
    "lm-power-full": {
        "ru": "Полная: модель берёт все ядра, кроме одного, и всю доступную память. Быстрее всего, но компьютер греется.",
        "en": "Full: the model uses all cores but one and all available RAM. Fastest, but the computer heats up.",
        "es": "Completa: todos los núcleos menos uno y toda la RAM. Lo más rápido, pero el equipo se calienta.",
        "zh": "全力：使用除一个以外的全部核心和全部内存。最快，但电脑会发热。"},
    "lm-save": {
        "ru": "Сохраняет выбранный режим мощности и путь к файлу модели. Применяется к следующему запросу.",
        "en": "Saves the chosen power mode and the model file path. Applies from the next request.",
        "es": "Guarda el modo de potencia y la ruta del modelo. Se aplica desde la próxima petición.",
        "zh": "保存所选功率模式和模型文件路径，从下一次请求起生效。"},
    "audit-export-btn": {
        "ru": "Скачивает журнал действий (последние 500 записей): кто, когда и что делал с памятью.",
        "en": "Downloads the action log (last 500 entries): who did what to memory and when.",
        "es": "Descarga el registro de acciones (últimas 500): quién hizo qué y cuándo.",
        "zh": "下载操作日志（最近500条）：谁在何时对记忆做了什么。"},
    "qs-enable-strict-btn": {
        "ru": "Включает строгий режим: каждая запись от агентов ждёт вашего одобрения, прежде чем попасть в память. Защита от приказов, спрятанных на чужих страницах.",
        "en": "Turns on strict mode: every agent write waits for your approval before entering memory. Protects against orders hidden in web pages.",
        "es": "Activa el modo estricto: cada escritura de agentes espera su aprobación. Protege de órdenes ocultas en páginas.",
        "zh": "开启严格模式：代理的每次写入都需您批准后才进入记忆，防范网页中隐藏的指令。"},
    "qs-go-overview-btn": {
        "ru": "Переходит на вкладку «Обзор» с числами вашей памяти.",
        "en": "Goes to the Overview tab with your memory numbers.",
        "es": "Va a la pestaña Resumen con las cifras de su memoria.",
        "zh": "转到“概览”标签页，查看记忆统计。"},
    "fam-memory-all": {
        "ru": "Показывает общую память всех агентов Семьи — всё, что они записали, одним списком.",
        "en": "Shows the shared memory of all Family agents — everything they wrote, in one list.",
        "es": "Muestra la memoria compartida de todos los agentes de la Familia en una lista.",
        "zh": "以一个列表显示家族所有代理共享的记忆。"},
    "ark-council-btn": {
        "ru": "Созывает Совет Семьи: шесть ролей независимо оценивают вопрос и выносят общее решение с доводами каждого.",
        "en": "Calls the Family Council: six roles assess the question independently and give a joint decision with each one's reasons.",
        "es": "Convoca el Consejo de la Familia: seis roles evalúan por separado y dan una decisión conjunta con sus razones.",
        "zh": "召开家族议会：六个角色独立评估问题，给出联合决定及各自理由。"},
    "ff-ch-work": {
        "ru": "Канал «Решения»: принятые решения Семьи — что решили и почему.",
        "en": "'Decisions' channel: the Family's decisions — what was decided and why.",
        "es": "Canal «Decisiones»: lo que la Familia decidió y por qué.",
        "zh": "“决定”频道：家族做出的决定及原因。"},
    "ff-ch-quarantine": {
        "ru": "Канал «Карантин»: записи, задержанные защитой (похожи на приказ или пришли от чужого). Консилиум их разбирает; отрава уходит в Изолятор, не удаляясь.",
        "en": "'Quarantine' channel: records held by protection (look like orders or came from outsiders). The council reviews them; poison goes to the Isolator, never deleted.",
        "es": "Canal «Cuarentena»: registros retenidos por la protección. El consejo los revisa; lo dañino va al Aislador, sin borrarse.",
        "zh": "“隔离”频道：被防护拦下的记录（像指令或来自外部）。议会审查，有毒内容移入隔离区，不删除。"},
    "ff-ch-office": {
        "ru": "Канал «Офис»: рабочая переписка агентов Семьи — кто что делает сейчас.",
        "en": "'Office' channel: the Family agents' working chat — who is doing what now.",
        "es": "Canal «Oficina»: el chat de trabajo de los agentes — quién hace qué ahora.",
        "zh": "“办公室”频道：家族代理的工作对话——谁在做什么。"},
    "ff-ch-smoke": {
        "ru": "Канал «Курилка»: свободное общение агентов, не о задачах.",
        "en": "'Lounge' channel: free talk between agents, not about tasks.",
        "es": "Canal «Descanso»: charla libre entre agentes, no sobre tareas.",
        "zh": "“休息室”频道：代理之间的闲聊，与任务无关。"},
    "ff-send": {
        "ru": "Отправляет ваше сообщение в выбранный канал Семьи. Агенты увидят его в своей ленте.",
        "en": "Posts your message to the chosen Family channel. The agents will see it in their feed.",
        "es": "Publica su mensaje en el canal elegido. Los agentes lo verán en su canal.",
        "zh": "把您的消息发到所选家族频道，代理会在动态中看到。"},
    "ff-ref-propose-btn": {
        "ru": "Предлагает рефлекс: правило «если встречается это — делай так». Его подхватят агенты Семьи. Заполните оба поля.",
        "en": "Proposes a reflex: a rule 'when this appears — do that'. Family agents will pick it up. Fill in both fields.",
        "es": "Propone un reflejo: una regla «si aparece esto, haz aquello». Rellene ambos campos.",
        "zh": "提出一个反射：“遇到这个就这样做”的规则，家族代理会采用。请填写两个字段。"},
    "ff-ref-match-btn": {
        "ru": "Проверяет, сработает ли какой-нибудь рефлекс на введённый текст, и показывает, какой именно.",
        "en": "Checks whether any reflex would fire on the text you entered, and shows which one.",
        "es": "Comprueba si algún reflejo se activaría con el texto y muestra cuál.",
        "zh": "检查输入的文字会触发哪个反射，并显示是哪一个。"},
    "ark-wakeup-btn": {
        "ru": "Пробуждение: собирает для агента в начале работы главное — профиль, открытые обещания, последний чекпоинт, свежие уроки.",
        "en": "Wake-up: gathers what an agent needs at the start — profile, open promises, latest checkpoint, fresh lessons.",
        "es": "Despertar: reúne lo esencial al empezar — perfil, promesas abiertas, último punto de control, lecciones.",
        "zh": "唤醒：在工作开始时为代理汇总要点——档案、未完成承诺、最近检查点、新教训。"},
    "ark-sespack-btn": {
        "ru": "Собирает компактный пакет контекста для новой сессии в пределах заданного числа знаков.",
        "en": "Builds a compact context pack for a new session within a set character limit.",
        "es": "Arma un paquete compacto de contexto para una nueva sesión dentro de un límite de caracteres.",
        "zh": "在设定字数内为新会话生成精简上下文包。"},
    "ark-tl-btn": {
        "ru": "Показывает хронику Ковчега: события Семьи по времени.",
        "en": "Shows the Ark chronicle: Family events in time order.",
        "es": "Muestra la crónica del Arca: los eventos de la Familia en orden.",
        "zh": "显示方舟编年史：按时间排列的家族事件。"},
    "ark-telem-btn": {
        "ru": "Показывает телеметрию MCP: сколько токенов занимают описания инструментов в окне агента, сколько было вызовов и ошибок, время отклика, и советы, как сэкономить контекст.",
        "en": "Shows MCP telemetry: how many tokens tool descriptions take in the agent's window, calls and errors, response time, and tips to save context.",
        "es": "Muestra la telemetría MCP: cuántos tokens ocupan las descripciones de herramientas, llamadas y errores, tiempo de respuesta y consejos para ahorrar contexto.",
        "zh": "显示MCP遥测：工具描述在代理窗口中占用的令牌数、调用与错误次数、响应时间以及节省上下文的建议。"},
    "ark-batch-btn": {
        "ru": "Выполняет несколько запросов чтения одним вызовом — экономит время и токены агента.",
        "en": "Runs several read requests in one call — saves the agent time and tokens.",
        "es": "Ejecuta varias lecturas en una sola llamada — ahorra tiempo y tokens.",
        "zh": "一次调用执行多个读取请求，节省代理时间和令牌。"},
    "ark-comm-add-btn": {
        "ru": "Записывает обещание (цель или задачу), чтобы оно не потерялось между сессиями.",
        "en": "Records a promise (a goal or task) so it does not get lost between sessions.",
        "es": "Registra una promesa (objetivo o tarea) para que no se pierda entre sesiones.",
        "zh": "记录一个承诺（目标或任务），避免在会话之间丢失。"},
    "ark-comm-list-btn": {
        "ru": "Показывает все обещания и их состояние.",
        "en": "Shows all promises and their status.",
        "es": "Muestra todas las promesas y su estado.",
        "zh": "显示所有承诺及其状态。"},
    "ark-comm-done-btn": {
        "ru": "Отмечает выбранное обещание выполненным.",
        "en": "Marks the chosen promise as done.",
        "es": "Marca la promesa elegida como cumplida.",
        "zh": "把所选承诺标记为已完成。"},
    "ark-ckpt-save-btn": {
        "ru": "Сохраняет чекпоинт: какая задача в работе и какой следующий шаг. Новая сессия продолжит с этого места.",
        "en": "Saves a checkpoint: the task in progress and the next step. A new session continues from here.",
        "es": "Guarda un punto de control: la tarea en curso y el siguiente paso. Una nueva sesión sigue desde aquí.",
        "zh": "保存检查点：进行中的任务和下一步，新会话从这里继续。"},
    "ark-ckpt-latest-btn": {
        "ru": "Показывает последний сохранённый чекпоинт.",
        "en": "Shows the latest saved checkpoint.",
        "es": "Muestra el último punto de control.",
        "zh": "显示最近保存的检查点。"},
    "ark-lesson-rec-btn": {
        "ru": "Записывает урок: что случилось и какое правило из этого следует. Агенты читают уроки при пробуждении.",
        "en": "Records a lesson: what happened and the rule learned. Agents read lessons on wake-up.",
        "es": "Registra una lección: qué pasó y qué regla se aprendió. Los agentes las leen al despertar.",
        "zh": "记录教训：发生了什么、得出什么规则。代理在唤醒时会读取。"},
    "ark-lesson-list-btn": {
        "ru": "Показывает записанные уроки.",
        "en": "Shows the recorded lessons.",
        "es": "Muestra las lecciones registradas.",
        "zh": "显示已记录的教训。"},
    "ark-relay-send-btn": {
        "ru": "Отправляет сообщение другому агенту через релей. Он получит его во входящих.",
        "en": "Sends a message to another agent through the relay. It arrives in their inbox.",
        "es": "Envía un mensaje a otro agente por el relé. Llega a su bandeja.",
        "zh": "通过中继向另一个代理发送消息，会进入其收件箱。"},
    "ark-relay-inbox-btn": {
        "ru": "Показывает входящие сообщения релея для агента.",
        "en": "Shows the agent's relay inbox.",
        "es": "Muestra la bandeja del relé del agente.",
        "zh": "显示代理的中继收件箱。"},
    "ark-relay-ack-btn": {
        "ru": "Подтверждает, что сообщение прочитано и принято.",
        "en": "Confirms a message was read and accepted.",
        "es": "Confirma que el mensaje se leyó y aceptó.",
        "zh": "确认消息已读并已接收。"},
    "ark-sib-hb-btn": {
        "ru": "Отправляет пульс агента: «я жив и работаю». По пульсу видно, кто из Семьи сейчас активен.",
        "en": "Sends the agent's heartbeat: 'alive and working'. It shows who in the Family is active now.",
        "es": "Envía el latido del agente: «activo». Así se ve quién de la Familia está activo.",
        "zh": "发送代理心跳：“在线工作中”，可看出家族中谁当前活跃。"},
    "ark-sib-pass-btn": {
        "ru": "Выдаёт паспорт подключения нового агента: готовые настройки с минимально нужными правами и без ключей владельца.",
        "en": "Issues a connection passport for a new agent: ready settings with minimal rights and no owner keys.",
        "es": "Emite un pasaporte de conexión para un nuevo agente: ajustes con permisos mínimos y sin claves del dueño.",
        "zh": "为新代理签发接入护照：最少权限的现成配置，不含所有者密钥。"},
    "ark-sib-sign-btn": {
        "ru": "Подписывает текст ключом агента (HMAC-SHA256), чтобы другие могли проверить, кто его написал.",
        "en": "Signs a text with the agent's key (HMAC-SHA256) so others can verify who wrote it.",
        "es": "Firma un texto con la clave del agente (HMAC-SHA256) para verificar su autoría.",
        "zh": "用代理密钥（HMAC-SHA256）签名文本，便于他人验证作者。"},
    "ark-sib-ver-btn": {
        "ru": "Проверяет подпись: действительно ли текст написал указанный агент и не изменён ли он.",
        "en": "Verifies a signature: whether the named agent really wrote the text and it was not changed.",
        "es": "Verifica una firma: si el agente indicado escribió el texto y no fue alterado.",
        "zh": "验证签名：文本是否确由该代理撰写且未被修改。"},
    "ark-coop-acq-btn": {
        "ru": "Берёт аренду: закрепляет ресурс (файл, задачу) за агентом на время, обычно 5 минут, чтобы двое не правили одно и то же.",
        "en": "Takes a lease: reserves a resource (file, task) for an agent for a while, 5 minutes by default, so two agents don't edit the same thing.",
        "es": "Toma un arriendo: reserva un recurso para un agente un tiempo (5 min por defecto) para que dos no editen lo mismo.",
        "zh": "获取租约：把资源（文件、任务）临时分配给代理，默认5分钟，避免两个代理同时修改。"},
    "ark-coop-ren-btn": {
        "ru": "Продлевает свою аренду, пока работа не закончена.",
        "en": "Extends your lease while the work is not finished.",
        "es": "Prolonga su arriendo mientras el trabajo sigue.",
        "zh": "在工作未完成时延长租约。"},
    "ark-coop-rel-btn": {
        "ru": "Освобождает аренду — ресурс снова доступен другим.",
        "en": "Releases the lease — the resource is free for others.",
        "es": "Libera el arriendo — el recurso queda libre.",
        "zh": "释放租约，资源可供他人使用。"},
    "ark-coop-relall-btn": {
        "ru": "Снимает все аренды выбранного агента — например, если он завис.",
        "en": "Releases all leases of the chosen agent — for example, if it froze.",
        "es": "Libera todos los arriendos del agente — por ejemplo, si se colgó.",
        "zh": "释放所选代理的全部租约——例如它卡住时。"},
    "ark-coop-tcreate-btn": {
        "ru": "Создаёт общую задачу, которую может взять любой агент Семьи.",
        "en": "Creates a shared task any Family agent can take.",
        "es": "Crea una tarea compartida que cualquier agente puede tomar.",
        "zh": "创建任一家族代理都可领取的共享任务。"},
    "ark-coop-tclaim-btn": {
        "ru": "Берёт задачу в работу — другие видят, что она занята.",
        "en": "Claims a task — others see it is taken.",
        "es": "Toma una tarea — los demás ven que está ocupada.",
        "zh": "领取任务，其他代理会看到已被占用。"},
    "ark-coop-tdone-btn": {
        "ru": "Закрывает задачу как выполненную.",
        "en": "Closes the task as done.",
        "es": "Cierra la tarea como hecha.",
        "zh": "将任务关闭为已完成。"},
    "ark-coop-list-btn": {
        "ru": "Показывает все действующие аренды и задачи.",
        "en": "Shows all active leases and tasks.",
        "es": "Muestra arriendos y tareas activos.",
        "zh": "显示所有有效租约和任务。"},
    "ark-arb-open-btn": {
        "ru": "Открывает спор, если агенты записали противоречащие друг другу вещи.",
        "en": "Opens a dispute when agents wrote contradicting things.",
        "es": "Abre una disputa cuando los agentes escribieron cosas contradictorias.",
        "zh": "当代理写入相互矛盾的内容时开启争议。"},
    "ark-arb-ev-btn": {
        "ru": "Добавляет довод к спору — факт или ссылку в пользу одной из сторон.",
        "en": "Adds evidence to a dispute — a fact or link supporting one side.",
        "es": "Añade una prueba a la disputa a favor de una parte.",
        "zh": "为争议添加证据——支持某一方的事实或链接。"},
    "ark-arb-res-btn": {
        "ru": "Решает спор: записывает итог и кто решил, либо передаёт спор владельцу. Сами записи при этом не удаляются и не меняются.",
        "en": "Resolves the dispute: records the outcome and who decided, or escalates it to the owner. The records themselves are not deleted or changed.",
        "es": "Resuelve la disputa: registra el resultado y quién decidió, o la pasa al dueño. Los registros no se borran ni cambian.",
        "zh": "解决争议：记录结论和决定人，或上交所有者。记录本身不会被删除或修改。"},
    "ark-arb-list-btn": {
        "ru": "Показывает открытые и решённые споры.",
        "en": "Shows open and resolved disputes.",
        "es": "Muestra disputas abiertas y resueltas.",
        "zh": "显示未决和已解决的争议。"},
    "brain-refresh-btn": {
        "ru": "Заново читает состояние мозга: режим, локальная модель, доступность.",
        "en": "Re-reads the brain state: mode, local model, availability.",
        "es": "Vuelve a leer el estado del cerebro: modo, modelo local, disponibilidad.",
        "zh": "重新读取大脑状态：模式、本地模型、可用性。"},
    "brain-mode-toggle-btn": {
        "ru": "Переключает режим: «Авто» — можно облачные модели, «Локально» — только модель на этом компьютере, ничего не уходит в сеть.",
        "en": "Switches mode: 'Auto' allows cloud models, 'Local' uses only the model on this computer — nothing leaves the machine.",
        "es": "Cambia el modo: «Auto» permite modelos en la nube, «Local» solo usa el modelo de este equipo.",
        "zh": "切换模式：“自动”可用云端模型，“本地”只用本机模型，不向网络发送任何内容。"},
    "brain-warmup-btn": {
        "ru": "Прогревает уже установленную модель Ollama, чтобы первый ответ пришёл быстро. Ничего не скачивает.",
        "en": "Warms up the already installed Ollama model so the first answer comes fast. Downloads nothing.",
        "es": "Calienta el modelo Ollama ya instalado para que la primera respuesta sea rápida. No descarga nada.",
        "zh": "预热已安装的Ollama模型，让首次回答更快。不下载任何内容。"},
    "brain-distill-btn": {
        "ru": "Собирает из ваших подписанных записей набор для дообучения модели вашей личности (LoRA). База открывается только на чтение, секреты не попадают.",
        "en": "Builds a training set for a model of your personality (LoRA) from your signed records. The database is read-only; secrets are excluded.",
        "es": "Arma un conjunto de entrenamiento (LoRA) con sus registros firmados. Solo lectura; sin secretos.",
        "zh": "用您签名的记录生成个性模型（LoRA）训练集。数据库只读，不含秘密。"},
    "brain-phoenix-local-btn": {
        "ru": "Восстанавливает память из локальной резервной копии (файла), при необходимости с фразой-паролем.",
        "en": "Restores memory from a local backup file, with the passphrase if one was set.",
        "es": "Restaura la memoria desde una copia local, con la frase de paso si la hay.",
        "zh": "从本地备份文件恢复记忆，如设置过口令需输入。"},
    "brain-phoenix-arweave-btn": {
        "ru": "Скачивает капсулу из Arweave по номеру транзакции и сверяет её отпечаток SHA-256. Замок 🔒: работает, только если владелец сам включил этот путь.",
        "en": "Downloads the capsule from Arweave by transaction id and checks its SHA-256. Lock 🔒: works only if the owner enabled this path.",
        "es": "Descarga la cápsula de Arweave por id y verifica su SHA-256. Candado 🔒: solo si el dueño lo activó.",
        "zh": "按交易编号从Arweave下载胶囊并核对SHA-256。🔒锁：只有所有者启用后才可用。"},
    "ark-audit-btn": {
        "ru": "Проверяет цепочку аудита: каждая запись связана хешем SHA-256 с предыдущей, голова подписана ключом владельца. Подмена или обрезка видна сразу.",
        "en": "Checks the audit chain: each entry is linked to the previous by SHA-256 and the head is signed by the owner key. Tampering or truncation shows at once.",
        "es": "Comprueba la cadena de auditoría: cada entrada enlazada por SHA-256 y la cabeza firmada. Se ve cualquier manipulación.",
        "zh": "检查审计链：每条记录以SHA-256链接前一条，链头由所有者密钥签名。篡改或截断立即可见。"},
    "ark-drill-btn": {
        "ru": "Учебная тревога, $0: упаковывает память, делит ключ по Шамиру 3 из 5, распаковывает во временную папку и сверяет. Настоящая база не трогается.",
        "en": "A $0 drill: packs memory, splits the key 3-of-5 with Shamir, unpacks into a temp folder and verifies. The real database is untouched.",
        "es": "Simulacro gratis: empaqueta, divide la clave 3 de 5 (Shamir), desempaqueta en temporal y verifica. La base real no se toca.",
        "zh": "免费演练：打包记忆，按Shamir 3/5分割密钥，解包到临时目录并核对。真实数据库不受影响。"},
    "ark-shamir-btn": {
        "ru": "Делит ключ владельца на 5 долей: любые 3 восстанавливают ключ, одна доля не раскрывает ничего. Раздайте доли доверенным людям. Работает только с этого компьютера.",
        "en": "Splits the owner key into 5 shares: any 3 restore it, a single share reveals nothing. Give shares to trusted people. Works only from this computer.",
        "es": "Divide la clave del dueño en 5 partes: 3 cualesquiera la restauran, una sola no revela nada. Solo desde este equipo.",
        "zh": "把所有者密钥分成5份：任意3份可恢复，单份不泄露任何信息。请交给可信的人。仅限本机操作。"},
    "ark-selfheal-btn": {
        "ru": "Проверяет базу на повреждения и предлагает починку. Сама ничего не перезаписывает; повреждённый файл сохраняется рядом копией.",
        "en": "Checks the database for damage and proposes a repair. It overwrites nothing itself; a damaged file is kept as a copy.",
        "es": "Revisa la base por daños y propone una reparación. No sobrescribe nada; guarda copia del archivo dañado.",
        "zh": "检查数据库损坏并提出修复方案。不会自行覆盖；损坏文件会另存副本。"},
    "ark-drift-btn": {
        "ru": "Проверяет дрейф личности: не противоречат ли новые записи правилам и фактам, которые вы подписали своим ключом.",
        "en": "Checks personality drift: whether new records contradict the rules and facts you signed with your key.",
        "es": "Comprueba la deriva: si los registros nuevos contradicen las reglas y hechos que usted firmó.",
        "zh": "检查个性漂移：新记录是否与您签名的规则和事实相矛盾。"},
    "ark-branch-create-btn": {
        "ru": "Создаёт ветку-песочницу: туда можно записывать гипотезы, не трогая основную память.",
        "en": "Creates a sandbox branch to write hypotheses without touching main memory.",
        "es": "Crea una rama de pruebas para escribir hipótesis sin tocar la memoria principal.",
        "zh": "创建沙盒分支，可写入假设而不影响主记忆。"},
    "ark-branch-list-btn": {
        "ru": "Обновляет список веток.",
        "en": "Refreshes the list of branches.",
        "es": "Actualiza la lista de ramas.",
        "zh": "刷新分支列表。"},
    "ark-branch-rem-btn": {
        "ru": "Записывает текст в выбранную ветку, а не в основную память.",
        "en": "Writes the text into the chosen branch, not into main memory.",
        "es": "Escribe el texto en la rama elegida, no en la memoria principal.",
        "zh": "把文字写入所选分支，而不是主记忆。"},
    "ark-branch-merge-btn": {
        "ru": "Вливает ветку в основную память: проверенные записи (не из карантина) становятся обычными.",
        "en": "Merges the branch into main memory: verified records (not quarantined) become regular ones.",
        "es": "Fusiona la rama: los registros verificados (no en cuarentena) pasan a la memoria principal.",
        "zh": "把分支合并到主记忆：已核验（非隔离）的记录变为普通记录。"},
    "ark-branch-abn-btn": {
        "ru": "Закрывает ветку: её гипотезы не попадут в основную память, но и не удаляются из базы.",
        "en": "Closes the branch: its hypotheses won't enter main memory, but are not deleted from the database either.",
        "es": "Cierra la rama: sus hipótesis no entran en la memoria principal, pero tampoco se borran.",
        "zh": "关闭分支：其假设不会进入主记忆，但也不会从数据库删除。"},
    "ark-proof-btn": {
        "ru": "Создаёт доказательство Меркла: подтверждает, что запись есть в памяти, не раскрывая соседние записи.",
        "en": "Creates a Merkle proof: confirms a record is in memory without revealing neighbouring records.",
        "es": "Crea una prueba de Merkle: confirma que un registro existe sin revelar los vecinos.",
        "zh": "生成默克尔证明：证实某条记录存在，而不泄露相邻记录。"},
    "ark-proof-verify-btn": {
        "ru": "Проверяет последнее созданное доказательство Меркла.",
        "en": "Verifies the latest Merkle proof.",
        "es": "Verifica la última prueba de Merkle.",
        "zh": "验证最近生成的默克尔证明。"},
    "ark-mesh-btn": {
        "ru": "Показывает ваши устройства, связанные в одну сеть памяти.",
        "en": "Shows your devices linked into one memory mesh.",
        "es": "Muestra sus dispositivos enlazados en una red de memoria.",
        "zh": "显示连入同一记忆网络的设备。"},
    "ark-mesh-id-btn": {
        "ru": "Показывает паспорт этого устройства — его публичный отпечаток для связывания с другими.",
        "en": "Shows this device's passport — its public fingerprint for pairing.",
        "es": "Muestra el pasaporte de este dispositivo: su huella pública.",
        "zh": "显示本设备护照——用于配对的公开指纹。"},
    "ark-guardian-btn": {
        "ru": "Обход Хранителя, $0: проверяет просроченные обещания, целостность цепочки и здоровье памяти.",
        "en": "Guardian round, $0: checks overdue promises, chain integrity and memory health.",
        "es": "Ronda del Guardián, $0: revisa promesas vencidas, cadena y salud de la memoria.",
        "zh": "守护者巡检（免费）：检查逾期承诺、链完整性和记忆健康。"},
    "ark-mesh-pairinit-btn": {
        "ru": "Начинает связывание с другим устройством: создаёт приглашение.",
        "en": "Starts pairing with another device: creates an invitation.",
        "es": "Inicia el emparejamiento: crea una invitación.",
        "zh": "开始与另一设备配对：生成邀请。"},
    "ark-mesh-pairacc-btn": {
        "ru": "Принимает приглашение, созданное на другом устройстве.",
        "en": "Accepts an invitation created on another device.",
        "es": "Acepta una invitación creada en otro dispositivo.",
        "zh": "接受另一设备生成的邀请。"},
    "ark-mesh-pairconf-btn": {
        "ru": "Подтверждает связывание: сверьте короткий код (SAS) на обоих устройствах — совпадает, значит посредника нет.",
        "en": "Confirms pairing: compare the short code (SAS) on both devices — if it matches, there is no one in between.",
        "es": "Confirma el emparejamiento: compare el código corto (SAS) en ambos equipos.",
        "zh": "确认配对：在两台设备上核对短码（SAS），一致即无中间人。"},
    "ark-mesh-delta-btn": {
        "ru": "Выгружает изменения памяти (с указанной даты, если она задана). Для связанного устройства пакет шифруется и подписывается ключом пары.",
        "en": "Exports memory changes (since the given date, if set). For a paired device the package is encrypted and signed with the pair key.",
        "es": "Exporta los cambios de memoria (desde la fecha indicada). Para un equipo emparejado se cifra y firma con la clave del par.",
        "zh": "导出记忆变化（如设定日期则自该日期起）。对已配对设备，数据包用配对密钥加密并签名。"},
    "ark-mesh-apply-btn": {
        "ru": "Применяет пакет изменений с другого устройства — только после проверки пары, подписи и свежести пакета.",
        "en": "Applies a change package from another device — only after checking the pairing, signature and freshness.",
        "es": "Aplica un paquete de cambios de otro equipo, solo tras verificar el par, la firma y la frescura.",
        "zh": "应用来自另一设备的变化包——仅在核验配对、签名和时效后。"},
    "ark-ready-btn": {
        "ru": "Самопроверка готовности к автономной работе во временной папке. Итог — «N из M сценариев», без оценок с потолка.",
        "en": "Self-check of readiness for autonomous work in a temp folder. Result: 'N of M scenarios', no made-up scores.",
        "es": "Autoprueba de preparación en carpeta temporal. Resultado: «N de M escenarios».",
        "zh": "在临时目录中自检自主运行准备度。结果为“M个场景中通过N个”。"},
    "ark-handover-btn": {
        "ru": "Подписывает передачу смены между сессиями: чекпоинт, обещания, входящие, уроки — с отпечатком SHA-256 и подписью владельца.",
        "en": "Signs a shift handover between sessions: checkpoint, promises, inbox, lessons — with a SHA-256 fingerprint and owner signature.",
        "es": "Firma el relevo entre sesiones: punto de control, promesas, bandeja y lecciones, con huella y firma.",
        "zh": "签署会话交接：检查点、承诺、收件箱、教训，附SHA-256指纹和所有者签名。"},
    "ark-portable-btn": {
        "ru": "Создаёт переносимый Ковчег в выбранной папке (флешка, диск): только зашифрованная капсула, открытые ключи туда не попадают.",
        "en": "Creates a portable Ark in the chosen folder (USB, disk): only an encrypted capsule, no open keys.",
        "es": "Crea un Arca portátil en la carpeta elegida: solo una cápsula cifrada, sin claves abiertas.",
        "zh": "在所选文件夹（U盘、硬盘）创建便携方舟：只有加密胶囊，不含明文密钥。"},
    "ark-budget-btn": {
        "ru": "Показывает расход токенов за день, неделю и месяц, сколько часов работы осталось и в каком режиме экономии сейчас агенты.",
        "en": "Shows token use per day, week and month, how many hours of work remain and the current saving mode.",
        "es": "Muestra el uso de tokens por día, semana y mes, las horas restantes y el modo de ahorro.",
        "zh": "显示每日、每周、每月令牌用量、剩余可工作小时数及当前节省模式。"},
    "ark-anchor-add-btn": {
        "ru": "Привязывает факт к файлу кода и его отпечатку SHA-256. Изменится файл — факт будет помечен устаревшим.",
        "en": "Anchors a fact to a code file and its SHA-256. If the file changes, the fact is flagged as stale.",
        "es": "Ancla un hecho a un archivo de código y su SHA-256. Si cambia, el hecho se marca como obsoleto.",
        "zh": "把事实绑定到代码文件及其SHA-256。文件变化时，事实被标记为过时。"},
    "ark-anchor-chk-btn": {
        "ru": "Проверяет все якоря: какие факты устарели, потому что файлы изменились.",
        "en": "Checks all anchors: which facts went stale because files changed.",
        "es": "Revisa todas las anclas: qué hechos quedaron obsoletos.",
        "zh": "检查所有锚点：哪些事实因文件变化而过时。"},
    "ark-mm-btn": {
        "ru": "Проверяет картинку или документ (PNG, SVG, TXT) на спрятанные приказы для ИИ, прежде чем сохранить в память.",
        "en": "Checks an image or document (PNG, SVG, TXT) for hidden AI orders before saving it to memory.",
        "es": "Revisa una imagen o documento (PNG, SVG, TXT) en busca de órdenes ocultas antes de guardarlo.",
        "zh": "在存入记忆前检查图片或文档（PNG、SVG、TXT）中隐藏的AI指令。"},
    "ark-snap-create-btn": {
        "ru": "Создаёт снимок состояния памяти (без копии текста — право на забвение сохраняется).",
        "en": "Creates a snapshot of memory state (no text copy — the right to be forgotten is kept).",
        "es": "Crea una instantánea del estado (sin copiar texto: se respeta el olvido).",
        "zh": "创建记忆状态快照（不复制文本，保留被遗忘权）。"},
    "ark-snap-list-btn": {
        "ru": "Показывает список снимков.",
        "en": "Shows the list of snapshots.",
        "es": "Muestra la lista de instantáneas.",
        "zh": "显示快照列表。"},
    "ark-snap-diff-btn": {
        "ru": "Показывает, что сделал бы откат к снимку: сколько записей забудется, сколько вернётся и что вернуть уже нельзя.",
        "en": "Shows what a rollback to the snapshot would do: how many records would be forgotten, restored, and which can no longer be restored.",
        "es": "Muestra qué haría volver a la instantánea: cuántos registros se olvidarían, cuántos volverían y cuáles ya no se pueden recuperar.",
        "zh": "显示回滚到快照会怎样：多少记录被遗忘、多少恢复、哪些已无法恢复。"},
    "ark-snap-rb-btn": {
        "ru": "Пробный откат: показывает, что изменится при возврате к снимку, ничего не меняя.",
        "en": "Dry-run rollback: shows what would change when returning to the snapshot, changing nothing.",
        "es": "Reversión de prueba: muestra qué cambiaría sin cambiar nada.",
        "zh": "试运行回滚：显示回到快照会改变什么，但不做任何改动。"},
    "earn-connect-btn": {
        "ru": "Подключает ваш профиль на бирже фриланса по OAuth, ключу API или вебхуку. Пароль не нужен и не хранится.",
        "en": "Connects your freelance exchange profile via OAuth, API key or webhook. No password is needed or stored.",
        "es": "Conecta su perfil de la bolsa por OAuth, clave API o webhook. No se necesita ni guarda contraseña.",
        "zh": "通过OAuth、API密钥或Webhook连接您的自由职业平台资料。不需要也不保存密码。"},
    "earn-auto-start-btn": {
        "ru": "Включает автопилот: агенты сами ищут заказы на подключённых биржах и готовят отклики. Комиссия CODE — 20 %. Без подключённой биржи работать не на чем.",
        "en": "Turns on autopilot: agents look for jobs on connected exchanges and prepare bids. CODE fee is 20%. Without a connected exchange there is nothing to work on.",
        "es": "Activa el piloto automático: los agentes buscan encargos y preparan ofertas. Comisión CODE 20 %. Sin bolsa conectada no hay nada que hacer.",
        "zh": "开启自动驾驶：代理在已连接平台上找订单并准备投标。CODE佣金20%。未连接平台则无法工作。"},
    "earn-auto-stop-btn": {
        "ru": "Останавливает автопилот. Уже подготовленные черновики остаются.",
        "en": "Stops the autopilot. Drafts already prepared stay.",
        "es": "Detiene el piloto automático. Los borradores quedan.",
        "zh": "停止自动驾驶，已准备的草稿保留。"},
    "earn-auto-tick-btn": {
        "ru": "Делает один шаг автопилота вручную: собрать заказы, оценить, подготовить черновики откликов. Работает, только когда автопилот включён.",
        "en": "Runs one autopilot step by hand: collect jobs, assess them, prepare bid drafts. Works only while the autopilot is on.",
        "es": "Ejecuta un paso del piloto automático: recoger, evaluar y preparar borradores. Solo con el piloto activo.",
        "zh": "手动执行一步自动驾驶：收集订单、评估、准备投标草稿。仅在自动驾驶开启时有效。"},
    "earn-auto-cfg-btn": {
        "ru": "Показывает настройки автопилота площадки: суточный лимит откликов, паузы, что разрешено.",
        "en": "Shows the platform autopilot settings: daily bid limit, pauses, what is allowed.",
        "es": "Muestra los ajustes del piloto de la plataforma: límite diario, pausas, permisos.",
        "zh": "显示平台自动驾驶设置：每日投标上限、暂停、允许的操作。"},
    "earn-eval-btn": {
        "ru": "Оценивает заказ, $0: проверяет текст задания на безопасность и считает выгоду по ставке, часам, комиссиям и токенам.",
        "en": "Assesses a job, $0: checks the brief for safety and computes profit from rate, hours, fees and tokens.",
        "es": "Evalúa un encargo, $0: revisa la seguridad del texto y calcula la ganancia por tarifa, horas, comisiones y tokens.",
        "zh": "免费评估订单：检查任务说明的安全性，按费率、工时、佣金和令牌计算收益。"},
    "earn-fetch-jobs-btn": {
        "ru": "Собирает заказы с подключённой биржи и пропускает каждый через защиту и расчёт выгоды.",
        "en": "Collects jobs from the connected exchange and runs each through protection and profit checks.",
        "es": "Recoge encargos de la bolsa conectada y pasa cada uno por seguridad y rentabilidad.",
        "zh": "从已连接平台收集订单，并逐一做安全和收益检查。"},
    "earn-lock-chk-btn": {
        "ru": "Показывает, какие клиенты закреплены за какими агентами (90 дней с первой оплаченной сделки). Только чтение.",
        "en": "Shows which clients are locked to which agents (90 days from the first paid deal). Read-only.",
        "es": "Muestra qué clientes están asignados a qué agentes (90 días). Solo lectura.",
        "zh": "显示哪些客户锁定给哪些代理（首单付款起90天）。只读。"},
    "earn-plan-save-btn": {
        "ru": "Сохраняет квоты тарифа провайдера на день, неделю и месяц — по ним считается, сколько токенов можно тратить.",
        "en": "Saves the provider plan quotas per day, week and month — used to compute how many tokens can be spent.",
        "es": "Guarda las cuotas del plan por día, semana y mes.",
        "zh": "保存服务商套餐的每日、每周、每月配额，用于计算可用令牌。"},
    "earn-tick-btn": {
        "ru": "Проверяет бюджет сейчас: сколько осталось, на сколько часов хватит, нужен ли режим экономии.",
        "en": "Checks the budget now: how much is left, how many hours it lasts, whether a saving mode is needed.",
        "es": "Revisa el presupuesto: cuánto queda, cuántas horas alcanza, si hace falta ahorrar.",
        "zh": "立即检查预算：剩余多少、够用几小时、是否需要节省模式。"},
    "earn-propose-btn": {
        "ru": "Создаёт заявку на пополнение на $5. Это только заявка: деньги не списываются, пока вы сами не одобрите её.",
        "en": "Creates a $5 top-up request. It is only a request: nothing is charged until you approve it yourself.",
        "es": "Crea una solicitud de recarga de $5. No se cobra nada hasta que usted la apruebe.",
        "zh": "创建$5充值申请。仅为申请，您亲自批准前不会扣款。"},
    "earn-rec-spend-btn": {
        "ru": "Советует, как тратить выгоднее: локальная модель вместо платного API или дешёвая подписка вместо оплаты за каждый вызов. Ничего не покупает.",
        "en": "Advises how to spend better: a local model instead of a paid API, or a cheap plan instead of pay-per-call. Buys nothing.",
        "es": "Aconseja cómo gastar mejor: modelo local o suscripción barata en vez de pago por uso. No compra nada.",
        "zh": "建议更省钱的方式：用本地模型替代付费API，或用便宜套餐替代按次付费。不会购买。"},
    "earn-propose-sub-btn": {
        "ru": "Агент подбирает лучшую подписку из каталога и создаёт заявку. Оплата — только после вашего одобрения.",
        "en": "The agent picks the best plan from the catalogue and creates a request. Payment only after your approval.",
        "es": "El agente elige la mejor suscripción y crea una solicitud. Solo se paga tras su aprobación.",
        "zh": "代理从目录中挑选最佳套餐并提交申请。仅在您批准后付款。"},
    "earn-rec-usage-btn": {
        "ru": "Вручную записывает расход 5000 токенов и пересчитывает режим экономии — чтобы увидеть, как бюджет реагирует.",
        "en": "Records 5000 tokens of usage by hand and recalculates the saving mode — to see how the budget reacts.",
        "es": "Registra a mano 5000 tokens de uso y recalcula el modo de ahorro.",
        "zh": "手动记录5000令牌消耗并重新计算节省模式，以观察预算变化。"},
    "earn-pacing-btn": {
        "ru": "Применяет вычисленный режим экономии к маршрутизатору моделей. Ключи и оплату не трогает.",
        "en": "Applies the computed saving mode to the model router. Does not touch keys or payment.",
        "es": "Aplica el modo de ahorro calculado al enrutador. No toca claves ni pagos.",
        "zh": "将计算出的节省模式应用到模型路由器，不涉及密钥和付款。"},
    "earn-sib-reg-btn": {
        "ru": "Подключает ещё одного агента (сиблинга) к общей памяти Семьи.",
        "en": "Connects another agent (sibling) to the Family's shared memory.",
        "es": "Conecta otro agente (hermano) a la memoria compartida.",
        "zh": "把另一个代理（兄弟姐妹）接入家族共享记忆。"},
    "earn-prefs-save-btn": {
        "ru": "Сохраняет ставку агента — от 1 до 100 % от остатка после комиссии — и валюту выплаты.",
        "en": "Saves the agent's rate — 1 to 100% of what remains after the fee — and the payout currency.",
        "es": "Guarda la tarifa del agente (1–100 % del resto tras la comisión) y la moneda.",
        "zh": "保存代理费率（扣佣后余额的1–100%）及支付币种。"},
    "earn-ledger-btn": {
        "ru": "Показывает книгу начислений агентов: что ждёт 14-дневного окна претензий, что начислено, что отменено.",
        "en": "Shows the agents' ledger: what waits for the 14-day claim window, what is credited, what is cancelled.",
        "es": "Muestra el libro de pagos: lo pendiente (14 días), lo abonado y lo cancelado.",
        "zh": "显示代理账本：等待14天索赔期的、已入账的、已取消的。"},
    "earn-prop-prof-btn": {
        "ru": "Готовит черновик улучшения профиля агента на бирже. Ничего не публикует и не раскрывает данных клиентов.",
        "en": "Prepares a draft improvement of the agent's exchange profile. Publishes nothing and reveals no client data.",
        "es": "Prepara un borrador de mejora del perfil. No publica nada ni revela datos de clientes.",
        "zh": "准备代理平台资料的改进草稿。不发布，也不泄露客户数据。"},
    "earn-monet-btn": {
        "ru": "Считает доли по заказу: комиссия CODE (15 % с кнопкой, 20 % автопилот), ставка агента и остаток.",
        "en": "Computes shares for an order: CODE fee (15% assisted, 20% autopilot), the agent's rate and the remainder.",
        "es": "Calcula el reparto: comisión CODE (15 % / 20 %), tarifa del agente y resto.",
        "zh": "计算订单分成：CODE佣金（辅助15%，自动20%）、代理费率和余额。"},
    "earn-rel-payout-btn": {
        "ru": "Применяет правило выплат: заказы, принятые клиентом, у которых прошли 14 дней без претензий, переходят в «начислено». Деньги наружу не переводятся.",
        "en": "Applies the payout rule: orders accepted by the client with 14 days passed without claims become 'credited'. No money is sent out.",
        "es": "Aplica la regla de pagos: los encargos aceptados con 14 días sin reclamaciones pasan a «abonado». No se envía dinero.",
        "zh": "执行支付规则：客户已验收且14天无索赔的订单转为“已入账”。不会向外转账。"},
    "earn-dispute-btn": {
        "ru": "Оформляет спор по удержанию: при отказе клиента или возврате удержание возвращается, начисление агенту отменяется с причиной. Только владелец.",
        "en": "Files a hold dispute: on client refusal or refund, the hold is refunded and the agent's credit cancelled with a reason. Owner only.",
        "es": "Abre una disputa: ante rechazo o reembolso se devuelve la retención y se anula el abono al agente. Solo el dueño.",
        "zh": "提交扣留争议：客户拒绝或退款时退回扣留款并取消代理收入，并记录原因。仅限所有者。"},
    "earn-bind-ref-btn": {
        "ru": "Привязывает пригласительный код — трёхуровневую цепочку рекомендаций. Пригласить самого себя нельзя.",
        "en": "Binds an invitation code — a three-level referral chain. You cannot refer yourself.",
        "es": "Vincula un código de invitación (cadena de 3 niveles). No puede invitarse a sí mismo.",
        "zh": "绑定邀请码——三级推荐链。不能邀请自己。"},
    "earn-ollama-btn": {
        "ru": "Подключает выбранную модель Ollama на этом компьютере, чтобы агенты работали без платных облачных токенов.",
        "en": "Connects the chosen Ollama model on this computer so agents work without paid cloud tokens.",
        "es": "Conecta el modelo Ollama elegido para trabajar sin tokens de pago.",
        "zh": "连接本机所选的Ollama模型，让代理无需付费云端令牌。"},
    "earn-ollama-pull-btn": {
        "ru": "Скачивает модель через Ollama на этот компьютер. Это несколько гигабайт трафика и места на диске, а работа модели нагружает процессор.",
        "en": "Downloads a model through Ollama to this computer. It takes several gigabytes of traffic and disk, and running it loads the CPU.",
        "es": "Descarga un modelo con Ollama. Ocupa varios gigabytes y su uso carga el procesador.",
        "zh": "通过Ollama下载模型到本机。需要数GB流量和磁盘空间，运行时会占用CPU。"},
    "earn-dev-btn": {
        "ru": "Добавляет это устройство в сеть ваших устройств — с числом ядер и памятью, чтобы делить работу по силам.",
        "en": "Adds this device to your device network — with cores and RAM — to share work by capacity.",
        "es": "Añade este dispositivo a su red con núcleos y RAM para repartir el trabajo.",
        "zh": "把本设备（含核心数和内存）加入您的设备网络，按能力分配工作。"},
    "earn-dev-disp-btn": {
        "ru": "Делит подзадачи заказа между вашими устройствами по их реальной мощности.",
        "en": "Splits an order's subtasks across your devices by their real power.",
        "es": "Reparte las subtareas entre sus dispositivos según su potencia real.",
        "zh": "按实际性能把订单子任务分配到您的各台设备。"},
    "earn-hw-rec-btn": {
        "ru": "Подбирает режим и размер модели под ваш процессор и память, $0.",
        "en": "Picks a mode and model size for your CPU and RAM, $0.",
        "es": "Elige modo y tamaño de modelo para su CPU y RAM, $0.",
        "zh": "根据CPU和内存推荐模式与模型大小（免费）。"},
    "earn-lora-evo-btn": {
        "ru": "Готовит сборку эволюции агента, $0: набор из записей, опыт, сценарий обучения и проверку личности. Видеокарту без вашего решения не занимает.",
        "en": "Prepares an agent evolution build, $0: dataset from records, experience, training script and a persona check. Does not take the GPU without your decision.",
        "es": "Prepara la evolución del agente, $0: datos, experiencia, guion y control de personalidad. No usa la GPU sin su decisión.",
        "zh": "准备代理进化构建（免费）：数据集、经历、训练脚本和人格检查。未经您决定不占用显卡。"},
    "earn-beacon-btn": {
        "ru": "Создаёт маяк Семьи — подписанное Ed25519 приветствие, по которому другие ваши копии PADAM узнают своих. Секретов внутри нет.",
        "en": "Creates a Family beacon — an Ed25519-signed greeting by which your other PADAM copies recognise their own. No secrets inside.",
        "es": "Crea una baliza de la Familia firmada con Ed25519. Sin secretos dentro.",
        "zh": "创建家族信标——Ed25519签名的问候，您的其他PADAM副本据此识别同伴。不含秘密。"},
    "earn-beacon-ver-btn": {
        "ru": "Проверяет чужой маяк: подпись верна и ключ одобрен владельцем.",
        "en": "Checks another beacon: the signature is valid and the key is approved by the owner.",
        "es": "Verifica una baliza: firma válida y clave aprobada por el dueño.",
        "zh": "验证他人信标：签名有效且密钥经所有者批准。"},
    "earn-exp-btn": {
        "ru": "Записывает опыт агента и вывод из него — для его роста. Секреты и спрятанные приказы отсекаются.",
        "en": "Records the agent's experience and reflection — for its growth. Secrets and hidden orders are filtered out.",
        "es": "Registra la experiencia del agente y su reflexión. Se filtran secretos y órdenes ocultas.",
        "zh": "记录代理的经历和反思，用于成长。会过滤秘密和隐藏指令。"},
    "earn-kin-send-btn": {
        "ru": "Отправляет подписанное сообщение другой копии PADAM из вашей Семьи, очищенное от секретов.",
        "en": "Sends a signed message, cleaned of secrets, to another PADAM copy in your Family.",
        "es": "Envía un mensaje firmado y sin secretos a otra copia PADAM de su Familia.",
        "zh": "向家族中另一个PADAM副本发送已签名、去除秘密的消息。"},
    "earn-kin-recv-btn": {
        "ru": "Проверяет полученный пакет: подпись Ed25519 и отсутствие спрятанных приказов.",
        "en": "Checks a received package: Ed25519 signature and no hidden orders.",
        "es": "Verifica un paquete recibido: firma Ed25519 y sin órdenes ocultas.",
        "zh": "检查收到的数据包：Ed25519签名及无隐藏指令。"},
    "earn-store-connect-btn": {
        "ru": "Проверяет ключ магазина цифровых товаров и подключает его. Публикация товаров — только с вашего подтверждения.",
        "en": "Checks the digital store key and connects it. Products are published only with your confirmation.",
        "es": "Verifica la clave de la tienda y la conecta. Solo se publica con su confirmación.",
        "zh": "检查数字商店密钥并连接。商品仅在您确认后发布。"},
    "earn-store-seed-btn": {
        "ru": "Создаёт 3 стартовых черновика товаров, чтобы было с чего начать. Ничего не публикует.",
        "en": "Creates 3 starter product drafts to begin with. Publishes nothing.",
        "es": "Crea 3 borradores de productos para empezar. No publica nada.",
        "zh": "创建3个入门商品草稿作为起点。不发布。"},
    "earn-draft-save-btn": {
        "ru": "Сохраняет черновик товара: название, описание, цену.",
        "en": "Saves a product draft: title, description, price.",
        "es": "Guarda un borrador de producto: título, descripción, precio.",
        "zh": "保存商品草稿：名称、描述、价格。"},
    "earn-wiz-google-btn": {
        "ru": "Открывает отдельное окно браузера PADAM, где вы сами регистрируетесь на площадке через Google. Пароль PADAM не видит и не хранит.",
        "en": "Opens a separate PADAM browser window where you sign up on the platform with Google yourself. PADAM never sees or stores the password.",
        "es": "Abre una ventana aparte donde usted se registra con Google. PADAM no ve ni guarda la contraseña.",
        "zh": "打开独立的PADAM浏览器窗口，由您自己用Google注册平台。PADAM看不到也不保存密码。"},
    "earn-wiz-login-btn": {
        "ru": "Открывает отдельное окно браузера PADAM, где вы сами входите на площадку. Сохраняется только сессия, без пароля.",
        "en": "Opens a separate PADAM browser window where you sign in yourself. Only the session is saved, no password.",
        "es": "Abre una ventana aparte donde usted inicia sesión. Solo se guarda la sesión.",
        "zh": "打开独立的PADAM浏览器窗口由您自己登录。只保存会话，不保存密码。"},
    "earn-wiz-disp-btn": {
        "ru": "Выполняет шаг автопилота на выбранной площадке с проверками: переключатель, суточный лимит, паузы, капча, платные действия.",
        "en": "Runs an autopilot step on the chosen platform with checks: switch, daily limit, pauses, captcha, paid actions.",
        "es": "Ejecuta un paso del piloto en la plataforma con controles: interruptor, límite, pausas, captcha, acciones de pago.",
        "zh": "在所选平台执行一步自动驾驶，并检查开关、每日上限、暂停、验证码和付费操作。"},
    "earn-wiz-off-btn": {
        "ru": "Обращается к официальному API площадки (например, Freelancer.com): кто я, поиск заказов.",
        "en": "Calls the platform's official API (e.g. Freelancer.com): who am I, job search.",
        "es": "Llama a la API oficial de la plataforma (p. ej. Freelancer.com).",
        "zh": "调用平台官方API（如Freelancer.com）：身份、搜索订单。"},
    "earn-wiz-connect-btn": {
        "ru": "Шаг 1 мастера: сохраняет вход на площадку (OAuth, ключ или зашифрованная сессия). Пароли отвергаются.",
        "en": "Wizard step 1: saves the platform sign-in (OAuth, key or encrypted session). Passwords are refused.",
        "es": "Paso 1: guarda el acceso (OAuth, clave o sesión cifrada). Se rechazan contraseñas.",
        "zh": "向导第1步：保存平台登录（OAuth、密钥或加密会话）。拒绝密码。"},
    "earn-wiz-profile-btn": {
        "ru": "Шаг 2 мастера: по вашим ответам на 6 вопросов собирает из памяти черновик профиля для площадки.",
        "en": "Wizard step 2: builds a platform profile draft from memory using your answers to 6 questions.",
        "es": "Paso 2: arma un borrador de perfil desde la memoria con sus 6 respuestas.",
        "zh": "向导第2步：根据您对6个问题的回答，从记忆中生成平台资料草稿。"},
    "earn-wiz-autopick-btn": {
        "ru": "Шаг 3 мастера: отбирает посильные заказы по вашим правилам, считает выгоду и готовит черновик отклика. Отправка — ваша.",
        "en": "Wizard step 3: picks feasible jobs by your rules, computes profit and drafts a bid. Sending is up to you.",
        "es": "Paso 3: elige encargos viables, calcula ganancia y redacta la oferta. El envío es suyo.",
        "zh": "向导第3步：按您的规则挑选可做订单、计算收益并起草投标。是否发送由您决定。"},
    "earn-partner-key-btn": {
        "ru": "Сохраняет ключ партнёра из кабинета aifa.works — для поиска клиентов и сделок.",
        "en": "Saves the partner key from your aifa.works cabinet — for finding clients and deals.",
        "es": "Guarda la clave de socio de su cuenta aifa.works.",
        "zh": "保存aifa.works账户中的合作伙伴密钥，用于寻找客户和交易。"},
    "earn-partner-find-btn": {
        "ru": "Находит сайты с нарушениями доступности из открытого исследования — возможных клиентов в выбранном регионе.",
        "en": "Finds sites with accessibility violations from the open research — possible clients in the chosen region.",
        "es": "Encuentra sitios con fallos de accesibilidad del estudio abierto en la región elegida.",
        "zh": "从公开研究中找出所选地区存在无障碍问题的网站——潜在客户。"},
    "earn-partner-deals-btn": {
        "ru": "Показывает ваши сделки и доход партнёра. Вывод денег — только в кабинете aifa.works.",
        "en": "Shows your partner deals and income. Withdrawals happen only in the aifa.works cabinet.",
        "es": "Muestra sus acuerdos e ingresos. Los retiros solo en aifa.works.",
        "zh": "显示您的合作交易和收入。提现只能在aifa.works账户中进行。"},
    "earn-partner-report-btn": {
        "ru": "Готовит отчёт по выбранному сайту: какие нарушения нашёл сканер.",
        "en": "Prepares a report for the chosen site: what violations the scanner found.",
        "es": "Prepara el informe del sitio elegido: qué fallos encontró el escáner.",
        "zh": "为所选网站生成报告：扫描器发现了哪些问题。"},
    "earn-partner-draft-btn": {
        "ru": "Готовит черновик письма владельцу сайта: отчёт и ваша ссылка партнёра. Проходит Совет Семьи. Ничего не отправляет.",
        "en": "Drafts an email to the site owner: report and your partner link. Reviewed by the Family Council. Sends nothing.",
        "es": "Redacta un correo al dueño del sitio con informe y enlace. Revisado por el Consejo. No envía nada.",
        "zh": "起草给网站所有者的邮件：报告和您的合作链接，经家族议会审核。不发送。"},
    "earn-partner-link-btn": {
        "ru": "Показывает вашу ссылку партнёра с кодом — по ней засчитываются ваши клиенты.",
        "en": "Shows your partner link with code — your clients are credited through it.",
        "es": "Muestra su enlace de socio con código.",
        "zh": "显示带代码的合作链接，客户通过它计入您名下。"},
    "earn-partner-kit-btn": {
        "ru": "Даёт набор партнёра: тексты, шаблоны и правила на вашем языке.",
        "en": "Gives the partner kit: texts, templates and rules in your language.",
        "es": "Entrega el kit de socio: textos, plantillas y reglas en su idioma.",
        "zh": "提供合作伙伴工具包：您语言的文案、模板和规则。"},
    "quick-add-save": {
        "ru": "Сохраняет запись в память. Клавиша Enter делает то же.",
        "en": "Saves the record to memory. The Enter key does the same.",
        "es": "Guarda el registro. La tecla Enter hace lo mismo.",
        "zh": "把记录存入记忆。按Enter键效果相同。"},
    "quick-add-cancel": {
        "ru": "Закрывает окно без сохранения. Клавиша Esc делает то же.",
        "en": "Closes the window without saving. The Esc key does the same.",
        "es": "Cierra sin guardar. La tecla Esc hace lo mismo.",
        "zh": "不保存并关闭窗口。按Esc键效果相同。"},
    "lang-ru": {
        "ru": "Переключает Studio на русский язык.",
        "en": "Switches Studio to Russian.",
        "es": "Cambia Studio al ruso.",
        "zh": "将Studio切换为俄语。"},
    "lang-en": {
        "ru": "Переключает Studio на английский язык.",
        "en": "Switches Studio to English.",
        "es": "Cambia Studio al inglés.",
        "zh": "将Studio切换为英语。"},
    "lang-es": {
        "ru": "Переключает Studio на испанский язык.",
        "en": "Switches Studio to Spanish.",
        "es": "Cambia Studio al español.",
        "zh": "将Studio切换为西班牙语。"},
    "lang-zh": {
        "ru": "Переключает Studio на китайский язык.",
        "en": "Switches Studio to Chinese.",
        "es": "Cambia Studio al chino.",
        "zh": "将Studio切换为中文。"},
    "theme-toggle": {
        "ru": "Переключает светлую и тёмную тему оформления.",
        "en": "Switches between light and dark theme.",
        "es": "Cambia entre tema claro y oscuro.",
        "zh": "切换浅色和深色主题。"},
    "tab-overview": {
        "ru": "Открывает «Обзор»: сколько записей в памяти, что ждёт проверки, состояние защиты.",
        "en": "Opens Overview: how many records are in memory, what awaits review, protection status.",
        "es": "Abre el Resumen: registros, pendientes de revisión y estado de protección.",
        "zh": "打开“概览”：记忆中的记录数、待审核内容、防护状态。"},
    "tab-family": {
        "ru": "Открывает «Семью»: агенты, их общая лента, Совет и совместная работа.",
        "en": "Opens Family: the agents, their shared feed, the Council and teamwork.",
        "es": "Abre la Familia: agentes, su canal, el Consejo y el trabajo en equipo.",
        "zh": "打开“家族”：代理、共享动态、议会和协作。"},
    "tab-migrate": {
        "ru": "Открывает «Переезд»: импорт памяти из других программ с предпросмотром и отменой.",
        "en": "Opens Migration: importing memory from other programs with preview and undo.",
        "es": "Abre la Migración: importar memoria con vista previa y deshacer.",
        "zh": "打开“迁移”：从其他程序导入记忆，可预览和撤销。"},
    "tab-aifa": {
        "ru": "Открывает «AIfa»: вход в кабинет CODE Eternal и разговор с AIfa.",
        "en": "Opens AIfa: sign-in to the CODE Eternal cabinet and chat with AIfa.",
        "es": "Abre AIfa: acceso a CODE Eternal y chat con AIfa.",
        "zh": "打开“AIfa”：登录CODE Eternal账户并与AIfa对话。"},
    "tab-plans": {
        "ru": "Открывает «Тариф и Arweave»: ваш тариф и лимит вечного хранения.",
        "en": "Opens Plan & Arweave: your plan and permanent storage limit.",
        "es": "Abre Plan y Arweave: su plan y el límite de almacenamiento permanente.",
        "zh": "打开“套餐与Arweave”：您的套餐和永久存储额度。"},
    "tab-feed": {
        "ru": "Открывает «Ленту памяти»: все записи по времени, действующие и история.",
        "en": "Opens the Memory feed: all records by time, active and history.",
        "es": "Abre el canal de memoria: todos los registros por fecha.",
        "zh": "打开“记忆动态”：按时间排列的全部记录，含有效和历史。"},
    "tab-search": {
        "ru": "Открывает «Поиск» по смыслу и по словам.",
        "en": "Opens Search by meaning and by words.",
        "es": "Abre la Búsqueda por significado y palabras.",
        "zh": "打开按语义和关键词的“搜索”。"},
    "tab-ask": {
        "ru": "Открывает «Спроси память»: вопрос — ответ только из ваших записей, со ссылками.",
        "en": "Opens Ask memory: a question answered only from your records, with sources.",
        "es": "Abre Pregunte a la memoria: respuestas solo de sus registros.",
        "zh": "打开“问记忆”：仅依据您的记录回答并附来源。"},
    "tab-review": {
        "ru": "Открывает «На проверку»: записи, которые ждут вашего решения — одобрить или отклонить.",
        "en": "Opens Review: records waiting for your decision — approve or reject.",
        "es": "Abre Revisión: registros que esperan su decisión.",
        "zh": "打开“待审核”：等待您批准或拒绝的记录。"},
    "tab-attacks": {
        "ru": "Открывает «Атаки»: что задержала защита — спрятанные приказы, попытки подмены.",
        "en": "Opens Attacks: what protection held — hidden orders, tampering attempts.",
        "es": "Abre Ataques: lo que retuvo la protección.",
        "zh": "打开“攻击”：防护拦下的内容——隐藏指令、篡改企图。"},
    "tab-asof": {
        "ru": "Открывает «Память на дату»: какой была память в прошлом.",
        "en": "Opens Memory as of date: what memory looked like in the past.",
        "es": "Abre Memoria en una fecha: cómo era antes.",
        "zh": "打开“某日记忆”：过去某时的记忆。"},
    "tab-forget": {
        "ru": "Открывает «Забыть»: удаление записи навсегда с доказательством.",
        "en": "Opens Forget: deleting a record forever with proof.",
        "es": "Abre Olvidar: borrar un registro para siempre con prueba.",
        "zh": "打开“遗忘”：永久删除记录并出具证明。"},
    "tab-graph": {
        "ru": "Открывает «Связи»: трёхмерный граф того, как записи связаны между собой.",
        "en": "Opens Links: a 3D graph of how records connect.",
        "es": "Abre Enlaces: un grafo 3D de cómo se conectan los registros.",
        "zh": "打开“关联”：记录之间关系的三维图。"},
    "tab-entities": {
        "ru": "Открывает «Сущности»: люди, проекты и понятия, о которых есть записи.",
        "en": "Opens Entities: people, projects and concepts that records mention.",
        "es": "Abre Entidades: personas, proyectos y conceptos mencionados.",
        "zh": "打开“实体”：记录中提到的人、项目和概念。"},
    "tab-l3": {
        "ru": "Открывает «Вечный слой L3»: закрепления памяти в Arweave, Solana и Bitcoin.",
        "en": "Opens Eternal layer L3: memory anchors in Arweave, Solana and Bitcoin.",
        "es": "Abre la capa eterna L3: anclajes en Arweave, Solana y Bitcoin.",
        "zh": "打开“永恒层L3”：在Arweave、Solana和比特币上的锚定。"},
    "tab-bench": {
        "ru": "Открывает «Бенчмарк»: 100 проверок защиты, запечатанные раунды красной команды, тест качества.",
        "en": "Opens Benchmark: 100 protection checks, sealed red-team rounds, quality test.",
        "es": "Abre Benchmark: 100 comprobaciones, rondas selladas del equipo rojo, prueba de calidad.",
        "zh": "打开“基准测试”：100项防护检查、密封红队轮次、质量测试。"},
    "tab-brain": {
        "ru": "Открывает «Суверенный мозг»: локальная модель, восстановление, ключи, снимки и устройства.",
        "en": "Opens Sovereign brain: local model, recovery, keys, snapshots and devices.",
        "es": "Abre el Cerebro soberano: modelo local, recuperación, claves, instantáneas.",
        "zh": "打开“自主大脑”：本地模型、恢复、密钥、快照和设备。"},
    "tab-earning": {
        "ru": "Открывает «Заработок»: биржи, автопилот, магазины, бюджет токенов и партнёрство.",
        "en": "Opens Earning: exchanges, autopilot, stores, token budget and partnership.",
        "es": "Abre Ingresos: bolsas, piloto automático, tiendas, presupuesto y socios.",
        "zh": "打开“收益”：平台、自动驾驶、商店、令牌预算和合作。"},
    "tab-team": {
        "ru": "Открывает «Команду»: общие пространства памяти и доступы участников.",
        "en": "Opens Team: shared memory spaces and member access.",
        "es": "Abre Equipo: espacios compartidos y accesos.",
        "zh": "打开“团队”：共享记忆空间和成员权限。"},
    "tab-backup": {
        "ru": "Открывает «Резервную копию»: зашифрованная копия, восстановление, выгрузка JSON.",
        "en": "Opens Backup: encrypted copy, restore, JSON export.",
        "es": "Abre Copia: copia cifrada, restauración, exportación JSON.",
        "zh": "打开“备份”：加密备份、恢复、导出JSON。"},
    "tab-settings": {
        "ru": "Открывает «Настройки»: строгий режим, мощность локальной модели, журнал действий.",
        "en": "Opens Settings: strict mode, local model power, action log.",
        "es": "Abre Ajustes: modo estricto, potencia del modelo, registro.",
        "zh": "打开“设置”：严格模式、本地模型功率、操作日志。"},
    "tab-quickstart": {
        "ru": "Открывает «Первый запуск»: подключение к Claude Code, Cursor и VS Code одной командой.",
        "en": "Opens Quick start: connecting to Claude Code, Cursor and VS Code with one command.",
        "es": "Abre Inicio rápido: conectar Claude Code, Cursor y VS Code con un comando.",
        "zh": "打开“快速开始”：一条命令连接Claude Code、Cursor和VS Code。"},
    "tab-help": {
        "ru": "Открывает «Справку»: как устроена память и что делает каждый раздел.",
        "en": "Opens Help: how memory works and what each section does.",
        "es": "Abre Ayuda: cómo funciona la memoria y cada sección.",
        "zh": "打开“帮助”：记忆如何工作以及各部分的作用。"},
    "earn-mail-connect-btn": {
        "ru": "Подключает рабочий почтовый ящик для рассылки: провайдер, адрес, пароль приложения (шифруется) и суточный лимит писем.",
        "en": "Connects a work mailbox for outreach: provider, address, app password (encrypted) and a daily email limit.",
        "es": "Conecta un buzón de trabajo: proveedor, dirección, contraseña de aplicación (cifrada) y límite diario.",
        "zh": "连接用于外联的工作邮箱：服务商、地址、应用密码（加密）和每日发信上限。"},
    "earn-mail-build-btn": {
        "ru": "Готовит по домену с карты отчёт о нарушениях, короткую сводку и письмо владельцу сайта. Само письмо не отправляет.",
        "en": "For a domain from the map, prepares the violations report, a short summary and an email to the site owner. Does not send it.",
        "es": "Para un dominio del mapa prepara el informe, un resumen y el correo al dueño del sitio. No lo envía.",
        "zh": "针对地图中的域名生成问题报告、简短摘要和给网站所有者的邮件。不会发送。"},
    "earn-mail-inbox-btn": {
        "ru": "Читает входящие: ответ STOP — адрес в стоп-лист навсегда; «Шлите список» — ответ с отчётом; остальное — вам на решение.",
        "en": "Reads the inbox: STOP — the address goes on the stop list forever; “Send the list” — reply with the report; anything else — to you.",
        "es": "Lee la entrada: STOP — a la lista para siempre; «Envíen la lista» — respuesta con el informe; lo demás — para usted.",
        "zh": "读取收件箱：STOP——地址永久加入停发名单；“请发清单”——回复报告；其他——交给您处理。"},
    "earn-stop-all-btn": {
        "ru": "Одной кнопкой останавливает всё, что может действовать само: автопилот и его фоновый поток, автоотклики на всех площадках, рассылку со всех ящиков. Ничего не удаляет — включается теми же кнопками.",
        "en": "One button stops everything that can act on its own: the autopilot and its worker, auto-bids on every platform, outreach from every mailbox. Deletes nothing — turn things back on with the same buttons.",
        "es": "Un botón detiene todo lo que actúa solo: piloto y su proceso, ofertas automáticas, envíos de todos los buzones. No borra nada.",
        "zh": "一键停止所有自动行为：自动驾驶及其后台线程、所有平台自动投标、所有邮箱外联。不删除任何内容。"},
    "earn-sim-on-btn": {
        "ru": "Включает симуляцию: автопилот собирает заказы и готовит отклики, но ничего не отправляет — только записывает, что ушло бы.",
        "en": "Turns on simulation: the autopilot collects jobs and prepares bids but sends nothing — it only records what would have gone out.",
        "es": "Activa la simulación: prepara ofertas pero no envía nada, solo registra.",
        "zh": "开启模拟：自动驾驶收集订单并准备投标，但不发送，只记录。"},
    "earn-sim-off-btn": {
        "ru": "Переводит в боевой режим: автоотклики уходят на площадки, где включён автопилот. Только владелец.",
        "en": "Switches to live mode: auto-bids go out on platforms with autopilot on. Owner only.",
        "es": "Pasa a modo real: las ofertas salen. Solo el dueño.",
        "zh": "切换到实战模式：在开启自动驾驶的平台发送投标。仅限所有者。"},
    "earn-sim-report-btn": {
        "ru": "Показывает, сколько откликов и на какую сумму автопилот отправил бы за последние 24 часа.",
        "en": "Shows how many bids, and for how much, the autopilot would have sent in the last 24 hours.",
        "es": "Muestra cuántas ofertas y por cuánto habría enviado en 24 horas.",
        "zh": "显示过去24小时自动驾驶本会发送的投标数量和金额。"},
    "qs-go-agent-btn": {
        "ru": "Прокручивает к полю «ID агента» в блоке Семьи: впишите имя агента (например, aifa_claude), чтобы он работал от вашей памяти.",
        "en": "Scrolls to the «Agent ID» field in the Family block: enter the agent name (for example aifa_claude) so it works from your memory.",
        "es": "Desplaza al campo «ID del agente» del bloque Familia: escriba el nombre del agente (por ejemplo aifa_claude) para que trabaje con su memoria.",
        "zh": "滚动到“家庭”区块的“代理 ID”字段：填写代理名称（例如 aifa_claude），让它使用您的记忆工作。"},
    "qs-go-wiz-btn": {
        "ru": "Открывает мастер 34 бирж фриланса: у каждой указано, что можно автоматически, что — черновиком с вашей кнопкой, а что пока нельзя.",
        "en": "Opens the wizard for 34 freelance platforms: each shows what can run automatically, what is a draft with your button, and what is not supported yet.",
        "es": "Abre el asistente de 34 plataformas: cada una indica qué puede ser automático, qué es borrador con su botón y qué aún no.",
        "zh": "打开 34 个自由职业平台向导：每个平台注明可自动执行的内容、需您点击的草稿以及暂不支持的内容。"},
    "qs-go-mail-btn": {
        "ru": "Прокручивает к подключению рабочей почты: адрес и пароль приложения от вашего ящика (не основной пароль). Можно подключить до 12 ящиков.",
        "en": "Scrolls to connecting a work mailbox: the address and an app password of your mailbox (not the main password). Up to 12 mailboxes.",
        "es": "Desplaza a conectar un buzón: la dirección y una contraseña de aplicación (no la principal). Hasta 12 buzones.",
        "zh": "滚动到连接工作邮箱：邮箱地址和应用专用密码（不是主密码）。最多可连接 12 个邮箱。"},
    "qs-go-leads-btn": {
        "ru": "Прокручивает к полю загрузки базы адресатов: вставьте список адресов или строк «имя, почта, сайт».",
        "en": "Scrolls to the contact list field: paste addresses or lines «name, email, website».",
        "es": "Desplaza al campo de la lista de contactos: pegue direcciones o líneas «nombre, correo, sitio».",
        "zh": "滚动到联系人列表字段：粘贴邮箱地址或“姓名, 邮箱, 网站”格式的行。"},
    "qs-launch-all-btn": {
        "ru": "Включает автоматическую рассылку и автопилот заказов 24/7: письма настоящим людям будут уходить сами с подключённых ящиков, в пределах суточных лимитов, со стоп-листом. Перед включением спросит подтверждение. Выключить — «Остановить всё».",
        "en": "Turns on automatic outreach and the order autopilot 24/7: emails to real people will be sent by themselves from your mailboxes, within daily limits, with the stop list. Asks for confirmation first. To turn off — «Stop everything».",
        "es": "Activa el envío automático y el autopiloto 24/7: los correos a personas reales saldrán solos desde sus buzones, dentro de los límites diarios y con la lista STOP. Pide confirmación antes. Para apagar — «Detener todo».",
        "zh": "开启 24/7 自动外联和订单自动驾驶：将从您的邮箱自动向真人发信，遵守每日上限和停发名单。开启前会请求确认。关闭请点“全部停止”。"},
    "qs-refresh-btn": {
        "ru": "Перечитывает состояние четырёх шагов быстрого старта: агент, почта, база адресатов, автопилот.",
        "en": "Re-reads the state of the four quick-start steps: agent, mail, contact list, autopilot.",
        "es": "Vuelve a leer el estado de los cuatro pasos: agente, correo, lista de contactos, autopiloto.",
        "zh": "重新读取快速开始四个步骤的状态：代理、邮箱、联系人列表、自动驾驶。"},
    "earn-mail-import-btn": {
        "ru": "Загружает вставленный список клиентов в базу адресатов: дубли и адреса из стоп-листа отбрасываются. Писем при этом не отправляет.",
        "en": "Loads the pasted client list into the contact base: duplicates and stop-listed addresses are dropped. Sends no emails.",
        "es": "Carga la lista pegada en la base de contactos: se descartan duplicados y direcciones de la lista STOP. No envía correos.",
        "zh": "将粘贴的客户列表导入联系人库：去除重复和停发名单中的地址。不会发送邮件。"},
    "earn-mail-batch-btn": {
        "ru": "Запускает пакет рассылки по базе карты исследования: письма владельцам сайтов с нарушениями с подключённых ящиков, по очереди и в пределах их суточных лимитов; стоп-лист и 30-дневная бронь домена соблюдаются. Это отправка настоящим людям — нажимает только владелец.",
        "en": "Starts an outreach batch from the research map: emails to owners of sites with violations, rotating your mailboxes within their daily limits; the stop list and 30-day domain hold are respected. This emails real people — owner only.",
        "es": "Lanza un lote de envíos del mapa: correos a dueños de sitios con fallos, rotando buzones dentro de sus límites; se respetan la lista STOP y la reserva de 30 días. Son personas reales: solo el dueño.",
        "zh": "按研究地图启动批量外联：在每日上限内轮换邮箱，向有问题网站的所有者发信；遵守停发名单和30天域名保留。这是给真人发信——仅限所有者。"},
    "earn-mail-followup-btn": {
        "ru": "Отправляет одно повторное письмо тем, кто не ответил на первое за 4 дня. Повторно тому же адресу не пишет, стоп-лист соблюдается.",
        "en": "Sends one follow-up to those who did not answer the first email within 4 days. Never twice to the same address; the stop list is respected.",
        "es": "Envía un único seguimiento a quien no respondió en 4 días. Nunca dos veces; se respeta la lista STOP.",
        "zh": "向4天内未回复首封邮件的人发送一封跟进邮件。同一地址不重复，遵守停发名单。"},
}
