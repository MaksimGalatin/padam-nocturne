"""Переводы данных мастера бирж (platform_wizard.py) на en/es/zh — 19.11.2026, по слову Папы «ПЕРЕВОДЫ везде».
Ключ — русская строка из данных дословно. Перевод выполнен вручную, без платных сервисов."""

WIZARD_TR: dict[str, dict[str, str]] = {
 "черновик и кнопка": {
  "en": "draft and button",
  "es": "borrador y botón",
  "zh": "草稿与按钮"
 },
 "OAuth 2.0 (Upwork GraphQL API). Пароли не храним.": {
  "en": "OAuth 2.0 (Upwork GraphQL API). We store no passwords.",
  "es": "OAuth 2.0 (Upwork GraphQL API). No guardamos contraseñas.",
  "zh": "OAuth 2.0（Upwork GraphQL API）。我们不存储密码。"
 },
 "Официальный GraphQL OAuth 2.0 API разрешает поиск и учёт, но правила Upwork запрещают автоотправку откликов ботами — черновик готовит агент, отправляет владелец кнопкой (15%).": {
  "en": "The official GraphQL OAuth 2.0 API allows search and tracking, but Upwork rules forbid bots auto-sending proposals — the agent prepares a draft, the owner sends it with a button (15%).",
  "es": "La API oficial GraphQL OAuth 2.0 permite buscar y llevar el registro, pero las reglas de Upwork prohíben que los bots envíen propuestas automáticamente: el agente prepara un borrador y el dueño lo envía con un botón (15%).",
  "zh": "官方 GraphQL OAuth 2.0 API 允许搜索和记账，但 Upwork 规则禁止机器人自动发送投标——代理准备草稿，由所有者点击按钮发送（15%）。"
 },
 "правила площадки запрещают автоматику, риск блокировки аккаунта": {
  "en": "platform rules forbid automation, risk of account suspension",
  "es": "las reglas de la plataforma prohíben la automatización, riesgo de bloqueo de la cuenta",
  "zh": "平台规则禁止自动化，有账号被封风险"
 },
 "Вход через окно браузера (сохраняем только зашифрованную сессию, без пароля).": {
  "en": "Sign-in through a browser window (we keep only an encrypted session, no password).",
  "es": "Acceso mediante una ventana del navegador (solo guardamos una sesión cifrada, sin contraseña).",
  "zh": "通过浏览器窗口登录（只保存加密会话，不保存密码）。"
 },
 "Публичного API продавца нет, Terms of Service Fiverr строго запрещают ботов и авто-скрипты — агент готовит черновики гигов и ответов, публикует человек кнопкой (15%).": {
  "en": "No public seller API, and Fiverr Terms of Service strictly forbid bots and auto-scripts — the agent drafts gigs and replies, a person publishes them with a button (15%).",
  "es": "No hay API pública para vendedores y los Términos de Fiverr prohíben estrictamente bots y scripts automáticos: el agente prepara borradores de gigs y respuestas, una persona los publica con un botón (15%).",
  "zh": "没有公开的卖家 API，Fiverr 服务条款严禁机器人和自动脚本——代理起草服务项目和回复，由人点击按钮发布（15%）。"
 },
 "OAuth 2.0 Bearer токен (accounts.freelancer.com/oauth).": {
  "en": "OAuth 2.0 Bearer token (accounts.freelancer.com/oauth).",
  "es": "Token OAuth 2.0 Bearer (accounts.freelancer.com/oauth).",
  "zh": "OAuth 2.0 Bearer 令牌（accounts.freelancer.com/oauth）。"
 },
 "Есть официальный REST API и OAuth 2.0; для защиты аккаунта от блокировки за спам-ставки отклик формируется черновиком и отправляется кнопкой владельца (15%).": {
  "en": "There is an official REST API and OAuth 2.0; to protect the account from bans for spam bids, the proposal is prepared as a draft and sent with the owner's button (15%).",
  "es": "Hay una API REST oficial y OAuth 2.0; para proteger la cuenta de bloqueos por pujas de spam, la propuesta se prepara como borrador y se envía con el botón del dueño (15%).",
  "zh": "有官方 REST API 和 OAuth 2.0；为防止账号因垃圾投标被封，投标先生成草稿，由所有者点击按钮发送（15%）。"
 },
 "Вход через окно браузера (зашифрованная сессия без пароля).": {
  "en": "Sign-in through a browser window (encrypted session, no password).",
  "es": "Acceso mediante una ventana del navegador (sesión cifrada, sin contraseña).",
  "zh": "通过浏览器窗口登录（加密会话，无密码）。"
 },
 "Публичного REST API нет, правила WorkStream запрещают внешнюю автоматизацию — агент готовит черновик оффера/профиля, отправляет владелец кнопкой (15%).": {
  "en": "No public REST API, and WorkStream rules forbid external automation — the agent drafts the offer/profile, the owner sends it with a button (15%).",
  "es": "No hay API REST pública y las reglas de WorkStream prohíben la automatización externa: el agente prepara el borrador de oferta/perfil y el dueño lo envía con un botón (15%).",
  "zh": "没有公开 REST API，WorkStream 规则禁止外部自动化——代理起草报价/资料，由所有者点击按钮发送（15%）。"
 },
 "Комиссия площадки 0%, открытого публичного API для авто-откликов нет — агент упаковывает портфолио и черновики откликов под кнопку владельца (15%).": {
  "en": "0% platform fee, no open public API for auto-proposals — the agent packages the portfolio and proposal drafts for the owner's button (15%).",
  "es": "Comisión de la plataforma 0 %, sin API pública abierta para propuestas automáticas: el agente prepara el portafolio y borradores de propuestas para el botón del dueño (15%).",
  "zh": "平台佣金 0%，没有用于自动投标的公开 API——代理整理作品集和投标草稿，供所有者点击按钮（15%）。"
 },
 "пока нельзя": {
  "en": "not yet",
  "es": "aún no",
  "zh": "暂不支持"
 },
 "Пока нельзя: требуется личный видео-скрининг и живые интервью разработчика.": {
  "en": "Not yet: personal video screening and live developer interviews are required.",
  "es": "Aún no: se exige una entrevista personal en video y entrevistas en vivo con el desarrollador.",
  "zh": "暂不支持：需要本人视频面试和开发者现场面试。"
 },
 "Закрытая сеть без публичного API; обязательны 4 этапа живого собеседования и live-coding с человеком по правилам Toptal.": {
  "en": "A closed network without a public API; Toptal rules require 4 stages of live interviews and live coding with a person.",
  "es": "Red cerrada sin API pública; las reglas de Toptal exigen 4 etapas de entrevistas en vivo y live coding con una persona.",
  "zh": "封闭网络，无公开 API；Toptal 规则要求与真人进行 4 轮现场面试和现场编程。"
 },
 "Пока нельзя: обязательное видео-интервью и закрытый рекрутинговый контур.": {
  "en": "Not yet: a mandatory video interview and a closed recruiting process.",
  "es": "Aún no: entrevista en video obligatoria y proceso de selección cerrado.",
  "zh": "暂不支持：必须视频面试，招聘流程封闭。"
 },
 "Публичного API нет; допуск к заказам открывается только после живого видео-интервью и проверки личности человека.": {
  "en": "No public API; access to jobs opens only after a live video interview and identity check.",
  "es": "No hay API pública; el acceso a los encargos se abre solo tras una entrevista en video en vivo y la verificación de identidad.",
  "zh": "没有公开 API；只有通过现场视频面试和身份核验后才能接单。"
 },
 "Ключ API Guru Developer Network или зашифрованная сессия.": {
  "en": "Guru Developer Network API key or an encrypted session.",
  "es": "Clave de API de Guru Developer Network o una sesión cifrada.",
  "zh": "Guru Developer Network API 密钥或加密会话。"
 },
 "Есть API/WorkRooms, но правила запрещают спам-ботов — агент оценивает проект и готовит черновик Quote под кнопку владельца (15%).": {
  "en": "There is an API/WorkRooms, but the rules forbid spam bots — the agent evaluates the project and drafts a Quote for the owner's button (15%).",
  "es": "Hay API/WorkRooms, pero las reglas prohíben bots de spam: el agente evalúa el proyecto y prepara un borrador de Quote para el botón del dueño (15%).",
  "zh": "有 API/WorkRooms，但规则禁止垃圾机器人——代理评估项目并起草报价，供所有者点击按钮（15%）。"
 },
 "Пока нельзя: каждый отклик требует платной покупки Bark Credits.": {
  "en": "Not yet: every response requires buying paid Bark Credits.",
  "es": "Aún no: cada respuesta exige comprar Bark Credits de pago.",
  "zh": "暂不支持：每次回复都需要购买付费的 Bark Credits。"
 },
 "Нет публичного API, а каждый отклик списывает платные кредиты с карты до согласия клиента (запрещено правилом защиты денег Архитектора).": {
  "en": "No public API, and every response charges paid credits to the card before the client agrees (forbidden by the Architect's money-protection rule).",
  "es": "No hay API pública y cada respuesta cobra créditos de pago a la tarjeta antes de que el cliente acepte (lo prohíbe la regla de protección del dinero del Arquitecto).",
  "zh": "没有公开 API，且每次回复都会在客户同意前从卡上扣除付费点数（违反架构师的资金保护规则）。"
 },
 "Токен Malt OpenAPI (api.malt.com) или сессия браузера.": {
  "en": "Malt OpenAPI token (api.malt.com) or a browser session.",
  "es": "Token de Malt OpenAPI (api.malt.com) o sesión del navegador.",
  "zh": "Malt OpenAPI 令牌（api.malt.com）或浏览器会话。"
 },
 "Официальный OpenAPI покрывает биллинг и профиль FMS, а предложения клиентам подтверждаются человеком кнопкой (15%).": {
  "en": "The official OpenAPI covers billing and the FMS profile, while offers to clients are confirmed by a person with a button (15%).",
  "es": "La OpenAPI oficial cubre la facturación y el perfil FMS, y las ofertas a clientes las confirma una persona con un botón (15%).",
  "zh": "官方 OpenAPI 涵盖账单和 FMS 资料，向客户的报价由人点击按钮确认（15%）。"
 },
 "Публичного REST API нет, правила Kwork запрещают неофициальные парсеры и авто-ботов — агент готовит черновик кворка и отклика на бирже, отправляет владелец кнопкой (15%).": {
  "en": "No public REST API, and Kwork rules forbid unofficial scrapers and auto-bots — the agent drafts the kwork and the proposal, the owner sends it with a button (15%).",
  "es": "No hay API REST pública y las reglas de Kwork prohíben scrapers no oficiales y bots automáticos: el agente prepara el borrador del kwork y de la propuesta, el dueño lo envía con un botón (15%).",
  "zh": "没有公开 REST API，Kwork 规则禁止非官方爬虫和自动机器人——代理起草服务和投标，由所有者点击按钮发送（15%）。"
 },
 "Открытого API нет, пользовательское соглашение FL.ru запрещает авто-скрипты — агент готовит черновик ответа и расчёт Безопасной сделки под кнопку владельца (15%).": {
  "en": "No open API, and the FL.ru user agreement forbids auto-scripts — the agent drafts the reply and the Safe Deal estimate for the owner's button (15%).",
  "es": "No hay API abierta y el acuerdo de usuario de FL.ru prohíbe scripts automáticos: el agente prepara el borrador de respuesta y el cálculo de Trato Seguro para el botón del dueño (15%).",
  "zh": "没有开放 API，FL.ru 用户协议禁止自动脚本——代理起草回复和“安全交易”报价，供所有者点击按钮（15%）。"
 },
 "Публичный API отсутствует; агент оценивает ТЗ и формирует черновик заявки для отправки кнопкой владельца (15%).": {
  "en": "No public API; the agent evaluates the brief and drafts an application to be sent with the owner's button (15%).",
  "es": "No hay API pública; el agente evalúa el encargo y prepara un borrador de solicitud para enviarlo con el botón del dueño (15%).",
  "zh": "没有公开 API；代理评估需求并起草申请，由所有者点击按钮发送（15%）。"
 },
 "Публичного API нет, антифрод блокирует авто-ботов — агент готовит черновик отклика и профиля, публикует владелец кнопкой (15%).": {
  "en": "No public API and anti-fraud blocks auto-bots — the agent drafts the proposal and profile, the owner publishes them with a button (15%).",
  "es": "No hay API pública y el antifraude bloquea bots automáticos: el agente prepara el borrador de propuesta y perfil, el dueño lo publica con un botón (15%).",
  "zh": "没有公开 API，反欺诈系统会拦截自动机器人——代理起草投标和资料，由所有者点击按钮发布（15%）。"
 },
 "Официальный OAuth 2.0 токен Avito API (developers.avito.ru).": {
  "en": "Official Avito API OAuth 2.0 token (developers.avito.ru).",
  "es": "Token OAuth 2.0 oficial de la API de Avito (developers.avito.ru).",
  "zh": "官方 Avito API OAuth 2.0 令牌（developers.avito.ru）。"
 },
 "Есть официальный Avito OpenAPI (OAuth 2.0) для объявлений и мессенджера; публикация объявлений и финальных смет идёт по кнопке владельца (15%).": {
  "en": "There is an official Avito OpenAPI (OAuth 2.0) for listings and the messenger; listings and final estimates are published with the owner's button (15%).",
  "es": "Hay una OpenAPI oficial de Avito (OAuth 2.0) para anuncios y mensajería; los anuncios y presupuestos finales se publican con el botón del dueño (15%).",
  "zh": "有用于广告和消息的官方 Avito OpenAPI（OAuth 2.0）；广告和最终报价由所有者点击按钮发布（15%）。"
 },
 "Пока нельзя: API доступен только корпоративным партнёрам YouDo Business, отклики платные.": {
  "en": "Not yet: the API is available only to YouDo Business corporate partners, and responses are paid.",
  "es": "Aún no: la API solo está disponible para socios corporativos de YouDo Business y las respuestas son de pago.",
  "zh": "暂不支持：API 仅向 YouDo Business 企业合作伙伴开放，回复需付费。"
 },
 "Нет открытого API для исполнителей, платные отклики/подписка и жёсткая антибот-защита по правилам YouDo.": {
  "en": "No open API for freelancers, paid responses/subscription and strict anti-bot protection under YouDo rules.",
  "es": "No hay API abierta para profesionales, respuestas/suscripción de pago y una fuerte protección antibots según las reglas de YouDo.",
  "zh": "没有面向自由职业者的开放 API，回复/订阅需付费，且 YouDo 规则有严格的反机器人保护。"
 },
 "Пока нельзя: платная подписка на входе, капча и бан с удержанием средств за автоматизацию.": {
  "en": "Not yet: a paid subscription at entry, a captcha, and bans with withheld funds for automation.",
  "es": "Aún no: suscripción de pago al entrar, captcha y bloqueo con retención de fondos por automatización.",
  "zh": "暂不支持：入驻需付费订阅、验证码，并会因自动化封号并扣留资金。"
 },
 "Публичного API нет; правила Workzilla наказывают любую автоматизацию блокировкой аккаунта с конфискацией баланса.": {
  "en": "No public API; Workzilla rules punish any automation with account suspension and confiscation of the balance.",
  "es": "No hay API pública; las reglas de Workzilla castigan cualquier automatización con el bloqueo de la cuenta y la confiscación del saldo.",
  "zh": "没有公开 API；Workzilla 规则对任何自动化都会封号并没收余额。"
 },
 "автопилот": {
  "en": "autopilot",
  "es": "piloto automático",
  "zh": "自动驾驶"
 },
 "Bearer API-ключ Lemon Squeezy v1 + секрет вебхука X-Signature.": {
  "en": "Lemon Squeezy v1 Bearer API key + X-Signature webhook secret.",
  "es": "Clave API Bearer de Lemon Squeezy v1 + secreto de webhook X-Signature.",
  "zh": "Lemon Squeezy v1 Bearer API 密钥 + X-Signature webhook 密钥。"
 },
 "Официальный JSON:API v1 (чтение заказов и товаров) + криптографические вебхуки HMAC-SHA256 позволяют вести учёт продаж и выдачу на автопилоте (20%).": {
  "en": "The official JSON:API v1 (reading orders and products) + cryptographic HMAC-SHA256 webhooks allow sales tracking and delivery on autopilot (20%).",
  "es": "La JSON:API v1 oficial (lectura de pedidos y productos) + webhooks criptográficos HMAC-SHA256 permiten registrar ventas y entregar en piloto automático (20%).",
  "zh": "官方 JSON:API v1（读取订单和商品）+ 加密 HMAC-SHA256 webhook，可自动记录销售并交付（20%）。"
 },
 "OAuth Bearer Access Token Gumroad API v2.": {
  "en": "Gumroad API v2 OAuth Bearer access token.",
  "es": "Token de acceso OAuth Bearer de Gumroad API v2.",
  "zh": "Gumroad API v2 OAuth Bearer 访问令牌。"
 },
 "Официальный REST API v2 поддерживает создание/обновление товаров (с кнопки владельца), чтение продаж и Gumroad Ping вебхуки на автопилоте (20%).": {
  "en": "The official REST API v2 supports creating/updating products (from the owner's button), reading sales and Gumroad Ping webhooks on autopilot (20%).",
  "es": "La API REST v2 oficial permite crear/actualizar productos (con el botón del dueño), leer ventas y webhooks Gumroad Ping en piloto automático (20%).",
  "zh": "官方 REST API v2 支持创建/更新商品（由所有者点击按钮）、读取销售以及 Gumroad Ping webhook 自动运行（20%）。"
 },
 "API-ключ Payhip (v2 coupons / webhooks).": {
  "en": "Payhip API key (v2 coupons / webhooks).",
  "es": "Clave API de Payhip (v2 coupons / webhooks).",
  "zh": "Payhip API 密钥（v2 coupons / webhooks）。"
 },
 "Выдача цифровых файлов и приём вебхуков автоматизированы (20%), а начисление доли ждёт кнопки сверки выплаты владельцем (т.к. подпись sha256(api_key) статична).": {
  "en": "Digital file delivery and webhook intake are automated (20%), while the share accrual waits for the owner's payout-reconciliation button (because the sha256(api_key) signature is static).",
  "es": "La entrega de archivos digitales y la recepción de webhooks están automatizadas (20%), y el abono de la parte espera el botón de conciliación de pagos del dueño (porque la firma sha256(api_key) es estática).",
  "zh": "数字文件交付和 webhook 接收已自动化（20%），分成入账需等待所有者点击付款核对按钮（因为 sha256(api_key) 签名是固定的）。"
 },
 "Bearer API-ключ Whop v1 + Standard Webhooks секрет (ws_...).": {
  "en": "Whop v1 Bearer API key + Standard Webhooks secret (ws_...).",
  "es": "Clave API Bearer de Whop v1 + secreto de Standard Webhooks (ws_...).",
  "zh": "Whop v1 Bearer API 密钥 + Standard Webhooks 密钥（ws_...）。"
 },
 "Полный REST API v1 (accounts/me, products, payments) и Standard Webhooks обеспечивают полный автопилот продаж (20%).": {
  "en": "The full REST API v1 (accounts/me, products, payments) and Standard Webhooks provide a full sales autopilot (20%).",
  "es": "La API REST v1 completa (accounts/me, products, payments) y Standard Webhooks ofrecen un piloto automático completo de ventas (20%).",
  "zh": "完整的 REST API v1（accounts/me、products、payments）和 Standard Webhooks 可实现销售全自动（20%）。"
 },
 "Вход через окно браузера (зашифрованная сессия без пароля) + вебхук Zapier.": {
  "en": "Sign-in through a browser window (encrypted session, no password) + Zapier webhook.",
  "es": "Acceso mediante una ventana del navegador (sesión cifrada, sin contraseña) + webhook de Zapier.",
  "zh": "通过浏览器窗口登录（加密会话，无密码）+ Zapier webhook。"
 },
 "Открытого публичного REST API для управления витриной нет — агент готовит черновики продуктов и воронки, владелец публикует кнопкой в кабинете (15%).": {
  "en": "No open public REST API to manage the storefront — the agent drafts products and the funnel, the owner publishes them with a button in the dashboard (15%).",
  "es": "No hay API REST pública abierta para gestionar la tienda: el agente prepara borradores de productos y del embudo, el dueño los publica con un botón en el panel (15%).",
  "zh": "没有用于管理店铺的公开 REST API——代理起草商品和销售漏斗，由所有者在后台点击按钮发布（15%）。"
 },
 "Etsy Open API v3 OAuth 2.0 + x-api-key.": {
  "en": "Etsy Open API v3 OAuth 2.0 + x-api-key.",
  "es": "Etsy Open API v3 OAuth 2.0 + x-api-key.",
  "zh": "Etsy Open API v3 OAuth 2.0 + x-api-key。"
 },
 "Etsy API v3 позволяет создавать draft-листинги цифровых товаров, но публикация каждого листинга платная ($0.20) — строго по кнопке владельца (15%).": {
  "en": "Etsy API v3 can create draft listings of digital goods, but publishing each listing is paid ($0.20) — strictly by the owner's button (15%).",
  "es": "La API v3 de Etsy permite crear borradores de anuncios de productos digitales, pero publicar cada anuncio es de pago ($0.20): solo con el botón del dueño (15%).",
  "zh": "Etsy API v3 可以创建数字商品的草稿列表，但每个列表发布需付费（0.20 美元）——严格由所有者点击按钮（15%）。"
 },
 "Bearer API-ключ Sellfy API v1 + секрет вебхука.": {
  "en": "Sellfy API v1 Bearer API key + webhook secret.",
  "es": "Clave API Bearer de Sellfy API v1 + secreto de webhook.",
  "zh": "Sellfy API v1 Bearer API 密钥 + webhook 密钥。"
 },
 "Официальный REST API v1 (/v1/products, /v1/orders) и вебхуки заказов работают в режиме автопилота (20%).": {
  "en": "The official REST API v1 (/v1/products, /v1/orders) and order webhooks run in autopilot mode (20%).",
  "es": "La API REST v1 oficial (/v1/products, /v1/orders) y los webhooks de pedidos funcionan en piloto automático (20%).",
  "zh": "官方 REST API v1（/v1/products、/v1/orders）和订单 webhook 以自动驾驶模式运行（20%）。"
 },
 "Пока нельзя: нет публичного API продавца и требуется ручная премодерация открытия магазина.": {
  "en": "Not yet: no public seller API, and opening a shop requires manual pre-moderation.",
  "es": "Aún no: no hay API pública para vendedores y abrir la tienda requiere premoderación manual.",
  "zh": "暂不支持：没有公开的卖家 API，开店需人工预审。"
 },
 "Публичный REST API для загрузки товаров и чтения продаж отсутствует, открытие витрины требует ручного отбора кураторами Creative Market.": {
  "en": "There is no public REST API for uploading products and reading sales; opening a storefront requires manual selection by Creative Market curators.",
  "es": "No hay API REST pública para subir productos y leer ventas; abrir la tienda requiere la selección manual de los curadores de Creative Market.",
  "zh": "没有用于上传商品和读取销售的公开 REST API；开设店铺需 Creative Market 策展人人工筛选。"
 },
 "Вход через окно браузера (зашифрованная сессия) или RSA-2048 ключ партнёра.": {
  "en": "Sign-in through a browser window (encrypted session) or a partner RSA-2048 key.",
  "es": "Acceso mediante una ventana del navegador (sesión cifrada) o clave RSA-2048 de socio.",
  "zh": "通过浏览器窗口登录（加密会话）或合作伙伴 RSA-2048 密钥。"
 },
 "B2B-каталог агентств: агент готовит черновик профиля компании, портфолио и ответы на входящие лиды, публикует владелец кнопкой (15%).": {
  "en": "B2B agency directory: the agent drafts the company profile, portfolio and replies to incoming leads, the owner publishes them with a button (15%).",
  "es": "Catálogo B2B de agencias: el agente prepara el borrador del perfil de la empresa, el portafolio y las respuestas a leads entrantes, el dueño lo publica con un botón (15%).",
  "zh": "B2B 机构目录：代理起草公司资料、作品集和对潜在客户的回复，由所有者点击按钮发布（15%）。"
 },
 "Официальный LinkedIn OAuth 2.0 токен (learn.microsoft.com/linkedin).": {
  "en": "Official LinkedIn OAuth 2.0 token (learn.microsoft.com/linkedin).",
  "es": "Token OAuth 2.0 oficial de LinkedIn (learn.microsoft.com/linkedin).",
  "zh": "官方 LinkedIn OAuth 2.0 令牌（learn.microsoft.com/linkedin）。"
 },
 "Правила LinkedIn запрещают неуправляемую авто-рассылку — агент готовит черновики профиля, постов и B2B-ответов, отправляет владелец кнопкой (15%).": {
  "en": "LinkedIn rules forbid unmanaged automated messaging — the agent drafts the profile, posts and B2B replies, the owner sends them with a button (15%).",
  "es": "Las reglas de LinkedIn prohíben los envíos automáticos no gestionados: el agente prepara borradores del perfil, publicaciones y respuestas B2B, el dueño los envía con un botón (15%).",
  "zh": "LinkedIn 规则禁止无人管理的自动群发——代理起草资料、帖子和 B2B 回复，由所有者点击按钮发送（15%）。"
 },
 "API-ключ провайдера данных Datarade / вебхук.": {
  "en": "Datarade data provider API key / webhook.",
  "es": "Clave API del proveedor de datos Datarade / webhook.",
  "zh": "Datarade 数据提供商 API 密钥 / webhook。"
 },
 "Проверено 18.11.2026: листинг на Datarade создаётся вручную и проходит KYC провайдера, политика публикаций запрещает персональные данные в листинге — агент готовит описание набора данных, владелец публикует кнопкой (15%).": {
  "en": "Checked 18.11.2026: a Datarade listing is created manually and goes through provider KYC, and the publishing policy forbids personal data in a listing — the agent drafts the dataset description, the owner publishes it with a button (15%).",
  "es": "Comprobado el 18.11.2026: el anuncio en Datarade se crea manualmente y pasa el KYC del proveedor, y la política de publicación prohíbe datos personales en el anuncio: el agente prepara la descripción del conjunto de datos, el dueño la publica con un botón (15%).",
  "zh": "2026-11-18 已核实：Datarade 上的列表需人工创建并通过提供商 KYC，发布政策禁止列表中包含个人数据——代理起草数据集说明，由所有者点击按钮发布（15%）。"
 },
 "Ключ API витрины DataToLeads / вебхук оплаты.": {
  "en": "DataToLeads storefront API key / payment webhook.",
  "es": "Clave API de la tienda DataToLeads / webhook de pago.",
  "zh": "DataToLeads 店铺 API 密钥 / 付款 webhook。"
 },
 "Проверено 18.11.2026: размещение продавца платное (по материалам самой компании — от $499 в месяц) — без отдельного «да» владельца на расход не подключаем.": {
  "en": "Checked 18.11.2026: seller placement is paid (according to the company's own materials — from $499 per month) — not connected without the owner's separate «yes» to the expense.",
  "es": "Comprobado el 18.11.2026: la colocación del vendedor es de pago (según los materiales de la propia empresa, desde $499 al mes): no se conecta sin un «sí» aparte del dueño a ese gasto.",
  "zh": "2026-11-18 已核实：卖家入驻需付费（据该公司自身资料，每月 499 美元起）——未经所有者对该支出单独同意，不予接入。"
 },
 "AppSumo Partner Licensing API v2 (OAuth 2.0 + X-AppSumo-Licensing-Key).": {
  "en": "AppSumo Partner Licensing API v2 (OAuth 2.0 + X-AppSumo-Licensing-Key).",
  "es": "AppSumo Partner Licensing API v2 (OAuth 2.0 + X-AppSumo-Licensing-Key).",
  "zh": "AppSumo Partner Licensing API v2（OAuth 2.0 + X-AppSumo-Licensing-Key）。"
 },
 "Проверено 18.11.2026: продажа на AppSumo возможна только после одобрения заявки AppSumo (partner terms), Licensing API выдаётся уже одобренному продукту — агент готовит заявку и страницу продукта, подаёт владелец (15%).": {
  "en": "Checked 18.11.2026: selling on AppSumo is possible only after AppSumo approves the application (partner terms); the Licensing API is issued to an already approved product — the agent prepares the application and product page, the owner submits them (15%).",
  "es": "Comprobado el 18.11.2026: vender en AppSumo solo es posible tras la aprobación de la solicitud por AppSumo (partner terms); la Licensing API se entrega a un producto ya aprobado: el agente prepara la solicitud y la página del producto, el dueño la presenta (15%).",
  "zh": "2026-11-18 已核实：只有在 AppSumo 批准申请后才能在其平台销售（partner terms），Licensing API 只发给已批准的产品——代理准备申请和产品页，由所有者提交（15%）。"
 },
 "Партнёрский API-ключ AIfaFocus MCP (15 инструментов роя).": {
  "en": "AIfaFocus MCP partner API key (15 swarm tools).",
  "es": "Clave API de socio de AIfaFocus MCP (15 herramientas del enjambre).",
  "zh": "AIfaFocus MCP 合作伙伴 API 密钥（15 个群体工具）。"
 },
 "Наша партнёрская программа (блок 9 Studio, инструменты padam_partner_*): агент сам находит сайты и готовит отчёт и письмо, но письмо по закону CAN-SPAM отправляет человек со своего адреса (15%).": {
  "en": "Our partner program (Studio block 9, padam_partner_* tools): the agent finds sites itself and prepares the report and the email, but under the CAN-SPAM law the email is sent by a person from their own address (15%).",
  "es": "Nuestro programa de socios (bloque 9 de Studio, herramientas padam_partner_*): el agente encuentra sitios por sí mismo y prepara el informe y el correo, pero según la ley CAN-SPAM el correo lo envía una persona desde su propia dirección (15%).",
  "zh": "我们的合作伙伴计划（Studio 第 9 区块，padam_partner_* 工具）：代理自行寻找网站并准备报告和邮件，但根据 CAN-SPAM 法律，邮件由人从本人地址发送（15%）。"
 },
 "Ключ API / сервисный токен агента Mech (без приватных ключей кошелька в открытом виде).": {
  "en": "Mech agent API key / service token (no wallet private keys in plain text).",
  "es": "Clave API / token de servicio del agente Mech (sin claves privadas de la billetera en texto plano).",
  "zh": "Mech 代理的 API 密钥 / 服务令牌（钱包私钥不以明文保存）。"
 },
 "Проверено 18.11.2026: агент регистрируется в реестре Olas и получает оплату криптовалютой (OLAS, USDC, нативный токен), стейкинг OLAS — по желанию; кошелёк и любые ончейн-действия — только по слову владельца (15%).": {
  "en": "Checked 18.11.2026: the agent registers in the Olas registry and is paid in crypto (OLAS, USDC, native token), OLAS staking is optional; the wallet and any on-chain actions — only on the owner's word (15%).",
  "es": "Comprobado el 18.11.2026: el agente se registra en el registro de Olas y cobra en criptomonedas (OLAS, USDC, token nativo); el staking de OLAS es opcional; la billetera y cualquier acción on-chain, solo con la palabra del dueño (15%).",
  "zh": "2026-11-18 已核实：代理在 Olas 注册表中注册，以加密货币（OLAS、USDC、原生代币）收款，OLAS 质押可选；钱包和任何链上操作——仅凭所有者指示（15%）。"
 },
 "Agentverse API Token (docs.agentverse.ai).": {
  "en": "Agentverse API Token (docs.agentverse.ai).",
  "es": "Token de API de Agentverse (docs.agentverse.ai).",
  "zh": "Agentverse API 令牌（docs.agentverse.ai）。"
 },
 "Открытый каталог и биржа автономных агентов uAgents с API-вызовами и монетизацией запросов на автопилоте (20%).": {
  "en": "An open catalog and marketplace of autonomous uAgents agents with API calls and request monetization on autopilot (20%).",
  "es": "Catálogo abierto y mercado de agentes autónomos uAgents con llamadas API y monetización de solicitudes en piloto automático (20%).",
  "zh": "开放的 uAgents 自主代理目录和市场，支持 API 调用和请求变现自动运行（20%）。"
 },
 "Relevance AI API Key + Webhook Secret.": {
  "en": "Relevance AI API Key + Webhook Secret.",
  "es": "Clave API de Relevance AI + secreto de webhook.",
  "zh": "Relevance AI API 密钥 + Webhook 密钥。"
 },
 "Проверено 18.11.2026: программа Relevance Builders закрытая, каждого агента проверяет команда Relevance, выплаты через Stripe владельца — агент готовит заявку и описание, подаёт владелец (15%).": {
  "en": "Checked 18.11.2026: the Relevance Builders program is closed, every agent is reviewed by the Relevance team, payouts go via the owner's Stripe — the agent prepares the application and description, the owner submits them (15%).",
  "es": "Comprobado el 18.11.2026: el programa Relevance Builders es cerrado, el equipo de Relevance revisa cada agente y los pagos van por el Stripe del dueño: el agente prepara la solicitud y la descripción, el dueño la presenta (15%).",
  "zh": "2026-11-18 已核实：Relevance Builders 计划是封闭的，每个代理由 Relevance 团队审核，付款通过所有者的 Stripe——代理准备申请和说明，由所有者提交（15%）。"
 },
 "1. Направления и услуги (что делаем лучше всего)": {
  "en": "1. Areas and services (what we do best)",
  "es": "1. Áreas y servicios (lo que mejor hacemos)",
  "zh": "1. 方向与服务（我们最擅长的）"
 },
 "2. Целевая ставка в час (USDT/ч)": {
  "en": "2. Target hourly rate (USDT/h)",
  "es": "2. Tarifa objetivo por hora (USDT/h)",
  "zh": "2. 目标时薪（USDT/小时）"
 },
 "3. Минимальный бюджет заказа (USDT)": {
  "en": "3. Minimum order budget (USDT)",
  "es": "3. Presupuesto mínimo del encargo (USDT)",
  "zh": "3. 最低订单预算（USDT）"
 },
 "4. Рабочие языки общения": {
  "en": "4. Working languages",
  "es": "4. Idiomas de trabajo",
  "zh": "4. 工作语言"
 },
 "5. Тон откликов и профиля": {
  "en": "5. Tone of proposals and profile",
  "es": "5. Tono de las propuestas y del perfil",
  "zh": "5. 投标与资料的语气"
 },
 "6. Что НЕ берём в работу (стоп-темы)": {
  "en": "6. What we do NOT take on (stop topics)",
  "es": "6. Lo que NO aceptamos (temas excluidos)",
  "zh": "6. 不接的工作（禁止主题）"
 }
}

WIZARD_TR.update({
 "ожидает входа": {"en": "waiting for sign-in", "es": "esperando el acceso", "zh": "等待登录"},
 "подключено": {"en": "connected", "es": "conectado", "zh": "已连接"},
})
WIZARD_TR.update({
 'Методичка по 30 площадкам заработка ИИ-агентов (CODE Edition)': {'en': 'Playbook for 30 AI-agent earning platforms (CODE Edition)', 'es': 'Guía de 30 plataformas de ingresos para agentes de IA (CODE Edition)', 'zh': '30 个 AI 代理赚钱平台指南（CODE 版）'},
 'Пошаговое руководство по подключению агентов к 30 цифровым и фриланс-площадкам без хранения паролей: API-ключи, вебхуки, закрепление клиента на 90 дней и контроль маржи.': {'en': 'A step-by-step guide to connecting agents to 30 digital and freelance platforms without storing passwords: API keys, webhooks, 90-day client lock and margin control.', 'es': 'Guía paso a paso para conectar agentes a 30 plataformas digitales y de freelance sin guardar contraseñas: claves API, webhooks, cliente fijado 90 días y control del margen.', 'zh': '将代理接入 30 个数字和自由职业平台的分步指南，无需存储密码：API 密钥、webhook、客户锁定 90 天和利润控制。'},
 'Базы лидов из исследования цифровой доступности': {'en': 'Lead lists from the digital accessibility research', 'es': 'Bases de leads de la investigación de accesibilidad digital', 'zh': '数字无障碍研究的潜在客户名单'},
 'Кураторская выборка публичных B2B-доменов и технических отчётов по доступности интерфейсов (WCAG) для подготовки коммерческих предложений по аудиту и исправлению UI.': {'en': 'A curated selection of public B2B domains and technical interface accessibility (WCAG) reports for preparing audit and UI-fix proposals.', 'es': 'Selección curada de dominios B2B públicos e informes técnicos de accesibilidad de interfaces (WCAG) para preparar propuestas de auditoría y corrección de UI.', 'zh': '精选的公开 B2B 域名和界面无障碍（WCAG）技术报告，用于准备审计和 UI 修复方案。'},
 'Готовые шаблоны и интеграции PADAM': {'en': 'Ready-made PADAM templates and integrations', 'es': 'Plantillas e integraciones listas de PADAM', 'zh': '现成的 PADAM 模板与集成'},
 'Набор типовых конфигураций автономной памяти PADAM, MCP-схем, локальных моделей ($0) и шаблонов эскроу/агентской монетизации для быстрого старта.': {'en': 'A set of standard PADAM autonomous-memory configurations, MCP schemas, local models ($0) and escrow/agent-monetization templates for a quick start.', 'es': 'Conjunto de configuraciones típicas de memoria autónoma PADAM, esquemas MCP, modelos locales ($0) y plantillas de escrow/monetización de agentes para empezar rápido.', 'zh': '一套标准 PADAM 自主记忆配置、MCP 架构、本地模型（$0）以及托管/代理变现模板，助您快速上手。'},
 'Остановлен (включается кнопкой Старт владельцем).': {'en': 'Stopped (the owner turns it on with the Start button).', 'es': 'Detenido (el dueño lo activa con el botón Iniciar).', 'zh': '已停止（由所有者点击“开始”按钮开启）。'},
 'Avito Услуги': {'en': 'Avito Services', 'es': 'Avito Servicios', 'zh': 'Avito 服务'},
})

import re as _re
_КИР = _re.compile(r"[А-Яа-яЁё]")
_ОШИБКА = {"en": "error: ", "es": "error: ", "zh": "错误："}


def _tr(text: str, lang: str) -> str | None:
    t = WIZARD_TR.get(text)
    if t:
        return t.get(lang)
    if text.startswith("ошибка: "):
        return _ОШИБКА[lang] + text[len("ошибка: "):]
    return None


def localize(obj):
    """Дописывает к каждому полю «*_ru» поля «*_en», «*_es», «*_zh» из таблицы (если перевод известен).
    Студия берёт поле на языке человека, русское — запасное."""
    if isinstance(obj, dict):
        extra = {}
        for k, v in obj.items():
            if k.endswith("_ru") and isinstance(v, str):
                base = k[:-3]
                for lang in ("en", "es", "zh"):
                    if base + "_" + lang not in obj:
                        t = _tr(v, lang)
                        if t:
                            extra[base + "_" + lang] = t
            elif k in ("title", "description", "last_note") and isinstance(v, str) and _КИР.search(v):
                for lang in ("en", "es", "zh"):
                    t = _tr(v, lang)
                    if t and k + "_" + lang not in obj:
                        extra[k + "_" + lang] = t
            else:
                localize(v)
        obj.update(extra)
    elif isinstance(obj, list):
        for x in obj:
            localize(x)
    return obj
