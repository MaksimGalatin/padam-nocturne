# -*- coding: utf-8 -*-
"""Честное сравнение PADAM с другими слоями памяти для агентов — для вкладки «Бенчмарк» Studio (18.11.2026).

Слово Папы: «сравнение адекватно с другими МСР по памяти». Правило: у PADAM — только то, что есть в коде и в замерах
этого репозитория (файлы указаны); у других — только устройство из их открытой документации и статей; где нашего
замера нет, так и написано. Никаких придуманных чисел о чужих продуктах.

Источники: Mem0 — github.com/mem0ai/mem0, статья arXiv:2504.19413; Zep / Graphiti — github.com/getzep/graphiti,
статья arXiv:2501.13956; MCP memory — эталонный сервер github.com/modelcontextprotocol/servers (src/memory).
Замеры PADAM: benchmarks/longmemeval/vs_mem0, benchmarks/scale/concurrent_writers.py, benchmarks/scale/search_latency.py,
benchmarks/quality/results_qa_honest_1611.json.
"""
from __future__ import annotations

COLS = {
    "padam": "PADAM NOCTURNE",
    "mem0": "Mem0",
    "zep": "Zep / Graphiti",
    "mcpmem": "MCP memory",
}


def _t(ru: str, en: str, es: str, zh: str) -> dict[str, str]:
    return {"ru": ru, "en": en, "es": es, "zh": zh}


NO = _t("нет нашего замера", "no measurement of ours", "sin medición nuestra", "我们未测量")

ROWS: list[dict] = [
    {"k": _t("Где хранится память", "Where memory lives", "Dónde vive la memoria", "记忆存放位置"),
     "padam": _t("Один файл на вашем компьютере, работает без интернета", "One file on your computer, works offline", "Un archivo en su equipo, funciona sin internet", "您电脑上的一个文件，离线可用"),
     "mem0": _t("Векторная база (Qdrant, pgvector и др.) или облако Mem0", "Vector DB (Qdrant, pgvector, …) or Mem0 cloud", "Base vectorial (Qdrant, pgvector…) o nube Mem0", "向量数据库（Qdrant、pgvector等）或Mem0云"),
     "zep": _t("Графовая СУБД (Neo4j, FalkorDB) или облако Zep", "Graph DB (Neo4j, FalkorDB) or Zep cloud", "Base de grafos (Neo4j, FalkorDB) o nube Zep", "图数据库（Neo4j、FalkorDB）或Zep云"),
     "mcpmem": _t("Один JSON-файл графа", "One JSON graph file", "Un archivo JSON de grafo", "一个JSON图文件")},
    {"k": _t("Нужна ли языковая модель при записи", "Needs an LLM on write", "Necesita un LLM al escribir", "写入时是否需要大模型"),
     "padam": _t("Нет — $0 за запись", "No — $0 per write", "No — $0 por escritura", "不需要——每次写入$0"),
     "mem0": _t("По умолчанию да: модель выделяет факты (ADD/UPDATE/DELETE)", "By default yes: a model extracts facts (ADD/UPDATE/DELETE)", "Por defecto sí: un modelo extrae hechos", "默认需要：由模型提取事实（ADD/UPDATE/DELETE）"),
     "zep": _t("Да: модель строит сущности и связи графа", "Yes: a model builds graph entities and edges", "Sí: un modelo construye entidades y aristas", "需要：由模型构建图实体和边"),
     "mcpmem": _t("Нет: агент сам пишет сущности", "No: the agent writes entities itself", "No: el agente escribe las entidades", "不需要：代理自己写实体")},
    {"k": _t("Как ищет", "How it searches", "Cómo busca", "检索方式"),
     "padam": _t("Смысл + слова (BM25) + точные номера, слияние RRF, переранжирование", "Meaning + words (BM25) + exact ids, RRF fusion, re-ranking", "Significado + palabras (BM25) + ids exactos, fusión RRF, reordenado", "语义+关键词（BM25）+精确编号，RRF融合，重排序"),
     "mem0": _t("Векторный поиск, граф — по желанию", "Vector search, graph optional", "Búsqueda vectorial, grafo opcional", "向量检索，可选图"),
     "zep": _t("Смысл + BM25 + обход графа + переранжирование", "Meaning + BM25 + graph traversal + re-ranking", "Significado + BM25 + recorrido de grafo + reordenado", "语义+BM25+图遍历+重排序"),
     "mcpmem": _t("Поиск по подстроке", "Substring match", "Coincidencia de subcadena", "子串匹配")},
    {"k": _t("Время у фактов", "Time on facts", "Tiempo en los hechos", "事实的时间"),
     "padam": _t("Да: когда факт верен и когда система узнала/отменила; память на любую дату; старое не стирается", "Yes: when a fact holds and when the system learned/retracted it; memory as of any date; old facts kept", "Sí: cuándo vale y cuándo se supo/anuló; memoria en cualquier fecha", "有：事实何时有效、系统何时得知/撤销；可查任意日期；旧事实保留"),
     "mem0": _t("Обновление и удаление фактов, история изменений", "Fact update/delete with change history", "Actualizar/borrar hechos con historial", "事实更新/删除，带变更历史"),
     "zep": _t("Да: би-темпоральные рёбра графа", "Yes: bi-temporal graph edges", "Sí: aristas bitemporales", "有：双时态图边"),
     "mcpmem": _t("Нет", "No", "No", "无")},
    {"k": _t("Рой агентов пишет в одну память", "Agent swarm writing to one memory", "Enjambre de agentes en una memoria", "多代理同时写入同一记忆"),
     "padam": _t("Замер 18.11: 20 и 40 процессов, 1000 записей — потерь 0", "Measured 18.11: 20 and 40 processes, 1000 writes — 0 lost", "Medido 18.11: 20 y 40 procesos, 1000 escrituras — 0 perdidas", "18.11实测：20和40个进程、1000次写入——丢失0"),
     "mem0": _t("Серверная СУБД с параллельными транзакциями", "Server DB with concurrent transactions", "Base de servidor con transacciones concurrentes", "服务器数据库，支持并发事务"),
     "zep": _t("Серверная СУБД с параллельными транзакциями", "Server DB with concurrent transactions", "Base de servidor con transacciones concurrentes", "服务器数据库，支持并发事务"),
     "mcpmem": _t("Один файл перезаписывается целиком", "One file rewritten whole", "Un archivo reescrito entero", "整个文件重写")},
    {"k": _t("Скорость поиска", "Search speed", "Velocidad de búsqueda", "检索速度"),
     "padam": _t("10 000 записей: 45 мс медиана, 47,5 мс p95; 20 000 — 54 мс (обычный ПК, без видеокарты, замер 18.11)", "10,000 records: 45 ms median, 47.5 ms p95; 20,000 — 54 ms (plain PC, no GPU, measured 18.11)", "10 000 registros: 45 ms mediana, 47,5 ms p95; 20 000 — 54 ms (PC normal)", "1万条：中位45毫秒，p95 47.5毫秒；2万条——54毫秒（普通电脑，无显卡，18.11实测）"),
     "mem0": _t("Серверные индексы HNSW на миллионы; " , "Server HNSW indexes for millions; ", "Índices HNSW para millones; ", "服务器HNSW索引可达百万级；"),
     "zep": _t("Серверный граф; ", "Server graph; ", "Grafo de servidor; ", "服务器图；"),
     "mcpmem": NO},
    {"k": _t("Находит нужное (LongMemEval, одни условия, без модели)", "Finds the evidence (LongMemEval, same setup, no LLM)", "Encuentra la evidencia (LongMemEval, mismas condiciones)", "找到证据（LongMemEval，同等条件，无模型）"),
     "padam": _t("Все доказательства в топ-10: 93,6 %; хоть одно в топ-10: 97,9 %", "All evidence in top-10: 93.6%; any in top-10: 97.9%", "Toda la evidencia en top-10: 93,6 %; alguna: 97,9 %", "全部证据在前10：93.6%；任一在前10：97.9%"),
     "mem0": _t("Все в топ-10: 91,5 %; хоть одно: 98,9 % (наш замер)", "All in top-10: 91.5%; any: 98.9% (our run)", "Toda en top-10: 91,5 %; alguna: 98,9 % (nuestra medición)", "全部在前10：91.5%；任一：98.9%（我们实测）"),
     "zep": NO, "mcpmem": NO},
    {"k": _t("Точность готовых ответов с моделью (LOCOMO)", "Answer accuracy with an LLM (LOCOMO)", "Precisión de respuestas con LLM (LOCOMO)", "带模型的答案准确率（LOCOMO）"),
     "padam": _t("Пока не публиковали: без модели F1 0,07 — PADAM отдаёт факты, ответ пишет ваш агент", "Not published yet: without a model F1 0.07 — PADAM returns facts, your agent writes the answer", "Aún no publicado: sin modelo F1 0,07", "尚未发布：无模型时F1 0.07——PADAM提供事实，由您的代理作答"),
     "mem0": _t("Публикуют в своей статье", "Published in their paper", "Publicado en su artículo", "在其论文中发布"),
     "zep": _t("Публикуют в своей статье", "Published in their paper", "Publicado en su artículo", "在其论文中发布"),
     "mcpmem": NO},
    {"k": _t("Защита от спрятанных приказов и утечки ключей", "Protection from hidden orders and key leaks", "Protección contra órdenes ocultas y fugas de claves", "防隐藏指令和密钥泄露"),
     "padam": _t("100 из 100 критериев; наш набор атак 34 из 34; в запечатанном раунде чужой модели — команды задержаны 12 из 20, секреты 16 из 20 (таблица ниже)",
                 "100/100 criteria; our attack set 34/34; in a sealed round by an outside model — commands held 12/20, secrets 16/20 (table below)",
                 "100/100 criterios; nuestro set 34/34; en ronda sellada de un modelo externo: órdenes 12/20, secretos 16/20",
                 "100/100项标准；我们的攻击集34/34；外部模型密封轮次中——指令拦截12/20，密钥16/20（见下表）"),
     "mem0": NO, "zep": NO, "mcpmem": NO},
    {"k": _t("Удаление навсегда с доказательством", "Forever deletion with proof", "Borrado definitivo con prueba", "带证明的永久删除"),
     "padam": _t("Да: ключ записи уничтожается, выдаётся квитанция", "Yes: the record key is destroyed and a receipt is issued", "Sí: se destruye la clave y se emite un recibo", "有：销毁记录密钥并出具回执"),
     "mem0": _t("Удаление записи", "Record delete", "Borrado de registro", "删除记录"),
     "zep": _t("Удаление записи", "Record delete", "Borrado de registro", "删除记录"),
     "mcpmem": _t("Удаление записи", "Record delete", "Borrado de registro", "删除记录")},
    {"k": _t("Облако и кластер", "Cloud and cluster", "Nube y clúster", "云与集群"),
     "padam": _t("Сознательно локально: перенос на флешке, связь ваших устройств напрямую", "Local by design: carry on a USB stick, your devices sync directly", "Local por diseño: en una memoria USB, sincronía directa", "刻意本地：U盘随身带，设备间直接同步"),
     "mem0": _t("Да, облачный сервис", "Yes, cloud service", "Sí, servicio en la nube", "有，云服务"),
     "zep": _t("Да, облачный сервис", "Yes, cloud service", "Sí, servicio en la nube", "有，云服务"),
     "mcpmem": _t("Нет", "No", "No", "无")},
    {"k": _t("Цена", "Price", "Precio", "价格"),
     "padam": _t("$0 на вашем компьютере", "$0 on your computer", "$0 en su equipo", "您电脑上$0"),
     "mem0": _t("Открытый код + платное облако; модель на запись платная", "Open source + paid cloud; the write-time LLM costs money", "Código abierto + nube de pago; el LLM cuesta", "开源+付费云；写入时模型收费"),
     "zep": _t("Открытый код + платное облако; модель на запись платная", "Open source + paid cloud; the write-time LLM costs money", "Código abierto + nube de pago; el LLM cuesta", "开源+付费云；写入时模型收费"),
     "mcpmem": _t("$0", "$0", "$0", "$0")},
]

# В двух клетках у конкурентов стоит устройство, а не наш замер: дописываем «нет нашего замера».
for _r in ROWS:
    for _c in ("mem0", "zep"):
        if _r[_c]["ru"].endswith("; "):
            _r[_c] = {lng: _r[_c][lng] + NO[lng] for lng in _r[_c]}


# Где PADAM пока уступает или замера нет — жёлтым; остальное зелёным. Пометка явная, а не по тексту клетки.
_WEAK = {"Точность готовых ответов с моделью (LOCOMO)", "Защита от спрятанных приказов и утечки ключей", "Облако и кластер"}
for _r in ROWS:
    _r["padam_weak"] = _r["k"]["ru"] in _WEAK


def compare_payload() -> dict:
    return {"cols": COLS, "rows": ROWS}
