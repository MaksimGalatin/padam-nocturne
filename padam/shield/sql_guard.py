# -*- coding: utf-8 -*-
"""Файрвол баз данных и запросов SQL / NoSQL / GraphQL (Database & Query Guard).

Защищает от критических аварий и атак ИИ-агентов с доступом к БД:
- Деструктивный DDL/DML: `DROP`, `TRUNCATE`, `ALTER`, `GRANT`, `REVOKE`, `ATTACH`,
  `LOAD_EXTENSION`, `VACUUM INTO`, `DELETE`/`UPDATE` без `WHERE` или с тавтологией
  (`WHERE 1=1`, `WHERE true`, `WHERE 'a'='a'`),
- Скрытые stacked queries (`; DROP TABLE ...`) с корректным лексическим разбором
  строковых литералов и комментариев (`--`, `/* */`),
- RCE и файловые примитивы БД: `COPY ... TO PROGRAM`, `INTO OUTFILE`, `LOAD_FILE`,
  `xp_cmdshell`, `pg_read_file`, `pg_ls_dir`,
- Режим `read_only=True` и защита от массовой выгрузки таблиц (`SELECT *` без `LIMIT`
  или с чрезмерным `LIMIT`),
- NoSQL-инъекции (`$where`, `$function`, `$accumulator`, `$ne` обходы) и
  GraphQL DoS (чрезмерная глубина вложенности, интроспекция `__schema`, алиас-бомбы).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


_DESTRUCTIVE_SQL_RE = re.compile(
    r"(?i)\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER|ROLE)|TRUNCATE\s+TABLE?|ALTER\s+(?:TABLE|SYSTEM|USER|ROLE)|"
    r"GRANT\s+|REVOKE\s+|ATTACH\s+DATABASE|DETACH\s+DATABASE|LOAD_EXTENSION|VACUUM\s+INTO|SHUTDOWN|FLUSH\s+PRIVILEGES|PRAGMA\s+(?:writable_schema|trusted_schema|journal_mode\s*=\s*off|foreign_keys\s*=\s*off))\b"
)

_DB_RCE_FILE_RE = re.compile(
    r"(?i)(?:COPY\s+[^\n;]{1,120}\b(?:TO|FROM)\s+PROGRAM\b|"
    r"\bINTO\s+(?:OUTFILE|DUMPFILE)\b|\bLOAD_FILE\s*\(|\bxp_cmdshell\b|"
    r"\bpg_read_file\s*\(|\bpg_read_binary_file\s*\(|\bpg_ls_dir\s*\(|\blo_import\s*\(|\blo_export\s*\()"
)

_SYSTEM_CATALOG_RE = re.compile(
    r"(?i)\b(?:pg_shadow|pg_authid|mysql\.user|information_schema\.user_privileges|sys\.sql_logins|sqlite_master)\b"
)

_WRITE_STMT_RE = re.compile(r"(?i)^\s*(?:INSERT|UPDATE|DELETE|REPLACE|MERGE|UPSERT|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|ATTACH|PRAGMA)\b")

_TAUTOLOGY_WHERE_RE = re.compile(
    r"(?i)\bWHERE\s+(?:1\s*=\s*1|true|'[^']*'\s*=\s*'[^']*'|\d+\s*=\s*\d+|\w+\s*=\s*\w+)\s*(?:--|$|;|LIMIT|ORDER)"
)


# 28.11.2026: прежнее правило тавтологии ловило альтернативой `\w+\s*=\s*\w+` любое `WHERE id = 42`, то есть
# блокировало обычное точечное обновление по id (ложное срабатывание, найденное внешней проверкой 27.11),
# и при этом пропускало `WHERE id = 1 OR 1 = 1`. Теперь условие разбирается по частям OR, и тавтологией
# считается только часть, истинная всегда: `true`, `1`, `NOT FALSE`, сравнение двух одинаковых литералов
# или одного и того же столбца с самим собой, истинное сравнение двух чисел, `LIKE '%'`.
_WHERE_TAIL_RE = re.compile(r"(?is)\bWHERE\b(.*?)(?:\bORDER\s+BY\b|\bGROUP\s+BY\b|\bLIMIT\b|\bRETURNING\b|\bOFFSET\b|--|;|$)")
_SQL_TRUE_ATOM_RE = re.compile(r"(?i)^\(*\s*(?:true|1|not\s+false|not\s+0)\s*\)*$")
_SQL_CMP_RE = re.compile(
    r"(?is)^\(*\s*('(?:[^']|'')*'|-?\d+(?:\.\d+)?|[A-Za-z_][\w.]*)\s*(=|==|<>|!=|>=|<=|>|<)\s*('(?:[^']|'')*'|-?\d+(?:\.\d+)?|[A-Za-z_][\w.]*)\s*\)*$"
)
_SQL_LIKE_ALL_RE = re.compile(r"(?i)^\(*\s*[A-Za-z_][\w.]*\s+LIKE\s+'%+'\s*\)*$")


def _sql_atom_always_true(part: str) -> bool:
    p = part.strip()
    if not p:
        return False
    if _SQL_TRUE_ATOM_RE.match(p) or _SQL_LIKE_ALL_RE.match(p):
        return True
    m = _SQL_CMP_RE.match(p)
    if not m:
        return False
    a, op, b = m.group(1), m.group(2), m.group(3)
    num = re.compile(r"^-?\d+(?:\.\d+)?$")
    if num.match(a) and num.match(b):
        x, y = float(a), float(b)
        return {"=": x == y, "==": x == y, "<>": x != y, "!=": x != y, ">=": x >= y, "<=": x <= y, ">": x > y, "<": x < y}[op]
    if a.startswith("'") and b.startswith("'"):
        return (a == b) if op in ("=", "==", ">=", "<=") else (a != b if op in ("<>", "!=") else False)
    if a.lower() == b.lower() and op in ("=", "==", ">=", "<="):
        # столбец сравнивается сам с собой (x = x); число/литерал против столбца сюда не попадает
        return not num.match(a) and not a.startswith("'")
    return False


def _where_is_tautology(statement: str) -> bool:
    m = _WHERE_TAIL_RE.search(statement)
    if not m:
        return False
    cond = m.group(1).strip()
    for part in re.split(r"(?i)\bOR\b|\|\|", cond):
        if _sql_atom_always_true(part):
            return True
    return False


_LIMIT_RE = re.compile(r"(?i)\bLIMIT\s+(\d+)\b")
_TOP_RE = re.compile(r"(?i)\bSELECT\s+TOP\s+(\d+)\b")

_NOSQL_DANGEROUS_KEYS = {"$where", "$function", "$accumulator"}
_NOSQL_AUTH_BYPASS_KEYS = {"$ne", "$gt", "$gte", "$regex"}


def _strip_sql_comments_and_split(sql: str) -> List[str]:
    """Разбирает SQL на отдельные выражения с учётом кавычек и комментариев."""
    stmts: List[str] = []
    buf: List[str] = []
    i = 0
    n = len(sql)
    in_single = False
    in_double = False
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if in_single:
            buf.append(ch)
            if ch == "'" and nxt == "'":
                buf.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            buf.append(ch)
            if ch == '"' and nxt == '"':
                buf.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        # Комментарий -- до конца строки
        if ch == "-" and nxt == "-":
            buf.append(" ")
            i += 2
            while i < n and sql[i] != "\n":
                i += 1
            continue
        # Комментарий /* ... */
        if ch == "/" and nxt == "*":
            buf.append(" ")
            i += 2
            while i + 1 < n and not (sql[i] == "*" and sql[i + 1] == "/"):
                i += 1
            i += 2
            continue
        if ch == "'":
            in_single = True
            buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            buf.append(ch)
            i += 1
            continue
        if ch == ";":
            part = "".join(buf).strip()
            if part:
                stmts.append(part)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        stmts.append(tail)
    return stmts


_SQL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def inspect_sql_query(
    sql: str,
    *,
    read_only: bool = False,
    allow_stacked: bool = False,
    max_limit: int = 1000,
    require_limit_on_select: bool = False,
) -> Dict[str, Any]:
    """Проверяет SQL-запрос агента на деструктивные команды, RCE, тавтологии и массовую выгрузку."""
    raw = str(sql or "").strip()
    findings: List[Dict[str, Any]] = []
    if not raw:
        return {"ok": True, "allowed": True, "blocked": False, "statements": 0, "findings": []}

    stmts = _strip_sql_comments_and_split(raw)
    # Parser Differential защита: проверяем также склейку без пробела на месте /*...*/ (ловит DR/**/OP, UN/**/ION)
    compact_raw = _SQL_BLOCK_COMMENT_RE.sub("", raw)
    compact_stmts = _strip_sql_comments_and_split(compact_raw) if "/*" in raw else []
    if len(stmts) > 1 and not allow_stacked:
        findings.append(
            {
                "rule_id": "SQL-STACKED-QUERY",
                "severity": "CRITICAL",
                "detail": f"Обнаружено несколько SQL-выражений через ';' ({len(stmts)} шт., риск SQL-инъекции)",
            }
        )

    candidates = list(stmts)
    for cst in compact_stmts:
        if cst and cst not in candidates:
            candidates.append(cst)

    for st in candidates:
        if _DB_RCE_FILE_RE.search(st):
            findings.append(
                {
                    "rule_id": "SQL-RCE-OR-FILE-IO",
                    "severity": "CRITICAL",
                    "detail": f"Обнаружен RCE или файловый примитив БД: {st[:120]}",
                }
            )
        if _DESTRUCTIVE_SQL_RE.search(st):
            findings.append(
                {
                    "rule_id": "SQL-DESTRUCTIVE-DDL",
                    "severity": "CRITICAL",
                    "detail": f"Заблокирована деструктивная DDL/админ-команда: {st[:120]}",
                }
            )
        if read_only and _WRITE_STMT_RE.search(st):
            findings.append(
                {
                    "rule_id": "SQL-WRITE-IN-READONLY",
                    "severity": "CRITICAL",
                    "detail": f"Попытка записи/изменения БД в режиме read_only: {st[:120]}",
                }
            )
        if re.match(r"(?i)^\s*(?:DELETE\s+FROM|UPDATE\s+)", st) or (re.match(r"(?i)^\s*WITH\b", st) and re.search(r"(?i)\b(?:DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b", st)):
            if not re.search(r"(?i)\bWHERE\b", st):
                findings.append(
                    {
                        "rule_id": "SQL-MASS-MUTATION-NO-WHERE",
                        "severity": "CRITICAL",
                        "detail": "Операция массового удаления/обновления без условия WHERE: " + st[:120],
                    }
                )
            elif _where_is_tautology(st):
                findings.append(
                    {
                        "rule_id": "SQL-TAUTOLOGY-WHERE",
                        "severity": "CRITICAL",
                        "detail": "Операция массового удаления/обновления с тавтологией WHERE (1=1 / true): " + st[:120],
                    }
                )
        if re.search(r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b", st) and _SYSTEM_CATALOG_RE.search(st):
            findings.append(
                {
                    "rule_id": "SQL-CATALOG-EXFIL",
                    "severity": "CRITICAL",
                    "detail": "Попытка UNION-извлечения системных таблиц паролей/схем",
                }
            )
        if re.match(r"(?i)^\s*SELECT\b", st):
            lm = _LIMIT_RE.search(st) or _TOP_RE.search(st)
            if lm:
                lim_val = int(lm.group(1))
                if lim_val > max_limit:
                    findings.append(
                        {
                            "rule_id": "SQL-EXCESSIVE-LIMIT",
                            "severity": "HIGH",
                            "detail": f"Запрошенный LIMIT {lim_val} превышает разрешённый порог {max_limit}",
                        }
                    )
            elif require_limit_on_select and re.search(r"(?i)\bSELECT\s+\*\s+FROM\b", st):
                findings.append(
                    {
                        "rule_id": "SQL-UNBOUNDED-SELECT-STAR",
                        "severity": "HIGH",
                        "detail": "Массовая выгрузка SELECT * без LIMIT запрещена политикой",
                    }
                )

    blocked = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "statements": len(stmts),
        "findings": findings,
    }


def inspect_nosql_filter(query_obj: Any, *, sensitive_context: bool = False) -> Dict[str, Any]:
    """Проверяет MongoDB / NoSQL JSON-фильтр на JS-инъекции ($where/$function) и обход авторизации."""
    findings: List[Dict[str, Any]] = []
    if isinstance(query_obj, str):
        try:
            query_obj = json.loads(query_obj)
        except Exception:
            return {"ok": False, "allowed": False, "blocked": True, "findings": [{"rule_id": "NOSQL-INVALID-JSON", "severity": "HIGH", "detail": "Невалидный JSON-фильтр NoSQL"}]}

    def _walk(node: Any, path: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                ks = str(k)
                if ks in _NOSQL_DANGEROUS_KEYS:
                    findings.append(
                        {
                            "rule_id": "NOSQL-JS-EXECUTION",
                            "severity": "CRITICAL",
                            "detail": f"Опасный NoSQL-оператор исполнения кода '{ks}' в {path or 'root'}",
                        }
                    )
                if sensitive_context and ks in _NOSQL_AUTH_BYPASS_KEYS:
                    findings.append(
                        {
                            "rule_id": "NOSQL-OPERATOR-INJECTION",
                            "severity": "HIGH",
                            "detail": f"Подозрительный оператор '{ks}' в чувствительном фильтре ({path or 'root'})",
                        }
                    )
                _walk(v, f"{path}.{ks}" if path else ks)
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                _walk(item, f"{path}[{idx}]")

    _walk(query_obj)
    blocked = len(findings) > 0
    return {"ok": not blocked, "allowed": not blocked, "blocked": blocked, "findings": findings}


def inspect_graphql_query(
    query: str,
    *,
    max_depth: int = 6,
    max_aliases: int = 12,
    block_introspection: bool = True,
) -> Dict[str, Any]:
    """Проверяет GraphQL-запрос на глубину вложенности, интроспекцию и алиас-бомбы."""
    raw = str(query or "")
    findings: List[Dict[str, Any]] = []
    if not raw.strip():
        return {"ok": True, "allowed": True, "blocked": False, "depth": 0, "findings": []}

    if block_introspection and re.search(r"\b(?:__schema|__type)\b", raw):
        findings.append(
            {
                "rule_id": "GQL-INTROSPECTION-BLOCKED",
                "severity": "HIGH",
                "detail": "Запрос интроспекции схемы GraphQL (__schema/__type) заблокирован",
            }
        )

    # Подсчёт глубины фигурных скобок вне строковых литералов
    depth = 0
    max_seen = 0
    in_str = False
    esc = False
    for ch in raw:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
            if depth > max_seen:
                max_seen = depth
        elif ch == "}":
            depth = max(0, depth - 1)

    if max_seen > max_depth:
        findings.append(
            {
                "rule_id": "GQL-DEPTH-BOMB",
                "severity": "CRITICAL",
                "detail": f"Глубина GraphQL-запроса ({max_seen}) превышает лимит ({max_depth})",
            }
        )

    aliases = re.findall(r"(?m)^\s*[A-Za-z_]\w*\s*:\s*[A-Za-z_]\w*\s*(?:\(|\{)", raw)
    if len(aliases) > max_aliases:
        findings.append(
            {
                "rule_id": "GQL-ALIAS-BATCH-BOMB",
                "severity": "CRITICAL",
                "detail": f"Обнаружена алиас-бомба GraphQL ({len(aliases)} алиасов > {max_aliases})",
            }
        )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "depth": max_seen,
        "aliases": len(aliases),
        "findings": findings,
    }
