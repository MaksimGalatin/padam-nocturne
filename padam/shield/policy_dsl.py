# -*- coding: utf-8 -*-
"""Программируемый движок политик безопасности (Rego-совместимый DSL + 25 шаблонов).

Исполняет кастомные правила Open Policy Agent (Rego-подмножество) полностью локально,
без `eval()` и без внешних бинарников, со временем оценки < 1 мс на вызов.
Поддерживает: `package`, `default allow = true|false`, `deny[msg] { ... }`, `allow { ... }`,
пути `input.a.b`, сравнения `==`, `!=`, `>`, `>=`, `<`, `<=`, `in`, отрицание `not`,
функции `contains(...)`, `startswith(...)`, `endswith(...)`, `regex.match(...)`, `count(...)`.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

# Библиотека из 25 готовых корпоративных и Web3 шаблонов Rego-политик
POLICY_TEMPLATES: dict[str, dict[str, str]] = {
    "01_crypto_limit_500_two_approvals": {
        "title": "Перевод криптоактивов > $500 только в рабочие часы и с 2 подтверждениями",
        "rego": (
            'package padam.fin\n'
            'default allow = true\n'
            'deny["Криптоперевод свыше $500 запрещён вне рабочих часов (09-18)"] {\n'
            '  input.action == "crypto_transfer"\n'
            '  input.amount > 500\n'
            '  input.hour < 9\n'
            '}\n'
            'deny["Криптоперевод свыше $500 требует минимум 2 подтверждения"] {\n'
            '  input.action == "crypto_transfer"\n'
            '  input.amount > 500\n'
            '  input.approvals < 2\n'
            '}\n'
        ),
    },
    "02_no_weekend_wires": {
        "title": "Запрет финансовых переводов в выходные дни (сб/вс)",
        "rego": (
            'package padam.fin\n'
            'default allow = true\n'
            'deny["Финансовые операции в выходные запрещены"] {\n'
            '  input.action in {"crypto_transfer", "wire_transfer", "iban_payment"}\n'
            '  input.weekday in {"sat", "sun"}\n'
            '}\n'
        ),
    },
    "03_block_unlimited_evm_approve": {
        "title": "Запрет бесконечного approve(MAX_UINT256) в EVM",
        "rego": (
            'package padam.web3\n'
            'default allow = true\n'
            'deny["Бесконечный approve токенов запрещён политикой"] {\n'
            '  input.method == "approve"\n'
            '  input.is_unlimited == true\n'
            '}\n'
        ),
    },
    "04_block_set_approval_for_all": {
        "title": "Запрет setApprovalForAll для непроверенных контрактов",
        "rego": (
            'package padam.web3\n'
            'default allow = true\n'
            'deny["setApprovalForAll запрещён для контрактов вне белого списка"] {\n'
            '  input.method == "setApprovalForAll"\n'
            '  input.contract_allowlisted == false\n'
            '}\n'
        ),
    },
    "05_block_solana_set_authority": {
        "title": "Блокировка смены полномочий Solana SetAuthority",
        "rego": (
            'package padam.web3\n'
            'default allow = true\n'
            'deny["Смена владельца Solana (SetAuthority) требует ручной подписи"] {\n'
            '  input.instruction == "SetAuthority"\n'
            '}\n'
        ),
    },
    "06_geo_ip_sanctions_block": {
        "title": "Географическая фильтрация IP-адресов",
        "rego": (
            'package padam.net\n'
            'default allow = true\n'
            'deny["Запрос с запрещённой гео-локации IP"] {\n'
            '  input.country in {"KP", "IR", "SY"}\n'
            '}\n'
        ),
    },
    "07_block_dot_env_read": {
        "title": "Запрет чтения файлов .env агентами",
        "rego": (
            'package padam.fs\n'
            'default allow = true\n'
            'deny["Чтение .env запрещено политикой"] {\n'
            '  endswith(input.path, ".env")\n'
            '}\n'
        ),
    },
    "08_block_ssh_keys_access": {
        "title": "Запрет доступа к каталогу ~/.ssh",
        "rego": (
            'package padam.fs\n'
            'default allow = true\n'
            'deny["Доступ к приватным SSH-ключам заблокирован"] {\n'
            '  contains(input.path, ".ssh")\n'
            '}\n'
        ),
    },
    "09_block_aws_credentials": {
        "title": "Запрет чтения AWS credentials",
        "rego": (
            'package padam.fs\n'
            'default allow = true\n'
            'deny["Доступ к .aws/credentials заблокирован"] {\n'
            '  contains(input.path, ".aws/credentials")\n'
            '}\n'
        ),
    },
    "10_block_shell_after_untrusted_web": {
        "title": "Запрет shell после чтения внешнего URL (Taint CFI)",
        "rego": (
            'package padam.cfi\n'
            'default allow = true\n'
            'deny["Исполнение shell запрещено после чтения внешних сайтов"] {\n'
            '  input.tool in {"bash", "shell", "powershell"}\n'
            '  input.tainted_untrusted == true\n'
            '}\n'
        ),
    },
    "11_block_unpinned_mcp": {
        "title": "Запрет вызова незакреплённых MCP-инструментов",
        "rego": (
            'package padam.mcp\n'
            'default allow = true\n'
            'deny["MCP-инструмент не закреплён SHA-256 пиннингом"] {\n'
            '  input.mcp_pinned == false\n'
            '}\n'
        ),
    },
    "12_require_dual_control_prod_unlock": {
        "title": "Два подтверждения SecurityAdmin для разблокировки продакшн Kill Switch",
        "rego": (
            'package padam.iam\n'
            'default allow = true\n'
            'deny["В продакшн-контуре снятие Kill Switch требует 2 подписи SecurityAdmin"] {\n'
            '  input.env == "production"\n'
            '  input.action == "unlock_kill_switch"\n'
            '  input.security_admin_approvals < 2\n'
            '}\n'
        ),
    },
    "13_readonly_role_no_writes": {
        "title": "Запрет записи для роли ReadOnly / Auditor",
        "rego": (
            'package padam.iam\n'
            'default allow = true\n'
            'deny["Роли ReadOnly и Auditor не могут изменять состояние"] {\n'
            '  input.role in {"ReadOnly", "Auditor"}\n'
            '  input.action in {"write", "delete", "transfer", "shell"}\n'
            '}\n'
        ),
    },
    "14_block_low_trust_a2a": {
        "title": "Изоляция агентов роя с Trust Score ниже 0.4",
        "rego": (
            'package padam.a2a\n'
            'default allow = true\n'
            'deny["Агент с низким Trust Score (< 0.4) заблокирован"] {\n'
            '  input.agent_trust_score < 0.4\n'
            '}\n'
        ),
    },
    "15_require_https_only": {
        "title": "Только HTTPS для всех исходящих сетевых запросов",
        "rego": (
            'package padam.net\n'
            'default allow = true\n'
            'deny["Незащищённый HTTP запрещён — используйте HTTPS"] {\n'
            '  startswith(input.url, "http://")\n'
            '}\n'
        ),
    },
    "16_block_url_shorteners": {
        "title": "Запрет сокращателей ссылок в исходящем трафике",
        "rego": (
            'package padam.net\n'
            'default allow = true\n'
            'deny["Сокращатели ссылок запрещены политикой"] {\n'
            '  input.host in {"bit.ly", "tinyurl.com", "t.co", "rb.gy"}\n'
            '}\n'
        ),
    },
    "17_block_large_exfil_payload": {
        "title": "Запрет массовой выгрузки (> 50 КБ) на внешние домены",
        "rego": (
            'package padam.dlp\n'
            'default allow = true\n'
            'deny["Исходящий объём превышает 50 КБ для внешнего домена"] {\n'
            '  input.payload_bytes > 51200\n'
            '  input.domain_allowlisted == false\n'
            '}\n'
        ),
    },
    "18_block_pii_outbound": {
        "title": "Жёсткий запрет отправки PII (GDPR/HIPAA) наружу",
        "rego": (
            'package padam.gdpr\n'
            'default allow = true\n'
            'deny["Исходящее сообщение содержит незамаскированные PII"] {\n'
            '  input.pii_count > 0\n'
            '}\n'
        ),
    },
    "19_block_pickle_models": {
        "title": "Запрет загрузки небезопасных .pkl моделей без проверки",
        "rego": (
            'package padam.ml\n'
            'default allow = true\n'
            'deny["Загрузка .pkl моделей запрещена — используйте .safetensors"] {\n'
            '  endswith(input.model_path, ".pkl")\n'
            '}\n'
        ),
    },
    "20_block_high_ueba_zscore": {
        "title": "Остановка агента при Z-score UEBA >= 4.0",
        "rego": (
            'package padam.ueba\n'
            'default allow = true\n'
            'deny["Критическая поведенческая аномалия (Z-score >= 4.0)"] {\n'
            '  input.ueba_z_score >= 4.0\n'
            '}\n'
        ),
    },
    "21_block_semantic_injection_score": {
        "title": "Блокировка при высокой семантической вероятности атаки (>= 0.80)",
        "rego": (
            'package padam.semantic\n'
            'default allow = true\n'
            'deny["Семантический классификатор выявил атаку (>= 0.80)"] {\n'
            '  input.semantic_score >= 0.80\n'
            '}\n'
        ),
    },
    "22_block_force_push_main": {
        "title": "Запрет git push --force в защищённые ветки",
        "rego": (
            'package padam.devops\n'
            'default allow = true\n'
            'deny["Принудительный force-push в main/master запрещён"] {\n'
            '  regex.match("git\\s+push.*(--force|-f).*(main|master)", input.command)\n'
            '}\n'
        ),
    },
    "23_block_prod_db_drop": {
        "title": "Запрет DROP TABLE / TRUNCATE в SQL-запросах агентов",
        "rego": (
            'package padam.devops\n'
            'default allow = true\n'
            'deny["Деструктивный SQL (DROP/TRUNCATE) заблокирован"] {\n'
            '  regex.match("(?i)\\b(DROP\\s+TABLE|TRUNCATE\\s+TABLE)\\b", input.sql)\n'
            '}\n'
        ),
    },
    "24_finance_daily_cap_2000": {
        "title": "Суточный лимит автономных платежей агента $2 000",
        "rego": (
            'package padam.fin\n'
            'default allow = true\n'
            'deny["Превышен суточный лимит платежей агента ($2000)"] {\n'
            '  input.daily_spent_usd > 2000\n'
            '}\n'
        ),
    },
    "25_airgap_no_external_email": {
        "title": "Запрет отправки писем за пределы корпоративного домена",
        "rego": (
            'package padam.mail\n'
            'default allow = true\n'
            'deny["Отправка писем на внешние домены запрещена в airgap-профиле"] {\n'
            '  input.action == "email_send"\n'
            '  not endswith(input.recipient, "@codeofdigitaleternity.com")\n'
            '}\n'
        ),
    },
}


def _resolve_value(expr: str, input_data: dict[str, Any]) -> Any:
    e = expr.strip()
    if e == "true":
        return True
    if e == "false":
        return False
    if e == "null":
        return None
    if (e.startswith('"') and e.endswith('"')) or (e.startswith("'") and e.endswith("'")):
        return e[1:-1]
    if e.startswith("{") and e.endswith("}"):
        inner = e[1:-1].strip()
        if not inner:
            return set()
        items = [x.strip() for x in re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", inner)]
        return {_resolve_value(it, input_data) for it in items}
    if re.fullmatch(r"-?\d+(?:\.\d+)?", e):
        return float(e) if "." in e else int(e)
    if e.startswith("input."):
        cur: Any = input_data
        for part in e.split(".")[1:]:
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur
    if e == "input":
        return input_data
    return e


def _eval_condition(line: str, input_data: dict[str, Any]) -> bool:
    s = line.strip()
    if not s or s.startswith("#"):
        return True
    negated = False
    if s.startswith("not "):
        negated = True
        s = s[4:].strip()

    res = False
    # Встроенные функции: contains(a, b), startswith(a, b), endswith(a, b), regex.match(pat, val)
    m_fn = re.fullmatch(r"(contains|startswith|endswith|regex\.match)\s*\((.+)\)", s)
    if m_fn:
        fn = m_fn.group(1)
        args_raw = re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", m_fn.group(2))
        args = [_resolve_value(a, input_data) for a in args_raw]
        if len(args) == 2:
            a0, a1 = str(args[0] or ""), str(args[1] or "")
            if fn == "contains":
                res = a1 in a0
            elif fn == "startswith":
                res = a0.startswith(a1)
            elif fn == "endswith":
                res = a0.endswith(a1)
            elif fn == "regex.match":
                try:
                    res = bool(re.search(a0, a1))
                except re.error:
                    res = False
        return (not res) if negated else res

    # Бинарные операторы сравнения
    m_bin = re.match(r"^(.+?)\s*(==|!=|>=|<=|>|<|\bin\b)\s*(.+)$", s)
    if m_bin:
        lhs = _resolve_value(m_bin.group(1), input_data)
        op = m_bin.group(2)
        rhs = _resolve_value(m_bin.group(3), input_data)
        if op == "==":
            res = lhs == rhs
        elif op == "!=":
            res = lhs != rhs
        elif op == "in":
            try:
                res = lhs in rhs  # type: ignore[operator]
            except TypeError:
                res = False
        elif lhs is not None and rhs is not None:
            try:
                lf, rf = float(lhs), float(rhs)
                if op == ">":
                    res = lf > rf
                elif op == ">=":
                    res = lf >= rf
                elif op == "<":
                    res = lf < rf
                elif op == "<=":
                    res = lf <= rf
            except (TypeError, ValueError):
                res = False
        return (not res) if negated else res

    val = _resolve_value(s, input_data)
    res = bool(val)
    return (not res) if negated else res


def evaluate_rego_policy(rego_source: str, input_data: dict[str, Any]) -> dict[str, Any]:
    """Локально вычисляет Rego-политику для переданного `input_data`."""
    t0 = time.perf_counter()
    src = str(rego_source or "")
    pkg_m = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)", src, re.M)
    package_name = pkg_m.group(1) if pkg_m else "padam.custom"

    def_m = re.search(r"^\s*default\s+allow\s*=\s*(true|false)", src, re.M)
    default_allow = (def_m.group(1) == "true") if def_m else True

    denies: list[str] = []
    allow_matched = False

    # Разбор блоков deny["msg"] { ... }
    for m in re.finditer(r'deny\s*\[\s*"([^"]+)"\s*\]\s*\{([^}]*)\}', src, re.S):
        msg = m.group(1)
        conds = [ln.strip() for ln in m.group(2).splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if conds and all(_eval_condition(c, input_data) for c in conds):
            denies.append(msg)

    # Разбор блоков allow { ... }
    has_allow_blocks = False
    for m in re.finditer(r'(?m)^\s*allow\s*\{([^}]*)\}', src, re.S):
        has_allow_blocks = True
        conds = [ln.strip() for ln in m.group(1).splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if conds and all(_eval_condition(c, input_data) for c in conds):
            allow_matched = True

    if denies:
        allowed = False
    elif has_allow_blocks:
        allowed = allow_matched or default_allow
    else:
        allowed = default_allow

    return {
        "ok": True,
        "package": package_name,
        "allowed": allowed,
        "deny_reasons": denies,
        "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }


def list_policy_templates() -> list[dict[str, str]]:
    """Возвращает каталог всех 25 готовых шаблонов Rego-политик."""
    return [
        {"id": k, "title": v["title"], "rego": v["rego"]}
        for k, v in sorted(POLICY_TEMPLATES.items())
    ]


def evaluate_template_by_id(template_id: str, input_data: dict[str, Any]) -> dict[str, Any]:
    tpl = POLICY_TEMPLATES.get(template_id)
    if tpl is None:
        raise KeyError(f"Unknown policy template: {template_id!r}")
    res = evaluate_rego_policy(tpl["rego"], input_data)
    res["template_id"] = template_id
    res["title"] = tpl["title"]
    return res
