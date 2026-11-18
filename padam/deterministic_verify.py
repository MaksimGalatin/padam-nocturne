# -*- coding: utf-8 -*-
"""Детерминированный Верификатор Чисел, Дат и Хешей (без eval(), пункт 7).

Держится строго в узких проверенных границах (поправка приёмки 17.11):
1. Арифметические выражения — только через безопасный парсер `ast.parse(..., mode='eval')`
   с разрешённым белым списком узлов (`+`, `-`, `*`, `/`, `//`, `%`, `**`, унарные `+/-`).
2. Проверка сумм процентов (например `5 + 5 + 15 + 7 + 3 + 65 == 100`).
3. Проверка календарной корректности ISO-дат (`YYYY-MM-DD`).
4. Проверка контрольных сумм `SHA-256` байтов или файла.
"""
from __future__ import annotations

import ast
import hashlib
import operator
import re
from datetime import date, datetime
from typing import Any

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval_ast_node(node: ast.AST) -> float:
    if isinstance(node, ast.Expression):
        return _eval_ast_node(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return float(node.value)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return float(_UNARY_OPS[type(node.op)](_eval_ast_node(node.operand)))
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        left = _eval_ast_node(node.left)
        right = _eval_ast_node(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > 1000:
            raise ValueError("Exponent too large for deterministic verification")
        return float(_BIN_OPS[type(node.op)](left, right))
    raise ValueError(f"Disallowed AST node in arithmetic expression: {type(node).__name__}")


def verify_arithmetic(expression: str) -> dict[str, Any]:
    """Безопасно вычисляет арифметическое выражение без `eval()`."""
    expr = (expression or "").strip()
    if not expr or len(expr) > 256:
        return {"ok": False, "error": "empty_or_too_long"}
    try:
        tree = ast.parse(expr, mode="eval")
        val = _eval_ast_node(tree)
        if val.is_integer():
            val_out: int | float = int(val)
        else:
            val_out = round(val, 10)
        return {"ok": True, "expression": expr, "value": val_out}
    except Exception as exc:
        return {"ok": False, "expression": expr, "error": str(exc)}


def verify_percentage_sum(shares: list[float | int] | str, *, expected_total: float = 100.0, tol: float = 1e-6) -> dict[str, Any]:
    """Проверяет, сходятся ли доли/проценты в ожидаемую сумму (например 100%)."""
    if isinstance(shares, str):
        nums = [float(x) for x in re.findall(r"-?\d+(?:\.\d+)?", shares)]
    else:
        nums = [float(x) for x in shares]
    total = round(sum(nums), 8)
    valid = bool(nums) and abs(total - expected_total) <= tol and all(x >= 0 for x in nums)
    return {
        "valid": valid,
        "parts": nums,
        "sum": total,
        "expected": expected_total,
        "diff": round(total - expected_total, 8),
    }


def verify_iso_date(text: str) -> dict[str, Any]:
    """Проверяет валидность календарной даты ISO (`YYYY-MM-DD` или `ISO-8601`)."""
    s = (text or "").strip()
    try:
        if len(s) == 10:
            d = date.fromisoformat(s)
            return {"valid": True, "normalized": d.isoformat()}
        norm = s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s
        dt = datetime.fromisoformat(norm)
        return {"valid": True, "normalized": dt.isoformat()}
    except Exception as exc:
        return {"valid": False, "input": s, "error": str(exc)}


def verify_sha256(data: bytes | str, expected_hex: str) -> dict[str, Any]:
    """Сверяет контрольную сумму SHA-256 без угадывания."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    actual = hashlib.sha256(raw).hexdigest()
    exp = (expected_hex or "").strip().lower()
    return {
        "valid": actual == exp,
        "actual_sha256": actual,
        "expected_sha256": exp,
    }
