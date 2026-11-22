# -*- coding: utf-8 -*-
"""Детерминированный Верификатор Чисел, Дат и Хешей (безопасный AST без произвольного исполнения кода, пункт 7).

Держится строго в узких проверенных границах (поправка приёмки 17.11):
1. Арифметические выражения — только через безопасный разбор синтаксического дерева `ast.parse`
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
from pathlib import Path

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


def _compute_ast_node(node: ast.AST) -> float:
    if isinstance(node, ast.Expression):
        return _compute_ast_node(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return float(node.value)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return float(_UNARY_OPS[type(node.op)](_compute_ast_node(node.operand)))
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        left = _compute_ast_node(node.left)
        right = _compute_ast_node(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > 1000:
            raise ValueError("Exponent too large for deterministic verification")
        return float(_BIN_OPS[type(node.op)](left, right))
    raise ValueError(f"Disallowed AST node in arithmetic expression: {type(node).__name__}")


def verify_arithmetic(expression: str) -> dict[str, Any]:
    """Безопасно вычисляет арифметическое выражение по AST-дереву без выполнения кода."""
    expr = (expression or "").strip()
    if not expr or len(expr) > 256:
        return {"ok": False, "error": "empty_or_too_long"}
    try:
        tree = ast.parse(expr, mode="eval")
        val = _compute_ast_node(tree)
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


def verify_file_claim(
    path: str | Path,
    *,
    expected_sha256: str | None = None,
    contains: str | None = None,
    min_bytes: int = 1,
) -> dict[str, Any]:
    """Детерминированно проверяет существование файла, размер, SHA-256 и подстроку."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {
            "kind": "file",
            "target": str(p),
            "valid": False,
            "exists": False,
            "error": "file_not_found",
        }
    raw = p.read_bytes()
    size = len(raw)
    sha256_actual = hashlib.sha256(raw).hexdigest()
    reasons: list[str] = []
    if size < max(0, int(min_bytes)):
        reasons.append(f"size_below_min:{size}<{min_bytes}")
    sha_ok = True
    if expected_sha256 is not None:
        exp = expected_sha256.strip().lower()
        sha_ok = sha256_actual == exp
        if not sha_ok:
            reasons.append("sha256_mismatch")
    contains_ok = True
    if contains is not None:
        text = raw.decode("utf-8", errors="replace")
        contains_ok = contains in text
        if not contains_ok:
            reasons.append("substring_not_found")
    return {
        "kind": "file",
        "target": str(p),
        "valid": len(reasons) == 0,
        "exists": True,
        "size_bytes": size,
        "sha256": sha256_actual,
        "sha256_match": sha_ok,
        "contains_match": contains_ok,
        "reasons": reasons,
    }


def verify_url_live(
    url: str,
    *,
    timeout: float = 8.0,
    expected_status: int | tuple[int, ...] = (200, 201, 204, 301, 302, 307, 308),
    contains: str | None = None,
    allow_localhost: bool = False,
    max_body_bytes: int = 262144,
) -> dict[str, Any]:
    """Проверяет живой URL через net_guard.safe_urlopen без обхода SSRF-защиты."""
    from .net_guard import safe_urlopen

    allowed_statuses = (
        (expected_status,) if isinstance(expected_status, int) else tuple(expected_status)
    )
    req_headers = {"User-Agent": "PADAM-DeterministicVerify/0.7.1"}
    try:
        with safe_urlopen(
            url,
            headers=req_headers,
            method="GET",
            timeout=float(timeout),
            allow_localhost=bool(allow_localhost),
            allow_http_localhost=bool(allow_localhost),
            require_https=not bool(allow_localhost),
        ) as resp:
            status = int(getattr(resp, "status", 0) or resp.getcode() or 0)
            body = resp.read(max_body_bytes)
            final_url = str(getattr(resp, "geturl", lambda: url)())
            sha256_actual = hashlib.sha256(body).hexdigest()
            reasons: list[str] = []
            if status not in allowed_statuses:
                reasons.append(f"unexpected_status:{status}")
            contains_ok = True
            if contains is not None:
                text = body.decode("utf-8", errors="replace")
                contains_ok = contains in text
                if not contains_ok:
                    reasons.append("substring_not_found")
            return {
                "kind": "url",
                "target": url,
                "final_url": final_url,
                "valid": len(reasons) == 0,
                "status": status,
                "size_bytes": len(body),
                "sha256": sha256_actual,
                "contains_match": contains_ok,
                "reasons": reasons,
            }
    except ValueError as exc:
        return {
            "kind": "url",
            "target": url,
            "valid": False,
            "blocked": True,
            "error": str(exc),
            "reasons": ["ssrf_blocked"],
        }
    except Exception as exc:
        return {
            "kind": "url",
            "target": url,
            "valid": False,
            "blocked": False,
            "error": str(exc),
            "reasons": ["request_failed"],
        }


def verify_claims_batch(
    claims: list[dict[str, Any]],
    *,
    allow_localhost: bool = False,
) -> dict[str, Any]:
    """Пакетно проверяет список утверждений (file, url, sha256, python_ast, date)."""
    results: list[dict[str, Any]] = []
    for item in claims:
        if not isinstance(item, dict):
            results.append({"kind": "unknown", "valid": False, "error": "invalid_claim_item"})
            continue
        kind = str(item.get("kind") or "").strip().lower()
        if kind == "file":
            res = verify_file_claim(
                str(item.get("path") or item.get("target") or ""),
                expected_sha256=item.get("expected_sha256"),
                contains=item.get("contains"),
                min_bytes=int(item.get("min_bytes", 1)),
            )
        elif kind == "url":
            exp_st = item.get("expected_status")
            kwargs: dict[str, Any] = {
                "timeout": float(item.get("timeout", 8.0)),
                "contains": item.get("contains"),
                "allow_localhost": bool(item.get("allow_localhost", allow_localhost)),
            }
            if exp_st is not None:
                kwargs["expected_status"] = (
                    tuple(int(x) for x in exp_st)
                    if isinstance(exp_st, (list, tuple))
                    else int(exp_st)
                )
            res = verify_url_live(str(item.get("url") or item.get("target") or ""), **kwargs)
        elif kind == "sha256":
            res = verify_sha256(str(item.get("data") or ""), str(item.get("expected_sha256") or ""))
            res["kind"] = "sha256"
        elif kind == "python_ast":
            res = verify_python_ast(
                str(item.get("code") or ""),
                expected_functions=item.get("expected_functions"),
            )
            res["kind"] = "python_ast"
        elif kind == "date":
            res = verify_date_consistency(
                str(item.get("raw_date") or item.get("target") or ""),
                expected_year=item.get("expected_year"),
            )
            res["kind"] = "date"
        else:
            res = {"kind": kind or "unknown", "valid": False, "error": "unsupported_kind"}
        if "label" in item:
            res["label"] = str(item["label"])
        results.append(res)

    passed = sum(1 for r in results if r.get("valid"))
    total = len(results)
    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "all_valid": total > 0 and passed == total,
        "results": results,
    }
