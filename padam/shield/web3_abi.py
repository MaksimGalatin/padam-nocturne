# -*- coding: utf-8 -*-
"""Локальный декодер смарт-контрактов EVM ABI и инструкций Solana для Кольца 3 (Payee-Swap).

Расширяет защиту криптоплатежей с проверки адресов на анализ вызовов смарт-контрактов:
- EVM calldata: `approve(address,uint256)` с проверкой `MAX_UINT256` / бесконечного лимита,
  `setApprovalForAll(address,bool)`, `transferOwnership(address)`, `permit(...)`,
  `increaseAllowance(...)`, `transfer(...)`, `transferFrom(...)`, `upgradeTo(address)`.
- Solana инструкции: `SPL Token Approve / ApproveChecked`, `SetAuthority`,
  `CloseAccount`, `SystemProgram.Transfer`, `BPFLoaderUpgrade`.
"""
from __future__ import annotations

import re
from typing import Any

# Известные 4-байтные селекторы опасных и финансовых методов EVM
EVM_SELECTORS: dict[str, dict[str, Any]] = {
    "095ea7b3": {"name": "approve(address,uint256)", "risk": "high", "kind": "allowance"},
    "a22cb465": {"name": "setApprovalForAll(address,bool)", "risk": "critical", "kind": "approval_all"},
    "f2fde38b": {"name": "transferOwnership(address)", "risk": "critical", "kind": "ownership"},
    "39509351": {"name": "increaseAllowance(address,uint256)", "risk": "high", "kind": "allowance"},
    "d505accf": {"name": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", "risk": "critical", "kind": "permit"},
    "a9059cbb": {"name": "transfer(address,uint256)", "risk": "medium", "kind": "transfer"},
    "23b872dd": {"name": "transferFrom(address,address,uint256)", "risk": "high", "kind": "transfer_from"},
    "3659cfe6": {"name": "upgradeTo(address)", "risk": "critical", "kind": "proxy_upgrade"},
    "4f1ef286": {"name": "upgradeToAndCall(address,bytes)", "risk": "critical", "kind": "proxy_upgrade"},
    "715018a6": {"name": "renounceOwnership()", "risk": "critical", "kind": "ownership"},
}

UNLIMITED_THRESHOLD = 1 << 255
MAX_UINT256 = (1 << 256) - 1

_CALLDATA_RE = re.compile(r"\b0x[a-fA-F0-9]{8,}\b")

# Опасные программы и инструкции Solana
SOLANA_DANGEROUS_INSTRUCTIONS: dict[str, str] = {
    "approve": "high",
    "approvechecked": "high",
    "setauthority": "critical",
    "closeaccount": "high",
    "transfer": "medium",
    "transferchecked": "medium",
    "assign": "critical",
    "upgrade": "critical",
    "setupgradeauthority": "critical",
}


def _decode_word_address(word_hex: str) -> str:
    if len(word_hex) < 64:
        return ""
    return "0x" + word_hex[24:64].lower()


def _decode_word_uint(word_hex: str) -> int:
    if len(word_hex) < 64:
        return 0
    return int(word_hex[:64], 16)


def decode_evm_calldata(
    calldata: str,
    *,
    contract_address: str = "",
    allowed_contracts: set[str] | None = None,
    allowed_spenders: set[str] | None = None,
) -> dict[str, Any]:
    """Декодирует EVM calldata без сети и проверяет на опасные вызовы смарт-контрактов."""
    raw = str(calldata or "").strip()
    if raw.lower().startswith("0x"):
        hex_body = raw[2:].lower()
    else:
        hex_body = raw.lower()
    if len(hex_body) < 8 or not re.fullmatch(r"[0-9a-f]+", hex_body):
        return {"ok": False, "decoded": False, "reason": "invalid_hex_calldata", "blocked": False, "findings": []}

    selector = hex_body[:8]
    args_hex = hex_body[8:]
    words = [args_hex[i : i + 64] for i in range(0, len(args_hex), 64) if len(args_hex[i : i + 64]) == 64]

    meta = EVM_SELECTORS.get(selector)
    if meta is None:
        return {
            "ok": True,
            "decoded": False,
            "selector": "0x" + selector,
            "method": "unknown",
            "blocked": False,
            "risk_level": "low",
            "findings": [],
        }

    method = meta["name"]
    kind = meta["kind"]
    allowed_c = {a.lower() for a in (allowed_contracts or set())}
    allowed_s = {a.lower() for a in (allowed_spenders or set())}
    c_addr = str(contract_address or "").strip().lower()

    findings: list[dict[str, str]] = []
    parsed_args: dict[str, Any] = {}
    blocked = False
    risk_level = "low"

    if kind == "allowance" and len(words) >= 2:
        spender = _decode_word_address(words[0])
        amount = _decode_word_uint(words[1])
        parsed_args = {
            "spender": spender,
            "amount": str(amount),
            "is_unlimited": amount >= UNLIMITED_THRESHOLD,
        }
        if amount >= UNLIMITED_THRESHOLD and spender not in allowed_s:
            blocked = True
            risk_level = "critical"
            findings.append({
                "code": "evm_unlimited_token_approval",
                "severity": "critical",
                "detail": f"Заблокирован бесконечный {method} (MAX_UINT256) для неутверждённого контракта {spender}!",
            })
        elif spender not in allowed_s and c_addr not in allowed_c:
            risk_level = "high"
            findings.append({
                "code": "evm_untrusted_spender_approval",
                "severity": "high",
                "detail": f"Вызов {method} на адрес {spender}, отсутствующий в белом списке владельца.",
            })

    elif kind == "approval_all" and len(words) >= 2:
        operator = _decode_word_address(words[0])
        approved = _decode_word_uint(words[1]) != 0
        parsed_args = {"operator": operator, "approved": approved}
        if approved and operator not in allowed_s:
            blocked = True
            risk_level = "critical"
            findings.append({
                "code": "evm_set_approval_for_all_blocked",
                "severity": "critical",
                "detail": f"Заблокирован {method} (approved=true) для неутверждённого оператора {operator}!",
            })

    elif kind == "ownership":
        new_owner = _decode_word_address(words[0]) if words else ""
        parsed_args = {"new_owner": new_owner}
        if not new_owner or new_owner not in allowed_s:
            blocked = True
            risk_level = "critical"
            findings.append({
                "code": "evm_ownership_transfer_blocked",
                "severity": "critical",
                "detail": f"Критическая блокировка {method} (новый владелец: {new_owner or 'renounced'})!",
            })

    elif kind == "proxy_upgrade":
        impl = _decode_word_address(words[0]) if words else ""
        parsed_args = {"implementation": impl}
        if impl not in allowed_c:
            blocked = True
            risk_level = "critical"
            findings.append({
                "code": "evm_proxy_upgrade_blocked",
                "severity": "critical",
                "detail": f"Заблокировано обновление прокси-контракта {method} на неутверждённую реализацию {impl}!",
            })

    elif kind == "permit" and len(words) >= 3:
        owner_addr = _decode_word_address(words[0])
        spender = _decode_word_address(words[1])
        value = _decode_word_uint(words[2])
        parsed_args = {"owner": owner_addr, "spender": spender, "value": str(value), "is_unlimited": value >= UNLIMITED_THRESHOLD}
        if spender not in allowed_s:
            blocked = value >= UNLIMITED_THRESHOLD
            risk_level = "critical" if blocked else "high"
            findings.append({
                "code": "evm_eip2612_permit_untrusted",
                "severity": risk_level,
                "detail": f"EIP-2612 {method} для неутверждённого spender {spender} (unlimited={value >= UNLIMITED_THRESHOLD}).",
            })

    elif kind in ("transfer", "transfer_from"):
        recipient = _decode_word_address(words[1] if kind == "transfer_from" and len(words) >= 2 else (words[0] if words else ""))
        amount = _decode_word_uint(words[2] if kind == "transfer_from" and len(words) >= 3 else (words[1] if len(words) >= 2 else ""))
        parsed_args = {"recipient": recipient, "amount": str(amount)}
        if recipient and recipient not in allowed_s:
            risk_level = "high"
            findings.append({
                "code": "evm_untrusted_token_recipient",
                "severity": "high",
                "detail": f"Вызов {method} на получателя {recipient}, отсутствующего в белом списке.",
            })

    return {
        "ok": True,
        "decoded": True,
        "chain": "evm",
        "selector": "0x" + selector,
        "method": method,
        "contract_address": c_addr,
        "args": parsed_args,
        "blocked": blocked,
        "risk_level": risk_level,
        "findings": findings,
    }


def inspect_solana_instruction(
    instruction: dict[str, Any],
    *,
    allowed_programs: set[str] | None = None,
    allowed_wallets: set[str] | None = None,
) -> dict[str, Any]:
    """Проверяет инструкцию Solana (SPL Token / System / BPF Loader) до подписания."""
    iname = str(instruction.get("instruction") or instruction.get("type") or "").strip()
    inorm = re.sub(r"[^a-z0-9]", "", iname.lower())
    prog = str(instruction.get("program_id") or instruction.get("program") or "").strip()
    delegate = str(
        instruction.get("delegate")
        or instruction.get("new_authority")
        or instruction.get("destination")
        or instruction.get("recipient")
        or ""
    ).strip()
    amount = int(instruction.get("amount") or 0)
    max_u64 = (1 << 64) - 1

    allowed_w = set(allowed_wallets or set())
    allowed_p = set(allowed_programs or set())
    findings: list[dict[str, str]] = []
    blocked = False
    risk_level = "low"

    if inorm == "setauthority" or inorm == "setupgradeauthority" or inorm == "assign":
        if delegate not in allowed_w:
            blocked = True
            risk_level = "critical"
            findings.append({
                "code": "solana_set_authority_blocked",
                "severity": "critical",
                "detail": f"Заблокирована смена прав Solana ({iname}) на неутверждённый адрес {delegate or 'unknown'}!",
            })
    elif inorm in ("approve", "approvechecked"):
        unlimited = amount >= (1 << 62) or amount == max_u64
        if unlimited and delegate not in allowed_w:
            blocked = True
            risk_level = "critical"
            findings.append({
                "code": "solana_unlimited_spl_approve_blocked",
                "severity": "critical",
                "detail": f"Заблокирован неограниченный SPL Token {iname} (amount={amount}) для делегата {delegate}!",
            })
        elif delegate and delegate not in allowed_w:
            risk_level = "high"
            findings.append({
                "code": "solana_untrusted_delegate",
                "severity": "high",
                "detail": f"SPL Token {iname} на делегата {delegate}, отсутствующего в белом списке.",
            })
    elif inorm == "closeaccount":
        if delegate and delegate not in allowed_w:
            blocked = True
            risk_level = "critical"
            findings.append({
                "code": "solana_close_account_untrusted",
                "severity": "critical",
                "detail": f"Заблокировано закрытие SPL-аккаунта с выводом rent на неутверждённый адрес {delegate}!",
            })
    elif inorm in ("transfer", "transferchecked") and delegate and delegate not in allowed_w:
        risk_level = "high"
        findings.append({
            "code": "solana_untrusted_recipient",
            "severity": "high",
            "detail": f"Solana {iname} на адрес {delegate}, отсутствующий в белом списке владельца.",
        })

    if prog and allowed_p and prog not in allowed_p:
        risk_level = "high" if risk_level == "low" else risk_level
        findings.append({
            "code": "solana_unlisted_program_id",
            "severity": "high",
            "detail": f"Программа Solana `{prog}` не входит в белый список доверенных контрактов.",
        })

    return {
        "ok": True,
        "chain": "solana",
        "instruction": iname,
        "program_id": prog,
        "delegate_or_recipient": delegate,
        "amount": amount,
        "blocked": blocked,
        "risk_level": risk_level,
        "findings": findings,
    }


def scan_text_for_web3_tx(
    text: str,
    *,
    allowed_wallets: set[str] | None = None,
) -> dict[str, Any]:
    """Ищет внутри произвольной нагрузки исходящего действия EVM calldata и Solana-инструкции."""
    raw = str(text or "")
    findings: list[dict[str, str]] = []
    decoded_calls: list[dict[str, Any]] = []
    blocked = False
    allowed_low = {w.lower() for w in (allowed_wallets or set())}

    # 1. Ищем hex calldata длиной >= 10 символов (исключаем обычные 40-символьные адреса и 64-символьные хеши,
    # если они не начинаются с известного 4-байтного селектора + хотя бы 1 аргумента)
    for m in _CALLDATA_RE.finditer(raw):
        tok = m.group(0)
        body = tok[2:].lower()
        if len(body) >= 72 and body[:8] in EVM_SELECTORS:
            res = decode_evm_calldata(tok, allowed_contracts=allowed_low, allowed_spenders=allowed_low)
            if res.get("decoded"):
                decoded_calls.append(res)
                findings.extend(res.get("findings") or [])
                if res.get("blocked"):
                    blocked = True

    # 2. Текстовые упоминания опасных вызовов смарт-контрактов (например, JSON/JS параметры транзакции)
    if re.search(r"(?i)\b(?:setApprovalForAll|transferOwnership|SetAuthority)\b", raw):
        if not decoded_calls:
            blocked = True
            findings.append({
                "code": "web3_dangerous_contract_method_text",
                "severity": "critical",
                "detail": "Обнаружен вызов опасного метода смарт-контракта (setApprovalForAll / transferOwnership / SetAuthority).",
            })
    elif re.search(r"(?i)\bapprove\s*\([^)]*(?:0xf{16,}|MAX_UINT256|unlimited|2\*\*256)", raw):
        if not decoded_calls:
            blocked = True
            findings.append({
                "code": "web3_unlimited_approve_text",
                "severity": "critical",
                "detail": "Обнаружен бесконечный approve(MAX_UINT256) в тексте исходящей транзакции.",
            })

    return {
        "ok": True,
        "blocked": blocked,
        "decoded_calls": decoded_calls,
        "findings": findings,
    }
