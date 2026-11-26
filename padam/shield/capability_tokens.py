# -*- coding: utf-8 -*-
"""Криптографические гранулярные мандаты возможностей (Attenuated Capability Tokens).

Закрывает атаку Confused Deputy (OWASP Agentic Top 10 #1): главный агент или
владелец выдаёт подписанный мандат с жёсткими рамками (инструменты, пути,
домены, лимит вызовов, бюджет в центах, TTL). Делегировать мандат субагенту
можно ТОЛЬКО сужая права (`attenuate_capability_token`): любая попытка
расширить список инструментов, пути, домены, бюджет или время жизни
криптографически отвергается. Отзыв родителя каскадно отзывает всю ветку.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .. import agentic_shield as _ash
from .. import integrity as _integrity


TOKEN_PREFIX = "PADAMCAP1"


def _ensure_tables(memory: Any) -> None:
    conn = memory.store.conn
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shield_capabilities (
            token_id TEXT PRIMARY KEY,
            parent_id TEXT,
            root_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            scope_json TEXT NOT NULL,
            calls_used INTEGER NOT NULL DEFAULT 0,
            spent_cents REAL NOT NULL DEFAULT 0.0,
            revoked INTEGER NOT NULL DEFAULT 0,
            expires_at REAL NOT NULL,
            created_at REAL NOT NULL,
            hmac_sig TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_shield_cap_parent ON shield_capabilities(parent_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_shield_cap_root ON shield_capabilities(root_id)"
    )
    conn.commit()


def _owner_key(memory: Any) -> bytes:
    key, _ = _integrity.owner_key(memory.store)
    return key if isinstance(key, bytes) else str(key).encode("utf-8")


def _sign_payload(memory: Any, payload_bytes: bytes) -> str:
    return hmac.new(_owner_key(memory), payload_bytes, hashlib.sha256).hexdigest()


def _norm_path(path: str) -> str:
    p = str(path or "").strip().replace("\\", "/")
    while "//" in p:
        p = p.replace("//", "/")
    return p.lower()


def _norm_list(items: Optional[Iterable[str]], *, lower: bool = True) -> List[str]:
    if not items:
        return []
    out: List[str] = []
    seen = set()
    for x in items:
        s = str(x or "").strip()
        if not s:
            continue
        if lower:
            s = s.lower()
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _pattern_covered_by(child_pat: str, parent_pats: Sequence[str]) -> bool:
    """Проверяет, что шаблон прав субагента не шире шаблонов родителя."""
    if not parent_pats:
        return False
    c = child_pat.strip().lower()
    for p in parent_pats:
        pp = p.strip().lower()
        if pp == "*" or pp == c:
            return True
        if fnmatch.fnmatchcase(c, pp):
            return True
        # Для путей: 'docs/sub/*' покрывается 'docs/*'
        if pp.endswith("/*") and c.startswith(pp[:-1]):
            return True
        if pp.endswith("/**") and c.startswith(pp[:-2]):
            return True
    return False


def _domain_covered_by(child_dom: str, parent_doms: Sequence[str]) -> bool:
    if not parent_doms:
        return False
    c = child_dom.strip().lower().lstrip(".")
    for p in parent_doms:
        pp = p.strip().lower().lstrip(".")
        if pp == "*" or pp == c:
            return True
        if pp.startswith("*.") and (c == pp[2:] or c.endswith("." + pp[2:])):
            return True
    return False


def _encode_token(payload: Dict[str, Any], sig: str) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{TOKEN_PREFIX}.{b64}.{sig}"


def _decode_token(token: str) -> Tuple[Optional[Dict[str, Any]], Optional[bytes], Optional[str], str]:
    parts = str(token or "").strip().split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        return None, None, None, "Неверный формат токена возможностей (ожидается PADAMCAP1.<payload>.<sig>)"
    b64, sig = parts[1], parts[2]
    pad = "=" * (-len(b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(b64 + pad)
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            return None, None, None, "Полезная нагрузка токена не является JSON-объектом"
        return payload, raw, sig, ""
    except Exception as exc:
        return None, None, None, f"Ошибка декодирования токена: {exc}"


def issue_capability_token(
    memory: Any,
    *,
    agent_id: str,
    allowed_tools: Sequence[str],
    allowed_paths: Sequence[str] = (),
    allowed_domains: Sequence[str] = (),
    max_calls: int = 100,
    max_spend_cents: float = 1000.0,
    ttl_sec: int = 3600,
    label: str = "",
) -> Dict[str, Any]:
    """Выпускает корневой подписанный Capability Token для агента."""
    _ensure_tables(memory)
    now = time.time()
    token_id = "cap_" + secrets.token_hex(8)
    expires_at = now + max(1, int(ttl_sec))
    scope = {
        "allowed_tools": _norm_list(allowed_tools, lower=True),
        "allowed_paths": [_norm_path(p) for p in _norm_list(allowed_paths, lower=False)],
        "allowed_domains": _norm_list(allowed_domains, lower=True),
        "max_calls": max(1, int(max_calls)),
        "max_spend_cents": max(0.0, float(max_spend_cents)),
    }
    payload = {
        "v": 1,
        "token_id": token_id,
        "parent_id": None,
        "root_id": token_id,
        "agent_id": str(agent_id or "default"),
        "scope": scope,
        "iat": round(now, 3),
        "exp": round(expires_at, 3),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = _sign_payload(memory, raw)
    token_str = _encode_token(payload, sig)

    conn = memory.store.conn
    conn.execute(
        """
        INSERT INTO shield_capabilities
            (token_id, parent_id, root_id, agent_id, label, scope_json,
             calls_used, spent_cents, revoked, expires_at, created_at, hmac_sig)
        VALUES (?, NULL, ?, ?, ?, ?, 0, 0.0, 0, ?, ?, ?)
        """,
        (
            token_id,
            token_id,
            payload["agent_id"],
            str(label or ""),
            json.dumps(scope, ensure_ascii=False),
            expires_at,
            now,
            sig,
        ),
    )
    conn.commit()
    return {
        "ok": True,
        "token_id": token_id,
        "root_id": token_id,
        "parent_id": None,
        "agent_id": payload["agent_id"],
        "scope": scope,
        "expires_at": expires_at,
        "token": token_str,
    }


def attenuate_capability_token(
    memory: Any,
    *,
    parent_token: str,
    delegate_agent_id: str,
    allowed_tools: Optional[Sequence[str]] = None,
    allowed_paths: Optional[Sequence[str]] = None,
    allowed_domains: Optional[Sequence[str]] = None,
    max_calls: Optional[int] = None,
    max_spend_cents: Optional[float] = None,
    ttl_sec: Optional[int] = None,
    label: str = "",
) -> Dict[str, Any]:
    """Делегирует мандат субагенту со строгим монотонным сужением прав."""
    _ensure_tables(memory)
    payload, raw, sig, err = _decode_token(parent_token)
    if err or payload is None or raw is None or sig is None:
        return {"ok": False, "blocked": True, "rule_id": "CAP-INVALID-TOKEN", "reason": err}

    expected_sig = _sign_payload(memory, raw)
    if not hmac.compare_digest(expected_sig, sig):
        return {
            "ok": False,
            "blocked": True,
            "rule_id": "CAP-SIGNATURE-INVALID",
            "reason": "Криптографическая подпись родительского мандата недействительна",
        }

    parent_id = str(payload.get("token_id") or "")
    row = memory.store.conn.execute(
        "SELECT root_id, scope_json, calls_used, spent_cents, revoked, expires_at, hmac_sig "
        "FROM shield_capabilities WHERE token_id = ?",
        (parent_id,),
    ).fetchone()
    if not row:
        return {
            "ok": False,
            "blocked": True,
            "rule_id": "CAP-UNKNOWN-PARENT",
            "reason": "Родительский мандат не зарегистрирован в локальном хранилище",
        }
    root_id, p_scope_json, p_calls_used, p_spent, p_revoked, p_exp, p_db_sig = row
    if not hmac.compare_digest(str(p_db_sig), sig):
        return {
            "ok": False,
            "blocked": True,
            "rule_id": "CAP-SIGNATURE-MISMATCH",
            "reason": "Подпись родительского мандата не совпадает с реестром",
        }
    if int(p_revoked) != 0 or _is_chain_revoked(memory, parent_id):
        return {
            "ok": False,
            "blocked": True,
            "rule_id": "CAP-PARENT-REVOKED",
            "reason": "Родительский мандат (или один из его предков) отозван",
        }
    now = time.time()
    if now >= float(p_exp):
        return {
            "ok": False,
            "blocked": True,
            "rule_id": "CAP-EXPIRED",
            "reason": "Срок действия родительского мандата истёк",
        }

    p_scope = json.loads(p_scope_json)
    violations: List[str] = []

    # 1. Инструменты: строго подмножество родительских
    p_tools = p_scope.get("allowed_tools") or []
    c_tools = _norm_list(allowed_tools, lower=True) if allowed_tools is not None else list(p_tools)
    for t in c_tools:
        if not _pattern_covered_by(t, p_tools):
            violations.append(f"Попытка расширить инструменты: '{t}' не входит в {p_tools}")

    # 2. Пути: если у родителя ограничены, субагент обязан укладываться в них
    p_paths = p_scope.get("allowed_paths") or []
    c_paths = [_norm_path(x) for x in _norm_list(allowed_paths, lower=False)] if allowed_paths is not None else list(p_paths)
    if p_paths:
        if not c_paths:
            violations.append("Нельзя снять ограничение на пути родительского мандата")
        else:
            for cp in c_paths:
                if not _pattern_covered_by(cp, p_paths):
                    violations.append(f"Попытка расширить путь: '{cp}' выходит за {p_paths}")

    # 3. Домены: строго подмножество родительских, если родитель ограничен
    p_doms = p_scope.get("allowed_domains") or []
    c_doms = _norm_list(allowed_domains, lower=True) if allowed_domains is not None else list(p_doms)
    if p_doms:
        if not c_doms:
            violations.append("Нельзя снять ограничение на домены родительского мандата")
        else:
            for cd in c_doms:
                if not _domain_covered_by(cd, p_doms):
                    violations.append(f"Попытка расширить домен: '{cd}' выходит за {p_doms}")

    # 4. Лимит вызовов и бюджет
    rem_calls = max(0, int(p_scope.get("max_calls", 0)) - int(p_calls_used))
    c_max_calls = int(max_calls) if max_calls is not None else rem_calls
    if c_max_calls > rem_calls or c_max_calls <= 0:
        violations.append(f"Лимит вызовов {c_max_calls} превышает остаток родителя ({rem_calls})")

    rem_spend = max(0.0, float(p_scope.get("max_spend_cents", 0.0)) - float(p_spent))
    c_max_spend = float(max_spend_cents) if max_spend_cents is not None else rem_spend
    if c_max_spend > rem_spend + 1e-6 or c_max_spend < 0:
        violations.append(f"Бюджет {c_max_spend:.2f}¢ превышает остаток родителя ({rem_spend:.2f}¢)")

    # 5. Срок жизни: не длиннее родителя
    c_exp = (now + int(ttl_sec)) if ttl_sec is not None else float(p_exp)
    if c_exp > float(p_exp) + 1.0:
        violations.append("Нельзя продлить TTL дочернего мандата дольше родительского")

    if violations:
        return {
            "ok": False,
            "blocked": True,
            "rule_id": "CAP-ESCALATION-DENIED",
            "reason": "; ".join(violations),
            "violations": violations,
        }

    token_id = "cap_" + secrets.token_hex(8)
    c_scope = {
        "allowed_tools": c_tools,
        "allowed_paths": c_paths,
        "allowed_domains": c_doms,
        "max_calls": c_max_calls,
        "max_spend_cents": round(c_max_spend, 4),
    }
    child_payload = {
        "v": 1,
        "token_id": token_id,
        "parent_id": parent_id,
        "root_id": str(root_id),
        "agent_id": str(delegate_agent_id or "subagent"),
        "scope": c_scope,
        "iat": round(now, 3),
        "exp": round(c_exp, 3),
    }
    child_raw = json.dumps(child_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    child_sig = _sign_payload(memory, child_raw)
    child_token = _encode_token(child_payload, child_sig)

    conn = memory.store.conn
    conn.execute(
        """
        INSERT INTO shield_capabilities
            (token_id, parent_id, root_id, agent_id, label, scope_json,
             calls_used, spent_cents, revoked, expires_at, created_at, hmac_sig)
        VALUES (?, ?, ?, ?, ?, ?, 0, 0.0, 0, ?, ?, ?)
        """,
        (
            token_id,
            parent_id,
            str(root_id),
            child_payload["agent_id"],
            str(label or ""),
            json.dumps(c_scope, ensure_ascii=False),
            c_exp,
            now,
            child_sig,
        ),
    )
    conn.commit()
    return {
        "ok": True,
        "blocked": False,
        "token_id": token_id,
        "parent_id": parent_id,
        "root_id": str(root_id),
        "agent_id": child_payload["agent_id"],
        "scope": c_scope,
        "expires_at": c_exp,
        "token": child_token,
    }


def _is_chain_revoked(memory: Any, token_id: str) -> bool:
    conn = memory.store.conn
    cur = token_id
    depth = 0
    while cur and depth < 32:
        row = conn.execute(
            "SELECT parent_id, revoked FROM shield_capabilities WHERE token_id = ?",
            (cur,),
        ).fetchone()
        if not row:
            return True
        parent_id, revoked = row
        if int(revoked) != 0:
            return True
        cur = parent_id
        depth += 1
    return False


def verify_and_consume_capability(
    memory: Any,
    *,
    token: str,
    tool_name: str,
    path: str = "",
    domain: str = "",
    spend_cents: float = 0.0,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Проверяет мандат и при разрешении списывает 1 вызов и бюджет."""
    _ensure_tables(memory)
    payload, raw, sig, err = _decode_token(token)
    if err or payload is None or raw is None or sig is None:
        return {"ok": False, "allowed": False, "blocked": True, "rule_id": "CAP-INVALID-TOKEN", "reason": err}

    expected_sig = _sign_payload(memory, raw)
    if not hmac.compare_digest(expected_sig, sig):
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": "CAP-SIGNATURE-INVALID",
            "reason": "Подпись мандата не прошла HMAC-проверку (возможна подделка)",
        }

    token_id = str(payload.get("token_id") or "")
    row = memory.store.conn.execute(
        "SELECT agent_id, scope_json, calls_used, spent_cents, revoked, expires_at, hmac_sig "
        "FROM shield_capabilities WHERE token_id = ?",
        (token_id,),
    ).fetchone()
    if not row:
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": "CAP-NOT-FOUND",
            "reason": "Мандат не найден в локальной базе",
        }
    agent_id, scope_json, calls_used, spent_cents, revoked, expires_at, db_sig = row
    if not hmac.compare_digest(str(db_sig), sig):
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": "CAP-SIGNATURE-MISMATCH",
            "reason": "Подпись мандата не совпадает с сохранённой",
        }
    if int(revoked) != 0 or _is_chain_revoked(memory, token_id):
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": "CAP-REVOKED",
            "reason": "Мандат (или его родитель в цепочке делегирования) отозван",
        }
    if time.time() >= float(expires_at):
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": "CAP-EXPIRED",
            "reason": "Срок действия мандата истёк",
        }

    scope = json.loads(scope_json)
    tool_l = str(tool_name or "").strip().lower()
    if not _pattern_covered_by(tool_l, scope.get("allowed_tools") or []):
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": "CAP-TOOL-DENIED",
            "reason": f"Инструмент '{tool_l}' запрещён мандатом (разрешены: {scope.get('allowed_tools')})",
        }

    if path and scope.get("allowed_paths"):
        norm_p = _norm_path(path)
        if ".." in norm_p.split("/") or not _pattern_covered_by(norm_p, scope["allowed_paths"]):
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "CAP-PATH-DENIED",
                "reason": f"Путь '{path}' выходит за границы мандата ({scope['allowed_paths']})",
            }

    if domain and scope.get("allowed_domains"):
        if not _domain_covered_by(domain, scope["allowed_domains"]):
            return {
                "ok": False,
                "allowed": False,
                "blocked": True,
                "rule_id": "CAP-DOMAIN-DENIED",
                "reason": f"Домен '{domain}' не разрешён мандатом ({scope['allowed_domains']})",
            }

    if int(calls_used) + 1 > int(scope.get("max_calls", 0)):
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": "CAP-CALL-LIMIT-EXCEEDED",
            "reason": f"Исчерпан лимит вызовов мандата ({calls_used}/{scope.get('max_calls')})",
        }

    new_spent = float(spent_cents) + max(0.0, float(spend_cents))
    if new_spent > float(scope.get("max_spend_cents", 0.0)) + 1e-6:
        return {
            "ok": False,
            "allowed": False,
            "blocked": True,
            "rule_id": "CAP-BUDGET-EXCEEDED",
            "reason": f"Превышен бюджет мандата ({new_spent:.2f}¢ > {scope.get('max_spend_cents'):.2f}¢)",
        }

    if not dry_run:
        memory.store.conn.execute(
            "UPDATE shield_capabilities SET calls_used = calls_used + 1, spent_cents = ? WHERE token_id = ?",
            (round(new_spent, 4), token_id),
        )
        memory.store.conn.commit()

    return {
        "ok": True,
        "allowed": True,
        "blocked": False,
        "token_id": token_id,
        "agent_id": agent_id,
        "calls_used": int(calls_used) + (0 if dry_run else 1),
        "max_calls": int(scope.get("max_calls", 0)),
        "spent_cents": round(new_spent if not dry_run else float(spent_cents), 4),
        "max_spend_cents": float(scope.get("max_spend_cents", 0.0)),
    }


def revoke_capability_token(memory: Any, token_id: str, *, cascade: bool = True) -> Dict[str, Any]:
    """Отзывает мандат и (по умолчанию) каскадно все делегированные дочерние мандаты."""
    _ensure_tables(memory)
    conn = memory.store.conn
    to_revoke = [str(token_id)]
    revoked_ids: List[str] = []
    seen = set()
    while to_revoke:
        cur = to_revoke.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        res = conn.execute("UPDATE shield_capabilities SET revoked = 1 WHERE token_id = ?", (cur,))
        if res.rowcount:
            revoked_ids.append(cur)
        if cascade:
            children = conn.execute(
                "SELECT token_id FROM shield_capabilities WHERE parent_id = ?",
                (cur,),
            ).fetchall()
            for (ch_id,) in children:
                if ch_id not in seen:
                    to_revoke.append(str(ch_id))
    conn.commit()
    return {
        "ok": True,
        "token_id": str(token_id),
        "cascade": bool(cascade),
        "revoked_count": len(revoked_ids),
        "revoked_ids": revoked_ids,
    }


def list_capability_tokens(memory: Any, *, include_revoked: bool = False) -> Dict[str, Any]:
    """Возвращает список выданных мандатов."""
    _ensure_tables(memory)
    q = (
        "SELECT token_id, parent_id, root_id, agent_id, label, scope_json, "
        "calls_used, spent_cents, revoked, expires_at, created_at "
        "FROM shield_capabilities"
    )
    if not include_revoked:
        q += " WHERE revoked = 0"
    q += " ORDER BY created_at DESC LIMIT 200"
    rows = memory.store.conn.execute(q).fetchall()
    items = []
    now = time.time()
    for r in rows:
        items.append(
            {
                "token_id": r[0],
                "parent_id": r[1],
                "root_id": r[2],
                "agent_id": r[3],
                "label": r[4],
                "scope": json.loads(r[5]),
                "calls_used": r[6],
                "spent_cents": r[7],
                "revoked": bool(r[8]),
                "expired": now >= float(r[9]),
                "expires_at": r[9],
                "created_at": r[10],
            }
        )
    return {"ok": True, "count": len(items), "items": items}
