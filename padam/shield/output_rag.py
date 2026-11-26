# -*- coding: utf-8 -*-
"""Двусторонний Output Guardrail (PII GDPR/HIPAA + SAST кода) и RAG Poisoning Shield.

1. Output Guardrail (`inspect_output_guardrails`):
   - Проверяет исходящий ответ и сгенерированный код на утечку секретов, канареек,
     персональных данных (PII: SSN, карты Luhn, IBAN mod-97, паспорта/ИНН/СНИЛС, мед-данные HIPAA)
     и опасные конструкции кода/терминала (SAST: SQLi, eval/exec, pickle.loads, subprocess shell=True,
     rm -rf, chmod 777, reverse shells, XSS innerHTML, отключение проверки TLS).
2. RAG Poisoning Shield (`sanitize_rag_document`):
   - Очищает HTML и бинарные PDF-документы ДО индексации в векторную память: вырезает скрытый
     текст (display:none, visibility:hidden, opacity:0, font-size:0, белый шрифт на белом фоне,
     PDF `Tf <= 1`, `1 1 1 rg`, `3 Tr` невидимый рендер), скрытые метаданные и Unicode-теги.
"""
from __future__ import annotations

import html as _html
import re
import zlib
from typing import Any

from .. import safety
from .exfil_guard import inspect_exfil_channels
from .semantic import classify_semantic_threat

# ---------- PII (GDPR / HIPAA) ----------
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SNILS_RE = re.compile(r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b")
_HIPAA_CONTEXT_RE = re.compile(
    r"(?i)\b(?:patient|diagnosis|medical\s+record|mrn|icd-?10|prescription|hipaa|диагноз|пациент|медкарт)\b"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# ---------- SAST (опасный код и команды терминала) ----------
_SAST_RULES: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    (
        "SAST-SQLI-CONCAT",
        "high",
        re.compile(r"(?i)(?:execute|query)\s*\(\s*(?:f[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*\{|[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*(?:\+|%\s*\())"),
        "Потенциальная SQL-инъекция: склейка/f-string в SQL-запросе вместо параметризации.",
    ),
    (
        "SAST-SHELL-DESTRUCTIVE",
        "critical",
        re.compile(r"(?i)(?:\brm\s+-[a-z]*r[a-z]*f\s+(?:/|~|\$HOME|\*)|\bchmod\s+-R\s+777\b|\bchmod\s+777\s+/|\bmkfs\.\w+\s+/dev/)"),
        "Разрушительная команда терминала (`rm -rf` / `chmod 777` / `mkfs`).",
    ),
    (
        "SAST-REVERSE-SHELL",
        "critical",
        re.compile(r"(?i)(?:/dev/tcp/\d|nc(?:at)?\s+[^\n]*-e\s+(?:/bin/)?(?:sh|bash)|bash\s+-i\s+>&|mkfifo\s+/tmp/|powershell(?:\.exe)?[^\n]*-enc(?:odedcommand)?\b)"),
        "Обнаружена сигнатура reverse-shell или закодированной команды PowerShell!",
    ),
    (
        "SAST-UNSAFE-DESERIALIZE",
        "high",
        re.compile(r"\b(?:pickle\.loads?|marshal\.loads?|yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)\))"),
        "Небезопасная десериализация (`pickle.loads` / `yaml.load` без SafeLoader).",
    ),
    (
        "SAST-SUBPROCESS-SHELL",
        "high",
        re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True"),
        "Вызов `subprocess(..., shell=True)` с риском инъекции команд ОС.",
    ),
    (
        "SAST-XSS-DOM",
        "medium",
        re.compile(r"(?:\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\()"),
        "Небезопасная вставка HTML в DOM (`innerHTML` / `document.write`) — риск XSS.",
    ),
    (
        "SAST-TLS-VERIFY-OFF",
        "medium",
        re.compile(r"(?:verify\s*=\s*Fals[e]|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)"),
        "Отключена проверка TLS-сертификатов (параметр `verify` равен `False`).",
    ),
)


def _luhn_valid(digits: str) -> bool:
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    total = 0
    rev = digits[::-1]
    for i, ch in enumerate(rev):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (total % 10) == 0


def _iban_valid(iban: str) -> bool:
    s = re.sub(r"\s+", "", iban).upper()
    if len(s) < 15 or len(s) > 34 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    rem = 0
    for ch in num:
        rem = (rem * 10 + (ord(ch) - 48)) % 97
    return rem == 1


def inspect_output_guardrails(
    text: str,
    *,
    memory: Any = None,
    agent_id: str = "agent",
    check_sast: bool = True,
    check_pii: bool = True,
) -> dict[str, Any]:
    """Двусторонний фильтр исходящих ответов агента: DLP/секреты + PII (GDPR/HIPAA) + SAST кода."""
    raw = str(text or "")
    redacted, sec_hits = safety.redact(raw)
    pii_findings: list[dict[str, str]] = []
    sast_findings: list[dict[str, str]] = []
    canary_hits: list[dict[str, Any]] = []

    if memory is not None:
        try:
            from .. import solana_crypto_shield

            canary_hits = solana_crypto_shield.scan_canaries_in_payload(memory, raw)
            for c in canary_hits:
                tok = str(c.get("token") or "")
                if tok:
                    redacted = redacted.replace(tok, "[CANARY_BLOCKED]")
        except Exception:
            pass

    if check_pii:
        if _SSN_RE.search(redacted):
            pii_findings.append({"code": "PII-US-SSN", "severity": "high", "detail": "Обнаружен US SSN в исходящем ответе."})
            redacted = _SSN_RE.sub("[REDACTED:SSN]", redacted)
        if _SNILS_RE.search(redacted):
            pii_findings.append({"code": "PII-RU-SNILS", "severity": "high", "detail": "Обнаружен СНИЛС в исходящем ответе."})
            redacted = _SNILS_RE.sub("[REDACTED:SNILS]", redacted)
        for m in _IBAN_RE.finditer(raw):
            if _iban_valid(m.group(0)):
                pii_findings.append({"code": "PII-IBAN", "severity": "high", "detail": f"Обнаружен IBAN ({m.group(0)[:6]}…)"})
                redacted = redacted.replace(m.group(0), "[REDACTED:IBAN]")
        for m in _CARD_RE.finditer(raw):
            digits = re.sub(r"[ -]", "", m.group(0))
            if _luhn_valid(digits):
                pii_findings.append({"code": "PII-PAYMENT-CARD", "severity": "critical", "detail": "Обнаружен номер банковской карты (Luhn valid)."})
                redacted = redacted.replace(m.group(0), "[REDACTED:CARD]")
        if _HIPAA_CONTEXT_RE.search(raw) and _EMAIL_RE.search(raw):
            pii_findings.append({"code": "PII-HIPAA-PHI", "severity": "high", "detail": "Медицинский контекст (HIPAA PHI) с персональной почтой."})
            redacted = _EMAIL_RE.sub("[REDACTED:PHI_EMAIL]", redacted)

    if check_sast:
        for rule_id, sev, rx, msg in _SAST_RULES:
            if rx.search(raw):
                sast_findings.append({"code": rule_id, "severity": sev, "detail": msg})

    exfil = inspect_exfil_channels(redacted)
    exfil_findings = list(exfil.get("findings") or [])
    if exfil.get("has_findings"):
        redacted = str(exfil.get("sanitized_text") or redacted)

    critical_sast = any(f["severity"] == "critical" for f in sast_findings)
    critical_pii = any(f["severity"] == "critical" for f in pii_findings)
    critical_exfil = bool(exfil.get("blocked"))
    blocked = bool(canary_hits) or critical_sast or critical_exfil
    action = "block" if blocked else ("redact" if (sec_hits or pii_findings or sast_findings or exfil_findings) else "allow")

    return {
        "ok": True,
        "action": action,
        "blocked": blocked,
        "sanitized_text": "[BLOCKED BY PADAM OUTPUT GUARDRAIL]" if (canary_hits or critical_sast) else redacted,
        "secrets_masked": len(sec_hits),
        "canary_hits": canary_hits,
        "pii_findings": pii_findings,
        "sast_findings": sast_findings,
        "exfil_findings": exfil_findings,
        "has_critical": blocked or critical_pii,
        "agent_id": agent_id,
    }


# ---------- RAG Poisoning Shield (HTML + PDF + невидимые метаданные) ----------
_HIDDEN_HTML_BLOCK_RE = re.compile(
    r"(?is)<\s*(?:div|span|p|section|article|aside|font|a|li|td)\b[^>]*\bstyle\s*=\s*([\"'])[^\"']*"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b|"
    r"font-size\s*:\s*0(?:px|pt|em|rem)?\b|font-size\s*:\s*1px\b|"
    r"color\s*:\s*(?:#fff(?:fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)|"
    r"position\s*:\s*absolute[^\"']*left\s*:\s*-\d{3,})"
    r"[^\"']*\1[^>]*>.*?</\s*(?:div|span|p|section|article|aside|font|a|li|td)\s*>"
)
_HTML_COMMENT_RE = re.compile(r"(?s)<!--.*?-->")
_HTML_SCRIPT_STYLE_RE = re.compile(r"(?is)<\s*(script|style|noscript|template|iframe|svg)\b[^>]*>.*?</\s*\1\s*>")
_HTML_META_RE = re.compile(r"(?is)<\s*meta\b[^>]*>")
_HTML_TAG_RE = re.compile(r"(?s)<[^>]+>")
_UNICODE_INVIS_RE = re.compile(r"[\U000E0000-\U000E007F\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]")


def _sanitize_html_for_rag(raw_html: str) -> dict[str, Any]:
    removed: list[dict[str, str]] = []
    txt = str(raw_html or "")

    for m in _HIDDEN_HTML_BLOCK_RE.finditer(txt):
        removed.append({"kind": "hidden_css_element", "snippet": m.group(0)[:120]})
    txt = _HIDDEN_HTML_BLOCK_RE.sub(" ", txt)

    for m in _HTML_COMMENT_RE.finditer(txt):
        body = m.group(0)
        if safety.looks_like_instruction(body) or classify_semantic_threat(body, threshold=0.72).get("is_threat"):
            removed.append({"kind": "poisoned_html_comment", "snippet": body[:120]})
    txt = _HTML_COMMENT_RE.sub(" ", txt)

    for m in _HTML_META_RE.finditer(txt):
        tag = m.group(0)
        if safety.looks_like_instruction(tag) or classify_semantic_threat(tag, threshold=0.75).get("is_threat"):
            removed.append({"kind": "poisoned_meta_tag", "snippet": tag[:120]})
    txt = _HTML_SCRIPT_STYLE_RE.sub(" ", txt)
    txt = _HTML_META_RE.sub(" ", txt)
    txt = _HTML_TAG_RE.sub(" ", txt)
    txt = _html.unescape(txt)

    invis_count = len(_UNICODE_INVIS_RE.findall(txt))
    if invis_count:
        removed.append({"kind": "invisible_unicode_chars", "snippet": f"count={invis_count}"})
        txt = _UNICODE_INVIS_RE.sub("", txt)

    clean = " ".join(txt.split())
    return {
        "ok": True,
        "format": "html",
        "clean_text": clean,
        "poison_removed": len(removed) > 0,
        "removed_items": removed,
    }


def _extract_pdf_text_literals(chunk: str) -> list[str]:
    """Извлекает строковые литералы `(...)` из блока PDF-операторов."""
    return [m.group(1) for m in re.finditer(r"\(([^()\\]*(?:\\.[^()\\]*)*)\)", chunk)]


def _sanitize_pdf_bytes_for_rag(raw_bytes: bytes) -> dict[str, Any]:
    """Очищает сырой PDF от скрытых слоёв (белый текст `1 1 1 rg`, `Tf <= 1`, `3 Tr` и метаданные)."""
    removed: list[dict[str, str]] = []
    visible_chunks: list[str] = []

    # 1. Проверка словаря метаданных PDF (/Author, /Subject, /Keywords, /Title)
    head_text = raw_bytes.decode("latin-1", "replace")
    for meta_key in ("Subject", "Keywords", "Author", "Creator", "Producer"):
        for m in re.finditer(rf"/{meta_key}\s*\(([^)]{{8,500}})\)", head_text):
            val = m.group(1)
            if safety.looks_like_instruction(val) or classify_semantic_threat(val, threshold=0.72).get("is_threat"):
                removed.append({"kind": f"poisoned_pdf_metadata_{meta_key}", "snippet": val[:120]})

    # 2. Извлечение и анализ content streams (включая сжатые FlateDecode)
    streams: list[str] = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw_bytes, re.S):
        body = m.group(1)
        try:
            dec = zlib.decompress(body).decode("latin-1", "replace")
        except Exception:
            dec = body.decode("latin-1", "replace")
        streams.append(dec)
    if not streams:
        streams = [head_text]

    _PDF_OP_TOKEN_RE = re.compile(
        r"(?P<white>(?:1(?:\.0+)?\s+1(?:\.0+)?\s+1(?:\.0+)?\s+r[gG]|1(?:\.0+)?\s+[gG]))\b|"
        r"(?P<black>(?:0(?:\.\d+)?\s+0(?:\.\d+)?\s+0(?:\.\d+)?\s+r[gG]|0(?:\.\d+)?\s+[gG]))\b|"
        r"(?P<tr_invis>\b3\s+Tr)\b|"
        r"(?P<tr_vis>\b[012]\s+Tr)\b|"
        r"(?P<tf>/[A-Za-z0-9_]+\s+(?P<fsize>[0-9]+(?:\.[0-9]+)?)\s+Tf)\b|"
        r"\((?P<lit>[^()\\]*(?:\\.[^()\\]*)*)\)"
    )

    for st in streams:
        hidden_state = False
        font_size = 12.0
        for m in _PDF_OP_TOKEN_RE.finditer(st):
            if m.group("white"):
                hidden_state = True
            elif m.group("black"):
                hidden_state = False
            elif m.group("tr_invis"):
                hidden_state = True
            elif m.group("tr_vis"):
                hidden_state = False
            elif m.group("tf"):
                font_size = float(m.group("fsize"))
            elif m.group("lit") is not None:
                lit = m.group("lit")
                if hidden_state or font_size <= 1.0:
                    removed.append({
                        "kind": "hidden_pdf_text" if hidden_state else "micro_font_pdf_text",
                        "snippet": lit[:120],
                    })
                else:
                    if _UNICODE_INVIS_RE.search(lit):
                        removed.append({"kind": "invisible_unicode_pdf", "snippet": lit[:80]})
                        lit = _UNICODE_INVIS_RE.sub("", lit)
                    visible_chunks.append(lit)

    clean = " ".join(" ".join(visible_chunks).split())
    return {
        "ok": True,
        "format": "pdf",
        "clean_text": clean,
        "poison_removed": len(removed) > 0,
        "removed_items": removed,
    }


def sanitize_rag_document(content: str | bytes, *, doc_format: str = "auto") -> dict[str, Any]:
    """Единая точка санитизации документов (PDF/HTML/Text) перед индексацией в RAG/векторную БД."""
    fmt = str(doc_format or "auto").strip().lower()
    if isinstance(content, bytes):
        if fmt == "pdf" or content.lstrip().startswith(b"%PDF"):
            return _sanitize_pdf_bytes_for_rag(content)
        txt = content.decode("utf-8", "replace")
    else:
        txt = str(content or "")
        if fmt == "pdf" or txt.lstrip().startswith("%PDF"):
            return _sanitize_pdf_bytes_for_rag(txt.encode("latin-1", "replace"))

    if fmt == "html" or (fmt == "auto" and re.search(r"<\s*(?:html|body|div|span|p|script|style|meta)\b", txt, re.I)):
        return _sanitize_html_for_rag(txt)

    # Обычный текст: снимаем скрытые Unicode-теги и Bidi
    removed: list[dict[str, str]] = []
    invis = _UNICODE_INVIS_RE.findall(txt)
    if invis:
        removed.append({"kind": "invisible_unicode_chars", "snippet": f"count={len(invis)}"})
        txt = _UNICODE_INVIS_RE.sub("", txt)
    return {
        "ok": True,
        "format": "text",
        "clean_text": " ".join(txt.split()),
        "poison_removed": len(removed) > 0,
        "removed_items": removed,
    }
