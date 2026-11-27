# -*- coding: utf-8 -*-
"""Файрвол браузерного / Computer-Use агента (DOM & UI-Redressing Guard).

Защищает браузерных агентов (Playwright, Chrome DevTools, Computer Use) от:
- невидимых DOM-инъекций (`opacity:0`, `display:none`, `visibility:hidden`,
  `font-size:0`, `left:-9999px`, белый текст на белом фоне, атрибут `hidden`),
- скрытых промпт-инъекций в атрибутах доступности (`aria-label`, `title`, `alt`, `data-*`),
- UI-Redressing / Clickjacking (прозрачные `iframe`/overlay с высоким `z-index`),
- Cross-Origin Form Hijack (подмена `action` формы с паролем/картой на чужой домен),
- опасных действий агента (чтение `document.cookie`/`localStorage`, ввод в скрытое поле,
  `javascript:`/`file://` переходы).
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .adversarial_norm import canonicalize_adversarial_text


_INJECTION_HINT_RE = re.compile(
    r"(?is)\b(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?"
    r"|system\s+(?:prompt|override)|you\s+are\s+now|disregard\s+safety|reveal\s+system\s+prompt"
    r"|send\s+(?:all|the|your)?\s*(?:cookies?|tokens?|secrets?|keys?|passwords?|session)"
    r"|exfiltrate|transfer\s+(?:funds|usdt|eth|sol|money)|click\s+approve|confirm\s+payment"
    r"|navigate\s+to\s+https?://|submit\s+credentials"
    r"|игнорируй\s+(?:предыдущие|все)\s+инструкции|отправь\s+(?:куки|парол|токен|ключ)"
    r")"
)

_HIDDEN_STYLE_RE = re.compile(
    r"(?is)(?:"
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*$)"
    r"|font-size\s*:\s*0(?:px|em|rem|%)?(?:\s*;|\s*$)"
    r"|(?:left|top|text-indent)\s*:\s*-\d{3,6}px"
    r"|clip\s*:\s*rect\(\s*0|clip-path\s*:\s*inset\(\s*100%|color\s*:\s*transparent|color\s*:\s*rgba\([^)]*,\s*0(?:\.0+)?\s*\)"
    r"|width\s*:\s*[01]px[^;]*;\s*height\s*:\s*[01]px"
    r")"
)

_SAME_WHITE_RE = re.compile(
    r"(?is)color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))"
    r".*?background(?:-color)?\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))"
)
_SAME_WHITE_REV_RE = re.compile(
    r"(?is)background(?:-color)?\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))"
    r".*?color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))"
)

_OVERLAY_STYLE_RE = re.compile(
    r"(?is)(?:position\s*:\s*(?:fixed|absolute)).*(?:opacity\s*:\s*0(?:\.0\d?)?)|"
    r"(?:opacity\s*:\s*0(?:\.0\d?)?).*(?:position\s*:\s*(?:fixed|absolute))"
)
_HIGH_ZINDEX_RE = re.compile(r"(?i)z-index\s*:\s*(\d{3,})")

_DANGEROUS_JS_RE = re.compile(
    r"(?is)(?:document\.cookie|localStorage|sessionStorage|indexedDB|window\.ethereum|"
    r"navigator\.credentials|fetch\s*\(\s*['\"]https?://|XMLHttpRequest|eval\s*\(|Function\s*\()"
)


_VOID_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)


class _DomShieldParser(HTMLParser):
    def __init__(self, page_host: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_host = page_host.lower()
        self._hidden_stack: List[Tuple[str, bool]] = []
        self.hidden_depth = 0
        self.skip_text_depth = 0
        self.current_form_action: Optional[str] = None
        self.current_form_has_sensitive = False
        self.findings: List[Dict[str, Any]] = []
        self.visible_chunks: List[str] = []
        self.hidden_chunks: List[str] = []

    def _is_hidden_tag(self, attrs_dict: Dict[str, str]) -> bool:
        if "hidden" in attrs_dict:
            return True
        if attrs_dict.get("aria-hidden", "").strip().lower() == "true":
            return True
        style = attrs_dict.get("style", "")
        if style and (_HIDDEN_STYLE_RE.search(style) or _SAME_WHITE_RE.search(style) or _SAME_WHITE_REV_RE.search(style)):
            return True
        return False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        t = tag.lower()
        ad = {k.lower(): (v or "") for k, v in attrs}

        if t in ("script", "style", "noscript"):
            self.skip_text_depth += 1

        is_hid = (t == "template") or self._is_hidden_tag(ad)
        if t not in _VOID_TAGS:
            self._hidden_stack.append((t, is_hid))
            if is_hid:
                self.hidden_depth += 1

        # Проверка опасных inline XSS-обработчиков событий (<svg onload=...>, <img onerror=...>)
        for attr_k, attr_v in ad.items():
            if attr_k in ("onload", "onerror", "onfocus", "onmouseover", "onanimationstart", "onpageshow") and attr_v.strip():
                self.findings.append(
                    {
                        "rule_id": "DOM-INLINE-XSS-EVENT",
                        "severity": "CRITICAL",
                        "detail": f"Обнаружен опасный inline-обработчик {attr_k} в теге <{t}>: {attr_v[:80]}",
                    }
                )

        # Проверка UI-Redressing / Clickjacking overlay
        style = ad.get("style", "")
        if t in ("iframe", "div", "a", "button") and style and _OVERLAY_STYLE_RE.search(style):
            zm = _HIGH_ZINDEX_RE.search(style)
            if t == "iframe" or (zm and int(zm.group(1)) >= 100):
                self.findings.append(
                    {
                        "rule_id": "DOM-CLICKJACKING-OVERLAY",
                        "severity": "CRITICAL",
                        "detail": f"Обнаружен прозрачный перехватывающий слой <{t}> поверх интерфейса (UI-Redressing)",
                    }
                )

        # Проверка атрибутов доступности и data-* на скрытые промпт-инъекции
        for attr_name, attr_val in ad.items():
            if not attr_val:
                continue
            if attr_name in ("aria-label", "alt", "title", "placeholder") or attr_name.startswith("data-"):
                norm = canonicalize_adversarial_text(attr_val)["canonical"]
                if _INJECTION_HINT_RE.search(attr_val) or _INJECTION_HINT_RE.search(norm):
                    self.findings.append(
                        {
                            "rule_id": "DOM-ARIA-INJECTION",
                            "severity": "CRITICAL",
                            "detail": f"Промпт-инъекция в атрибуте {attr_name} тега <{t}>: {attr_val[:120]}",
                        }
                    )

        # Проверка форм на перехват учётных данных на сторонний домен
        if t == "form":
            self.current_form_action = ad.get("action", "").strip()
            self.current_form_has_sensitive = False
        elif t == "input" and self.current_form_action is not None:
            itype = ad.get("type", "").lower()
            iname = (ad.get("name", "") + " " + ad.get("id", "") + " " + ad.get("autocomplete", "")).lower()
            if itype == "password" or any(k in iname for k in ("pass", "card", "cvv", "cc-number", "seed", "secret")):
                self.current_form_has_sensitive = True

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in ("script", "style", "noscript") and self.skip_text_depth > 0:
            self.skip_text_depth -= 1
        # Корректный откат стека скрытости до ближайшего открытого тега `t`
        for idx in range(len(self._hidden_stack) - 1, -1, -1):
            if self._hidden_stack[idx][0] == t:
                popped = self._hidden_stack[idx:]
                del self._hidden_stack[idx:]
                for _, was_hid in popped:
                    if was_hid and self.hidden_depth > 0:
                        self.hidden_depth -= 1
                break
        if t == "form" and self.current_form_action is not None:
            act = self.current_form_action
            if self.current_form_has_sensitive and act.lower().startswith(("http://", "https://")):
                act_host = (urlparse(act).hostname or "").lower()
                if self.page_host and act_host and act_host != self.page_host and not act_host.endswith("." + self.page_host):
                    self.findings.append(
                        {
                            "rule_id": "DOM-FORM-HIJACK",
                            "severity": "CRITICAL",
                            "detail": f"Форма с паролем/картой отправляет данные на чужой домен: {act_host} (страница: {self.page_host})",
                        }
                    )
            self.current_form_action = None
            self.current_form_has_sensitive = False

    def handle_data(self, data: str) -> None:
        if self.skip_text_depth > 0:
            return
        txt = data.strip()
        if not txt:
            return
        if self.hidden_depth > 0:
            self.hidden_chunks.append(txt)
            norm = canonicalize_adversarial_text(txt)["canonical"]
            if _INJECTION_HINT_RE.search(txt) or _INJECTION_HINT_RE.search(norm):
                self.findings.append(
                    {
                        "rule_id": "DOM-HIDDEN-INJECTION",
                        "severity": "CRITICAL",
                        "detail": f"Промпт-инъекция в невидимом DOM-элементе: {txt[:140]}",
                    }
                )
        else:
            self.visible_chunks.append(txt)

    def handle_comment(self, data: str) -> None:
        txt = str(data or "").strip()
        if not txt:
            return
        self.hidden_chunks.append(txt)
        norm = canonicalize_adversarial_text(txt)["canonical"]
        if _INJECTION_HINT_RE.search(txt) or _INJECTION_HINT_RE.search(norm):
            self.findings.append(
                {
                    "rule_id": "DOM-COMMENT-INJECTION",
                    "severity": "CRITICAL",
                    "detail": f"Промпт-инъекция внутри скрытого HTML-комментария: {txt[:140]}",
                }
            )


def inspect_dom_html(html: str, *, page_url: str = "") -> Dict[str, Any]:
    """Инспектирует HTML-страницу для браузерного агента и возвращает безопасный видимый текст."""
    page_host = (urlparse(page_url).hostname or "").lower() if page_url else ""
    parser = _DomShieldParser(page_host=page_host)
    parser.feed(str(html or ""))
    parser.close()

    # Дедупликация находок по (rule_id, detail)
    dedup: List[Dict[str, Any]] = []
    seen = set()
    for f in parser.findings:
        k = (f["rule_id"], f["detail"])
        if k not in seen:
            seen.add(k)
            dedup.append(f)

    blocked = any(f["severity"] in ("CRITICAL", "HIGH") for f in dedup)
    return {
        "ok": not blocked,
        "blocked": blocked,
        "page_url": page_url,
        "findings": dedup,
        "hidden_text_count": len(parser.hidden_chunks),
        "sanitized_text": " ".join(parser.visible_chunks),
    }


def inspect_browser_action(
    *,
    action: str,
    target_url: str = "",
    selector: str = "",
    js_code: str = "",
    element_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Проверяет конкретное действие браузерного агента (click/type/eval/navigate)."""
    act = str(action or "").strip().lower()
    findings: List[Dict[str, Any]] = []
    meta = element_meta or {}

    if target_url:
        low_u = target_url.strip().lower()
        if low_u.startswith(("javascript:", "data:text/html", "vbscript:", "file://")):
            findings.append(
                {
                    "rule_id": "BROWSER-UNSAFE-SCHEME",
                    "severity": "CRITICAL",
                    "detail": f"Запрещённая схема перехода браузерного агента: {low_u[:40]}",
                }
            )

    if act in ("eval", "evaluate", "execute_js", "script") and js_code:
        if _DANGEROUS_JS_RE.search(js_code):
            findings.append(
                {
                    "rule_id": "BROWSER-SENSITIVE-JS",
                    "severity": "CRITICAL",
                    "detail": "Попытка чтения cookie/localStorage/кошелька или сетевого вызова через eval JS",
                }
            )

    if act in ("click", "submit", "press"):
        if meta.get("visible") is False or float(meta.get("opacity", 1.0)) <= 0.05 or meta.get("occluded") is True:
            findings.append(
                {
                    "rule_id": "BROWSER-HIDDEN-ELEMENT-CLICK",
                    "severity": "CRITICAL",
                    "detail": "Блокировка клика по невидимому или перекрытому элементу (защита от Clickjacking)",
                }
            )

    if act in ("type", "fill", "read_value"):
        sel_l = selector.lower()
        el_type = str(meta.get("type", "")).lower()
        if el_type == "password" or "password" in sel_l or "input[type=password]" in sel_l:
            findings.append(
                {
                    "rule_id": "BROWSER-PASSWORD-FIELD",
                    "severity": "HIGH",
                    "detail": "Доступ агента к полю пароля требует явного ручного подтверждения владельца",
                }
            )

    blocked = len(findings) > 0
    return {
        "ok": not blocked,
        "allowed": not blocked,
        "blocked": blocked,
        "action": act,
        "findings": findings,
    }
