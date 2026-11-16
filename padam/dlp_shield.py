"""Превентивный Семантический Фаервол (DLP & Zero-Leak Shield).

Перехватывает секреты (API-ключи, пароли, приватные ключи, JWT, токены,
опционально PII) ДО отправки в облачную модель или MCP-клиент, заменяет их
на связные псевдонимы [PADAM_SECRET_ID_1], [PADAM_SECRET_ID_2], ... и хранит
обратное соответствие исключительно локально в зашифрованной AES-256-GCM таблице dlp_vault.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler
from ._httpserver import ThreadingHTTPServer  # без DNS при запуске (macOS)
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import config, integrity, safety
from .memory import Memory
from .store import now_iso

_REDACT_TAG_RE = re.compile(r"(\[REDACTED:([A-Za-z0-9_]+)\])")
_ALIAS_RE = re.compile(r"\[PADAM_SECRET_ID_(\d+)\]")
ALIAS_TEMPLATE = "[PADAM_SECRET_ID_{}]"


def _derive_dlp_keys(mem: Memory) -> tuple[bytes, bytes]:
    """Возвращает пару 32-байтных ключей (enc_key, hmac_key), локальных для базы."""
    cached = getattr(mem, "_dlp_keys", None)
    if cached is not None:
        return cached
    raw_master = os.environ.get("PADAM_DLP_KEY", "").strip()
    if raw_master:
        ikm = hashlib.sha256(raw_master.encode("utf-8")).digest()
    else:
        # Используем существующий локальный ключ владельца из каталога БД (0600 на POSIX)
        ikm, _ = integrity.owner_key(mem.store)
    enc_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"padam-dlp-enc-v1").derive(ikm)
    mac_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"padam-dlp-hmac-v1").derive(ikm)
    mem._dlp_keys = (enc_key, mac_key)
    return enc_key, mac_key


def _extract_redacted_spans(text: str) -> tuple[list[tuple[int, int, str, str]], dict[str, int]]:
    """Использует все детекторы safety.redact без дублирования, восстанавливая точные спаны секретов."""
    if not text:
        return [], {}
    old_keep = config.KEEP_SECRETS
    if old_keep:
        config.KEEP_SECRETS = False
    try:
        redacted, counts = safety.redact(text)
    finally:
        if old_keep:
            config.KEEP_SECRETS = True
    if not counts or "[REDACTED:" not in redacted:
        return [], counts

    parts = _REDACT_TAG_RE.split(redacted)
    # _REDACT_TAG_RE имеет 2 группы: (полный тег, kind), поэтому split выдаёт [lit, tag, kind, lit, ...]
    spans: list[tuple[int, int, str, str]] = []
    pos = 0
    idx = 0
    n_parts = len(parts)
    while idx < n_parts:
        lit = parts[idx]
        if idx == n_parts - 1:
            break
        if lit:
            found_lit = text.find(lit, pos)
            if found_lit == -1:
                # Запасной безопасный сдвиг: не теряем выравнивание
                break
            pos = found_lit + len(lit)
        # Следующие элементы: full_tag = parts[idx + 1], kind = parts[idx + 2], next_lit = parts[idx + 3]
        kind = parts[idx + 2]
        next_idx = idx + 3
        # Ищем следующий непустой литерал, чтобы определить правую границу секрета(ов)
        end_pos = len(text)
        look = next_idx
        while look < n_parts:
            if parts[look]:
                nxt = text.find(parts[look], pos)
                if nxt != -1:
                    end_pos = nxt
                break
            look += 3
        if end_pos > pos:
            spans.append((pos, end_pos, kind, text[pos:end_pos]))
            pos = end_pos
        idx = next_idx
    return spans, counts


class DlpShield:
    """Локальный DLP-фаервол с зашифрованным хранилищем псевдонимов [PADAM_SECRET_ID_N]."""

    def __init__(self, mem: Memory):
        self.mem = mem
        self._enc_key, self._mac_key = _derive_dlp_keys(mem)

    def _alias_for(self, secret_val: str, kind: str) -> str:
        secret_hash = hmac.new(self._mac_key, secret_val.encode("utf-8"), hashlib.sha256).hexdigest()
        with self.mem.store._lock:
            existing = self.mem.store.one(
                "SELECT alias FROM dlp_vault WHERE user_id = ? AND secret_hash = ?",
                (self.mem.user_id, secret_hash),
            )
            if existing is not None:
                alias = str(existing["alias"])
                self.mem.store.conn.execute(
                    "UPDATE dlp_vault SET hit_count = hit_count + 1 WHERE user_id = ? AND alias = ?",
                    (self.mem.user_id, alias),
                )
                self.mem.store.conn.commit()
                return alias

            rows = self.mem.store.conn.execute(
                "SELECT alias FROM dlp_vault WHERE user_id = ?",
                (self.mem.user_id,),
            ).fetchall()
            max_num = 0
            for r in rows:
                m = _ALIAS_RE.fullmatch(str(r["alias"]))
                if m:
                    max_num = max(max_num, int(m.group(1)))
            alias = ALIAS_TEMPLATE.format(max_num + 1)
            nonce = secrets.token_bytes(12)
            sealed = nonce + AESGCM(self._enc_key).encrypt(
                nonce, secret_val.encode("utf-8"), f"{self.mem.user_id}|{alias}".encode("utf-8")
            )
            self.mem.store.conn.execute(
                """INSERT INTO dlp_vault (user_id, alias, kind, secret_hash, sealed_hex, created_at, hit_count)
                   VALUES (?,?,?,?,?,?,1)""",
                (self.mem.user_id, alias, kind, secret_hash, sealed.hex(), now_iso()),
            )
            self.mem.store.conn.commit()
            return alias

    def sanitize_text(
        self,
        text: str,
        *,
        scope: str | None = None,
        record_audit: bool = True,
    ) -> tuple[str, dict]:
        """Заменяет найденные секреты в строке на [PADAM_SECRET_ID_N] и шифрует оригиналы в dlp_vault."""
        if not text:
            return text, {"intercepted": 0, "aliases": [], "kinds": []}
        spans, _ = _extract_redacted_spans(text)
        if not spans:
            return text, {"intercepted": 0, "aliases": [], "kinds": []}

        out_parts: list[str] = []
        aliases: list[str] = []
        kinds: list[str] = []
        cursor = 0
        for s_start, s_end, kind, raw_val in spans:
            if s_start < cursor:
                continue
            out_parts.append(text[cursor:s_start])
            alias = self._alias_for(raw_val, kind)
            out_parts.append(alias)
            aliases.append(alias)
            kinds.append(kind)
            cursor = s_end
        out_parts.append(text[cursor:])
        sanitized = "".join(out_parts)

        if record_audit and aliases:
            self.mem._log_audit(
                "dlp_redact",
                None,
                actor="owner",
                agent_id="padam-dlp-shield",
                scope=scope or "global",
                outcome="sanitized",
                detail=f"intercepted={len(aliases)} kinds={','.join(sorted(set(kinds)))}",
            )
        return sanitized, {
            "intercepted": len(aliases),
            "aliases": list(dict.fromkeys(aliases)),
            "kinds": list(dict.fromkeys(kinds)),
        }

    def sanitize_payload(
        self,
        payload: Any,
        *,
        scope: str | None = None,
        record_audit: bool = True,
    ) -> tuple[Any, dict]:
        """Рекурсивно очищает JSON-полезную нагрузку (OpenAI / Anthropic / MCP) от секретов."""
        all_aliases: list[str] = []
        all_kinds: list[str] = []
        total_intercepted = [0]

        def _walk(node: Any) -> Any:
            if isinstance(node, str):
                clean, info = self.sanitize_text(node, scope=scope, record_audit=False)
                if info["intercepted"] > 0:
                    total_intercepted[0] += info["intercepted"]
                    all_aliases.extend(info["aliases"])
                    all_kinds.extend(info["kinds"])
                return clean
            if isinstance(node, list):
                return [_walk(it) for it in node]
            if isinstance(node, dict):
                return {k: _walk(v) for k, v in node.items()}
            return node

        cleaned = _walk(payload)
        uniq_aliases = list(dict.fromkeys(all_aliases))
        uniq_kinds = list(dict.fromkeys(all_kinds))
        if record_audit and total_intercepted[0] > 0:
            self.mem._log_audit(
                "dlp_redact",
                None,
                actor="owner",
                agent_id="padam-dlp-shield",
                scope=scope or "global",
                outcome="sanitized",
                detail=f"intercepted={total_intercepted[0]} kinds={','.join(uniq_kinds)}",
            )
        return cleaned, {
            "intercepted": total_intercepted[0],
            "aliases": uniq_aliases,
            "kinds": uniq_kinds,
        }

    def detokenize_local(self, text: str, *, owner_authorized: bool = False) -> str:
        """Разворачивает [PADAM_SECRET_ID_N] строго в доверенном локальном контексте владельца."""
        if not owner_authorized:
            raise PermissionError("DLP detokenization is forbidden without local owner authorization")
        if not text or "[PADAM_SECRET_ID_" not in text:
            return text

        def _sub(m: re.Match) -> str:
            alias = m.group(0)
            row = self.mem.store.one(
                "SELECT sealed_hex FROM dlp_vault WHERE user_id = ? AND alias = ?",
                (self.mem.user_id, alias),
            )
            if row is None:
                return alias
            blob = bytes.fromhex(row["sealed_hex"])
            try:
                plain = AESGCM(self._enc_key).decrypt(
                    blob[:12], blob[12:], f"{self.mem.user_id}|{alias}".encode("utf-8")
                )
                return plain.decode("utf-8")
            except InvalidTag:
                return alias

        return _ALIAS_RE.sub(_sub, text)

    def stats(self) -> dict:
        row = self.mem.store.one(
            "SELECT COUNT(*) AS unique_aliases, COALESCE(SUM(hit_count), 0) AS total_interceptions "
            "FROM dlp_vault WHERE user_id = ?",
            (self.mem.user_id,),
        )
        return {
            "unique_aliases": int(row["unique_aliases"] or 0) if row else 0,
            "total_interceptions": int(row["total_interceptions"] or 0) if row else 0,
        }


def make_dlp_proxy_server(
    mem: Memory,
    *,
    upstream_url: str | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    token: str | None = None,
) -> tuple[ThreadingHTTPServer, str, str]:
    """Поднимает локальный Zero-Leak HTTP DLP-прокси-шлюз (строго 127.0.0.1 / localhost).

    Перехватывает JSON-запросы (OpenAI /v1/chat/completions, Anthropic /v1/messages,
    /sanitize), подменяет секреты на [PADAM_SECRET_ID_N] и при наличии upstream_url
    отправляет наружу ТОЛЬКО санитизированный слепок.
    """
    host_clean = (host or "127.0.0.1").strip().lower()
    if host_clean not in ("127.0.0.1", "localhost", "::1") and not host_clean.startswith("127."):
        raise ValueError("DLP proxy server is restricted to 127.0.0.1 / localhost only")

    tok = (token or os.environ.get("PADAM_API_TOKEN") or "").strip()
    if tok and len(tok) < 16:
        raise ValueError("Proxy token must be at least 16 characters")
    if not tok:
        tok = secrets.token_urlsafe(24)

    shield = DlpShield(mem)
    eff_upstream = (upstream_url or config.mcp_dlp_upstream_url()).strip().rstrip("/")
    MAX_BODY = 2 * 1024 * 1024

    class _DlpProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def _send_json(self, code: int, obj: dict) -> None:
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _authorized(self) -> bool:
            auth = self.headers.get("Authorization", "")
            return auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].strip(), tok)

        def do_GET(self):
            if self.path == "/health":
                return self._send_json(200, {"status": "ok", "service": "padam-dlp-proxy", **shield.stats()})
            return self._send_json(404, {"error": "not found"})

        def do_POST(self):
            if not self._authorized():
                return self._send_json(401, {"error": "unauthorized"})
            try:
                ln = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                ln = 0
            if ln <= 0 or ln > MAX_BODY:
                return self._send_json(400, {"error": "invalid or oversized body"})
            try:
                body_obj = json.loads(self.rfile.read(ln).decode("utf-8"))
            except Exception:
                return self._send_json(400, {"error": "invalid json"})

            sanitized_obj, dlp_report = shield.sanitize_payload(body_obj)
            if self.path == "/sanitize" or not eff_upstream:
                return self._send_json(200, {"sanitized": sanitized_obj, "dlp": dlp_report})

            target_url = eff_upstream if eff_upstream.endswith(self.path) else (eff_upstream + self.path)
            out_bytes = json.dumps(sanitized_obj, ensure_ascii=False).encode("utf-8")
            fwd_req = urllib.request.Request(
                target_url,
                data=out_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            want_local_detok = (self.headers.get("X-Padam-Local-Detokenize") or "").strip() == "1"

            def _detok_tree(node: Any) -> Any:
                if isinstance(node, str):
                    return shield.detokenize_local(node, owner_authorized=True)
                if isinstance(node, list):
                    return [_detok_tree(it) for it in node]
                if isinstance(node, dict):
                    return {k: _detok_tree(v) for k, v in node.items()}
                return node

            try:
                with urllib.request.urlopen(fwd_req, timeout=30.0) as resp:
                    up_raw = resp.read()
                    up_status = resp.status
                    up_obj = json.loads(up_raw.decode("utf-8")) if up_raw else {}
                if want_local_detok:
                    up_obj = _detok_tree(up_obj)
                return self._send_json(
                    up_status,
                    {"upstream": up_obj, "dlp": {**dlp_report, "detokenized_locally": want_local_detok}},
                )
            except urllib.error.HTTPError as he:
                return self._send_json(he.code, {"error": str(he), "dlp": dlp_report})
            except Exception as exc:
                return self._send_json(502, {"error": f"upstream error: {exc}", "dlp": dlp_report})

    srv = ThreadingHTTPServer((host, port), _DlpProxyHandler)
    srv.daemon_threads = True
    actual_port = srv.server_address[1]
    return srv, f"http://{host}:{actual_port}", tok
