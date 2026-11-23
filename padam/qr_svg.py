# -*- coding: utf-8 -*-
"""Генератор SVG QR-кодов (0 внешних зависимостей) и защищённая LAN-синхронизация ПК <-> Android.

Позволяет навести камеру телефона Android на экран PADAM Studio на ПК и за 2 секунды
синхронизировать дельту памяти напрямую по локальному Wi-Fi с шифрованием AES-256-GCM ($0, без облака).
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import threading
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Таблицы Рида-Соломона GF(256) для стандартного QR-кода (ISO/IEC 18004, уровень L) ---

_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]

# (version, total_data_bytes, ec_bytes_per_block, blocks, alignment_coords) — уровень L
_QR_VERSIONS = [
    (1, 19, 7, 1, []),
    (2, 34, 10, 1, [6, 18]),
    (3, 55, 15, 1, [6, 22]),
    (4, 80, 20, 1, [6, 26]),
    (5, 108, 26, 1, [6, 30]),
    (6, 136, 18, 2, [6, 34]),
    (7, 156, 20, 2, [6, 22, 38]),
    (8, 194, 24, 2, [6, 24, 42]),
    (9, 232, 30, 2, [6, 26, 46]),
    (10, 274, 18, 4, [6, 28, 50]),
]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_gen_poly(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        next_p = [0] * (len(poly) + 1)
        root = _GF_EXP[i]
        for j, coeff in enumerate(poly):
            next_p[j] ^= coeff
            next_p[j + 1] ^= _gf_mul(coeff, root)
        poly = next_p
    return poly


def _rs_encode(data: bytes, ec_len: int) -> bytes:
    gen = _rs_gen_poly(ec_len)
    rem = list(data) + [0] * ec_len
    for i in range(len(data)):
        factor = rem[i]
        if factor != 0:
            for j in range(1, len(gen)):
                rem[i + j] ^= _gf_mul(gen[j], factor)
    return bytes(rem[len(data):])


def _format_bits(mask: int) -> int:
    # Уровень L = 01
    data = (0b01 << 3) | (mask & 0b111)
    rem = data << 10
    for i in range(14, 9, -1):
        if (rem >> i) & 1:
            rem ^= 0x537 << (i - 10)
    return ((data << 10) | rem) ^ 0x5412


def _version_bits(ver: int) -> int:
    rem = ver << 12
    for i in range(17, 11, -1):
        if (rem >> i) & 1:
            rem ^= 0x1F25 << (i - 12)
    return (ver << 12) | rem


def make_qr_matrix(text: str) -> list[list[bool]]:
    """Строит стандартную матрицу QR-кода (byte mode, ECC L, версии 1..10)."""
    payload = text.encode("utf-8")
    chosen = None
    for spec in _QR_VERSIONS:
        ver, cap, ec_len, blocks, align = spec
        cnt_bits = 8 if ver <= 9 else 16
        needed_bytes = (4 + cnt_bits + len(payload) * 8 + 7) // 8
        if needed_bytes <= cap:
            chosen = spec
            break
    if chosen is None:
        raise ValueError(f"QR payload too long ({len(payload)} bytes; max 270)")

    ver, cap, ec_len, blocks, align = chosen
    size = 17 + 4 * ver

    # Битовый поток данных (Mode 0100 = Byte)
    bits: list[int] = []
    def _push(val: int, nbits: int):
        for b in range(nbits - 1, -1, -1):
            bits.append((val >> b) & 1)

    _push(0b0100, 4)
    _push(len(payload), 8 if ver <= 9 else 16)
    for byte in payload:
        _push(byte, 8)
    max_bits = cap * 8
    term = min(4, max_bits - len(bits))
    _push(0, term)
    while len(bits) % 8 != 0:
        bits.append(0)
    data_bytes = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for j in range(8):
            v = (v << 1) | bits[i + j]
        data_bytes.append(v)
    pad_seq = (0xEC, 0x11)
    pi = 0
    while len(data_bytes) < cap:
        data_bytes.append(pad_seq[pi & 1])
        pi += 1

    # Разбиение на блоки + Reed-Solomon + интерливинг
    base_len = cap // blocks
    extra = cap % blocks
    data_blocks: list[bytes] = []
    ec_blocks: list[bytes] = []
    pos = 0
    for b_idx in range(blocks):
        blen = base_len + (1 if b_idx >= blocks - extra else 0)
        blk = bytes(data_bytes[pos : pos + blen])
        pos += blen
        data_blocks.append(blk)
        ec_blocks.append(_rs_encode(blk, ec_len))

    stream: list[int] = []
    max_blen = max(len(b) for b in data_blocks)
    for i in range(max_blen):
        for blk in data_blocks:
            if i < len(blk):
                stream.append(blk[i])
    for i in range(ec_len):
        for ec in ec_blocks:
            stream.append(ec[i])

    # Разметка матрицы
    mat = [[False] * size for _ in range(size)]
    reserved = [[False] * size for _ in range(size)]

    def _set_func(r: int, c: int, val: bool):
        if 0 <= r < size and 0 <= c < size:
            mat[r][c] = val
            reserved[r][c] = True

    def _finder(r0: int, c0: int):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = r0 + dr, c0 + dc
                if 0 <= r < size and 0 <= c < size:
                    in_outer = 0 <= dr <= 6 and 0 <= dc <= 6
                    on_border = dr in (0, 6) or dc in (0, 6)
                    in_core = 2 <= dr <= 4 and 2 <= dc <= 4
                    _set_func(r, c, in_outer and (on_border or in_core))

    _finder(0, 0)
    _finder(0, size - 7)
    _finder(size - 7, 0)

    for i in range(8, size - 8):
        _set_func(6, i, (i % 2) == 0)
        _set_func(i, 6, (i % 2) == 0)

    for r_c in align:
        for c_c in align:
            if reserved[r_c][c_c]:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    val = max(abs(dr), abs(dc)) != 1
                    _set_func(r_c + dr, c_c + dc, val)

    # Dark module & format/version reservations
    _set_func(size - 8, 8, True)
    for i in range(9):
        if not reserved[8][i]:
            reserved[8][i] = True
        if not reserved[i][8]:
            reserved[i][8] = True
    for i in range(8):
        reserved[8][size - 1 - i] = True
        reserved[size - 1 - i][8] = True

    if ver >= 7:
        vb = _version_bits(ver)
        for i in range(18):
            bit = bool((vb >> i) & 1)
            r = i // 3
            c = size - 11 + (i % 3)
            _set_func(r, c, bit)
            _set_func(c, r, bit)

    # Размещение битов данных с маской 0 ((r + c) % 2 == 0)
    mask_id = 0
    bit_stream = []
    for byte in stream:
        for b in range(7, -1, -1):
            bit_stream.append(bool((byte >> b) & 1))

    idx = 0
    col = size - 1
    up = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if up else range(size)
        for r in rows:
            for dc in (0, -1):
                c = col + dc
                if not reserved[r][c]:
                    bit = bit_stream[idx] if idx < len(bit_stream) else False
                    idx += 1
                    if ((r + c) % 2) == 0:
                        bit = not bit
                    mat[r][c] = bit
        up = not up
        col -= 2

    # Запись format information (mask 0, ECC L)
    fb = _format_bits(mask_id)
    for i in range(6):
        mat[8][i] = bool((fb >> (14 - i)) & 1)
    mat[8][7] = bool((fb >> 8) & 1)
    mat[8][8] = bool((fb >> 7) & 1)
    mat[7][8] = bool((fb >> 6) & 1)
    for i in range(9, 15):
        mat[14 - i][8] = bool((fb >> (14 - i)) & 1)
    for i in range(8):
        mat[size - 1 - i][8] = bool((fb >> i) & 1)
    for i in range(8):
        mat[8][size - 8 + i] = bool((fb >> (7 - i)) & 1)

    return mat


def make_qr_svg(text: str, *, scale: int = 6, border: int = 3) -> str:
    """Генерирует чистый автономный SVG-код QR (CSP-безопасный, без внешних зависимостей)."""
    mat = make_qr_matrix(text)
    n = len(mat)
    dim = (n + border * 2) * scale
    rects: list[str] = []
    for r, row in enumerate(mat):
        for c, val in enumerate(row):
            if val:
                x = (c + border) * scale
                y = (r + border) * scale
                rects.append(f'<rect x="{x}" y="{y}" width="{scale}" height="{scale}"/>')
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" '
        f'width="{dim}" height="{dim}" role="img" aria-label="PADAM LAN Pairing QR">'
        f'<rect width="100%" height="100%" fill="#ffffff"/>'
        f'<g fill="#0f172a">{"".join(rects)}</g></svg>'
    )


# --- Защищённые одноразовые пары LAN Pairing (ПК <-> Android, AES-256-GCM) ---

_PAIR_LOCK = threading.Lock()
_ACTIVE_OFFERS: dict[str, dict[str, Any]] = {}
_CONSUMED_NONCES: dict[str, set[str]] = {}


def _is_virtual_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if a == 127 or (a == 169 and b == 254):
        return True
    # Docker/WSL/Hyper-V обычно живут в 172.16.0.0/12; домашний Wi-Fi почти всегда 192.168.x.x
    if a == 172 and 16 <= b <= 31:
        return True
    return False


def list_lan_ips() -> list[str]:
    """Возвращает упорядоченный список локальных IPv4-адресов с приоритетом физических Wi-Fi/LAN."""
    found: list[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                found.append(ip)
        finally:
            s.close()
    except Exception:
        pass
    # 23.11.2026: на macOS getaddrinfo(gethostname()) ждёт системную службу имён десятки секунд, и предложение
    # сопряжения зависало (тест test_live_api_endpoints_and_studio_4_langs падал по тайм-ауту на всех macOS в CI).
    # Нашли реальный адрес первым способом — второй не нужен; иначе спрашиваем имя не дольше 1,5 с в отдельном потоке.
    if not found or all(_is_virtual_ip(ip) for ip in found):
        import threading as _th
        ответ: list[str] = []

        def _по_имени() -> None:
            try:
                for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                    ответ.append(str(info[4][0]))
            except Exception:
                pass

        поток = _th.Thread(target=_по_имени, daemon=True)
        поток.start()
        поток.join(1.5)
        for cand in list(ответ):
            if cand and not cand.startswith("127.") and cand not in found:
                found.append(cand)
    real = [ip for ip in found if not _is_virtual_ip(ip)]
    phys_192 = [ip for ip in real if ip.startswith("192.168.")]
    other_real = [ip for ip in real if not ip.startswith("192.168.")]
    virt = [ip for ip in found if ip not in real]
    ordered = phys_192 + other_real + virt
    return ordered or ["127.0.0.1"]


def detect_lan_ip() -> str:
    """Выбирает наиболее подходящий физический Wi-Fi/LAN IP для Android QR-сопряжения."""
    return list_lan_ips()[0]


def create_lan_pair_offer(
    *,
    port: int,
    host_ip: str | None = None,
    ttl_s: int = 300,
) -> dict[str, Any]:
    """Создаёт одноразовый код сопряжения ПК <-> Android с 256-битным ключом AES-GCM и SVG QR."""
    pair_id = secrets.token_hex(16)
    key_bytes = secrets.token_bytes(32)
    key_hex = key_bytes.hex()
    ip = str(host_ip or detect_lan_ip())
    exp = time.time() + max(30, min(int(ttl_s), 1800))
    offer = {
        "pair_id": pair_id,
        "key_hex": key_hex,
        "host": ip,
        "port": int(port),
        "expires_at": exp,
        "created_at": time.time(),
    }
    with _PAIR_LOCK:
        # Чистим просроченные
        now = time.time()
        for k in list(_ACTIVE_OFFERS.keys()):
            if _ACTIVE_OFFERS[k]["expires_at"] < now:
                _ACTIVE_OFFERS.pop(k, None)
                _CONSUMED_NONCES.pop(k, None)
        _ACTIVE_OFFERS[pair_id] = offer

    uri = f"padam-sync://v1?h={ip}&p={int(port)}&id={pair_id}&k={key_hex}"
    return {
        "ok": True,
        "pair_id": pair_id,
        "host": ip,
        "port": int(port),
        "expires_at": exp,
        "uri": uri,
        "qr_svg": make_qr_svg(uri, scale=5, border=3),
    }


def get_active_offer(pair_id: str) -> dict[str, Any] | None:
    with _PAIR_LOCK:
        offer = _ACTIVE_OFFERS.get(str(pair_id or "").strip())
        if not offer:
            return None
        if offer["expires_at"] < time.time():
            _ACTIVE_OFFERS.pop(pair_id, None)
            return None
        return dict(offer)


def encrypt_sync_delta(records: list[dict[str, Any]], key_hex: str) -> dict[str, str]:
    """Шифрует дельту записей памяти ключом пары (AES-256-GCM + случайный 96-битный nonce)."""
    key = bytes.fromhex(key_hex)
    nonce = os.urandom(12)
    plain = json.dumps({"v": 1, "records": records}, ensure_ascii=False).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plain, b"padam-lan-sync-v1")
    return {
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
    }


def decrypt_sync_delta(nonce_b64: str, ciphertext_b64: str, key_hex: str) -> list[dict[str, Any]]:
    """Расшифровывает дельту записей памяти с проверкой аутентичности GCM."""
    key = bytes.fromhex(key_hex)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ciphertext_b64)
    plain = AESGCM(key).decrypt(nonce, ct, b"padam-lan-sync-v1")
    obj = json.loads(plain.decode("utf-8"))
    recs = obj.get("records")
    return recs if isinstance(recs, list) else []


def create_lan_pairing_offer(
    *,
    port: int,
    host: str | None = None,
    ttl_sec: int = 300,
) -> dict[str, Any]:
    """Создаёт одноразовое предложение LAN-сопряжения с data-URI SVG QR для CSP-безопасного <img>."""
    raw = create_lan_pair_offer(port=port, host_ip=host, ttl_s=ttl_sec)
    offer = get_active_offer(raw["pair_id"]) or {}
    key_hex = str(offer.get("key_hex") or "")
    key_b64 = base64.urlsafe_b64encode(bytes.fromhex(key_hex)).decode("ascii").rstrip("=") if key_hex else ""
    base_url = f"http://{raw['host']}:{raw['port']}"
    from urllib.parse import quote as _q
    qr_uri = f"padam://lan-sync?url={_q(base_url, safe='')}&token={_q(raw['pair_id'], safe='')}&key={_q(key_b64, safe='')}"
    svg_txt = make_qr_svg(qr_uri, scale=5, border=3)
    svg_b64 = base64.b64encode(svg_txt.encode("utf-8")).decode("ascii")
    return {
        **raw,
        "lan_candidates": list_lan_ips(),
        "token": raw["pair_id"],
        "key_b64": key_b64,
        "base_url": base_url,
        "ttl_sec": int(ttl_sec),
        "qr_uri": qr_uri,
        "qr_svg": svg_txt,
        "qr_data_uri": f"data:image/svg+xml;base64,{svg_b64}",
    }


def decrypt_lan_payload(key_bytes: bytes, nonce_b64: str, ciphertext_b64: str) -> list[dict[str, Any]]:
    """Расшифровывает LAN-дельту по сырым 32 байтам ключа AES-256-GCM."""
    return decrypt_sync_delta(nonce_b64, ciphertext_b64, key_bytes.hex())


def export_encrypted_delta(
    memory,
    token: str,
    *,
    since: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Экспортирует активные записи памяти в зашифрованный AES-256-GCM конверт по одноразовому токену."""
    offer = get_active_offer(token)
    if not offer:
        return {"ok": False, "error": "invalid_or_expired_token"}
    lim = max(1, min(500, int(limit or 200)))
    if since:
        rows = memory.store.query(
            "SELECT id, kind, scope, content, agent_id, created_at FROM memory "
            "WHERE user_id = ? AND status = 'active' AND created_at >= ? ORDER BY created_at DESC LIMIT ?",
            (memory.user_id, str(since), lim),
        )
    else:
        rows = memory.store.query(
            "SELECT id, kind, scope, content, agent_id, created_at FROM memory "
            "WHERE user_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT ?",
            (memory.user_id, lim),
        )
    from . import safety as _safety
    items = []
    for r in rows:
        clean_txt, _ = _safety.redact(str(r["content"] or ""))
        items.append({
            "id": str(r["id"]),
            "kind": str(r["kind"] or "fact"),
            "scope": str(r["scope"] or "global"),
            "agent_id": str(r["agent_id"] or "owner") if "agent_id" in r.keys() else "owner",
            "content": clean_txt[:4000],
            "created_at": str(r["created_at"] or ""),
        })
    enc = encrypt_sync_delta(items, offer["key_hex"])
    return {
        "ok": True,
        "count": len(items),
        "nonce_b64": enc["nonce_b64"],
        "ciphertext_b64": enc["ciphertext_b64"],
    }


def import_encrypted_delta(memory, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Принимает зашифрованную LAN-дельту с Android и пропускает каждую запись через guarded=True."""
    offer = get_active_offer(token)
    if not offer:
        return {"ok": False, "error": "invalid_or_expired_token"}
    nonce_str = str(payload.get("nonce_b64") or "").strip()
    with _PAIR_LOCK:
        seen = _CONSUMED_NONCES.setdefault(token, set())
        if nonce_str in seen:
            return {"ok": False, "error": "replay_nonce_rejected"}
    try:
        items = decrypt_sync_delta(
            nonce_str,
            str(payload.get("ciphertext_b64") or ""),
            offer["key_hex"],
        )
    except Exception as exc:
        return {"ok": False, "error": f"decrypt_failed: {exc}"}
    imported = 0
    quarantined = 0
    for it in items:
        txt = str(it.get("content") or "").strip()
        if not txt:
            continue
        outcome, _ = memory.remember(
            txt[:6000],
            kind=str(it.get("kind") or "fact"),
            scope=str(it.get("scope") or "global"),
            origin="agent",
            guarded=True,
            agent_id=str(it.get("agent_id") or "android_lan_sync"),
        )
        if outcome == "quarantined":
            quarantined += 1
        elif outcome != "duplicate":
            imported += 1
    with _PAIR_LOCK:
        _CONSUMED_NONCES.setdefault(token, set()).add(nonce_str)
    return {"ok": True, "received": len(items), "imported": imported, "quarantined": quarantined}
