# -*- coding: utf-8 -*-
"""Локальное авто-обнаружение устройств Семьи по Wi-Fi / LAN (opt-in, анонимный маячок).

Правила безопасности (MESH-02):
1. По умолчанию ВЫКЛЮЧЕНО (`PADAM_LAN_DISCOVERY=0`).
2. Маячок НЕ раскрывает `user_id`, имя владельца или `device_name` в открытом виде — передаётся только
   случайный `beacon_id`, порт, временная метка, `nonce` и крипто-метка `HMAC-SHA256(sync_key, nonce|ts)[:16]`.
3. Допустимы исключительно частные локальные подсети (RFC1918, loopback, link-local) — внешние IP блокируются.
4. Синхронизация дельт по обнаруженному адресу разрешена ТОЛЬКО с уже сопряжённым устройством (`trusted == 1`)
   и при совпадении `sender_ip` с закреплённым `endpoint_url` пира (если он указан).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import time
import urllib.parse
from typing import Any

from . import live_mesh

DEFAULT_DISCOVERY_PORT = 41877


def is_lan_discovery_enabled() -> bool:
    return os.environ.get("PADAM_LAN_DISCOVERY", "0").strip() == "1"


def is_private_ip(host: str) -> bool:
    """Возвращает True только для частных, локальных или link-local адресов (не публичный интернет)."""
    clean = (host or "").strip().split("%")[0]
    try:
        ip = ipaddress.ip_address(clean)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return False


def _beacon_tag(sync_key: bytes, nonce: str, ts: int) -> str:
    msg = f"padam-lan-beacon-v2|{nonce}|{int(ts)}".encode("utf-8")
    return hmac.new(sync_key, msg, hashlib.sha256).hexdigest()[:16]


def issue_beacon_challenge() -> str:
    """Генерирует случайный challenge-nonce для проверки ответа маячка."""
    return secrets.token_hex(12)


def create_beacon_packet(
    memory,
    *,
    api_port: int = 8077,
    force: bool = False,
    peer_id: str | None = None,
    challenge_nonce: str = "",
) -> dict[str, Any]:
    """Формирует анонимный пакет маячка с HMAC-тегом на общем sync_key сопряжённых пиров."""
    if not force and not is_lan_discovery_enabled():
        raise PermissionError("LAN discovery is disabled by default; set PADAM_LAN_DISCOVERY=1 to enable")
    live_mesh.get_or_create_node_identity(memory)
    nonce = str(challenge_nonce or secrets.token_hex(8))
    ts = int(time.time())

    tags: list[str] = []
    peers = live_mesh.list_peers(memory)
    for p in peers:
        pid = str(p.get("peer_id") or "")
        if int(p.get("trusted") or 0) != 1 or not pid:
            continue
        if peer_id and pid != peer_id:
            continue
        try:
            skey = live_mesh._peer_sync_key(memory, pid)
            tags.append(_beacon_tag(skey, nonce, ts))
        except Exception:
            continue

    return {
        "schema": "padam-lan-beacon-v2",
        "beacon_id": secrets.token_hex(12),
        "nonce": nonce,
        "peer_tag": tags[0] if tags else secrets.token_hex(8),
        "peer_tags": tags,
        "port": int(api_port),
        "ts": ts,
    }


def _endpoint_ip_matches(endpoint_url: str, sender_ip: str) -> bool:
    ep = str(endpoint_url or "").strip()
    if not ep:
        return True
    try:
        host = (urllib.parse.urlsplit(ep).hostname or "").strip()
    except Exception:
        return False
    if not host:
        return True
    return host == sender_ip


def parse_and_match_beacon(
    memory,
    raw_bytes: bytes,
    sender_ip: str,
    *,
    max_age_s: int = 120,
    expected_nonce: str | None = None,
) -> dict[str, Any]:
    """Проверяет маячок по HMAC-SHA256(sync_key, nonce|ts) и сверяет source IP с endpoint_url пира."""
    if not is_private_ip(sender_ip):
        return {"accepted": False, "trusted": False, "reason": "non_private_source_ip"}

    try:
        pkt = json.loads(raw_bytes.decode("utf-8"))
    except Exception:
        return {"accepted": False, "trusted": False, "reason": "invalid_json"}

    if pkt.get("schema") not in ("padam-lan-beacon-v2",):
        return {"accepted": False, "trusted": False, "reason": "unknown_schema"}

    ts = int(pkt.get("ts") or 0)
    if abs(int(time.time()) - ts) > max_age_s:
        return {"accepted": False, "trusted": False, "reason": "stale_beacon"}

    nonce = str(pkt.get("nonce") or "")
    if expected_nonce is not None and not hmac.compare_digest(nonce, str(expected_nonce)):
        return {"accepted": False, "trusted": False, "reason": "challenge_nonce_mismatch"}

    offered = [str(t) for t in (pkt.get("peer_tags") or []) if t]
    single = str(pkt.get("peer_tag") or "")
    if single and single not in offered:
        offered.append(single)
    port = int(pkt.get("port") or 0)
    if not nonce or not offered or not (1 <= port <= 65535):
        return {"accepted": False, "trusted": False, "reason": "malformed_fields"}

    peers = live_mesh.list_peers(memory)
    for p in peers:
        pid = str(p.get("peer_id") or "")
        if int(p.get("trusted") or 0) != 1 or not pid:
            continue
        try:
            skey = live_mesh._peer_sync_key(memory, pid)
        except Exception:
            continue
        expected_tag = _beacon_tag(skey, nonce, ts)
        if any(hmac.compare_digest(expected_tag, tok) for tok in offered):
            if not _endpoint_ip_matches(str(p.get("endpoint_url") or ""), sender_ip):
                return {
                    "accepted": False,
                    "paired": True,
                    "trusted": False,
                    "peer_id": None,
                    "reason": "endpoint_ip_mismatch",
                }
            return {
                "accepted": True,
                "paired": True,
                "trusted": True,
                "peer_id": pid,
                "endpoint": f"http://{sender_ip}:{port}",
                "reason": "trusted_peer_matched",
            }

    return {
        "accepted": False,
        "paired": False,
        "trusted": False,
        "beacon_id": str(pkt.get("beacon_id") or ""),
        "reason": "unknown_unpaired_device",
    }


def probe_udp_beacon(memory, *, bind_ip: str = "127.0.0.1", port: int = 0, api_port: int = 8077) -> dict[str, Any]:
    """Локальный цикл проверки отправки/приёма UDP-маячка через loopback/LAN."""
    if not is_lan_discovery_enabled():
        return {"ok": False, "enabled": False, "reason": "PADAM_LAN_DISCOVERY is disabled"}
    if not is_private_ip(bind_ip):
        raise ValueError("LAN discovery only binds to private or loopback addresses")

    pkt = create_beacon_packet(memory, api_port=api_port)
    raw = json.dumps(pkt, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.settimeout(1.0)
        srv.bind((bind_ip, port))
        bound_port = srv.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cli:
            cli.sendto(raw, (bind_ip, bound_port))
        data, addr = srv.recvfrom(4096)

    matched = parse_and_match_beacon(memory, data, addr[0])
    return {
        "ok": True,
        "enabled": True,
        "beacon": pkt,
        "source_ip": addr[0],
        "matched": matched,
    }
