# -*- coding: utf-8 -*-
"""Локальное авто-обнаружение устройств Семьи по Wi-Fi / LAN (opt-in, анонимный маячок).

Правила безопасности (поправка приёмки 17.11):
1. По умолчанию ВЫКЛЮЧЕНО (`PADAM_LAN_DISCOVERY=0`).
2. Маячок НЕ раскрывает `user_id`, имя владельца или `device_name` в открытом виде — передаётся только
   случайный `beacon_id`, порт, временная метка, `nonce` и крипто-метка `peer_tag = sha256(node_id|nonce)[:16]`.
3. Допустимы исключительно частные локальные подсети (RFC1918, loopback, link-local) — внешние IP блокируются.
4. Синхронизация дельт по обнаруженному адресу разрешена ТОЛЬКО с уже сопряжённым устройством (`trusted == 1`).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import socket
import time
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


def _beacon_tag(node_id: str, nonce: str) -> str:
    return hashlib.sha256(f"padam-lan-beacon-tag-v1|{node_id}|{nonce}".encode("utf-8")).hexdigest()[:16]


def create_beacon_packet(memory, *, api_port: int = 8077, force: bool = False) -> dict[str, Any]:
    """Формирует анонимный пакет маячка без имён владельца/устройства и без PII."""
    if not force and not is_lan_discovery_enabled():
        raise PermissionError("LAN discovery is disabled by default; set PADAM_LAN_DISCOVERY=1 to enable")
    ident = live_mesh.get_or_create_node_identity(memory)
    nonce = secrets.token_hex(8)
    return {
        "schema": "padam-lan-beacon-v1",
        "beacon_id": secrets.token_hex(12),
        "nonce": nonce,
        "peer_tag": _beacon_tag(str(ident["node_id"]), nonce),
        "port": int(api_port),
        "ts": int(time.time()),
    }


def parse_and_match_beacon(
    memory,
    raw_bytes: bytes,
    sender_ip: str,
    *,
    max_age_s: int = 120,
) -> dict[str, Any]:
    """Разбирает входящий маячок с частного IP и проверяет, соответствует ли он сопряжённому пиру (`trusted == 1`)."""
    if not is_private_ip(sender_ip):
        return {"accepted": False, "trusted": False, "reason": "non_private_source_ip"}

    try:
        pkt = json.loads(raw_bytes.decode("utf-8"))
    except Exception:
        return {"accepted": False, "trusted": False, "reason": "invalid_json"}

    if pkt.get("schema") != "padam-lan-beacon-v1":
        return {"accepted": False, "trusted": False, "reason": "unknown_schema"}

    ts = int(pkt.get("ts") or 0)
    if abs(int(time.time()) - ts) > max_age_s:
        return {"accepted": False, "trusted": False, "reason": "stale_beacon"}

    nonce = str(pkt.get("nonce") or "")
    tag = str(pkt.get("peer_tag") or "")
    port = int(pkt.get("port") or 0)
    if not nonce or not tag or not (1 <= port <= 65535):
        return {"accepted": False, "trusted": False, "reason": "malformed_fields"}

    # Проверяем только среди уже известных пиров; синхронизация возможна только с trusted == 1
    peers = live_mesh.list_peers(memory)
    for p in peers:
        pid = str(p.get("peer_id") or "")
        if pid and _beacon_tag(pid, nonce) == tag:
            is_trusted = int(p.get("trusted") or 0) == 1
            return {
                "accepted": is_trusted,
                "paired": True,
                "trusted": is_trusted,
                "peer_id": pid if is_trusted else None,
                "endpoint": f"http://{sender_ip}:{port}" if is_trusted else "",
                "reason": "trusted_peer_matched" if is_trusted else "pairing_sas_required",
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
