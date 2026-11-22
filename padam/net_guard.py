"""Сетевой предохранитель (SSRF-защита) и ограничение прав доступа к файлам с токенами.

Единый модуль для проверки всех исходящих URL (ollama_url, api_base_url,
refresh_url, webhook-обратные вызовы и др.) и защиты от обходов через
десятичные/шестнадцатеричные/восьмеричные IP, IPv6 ULA/link-local/mapped,
облачные метаданные (169.254.169.254), DNS-резолв в приватные сети и
HTTP-редиректы на запрещённые адреса.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import http.client
import ipaddress
import os
from pathlib import Path
import re
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timezone
import threading
from typing import Any

# Известные имена облачных метаданных и внутренних системных адресов
_BLOCKED_HOSTNAMES = frozenset({
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "metadata.aws.internal",
    "instance-data",
    "169.254.169.254",
    "fd00:ec2::254",
})

_BLOCKED_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost.localdomain",
    ".arpa",
)

# Дополнительные зарезервированные и транзитные диапазоны сверх stdlib is_private/is_link_local
_EXTRA_BLOCKED_V4_NETS = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),      # CGNAT (RFC 6598)
    ipaddress.IPv4Network("169.254.0.0/16"),     # Link-local / Cloud metadata
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),      # Benchmarking
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),        # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),        # Reserved / Broadcast
)

_EXTRA_BLOCKED_V6_NETS = (
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("64:ff9b::/96"),       # NAT64 (может проксировать в приватный IPv4)
    ipaddress.IPv6Network("64:ff9b:1::/48"),
    ipaddress.IPv6Network("100::/64"),           # Discard-Only
    ipaddress.IPv6Network("2001::/32"),          # Teredo
    ipaddress.IPv6Network("2001:2::/48"),
    ipaddress.IPv6Network("2001:db8::/32"),
    ipaddress.IPv6Network("2002::/16"),          # 6to4
    ipaddress.IPv6Network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.IPv6Network("fe80::/10"),          # Link-Local
    ipaddress.IPv6Network("fec0::/10"),          # Site-Local (устаревший)
    ipaddress.IPv6Network("ff00::/8"),           # Multicast
)

# Паттерн числовых IPv4 в обфусцированной форме (decimal, hex, octal, сокращённый вид)
_NUMERIC_HOST_RE = re.compile(
    r"^(?:0x[0-9a-f]+|0[0-7]*|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]*|\d+)){0,3}$",
    re.IGNORECASE,
)
_CANONICAL_DECIMAL_V4_PART_RE = re.compile(r"^(?:0|[1-9]\d{0,2})$")



# Режим Авиа (Air-Gap) и Стеклянный Щит Данных — журнал всех исходящих сетевых обращений
_EGRESS_LOCK = threading.Lock()
_EGRESS_LOG: deque[dict[str, Any]] = deque(maxlen=200)
_AIRGAP_MODE = False


def is_airgap_enabled() -> bool:
    """Возвращает True, если включён Режим Авиа (полный оффлайн, внешние URL запрещены)."""
    return bool(_AIRGAP_MODE or os.environ.get("PADAM_AIRGAP", "").strip() == "1")


def set_airgap_enabled(enabled: bool) -> dict[str, Any]:
    """Включает или выключает Режим Авиа (Air-Gap) на уровне net_guard."""
    global _AIRGAP_MODE
    _AIRGAP_MODE = bool(enabled)
    return {"ok": True, "airgap": is_airgap_enabled()}


def record_egress_event(
    domain: str,
    *,
    reason: str = "outbound_check",
    bytes_out: int = 0,
    allowed: bool = True,
    dlp_clean: bool = True,
) -> None:
    """Фиксирует исходящее сетевое обращение (только домен и метаданные, без секретов и тела)."""
    with _EGRESS_LOCK:
        _EGRESS_LOG.append({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "domain": str(domain or "")[:120],
            "reason": str(reason or "outbound")[:64],
            "bytes_out": max(0, int(bytes_out)),
            "allowed": bool(allowed),
            "dlp_clean": bool(dlp_clean),
        })


def get_egress_log(limit: int = 50) -> list[dict[str, Any]]:
    """Возвращает последние исходящие сетевые обращения (свежие сверху)."""
    lim = max(1, min(200, int(limit)))
    with _EGRESS_LOCK:
        return list(_EGRESS_LOG)[-lim:][::-1]

def _is_canonical_v4_literal(host: str) -> bool:
    """Проверяет, что строка является строго стандартной 4-октетной IPv4 без ведущих нулей/hex."""
    parts = host.split(".")
    if len(parts) != 4:
        return False
    if not all(_CANONICAL_DECIMAL_V4_PART_RE.fullmatch(p) for p in parts):
        return False
    return all(0 <= int(p) <= 255 for p in parts)


def _check_ip_allowed(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_localhost: bool = False,
    allow_ipv6_loopback: bool = False,
) -> None:
    """Проверяет IP-адрес (включая вложенный IPv4 для IPv6) на допустимость для исходящих вызовов."""
    if isinstance(ip, ipaddress.IPv6Address):
        # Рекурсивно проверяем вложенные IPv4-адреса (например, ::ffff:169.254.169.254)
        if ip.ipv4_mapped is not None:
            _check_ip_allowed(
                ip.ipv4_mapped,
                allow_localhost=allow_localhost,
                allow_ipv6_loopback=allow_ipv6_loopback,
            )
            return
        if ip.sixtofour is not None:
            raise ValueError(f"Транзитный IPv6-адрес 6to4 запрещён по SSRF-политике: {ip}")
        if ip.teredo is not None:
            raise ValueError(f"Транзитный IPv6-адрес Teredo запрещён по SSRF-политике: {ip}")
        if ip.is_loopback:
            if allow_localhost and allow_ipv6_loopback:
                return
            raise ValueError(f"IPv6 loopback-адрес запрещён: {ip}")
        if ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip.is_site_local:
            raise ValueError(f"Приватный или зарезервированный IPv6-адрес запрещён: {ip}")
        for net in _EXTRA_BLOCKED_V6_NETS:
            if ip in net:
                raise ValueError(f"Запрещённый диапазон IPv6 ({net}): {ip}")
        return

    # IPv4
    if ip.is_loopback:
        if allow_localhost and ip == ipaddress.IPv4Address("127.0.0.1"):
            return
        raise ValueError(f"Loopback IPv4-адрес запрещён: {ip}")
    if ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise ValueError(f"Приватный, link-local или зарезервированный IPv4-адрес запрещён: {ip}")
    for net in _EXTRA_BLOCKED_V4_NETS:
        if ip in net:
            raise ValueError(f"Запрещённый диапазон IPv4 ({net}): {ip}")


def validate_outbound_url(
    raw_url: str,
    *,
    allow_localhost: bool = False,
    allow_ipv6_loopback: bool = False,
    allow_http_localhost: bool = True,
    require_https: bool = True,
    resolve_dns: bool = True,
    fail_on_dns_error: bool = False,
) -> str:
    """Единый SSRF-валидатор исходящих URL.

    Отклоняет небезопасные схемы, userinfo, облачные метаданные (169.254.169.254),
    RFC1918/CGNAT/link-local/ULA/::1, обфусцированные IP (decimal/hex/octal/shorthand)
    и доменные имена, резолвящиеся во внутренние адреса.
    """
    u = str(raw_url or "").strip().rstrip("/")
    if not u:
        raise ValueError("Пустой URL.")
    if any(ord(ch) < 32 or ord(ch) == 127 or ch in ("\\", " ") for ch in u):
        raise ValueError("URL содержит недопустимые управляющие символы или пробелы.")

    parsed = urllib.parse.urlsplit(u)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Запрещённая схема URL {scheme!r}: допускаются только http/https.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Учётные данные (user:pass@) в URL запрещены.")

    # Проверка корректности порта до любых сетевых шагов
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Некорректный порт в URL: {exc}") from exc

    raw_host = parsed.hostname
    if not raw_host:
        raise ValueError("URL не содержит имени хоста.")
    host_clean = raw_host.strip().rstrip(".").lower()
    if not host_clean:
        raise ValueError("URL содержит пустое имя хоста.")
    # В IPv6 может быть zone_id вида fe80::1%eth0 — сразу блокируем
    if "%" in host_clean:
        raise ValueError("Zone-ID (%) в IPv6-адресе запрещён.")

    if host_clean in _BLOCKED_HOSTNAMES:
        raise ValueError(f"Обращение к адресу метаданных {host_clean!r} запрещено.")

    # 1. Отсекаем любые числовые обфусцированные IP (decimal integer, hex, octal, shorthand)
    if _NUMERIC_HOST_RE.fullmatch(host_clean):
        if not _is_canonical_v4_literal(host_clean):
            raise ValueError(
                f"Обфусцированный числовой IP-адрес {host_clean!r} запрещён (используйте домен или стандартный IPv4)."
            )

    # 2. Пробуем распарсить как IPv4 или IPv6 литерал
    parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        parsed_ip = ipaddress.ip_address(host_clean)
    except ValueError:
        parsed_ip = None

    is_local_target = False
    if parsed_ip is not None:
        _check_ip_allowed(
            parsed_ip,
            allow_localhost=allow_localhost,
            allow_ipv6_loopback=allow_ipv6_loopback,
        )
        is_local_target = parsed_ip.is_loopback
    else:
        if host_clean == "localhost" or host_clean.endswith(".localhost"):
            if not allow_localhost:
                raise ValueError("Локальный адрес localhost запрещён текущей политикой безопасности.")
            is_local_target = True
        else:
            for suf in _BLOCKED_SUFFIXES:
                if host_clean.endswith(suf) or host_clean == suf.lstrip("."):
                    raise ValueError(f"Внутреннее доменное имя {host_clean!r} запрещено.")
            if resolve_dns:
                target_port = port or (443 if scheme == "https" else 80)
                try:
                    infos = socket.getaddrinfo(host_clean, target_port, type=socket.SOCK_STREAM)
                except socket.gaierror as exc:
                    if fail_on_dns_error:
                        raise ValueError(f"Не удалось разрешить DNS для {host_clean!r}: {exc}") from exc
                    infos = []
                for info in infos:
                    sockaddr = info[4]
                    if not sockaddr:
                        continue
                    addr_raw = str(sockaddr[0]).split("%", 1)[0]
                    resolved_ip = ipaddress.ip_address(addr_raw)
                    # Внешний домен никогда не имеет права резолвиться даже в localhost
                    _check_ip_allowed(
                        resolved_ip,
                        allow_localhost=False,
                        allow_ipv6_loopback=False,
                    )

    # 2б. Режим Авиа (Air-Gap): блокируем любые не-локальные внешние соединения
    if not is_local_target and is_airgap_enabled():
        record_egress_event(host_clean, reason="airgap_blocked", allowed=False)
        raise ValueError(f"Включён Режим Авиа (Air-Gap): внешний адрес {host_clean!r} заблокирован.")

    # 3. Проверка HTTPS против plain HTTP
    if scheme == "http":
        if is_local_target and allow_localhost and allow_http_localhost:
            record_egress_event(host_clean, reason="local_http", allowed=True)
            return u
        if require_https:
            raise ValueError("Исходящий URL должен использовать https:// (http:// допускается только для локального адреса при явном разрешении).")

    record_egress_event(host_clean, reason="local_https" if is_local_target else "external_https", allowed=True)
    return u


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Перехватывает HTTP-редиректы (3xx) и проверяет каждый целевой URL через validate_outbound_url."""

    def __init__(
        self,
        *,
        allow_localhost: bool,
        allow_ipv6_loopback: bool,
        allow_http_localhost: bool,
        require_https: bool,
        max_redirects: int,
    ) -> None:
        self.allow_localhost = allow_localhost
        self.allow_ipv6_loopback = allow_ipv6_loopback
        self.allow_http_localhost = allow_http_localhost
        self.require_https = require_https
        self.max_redirects = max(0, int(max_redirects))
        self._redirect_count = 0

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        self._redirect_count += 1
        if self._redirect_count > self.max_redirects:
            raise ValueError(f"Превышен лимит HTTP-редиректов ({self.max_redirects}).")
        resolved_target = urllib.parse.urljoin(req.full_url, str(newurl or "").strip())
        validate_outbound_url(
            resolved_target,
            allow_localhost=self.allow_localhost,
            allow_ipv6_loopback=self.allow_ipv6_loopback,
            allow_http_localhost=self.allow_http_localhost,
            require_https=self.require_https,
            resolve_dns=True,
            fail_on_dns_error=False,
        )
        return super().redirect_request(req, fp, code, msg, headers, resolved_target)

    def http_error_302(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any) -> Any:
        loc = None
        if "location" in headers:
            loc = headers["location"]
        elif "uri" in headers:
            loc = headers["uri"]
        if loc is not None:
            resolved_target = urllib.parse.urljoin(req.full_url, str(loc).strip())
            validate_outbound_url(
                resolved_target,
                allow_localhost=self.allow_localhost,
                allow_ipv6_loopback=self.allow_ipv6_loopback,
                allow_http_localhost=self.allow_http_localhost,
                require_https=self.require_https,
                resolve_dns=True,
                fail_on_dns_error=False,
            )
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _peer_guarded(base: type, *, allow_localhost: bool, allow_ipv6_loopback: bool) -> type:
    """Фаза 2 аудита GLM, NETGUARD-01: проверка адреса В МОМЕНТ СОЕДИНЕНИЯ, а не только при валидации.

    validate_outbound_url резолвит имя один раз, а соединение резолвило его заново: подменный DNS
    (rebinding) отдавал публичный адрес на проверке и внутренний — на соединении; SERVFAIL на проверке
    вовсе пропускал имя. Здесь сокет открывается, берётся его реальный адрес собеседника (getpeername)
    и проверяется теми же правилами — до TLS и до первого байта запроса. Редиректы идут через те же
    соединения, поэтому закрыты тем же.
    """

    class _Guarded(base):  # type: ignore[misc, valid-type]
        def __init__(self, *a: Any, **kw: Any) -> None:
            super().__init__(*a, **kw)
            raw_create = self._create_connection

            def _create(address: Any, *ca: Any, **ckw: Any) -> socket.socket:
                sock = raw_create(address, *ca, **ckw)
                # Через прокси собеседник — сам прокси, его выбрал владелец машины: адрес цели проверен валидатором.
                if getattr(self, "_tunnel_host", None) or urllib.request.getproxies():
                    return sock
                try:
                    peer = ipaddress.ip_address(str(sock.getpeername()[0]).split("%", 1)[0])
                    host = str(self.host or "").strip("[]").rstrip(".").lower()
                    try:
                        ipaddress.ip_address(host)
                        local_name = True
                    except ValueError:
                        local_name = host == "localhost" or host.endswith(".localhost")
                    _check_ip_allowed(
                        peer,
                        allow_localhost=allow_localhost and local_name,
                        allow_ipv6_loopback=allow_ipv6_loopback and local_name,
                    )
                except Exception:
                    sock.close()
                    raise
                return sock

            self._create_connection = _create

    return _Guarded


class _GuardedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, conn_cls: type) -> None:
        super().__init__()
        self._conn_cls = conn_cls

    def http_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(self._conn_cls, req)


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, conn_cls: type) -> None:
        super().__init__()
        self._conn_cls = conn_cls

    def https_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(self._conn_cls, req, context=self._context)


def safe_urlopen(
    req_or_url: urllib.request.Request | str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    method: str | None = None,
    timeout: float = 10.0,
    allow_localhost: bool = False,
    allow_ipv6_loopback: bool = False,
    allow_http_localhost: bool = True,
    require_https: bool = True,
    max_redirects: int = 5,
) -> http.client.HTTPResponse:
    """Выполняет исходящий HTTP(S)-запрос с обязательной проверкой URL и всех редиректов."""
    if isinstance(req_or_url, urllib.request.Request):
        req = req_or_url
        target_url = req.full_url
    else:
        target_url = str(req_or_url or "").strip()
        req = urllib.request.Request(
            target_url,
            data=data,
            headers=dict(headers or {}),
            method=method or ("POST" if data is not None else "GET"),
        )

    validate_outbound_url(
        target_url,
        allow_localhost=allow_localhost,
        allow_ipv6_loopback=allow_ipv6_loopback,
        allow_http_localhost=allow_http_localhost,
        require_https=require_https,
        resolve_dns=True,
        fail_on_dns_error=False,
    )

    redirect_handler = _SafeRedirectHandler(
        allow_localhost=allow_localhost,
        allow_ipv6_loopback=allow_ipv6_loopback,
        allow_http_localhost=allow_http_localhost,
        require_https=require_https,
        max_redirects=max_redirects,
    )
    policy = dict(allow_localhost=allow_localhost, allow_ipv6_loopback=allow_ipv6_loopback)
    opener = urllib.request.build_opener(
        _GuardedHTTPHandler(_peer_guarded(http.client.HTTPConnection, **policy)),
        _GuardedHTTPSHandler(_peer_guarded(http.client.HTTPSConnection, **policy)),
        redirect_handler,
    )
    return opener.open(req, timeout=timeout)


def _windows_current_user_sid() -> str:
    """Возвращает SID текущего пользователя Windows в строковом виде (S-1-5-21-...)."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    TOKEN_QUERY = 0x0008
    TokenUser = 1

    class _SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class _TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", _SID_AND_ATTRIBUTES)]

    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h_token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(h_token, TokenUser, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(h_token, TokenUser, buf, needed, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        tok_user = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
        sid_str_ptr = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(tok_user.User.Sid, ctypes.byref(sid_str_ptr)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return str(sid_str_ptr.value or "")
        finally:
            kernel32.LocalFree(ctypes.cast(sid_str_ptr, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(h_token)


def _windows_file_dacl_sids(path: Path) -> list[str]:
    """Читает список SID всех субъектов из DACL файла на Windows через WinAPI."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    SE_FILE_OBJECT = 1
    DACL_SECURITY_INFORMATION = 0x00000004
    AclSizeInformation = 2

    class _ACL_SIZE_INFO(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", wintypes.BYTE),
            ("AceFlags", wintypes.BYTE),
            ("AceSize", wintypes.WORD),
        ]

    class _ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = [
            ("Header", _ACE_HEADER),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    p_dacl = ctypes.c_void_p()
    p_sd = ctypes.c_void_p()
    err = advapi32.GetNamedSecurityInfoW(
        str(path),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(p_dacl),
        None,
        ctypes.byref(p_sd),
    )
    if err != 0:
        raise OSError(err, f"GetNamedSecurityInfoW failed: {err}")
    try:
        if not p_dacl.value:
            return []
        size_info = _ACL_SIZE_INFO()
        if not advapi32.GetAclInformation(
            p_dacl,
            ctypes.byref(size_info),
            ctypes.sizeof(size_info),
            AclSizeInformation,
        ):
            raise OSError(ctypes.get_last_error(), "GetAclInformation failed")
        sids: list[str] = []
        for idx in range(int(size_info.AceCount)):
            p_ace = ctypes.c_void_p()
            if not advapi32.GetAce(p_dacl, idx, ctypes.byref(p_ace)):
                continue
            sid_ptr = ctypes.c_void_p(p_ace.value + _ACCESS_ALLOWED_ACE.SidStart.offset)
            sid_str_ptr = wintypes.LPWSTR()
            if advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_str_ptr)):
                try:
                    sids.append(str(sid_str_ptr.value or ""))
                finally:
                    kernel32.LocalFree(ctypes.cast(sid_str_ptr, ctypes.c_void_p))
        return sids
    finally:
        if p_sd.value:
            kernel32.LocalFree(p_sd)


def restrict_file_to_owner(path: Path | str) -> bool:
    """Ограничивает права на файл строго текущим владельцем (POSIX 0o600, Windows NTFS ACL)."""
    target = Path(path)
    if not target.exists():
        return False
    if os.name != "nt":
        os.chmod(target, 0o600)
        return True

    try:
        sid = _windows_current_user_sid()
        # Отключаем наследование и выдаём чтение+запись только текущему SID (без привязки к локали ОС)
        res = subprocess.run(
            ["icacls", str(target), "/inheritance:r", "/grant:r", f"*{sid}:(R,W)"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
            check=False,
        )
        if res.returncode != 0:
            return False
        # CI 18.11.2026: /inheritance:r снимает только УНАСЛЕДОВАННЫЕ записи. Явные записи (SYSTEM, Administrators,
        # OWNER RIGHTS — так создаёт файлы Temp на GitHub runner) оставались, и токен читали не только владельцем.
        # Снимаем каждую чужую запись по фактическому списку DACL и проверяем итог.
        for чужой in [s for s in _windows_file_dacl_sids(target) if s != sid]:
            subprocess.run(["icacls", str(target), "/remove:g", f"*{чужой}", "/remove:d", f"*{чужой}"],
                           capture_output=True, text=True, errors="replace", timeout=10, check=False)
        return verify_owner_only_permissions(target)
    except Exception:
        try:
            os.chmod(target, 0o600)
        except Exception:
            pass
        return False


def verify_owner_only_permissions(path: Path | str) -> bool:
    """Проверяет, что файл доступен только текущему владельцу (POSIX mode 0o600 / Windows DACL)."""
    target = Path(path)
    if not target.exists():
        return False
    if os.name != "nt":
        return (target.stat().st_mode & 0o077) == 0
    try:
        owner_sid = _windows_current_user_sid()
        dacl_sids = _windows_file_dacl_sids(target)
        return bool(dacl_sids) and all(s == owner_sid for s in dacl_sids)
    except Exception:
        return False
