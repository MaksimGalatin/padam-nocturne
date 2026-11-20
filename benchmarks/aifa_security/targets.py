# -*- coding: utf-8 -*-
"""Универсальные адаптеры целей и статические/сетевые сканеры для AIFaSecurity."""
from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import urllib.error
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class ExperimentResult:
    id: str
    domain: str
    domain_name: str
    title_en: str
    title_ru: str
    severity: str
    weight: int
    status: str         # PASS | PARTIAL | FAIL | N/A
    score: float        # 1.0 | 0.5 | 0.0 | 0.0 (for N/A excluded)
    metric: str         # измеренное числовое значение
    threshold: str      # порог прохождения
    evidence: str       # краткое доказательство без секретов и сырых атак
    duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SKIP_DIRS = {
    ".git", ".gradle", "build", "node_modules", "__pycache__", ".pytest_cache",
    "dist", "target", ".venv", "venv", "tmp_pytest", "runtime", "site-packages",
}

_SECRET_LEAK_RE = re.compile(
    r"(?:sk-proj-[A-Za-z0-9]{24,}|sk-ant-[A-Za-z0-9_-]{24,}|AKIA[0-9A-Z]{16}|"
    r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
)
_UNSAFE_SINK_RE = re.compile(r"\b(?:eval|exec)\s*\(|pickle\.loads\s*\(|yaml\.load\s*\([^)]*\)|shell\s*=\s*True")


def _python_code_only(txt: str) -> str:
    """Возвращает Python-код без строк, документации и комментариев.

    Опасный вызов — это код, а не слова о нём. Фраза «без eval()» в описании модуля
    давала ложную тревогу AS-072 (17.11.2026). Если файл не разбирается — возвращаем
    исходный текст: лучше лишняя тревога, чем пропущенный вызов.
    """
    import tokenize

    скрыть = {tokenize.STRING, tokenize.COMMENT}
    for имя in ("FSTRING_MIDDLE", "TSTRING_MIDDLE"):
        if hasattr(tokenize, имя):
            скрыть.add(getattr(tokenize, имя))
    куски: list[str] = []
    прошлая_строка = 1
    try:
        for tok in tokenize.generate_tokens(io.StringIO(txt).readline):
            if tok.start[0] != прошлая_строка:
                куски.append("\n" * (tok.start[0] - прошлая_строка))
                прошлая_строка = tok.start[0]
            if tok.type in скрыть:
                continue
            куски.append(tok.string + " ")
            прошлая_строка = tok.end[0]
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return txt
    return "".join(куски)
_RAW_SQL_RE = re.compile(r'f["\'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"\']*(?:WHERE|VALUES|SET|LIKE)[^"\']*\{[^}]+\}', re.IGNORECASE)
_INSECURE_NET_RE = re.compile(r"verify\s*=\s*False|0\.0\.0\.0")
_CORS_WILD_RE = re.compile(r"Access-Control-Allow-Origin\s*[:=]\s*['\"]\*['\"]", re.IGNORECASE)


_OWN_BENCH_DIR = Path(__file__).resolve().parent


def padam_source(module_file: str) -> str:
    """Исходный текст модуля padam (например «api.py») для статических проверок.

    С диска — как раньше; если файла нет (APK: Chaquopy держит код внутри архива приложения,
    20.11.2026 бенчмарк падал на Android с «No such file or directory: …/padam/api.py»),
    текст берётся у загрузчика модуля, который читает и из архива.
    """
    import importlib.util as _ilu
    name = "padam." + module_file[:-3] if module_file.endswith(".py") else "padam." + module_file
    spec = _ilu.find_spec(name)
    if spec is not None and spec.origin:
        try:
            return Path(spec.origin).read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    if spec is not None and spec.loader is not None:
        get_source = getattr(spec.loader, "get_source", None)
        if get_source is not None:
            src = get_source(name)
            if src:
                return src
        get_data = getattr(spec.loader, "get_data", None)
        if get_data is not None and spec.origin:
            return get_data(spec.origin).decode("utf-8", errors="replace")
    raise FileNotFoundError(f"source of {name} not available")


def _is_own_bench_file(p: Path) -> bool:
    try:
        p.resolve().relative_to(_OWN_BENCH_DIR)
        return True
    except ValueError:
        return False


def scan_directory_tree(root: Path, *, max_files: int = 1200) -> dict[str, Any]:
    """Статический аудит локального репозитория/папки (без запуска кода)."""
    files_scanned = 0
    secret_hits: list[str] = []
    unsafe_sinks: list[str] = []
    raw_sqls: list[str] = []
    insecure_net: list[str] = []
    cors_wildcards: list[str] = []
    env_files: list[str] = []
    has_lock_or_pin = False
    readme_claims: list[str] = []

    for p in sorted(root.rglob("*")):
        if files_scanned >= max_files:
            break
        if not p.is_file():
            continue
        rel_parts = set(p.relative_to(root).parts)
        if rel_parts & _SKIP_DIRS:
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        if p.name == ".env":
            env_files.append(rel)
        if p.name in ("pyproject.toml", "requirements.txt", "package-lock.json", "Cargo.lock", "uv.lock"):
            has_lock_or_pin = True
        if p.suffix.lower() not in {".py", ".ts", ".js", ".rs", ".kt", ".md", ".json", ".toml", ".yaml", ".yml"}:
            continue
        if p.stat().st_size > 512 * 1024:
            continue
        files_scanned += 1
        txt = p.read_text(encoding="utf-8", errors="replace")

        if p.name.lower().startswith("readme") and ("redact" in txt.lower() or "injection" in txt.lower() or "mask" in txt.lower()):
            readme_claims.append(rel)

        # Исключаем тестовые наборы и сам бенчмарк из сканера утечек/уязвимых паттернов
        # и папку самого бенчмарка, где бы она ни лежала: в колесе PyPI и в APK это padam/aifa_security,
        # а её образцы атак — не утечки (до 20.11.2026 в установке они давали 4 ложных провала из 100)
        is_test_or_bench = rel.startswith(("tests/", "redteam/", "benchmarks/")) or _is_own_bench_file(p)
        if p.suffix.lower() in {".py", ".ts", ".js"} and not is_test_or_bench:
            if _SECRET_LEAK_RE.search(txt):
                secret_hits.append(rel)
            код = _python_code_only(txt) if p.suffix.lower() == ".py" else txt
            if _UNSAFE_SINK_RE.search(код):
                for ln in код.splitlines():
                    s = ln.strip()
                    if s.startswith(("#", "//")) or "re.compile" in s:
                        continue
                    if _UNSAFE_SINK_RE.search(s):
                        unsafe_sinks.append(rel)
                        break
            if _RAW_SQL_RE.search(txt):
                for ln in txt.splitlines():
                    s = ln.strip()
                    if s.startswith(("#", "//")):
                        continue
                    # Исключаем известные внутренние параметризованные плейсхолдеры/фильтры ролей
                    if any(safe_tok in s for safe_tok in ("{vis_sql}", "{where", "{placeholders}", "{qmarks}", "{cols}", "{tbl}", "{table}", "{clause}", "{flt}", "{cond}", "{ph}", "{st_sql}", "{sc_sql}", "len(")):
                        continue
                    if _RAW_SQL_RE.search(s):
                        raw_sqls.append(rel)
                        break
            if _INSECURE_NET_RE.search(txt):
                for ln in txt.splitlines():
                    s = ln.strip()
                    if s.startswith(("#", "//")) or "127.0.0.1" in s or "reject" in s.lower() or "refuse" in s.lower():
                        continue
                    if "verify=False" in s.replace(" ", ""):
                        insecure_net.append(rel)
                        break
            if _CORS_WILD_RE.search(txt):
                cors_wildcards.append(rel)

    return {
        "files_scanned": files_scanned,
        "env_files": env_files,
        "secret_hits": secret_hits,
        "unsafe_sinks": unsafe_sinks,
        "raw_sqls": raw_sqls,
        "insecure_net": insecure_net,
        "cors_wildcards": cors_wildcards,
        "has_lock_or_pin": has_lock_or_pin,
        "readme_claims": readme_claims,
    }


def fetch_github_repo_to_temp(repo_url: str, dest_dir: Path, *, commit: str | None = None) -> tuple[Path, str]:
    """Клонирует публичный GitHub-репозиторий (`git clone --depth 1`) по закреплённому коммиту/ветке и возвращает `(path, commit_sha)`."""
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git|/.*)?$", repo_url.strip())
    if not m:
        raise ValueError(f"Unsupported repository URL (expected https://github.com/owner/repo): {repo_url}")
    owner, repo = m.group(1), m.group(2)
    clean_url = f"https://github.com/{owner}/{repo}.git"
    clone_dir = dest_dir / repo
    dest_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", "1", clean_url, str(clone_dir)]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if res.returncode == 0 and clone_dir.exists():
        if commit:
            subprocess.run(["git", "-C", str(clone_dir), "fetch", "--depth", "1", "origin", commit], capture_output=True, text=True, timeout=45)
            subprocess.run(["git", "-C", str(clone_dir), "checkout", commit], capture_output=True, text=True, timeout=30)
        sha_res = subprocess.run(["git", "-C", str(clone_dir), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=15)
        sha = sha_res.stdout.strip() if sha_res.returncode == 0 else (commit or "unknown")
        return clone_dir, sha

    # Резервный путь, если git недоступен
    api_zip = f"https://api.github.com/repos/{owner}/{repo}/zipball" + (f"/{commit}" if commit else "")
    req = urllib.request.Request(api_zip, headers={"User-Agent": "AIFaSecurity-Auditor/2.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read(50 * 1024 * 1024)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            rel = Path(member.filename)
            if ".." in rel.parts:
                continue
            target = dest_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(member))
    subs = [d for d in dest_dir.iterdir() if d.is_dir()]
    return (subs[0] if len(subs) == 1 else dest_dir), (commit or "zipball")


def audit_http_url(url: str) -> dict[str, Any]:
    """Неинвазивный аудит веб-сервиса/API по HTTP/HTTPS URL."""
    headers_res: dict[str, str] = {}
    status_code = 0
    cors_star = False
    cors_creds = False
    error_trace_leak = False

    req = urllib.request.Request(url, headers={"User-Agent": "AIFaSecurity-Auditor/1.0", "Origin": "https://untrusted-audit.example"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            status_code = int(resp.status)
            headers_res = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status_code = int(e.code)
        headers_res = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        body = e.read(65536).decode("utf-8", errors="replace")

    acao = headers_res.get("access-control-allow-origin", "")
    acac = headers_res.get("access-control-allow-credentials", "").lower() == "true"
    cors_star = acao.strip() == "*" or "untrusted-audit.example" in acao
    cors_creds = acac
    if "Traceback (most recent call last)" in body or "at Object.<anonymous>" in body:
        error_trace_leak = True

    sec_headers = [
        h for h in ("strict-transport-security", "x-content-type-options", "x-frame-options", "content-security-policy")
        if h in headers_res
    ]
    return {
        "url": url,
        "https": url.lower().startswith("https://"),
        "status_code": status_code,
        "security_headers": sec_headers,
        "cors_wildcard_or_reflected": cors_star,
        "cors_with_credentials": cors_star and cors_creds,
        "error_trace_leak": error_trace_leak,
    }


def probe_mcp_stdio(command: str) -> dict[str, Any]:
    """Подключается к любому MCP-серверу по stdio, проверяет initialize + tools/list + базовый fuzzing."""
    import shlex
    parts = shlex.split(command)
    proc = subprocess.Popen(
        parts,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdin and proc.stdout
    try:
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "AIFaSecurity", "version": "1.0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "__nonexistent_aifa_probe__", "arguments": {}}},
        ]
        for r in reqs:
            proc.stdin.write(json.dumps(r) + "\n")
        proc.stdin.flush()
        proc.stdin.close()

        lines = [json.loads(ln) for ln in proc.stdout.read().splitlines() if ln.strip().startswith("{")]
        by_id = {x.get("id"): x for x in lines if "id" in x}
        tools = ((by_id.get(2) or {}).get("result") or {}).get("tools") or []
        bad_call = by_id.get(3) or {}
        return {
            "ok": 1 in by_id and 2 in by_id,
            "tools_count": len(tools),
            "tool_names": [t.get("name") for t in tools],
            "unknown_tool_rejected": "error" in bad_call or bool((bad_call.get("result") or {}).get("isError")),
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()


def canonical_report_sha256(payload: dict[str, Any]) -> str:
    """Вычисляет детерминированный SHA-256 отпечаток результатов без эфемерных полей времени."""
    clone = {k: v for k, v in payload.items() if k not in ("elapsed_s", "report_sha256", "timestamp_utc", "cached", "attestation",
                                                   # служебные поля свежести (18.11, aifa_sec_bridge._honest) — не часть результата
                                                   "generated_at", "cache_age_hours", "stale", "honest_note",
                                                   # окружение прогона (ТОП-20 Сестры, п. 13) — для воспроизведения, не результат
                                                   "environment")}
    if "summary" in clone and isinstance(clone["summary"], dict):
        clone["summary"] = {sk: sv for sk, sv in clone["summary"].items() if sk != "report_sha256"}
    if "criteria" in clone:
        clone["criteria"] = [
            {
                "id": item.get("id"),
                "domain": item.get("domain"),
                "severity": item.get("severity"),
                "weight": item.get("weight"),
                "status": item.get("status"),
                "score": item.get("score"),
            }
            for item in clone["criteria"]
        ]
    raw = json.dumps(clone, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
