"""B6 дорожной карты Сестры (19.11.2026): Plugin SDK — инструменты сообщества без форка репозитория.

Плагин — папка в PADAM_HOME/plugins/<имя>/ с двумя файлами:
  plugin.json  — {"name", "version", "entry": "plugin.py", "capabilities": ["memory:read"], "description"}
  plugin.py    — функция register(api), где api.register_tool(имя, функция, описание) и api.search(запрос, limit)

Правила доверия (честно):
* Плагин загружается ТОЛЬКО после одобрения владельца (`padam plugin approve <имя>`). Одобрение закрепляется
  отпечатком SHA-256 манифеста и кода: изменился хоть байт — плагин не грузится, пока владелец не одобрит снова.
* Права (capabilities) пока одни: memory:read. Любое другое право — отказ при загрузке.
* Плагин получает только фасад: поиск, который отдаёт КОПИИ записей (id, kind, content), и регистрацию своих
  инструментов. Запись, забвение, деньги, ключи — недоступны через фасад.
* Это НЕ песочница против злонамеренного кода: Python не даёт такой изоляции. Защита — одобрение владельца,
  привязанное к отпечатку кода. Чужой плагин читайте перед одобрением.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
from typing import Any, Callable

РАЗРЕШЁННЫЕ_ПРАВА = {"memory:read"}
_ИМЯ = re.compile(r"^[a-z0-9][a-z0-9_\-]{1,40}$")


def plugins_dir() -> Path:
    base = os.environ.get("PADAM_PLUGINS_DIR") or os.path.join(
        os.environ.get("PADAM_HOME") or os.path.join(os.path.expanduser("~"), ".padam"), "plugins")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _approvals_file() -> Path:
    return plugins_dir() / "approved.json"


def _approvals() -> dict[str, str]:
    try:
        return json.loads(_approvals_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _manifest(folder: Path) -> dict[str, Any]:
    m = json.loads((folder / "plugin.json").read_text(encoding="utf-8"))
    name = str(m.get("name") or "")
    if not _ИМЯ.match(name) or name != folder.name:
        raise ValueError(f"имя плагина должно совпадать с папкой и быть вида a-z0-9_-: {name!r}")
    entry = str(m.get("entry") or "plugin.py")
    if "/" in entry or "\\" in entry or ".." in entry:
        raise ValueError("entry — только имя файла в папке плагина")
    caps = list(m.get("capabilities") or [])
    лишние = [c for c in caps if c not in РАЗРЕШЁННЫЕ_ПРАВА]
    if лишние:
        raise ValueError(f"неподдерживаемые права: {лишние}; разрешено только {sorted(РАЗРЕШЁННЫЕ_ПРАВА)}")
    m["entry"] = entry
    m["capabilities"] = caps
    return m


def fingerprint(folder: Path) -> str:
    m = json.loads((folder / "plugin.json").read_text(encoding="utf-8"))
    h = hashlib.sha256()
    h.update((folder / "plugin.json").read_bytes())
    h.update((folder / str(m.get("entry") or "plugin.py")).read_bytes())
    return h.hexdigest()


def list_plugins() -> list[dict[str, Any]]:
    out = []
    ok = _approvals()
    for f in sorted(p for p in plugins_dir().iterdir() if p.is_dir()):
        item: dict[str, Any] = {"name": f.name}
        try:
            m = _manifest(f)
            fp = fingerprint(f)
            item.update(version=m.get("version", ""), description=m.get("description", ""),
                        capabilities=m["capabilities"], fingerprint=fp[:16])
            item["state"] = ("approved" if ok.get(f.name) == fp else
                             "changed_since_approval" if f.name in ok else "not_approved")
        except Exception as exc:
            item.update(state="invalid", error=str(exc)[:200])
        out.append(item)
    return out


def approve(name: str) -> dict[str, Any]:
    folder = plugins_dir() / name
    _manifest(folder)
    ok = _approvals()
    ok[name] = fingerprint(folder)
    _approvals_file().write_text(json.dumps(ok, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"approved": name, "fingerprint": ok[name][:16]}


def revoke(name: str) -> dict[str, Any]:
    ok = _approvals()
    was = ok.pop(name, None) is not None
    _approvals_file().write_text(json.dumps(ok, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"revoked": name, "was_approved": was}


class PluginAPI:
    """Фасад для плагина: только чтение памяти копиями и регистрация своих инструментов."""

    __slots__ = ("_search", "_tools", "_plugin")

    def __init__(self, plugin: str, search_fn: Callable[[str, int], list[dict]]):
        self._plugin = plugin
        self._search = search_fn
        self._tools: dict[str, dict[str, Any]] = {}

    def search(self, query: str, limit: int = 5) -> list[dict]:
        return self._search(str(query), max(1, min(int(limit), 20)))

    def register_tool(self, name: str, fn: Callable[[dict], Any], description: str = "") -> None:
        if not _ИМЯ.match(str(name)):
            raise ValueError(f"имя инструмента вида a-z0-9_-: {name!r}")
        self._tools[f"{self._plugin}.{name}"] = {"fn": fn, "description": str(description)[:300]}


def load_approved(memory) -> dict[str, dict[str, Any]]:
    """Загружает только одобренные плагины с неизменённым кодом. Возвращает {«плагин.инструмент»: {...}}."""
    def _search(q: str, limit: int) -> list[dict]:
        return [{"id": r.id, "kind": r.kind, "content": r.content} for r in memory.recall(q, limit=limit)]

    tools: dict[str, dict[str, Any]] = {}
    ok = _approvals()
    for f in sorted(p for p in plugins_dir().iterdir() if p.is_dir()):
        if ok.get(f.name) is None:
            continue
        try:
            m = _manifest(f)
            if fingerprint(f) != ok[f.name]:
                continue                      # код изменён после одобрения — не грузим
            spec = importlib.util.spec_from_file_location(f"padam_plugin_{f.name.replace('-', '_')}", f / m["entry"])
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            api = PluginAPI(f.name, _search)
            mod.register(api)
            tools.update(api._tools)
        except Exception:
            continue                          # сломанный плагин не роняет память
    return tools


def run_tool(memory, full_name: str, args: dict | None = None) -> Any:
    tools = load_approved(memory)
    if full_name not in tools:
        raise KeyError(f"нет одобренного инструмента {full_name}")
    return tools[full_name]["fn"](dict(args or {}))
