# -*- coding: utf-8 -*-
"""Forget across agents: agent A reads a preference, the owner deletes it, A reconnects — does recall drop it?

Suggested by @jul1anodev (14 Nov 2026). Real processes only: two MCP servers over stdio (agents A and B) on one
SQLite file, the owner in a separate process.  Run:  python examples/forget_two_agents.py
Uses the padam installed in this Python (pip install padam-nocturne); from a source checkout: PYTHONPATH=. python ...
(Прогон 26.11.2026: одинаковый итог на PADAM 0.8.0 из установленного пакета и на 0.9.1 из исходников.)"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import tempfile
ПАПКА = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="padam_forget_"))
ПАПКА.mkdir(parents=True, exist_ok=True)
БАЗА = ПАПКА / f"juliano_{int(time.time())}.db"
PY = sys.executable
ОКР = {**os.environ, "PADAM_DB": str(БАЗА), "PADAM_USER": "owner", "PADAM_EMBEDDER": "builtin"}
ЗНАЧЕНИЕ = "The owner's favourite code editor is Helix"
ЗАПРОС = "favourite code editor"
журнал: list[str] = []


def лог(s: str) -> None:
    print(s, flush=True)
    журнал.append(s)


def владелец(код: str) -> str:
    p = subprocess.run([PY, "-X", "utf8", "-I", "-c", код], env=ОКР, capture_output=True, text=True,
                       encoding="utf-8", timeout=120)
    if p.returncode != 0:
        raise SystemExit(p.stderr[-2000:])
    return p.stdout.strip()


class Агент:
    def __init__(self, имя: str):
        self.имя = имя
        self.p = subprocess.Popen([PY, "-X", "utf8", "-I", "-m", "padam.mcp_server"],
                                  env={**ОКР, "PADAM_AGENT_ID": имя}, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                "clientInfo": {"name": имя, "version": "1"}})

    def rpc(self, метод: str, params: dict) -> dict:
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": метод, "params": params}) + "\n")
        self.p.stdin.flush()
        while True:
            строка = self.p.stdout.readline()
            if not строка:
                raise SystemExit(f"{self.имя}: сервер закрылся")
            o = json.loads(строка)
            if o.get("id") == self.n:
                return o

    def вызов(self, инструмент: str, аргументы: dict) -> dict:
        return self.rpc("tools/call", {"name": инструмент, "arguments": аргументы})

    def видит(self) -> bool:
        r = self.вызов("padam_search", {"query": ЗАПРОС, "limit": 5})
        текст = json.dumps(r, ensure_ascii=False)
        return "Helix" in текст

    def закрыть(self) -> None:
        self.p.stdin.close()
        self.p.wait(timeout=30)


import padam  # noqa: E402  (версия пакета, которым идёт проверка)
лог(f"PADAM {padam.__version__} · db {БАЗА.name}")

# 1. Владелец сохраняет предпочтение (его запись не уходит на проверку).
rid = владелец(
    "from padam.memory import Memory\nfrom padam.store import Store\nimport os\n"
    f"m=Memory(user_id='owner', store=Store(os.environ['PADAM_DB']))\n_, rid=m.remember({ЗНАЧЕНИЕ!r}, kind='preference')\nprint(rid)"
).splitlines()[-1]
лог(f"1. owner stored a preference: {rid}")

# 2. Агент A читает его.
a = Агент("agent_a")
лог(f"2. agent A finds 'Helix': {a.видит()}")

# 3. Агент B пробует удалить через MCP — в PADAM удаление только у владельца.
b = Агент("agent_b")
r = b.вызов("forget", {"id": rid})
отказ = r.get("error") or (r.get("result") or {}).get("isError")
лог(f"3. agent B calling forget over MCP is refused: {bool(отказ)} ({json.dumps(r.get('error') or '', ensure_ascii=False)[:120]})")
лог(f"   agent B also finds 'Helix': {b.видит()}")

# 4. Владелец забывает запись (то же, что `padam forget <id>`).
вывод = владелец(
    "from padam.memory import Memory\nfrom padam.store import Store\nimport os,json\n"
    f"m=Memory(user_id='owner', store=Store(os.environ['PADAM_DB']))\nok=m.revoke({rid!r})\n"
    "rc=getattr(m,'_last_receipt',None) or {}\nprint(json.dumps({'ok':bool(ok),'receipt':rc.get('receipt_id') if isinstance(rc,dict) else None}))"
).splitlines()[-1]
лог(f"4. owner forgot the record (same as `padam forget <id>`): {вывод}")

# 5. Агент A без переподключения (живой процесс, его кэш) ищет снова.
лог(f"5. agent A, same process, finds 'Helix': {a.видит()}")
a.закрыть()

# 6. Агент A переподключается — новый процесс сервера.
a2 = Агент("agent_a")
лог(f"6. agent A after reconnecting finds 'Helix': {a2.видит()}")
лог(f"   agent B, still running, finds 'Helix': {b.видит()}")
a2.закрыть(); b.закрыть()

# 7. В файле базы не осталось текста.
сырые = БАЗА.read_bytes()
for суффикс in ("-wal", "-shm"):
    f = Path(str(БАЗА) + суффикс)
    if f.exists():
        сырые += f.read_bytes()
лог(f"7. bytes 'Helix' left in the database file (incl. WAL): {сырые.count(b'Helix')}")

(ПАПКА / "result.txt").write_text("\n".join(журнал) + "\n", encoding="utf-8")
