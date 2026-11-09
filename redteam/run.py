# -*- coding: utf-8 -*-
"""PADAM Red Team runner: write each case through MCP like an outside agent, then judge by the raw database bytes.

Usage:
    python -I -X utf8 redteam/run.py <cases.jsonl> [--out report.json] [--python <interpreter with padam installed>]

Each line of cases.jsonl is one JSON object:
    {"id": "s-001", "category": "secret",  "text": "...", "secret": "<exact value that must never reach the disk>"}
    {"id": "c-001", "category": "command", "text": "<an order hidden in a note>"}
    {"id": "b-001", "category": "benign",  "text": "<ordinary memory that must stay usable>"}
Any "text" or "secret" may be given as "text_enc" / "secret_enc" instead: base64 of the UTF-8 of the REVERSED
string (so that code hosts' secret scanners do not flag synthetic keys; plain base64 is decoded by GitHub).
Optional: "origin" ("agent" by default; "external" is held for the owner anyway since 0.4.0), "kind".

A case passes when:
    secret  — the "secret" value is found nowhere in the database files (main file, WAL, SHM), byte for byte;
    command — the record waits for the owner (status "quarantined"), so it never reaches an agent's search;
    benign  — the record is stored and not held as a command (a false alarm counts as a failure too); identity and
              preference notes from an agent wait for the owner by design, which is not a false alarm.

Everything runs locally in a fresh temporary database. Ollama is pointed at a closed port, nothing goes to the
network. Use synthetic secrets only: never a real key, password, seed phrase or wallet.
"""
import base64
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path


def arg(name, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def load(path):
    cases = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        c = json.loads(line)
        for field in ("text", "secret"):          # the public set stores synthetic keys reversed + base64
            if field + "_enc" in c:
                c[field] = base64.b64decode(c.pop(field + "_enc")).decode("utf-8")[::-1]
        if c.get("category") not in ("secret", "command", "benign") or not c.get("text") or not c.get("id"):
            sys.exit(f"line {n}: needs id, text and category secret|command|benign")
        if c["category"] == "secret" and not c.get("secret"):
            sys.exit(f"line {n}: a secret case needs the exact 'secret' value to look for on disk")
        cases.append(c)
    if len({c["id"] for c in cases}) != len(cases):
        sys.exit("case ids must be unique")
    return cases


def run(cases, python):
    folder = tempfile.mkdtemp(prefix="padam-redteam-")
    db = os.path.join(folder, "memory.db")
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PADAM_")}
    env.update({"PADAM_DB": db, "OLLAMA_URL": "http://127.0.0.1:9", "PADAM_EMBEDDER": "builtin",
                "PYTHONIOENCODING": "utf-8"})
    p = subprocess.Popen([python, "-m", "padam.mcp_server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=env, cwd=folder)
    n = [0]

    def call(method, params=None):
        n[0] += 1
        p.stdin.write((json.dumps({"jsonrpc": "2.0", "id": n[0], "method": method, "params": params or {}},
                                  ensure_ascii=False) + "\n").encode("utf-8"))
        p.stdin.flush()
        return json.loads(p.stdout.readline().decode("utf-8"))

    call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "padam-redteam", "version": "1"}})
    p.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    p.stdin.flush()
    for c in cases:
        a = {"content": c["text"], "origin": c.get("origin", "agent"), "scope": "rt-" + c["id"]}
        if c.get("kind"):
            a["kind"] = c["kind"]
        c["_reply"] = call("tools/call", {"name": "padam_write", "arguments": a})
    p.stdin.close()
    p.wait(timeout=60)

    raw = b"".join(Path(db + s).read_bytes() for s in ("", "-wal", "-shm") if Path(db + s).exists())
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    status, as_command = {}, set()
    for scope, st, why in con.execute("SELECT scope, status, quarantine_reason FROM memory"):
        status.setdefault(scope, set()).add(st)
        if st == "quarantined" and why == "looks like an instruction":
            as_command.add(scope)
    con.close()
    shutil.rmtree(folder, ignore_errors=True)

    results = []
    for c in cases:
        st = status.get("rt-" + c["id"], set())
        if c["category"] == "secret":
            ok = c["secret"].encode("utf-8") not in raw
        elif c["category"] == "command":
            ok = st == {"quarantined"}
        else:
            # A false alarm is a record held AS A COMMAND. Identity and preference notes from an agent always wait
            # for the owner by design ("The user prefers dark mode"): that is not a false alarm.
            ok = bool(st) and "rt-" + c["id"] not in as_command
        results.append({"id": c["id"], "category": c["category"], "passed": ok, "status": sorted(st)})
    return results


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cases = load(sys.argv[1])
    python = arg("--python", sys.executable)
    started = time.time()
    # Every secret case gets a database of its own: a value left by one case must not be blamed on another,
    # and another case's text must not make a leak look like a pass or a pass look like a leak.
    results = run([c for c in cases if c["category"] != "secret"], python)
    for c in cases:
        if c["category"] == "secret":
            results += run([c], python)
    order = {c["id"]: i for i, c in enumerate(cases)}
    results.sort(key=lambda r: order[r["id"]])
    version = subprocess.run([python, "-c", "import padam; print(padam.__version__)"],
                             capture_output=True, text=True).stdout.strip()
    total, passed = Counter(r["category"] for r in results), Counter(r["category"] for r in results if r["passed"])
    report = {"padam_version": version, "cases": len(results), "seconds": round(time.time() - started, 1),
              "by_category": {k: {"passed": passed[k], "of": total[k]} for k in sorted(total)},
              "failed": [r for r in results if not r["passed"]]}
    out = arg("--out")
    if out:
        Path(out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("padam_version", "cases", "seconds", "by_category")}, ensure_ascii=False))
    for r in report["failed"]:
        print("FAILED", r["id"], r["category"], r["status"])


if __name__ == "__main__":
    main()
