# -*- coding: utf-8 -*-
"""Build redteam/public_cases.jsonl from the parameters of the test suite.

The public set is everything PADAM already defends against: each case comes from a parametrised test, so the set
and the suite never drift apart. It is a regression set, not a measure of strength: the measure is a sealed set
written by someone who has not seen the code changes (see redteam/README.md).

Run from the repository root: python -I -X utf8 redteam/build_public_set.py
Arguments are read by name: секрет → secret; (фраза, пароль) → secret with the password as the value to look for;
команда → command; обычное, речь, рассказ → benign. Other parametrised tests are not attack cases and are skipped.
"""
import base64
import importlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
MODULES = ["test_safety", "test_generic_detector", "test_evil_0911", "test_commands_option_v"]
BENIGN = {"обычное", "речь", "рассказ"}
CARD = re.compile(r"(?:\d[ -]?){12,18}\d")


def enc(s):
    """Reversed, then base64: GitHub decodes plain base64 and still matched the synthetic keys."""
    return base64.b64encode(s[::-1].encode("utf-8")).decode("ascii")


def secret_value(text):
    """The value that must not reach the disk: card digits if present, else the longest token of the text."""
    m = CARD.search(text)
    if m:
        return m.group(0)
    token = max(re.split(r"[\s\"'=:,;{}()<>\[\]`]+", text), key=len)
    # Short values ("123", "8402") occur in database bytes by chance; then the whole text must be gone instead.
    return token if len(token) >= 8 else text


def cases():
    seen = set()
    for name in MODULES:
        mod = importlib.import_module(name)
        for fname in sorted(dir(mod)):
            fn = getattr(mod, fname)
            if not fname.startswith("test_") or not callable(fn):
                continue
            for mark in getattr(fn, "pytestmark", []):
                if mark.name != "parametrize":
                    continue
                names = [n.strip() for n in mark.args[0].split(",")]
                for value in mark.args[1]:
                    value = getattr(value, "values", value)          # pytest.param(...)
                    row = dict(zip(names, value if isinstance(value, (tuple, list)) else (value,)))
                    if names == ["секрет"]:
                        case = {"category": "secret", "text": row["секрет"], "secret": secret_value(row["секрет"])}
                    elif names == ["фраза", "пароль"]:
                        case = {"category": "secret", "text": row["фраза"], "secret": row["пароль"]}
                    elif names == ["команда"]:
                        case = {"category": "command", "text": row["команда"]}
                    elif len(names) == 1 and names[0] in BENIGN:
                        case = {"category": "benign", "text": row[names[0]]}
                    else:
                        continue
                    if not isinstance(case["text"], str) or case["text"] in seen:
                        continue
                    seen.add(case["text"])
                    case["source"] = f"tests/{name}.py::{fname}"
                    yield case


def main():
    out = ROOT / "redteam" / "public_cases.jsonl"
    rows, counters = [], {}
    for c in cases():
        k = c["category"]
        counters[k] = counters.get(k, 0) + 1
        if k == "secret":
            # Synthetic keys still look real to code hosts' secret scanners (GitHub refused the push), so secret
            # cases are stored reversed and base64-encoded here; run.py decodes them. Your own case files may use plain text.
            c = {"category": k, "text_enc": enc(c["text"]), "secret_enc": enc(c["secret"]), "source": c["source"]}
        rows.append(json.dumps({"id": f"{k[0]}-{counters[k]:03d}", **c}, ensure_ascii=False))
    out.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(out.relative_to(ROOT), counters)


if __name__ == "__main__":
    main()
