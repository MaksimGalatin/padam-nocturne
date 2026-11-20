# -*- coding: utf-8 -*-
"""CI/CD раннер для GitHub Action PADAM Agentic Shield (Apache-2.0)."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if (_REPO_ROOT / "padam").is_dir() and str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from padam import agentic_shield, safety, supply_chain_guard
from padam.memory import Memory
from padam.store import Store

_GRADE_ORDER = {"S": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="PADAM Agentic Shield CI/CD Scanner")
    p.add_argument("--url", default="")
    p.add_argument("--html-path", default="")
    p.add_argument("--mcp-config", default="")
    p.add_argument("--sarif-out", default="padam-agentic-shield.sarif")
    p.add_argument("--html-out", default="padam-supply-chain-checkup.html")
    p.add_argument("--min-grade", default="B")
    p.add_argument("--allow-localhost", action="store_true")
    args = p.parse_args(argv)

    mem = Memory(user_id="ci-runner", store=Store(":memory:"))
    try:
        sc_report = None
        if args.html_path:
            hp = Path(args.html_path)
            if not hp.exists():
                print(f"::error::HTML file not found: {hp}", file=sys.stderr)
                return 2
            sc_report = supply_chain_guard.analyze_supply_chain_snapshot(
                args.url or f"https://ci.local/{hp.name}",
                hp.read_text(encoding="utf-8", errors="replace"),
                memory=mem,
            )
        elif args.url:
            sc_report = supply_chain_guard.scan_url_supply_chain(
                args.url, memory=mem, allow_localhost=args.allow_localhost
            )
            if not sc_report.get("ok"):
                print(f"::error::Supply-chain scan failed: {sc_report.get('error')}", file=sys.stderr)
                return 2

        mcp_report = None
        if args.mcp_config:
            mp = Path(args.mcp_config)
            if mp.exists():
                mcp_report = agentic_shield.audit_mcp_tools(mem, str(mp), server_name=mp.stem)
                for f in mcp_report.get("findings") or []:
                    print(f"::warning title=MCP Security ({f.get('code')})::{f.get('detail')}")

        grade = (sc_report or {}).get("grade") or "S"
        score = int((sc_report or {}).get("score") if sc_report else 100)

        if sc_report:
            sarif = supply_chain_guard.supply_chain_to_sarif(
                sc_report, target_file=args.html_path or "index.html"
            )
            Path(args.sarif_out).write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
            if sc_report.get("html_report"):
                Path(args.html_out).write_text(sc_report["html_report"], encoding="utf-8")

        gh_out = os.environ.get("GITHUB_OUTPUT")
        if gh_out:
            with Path(gh_out).open("a", encoding="utf-8") as fh:
                fh.write(f"grade={grade}\n")
                fh.write(f"score={score}\n")
                fh.write(f"sarif_file={args.sarif_out}\n")
                fh.write(f"html_file={args.html_out}\n")

        summary = {
            "grade": grade,
            "score": score,
            "compliance": (sc_report or {}).get("compliance", {}),
            "findings_count": len((sc_report or {}).get("findings") or []),
            "mcp_findings": len((mcp_report or {}).get("findings") or []),
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))

        if mcp_report and not mcp_report.get("clean"):
            print("::error::MCP config or tool poisoning risks found.", file=sys.stderr)
            return 1
        req_grade = _GRADE_ORDER.get(str(args.min_grade or "B").upper(), 4)
        cur_grade = _GRADE_ORDER.get(str(grade).upper(), 1)
        if sc_report and cur_grade < req_grade:
            print(
                f"::error::Supply-Chain grade {grade} ({score}/100) is below required minimum {args.min_grade}.",
                file=sys.stderr,
            )
            return 1
        return 0
    finally:
        mem.close()


if __name__ == "__main__":
    raise SystemExit(main())
