"""tfgate command line.

Exit codes: 0 = passed, 1 = failing findings or expired waivers, 2 = usage or input error.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date

from . import report
from .rules import RULES, Severity
from .scanner import load_plan, load_waivers, scan


def main(argv: list[str] | None = None, today: date | None = None) -> int:
    p = argparse.ArgumentParser(prog="tfgate", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a Terraform JSON plan")
    s.add_argument("plan", help="output of: terraform show -json plan.out")
    s.add_argument("--format", choices=["table", "json", "sarif"], default="table")
    s.add_argument("--fail-on", default="high", help="lowest severity that fails the gate")
    s.add_argument("--waivers", help="JSON file of approved, time-boxed exceptions")
    s.add_argument("--output", "-o", help="write the report to a file instead of stdout")

    sub.add_parser("rules", help="list rules and the controls they map to")

    args = p.parse_args(argv)

    if args.cmd == "rules":
        for r in RULES:
            print(f"{r.id:<11} {r.severity.name:<9} {','.join(r.controls):<14} {r.title}")
        return 0

    try:
        threshold = Severity.parse(args.fail_on)
        plan = load_plan(args.plan)
        active, expired = load_waivers(args.waivers, today or date.today())
    except (OSError, ValueError) as e:
        print(f"tfgate: {e}", file=sys.stderr)
        return 2

    result = scan(plan, active)
    result.expired_waivers = expired

    if args.format == "json":
        out = report.as_json(result, threshold)
    elif args.format == "sarif":
        out = report.as_sarif(result, args.plan)
    else:
        out = report.table(result, threshold)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(report.table(result, threshold))  # still show a summary in the CI log
    else:
        print(out)

    return 1 if result.failing(threshold) or expired else 0


if __name__ == "__main__":
    sys.exit(main())
