"""``python -m sensitiveguard.eval`` — run the benchmarks from the command line.

    python -m sensitiveguard.eval list
    python -m sensitiveguard.eval run                 # all six, in order
    python -m sensitiveguard.eval run airgap-agent-r  # one of them
    python -m sensitiveguard.eval run --json report.json
    python -m sensitiveguard.eval lint                # every policy's structural lint

No arguments and no network: the bundled datasets run in well under a second, so
the command is meant to be run on every change, the way the policy self-tests are.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..policy.engine import PolicyEngine
from ..policy.loader import load_policy
from . import report
from .harness import POLICY_ROOT, get, registry


def _cmd_list(_: argparse.Namespace) -> int:
    benchmarks = registry()
    from .benchmarks import ORDER

    print("benchmarks (run in this order):")
    for name in ORDER:
        print(f"  {benchmarks[name].describe()}")
        print(f"                   upstream: {benchmarks[name].upstream}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    from .benchmarks import ORDER

    names = args.names or list(ORDER)
    results = []
    for name in names:
        benchmark = get(name)
        kwargs = {"limit": args.limit}
        if args.data and len(names) == 1:
            kwargs["data"] = args.data
        results.extend(benchmark.run(**kwargs))

    print(report.render(results))
    print()
    print(report.headline_table(results))

    if args.json:
        Path(args.json).write_text(report.to_json(results), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


def _cmd_lint(_: argparse.Namespace) -> int:
    status = 0
    for path in sorted(POLICY_ROOT.glob("*.yaml")):
        policy = load_policy(path, strict=False)
        findings = PolicyEngine(policy).lint()
        errors = [finding for finding in findings if finding.severity == "error"]
        warnings = [finding for finding in findings if finding.severity == "warning"]
        state = "FAIL" if errors else ("warn" if warnings else "ok")
        print(f"{policy.label:<32} {state:<5} {len(findings)} finding(s)")
        for finding in findings:
            print(f"    {finding.describe()}")
        if errors:
            status = 1
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sensitiveguard.eval", description=__doc__)
    sub = parser.add_subparsers(dest="command")

    list_parser = sub.add_parser("list", help="list the benchmarks")
    list_parser.set_defaults(func=_cmd_list)

    run_parser = sub.add_parser("run", help="run benchmarks")
    run_parser.add_argument("names", nargs="*", help="benchmark names; default is all, in order")
    run_parser.add_argument("--limit", type=int, default=None, help="cap the number of cases per benchmark")
    run_parser.add_argument("--data", type=str, default=None, help="override dataset path (single benchmark only)")
    run_parser.add_argument("--json", type=str, default=None, help="also write the full result as JSON here")
    run_parser.set_defaults(func=_cmd_run)

    lint_parser = sub.add_parser("lint", help="lint every bundled policy")
    lint_parser.set_defaults(func=_cmd_lint)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
