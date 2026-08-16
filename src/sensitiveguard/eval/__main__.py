"""Command line entry point: ``python -m sensitiveguard.eval``.

Runs the shipped acceptance suite across the B0-B3 baselines, prints the
comparison table, and exits non-zero when a graded baseline misses the bar so
the same command works as a CI gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .acceptance import AcceptanceCriteria
from .baselines import Baseline
from .benchmarks import BenchmarkName
from .datasets import SEED_SUITE_PATH, load_seed_suite
from .report import render_report
from .runtimes import build_baseline_runtimes
from .scenario import Scenario, load_scenarios
from .suite import measure_stability, run_suite


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m sensitiveguard.eval",
        description="Run the SensitiveGuard benchmark suite and print the acceptance table.",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help=f"JSONL scenario file (default: the shipped seed suite at {SEED_SUITE_PATH.name})",
    )
    parser.add_argument(
        "--baseline",
        action="append",
        choices=[item.value for item in Baseline],
        help="Baseline to run; repeat for several (default: all of B0-B3)",
    )
    parser.add_argument(
        "--benchmark",
        action="append",
        choices=[item.value for item in BenchmarkName],
        help="Restrict the run to one or more benchmarks (default: all)",
    )
    parser.add_argument(
        "--graded",
        action="append",
        choices=[item.value for item in Baseline],
        help="Baseline the acceptance thresholds apply to (default: B3)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "LiteLLM model id to drive the planner instead of the scripted plans. "
            "Required for the tool and robustness layers to grade an agent rather than the dataset."
        ),
    )
    parser.add_argument("--api-base", default=None, help="Base URL for --model, e.g. a local Ollama endpoint")
    parser.add_argument(
        "--grade-planner-layers",
        action="store_true",
        help="Force the tool and robustness layers into the gate even under the scripted planner",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=0,
        help="Re-run the graded baseline N times and report each metric's observed range",
    )
    parser.add_argument("--json", type=Path, default=None, help="Write the full machine-readable report here")
    parser.add_argument("--no-evidence", action="store_true", help="Omit the per-leak evidence section")
    parser.add_argument(
        "--no-gate",
        action="store_true",
        help="Always exit 0; report the verdict without failing the command",
    )
    return parser.parse_args(argv)


def _build_planner_model(args: argparse.Namespace) -> Any | None:
    if not args.model:
        return None
    from smolagents import LiteLLMModel

    options: dict[str, Any] = {"model_id": args.model, "temperature": 0.0}
    if args.api_base:
        options["api_base"] = args.api_base
    return LiteLLMModel(**options)


def _select_scenarios(args: argparse.Namespace) -> tuple[Scenario, ...]:
    scenarios = load_scenarios(args.dataset) if args.dataset else load_seed_suite()
    if args.benchmark:
        wanted = {BenchmarkName(name) for name in args.benchmark}
        scenarios = tuple(scenario for scenario in scenarios if scenario.benchmark in wanted)
    if not scenarios:
        raise SystemExit("No scenarios matched the requested filters.")
    return scenarios


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    scenarios = _select_scenarios(args)
    planner_model = _build_planner_model(args)
    runtimes = build_baseline_runtimes(args.baseline or None, planner_model=planner_model)
    graded = args.graded or (Baseline.B3,)
    report = run_suite(
        scenarios,
        runtimes=runtimes,
        criteria=AcceptanceCriteria(),
        graded_baselines=graded,
        grade_planner_layers=True if args.grade_planner_layers else None,
    )

    stability = None
    if args.repeat:
        target = next((runtime for runtime in runtimes if runtime.baseline in set(report.acceptance)), runtimes[-1])
        stability = measure_stability(scenarios, runtime=target, repeats=args.repeat)

    print(render_report(report, include_evidence=not args.no_evidence, stability=stability))
    if args.json:
        payload = report.to_dict()
        if stability is not None:
            payload["stability"] = stability.to_dict()
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nWrote {args.json}")
    if args.no_gate:
        return 0
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
