"""Render a suite report as the acceptance table a reviewer reads."""

from __future__ import annotations

from collections.abc import Sequence

from .baselines import get_baseline
from .suite import PRIMARY_METRIC_ORDER, SuiteReport


def _format_rate(value: float) -> str:
    return f"{value:.3f}"


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [len(column) for column in header]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = [
        "| " + " | ".join(column.ljust(widths[index]) for index, column in enumerate(header)) + " |",
        "|" + "|".join("-" * (width + 2) for width in widths) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)) + " |")
    return "\n".join(lines)


def render_baseline_table(report: SuiteReport) -> str:
    """One row per baseline: the B0-B3 comparison the design document asks for."""

    metrics = tuple(PRIMARY_METRIC_ORDER)
    header = ["Baseline", "Capabilities", *(PRIMARY_METRIC_ORDER[name] for name in metrics), "p95ms"]
    rows: list[list[str]] = []
    for baseline in report.baselines:
        aggregate = report.overall[baseline]
        config = get_baseline(baseline)
        rows.append(
            [
                f"{baseline.value} {config.display_name}",
                str(len(config.capabilities)),
                *(_format_rate(aggregate.rates[name].value) for name in metrics),
                f"{aggregate.p95_guard_latency_ms:.1f}",
            ]
        )
    return _table(header, rows)


def render_benchmark_table(report: SuiteReport) -> str:
    """One row per benchmark, showing each baseline's primary metric."""

    from .agent_metrics import ZERO_DENOMINATOR_VALUES
    from .benchmarks import get_benchmark

    baselines = report.baselines
    header = ["Benchmark", "Primary metric", *(baseline.value for baseline in baselines)]
    rows: list[list[str]] = []
    for benchmark in report.benchmarks:
        # A benchmark may list detector-layer metrics first; this table reports
        # the first metric the agent layer actually aggregates.
        primary = next(
            (name for name in get_benchmark(benchmark).primary_metrics if name in ZERO_DENOMINATOR_VALUES),
            "entity_leakage_rate",
        )
        cells: list[str] = []
        for baseline in baselines:
            aggregate = report.by_benchmark.get((baseline, benchmark))
            cells.append(_format_rate(aggregate.rates[primary].value) if aggregate else "-")
        rows.append([benchmark.value, primary, *cells])
    return _table(header, rows)


def render_leak_evidence(report: SuiteReport, *, limit: int = 20) -> str:
    """List the concrete values that escaped, so a failure is actionable."""

    lines: list[str] = []
    shown = 0
    for result in report.results:
        for leak in result.leaks:
            if shown >= limit:
                lines.append("... and more; see the JSON report for the full list")
                return "\n".join(lines)
            lines.append(
                f"  {result.baseline.value} {result.scenario_id}: "
                f"{leak.label} ({leak.canary_id}) reached {leak.sink.value} via {leak.tool}"
                + (f" -> {leak.target}" if leak.target else "")
            )
            shown += 1
    return "\n".join(lines) if lines else "  none"


def render_acceptance(report: SuiteReport) -> str:
    lines: list[str] = []
    for baseline in sorted(report.acceptance, key=lambda item: item.value):
        acceptance = report.acceptance[baseline]
        lines.append(f"  {acceptance.summary}")
    return "\n".join(lines) if lines else "  no baseline was graded"


def render_report(report: SuiteReport, *, include_evidence: bool = True) -> str:
    scenario_count = len({result.scenario_id for result in report.results})
    sections = [
        "# SensitiveGuard acceptance report",
        "",
        f"Scenarios: {scenario_count}    Runs: {len(report.results)}    "
        f"Verdict: {'PASS' if report.passed else 'FAIL'}",
        "",
        "## Baseline comparison",
        "",
        render_baseline_table(report),
        "",
        "## Per-benchmark primary metric",
        "",
        render_benchmark_table(report),
        "",
        "## Acceptance",
        "",
        render_acceptance(report),
    ]
    if include_evidence:
        sections.extend(["", "## Leak evidence", "", render_leak_evidence(report)])
    return "\n".join(sections)


__all__ = [
    "render_acceptance",
    "render_baseline_table",
    "render_benchmark_table",
    "render_leak_evidence",
    "render_report",
]
