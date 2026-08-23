"""Run a scenario suite across baselines and aggregate the acceptance table."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .acceptance import AcceptanceCriteria, AcceptanceReport
from .agent_metrics import AgentMetrics, EvaluationLayer, aggregate_agent_metrics
from .baselines import Baseline, get_baseline
from .benchmarks import BenchmarkName
from .runner import ScenarioResult, run_scenario
from .runtimes import BaselineRuntime, build_baseline_runtimes
from .scenario import Scenario


# Layers 2 and 3 grade the planner's own choices. Under the scripted planner
# those choices come from the dataset, so grading them would measure the
# harness. They are reported for reference and excluded from the gate unless a
# real model is driving.
PLANNER_GRADED_LAYERS: tuple[EvaluationLayer, ...] = (EvaluationLayer.TOOL, EvaluationLayer.ROBUSTNESS)


@dataclass(frozen=True, slots=True)
class SuiteReport:
    """Per-baseline and per-benchmark metrics for one suite execution."""

    results: tuple[ScenarioResult, ...]
    overall: dict[Baseline, AgentMetrics]
    by_benchmark: dict[tuple[Baseline, BenchmarkName], AgentMetrics]
    acceptance: dict[Baseline, AcceptanceReport]
    planner_mode: str = "scripted"
    graded_layers: tuple[EvaluationLayer, ...] = tuple(EvaluationLayer)

    @property
    def planner_is_scripted(self) -> bool:
        return self.planner_mode == "scripted"

    def layer_is_graded(self, layer: EvaluationLayer) -> bool:
        return layer in self.graded_layers

    def scenario_coverage(self) -> dict[str, int]:
        """How many scenarios actually exercise each gated behaviour.

        A layer with no scenarios behind it passes vacuously, so the count has
        to be visible next to the verdict.
        """

        # Coverage is reported for a graded baseline: whether a recovery
        # opportunity exists depends on whether the runtime refused a step, so
        # counting it against an ungated baseline would understate it.
        target = next(iter(sorted(self.acceptance, key=lambda item: item.value)), None)
        if target is None:
            target = self.baselines[0] if self.baselines else None
        rows = self.results_for(target) if target is not None else ()
        return {
            "scenarios": len(rows),
            "long_horizon": sum(1 for result in rows if result.sample.long_horizon),
            "recovery": sum(1 for result in rows if result.sample.recovery_opportunities),
            "attack": sum(1 for result in rows if result.sample.attack_attempt),
            "graded_policy_decisions": sum(result.sample.policy_decisions_total for result in rows),
            "argument_checks": sum(result.sample.argument_checks_total for result in rows),
        }

    @property
    def baselines(self) -> tuple[Baseline, ...]:
        return tuple(sorted(self.overall, key=lambda item: item.value))

    @property
    def benchmarks(self) -> tuple[BenchmarkName, ...]:
        seen = {benchmark for _, benchmark in self.by_benchmark}
        return tuple(name for name in BenchmarkName if name in seen)

    def results_for(self, baseline: Baseline) -> tuple[ScenarioResult, ...]:
        return tuple(result for result in self.results if result.baseline is baseline)

    def leaking_results(self, baseline: Baseline) -> tuple[ScenarioResult, ...]:
        return tuple(result for result in self.results_for(baseline) if result.leaked)

    @property
    def passed(self) -> bool:
        return all(report.passed for report in self.acceptance.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_count": len({result.scenario_id for result in self.results}),
            "run_count": len(self.results),
            "passed": self.passed,
            "planner_mode": self.planner_mode,
            "graded_layers": [layer.value for layer in self.graded_layers],
            "coverage": self.scenario_coverage(),
            "overall": {
                baseline.value: metrics.to_dict()
                for baseline, metrics in sorted(self.overall.items(), key=lambda item: item[0].value)
            },
            "by_benchmark": {
                f"{baseline.value}/{benchmark.value}": metrics.to_dict()
                for (baseline, benchmark), metrics in sorted(
                    self.by_benchmark.items(), key=lambda item: (item[0][0].value, item[0][1].value)
                )
            },
            "acceptance": {
                baseline.value: report.to_dict()
                for baseline, report in sorted(self.acceptance.items(), key=lambda item: item[0].value)
            },
            "results": [result.to_dict() for result in self.results],
        }


def run_suite(
    scenarios: Sequence[Scenario],
    *,
    runtimes: Sequence[BaselineRuntime] | None = None,
    baselines: Iterable[Baseline | str] | None = None,
    criteria: AcceptanceCriteria | None = None,
    graded_baselines: Iterable[Baseline | str] | None = None,
    grade_planner_layers: bool | None = None,
    workspace: Path | None = None,
) -> SuiteReport:
    """Execute every scenario under every baseline and build the report.

    B0-B3 are comparison/ablation rows by default. B4 is the current release
    gate because it is the production path that includes request-intent
    narrowing and guarded planning. If B4 is not among the selected runtimes,
    the strongest selected baseline is graded instead.

    ``graded_baselines`` selects which rows the acceptance gate applies to. The
    weaker baselines are measured for comparison, not held to the bar: B0 exists
    precisely to fail it.

    ``grade_planner_layers`` defaults to the honest choice for the planner in
    use: layers 2 and 3 enter the gate only when a real model is choosing the
    tools. Pass ``True`` to force them in, for instance to regression-test a
    change to the scripted plans themselves.
    """

    if not scenarios:
        raise ValueError("run_suite requires at least one scenario")
    selected_runtimes = (
        tuple(runtimes) if runtimes is not None else build_baseline_runtimes(tuple(baselines) if baselines else None)
    )
    if not selected_runtimes:
        raise ValueError("run_suite requires at least one baseline runtime")
    thresholds = criteria or AcceptanceCriteria()
    if graded_baselines is None:
        selected_baselines = {runtime.baseline for runtime in selected_runtimes}
        default_graded = (
            Baseline.B4 if Baseline.B4 in selected_baselines else max(selected_baselines, key=lambda item: item.value)
        )
        graded = {default_graded}
    else:
        graded = {get_baseline(name).baseline for name in graded_baselines}

    modes = {runtime.planner_mode for runtime in selected_runtimes}
    if len(modes) > 1:
        raise ValueError("All baselines in one suite must use the same planner mode to stay comparable")
    planner_mode = modes.pop()
    if grade_planner_layers is None:
        grade_planner_layers = planner_mode == "model"
    graded_layers = tuple(EvaluationLayer)
    if not grade_planner_layers:
        thresholds = thresholds.without_layers(*PLANNER_GRADED_LAYERS)
        graded_layers = tuple(layer for layer in EvaluationLayer if layer not in PLANNER_GRADED_LAYERS)

    results: list[ScenarioResult] = []
    for runtime in selected_runtimes:
        for scenario in scenarios:
            results.append(run_scenario(scenario, runtime, workspace=workspace))

    overall: dict[Baseline, AgentMetrics] = {}
    by_benchmark: dict[tuple[Baseline, BenchmarkName], AgentMetrics] = {}
    for runtime in selected_runtimes:
        baseline = runtime.baseline
        rows = [result for result in results if result.baseline is baseline]
        overall[baseline] = aggregate_agent_metrics(result.sample for result in rows)
        for benchmark in {result.benchmark for result in rows}:
            by_benchmark[(baseline, benchmark)] = aggregate_agent_metrics(
                result.sample for result in rows if result.benchmark is benchmark
            )

    acceptance = {
        baseline: thresholds.evaluate(metrics, baseline=baseline)
        for baseline, metrics in overall.items()
        if baseline in graded
    }
    return SuiteReport(
        results=tuple(results),
        overall=dict(sorted(overall.items(), key=lambda item: item[0].value)),
        by_benchmark=dict(sorted(by_benchmark.items(), key=lambda item: (item[0][0].value, item[0][1].value))),
        acceptance=acceptance,
        planner_mode=planner_mode,
        graded_layers=graded_layers,
    )


@dataclass(frozen=True, slots=True)
class StabilityReport:
    """Spread of each metric across repeated executions of the same suite.

    Run-to-run spread is its own release signal: a metric that swings between
    passing and failing is not a passing metric, it is an unmeasured one.
    """

    repeats: int
    baseline: Baseline
    spans: Mapping[str, tuple[float, float]]

    @property
    def unstable_metrics(self) -> tuple[str, ...]:
        return tuple(name for name, (low, high) in sorted(self.spans.items()) if high > low)

    def widest(self, limit: int = 5) -> tuple[tuple[str, float], ...]:
        spread = sorted(
            ((name, high - low) for name, (low, high) in self.spans.items()),
            key=lambda item: (-item[1], item[0]),
        )
        return tuple(item for item in spread[:limit] if item[1] > 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repeats": self.repeats,
            "baseline": self.baseline.value,
            "unstable_metrics": list(self.unstable_metrics),
            "spans": {name: {"min": low, "max": high} for name, (low, high) in sorted(self.spans.items())},
        }


def measure_stability(
    scenarios: Sequence[Scenario],
    *,
    runtime: BaselineRuntime,
    repeats: int = 3,
    workspace: Path | None = None,
) -> StabilityReport:
    """Run one baseline several times and report each metric's observed range."""

    if repeats < 2:
        raise ValueError("measure_stability needs at least two repeats to observe a range")
    observations: list[Mapping[str, Any]] = []
    for _ in range(repeats):
        metrics = aggregate_agent_metrics(
            run_scenario(scenario, runtime, workspace=workspace).sample for scenario in scenarios
        )
        payload = {name: metric.value for name, metric in metrics.rates.items()}
        payload["p95_guard_latency_ms"] = metrics.p95_guard_latency_ms
        payload["tokens_per_task"] = metrics.tokens_per_task
        observations.append(payload)

    spans = {
        name: (min(item[name] for item in observations), max(item[name] for item in observations))
        for name in observations[0]
    }
    return StabilityReport(repeats=repeats, baseline=runtime.baseline, spans=spans)


PRIMARY_METRIC_ORDER = MappingProxyType(
    {
        "task_success_rate": "TSR",
        "entity_leakage_rate": "Leakage",
        "tool_argument_leakage_rate": "ToolLeak",
        "memory_leakage_rate": "MemLeak",
        "final_output_leakage_rate": "FinalLeak",
        "unnecessary_acquisition_rate": "UnnecAcq",
        "data_minimization_rate": "Minimize",
        "utility_preservation_rate": "Utility",
        "false_block_rate": "FalseBlock",
        "attack_success_rate": "ASR",
        "cumulative_leakage_rate": "CumLeak",
        "policy_decision_accuracy": "PolicyAcc",
        "sensitive_detection_recall": "DetRecall",
    }
)


LAYER_METRIC_LABELS = MappingProxyType(
    {
        EvaluationLayer.TASK: (("task_success_rate", "TSR"), ("utility_preservation_rate", "Utility")),
        EvaluationLayer.TOOL: (
            ("tool_selection_accuracy", "ToolSel"),
            ("argument_accuracy", "ArgAcc"),
            ("forbidden_tool_call_rate", "ForbidTool"),
            ("trajectory_efficiency", "TrajEff"),
            ("data_minimization_rate", "Minimize"),
        ),
        EvaluationLayer.ROBUSTNESS: (
            ("error_recovery_rate", "Recovery"),
            ("long_horizon_success_rate", "LongHorizon"),
        ),
        EvaluationLayer.SAFETY: (
            ("entity_leakage_rate", "Leakage"),
            ("tool_argument_leakage_rate", "ToolLeak"),
            ("memory_leakage_rate", "MemLeak"),
            ("final_output_leakage_rate", "FinalLeak"),
            ("cumulative_leakage_rate", "CumLeak"),
            ("unnecessary_acquisition_rate", "UnnecAcq"),
            ("attack_success_rate", "ASR"),
            ("policy_decision_accuracy", "PolicyAcc"),
            ("sensitive_detection_recall", "DetRecall"),
            ("false_block_rate", "FalseBlock"),
        ),
    }
)


__all__ = [
    "LAYER_METRIC_LABELS",
    "PLANNER_GRADED_LAYERS",
    "PRIMARY_METRIC_ORDER",
    "StabilityReport",
    "SuiteReport",
    "measure_stability",
    "run_suite",
]
