"""Run a scenario suite across baselines and aggregate the acceptance table."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .acceptance import AcceptanceCriteria, AcceptanceReport
from .agent_metrics import AgentMetrics, aggregate_agent_metrics
from .baselines import Baseline, get_baseline
from .benchmarks import BenchmarkName
from .runner import ScenarioResult, run_scenario
from .runtimes import BaselineRuntime, build_baseline_runtimes
from .scenario import Scenario


@dataclass(frozen=True, slots=True)
class SuiteReport:
    """Per-baseline and per-benchmark metrics for one suite execution."""

    results: tuple[ScenarioResult, ...]
    overall: dict[Baseline, AgentMetrics]
    by_benchmark: dict[tuple[Baseline, BenchmarkName], AgentMetrics]
    acceptance: dict[Baseline, AcceptanceReport]

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
    graded_baselines: Iterable[Baseline | str] = (Baseline.B4,),
    workspace: Path | None = None,
) -> SuiteReport:
    """Execute every scenario under every baseline and build the report.

    B0-B3 are comparison/ablation rows by default. B4 is the current release
    gate because it is the production path that includes request-intent
    narrowing and guarded planning.
    """

    if not scenarios:
        raise ValueError("run_suite requires at least one scenario")
    selected_runtimes = (
        tuple(runtimes) if runtimes is not None else build_baseline_runtimes(tuple(baselines) if baselines else None)
    )
    if not selected_runtimes:
        raise ValueError("run_suite requires at least one baseline runtime")
    thresholds = criteria or AcceptanceCriteria()
    graded = {get_baseline(name).baseline for name in graded_baselines}

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
    )


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


__all__ = ["PRIMARY_METRIC_ORDER", "SuiteReport", "run_suite"]
