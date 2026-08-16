"""Offline model- and agent-layer evaluation for SensitiveGuard.

Two layers live here. The metric primitives (``AgentEvalSample``,
``EntityMetrics``) define what is measured; the benchmark harness
(``Scenario``, ``run_suite``, ``AcceptanceCriteria``) actually produces those
measurements by running scenarios against executable B0-B3 baselines and
comparing recorded sink traffic to planted ground truth.

Run the shipped acceptance suite with ``python -m sensitiveguard.eval``.
"""

from .acceptance import AcceptanceCriteria, AcceptanceReport, Threshold, ThresholdFailure
from .agent_metrics import (
    ZERO_DENOMINATOR_SEMANTICS,
    ZERO_DENOMINATOR_VALUES,
    AgentEvalSample,
    AgentEvaluator,
    AgentMetrics,
    MetricCount,
    aggregate_agent_metrics,
)
from .baselines import BASELINES, Baseline, BaselineConfig, BaselineName, get_baseline, list_baselines
from .benchmarks import BENCHMARKS, BenchmarkName, BenchmarkSpec, get_benchmark, list_benchmarks
from .capture import BaselineCapture, LatencyProbe, ObservedDecision
from .datasets import SEED_SUITE_PATH, load_seed_suite
from .entity_metrics import (
    EntityEvaluator,
    EntityMetrics,
    EntitySpan,
    PRFScore,
    evaluate_entities,
    evaluate_entity_corpus,
)
from .report import render_baseline_table, render_benchmark_table, render_report
from .runner import ScenarioResult, encountered_canaries, run_scenario, run_scenarios, score_run
from .runtimes import (
    BaselineRuntime,
    RunTrace,
    ScriptedPlanner,
    build_baseline_runtime,
    build_baseline_runtimes,
    build_default_detector,
)
from .scenario import Canary, Scenario, ScenarioStep, Sink, load_scenarios, scenarios_by_benchmark
from .sinks import Leak, SinkRecord, SinkRecorder
from .suite import SuiteReport, run_suite
from .world import ScenarioWorld


__all__ = [
    "BASELINES",
    "BENCHMARKS",
    "SEED_SUITE_PATH",
    "ZERO_DENOMINATOR_SEMANTICS",
    "ZERO_DENOMINATOR_VALUES",
    "AcceptanceCriteria",
    "AcceptanceReport",
    "AgentEvalSample",
    "AgentEvaluator",
    "AgentMetrics",
    "Baseline",
    "BaselineCapture",
    "BaselineConfig",
    "BaselineName",
    "BaselineRuntime",
    "BenchmarkName",
    "BenchmarkSpec",
    "Canary",
    "EntityEvaluator",
    "EntityMetrics",
    "EntitySpan",
    "LatencyProbe",
    "Leak",
    "MetricCount",
    "ObservedDecision",
    "PRFScore",
    "RunTrace",
    "Scenario",
    "ScenarioResult",
    "ScenarioStep",
    "ScenarioWorld",
    "ScriptedPlanner",
    "Sink",
    "SinkRecord",
    "SinkRecorder",
    "SuiteReport",
    "Threshold",
    "ThresholdFailure",
    "aggregate_agent_metrics",
    "build_baseline_runtime",
    "build_baseline_runtimes",
    "build_default_detector",
    "encountered_canaries",
    "evaluate_entities",
    "evaluate_entity_corpus",
    "get_baseline",
    "get_benchmark",
    "list_baselines",
    "list_benchmarks",
    "load_scenarios",
    "load_seed_suite",
    "render_baseline_table",
    "render_benchmark_table",
    "render_report",
    "run_scenario",
    "run_scenarios",
    "run_suite",
    "scenarios_by_benchmark",
    "score_run",
]
