"""Offline model- and agent-layer evaluation for SensitiveGuard."""

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
from .entity_metrics import (
    EntityEvaluator,
    EntityMetrics,
    EntitySpan,
    PRFScore,
    evaluate_entities,
    evaluate_entity_corpus,
)


__all__ = [
    "BASELINES",
    "BENCHMARKS",
    "ZERO_DENOMINATOR_SEMANTICS",
    "ZERO_DENOMINATOR_VALUES",
    "AgentEvalSample",
    "AgentEvaluator",
    "AgentMetrics",
    "Baseline",
    "BaselineConfig",
    "BaselineName",
    "BenchmarkName",
    "BenchmarkSpec",
    "EntityEvaluator",
    "EntityMetrics",
    "EntitySpan",
    "MetricCount",
    "PRFScore",
    "aggregate_agent_metrics",
    "evaluate_entities",
    "evaluate_entity_corpus",
    "get_baseline",
    "get_benchmark",
    "list_baselines",
    "list_benchmarks",
]
