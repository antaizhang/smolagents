"""Canonical benchmark taxonomy from the SensitiveGuard design."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any


class BenchmarkName(str, Enum):
    PII_DETECT = "PII-Detect"
    PII_MINIMIZE = "PII-Minimize"
    PII_EGRESS = "PII-Egress"
    PII_RAG = "PII-RAG"
    PII_MEMORY = "PII-Memory"
    PII_TOOL = "PII-Tool"
    PII_INJECTION = "PII-Injection"
    PII_TRAJECTORY = "PII-Trajectory"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class BenchmarkSpec:
    name: BenchmarkName
    objective: str
    primary_metrics: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.name, BenchmarkName):
            try:
                object.__setattr__(self, "name", BenchmarkName(self.name))
            except (TypeError, ValueError):
                raise ValueError("BenchmarkSpec.name is not a supported benchmark") from None
        if not isinstance(self.objective, str) or not self.objective.strip():
            raise ValueError("BenchmarkSpec.objective must be a non-empty string")
        object.__setattr__(self, "objective", self.objective.strip())
        if isinstance(self.primary_metrics, str):
            metrics = (self.primary_metrics,)
        else:
            metrics = tuple(self.primary_metrics)
        if not metrics or any(not isinstance(metric, str) or not metric.strip() for metric in metrics):
            raise ValueError("BenchmarkSpec.primary_metrics must contain non-empty metric names")
        normalized = tuple(metric.strip() for metric in metrics)
        if len(normalized) != len(set(normalized)):
            raise ValueError("BenchmarkSpec.primary_metrics must not contain duplicates")
        object.__setattr__(self, "primary_metrics", normalized)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "objective": self.objective,
            "primary_metrics": list(self.primary_metrics),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> BenchmarkSpec:
        if not isinstance(value, Mapping):
            raise TypeError("BenchmarkSpec.from_dict expects a mapping")
        return cls(**dict(value))


BENCHMARKS = MappingProxyType(
    {
        BenchmarkName.PII_DETECT: BenchmarkSpec(
            name=BenchmarkName.PII_DETECT,
            objective="Measure exact-span sensitive entity detection across the supported labels.",
            primary_metrics=("entity_precision", "entity_recall", "entity_f1", "sensitive_detection_recall"),
        ),
        BenchmarkName.PII_MINIMIZE: BenchmarkSpec(
            name=BenchmarkName.PII_MINIMIZE,
            objective="Measure whether the agent avoids acquiring data unnecessary for its task.",
            primary_metrics=(
                "unnecessary_acquisition_rate",
                "data_minimization_rate",
                "utility_preservation_rate",
            ),
        ),
        BenchmarkName.PII_EGRESS: BenchmarkSpec(
            name=BenchmarkName.PII_EGRESS,
            objective="Measure forbidden sensitive-data disclosure across an external boundary.",
            primary_metrics=("entity_leakage_rate", "policy_decision_accuracy"),
        ),
        BenchmarkName.PII_RAG: BenchmarkSpec(
            name=BenchmarkName.PII_RAG,
            objective="Measure over-retrieval, cross-scope retrieval, and sensitive RAG leakage.",
            primary_metrics=("entity_leakage_rate", "unnecessary_acquisition_rate"),
        ),
        BenchmarkName.PII_MEMORY: BenchmarkSpec(
            name=BenchmarkName.PII_MEMORY,
            objective="Measure sensitive information retained in agent memory.",
            primary_metrics=("memory_leakage_rate",),
        ),
        BenchmarkName.PII_TOOL: BenchmarkSpec(
            name=BenchmarkName.PII_TOOL,
            objective="Measure sensitive information exposed in tool arguments.",
            primary_metrics=("tool_argument_leakage_rate",),
        ),
        BenchmarkName.PII_INJECTION: BenchmarkSpec(
            name=BenchmarkName.PII_INJECTION,
            objective="Measure whether prompt injection successfully causes a privacy breach.",
            primary_metrics=("attack_success_rate",),
        ),
        BenchmarkName.PII_TRAJECTORY: BenchmarkSpec(
            name=BenchmarkName.PII_TRAJECTORY,
            objective="Measure cumulative disclosure across a multi-step agent trajectory.",
            primary_metrics=("cumulative_leakage_rate",),
        ),
    }
)


def get_benchmark(name: BenchmarkName | str) -> BenchmarkSpec:
    try:
        normalized = name if isinstance(name, BenchmarkName) else BenchmarkName(name)
    except (TypeError, ValueError):
        raise KeyError(f"Unknown SensitiveGuard benchmark: {name}") from None
    return BENCHMARKS[normalized]


def list_benchmarks() -> tuple[BenchmarkSpec, ...]:
    return tuple(BENCHMARKS[name] for name in BenchmarkName)
