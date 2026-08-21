"""Normalized result models for third-party Agent benchmarks.

External benchmark harnesses remain the source of truth for task execution and
scoring. SensitiveGuard only normalizes their native metrics so B0/B3 results
can be compared in one report without rewriting the benchmark dataset or
oracle.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


_RATE_FIELDS = (
    "security_score",
    "utility_score",
    "attack_success_rate",
    "leakage_rate",
    "task_success_rate",
    "tool_call_accuracy",
    "data_minimization_rate",
)


@dataclass(frozen=True, slots=True)
class ExternalBenchmarkResult:
    benchmark: str
    benchmark_version: str
    runtime: str
    model: str
    sample_count: int
    security_score: float | None = None
    utility_score: float | None = None
    attack_success_rate: float | None = None
    leakage_rate: float | None = None
    task_success_rate: float | None = None
    tool_call_accuracy: float | None = None
    data_minimization_rate: float | None = None
    mean_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    native_metrics: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("benchmark", "benchmark_version", "runtime", "model"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            object.__setattr__(self, name, value.strip())
        if isinstance(self.sample_count, bool) or not isinstance(self.sample_count, int) or self.sample_count < 0:
            raise ValueError("sample_count must be a non-negative integer")
        for name in _RATE_FIELDS:
            value = getattr(self, name)
            if value is None:
                continue
            normalized = float(value)
            if not 0.0 <= normalized <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
            object.__setattr__(self, name, normalized)
        for name in ("mean_latency_ms", "p95_latency_ms"):
            value = getattr(self, name)
            if value is None:
                continue
            normalized = float(value)
            if normalized < 0:
                raise ValueError(f"{name} must be non-negative")
            object.__setattr__(self, name, normalized)
        if not isinstance(self.native_metrics, Mapping):
            raise TypeError("native_metrics must be a mapping")
        object.__setattr__(self, "native_metrics", dict(self.native_metrics))

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": self.benchmark,
            "benchmark_version": self.benchmark_version,
            "runtime": self.runtime,
            "model": self.model,
            "sample_count": self.sample_count,
            "security_score": self.security_score,
            "utility_score": self.utility_score,
            "attack_success_rate": self.attack_success_rate,
            "leakage_rate": self.leakage_rate,
            "task_success_rate": self.task_success_rate,
            "tool_call_accuracy": self.tool_call_accuracy,
            "data_minimization_rate": self.data_minimization_rate,
            "mean_latency_ms": self.mean_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "native_metrics": dict(self.native_metrics),
        }


@dataclass(frozen=True, slots=True)
class ExternalBenchmarkComparison:
    """A same-model B0/B3 comparison for one third-party benchmark."""

    baseline: ExternalBenchmarkResult
    guarded: ExternalBenchmarkResult

    def __post_init__(self) -> None:
        if self.baseline.benchmark != self.guarded.benchmark:
            raise ValueError("comparison results must use the same benchmark")
        if self.baseline.model != self.guarded.model:
            raise ValueError("comparison results must use the same model")

    @staticmethod
    def _delta(left: float | None, right: float | None) -> float | None:
        if left is None or right is None:
            return None
        return right - left

    @property
    def utility_delta(self) -> float | None:
        return self._delta(self.baseline.utility_score, self.guarded.utility_score)

    @property
    def security_delta(self) -> float | None:
        return self._delta(self.baseline.security_score, self.guarded.security_score)

    @property
    def attack_success_delta(self) -> float | None:
        return self._delta(self.baseline.attack_success_rate, self.guarded.attack_success_rate)

    @property
    def leakage_delta(self) -> float | None:
        return self._delta(self.baseline.leakage_rate, self.guarded.leakage_rate)

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": self.baseline.benchmark,
            "model": self.baseline.model,
            "baseline": self.baseline.to_dict(),
            "guarded": self.guarded.to_dict(),
            "utility_delta": self.utility_delta,
            "security_delta": self.security_delta,
            "attack_success_delta": self.attack_success_delta,
            "leakage_delta": self.leakage_delta,
        }
