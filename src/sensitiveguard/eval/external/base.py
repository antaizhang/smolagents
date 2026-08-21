"""Common contract for third-party benchmark integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping

from .models import ExternalBenchmarkResult


@dataclass(frozen=True, slots=True)
class BenchmarkAdapter(ABC):
    """Describe an external benchmark and normalize its authoritative scorer output.

    Execution lives in a benchmark-specific optional-dependency module. The
    adapter deliberately does not own/reimplement datasets, environments or
    scoring logic; it only provides a stable registry and result schema.
    """

    name: str
    description: str
    runner_module: str

    @abstractmethod
    def normalize(
        self,
        native: Mapping[str, Any],
        *,
        runtime: str,
        model: str,
        benchmark_version: str = "unknown",
    ) -> ExternalBenchmarkResult:
        raise NotImplementedError

    @property
    def module_command(self) -> str:
        return f"python -m {self.runner_module}"

    @staticmethod
    def _result(
        *,
        benchmark: str,
        benchmark_version: str,
        runtime: str,
        model: str,
        sample_count: int,
        native: Mapping[str, Any],
        **metrics: Any,
    ) -> ExternalBenchmarkResult:
        return ExternalBenchmarkResult(
            benchmark=benchmark,
            benchmark_version=benchmark_version,
            runtime=runtime,
            model=model,
            sample_count=sample_count,
            native_metrics=dict(native),
            **metrics,
        )


__all__ = ["BenchmarkAdapter"]
