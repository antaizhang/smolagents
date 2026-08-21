"""Metric adapters for external Agent benchmark native scorer outputs.

These adapters intentionally do not re-score benchmark trajectories. The
third-party harness remains authoritative; adapters only map its native metrics
to :class:`ExternalBenchmarkResult` while preserving the full native payload.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .models import ExternalBenchmarkResult


def _flatten_numeric(value: Any) -> list[float]:
    if value is None:
        return []
    if isinstance(value, bool):
        return [1.0 if value else 0.0]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [float(value)]
    if isinstance(value, Mapping):
        result: list[float] = []
        for item in value.values():
            result.extend(_flatten_numeric(item))
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        result = []
        for item in value:
            result.extend(_flatten_numeric(item))
        return result
    return []


def _mean(value: Any) -> float | None:
    values = _flatten_numeric(value)
    if not values:
        return None
    return sum(values) / len(values)


def _count(value: Any) -> int:
    return len(_flatten_numeric(value))


def _first(native: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in native:
            return native[name]
    return None


@dataclass(frozen=True, slots=True)
class BenchmarkResultAdapter:
    name: str
    description: str

    def normalize(
        self,
        native: Mapping[str, Any],
        *,
        runtime: str,
        model: str,
        benchmark_version: str = "unknown",
    ) -> ExternalBenchmarkResult:
        raise NotImplementedError

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


class AgentDojoResultAdapter(BenchmarkResultAdapter):
    def __init__(self) -> None:
        super().__init__("agentdojo", "AgentDojo native utility/security scorer output")

    def normalize(self, native: Mapping[str, Any], *, runtime: str, model: str, benchmark_version: str = "unknown"):
        utility_raw = _first(native, "utility_results", "utility")
        security_raw = _first(native, "security_results", "security")
        utility = _mean(utility_raw)
        security = _mean(security_raw)
        return self._result(
            benchmark=self.name,
            benchmark_version=benchmark_version,
            runtime=runtime,
            model=model,
            sample_count=max(_count(utility_raw), _count(security_raw)),
            native=native,
            utility_score=utility,
            security_score=security,
            attack_success_rate=None if security is None else 1.0 - security,
        )


class AgentThreatBenchResultAdapter(BenchmarkResultAdapter):
    def __init__(self) -> None:
        super().__init__("agent-threat-bench", "Inspect AgentThreatBench utility/security output")

    def normalize(self, native: Mapping[str, Any], *, runtime: str, model: str, benchmark_version: str = "unknown"):
        utility_raw = _first(native, "utility", "utility_results", "utility_score")
        security_raw = _first(native, "security", "security_results", "security_score")
        utility = _mean(utility_raw)
        security = _mean(security_raw)
        return self._result(
            benchmark=self.name,
            benchmark_version=benchmark_version,
            runtime=runtime,
            model=model,
            sample_count=max(_count(utility_raw), _count(security_raw)),
            native=native,
            utility_score=utility,
            security_score=security,
            attack_success_rate=None if security is None else 1.0 - security,
        )


class PrivacyLensResultAdapter(BenchmarkResultAdapter):
    def __init__(self) -> None:
        super().__init__("privacylens", "PrivacyLens action leakage/helpfulness output")

    def normalize(self, native: Mapping[str, Any], *, runtime: str, model: str, benchmark_version: str = "unknown"):
        leakage_raw = _first(native, "leakage_rate", "leakage")
        utility_raw = _first(native, "helpfulness_score", "utility_score", "helpfulness")
        leakage = _mean(leakage_raw)
        utility = _mean(utility_raw)
        if utility is not None and not 0.0 <= utility <= 1.0:
            utility = None
        return self._result(
            benchmark=self.name,
            benchmark_version=benchmark_version,
            runtime=runtime,
            model=model,
            sample_count=max(_count(leakage_raw), _count(utility_raw)),
            native=native,
            leakage_rate=leakage,
            utility_score=utility,
            security_score=None if leakage is None else 1.0 - leakage,
        )


class AgentDAMResultAdapter(BenchmarkResultAdapter):
    def __init__(self) -> None:
        super().__init__("agentdam", "AgentDAM data-minimization output")

    def normalize(self, native: Mapping[str, Any], *, runtime: str, model: str, benchmark_version: str = "unknown"):
        minimize_raw = _first(native, "data_minimization_rate", "minimization_rate")
        task_raw = _first(native, "task_success_rate", "task_success", "utility")
        return self._result(
            benchmark=self.name,
            benchmark_version=benchmark_version,
            runtime=runtime,
            model=model,
            sample_count=max(_count(minimize_raw), _count(task_raw)),
            native=native,
            data_minimization_rate=_mean(minimize_raw),
            task_success_rate=_mean(task_raw),
            utility_score=_mean(task_raw),
        )


class BFCLResultAdapter(BenchmarkResultAdapter):
    def __init__(self) -> None:
        super().__init__("bfcl", "Berkeley Function Calling Leaderboard native accuracy output")

    def normalize(self, native: Mapping[str, Any], *, runtime: str, model: str, benchmark_version: str = "unknown"):
        accuracy_raw = _first(native, "tool_call_accuracy", "accuracy", "overall_accuracy")
        accuracy = _mean(accuracy_raw)
        return self._result(
            benchmark=self.name,
            benchmark_version=benchmark_version,
            runtime=runtime,
            model=model,
            sample_count=_count(accuracy_raw),
            native=native,
            tool_call_accuracy=accuracy,
            utility_score=accuracy,
        )


class Tau3ResultAdapter(BenchmarkResultAdapter):
    def __init__(self) -> None:
        super().__init__("tau3", "tau3/tau2 native task reward output")

    def normalize(self, native: Mapping[str, Any], *, runtime: str, model: str, benchmark_version: str = "unknown"):
        task_raw = _first(native, "task_success_rate", "reward", "rewards", "success")
        task_success = _mean(task_raw)
        return self._result(
            benchmark=self.name,
            benchmark_version=benchmark_version,
            runtime=runtime,
            model=model,
            sample_count=_count(task_raw),
            native=native,
            task_success_rate=task_success,
            utility_score=task_success,
        )


_ADAPTERS: dict[str, BenchmarkResultAdapter] = {
    adapter.name: adapter
    for adapter in (
        AgentDojoResultAdapter(),
        AgentThreatBenchResultAdapter(),
        PrivacyLensResultAdapter(),
        AgentDAMResultAdapter(),
        BFCLResultAdapter(),
        Tau3ResultAdapter(),
    )
}


def get_result_adapter(name: str) -> BenchmarkResultAdapter:
    key = str(name).strip().lower()
    try:
        return _ADAPTERS[key]
    except KeyError:
        raise KeyError(f"Unknown external benchmark adapter: {name}") from None


def list_result_adapters() -> tuple[BenchmarkResultAdapter, ...]:
    return tuple(_ADAPTERS[name] for name in sorted(_ADAPTERS))
