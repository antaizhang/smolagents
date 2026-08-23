"""Metric adapters for external Agent benchmark native scorer outputs.

These adapters never re-score trajectories. Third-party harnesses remain the
source of truth; adapters only normalize their native metrics and point to the
optional execution module for each benchmark.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .base import BenchmarkAdapter


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
    return None if not values else sum(values) / len(values)


def _count(value: Any) -> int:
    return len(_flatten_numeric(value))


def _first(native: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in native:
            return native[name]
    return None


class AgentDojoAdapter(BenchmarkAdapter):
    def __init__(self) -> None:
        super().__init__(
            "agentdojo", "AgentDojo native utility/security scorer", "sensitiveguard.eval.external.agentdojo"
        )

    def normalize(self, native, *, runtime, model, benchmark_version="unknown"):
        utility_raw = _first(native, "utility_results", "utility")
        security_raw = _first(native, "security_results", "security")
        utility, security = _mean(utility_raw), _mean(security_raw)
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


class AgentThreatBenchAdapter(BenchmarkAdapter):
    def __init__(self) -> None:
        super().__init__(
            "agent-threat-bench",
            "Inspect AgentThreatBench native utility/security scorer",
            "sensitiveguard.eval.external.agent_threat_bench",
        )

    def normalize(self, native, *, runtime, model, benchmark_version="unknown"):
        utility_raw = _first(native, "utility", "utility_results", "utility_score")
        security_raw = _first(native, "security", "security_results", "security_score")
        utility, security = _mean(utility_raw), _mean(security_raw)
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


class PrivacyLensAdapter(BenchmarkAdapter):
    def __init__(self) -> None:
        super().__init__(
            "privacylens", "PrivacyLens action leakage/helpfulness scorer", "sensitiveguard.eval.external.privacylens"
        )

    def normalize(self, native, *, runtime, model, benchmark_version="unknown"):
        leakage_raw = _first(native, "leakage_rate", "leakage")
        utility_raw = _first(native, "helpfulness_rate", "utility_score", "helpfulness")
        leakage, utility = _mean(leakage_raw), _mean(utility_raw)
        # PrivacyLens may report helpfulness on a non-[0,1] rating scale. Keep
        # that untouched in native_metrics rather than fabricating a rate.
        utility_rate = utility if utility is None or 0.0 <= utility <= 1.0 else None
        return self._result(
            benchmark=self.name,
            benchmark_version=benchmark_version,
            runtime=runtime,
            model=model,
            sample_count=max(_count(leakage_raw), _count(utility_raw)),
            native=native,
            leakage_rate=leakage,
            utility_score=utility_rate,
            security_score=None if leakage is None else 1.0 - leakage,
        )


class AgentDAMAdapter(BenchmarkAdapter):
    def __init__(self) -> None:
        super().__init__(
            "agentdam", "AgentDAM data-minimization/privacy output", "sensitiveguard.eval.external.agentdam"
        )

    def normalize(self, native, *, runtime, model, benchmark_version="unknown"):
        minimize_raw = _first(native, "data_minimization_rate", "minimization_rate", "privacy_score")
        leakage_raw = _first(native, "leakage_rate", "privacy_leakage_rate")
        task_raw = _first(native, "task_success_rate", "task_success", "utility", "performance_score")
        minimization = _mean(minimize_raw)
        leakage = _mean(leakage_raw)
        if leakage is None and minimization is not None:
            leakage = 1.0 - minimization if 0.0 <= minimization <= 1.0 else None
        return self._result(
            benchmark=self.name,
            benchmark_version=benchmark_version,
            runtime=runtime,
            model=model,
            sample_count=max(_count(minimize_raw), _count(task_raw), _count(leakage_raw)),
            native=native,
            data_minimization_rate=minimization,
            leakage_rate=leakage,
            security_score=None if leakage is None else 1.0 - leakage,
            task_success_rate=_mean(task_raw),
            utility_score=_mean(task_raw),
        )


class BFCLAdapter(BenchmarkAdapter):
    def __init__(self) -> None:
        super().__init__(
            "bfcl", "Berkeley Function Calling Leaderboard native accuracy", "sensitiveguard.eval.external.bfcl"
        )

    def normalize(self, native, *, runtime, model, benchmark_version="unknown"):
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


class Tau3Adapter(BenchmarkAdapter):
    def __init__(self) -> None:
        super().__init__("tau3", "tau3/tau2 native task reward", "sensitiveguard.eval.external.tau3")

    def normalize(self, native, *, runtime, model, benchmark_version="unknown"):
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


_ADAPTERS: dict[str, BenchmarkAdapter] = {
    adapter.name: adapter
    for adapter in (
        AgentDojoAdapter(),
        AgentThreatBenchAdapter(),
        PrivacyLensAdapter(),
        AgentDAMAdapter(),
        BFCLAdapter(),
        Tau3Adapter(),
    )
}


def get_result_adapter(name: str) -> BenchmarkAdapter:
    key = str(name).strip().lower()
    try:
        return _ADAPTERS[key]
    except KeyError:
        raise KeyError(f"Unknown external benchmark adapter: {name}") from None


def list_result_adapters() -> tuple[BenchmarkAdapter, ...]:
    return tuple(_ADAPTERS[name] for name in sorted(_ADAPTERS))


# Backward-compatible name from the first external-eval scaffold.
BenchmarkResultAdapter = BenchmarkAdapter

__all__ = ["BenchmarkAdapter", "BenchmarkResultAdapter", "get_result_adapter", "list_result_adapters"]
