"""Scoring, and the arithmetic that keeps a score from flattering the system.

The recurring failure of a privacy benchmark is that one number can be won by
doing nothing useful. Withhold everything and the leak rate is zero. Send
everything and the task-completion rate is perfect. So nothing here reports a
single number: privacy and utility are computed against separate ground truth
and printed side by side, and a run that moved one at the expense of the other
shows it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


def ratio(numerator: int, denominator: int) -> float:
    """A rate that is honest about an empty denominator.

    Zero cases is not a perfect score and not a failing one; it is no
    measurement. Reporting ``0.0`` for both would let an empty slice look like a
    result, so the callers below always print the denominator next to the rate.
    """

    return numerator / denominator if denominator else 0.0


@dataclass(frozen=True)
class Rate:
    """A rate that carries the counts it came from."""

    name: str
    hits: int
    total: int

    @property
    def value(self) -> float:
        return ratio(self.hits, self.total)

    @property
    def measured(self) -> bool:
        return self.total > 0

    def describe(self) -> str:
        if not self.measured:
            return f"{self.name}: n/a (0 cases)"
        return f"{self.name}: {self.value:.1%} ({self.hits}/{self.total})"

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "value": round(self.value, 6), "hits": self.hits, "total": self.total}


@dataclass(frozen=True)
class Confusion:
    """The four cells, for a benchmark whose ground truth is a binary decision."""

    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def total(self) -> int:
        return self.true_positive + self.false_positive + self.true_negative + self.false_negative

    @property
    def accuracy(self) -> float:
        return ratio(self.true_positive + self.true_negative, self.total)

    @property
    def precision(self) -> float:
        return ratio(self.true_positive, self.true_positive + self.false_positive)

    @property
    def recall(self) -> float:
        return ratio(self.true_positive, self.true_positive + self.false_negative)

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "accuracy": round(self.accuracy, 6),
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "f1": round(self.f1, 6),
        }

    def describe(self) -> str:
        return (
            f"acc={self.accuracy:.1%} p={self.precision:.1%} r={self.recall:.1%} f1={self.f1:.1%} "
            f"(tp={self.true_positive} fp={self.false_positive} tn={self.true_negative} fn={self.false_negative})"
        )


@dataclass
class BenchmarkResult:
    """What one benchmark produced, for one runtime.

    ``rates`` and ``counters`` are free-form so a benchmark can report what it
    actually measures, and ``headline`` names the two or three that belong in a
    summary table next to the others.
    """

    benchmark: str
    runtime: str
    cases: int
    rates: dict[str, Rate] = field(default_factory=dict)
    counters: dict[str, float] = field(default_factory=dict)
    confusion: Confusion | None = None
    headline: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    breakdown: dict[str, dict[str, Any]] = field(default_factory=dict)

    def rate(self, name: str) -> Rate:
        return self.rates.get(name, Rate(name, 0, 0))

    def add_rate(self, name: str, hits: int, total: int) -> Rate:
        self.rates[name] = Rate(name, hits, total)
        return self.rates[name]

    def as_dict(self) -> dict[str, Any]:
        return {
            "benchmark": self.benchmark,
            "runtime": self.runtime,
            "cases": self.cases,
            "rates": {name: rate.as_dict() for name, rate in self.rates.items()},
            "counters": dict(self.counters),
            "confusion": self.confusion.as_dict() if self.confusion is not None else None,
            "headline": list(self.headline),
            "notes": list(self.notes),
            "breakdown": dict(self.breakdown),
        }

    def describe(self) -> str:
        lines = [f"{self.benchmark} [{self.runtime}] {self.cases} case(s)"]
        if self.confusion is not None:
            lines.append(f"  {self.confusion.describe()}")
        for name, rate in self.rates.items():
            lines.append(f"  {rate.describe()}")
        for name, value in self.counters.items():
            rendered = f"{value:.2f}" if isinstance(value, float) else str(value)
            lines.append(f"  {name}: {rendered}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


def mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


__all__ = ["BenchmarkResult", "Confusion", "Rate", "mean", "ratio"]
