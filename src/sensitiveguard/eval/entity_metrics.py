"""Exact-span entity metrics for the SensitiveGuard detector layer."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any


def _normalize_label(label: Any) -> str:
    if not isinstance(label, str) or not label.strip():
        raise ValueError("Entity labels must be non-empty strings")
    return label.strip().upper()


def _validate_count(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True, order=True)
class EntitySpan:
    """An entity annotation identified by its normalized label and exact span."""

    label: str
    start: int
    end: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", _normalize_label(self.label))
        if isinstance(self.start, bool) or not isinstance(self.start, int) or self.start < 0:
            raise ValueError("EntitySpan.start must be a non-negative integer")
        if isinstance(self.end, bool) or not isinstance(self.end, int) or self.end <= self.start:
            raise ValueError("EntitySpan.end must be an integer greater than start")

    @property
    def key(self) -> tuple[str, int, int]:
        return self.label, self.start, self.end

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "start": self.start, "end": self.end}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> EntitySpan:
        if not isinstance(value, Mapping):
            raise TypeError("EntitySpan.from_dict expects a mapping")
        try:
            return cls(label=value["label"], start=value["start"], end=value["end"])
        except KeyError as exc:
            raise ValueError(f"Entity span is missing required field: {exc.args[0]}") from None


@dataclass(frozen=True, slots=True)
class PRFScore:
    """Precision/recall/F1 counts with explicit empty-set semantics.

    If both gold and predictions are empty, precision, recall and F1 are 1.0.
    If gold is non-empty but predictions are empty, all three are 0.0.  If gold
    is empty but predictions are non-empty, recall is 1.0 while precision and
    F1 are 0.0.
    """

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    def __post_init__(self) -> None:
        for name in ("true_positives", "false_positives", "false_negatives"):
            _validate_count(name, getattr(self, name))

    @property
    def predicted_count(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def expected_count(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def precision(self) -> float:
        if self.predicted_count:
            return self.true_positives / self.predicted_count
        return 1.0 if self.expected_count == 0 else 0.0

    @property
    def recall(self) -> float:
        if self.expected_count:
            return self.true_positives / self.expected_count
        return 1.0

    @property
    def f1(self) -> float:
        total = self.precision + self.recall
        return 0.0 if total == 0.0 else 2.0 * self.precision * self.recall / total

    def merge(self, other: PRFScore) -> PRFScore:
        if not isinstance(other, PRFScore):
            raise TypeError("PRFScore.merge expects another PRFScore")
        return PRFScore(
            true_positives=self.true_positives + other.true_positives,
            false_positives=self.false_positives + other.false_positives,
            false_negatives=self.false_negatives + other.false_negatives,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "predicted_count": self.predicted_count,
            "expected_count": self.expected_count,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


@dataclass(frozen=True, slots=True)
class EntityMetrics:
    """Micro exact-span metrics plus a score for every observed label."""

    overall: PRFScore = field(default_factory=PRFScore)
    per_label: Mapping[str, PRFScore] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.overall, PRFScore):
            raise TypeError("EntityMetrics.overall must be a PRFScore")
        normalized: dict[str, PRFScore] = {}
        for label, score in self.per_label.items():
            normalized_label = _normalize_label(label)
            if not isinstance(score, PRFScore):
                raise TypeError("EntityMetrics.per_label values must be PRFScore instances")
            if normalized_label in normalized:
                raise ValueError(f"Duplicate normalized per-label metric: {normalized_label}")
            normalized[normalized_label] = score
        if normalized:
            summed = PRFScore(
                true_positives=sum(score.true_positives for score in normalized.values()),
                false_positives=sum(score.false_positives for score in normalized.values()),
                false_negatives=sum(score.false_negatives for score in normalized.values()),
            )
            if summed != self.overall:
                raise ValueError("EntityMetrics overall counts must equal the sum of per-label counts")
        elif self.overall != PRFScore():
            raise ValueError("Non-empty overall entity counts require per-label counts")
        object.__setattr__(self, "per_label", MappingProxyType(dict(sorted(normalized.items()))))

    @property
    def true_positives(self) -> int:
        return self.overall.true_positives

    @property
    def false_positives(self) -> int:
        return self.overall.false_positives

    @property
    def false_negatives(self) -> int:
        return self.overall.false_negatives

    @property
    def precision(self) -> float:
        return self.overall.precision

    @property
    def recall(self) -> float:
        return self.overall.recall

    @property
    def f1(self) -> float:
        return self.overall.f1

    def merge(self, other: EntityMetrics) -> EntityMetrics:
        if not isinstance(other, EntityMetrics):
            raise TypeError("EntityMetrics.merge expects another EntityMetrics")
        labels = set(self.per_label) | set(other.per_label)
        empty = PRFScore()
        return EntityMetrics(
            overall=self.overall.merge(other.overall),
            per_label={
                label: self.per_label.get(label, empty).merge(other.per_label.get(label, empty)) for label in labels
            },
        )

    def to_dict(self) -> dict[str, Any]:
        result = self.overall.to_dict()
        result["matching"] = "exact_label_and_span"
        result["per_label"] = {label: score.to_dict() for label, score in self.per_label.items()}
        return result


def _coerce_span(value: Any) -> EntitySpan:
    if isinstance(value, EntitySpan):
        return value
    if isinstance(value, Mapping):
        return EntitySpan.from_dict(value)
    if all(hasattr(value, name) for name in ("label", "start", "end")):
        return EntitySpan(label=value.label, start=value.start, end=value.end)
    raise TypeError("Entities must be EntitySpan, Finding-like objects, or mappings")


def _coerce_unique_spans(values: Iterable[Any], name: str) -> tuple[EntitySpan, ...]:
    if isinstance(values, (str, bytes, Mapping)):
        raise TypeError(f"{name} must be an iterable of entities")
    try:
        spans = tuple(_coerce_span(value) for value in values)
    except TypeError:
        raise
    keys = [span.key for span in spans]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{name} contains duplicate entity annotations")
    return spans


def evaluate_entities(expected: Iterable[Any], predicted: Iterable[Any]) -> EntityMetrics:
    """Evaluate one document using exact normalized-label and span matching."""

    expected_spans = _coerce_unique_spans(expected, "expected")
    predicted_spans = _coerce_unique_spans(predicted, "predicted")
    expected_keys = {span.key for span in expected_spans}
    predicted_keys = {span.key for span in predicted_spans}

    labels = {span.label for span in expected_spans} | {span.label for span in predicted_spans}
    per_label: dict[str, PRFScore] = {}
    for label in labels:
        label_expected = {key for key in expected_keys if key[0] == label}
        label_predicted = {key for key in predicted_keys if key[0] == label}
        per_label[label] = PRFScore(
            true_positives=len(label_expected & label_predicted),
            false_positives=len(label_predicted - label_expected),
            false_negatives=len(label_expected - label_predicted),
        )

    overall = PRFScore(
        true_positives=len(expected_keys & predicted_keys),
        false_positives=len(predicted_keys - expected_keys),
        false_negatives=len(expected_keys - predicted_keys),
    )
    return EntityMetrics(overall=overall, per_label=per_label)


def evaluate_entity_corpus(samples: Iterable[tuple[Iterable[Any], Iterable[Any]]]) -> EntityMetrics:
    """Micro-aggregate ``(expected, predicted)`` pairs across a corpus."""

    aggregate = EntityMetrics()
    if isinstance(samples, (str, bytes, Mapping)):
        raise TypeError("samples must be an iterable of (expected, predicted) pairs")
    for sample in samples:
        if not isinstance(sample, (tuple, list)) or len(sample) != 2:
            raise TypeError("Each entity corpus sample must be an (expected, predicted) pair")
        aggregate = aggregate.merge(evaluate_entities(sample[0], sample[1]))
    return aggregate


class EntityEvaluator:
    """Stateless OO facade for callers that prefer evaluator objects."""

    @staticmethod
    def evaluate(expected: Iterable[Any], predicted: Iterable[Any]) -> EntityMetrics:
        return evaluate_entities(expected, predicted)

    @staticmethod
    def evaluate_corpus(samples: Iterable[tuple[Iterable[Any], Iterable[Any]]]) -> EntityMetrics:
        return evaluate_entity_corpus(samples)
