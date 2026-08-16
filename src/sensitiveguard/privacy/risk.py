"""Configurable and deterministic sensitive-data risk scoring."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from sensitiveguard.models import Finding, RiskAssessment, Severity
from sensitiveguard.privacy.context import PrivacyContext


def _clamp(value: float) -> float:
    return max(0.0, min(float(value), 1.0))


@dataclass(frozen=True, slots=True)
class RiskWeights:
    sensitivity: float = 0.30
    destination: float = 0.25
    non_necessity: float = 0.20
    exposure: float = 0.15
    combination: float = 0.10

    def __post_init__(self) -> None:
        values = (
            self.sensitivity,
            self.destination,
            self.non_necessity,
            self.exposure,
            self.combination,
        )
        if any(value < 0 for value in values):
            raise ValueError("Risk weights must be non-negative")
        if sum(values) <= 0:
            raise ValueError("At least one risk weight must be positive")

    @property
    def total(self) -> float:
        return self.sensitivity + self.destination + self.non_necessity + self.exposure + self.combination


DEFAULT_SENSITIVITY_SCORES: Mapping[Severity, float] = {
    Severity.LOW: 0.20,
    Severity.MEDIUM: 0.45,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.00,
}

DEFAULT_DESTINATION_SCORES: Mapping[str, float] = {
    "local": 0.05,
    "internal": 0.10,
    "trusted": 0.10,
    "restricted": 0.25,
    "partner": 0.55,
    "external": 0.85,
    "external_llm": 0.90,
    "public": 1.00,
    "untrusted": 1.00,
    "external_unknown": 1.00,
    "unknown": 0.85,
}

DEFAULT_EXPOSURE_SCORES: Mapping[str, float] = {
    "raw": 1.00,
    "allow": 1.00,
    "masked": 0.50,
    "mask": 0.50,
    "pseudonymized": 0.35,
    "pseudonymize": 0.35,
    "generalized": 0.30,
    "generalize": 0.30,
    "tokenized": 0.20,
    "tokenize": 0.20,
    "redacted": 0.00,
    "redact": 0.00,
    "blocked": 0.00,
    "block": 0.00,
}


class RiskEngine:
    """Compute a normalized 0..100 risk score from configurable components."""

    def __init__(
        self,
        *,
        weights: RiskWeights | Mapping[str, float] | None = None,
        sensitivity_scores: Mapping[Severity | str, float] | None = None,
        destination_scores: Mapping[str, float] | None = None,
        exposure_scores: Mapping[str, float] | None = None,
        label_scores: Mapping[str, float] | None = None,
        unknown_destination_score: float = 0.85,
        unknown_exposure_score: float = 1.0,
    ) -> None:
        if weights is None:
            self.weights = RiskWeights()
        elif isinstance(weights, RiskWeights):
            self.weights = weights
        elif isinstance(weights, Mapping):
            self.weights = RiskWeights(**dict(weights))
        else:
            raise TypeError("weights must be RiskWeights or a mapping")
        self.sensitivity_scores = dict(DEFAULT_SENSITIVITY_SCORES)
        for severity, score in (sensitivity_scores or {}).items():
            key = severity if isinstance(severity, Severity) else Severity(str(severity).lower())
            self.sensitivity_scores[key] = _clamp(score)
        self.destination_scores = {
            str(key).strip().casefold(): _clamp(score)
            for key, score in {**DEFAULT_DESTINATION_SCORES, **(destination_scores or {})}.items()
        }
        self.exposure_scores = {
            str(key).strip().casefold(): _clamp(score)
            for key, score in {**DEFAULT_EXPOSURE_SCORES, **(exposure_scores or {})}.items()
        }
        self.label_scores = {str(key).strip().upper(): _clamp(score) for key, score in (label_scores or {}).items()}
        self.unknown_destination_score = _clamp(unknown_destination_score)
        self.unknown_exposure_score = _clamp(unknown_exposure_score)

    def assess(
        self,
        finding: Finding,
        context: PrivacyContext,
        necessary: bool,
        exposure: str = "raw",
        cumulative_risk: float = 0,
    ) -> RiskAssessment:
        if not isinstance(finding, Finding):
            raise TypeError("RiskEngine.assess expects a Finding")
        if not isinstance(context, PrivacyContext):
            raise TypeError("RiskEngine.assess expects a PrivacyContext")
        if cumulative_risk < 0:
            raise ValueError("cumulative_risk must be non-negative")

        sensitivity = self.label_scores.get(
            finding.label,
            self.sensitivity_scores.get(finding.severity, DEFAULT_SENSITIVITY_SCORES[finding.severity]),
        )
        destination = self._destination_risk(context)
        non_necessity = 0.0 if necessary else 1.0
        exposure_risk = self.exposure_scores.get(exposure.strip().casefold(), self.unknown_exposure_score)
        combination = _clamp(cumulative_risk if cumulative_risk <= 1 else cumulative_risk / 100.0)

        weights = self.weights
        weighted = (
            weights.sensitivity * sensitivity
            + weights.destination * destination
            + weights.non_necessity * non_necessity
            + weights.exposure * exposure_risk
            + weights.combination * combination
        ) / weights.total
        return RiskAssessment(
            score=round(weighted * 100.0, 4),
            sensitivity=round(sensitivity, 4),
            destination=round(destination, 4),
            non_necessity=non_necessity,
            exposure=round(exposure_risk, 4),
            combination=round(combination, 4),
        )

    def _destination_risk(self, context: PrivacyContext) -> float:
        candidates = (context.destination, context.trust_level)
        for candidate in candidates:
            if not candidate:
                continue
            key = candidate.strip().casefold()
            if key in self.destination_scores:
                return self.destination_scores[key]
            marker_scores = [
                score for marker, score in self.destination_scores.items() if marker != "unknown" and marker in key
            ]
            if marker_scores:
                return max(marker_scores)
        return self.unknown_destination_score


__all__ = [
    "DEFAULT_DESTINATION_SCORES",
    "DEFAULT_EXPOSURE_SCORES",
    "DEFAULT_SENSITIVITY_SCORES",
    "RiskEngine",
    "RiskWeights",
]
