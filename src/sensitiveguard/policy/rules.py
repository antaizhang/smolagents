"""Declarative policy rule model."""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sensitiveguard.models import Action, Finding, GuardStage, Severity
from sensitiveguard.privacy.context import PrivacyContext


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, GuardStage)):
        value = (value,)
    result: list[str] = []
    for item in value:
        text = item.value if isinstance(item, GuardStage) else str(item)
        text = text.strip()
        if text == "*":
            return ()
        if text:
            result.append(text)
    return tuple(result)


def _matches_patterns(value: str | None, patterns: tuple[str, ...]) -> bool:
    if not patterns:
        return True
    if value is None:
        return False
    candidate = value.strip().casefold()
    return any(fnmatch.fnmatchcase(candidate, pattern.casefold()) for pattern in patterns)


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """A deterministic, auditable match rule for one policy action."""

    policy_id: str
    action: Action
    labels: tuple[str, ...] = ()
    stages: tuple[str, ...] = ()
    purposes: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    recipients: tuple[str, ...] = ()
    trust_levels: tuple[str, ...] = ()
    necessary: bool | None = None
    min_confidence: float = 0.0
    min_risk: float = 0.0
    max_risk: float = 100.0
    reason: str = "Matched deterministic privacy policy"
    severity: Severity | None = None
    allowed_after_transform: bool | None = None
    priority: int = 0

    def __post_init__(self) -> None:
        policy_id = str(self.policy_id).strip()
        if not policy_id:
            raise ValueError("PolicyRule.policy_id must not be empty")
        object.__setattr__(self, "policy_id", policy_id)
        if not isinstance(self.action, Action):
            object.__setattr__(self, "action", Action(str(self.action).strip().upper()))
        object.__setattr__(self, "labels", tuple(label.upper() for label in _as_tuple(self.labels)))
        object.__setattr__(self, "stages", tuple(stage.casefold() for stage in _as_tuple(self.stages)))
        object.__setattr__(self, "purposes", _as_tuple(self.purposes))
        object.__setattr__(self, "sources", _as_tuple(self.sources))
        object.__setattr__(self, "destinations", _as_tuple(self.destinations))
        object.__setattr__(self, "recipients", _as_tuple(self.recipients))
        object.__setattr__(self, "trust_levels", _as_tuple(self.trust_levels))
        valid_stages = {stage.value for stage in GuardStage}
        invalid_stages = set(self.stages) - valid_stages
        if invalid_stages:
            raise ValueError(f"Unknown guard stages: {', '.join(sorted(invalid_stages))}")
        if self.necessary is not None and not isinstance(self.necessary, bool):
            raise TypeError("PolicyRule.necessary must be a boolean or None")
        object.__setattr__(self, "min_confidence", float(self.min_confidence))
        object.__setattr__(self, "min_risk", float(self.min_risk))
        object.__setattr__(self, "max_risk", float(self.max_risk))
        if not 0 <= self.min_confidence <= 1:
            raise ValueError("PolicyRule.min_confidence must be between 0 and 1")
        if not 0 <= self.min_risk <= 100 or not 0 <= self.max_risk <= 100:
            raise ValueError("PolicyRule risk bounds must be between 0 and 100")
        if self.min_risk > self.max_risk:
            raise ValueError("PolicyRule.min_risk must not exceed max_risk")
        if self.severity is not None and not isinstance(self.severity, Severity):
            object.__setattr__(self, "severity", Severity(str(self.severity).strip().lower()))
        if self.allowed_after_transform is not None and not isinstance(self.allowed_after_transform, bool):
            raise TypeError("PolicyRule.allowed_after_transform must be a boolean or None")
        object.__setattr__(self, "reason", str(self.reason).strip() or "Matched deterministic privacy policy")
        object.__setattr__(self, "priority", int(self.priority))

    @property
    def specificity(self) -> int:
        dimensions = (
            self.labels,
            self.stages,
            self.purposes,
            self.sources,
            self.destinations,
            self.recipients,
            self.trust_levels,
        )
        score = sum(bool(dimension) for dimension in dimensions)
        score += int(self.necessary is not None)
        score += int(self.min_confidence > 0)
        score += int(self.min_risk > 0 or self.max_risk < 100)
        return score

    def matches(
        self,
        finding: Finding,
        context: PrivacyContext,
        stage: GuardStage,
        *,
        necessary: bool,
        risk_score: float,
        destination: str | None = None,
        recipient: str | None = None,
    ) -> bool:
        effective_destination = context.destination if destination is None else destination
        effective_recipient = context.recipient if recipient is None else recipient
        return (
            _matches_patterns(finding.label, self.labels)
            and _matches_patterns(stage.value, self.stages)
            and _matches_patterns(context.purpose, self.purposes)
            and _matches_patterns(context.source, self.sources)
            and _matches_patterns(effective_destination, self.destinations)
            and _matches_patterns(effective_recipient, self.recipients)
            and _matches_patterns(context.trust_level, self.trust_levels)
            and (self.necessary is None or self.necessary is necessary)
            and finding.score >= self.min_confidence
            and self.min_risk <= risk_score <= self.max_risk
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PolicyRule:
        if not isinstance(data, Mapping):
            raise TypeError("PolicyRule.from_dict expects a mapping")
        values = dict(data)
        aliases = {
            "id": "policy_id",
            "label": "labels",
            "stage": "stages",
            "purpose": "purposes",
            "source": "sources",
            "destination": "destinations",
            "recipient": "recipients",
            "trust_level": "trust_levels",
        }
        for alias, canonical in aliases.items():
            if alias in values:
                if canonical in values:
                    raise ValueError(f"Policy rule defines both {alias!r} and {canonical!r}")
                values[canonical] = values.pop(alias)
        valid_fields = set(cls.__dataclass_fields__)
        unknown = set(values) - valid_fields
        if unknown:
            raise ValueError(f"Unknown policy rule fields: {', '.join(sorted(unknown))}")
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "action": self.action.value,
            "labels": list(self.labels),
            "stages": list(self.stages),
            "purposes": list(self.purposes),
            "sources": list(self.sources),
            "destinations": list(self.destinations),
            "recipients": list(self.recipients),
            "trust_levels": list(self.trust_levels),
            "necessary": self.necessary,
            "min_confidence": self.min_confidence,
            "min_risk": self.min_risk,
            "max_risk": self.max_risk,
            "reason": self.reason,
            "severity": self.severity.value if self.severity else None,
            "allowed_after_transform": self.allowed_after_transform,
            "priority": self.priority,
        }


__all__ = ["PolicyRule"]
