"""Shared, serialization-safe models used by the SensitiveGuard runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class Action(_StringEnum):
    """Deterministic actions supported by the policy and transformation layers."""

    ALLOW = "ALLOW"
    MASK = "MASK"
    REDACT = "REDACT"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    TOKENIZE = "TOKENIZE"
    GENERALIZE = "GENERALIZE"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Severity(_StringEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GuardStage(_StringEnum):
    DATA_ACQUISITION = "data_acquisition"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"
    FINAL_OUTPUT = "final_output"
    HANDOFF = "handoff"
    MCP_INPUT = "mcp_input"
    MCP_OUTPUT = "mcp_output"


class GuardStatus(_StringEnum):
    ALLOWED = "ALLOWED"
    TRANSFORMED = "TRANSFORMED"
    BLOCKED = "BLOCKED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


@dataclass(frozen=True, slots=True)
class Finding:
    """A normalized sensitive span.

    ``value`` is deliberately excluded from repr and public serialization. It is
    retained only so the local transformation layer can verify detector spans.
    """

    label: str
    start: int
    end: int
    score: float
    severity: Severity
    detector: str
    value: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        normalized_label = self.label.upper() if self.label.lower() != "address" else "ADDRESS"
        object.__setattr__(self, "label", normalized_label)
        object.__setattr__(self, "score", max(0.0, min(float(self.score), 1.0)))
        if self.start < 0 or self.end <= self.start:
            raise ValueError(f"Invalid finding span ({self.start}, {self.end})")
        if self.value and len(self.value) != self.end - self.start:
            raise ValueError("Finding value length does not match its span")

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "start": self.start,
            "end": self.end,
            "score": self.score,
            "severity": self.severity.value,
            "detector": self.detector,
        }


@dataclass(frozen=True, slots=True)
class DetectionResult:
    findings: tuple[Finding, ...] = ()

    @property
    def contains_sensitive_data(self) -> bool:
        return bool(self.findings)

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(sorted({finding.label for finding in self.findings}))

    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for finding in self.findings:
            result[finding.label] = result.get(finding.label, 0) + 1
        return dict(sorted(result.items()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "contains_sensitive_data": self.contains_sensitive_data,
            "findings": [finding.to_dict() for finding in self.findings],
            "counts": self.counts(),
        }


@dataclass(frozen=True, slots=True)
class NecessityDecision:
    label: str
    necessary: bool
    reason: str


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: float
    sensitivity: float
    destination: float
    non_necessity: float
    exposure: float
    combination: float

    def to_dict(self) -> dict[str, float]:
        return {
            "score": self.score,
            "sensitivity": self.sensitivity,
            "destination": self.destination,
            "non_necessity": self.non_necessity,
            "exposure": self.exposure,
            "combination": self.combination,
        }


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    finding: Finding
    action: Action
    reason: str
    policy_id: str
    severity: Severity
    allowed_after_transform: bool
    necessary: bool
    risk: RiskAssessment | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "finding": self.finding.to_dict(),
            "decision": self.action.value,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "severity": self.severity.value,
            "allowed_after_transform": self.allowed_after_transform,
            "necessary": self.necessary,
        }
        if self.risk is not None:
            result["risk"] = self.risk.to_dict()
        return result


@dataclass(frozen=True, slots=True)
class DecisionSet:
    decisions: tuple[PolicyDecision, ...] = ()

    def has(self, action: Action) -> bool:
        return any(decision.action is action for decision in self.decisions)

    def has_block(self) -> bool:
        return self.has(Action.BLOCK)

    def requires_approval(self) -> bool:
        return self.has(Action.REQUIRE_APPROVAL)

    @property
    def actions(self) -> tuple[str, ...]:
        return tuple(decision.action.value for decision in self.decisions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decisions": [decision.to_dict() for decision in self.decisions],
            "has_block": self.has_block(),
            "requires_approval": self.requires_approval(),
        }


@dataclass(frozen=True, slots=True)
class GuardResult:
    status: GuardStatus
    content: Any = field(default=None, repr=False)
    detection: DetectionResult = field(default_factory=DetectionResult)
    decisions: DecisionSet = field(default_factory=DecisionSet)
    reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.status in {GuardStatus.ALLOWED, GuardStatus.TRANSFORMED}

    @property
    def transformed(self) -> bool:
        return self.status is GuardStatus.TRANSFORMED

    def to_dict(self, *, include_content: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": self.status.value,
            "detection": self.detection.to_dict(),
            "policy": self.decisions.to_dict(),
            "reason": self.reason,
        }
        if include_content and self.allowed:
            result["content"] = self.content
        return result
