"""Serialization-safe audit event model."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .sanitize import collect_raw_values, safe_json_value, scrub_string


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(child) for key, child in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(child) for child in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(child) for child in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_thaw(child) for child in value]
    return value


@dataclass(frozen=True, slots=True)
class AuditEvent:
    run_id: str
    step_id: int
    timestamp: float
    event_type: str
    status: str
    stage: str | None = None
    tool: str | None = None
    destination: str | None = None
    sensitive_labels: tuple[str, ...] = ()
    detection: Mapping[str, Any] | None = field(default=None, repr=False)
    decisions: Mapping[str, Any] | None = field(default=None, repr=False)
    reason: str | None = None
    risk: float = 0.0
    metadata: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.step_id < 1:
            raise ValueError("step_id must be positive")
        if not math.isfinite(self.timestamp):
            raise ValueError("timestamp must be finite")
        if not math.isfinite(self.risk) or self.risk < 0:
            raise ValueError("risk must be finite and non-negative")
        raw_values = collect_raw_values(self.detection, self.decisions, self.metadata)
        safe_detection = safe_json_value(self.detection, raw_values)
        safe_decisions = safe_json_value(self.decisions, raw_values)
        safe_metadata = safe_json_value(self.metadata, raw_values)
        object.__setattr__(self, "run_id", scrub_string(self.run_id, raw_values) or "[REDACTED]")
        object.__setattr__(self, "event_type", scrub_string(self.event_type, raw_values) or "guard")
        object.__setattr__(self, "stage", scrub_string(self.stage, raw_values))
        object.__setattr__(self, "tool", scrub_string(self.tool, raw_values))
        object.__setattr__(self, "destination", scrub_string(self.destination, raw_values))
        object.__setattr__(self, "reason", "[REDACTED:REASON]" if self.reason is not None else None)
        object.__setattr__(self, "sensitive_labels", tuple(self.sensitive_labels))
        object.__setattr__(self, "detection", _freeze(safe_detection) if safe_detection is not None else None)
        object.__setattr__(self, "decisions", _freeze(safe_decisions) if safe_decisions is not None else None)
        object.__setattr__(self, "metadata", _freeze(safe_metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "step_id": self.step_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "stage": self.stage,
            "tool": self.tool,
            "destination": self.destination,
            "sensitive_labels": list(self.sensitive_labels),
            "detection": _thaw(self.detection),
            "decisions": _thaw(self.decisions),
            "status": self.status,
            "reason": self.reason,
            "risk": self.risk,
            "metadata": _thaw(self.metadata),
        }
