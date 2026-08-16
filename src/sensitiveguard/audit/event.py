"""Serialization-safe audit event model."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .sanitize import (
    safe_audit_metadata,
    safe_decisions_summary,
    safe_destination,
    safe_detection_summary,
    safe_event_type,
    safe_label,
    safe_run_id,
    safe_stage,
    safe_tool_name,
)


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
    _sanitization_key: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.step_id < 1:
            raise ValueError("step_id must be positive")
        if not math.isfinite(self.timestamp):
            raise ValueError("timestamp must be finite")
        if not math.isfinite(self.risk) or self.risk < 0:
            raise ValueError("risk must be finite and non-negative")
        key = self._sanitization_key
        if key is not None and (not isinstance(key, bytes) or len(key) < 16):
            raise ValueError("AuditEvent sanitization key must contain at least 16 bytes")
        safe_detection = safe_detection_summary(self.detection, key=key)
        safe_decisions = safe_decisions_summary(self.decisions, key=key)
        safe_metadata = safe_audit_metadata(self.metadata, key=key)
        safe_statuses = {"ALLOWED", "APPROVAL_REQUIRED", "BLOCKED", "TRANSFORMED"}
        safe_status = str(self.status).upper()
        object.__setattr__(self, "run_id", safe_run_id(self.run_id, key=key))
        object.__setattr__(self, "event_type", safe_event_type(self.event_type))
        object.__setattr__(self, "stage", safe_stage(self.stage))
        object.__setattr__(self, "tool", safe_tool_name(self.tool, key=key))
        object.__setattr__(self, "destination", safe_destination(self.destination, key=key))
        object.__setattr__(self, "status", safe_status if safe_status in safe_statuses else "BLOCKED")
        object.__setattr__(self, "reason", "[REDACTED:REASON]" if self.reason is not None else None)
        object.__setattr__(
            self, "sensitive_labels", tuple(sorted({safe_label(label) for label in self.sensitive_labels}))
        )
        object.__setattr__(self, "detection", _freeze(safe_detection) if safe_detection is not None else None)
        object.__setattr__(self, "decisions", _freeze(safe_decisions) if safe_decisions is not None else None)
        object.__setattr__(self, "metadata", _freeze(safe_metadata))
        object.__setattr__(self, "_sanitization_key", None)

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
