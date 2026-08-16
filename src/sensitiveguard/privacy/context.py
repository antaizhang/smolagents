"""Per-run privacy context used by all SensitiveGuard decisions."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any
from uuid import uuid4


def _normalize_values(values: Iterable[str] | str | None) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        if not item:
            continue
        key = item.casefold()
        if key not in seen:
            seen.add(key)
            normalized.append(item)
    return tuple(normalized)


def _normalize_optional(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


@dataclass(frozen=True, slots=True)
class PrivacyContext:
    """Purpose, authorization scope, and trust state for one agent run."""

    task: str
    purpose: str
    requester: str | None = None
    recipient: str | None = None
    source: str | None = None
    destination: str | None = None
    trust_level: str = "unknown"
    required_fields: tuple[str, ...] = ()
    optional_fields: tuple[str, ...] = ()
    forbidden_fields: tuple[str, ...] = ()
    allowed_scope: tuple[str, ...] = ()
    allowed_operations: tuple[str, ...] = ()
    denied_operations: tuple[str, ...] = ()
    allowed_capabilities: tuple[str, ...] = ()
    denied_capabilities: tuple[str, ...] = ()
    allowed_effects: tuple[str, ...] = ()
    denied_effects: tuple[str, ...] = ()
    allowed_destinations: tuple[str, ...] = ()
    denied_destinations: tuple[str, ...] = ()
    allowed_recipients: tuple[str, ...] = ()
    denied_recipients: tuple[str, ...] = ()
    intent_version: int = 1
    intent_expires_at: float | None = None
    run_id: str = field(default_factory=lambda: uuid4().hex)

    def __post_init__(self) -> None:
        task = str(self.task).strip()
        purpose = str(self.purpose).strip()
        run_id = str(self.run_id).strip()
        if not task:
            raise ValueError("PrivacyContext.task must not be empty")
        if not purpose:
            raise ValueError("PrivacyContext.purpose must not be empty")
        if not run_id:
            raise ValueError("PrivacyContext.run_id must not be empty")
        if isinstance(self.intent_version, bool) or int(self.intent_version) < 1:
            raise ValueError("PrivacyContext.intent_version must be a positive integer")
        if self.intent_expires_at is not None and not math.isfinite(float(self.intent_expires_at)):
            raise ValueError("PrivacyContext.intent_expires_at must be finite")

        object.__setattr__(self, "task", task)
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "requester", _normalize_optional(self.requester))
        object.__setattr__(self, "recipient", _normalize_optional(self.recipient))
        object.__setattr__(self, "source", _normalize_optional(self.source))
        object.__setattr__(self, "destination", _normalize_optional(self.destination))
        object.__setattr__(self, "trust_level", str(self.trust_level or "unknown").strip().lower())
        object.__setattr__(self, "required_fields", _normalize_values(self.required_fields))
        object.__setattr__(self, "optional_fields", _normalize_values(self.optional_fields))
        object.__setattr__(self, "forbidden_fields", _normalize_values(self.forbidden_fields))
        object.__setattr__(self, "allowed_scope", _normalize_values(self.allowed_scope))
        object.__setattr__(self, "allowed_operations", _normalize_values(self.allowed_operations))
        object.__setattr__(self, "denied_operations", _normalize_values(self.denied_operations))
        object.__setattr__(self, "allowed_capabilities", _normalize_values(self.allowed_capabilities))
        object.__setattr__(self, "denied_capabilities", _normalize_values(self.denied_capabilities))
        object.__setattr__(self, "allowed_effects", _normalize_values(self.allowed_effects))
        object.__setattr__(self, "denied_effects", _normalize_values(self.denied_effects))
        object.__setattr__(self, "allowed_destinations", _normalize_values(self.allowed_destinations))
        object.__setattr__(self, "denied_destinations", _normalize_values(self.denied_destinations))
        object.__setattr__(self, "allowed_recipients", _normalize_values(self.allowed_recipients))
        object.__setattr__(self, "denied_recipients", _normalize_values(self.denied_recipients))
        object.__setattr__(self, "intent_version", int(self.intent_version))
        if self.intent_expires_at is not None:
            object.__setattr__(self, "intent_expires_at", float(self.intent_expires_at))

    @staticmethod
    def _matches(value: str, candidates: tuple[str, ...]) -> bool:
        key = value.strip().casefold()
        return "*" in candidates or any(key == candidate.casefold() for candidate in candidates)

    def is_required(self, field_name: str) -> bool:
        return self._matches(field_name, self.required_fields)

    def is_optional(self, field_name: str) -> bool:
        return self._matches(field_name, self.optional_fields)

    def is_forbidden(self, field_name: str) -> bool:
        return self._matches(field_name, self.forbidden_fields)

    def scope_allows(self, field_name: str) -> bool:
        return not self.allowed_scope or self._matches(field_name, self.allowed_scope)

    @property
    def crosses_trust_boundary(self) -> bool:
        trust = self.trust_level.casefold()
        destination = (self.destination or "").casefold()
        internal_destinations = {"internal", "local", "agent_memory", "database", "internal_database", "rag", "memory"}
        if destination in internal_destinations or destination.startswith(("internal_", "local_")):
            return False
        external_markers = ("external", "public", "internet", "third_party", "third-party", "untrusted")
        return trust in {"external", "public", "untrusted", "unknown"} or any(
            marker in destination for marker in external_markers
        )

    def with_overrides(self, **changes: Any) -> PrivacyContext:
        """Return an immutable copy with gateway-provided overrides."""

        return replace(self, **changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "purpose": self.purpose,
            "requester": self.requester,
            "recipient": self.recipient,
            "source": self.source,
            "destination": self.destination,
            "trust_level": self.trust_level,
            "required_fields": list(self.required_fields),
            "optional_fields": list(self.optional_fields),
            "forbidden_fields": list(self.forbidden_fields),
            "allowed_scope": list(self.allowed_scope),
            "allowed_operations": list(self.allowed_operations),
            "denied_operations": list(self.denied_operations),
            "allowed_capabilities": list(self.allowed_capabilities),
            "denied_capabilities": list(self.denied_capabilities),
            "allowed_effects": list(self.allowed_effects),
            "denied_effects": list(self.denied_effects),
            "allowed_destinations": list(self.allowed_destinations),
            "denied_destinations": list(self.denied_destinations),
            "allowed_recipients": list(self.allowed_recipients),
            "denied_recipients": list(self.denied_recipients),
            "intent_version": self.intent_version,
            "intent_expires_at": self.intent_expires_at,
            "run_id": self.run_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PrivacyContext:
        if not isinstance(value, Mapping):
            raise TypeError("PrivacyContext.from_dict expects a mapping")
        return cls(**dict(value))


__all__ = ["PrivacyContext"]
