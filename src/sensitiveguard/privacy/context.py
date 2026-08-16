"""Per-run privacy context used by all SensitiveGuard decisions."""

from __future__ import annotations

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
            "run_id": self.run_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PrivacyContext:
        if not isinstance(value, Mapping):
            raise TypeError("PrivacyContext.from_dict expects a mapping")
        return cls(**dict(value))


__all__ = ["PrivacyContext"]
