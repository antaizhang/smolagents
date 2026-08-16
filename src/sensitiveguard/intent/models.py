"""Immutable, serialization-safe models for host-authorized agent intent.

The models deliberately contain no task or purpose text.  A resolver reduces
that trusted text to an HMAC digest before constructing :class:`IntentSpec`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, TypeVar


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class IntentOperation(_StringEnum):
    """Host-recognized operations that an agent may place in a plan."""

    READ = "READ"
    QUERY = "QUERY"
    RETRIEVE = "RETRIEVE"
    SCAN = "SCAN"
    DETECT = "DETECT"
    ANALYZE = "ANALYZE"
    SUMMARIZE = "SUMMARIZE"
    TRANSFORM = "TRANSFORM"
    WRITE = "WRITE"
    SEND = "SEND"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    HANDOFF = "HANDOFF"

    # Useful vocabulary aliases.  Aliases serialize to the canonical value so
    # they cannot create two semantically distinct signatures.
    ACQUIRE = "READ"
    READ_DATA = "READ"
    SEARCH = "RETRIEVE"
    SANITIZE = "TRANSFORM"
    WRITE_DATA = "WRITE"
    EXPORT = "SEND"
    SEND_DATA = "SEND"
    DELETE_DATA = "DELETE"
    EXECUTE_CODE = "EXECUTE"


class Effect(_StringEnum):
    """Observable effects declared by a proposed action."""

    READ = "READ"
    WRITE = "WRITE"
    NETWORK = "NETWORK"
    MESSAGE = "MESSAGE"
    MODEL = "MODEL"
    EXECUTE = "EXECUTE"
    DELETE = "DELETE"
    HANDOFF = "HANDOFF"
    EXTERNAL = "EXTERNAL"

    DATA_READ = "READ"
    READ_DATA = "READ"
    READ_ONLY = "READ"
    DATA_WRITE = "WRITE"
    WRITE_DATA = "WRITE"
    NETWORK_EGRESS = "NETWORK"
    NETWORK_ACCESS = "NETWORK"
    MESSAGE_EGRESS = "MESSAGE"
    MODEL_EGRESS = "MODEL"
    CODE_EXECUTION = "EXECUTE"
    EXTERNAL_EGRESS = "EXTERNAL"
    EXTERNAL_SIDE_EFFECT = "EXTERNAL"


_EnumT = TypeVar("_EnumT", bound=_StringEnum)


def _coerce_enum(value: Any, enum_type: type[_EnumT], *, field_name: str) -> _EnumT:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{field_name} values must be non-empty strings or {enum_type.__name__} members")
    normalized = value.strip().upper().replace("-", "_").replace(" ", "_")
    try:
        return enum_type[normalized]
    except KeyError:
        try:
            return enum_type(normalized)
        except ValueError as error:
            raise ValueError(f"Unsupported {field_name} value") from error


def _enum_tuple(values: Iterable[Any] | Any | None, enum_type: type[_EnumT], *, field_name: str) -> tuple[_EnumT, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, enum_type)):
        values = (values,)
    try:
        normalized = {_coerce_enum(value, enum_type, field_name=field_name) for value in values}
    except TypeError as error:
        if "not iterable" in str(error):
            raise TypeError(f"{field_name} must be iterable") from error
        raise
    return tuple(sorted(normalized, key=lambda item: item.value))


def _string_tuple(values: Iterable[Any] | str | None, *, field_name: str, casefold: bool = True) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    normalized: set[str] = set()
    try:
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise TypeError(f"{field_name} values must be non-empty strings")
            item = value.strip()
            normalized.add(item.casefold() if casefold else item)
    except TypeError as error:
        if "not iterable" in str(error):
            raise TypeError(f"{field_name} must be iterable") from error
        raise
    return tuple(sorted(normalized))


def _finite_timestamp(value: Any, *, field_name: str, allow_none: bool = False) -> float | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{field_name} must be finite and non-negative")
    return result


def _validate_version(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("version must be an integer")
    if value < 1:
        raise ValueError("version must be positive")
    return value


@dataclass(frozen=True, slots=True)
class IntentSpec:
    """A signed authorization envelope derived from trusted task context.

    ``goal_digest`` is an HMAC-SHA256 digest.  The raw goal is intentionally
    absent from both the in-process object and its serialized representation.
    """

    intent_id: str
    run_id: str
    version: int
    goal_digest: str
    issued_at: float
    expires_at: float
    allowed_operations: tuple[IntentOperation, ...] = ()
    allowed_capabilities: tuple[str, ...] = ()
    allowed_effects: tuple[Effect, ...] = ()
    allowed_fields: tuple[str, ...] = ()
    forbidden_fields: tuple[str, ...] = ()
    allowed_destinations: tuple[str, ...] = ()
    allowed_recipients: tuple[str, ...] = ()
    parent_intent_id: str | None = None

    def __post_init__(self) -> None:
        intent_id = str(self.intent_id).strip()
        run_id = str(self.run_id).strip()
        goal_digest = str(self.goal_digest).strip().lower()
        if not intent_id:
            raise ValueError("intent_id must not be empty")
        if not run_id:
            raise ValueError("run_id must not be empty")
        if len(goal_digest) != 64 or any(character not in "0123456789abcdef" for character in goal_digest):
            raise ValueError("goal_digest must be a SHA-256 hex digest")
        issued_at = _finite_timestamp(self.issued_at, field_name="issued_at")
        expires_at = _finite_timestamp(self.expires_at, field_name="expires_at")
        assert issued_at is not None and expires_at is not None
        if expires_at <= issued_at:
            raise ValueError("expires_at must be later than issued_at")
        parent = None if self.parent_intent_id is None else str(self.parent_intent_id).strip()
        if self.parent_intent_id is not None and not parent:
            raise ValueError("parent_intent_id must not be empty")

        object.__setattr__(self, "intent_id", intent_id)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "version", _validate_version(self.version))
        object.__setattr__(self, "goal_digest", goal_digest)
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(
            self,
            "allowed_operations",
            _enum_tuple(self.allowed_operations, IntentOperation, field_name="allowed_operations"),
        )
        object.__setattr__(
            self,
            "allowed_capabilities",
            _string_tuple(self.allowed_capabilities, field_name="allowed_capabilities"),
        )
        object.__setattr__(
            self,
            "allowed_effects",
            _enum_tuple(self.allowed_effects, Effect, field_name="allowed_effects"),
        )
        object.__setattr__(self, "allowed_fields", _string_tuple(self.allowed_fields, field_name="allowed_fields"))
        object.__setattr__(
            self,
            "forbidden_fields",
            _string_tuple(self.forbidden_fields, field_name="forbidden_fields"),
        )
        object.__setattr__(
            self,
            "allowed_destinations",
            _string_tuple(self.allowed_destinations, field_name="allowed_destinations"),
        )
        object.__setattr__(
            self,
            "allowed_recipients",
            _string_tuple(self.allowed_recipients, field_name="allowed_recipients"),
        )
        object.__setattr__(self, "parent_intent_id", parent)

    # Short aliases make policy code readable while retaining explicit public
    # serialized field names.
    @property
    def operations(self) -> tuple[IntentOperation, ...]:
        return self.allowed_operations

    @property
    def digest(self) -> str:
        return self.goal_digest

    @property
    def capabilities(self) -> tuple[str, ...]:
        return self.allowed_capabilities

    @property
    def effects(self) -> tuple[Effect, ...]:
        return self.allowed_effects

    @property
    def fields(self) -> tuple[str, ...]:
        return self.allowed_fields

    @property
    def destinations(self) -> tuple[str, ...]:
        return self.allowed_destinations

    @property
    def recipients(self) -> tuple[str, ...]:
        return self.allowed_recipients

    def is_expired(self, now: float) -> bool:
        return float(now) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "run_id": self.run_id,
            "version": self.version,
            "goal_digest": self.goal_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "allowed_operations": [item.value for item in self.allowed_operations],
            "allowed_capabilities": list(self.allowed_capabilities),
            "allowed_effects": [item.value for item in self.allowed_effects],
            "allowed_fields": list(self.allowed_fields),
            "forbidden_fields": list(self.forbidden_fields),
            "allowed_destinations": list(self.allowed_destinations),
            "allowed_recipients": list(self.allowed_recipients),
            "parent_intent_id": self.parent_intent_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IntentSpec":
        if not isinstance(value, Mapping):
            raise TypeError("IntentSpec.from_dict expects a mapping")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """One exact, replay-protected action proposed under an intent."""

    request_id: str
    run_id: str
    intent_id: str
    version: int
    operation: IntentOperation
    capability: str
    effects: tuple[Effect, ...] = ()
    fields: tuple[str, ...] = ()
    destination: str | None = None
    recipient: str | None = None
    issued_at: float | None = None
    expires_at: float | None = None
    lineage_taints: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        request_id = str(self.request_id).strip()
        run_id = str(self.run_id).strip()
        intent_id = str(self.intent_id).strip()
        capability = str(self.capability).strip().casefold()
        if not request_id:
            raise ValueError("request_id must not be empty")
        if not run_id:
            raise ValueError("run_id must not be empty")
        if not intent_id:
            raise ValueError("intent_id must not be empty")
        if not capability:
            raise ValueError("capability must not be empty")
        issued = _finite_timestamp(self.issued_at, field_name="issued_at", allow_none=True)
        expires = _finite_timestamp(self.expires_at, field_name="expires_at", allow_none=True)
        if issued is not None and expires is not None and expires <= issued:
            raise ValueError("ActionRequest expires_at must be later than issued_at")

        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "intent_id", intent_id)
        object.__setattr__(self, "version", _validate_version(self.version))
        object.__setattr__(self, "operation", _coerce_enum(self.operation, IntentOperation, field_name="operation"))
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "effects", _enum_tuple(self.effects, Effect, field_name="effects"))
        object.__setattr__(self, "fields", _string_tuple(self.fields, field_name="fields"))
        object.__setattr__(self, "destination", _optional_scope(self.destination, field_name="destination"))
        object.__setattr__(self, "recipient", _optional_scope(self.recipient, field_name="recipient"))
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(
            self,
            "lineage_taints",
            _string_tuple(self.lineage_taints, field_name="lineage_taints"),
        )

    @property
    def intent_version(self) -> int:
        return self.version

    @property
    def action_id(self) -> str:
        return self.request_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "run_id": self.run_id,
            "intent_id": self.intent_id,
            "version": self.version,
            "operation": self.operation.value,
            "capability": self.capability,
            "effects": [item.value for item in self.effects],
            "fields": list(self.fields),
            "destination": self.destination,
            "recipient": self.recipient,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "lineage_taints": list(self.lineage_taints),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ActionRequest":
        if not isinstance(value, Mapping):
            raise TypeError("ActionRequest.from_dict expects a mapping")
        return cls(**dict(value))


def _optional_scope(value: Any, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string or None")
    normalized = value.strip().casefold()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


@dataclass(frozen=True, slots=True)
class IntentDecision:
    """A public decision that never echoes action arguments or goal text."""

    allowed: bool
    code: str
    reason: str
    intent_id: str | None = None
    request_id: str | None = None
    version: int | None = None
    consumed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError("allowed must be boolean")
        code = str(self.code).strip().upper()
        reason = str(self.reason).strip()
        if not code or not reason:
            raise ValueError("IntentDecision code and reason must not be empty")
        if self.version is not None:
            _validate_version(self.version)
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "reason", reason)

    @property
    def status(self) -> str:
        return "ALLOWED" if self.allowed else "BLOCKED"

    @property
    def permitted(self) -> bool:
        return self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "allowed": self.allowed,
            "code": self.code,
            "reason": self.reason,
            "intent_id": self.intent_id,
            "request_id": self.request_id,
            "version": self.version,
            "consumed": self.consumed,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IntentDecision":
        if not isinstance(value, Mapping):
            raise TypeError("IntentDecision.from_dict expects a mapping")
        fields = dict(value)
        fields.pop("status", None)
        return cls(**fields)


def _intent_signature_payload(intent: IntentSpec) -> bytes:
    """Canonical signed scope, excluding the signature-like ``intent_id``."""

    payload = intent.to_dict()
    payload.pop("intent_id", None)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signed_intent_id(intent: IntentSpec, key: bytes) -> str:
    digest = hmac.new(key, b"SensitiveGuard.IntentSpec.v1\0" + _intent_signature_payload(intent), hashlib.sha256)
    return f"intent_{digest.hexdigest()}"


def _scope_allows(allowed: Iterable[Any], requested: Any) -> bool:
    allowed_values = {item.value if isinstance(item, Enum) else str(item).casefold() for item in allowed}
    requested_value = requested.value if isinstance(requested, Enum) else str(requested).casefold()
    return "*" in allowed_values or requested_value in allowed_values


def _scope_is_narrower(child: Iterable[Any], parent: Iterable[Any]) -> bool:
    child_values = {item.value if isinstance(item, Enum) else str(item).casefold() for item in child}
    parent_values = {item.value if isinstance(item, Enum) else str(item).casefold() for item in parent}
    if not child_values:
        return True
    if "*" in parent_values:
        return True
    if "*" in child_values:
        return False
    return child_values <= parent_values


__all__ = ["ActionRequest", "Effect", "IntentDecision", "IntentOperation", "IntentSpec"]
