"""Immutable models for host-controlled privacy routing."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sensitiveguard.models import Severity


class RouteKind(str, Enum):
    LOCAL = "local"
    MODEL = "model"
    FILESYSTEM = "filesystem"
    DATABASE = "database"
    RETRIEVAL = "retrieval"
    MESSAGE = "message"
    NETWORK = "network"
    PROCESS = "process"
    REQUESTER = "requester"
    UNKNOWN = "unknown"


class RouteStatus(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class EndpointDescriptor:
    """A model/service endpoint registered by the trusted host.

    The descriptor intentionally contains no client object. The application
    binds the selected ``endpoint_id`` to a concrete client outside the model's
    control.
    """

    endpoint_id: str
    destination: str
    trust_level: str
    is_local: bool
    operations: tuple[str, ...] = ()
    max_sensitivity: Severity = Severity.MEDIUM
    priority: int = 100
    available: bool = True
    allow_fallback: bool = False

    def __post_init__(self) -> None:
        endpoint_id = str(self.endpoint_id).strip()
        destination = str(self.destination).strip()
        if not endpoint_id or not destination:
            raise ValueError("Endpoint id and destination must not be empty")
        object.__setattr__(self, "endpoint_id", endpoint_id)
        object.__setattr__(self, "destination", destination)
        object.__setattr__(self, "trust_level", str(self.trust_level or "unknown").strip().lower())
        object.__setattr__(self, "operations", tuple(sorted({str(item).strip().lower() for item in self.operations})))
        if not isinstance(self.max_sensitivity, Severity):
            object.__setattr__(self, "max_sensitivity", Severity(str(self.max_sensitivity)))

    def supports(self, operation: str) -> bool:
        normalized = str(operation).strip().lower()
        return not self.operations or normalized in self.operations or "*" in self.operations


@dataclass(frozen=True, slots=True)
class RouteDecision:
    status: RouteStatus
    route_kind: RouteKind
    destination: str
    endpoint_id: str | None = None
    reason_code: str = "ROUTE_ALLOWED"
    external: bool = False
    recipient_fingerprint: str | None = None
    recipient: str | None = field(default=None, repr=False, compare=False)

    @property
    def allowed(self) -> bool:
        return self.status is RouteStatus.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "route_kind": self.route_kind.value,
            "destination": self.destination,
            "endpoint_id": self.endpoint_id,
            "reason_code": self.reason_code,
            "external": self.external,
            "recipient_fingerprint": self.recipient_fingerprint,
        }


__all__ = ["EndpointDescriptor", "RouteDecision", "RouteKind", "RouteStatus"]
