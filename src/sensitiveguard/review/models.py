"""Public, raw-free models for deterministic tool security review."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sensitiveguard.intent import IntentDecision
from sensitiveguard.routing import RouteDecision

from .permits import ExecutionPermit


@dataclass(frozen=True, slots=True)
class SecurityReviewResult:
    allowed: bool
    code: str
    reason: str
    route: RouteDecision | None = None
    intent: IntentDecision | None = None
    permit: ExecutionPermit | None = None
    operation_id: str | None = None
    lineage_ids: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        return "ALLOWED" if self.allowed else "BLOCKED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "allowed": self.allowed,
            "code": self.code,
            "reason": self.reason,
            "route": self.route.to_dict() if self.route is not None else None,
            "intent": self.intent.to_dict() if self.intent is not None else None,
            "permit": self.permit.to_dict() if self.permit is not None else None,
            "operation_id": self.operation_id,
            "lineage_ids": list(self.lineage_ids),
        }


__all__ = ["SecurityReviewResult"]
