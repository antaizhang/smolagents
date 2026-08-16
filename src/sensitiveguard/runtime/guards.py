"""Named adapters for the four privacy boundaries in the architecture."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sensitiveguard.models import GuardResult, GuardStage

from .error_model import AuthorizationError


@dataclass(frozen=True, slots=True)
class AcquisitionPlan:
    requested_fields: tuple[str, ...]
    approved_fields: tuple[str, ...]
    omitted_fields: tuple[str, ...]

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "requested_fields": list(self.requested_fields),
            "approved_fields": list(self.approved_fields),
            "omitted_fields": list(self.omitted_fields),
        }


class DataAcquisitionGuard:
    """Produce a minimal structured projection before a data source is read."""

    def plan_fields(self, requested_fields: list[str] | tuple[str, ...], context: Any) -> AcquisitionPlan:
        if not requested_fields or any(not isinstance(field, str) or not field.strip() for field in requested_fields):
            raise AuthorizationError("A non-empty structured field projection is required.")
        requested = tuple(dict.fromkeys(field.strip() for field in requested_fields))
        if "*" in requested:
            raise AuthorizationError("Wildcard acquisition is forbidden; request explicit minimal fields.")

        approved: list[str] = []
        omitted: list[str] = []
        for field in requested:
            if context.is_forbidden(field):
                omitted.append(field)
                continue
            necessary = context.is_required(field) or context.is_optional(field)
            if necessary and context.scope_allows(field):
                approved.append(field)
            else:
                omitted.append(field)
        if not approved:
            raise AuthorizationError("None of the requested fields are necessary and authorized for this task.")
        return AcquisitionPlan(requested, tuple(approved), tuple(omitted))


class ToolInputGuard:
    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    def guard(
        self,
        arguments: Any,
        context: Any,
        *,
        destination: str,
        recipient: str | None = None,
        tool_name: str | None = None,
    ) -> GuardResult:
        return self.gateway.guard_payload(
            arguments,
            context,
            GuardStage.TOOL_INPUT,
            destination=destination,
            recipient=recipient,
            tool_name=tool_name,
        )


class ObservationGuard:
    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    def guard(self, observation: Any, context: Any, *, tool_name: str | None = None) -> GuardResult:
        return self.gateway.guard_payload(
            observation,
            context,
            GuardStage.TOOL_OUTPUT,
            destination="agent_memory",
            tool_name=tool_name,
            record_disclosure=False,
        )


class FinalOutputGuard:
    def __init__(self, gateway: Any, *, destination: str = "requester") -> None:
        self.gateway = gateway
        self.destination = destination

    def guard(self, answer: Any, context: Any) -> GuardResult:
        return self.gateway.guard_payload(
            answer,
            context,
            GuardStage.FINAL_OUTPUT,
            destination=self.destination,
            recipient=context.requester,
            tool_name="final_output",
            record_disclosure=True,
        )
