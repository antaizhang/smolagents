"""A replacement final_answer tool that guards before returning or logging."""

from __future__ import annotations

from typing import Any

from sensitiveguard.models import GuardStage

from .base import SensitiveGuardTool


class FinalAnswerGuardTool(SensitiveGuardTool):
    name = "final_answer"
    description = "Return a final answer only after recursive SensitiveGuard output enforcement."
    inputs = {"answer": {"type": "any", "description": "Proposed final answer."}}
    output_type = "any"
    handles_sensitive_input = True

    def __init__(self, *, gateway: Any, context: Any, destination: str = "requester") -> None:
        super().__init__(gateway=gateway, context=context)
        self.destination = destination
        self.last_guard_result = None

    def forward(self, answer: Any) -> Any:
        result = self.gateway.guard_payload(
            answer,
            self.context,
            GuardStage.FINAL_OUTPUT,
            destination=self.destination,
            recipient=self.context.requester,
            tool_name=self.name,
            record_disclosure=True,
        )
        self.last_guard_result = result
        if result.allowed:
            return result.content
        if result.status.value == "APPROVAL_REQUIRED":
            return "The answer was withheld because explicit disclosure approval is required."
        return "The answer was withheld because it violates the active privacy policy."
