"""Base classes for tools that are safe to expose to a ToolCallingAgent."""

from __future__ import annotations

from enum import Enum
from typing import Any

from sensitiveguard.models import GuardResult, GuardStatus
from smolagents import Tool


class ToolExecutionOutcome(str, Enum):
    UNKNOWN = "UNKNOWN"
    NOT_STARTED = "NOT_STARTED"
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"


class SensitiveGuardTool(Tool):
    """Marker base class used to prevent raw tools from entering the agent."""

    is_sensitiveguard_tool = True
    handles_sensitive_input = False

    def __init__(self, *, gateway: Any, context: Any) -> None:
        super().__init__()
        self.gateway = gateway
        self.context = context
        self._tracks_execution_outcome = False
        self._execution_outcome = ToolExecutionOutcome.UNKNOWN

    @property
    def execution_outcome(self) -> ToolExecutionOutcome:
        return self._execution_outcome

    @property
    def tracks_execution_outcome(self) -> bool:
        return self._tracks_execution_outcome

    def reset_execution_outcome(self) -> None:
        self._execution_outcome = (
            ToolExecutionOutcome.NOT_STARTED if self._tracks_execution_outcome else ToolExecutionOutcome.UNKNOWN
        )

    def mark_execution_started(self) -> None:
        if self._tracks_execution_outcome:
            self._execution_outcome = ToolExecutionOutcome.STARTED

    def mark_execution_completed(self) -> None:
        if self._tracks_execution_outcome:
            self._execution_outcome = ToolExecutionOutcome.COMPLETED

    @staticmethod
    def result_payload(result: GuardResult) -> dict[str, Any]:
        payload = result.to_dict(include_content=result.allowed)
        payload["privacy_actions"] = list(result.decisions.actions)
        return payload

    @staticmethod
    def safe_block(reason: str, *, status: GuardStatus = GuardStatus.BLOCKED) -> dict[str, Any]:
        return {"status": status.value, "reason": reason, "privacy_actions": []}


__all__ = ["SensitiveGuardTool", "ToolExecutionOutcome"]
