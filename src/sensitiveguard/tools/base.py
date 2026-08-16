"""Base classes for tools that are safe to expose to a ToolCallingAgent."""

from __future__ import annotations

from typing import Any

from sensitiveguard.models import GuardResult, GuardStatus
from smolagents import Tool


class SensitiveGuardTool(Tool):
    """Marker base class used to prevent raw tools from entering the agent."""

    is_sensitiveguard_tool = True
    handles_sensitive_input = False

    def __init__(self, *, gateway: Any, context: Any) -> None:
        super().__init__()
        self.gateway = gateway
        self.context = context

    @staticmethod
    def result_payload(result: GuardResult) -> dict[str, Any]:
        payload = result.to_dict(include_content=result.allowed)
        payload["privacy_actions"] = list(result.decisions.actions)
        return payload

    @staticmethod
    def safe_block(reason: str, *, status: GuardStatus = GuardStatus.BLOCKED) -> dict[str, Any]:
        return {"status": status.value, "reason": reason, "privacy_actions": []}
