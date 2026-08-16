"""Detection and policy-inspection tools."""

from __future__ import annotations

from typing import Any

from sensitiveguard.models import GuardStage

from .base import SensitiveGuardTool


class DetectSensitiveDataTool(SensitiveGuardTool):
    name = "detect_sensitive_data"
    description = "Detect sensitive spans without returning the raw sensitive values."
    inputs = {"text": {"type": "string", "description": "Text to inspect locally."}}
    output_type = "object"
    handles_sensitive_input = True

    def __init__(self, *, detector: Any, context: Any) -> None:
        # Detection is local and does not need a gateway invocation.
        self.detector = detector
        self.context = context
        super().__init__(gateway=None, context=context)

    def forward(self, text: str) -> dict[str, Any]:
        return self.detector.detect(text, context=self.context).to_dict()


class EvaluateDataPolicyTool(SensitiveGuardTool):
    name = "evaluate_data_policy"
    description = "Evaluate the host-configured privacy policy for text without disclosing it."
    inputs = {"text": {"type": "string", "description": "Text to evaluate locally."}}
    output_type = "object"
    handles_sensitive_input = True

    def __init__(self, *, gateway: Any, context: Any, destination: str = "external_llm") -> None:
        super().__init__(gateway=gateway, context=context)
        self.destination = destination

    def forward(self, text: str) -> dict[str, Any]:
        result = self.gateway.guard_text(
            text,
            self.context,
            GuardStage.TOOL_INPUT,
            destination=self.destination,
            tool_name=self.name,
            record_disclosure=False,
        )
        return result.to_dict(include_content=False)
