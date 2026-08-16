"""Local text transformation tools backed by the shared transformation engine."""

from __future__ import annotations

from typing import Any

from sensitiveguard.models import Action, DecisionSet, GuardStage, PolicyDecision

from .base import SensitiveGuardTool


class SanitizeTextTool(SensitiveGuardTool):
    name = "sanitize_text"
    description = "Apply context-aware privacy policy and return a safe text representation."
    inputs = {"text": {"type": "string", "description": "Text to sanitize locally."}}
    output_type = "object"
    handles_sensitive_input = True

    def __init__(self, *, gateway: Any, context: Any, destination: str = "external_llm") -> None:
        super().__init__(gateway=gateway, context=context)
        self.destination = destination

    def forward(self, text: str) -> dict[str, Any]:
        result = self.gateway.guard_text(
            text,
            self.context,
            GuardStage.TOOL_OUTPUT,
            destination=self.destination,
            tool_name=self.name,
            record_disclosure=False,
        )
        return self.result_payload(result)


class _ExplicitTransformationTool(SensitiveGuardTool):
    action: Action
    handles_sensitive_input = True

    def __init__(self, *, detector: Any, transformer: Any, context: Any) -> None:
        super().__init__(gateway=None, context=context)
        self.detector = detector
        self.transformer = transformer

    def forward(self, text: str) -> dict[str, Any]:
        detection = self.detector.detect(text, context=self.context)
        decisions = DecisionSet(
            decisions=tuple(
                PolicyDecision(
                    finding=finding,
                    action=self._effective_action(finding.label),
                    reason=f"Explicit local {self.action.value.lower()} request",
                    policy_id=f"EXPLICIT-{self.action.value}-001",
                    severity=finding.severity,
                    allowed_after_transform=True,
                    necessary=False,
                )
                for finding in detection.findings
            )
        )
        transformed = self.transformer.apply(text, decisions, run_id=self.context.run_id)
        for decision in decisions.decisions:
            raw_value = decision.finding.value
            if raw_value and raw_value in transformed:
                return {
                    "status": "BLOCKED",
                    "reason": "Transformation verification failed.",
                    "detection": detection.to_dict(),
                    "privacy_actions": list(decisions.actions),
                }
        return {
            "status": "TRANSFORMED" if decisions.decisions else "ALLOWED",
            "content": transformed,
            "detection": detection.to_dict(),
            "privacy_actions": list(decisions.actions),
        }

    def _effective_action(self, label: str) -> Action:
        # Passwords and reusable secrets are never partially masked.
        if self.action is Action.MASK and label in {"PASSWD", "API_KEY", "ACCESS_TOKEN", "PRIVATE_KEY", "JWT"}:
            return Action.REDACT
        return self.action


class MaskTextTool(_ExplicitTransformationTool):
    name = "mask_text"
    description = "Mask detected sensitive spans; reusable secrets are fully redacted."
    inputs = {"text": {"type": "string", "description": "Text to mask locally."}}
    output_type = "object"
    action = Action.MASK


class RedactTextTool(_ExplicitTransformationTool):
    name = "redact_text"
    description = "Replace every detected sensitive span with a typed redaction marker."
    inputs = {"text": {"type": "string", "description": "Text to redact locally."}}
    output_type = "object"
    action = Action.REDACT


class PseudonymizeTextTool(_ExplicitTransformationTool):
    name = "pseudonymize_text"
    description = "Replace sensitive spans with stable, run-scoped pseudonyms."
    inputs = {"text": {"type": "string", "description": "Text to pseudonymize locally."}}
    output_type = "object"
    action = Action.PSEUDONYMIZE


class TokenizeSensitiveDataTool(_ExplicitTransformationTool):
    name = "tokenize_sensitive_data"
    description = "Replace sensitive spans with non-reversible, run-scoped secure tokens."
    inputs = {"text": {"type": "string", "description": "Text to tokenize locally."}}
    output_type = "object"
    action = Action.TOKENIZE
