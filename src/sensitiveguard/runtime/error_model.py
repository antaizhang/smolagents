"""Fail-closed errors whose public messages never echo protected payloads."""

from __future__ import annotations

from typing import Any


class SensitiveGuardError(RuntimeError):
    code = "SENSITIVE_GUARD_ERROR"
    default_message = "SensitiveGuard could not safely complete the operation."

    def __init__(self, message: str | None = None, *, details: dict[str, Any] | None = None) -> None:
        self.public_message = message or self.default_message
        self.details = details or {}
        super().__init__(self.public_message)

    def to_dict(self) -> dict[str, Any]:
        # ``details`` are retained only for trusted in-process diagnostics.
        # Tool names and adapter metadata can still originate from an
        # untrusted provider, so public serialization never includes them.
        return {"error": self.code, "message": self.public_message}


class DetectionError(SensitiveGuardError):
    code = "DETECTION_FAILED"
    default_message = "Sensitive content detection failed; the operation was denied."


class PolicyError(SensitiveGuardError):
    code = "POLICY_FAILED"
    default_message = "Privacy policy evaluation failed; the operation was denied."


class TransformationError(SensitiveGuardError):
    code = "TRANSFORMATION_FAILED"
    default_message = "Sensitive content transformation failed; the operation was denied."


class AuthorizationError(SensitiveGuardError):
    code = "NOT_AUTHORIZED"
    default_message = "The requested operation is outside the authorized scope."


class GuardBlockedError(SensitiveGuardError):
    code = "BLOCKED_BY_POLICY"
    default_message = "The requested operation was blocked by privacy policy."


class ApprovalRequiredError(SensitiveGuardError):
    code = "APPROVAL_REQUIRED"
    default_message = "The requested disclosure requires explicit approval."


class PrivacyBudgetExceededError(SensitiveGuardError):
    code = "PRIVACY_BUDGET_EXCEEDED"
    default_message = "The disclosure would exceed the privacy budget."


class UnsafeToolError(SensitiveGuardError):
    code = "UNSAFE_TOOL"
    default_message = "Only registered SensitiveGuard tools may be executed."


class ToolExecutionError(SensitiveGuardError):
    code = "TOOL_EXECUTION_FAILED"
    default_message = "The protected tool failed without exposing its arguments."
