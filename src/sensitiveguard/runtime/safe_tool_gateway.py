"""The mandatory privacy boundary around data acquisition and tool execution."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any

from sensitiveguard.models import (
    Action,
    DecisionSet,
    DetectionResult,
    Finding,
    GuardResult,
    GuardStage,
    GuardStatus,
    PolicyDecision,
    Severity,
)

from .approval import ApprovalStore
from .authorization import AuthorizationPolicy
from .error_model import (
    DetectionError,
    PolicyError,
    PrivacyBudgetExceededError,
    SensitiveGuardError,
    TransformationError,
)
from .tool_registry import ToolRegistry


_TRANSFORM_ACTIONS = {
    Action.MASK,
    Action.REDACT,
    Action.PSEUDONYMIZE,
    Action.TOKENIZE,
    Action.GENERALIZE,
}
_INTERNAL_DESTINATIONS = {
    "agent_memory",
    "database",
    "internal",
    "internal_database",
    "internal_file",
    "local",
    "memory",
    "rag",
}
_SENSITIVE_FIELD_LABELS = {
    "access_token": "ACCESS_TOKEN",
    "address": "ADDRESS",
    "password": "PASSWD",
    "passwd": "PASSWD",
    "pwd": "PASSWD",
    "api_key": "API_KEY",
    "apikey": "API_KEY",
    "authorization": "ACCESS_TOKEN",
    "bank_card": "BANKACCOUNT",
    "idcard": "IDCARD",
    "id_card": "IDCARD",
    "bank_account": "BANKACCOUNT",
    "bankaccount": "BANKACCOUNT",
    "client_secret": "API_KEY",
    "email": "EMAIL",
    "fax": "FAX",
    "jwt": "JWT",
    "mobile": "MOBILE",
    "name": "NAME",
    "passport": "PASSPORTID",
    "passport_id": "PASSPORTID",
    "phone": "MOBILE",
    "private_key": "PRIVATE_KEY",
    "secret": "PASSWD",
    "tel": "TEL",
    "token": "ACCESS_TOKEN",
}
_FIELD_SEVERITY = {
    "PASSWD": Severity.CRITICAL,
    "API_KEY": Severity.CRITICAL,
    "ACCESS_TOKEN": Severity.CRITICAL,
    "PRIVATE_KEY": Severity.CRITICAL,
    "JWT": Severity.CRITICAL,
    "IDCARD": Severity.CRITICAL,
    "PASSPORTID": Severity.CRITICAL,
    "BANKACCOUNT": Severity.CRITICAL,
    "ADDRESS": Severity.HIGH,
    "EMAIL": Severity.HIGH,
    "FAX": Severity.HIGH,
    "MOBILE": Severity.HIGH,
    "TEL": Severity.HIGH,
    "NAME": Severity.MEDIUM,
}


@dataclass(slots=True)
class _TextEvaluation:
    original: str
    transformed: str
    detection: DetectionResult
    decisions: DecisionSet


class SafeToolGateway:
    """Detect, decide, transform, account and audit before data crosses a boundary."""

    def __init__(
        self,
        *,
        detector: Any,
        policy_engine: Any,
        transformer: Any,
        ledger: Any,
        audit_logger: Any,
        authorization: AuthorizationPolicy | None = None,
        registry: ToolRegistry | None = None,
        approval_callback: Callable[[DecisionSet, Any, str], bool] | None = None,
        lineage_tracker: Any | None = None,
    ) -> None:
        self.detector = detector
        self.policy_engine = policy_engine
        self.transformer = transformer
        self.ledger = ledger
        self.audit_logger = audit_logger
        self.authorization = authorization or AuthorizationPolicy()
        self.registry = registry or ToolRegistry()
        self.approval_callback = approval_callback
        self.lineage_tracker = lineage_tracker

    def guard_text(
        self,
        content: str,
        context: Any,
        stage: GuardStage,
        *,
        destination: str | None = None,
        recipient: str | None = None,
        tool_name: str | None = None,
        record_disclosure: bool | None = None,
    ) -> GuardResult:
        if not isinstance(content, str):
            raise TypeError("guard_text expects a string")
        result = self._guard_payload(
            content,
            context,
            stage,
            destination=destination,
            recipient=recipient,
            tool_name=tool_name,
            record_disclosure=record_disclosure,
            field_label=None,
        )
        return self._record_lineage(
            content,
            result,
            context,
            stage,
            tool_name=tool_name,
            destination=destination,
        )

    def guard_payload(
        self,
        payload: Any,
        context: Any,
        stage: GuardStage,
        *,
        destination: str | None = None,
        recipient: str | None = None,
        tool_name: str | None = None,
        record_disclosure: bool | None = None,
    ) -> GuardResult:
        result = self._guard_payload(
            payload,
            context,
            stage,
            destination=destination,
            recipient=recipient,
            tool_name=tool_name,
            record_disclosure=record_disclosure,
            field_label=None,
        )
        return self._record_lineage(
            payload,
            result,
            context,
            stage,
            tool_name=tool_name,
            destination=destination,
        )

    def _record_lineage(
        self,
        payload: Any,
        result: GuardResult,
        context: Any,
        stage: GuardStage,
        *,
        tool_name: str | None,
        destination: str | None,
    ) -> GuardResult:
        if self.lineage_tracker is None:
            return result
        try:
            self.lineage_tracker.record_guard(
                payload,
                result.content if result.allowed else None,
                context,
                stage,
                tool_name,
                destination or getattr(context, "destination", None),
                result.detection,
                result.decisions,
                result.status,
            )
        except Exception:
            if result.allowed:
                self._audit_failure(
                    context,
                    stage,
                    destination or getattr(context, "destination", None) or "unknown",
                    tool_name,
                    "LINEAGE_RECORD_FAILED",
                    "Data lineage could not be recorded; the operation was denied.",
                )
                return GuardResult(
                    status=GuardStatus.BLOCKED,
                    detection=result.detection,
                    decisions=result.decisions,
                    reason="Data lineage could not be recorded; the operation was denied.",
                )
        return result

    def _guard_payload(
        self,
        payload: Any,
        context: Any,
        stage: GuardStage,
        *,
        destination: str | None,
        recipient: str | None,
        tool_name: str | None,
        record_disclosure: bool | None,
        field_label: str | None,
    ) -> GuardResult:
        effective_destination = destination or getattr(context, "destination", None) or "unknown"
        effective_recipient = recipient if recipient is not None else getattr(context, "recipient", None)
        evaluations: list[_TextEvaluation] = []
        try:
            transformed_payload = self._walk_and_evaluate(
                payload,
                context,
                stage,
                effective_destination,
                effective_recipient,
                evaluations,
                field_label=field_label,
            )
        except SensitiveGuardError as error:
            self._audit_failure(
                context,
                stage,
                effective_destination,
                tool_name,
                error.code,
                error.public_message,
            )
            return GuardResult(status=GuardStatus.BLOCKED, reason=error.public_message)
        except Exception as error:
            safe_error = DetectionError(details={"exception_type": type(error).__name__})
            self._audit_failure(
                context,
                stage,
                effective_destination,
                tool_name,
                safe_error.code,
                safe_error.public_message,
            )
            return GuardResult(status=GuardStatus.BLOCKED, reason=safe_error.public_message)

        findings = tuple(finding for evaluation in evaluations for finding in evaluation.detection.findings)
        decisions = tuple(decision for evaluation in evaluations for decision in evaluation.decisions.decisions)
        detection_result = DetectionResult(findings=findings)
        decision_set = DecisionSet(decisions=decisions)

        if decision_set.has_block():
            reason = "The payload contains data forbidden by privacy policy."
            self._audit(
                context=context,
                stage=stage,
                destination=effective_destination,
                tool_name=tool_name,
                detection=detection_result,
                decisions=decision_set,
                status=GuardStatus.BLOCKED,
                reason=reason,
            )
            return GuardResult(
                status=GuardStatus.BLOCKED,
                detection=detection_result,
                decisions=decision_set,
                reason=reason,
            )

        denied_release = tuple(
            decision
            for decision in decisions
            if decision.action not in {Action.BLOCK, Action.REQUIRE_APPROVAL} and not decision.allowed_after_transform
        )
        if denied_release:
            reason = "Privacy policy does not authorize release after transformation."
            self._audit(
                context=context,
                stage=stage,
                destination=effective_destination,
                tool_name=tool_name,
                detection=detection_result,
                decisions=decision_set,
                status=GuardStatus.BLOCKED,
                reason=reason,
            )
            return GuardResult(
                status=GuardStatus.BLOCKED,
                detection=detection_result,
                decisions=decision_set,
                reason=reason,
            )

        approved_release = False
        if decision_set.requires_approval():
            approved = False
            if self.approval_callback is not None:
                try:
                    approval_context = (
                        context.with_overrides(
                            destination=effective_destination,
                            recipient=effective_recipient,
                        )
                        if hasattr(context, "with_overrides")
                        else context
                    )
                    if isinstance(self.approval_callback, ApprovalStore):
                        approved = self.approval_callback.consume(
                            decision_set,
                            approval_context,
                            effective_destination,
                            stage=stage,
                            recipient=effective_recipient,
                            policy_version=getattr(self.policy_engine, "policy_version", None),
                            tool_name=tool_name,
                        )
                    else:
                        approved = bool(
                            self.approval_callback(
                                decision_set,
                                approval_context,
                                effective_destination,
                            )
                        )
                except Exception:
                    approved = False
            if not approved:
                reason = "Explicit approval is required before this disclosure."
                self._audit(
                    context=context,
                    stage=stage,
                    destination=effective_destination,
                    tool_name=tool_name,
                    detection=detection_result,
                    decisions=decision_set,
                    status=GuardStatus.APPROVAL_REQUIRED,
                    reason=reason,
                )
                return GuardResult(
                    status=GuardStatus.APPROVAL_REQUIRED,
                    detection=detection_result,
                    decisions=decision_set,
                    reason=reason,
                )
            approved_release = True

        should_record = (
            record_disclosure
            if record_disclosure is not None
            else self._should_record_disclosure(stage, effective_destination)
        )
        if should_record and decisions:
            ledger_decisions = decision_set
            if approved_release:
                # Approval authorizes this exact raw disclosure. Account it as
                # raw exposure rather than the zero-risk pending-approval state.
                ledger_decisions = DecisionSet(
                    decisions=tuple(
                        replace(decision, action=Action.ALLOW, allowed_after_transform=True)
                        if decision.action is Action.REQUIRE_APPROVAL
                        else decision
                        for decision in decisions
                    )
                )
            try:
                reservation = self.ledger.reserve(
                    getattr(context, "run_id"),
                    effective_destination,
                    ledger_decisions,
                )
            except Exception as error:
                safe_error = PrivacyBudgetExceededError(details={"exception_type": type(error).__name__})
                self._audit_failure(
                    context,
                    stage,
                    effective_destination,
                    tool_name,
                    safe_error.code,
                    safe_error.public_message,
                )
                return GuardResult(
                    status=GuardStatus.BLOCKED,
                    detection=detection_result,
                    decisions=decision_set,
                    reason=safe_error.public_message,
                )
            if not reservation:
                reason = getattr(reservation, "reason", None) or "The disclosure would exceed the privacy budget."
                self._audit(
                    context=context,
                    stage=stage,
                    destination=effective_destination,
                    tool_name=tool_name,
                    detection=detection_result,
                    decisions=decision_set,
                    status=GuardStatus.BLOCKED,
                    reason=reason,
                )
                return GuardResult(
                    status=GuardStatus.BLOCKED,
                    detection=detection_result,
                    decisions=decision_set,
                    reason=reason,
                )

        transformed = (
            any(decision.action in _TRANSFORM_ACTIONS for decision in decisions) or transformed_payload != payload
        )
        status = GuardStatus.TRANSFORMED if transformed else GuardStatus.ALLOWED
        audit_succeeded = self._audit(
            context=context,
            stage=stage,
            destination=effective_destination,
            tool_name=tool_name,
            detection=detection_result,
            decisions=decision_set,
            status=status,
            reason=None,
        )
        if not audit_succeeded:
            # An unaudited disclosure is denied. The conservative ledger debit,
            # if already reserved, is intentionally retained.
            return GuardResult(
                status=GuardStatus.BLOCKED,
                detection=detection_result,
                decisions=decision_set,
                reason="Privacy audit persistence failed; the operation was denied.",
            )
        return GuardResult(
            status=status,
            content=transformed_payload,
            detection=detection_result,
            decisions=decision_set,
        )

    def _walk_and_evaluate(
        self,
        value: Any,
        context: Any,
        stage: GuardStage,
        destination: str,
        recipient: str | None,
        evaluations: list[_TextEvaluation],
        *,
        field_label: str | None,
    ) -> Any:
        if isinstance(value, str):
            evaluation = self._evaluate_text(
                value,
                context,
                stage,
                destination,
                recipient,
                field_label=field_label,
            )
            evaluations.append(evaluation)
            return evaluation.transformed
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            if isinstance(value, float) and (value != value or value in {float("inf"), float("-inf")}):
                raise DetectionError("Protected payload numbers must be finite.")
            evaluation = self._evaluate_text(
                str(value),
                context,
                stage,
                destination,
                recipient,
                field_label=field_label,
            )
            evaluations.append(evaluation)
            if not evaluation.detection.findings and evaluation.transformed == str(value):
                return value
            return evaluation.transformed
        if isinstance(value, dict):
            transformed: dict[Any, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise DetectionError("Protected payload dictionaries must use string keys.")
                key_evaluation = self._evaluate_text(
                    key,
                    context,
                    stage,
                    destination,
                    recipient,
                    field_label=None,
                )
                evaluations.append(key_evaluation)
                transformed_key = key_evaluation.transformed
                if transformed_key in transformed:
                    raise DetectionError(
                        "Protected dictionary keys collide after privacy transformation; the payload was denied."
                    )
                normalized_key = key.strip().lower().replace("-", "_").replace(" ", "_")
                label = _SENSITIVE_FIELD_LABELS.get(normalized_key)
                transformed[transformed_key] = self._walk_and_evaluate(
                    item,
                    context,
                    stage,
                    destination,
                    recipient,
                    evaluations,
                    field_label=label,
                )
            return transformed
        if isinstance(value, list):
            return [
                self._walk_and_evaluate(
                    item,
                    context,
                    stage,
                    destination,
                    recipient,
                    evaluations,
                    field_label=field_label,
                )
                for item in value
            ]
        if isinstance(value, tuple):
            return tuple(
                self._walk_and_evaluate(
                    item,
                    context,
                    stage,
                    destination,
                    recipient,
                    evaluations,
                    field_label=field_label,
                )
                for item in value
            )
        raise DetectionError(
            "Protected payloads must be composed of strings, numbers, booleans, nulls, lists, tuples or dictionaries.",
            details={"payload_type": type(value).__name__},
        )

    def _evaluate_text(
        self,
        text: str,
        context: Any,
        stage: GuardStage,
        destination: str,
        recipient: str | None,
        *,
        field_label: str | None,
    ) -> _TextEvaluation:
        try:
            detection = self.detector.detect(text, context=context)
        except Exception as error:
            raise DetectionError(details={"exception_type": type(error).__name__}) from error
        if not isinstance(detection, DetectionResult):
            raise DetectionError("A detector returned an invalid result type.")

        from sensitiveguard.transform.representations import is_generated_representation

        generated_findings = tuple(
            finding for finding in detection.findings if is_generated_representation(text, finding)
        )
        findings = [finding for finding in detection.findings if finding not in generated_findings]
        field_already_safe = any(finding.label == field_label for finding in generated_findings)
        if field_label and text and not field_already_safe:
            synthetic = Finding(
                label=field_label,
                start=0,
                end=len(text),
                score=1.0,
                severity=_FIELD_SEVERITY[field_label],
                detector="field_schema",
                value=text,
            )
            if not any(
                finding.label == synthetic.label and finding.start < synthetic.end and synthetic.start < finding.end
                for finding in findings
            ):
                findings.append(synthetic)
        detection = DetectionResult(
            findings=tuple(sorted(findings, key=lambda item: (item.start, item.end, item.label)))
        )

        try:
            decisions = self.policy_engine.evaluate(
                detection.findings,
                context,
                stage,
                destination=destination,
                recipient=recipient,
            )
        except Exception as error:
            raise PolicyError(details={"exception_type": type(error).__name__}) from error
        if not isinstance(decisions, DecisionSet):
            raise PolicyError("The policy engine returned an invalid decision type.")

        if decisions.has_block():
            transformed = text
        else:
            # REQUIRE_APPROVAL governs release of that finding but is not a
            # transformation. Other findings in the same payload must still be
            # minimized before an approved release.
            transformable = DecisionSet(
                decisions=tuple(
                    decision for decision in decisions.decisions if decision.action is not Action.REQUIRE_APPROVAL
                )
            )
            try:
                transformed = self.transformer.apply(text, transformable, run_id=getattr(context, "run_id"))
            except Exception as error:
                raise TransformationError(details={"exception_type": type(error).__name__}) from error
            self._verify_original_values_removed(transformed, transformable.decisions)
        return _TextEvaluation(text, transformed, detection, decisions)

    @staticmethod
    def _verify_original_values_removed(transformed: str, decisions: Iterable[PolicyDecision]) -> None:
        for decision in decisions:
            if decision.action not in _TRANSFORM_ACTIONS:
                continue
            raw_value = decision.finding.value
            if raw_value and raw_value in transformed:
                raise TransformationError(
                    "Transformation verification failed; the operation was denied.",
                    details={"label": decision.finding.label, "action": decision.action.value},
                )

    @staticmethod
    def _should_record_disclosure(stage: GuardStage, destination: str) -> bool:
        if stage not in {
            GuardStage.TOOL_INPUT,
            GuardStage.FINAL_OUTPUT,
            GuardStage.HANDOFF,
            GuardStage.MCP_INPUT,
        }:
            return False
        return destination.lower() not in _INTERNAL_DESTINATIONS

    def _audit(
        self,
        *,
        context: Any,
        stage: GuardStage,
        destination: str,
        tool_name: str | None,
        detection: DetectionResult,
        decisions: DecisionSet,
        status: GuardStatus,
        reason: str | None,
    ) -> bool:
        try:
            self.audit_logger.log(
                run_id=getattr(context, "run_id"),
                event_type="guard",
                stage=stage,
                tool=tool_name,
                destination=destination,
                detection=detection,
                decisions=decisions,
                status=status,
                reason=reason,
            )
        except Exception:
            return False
        return True

    def _audit_failure(
        self,
        context: Any,
        stage: GuardStage,
        destination: str,
        tool_name: str | None,
        code: str,
        reason: str,
    ) -> None:
        try:
            self.audit_logger.log(
                run_id=getattr(context, "run_id", "unknown"),
                event_type="guard_error",
                stage=stage,
                tool=tool_name,
                destination=destination,
                detection=DetectionResult(),
                decisions=DecisionSet(),
                status=GuardStatus.BLOCKED,
                reason=reason,
                metadata={"error_code": code},
            )
        except Exception:
            pass

    def execute_registered(
        self,
        capability_name: str,
        arguments: Any,
        context: Any,
        *,
        recipient: str | None = None,
    ) -> dict[str, Any]:
        """Guard both sides of a fixed, host-registered capability call."""

        self.authorization.authorize_tool(capability_name)
        capability = self.registry.get(capability_name)
        guarded_input = self.guard_payload(
            arguments,
            context,
            GuardStage.TOOL_INPUT,
            destination=capability.destination,
            recipient=recipient,
            tool_name=capability_name,
        )
        if not guarded_input.allowed:
            return guarded_input.to_dict(include_content=False)
        if isinstance(guarded_input.content, dict):
            raw_result = self.registry.execute(capability_name, **guarded_input.content)
        else:
            raw_result = self.registry.execute(capability_name, guarded_input.content)
        guarded_output = self.guard_payload(
            raw_result,
            context,
            GuardStage.TOOL_OUTPUT,
            destination="agent_memory",
            tool_name=capability_name,
            record_disclosure=False,
        )
        result = guarded_output.to_dict(include_content=True)
        result["input_privacy_actions"] = list(guarded_input.decisions.actions)
        return result
