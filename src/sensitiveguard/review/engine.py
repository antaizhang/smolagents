"""Preflight/permit/postflight review for every Agent tool call."""

from __future__ import annotations

import fnmatch
import secrets
from collections.abc import Mapping
from typing import Any

from sensitiveguard.intent import ActionRequest, Effect, IntentDecision, IntentGuard, IntentOperation, IntentSpec
from sensitiveguard.routing import PrivacyRouter, RouteDecision
from sensitiveguard.runtime.capability_manifest import CapabilityManifest, CapabilityManifestRegistry

from .models import SecurityReviewResult
from .permits import ExecutionPermitStore


_INFRASTRUCTURE_TOOLS = {
    "audit_privacy_trajectory",
    "detect_sensitive_data",
    "evaluate_data_policy",
    "final_answer",
    "mask_text",
    "pseudonymize_text",
    "redact_text",
    "sanitize_text",
    "tokenize_sensitive_data",
    "trace_data_lineage",
}


class SecurityReviewEngine:
    """Bind route, intent, manifest, arguments and lineage to one permit."""

    def __init__(
        self,
        *,
        router: PrivacyRouter,
        intent_guard: IntentGuard,
        manifests: CapabilityManifestRegistry,
        permits: ExecutionPermitStore,
        lineage_tracker: Any,
        audit_logger: Any,
        gateway: Any,
        context: Any,
        policy_version: str = "unknown",
    ) -> None:
        self.router = router
        self.intent_guard = intent_guard
        self.manifests = manifests
        self.permits = permits
        self.lineage_tracker = lineage_tracker
        self.audit_logger = audit_logger
        self.gateway = gateway
        self.context = context
        self.policy_version = str(policy_version)

    def register_tools(self, tools: list[Any]) -> None:
        for tool in tools:
            self.manifests.register_tool(tool)

    def preflight(
        self,
        tool: Any,
        arguments: Any,
        context: Any,
        intent: IntentSpec,
    ) -> SecurityReviewResult:
        name = str(getattr(tool, "name", "unknown"))
        if context is not self.context or getattr(tool, "context", None) is not self.context:
            return self._blocked(context, "CAPABILITY_CONTEXT_MISMATCH")
        if getattr(tool, "gateway", None) is not self.gateway:
            return self._blocked(context, "CAPABILITY_GATEWAY_MISMATCH")
        try:
            envelope = self.intent_guard.validate_intent(
                intent,
                run_id=getattr(context, "run_id"),
            )
        except Exception:
            return self._blocked(context, "INVALID_INTENT_ENVELOPE")
        if not envelope.allowed:
            return self._blocked(context, envelope.code, intent=envelope)
        try:
            tool.gateway.authorization.authorize_tool(name)
            manifest = self.manifests.get(name)
        except Exception:
            return self._blocked(context, "CAPABILITY_NOT_REGISTERED")
        if not manifest.matches_tool(tool):
            return self._blocked(context, "CAPABILITY_IMPLEMENTATION_CHANGED")
        route = self.router.route_tool(
            tool,
            arguments,
            context,
            operation=manifest.operation,
            destination_hint=getattr(context, "destination", None),
        )
        if not route.allowed:
            return self._blocked(context, route.reason_code, route=route)
        if not self._route_matches_manifest(route, manifest):
            return self._blocked(context, "CAPABILITY_ROUTE_MISMATCH", route=route)

        operation = self._operation(manifest, intent, name)
        effects = tuple(Effect(value.upper()) for value in manifest.effects)
        fields = self._fields(arguments)
        lineage = self._lineage_report(context)
        if lineage is None:
            return self._blocked(context, "LINEAGE_UNAVAILABLE", route=route)
        taints = ("PROMPT_INJECTION",) if getattr(lineage, "tainted_artifact_ids", ()) else ()
        request = ActionRequest(
            request_id="action_" + secrets.token_hex(16),
            run_id=intent.run_id,
            intent_id=intent.intent_id,
            version=intent.version,
            operation=operation,
            capability=name,
            effects=effects,
            fields=fields,
            destination=route.destination,
            recipient=route.recipient,
            lineage_taints=taints,
        )
        if name in _INFRASTRUCTURE_TOOLS:
            intent_decision = IntentDecision(
                allowed=True,
                code="PRIVACY_INFRASTRUCTURE_ALLOWED",
                reason="The capability is part of the mandatory privacy boundary.",
                intent_id=intent.intent_id,
                request_id=request.request_id,
                version=intent.version,
            )
        elif manifest.operation == "execute" and name != "safe_run_command":
            # A custom implementation is part of the trusted host TCB. It may
            # only use the internal route and still receives the Agent's
            # mandatory input/output guards.
            if route.external:
                return self._blocked(context, "CUSTOM_CAPABILITY_EXTERNAL_ROUTE", route=route)
            if not self._custom_capability_in_host_scope(context, manifest, route):
                return self._blocked(context, "CUSTOM_CAPABILITY_OUTSIDE_HOST_SCOPE", route=route)
            intent_decision = IntentDecision(
                allowed=True,
                code="HOST_REGISTERED_INTERNAL_CAPABILITY",
                reason="The host registered this implementation for an internal route.",
                intent_id=intent.intent_id,
                request_id=request.request_id,
                version=intent.version,
            )
        else:
            intent_decision = self.intent_guard.evaluate(intent, request, lineage=lineage, consume=False)
        if not intent_decision.allowed:
            return self._blocked(context, intent_decision.code, route=route, intent=intent_decision)
        if taints and (
            route.external or any(effect in {Effect.EXTERNAL, Effect.NETWORK, Effect.MESSAGE} for effect in effects)
        ):
            return self._blocked(context, "INJECTION_LINEAGE_BLOCKED", route=route, intent=intent_decision)

        operation_event = None
        try:
            operation_event = self.lineage_tracker.prepare_operation(
                arguments,
                context,
                operation_name=name,
                tool_name=name,
                destination=route.destination,
            )
            prepared_lineage = self._lineage_report(context)
            if prepared_lineage is None:
                raise RuntimeError("Lineage integrity is unavailable after prepare")
            lineage_ids = self._lineage_binding(prepared_lineage)
            permit = self.permits.issue(
                run_id=intent.run_id,
                intent_id=intent.intent_id,
                intent_version=intent.version,
                capability=name,
                manifest_digest=manifest.digest,
                arguments=arguments,
                destination=route.destination,
                recipient=route.recipient,
                lineage_ids=lineage_ids,
                policy_version=self.policy_version,
            )
        except Exception:
            if operation_event is not None:
                self._abort_safely(operation_event.operation_id, context)
            return self._blocked(context, "REVIEW_PREPARE_FAILED", route=route, intent=intent_decision)
        result = SecurityReviewResult(
            allowed=True,
            code="SECURITY_REVIEW_ALLOWED",
            reason="The exact guarded action received a single-use execution permit.",
            route=route,
            intent=intent_decision,
            permit=permit,
            operation_id=operation_event.operation_id,
            lineage_ids=lineage_ids,
        )
        if not self._audit(context, result):
            self._abort_safely(result.operation_id, context)
            return SecurityReviewResult(
                allowed=False,
                code="SECURITY_REVIEW_AUDIT_FAILED",
                reason="The review could not be persisted and execution was denied.",
                route=route,
                intent=intent_decision,
            )
        return result

    def consume(
        self, review: SecurityReviewResult, tool: Any, arguments: Any, context: Any, intent: IntentSpec
    ) -> bool:
        if not review.allowed or review.permit is None or review.route is None:
            return False
        if (
            context is not self.context
            or getattr(tool, "context", None) is not self.context
            or getattr(tool, "gateway", None) is not self.gateway
        ):
            self._abort_safely(review.operation_id, self.context)
            return False
        try:
            envelope = self.intent_guard.validate_intent(
                intent,
                run_id=getattr(context, "run_id"),
            )
            if not envelope.allowed:
                self._abort_safely(review.operation_id, context)
                return False
            manifest = self.manifests.get(str(getattr(tool, "name", "unknown")))
            if not manifest.matches_tool(tool):
                self._abort_safely(review.operation_id, context)
                return False
            current_route = self.router.route_tool(
                tool,
                arguments,
                context,
                operation=manifest.operation,
                destination_hint=getattr(context, "destination", None),
            )
            if (
                not current_route.allowed
                or current_route.route_kind is not review.route.route_kind
                or current_route.destination != review.route.destination
                or current_route.recipient != review.route.recipient
                or not self._route_matches_manifest(current_route, manifest)
            ):
                self._abort_safely(review.operation_id, context)
                return False
            current_lineage = self._lineage_report(context)
            if current_lineage is None or self._lineage_binding(current_lineage) != review.lineage_ids:
                self._abort_safely(review.operation_id, context)
                return False
            consumed = self.permits.consume(
                review.permit.permit_id,
                run_id=intent.run_id,
                intent_id=intent.intent_id,
                intent_version=intent.version,
                capability=manifest.name,
                manifest_digest=manifest.digest,
                arguments=arguments,
                destination=review.route.destination,
                recipient=review.route.recipient,
                lineage_ids=review.lineage_ids,
                policy_version=self.policy_version,
            )
            if not consumed or not self.manifests.reserve_call(intent.run_id, manifest.name):
                self._abort_safely(review.operation_id, context)
                return False
            return True
        except Exception:
            self._abort_safely(review.operation_id, context)
            return False

    def complete(self, review: SecurityReviewResult, output: Any, context: Any) -> bool:
        if not review.operation_id:
            return False
        try:
            self.lineage_tracker.commit_operation(review.operation_id, output, context=context)
        except Exception:
            try:
                self.lineage_tracker.mark_indeterminate(review.operation_id, context=context)
            except Exception:
                pass
            return False
        return True

    def fail(self, review: SecurityReviewResult, context: Any, *, indeterminate: bool) -> bool:
        if not review.operation_id:
            return False
        try:
            if indeterminate:
                self.lineage_tracker.mark_indeterminate(review.operation_id, context=context)
            else:
                self.lineage_tracker.abort_operation(review.operation_id, context=context)
        except Exception:
            return False
        return True

    @staticmethod
    def _operation(manifest: CapabilityManifest, intent: IntentSpec, name: str) -> IntentOperation:
        if name == "safe_llm_call":
            for candidate in (IntentOperation.ANALYZE, IntentOperation.SUMMARIZE, IntentOperation.SEND):
                if candidate in intent.allowed_operations:
                    return candidate
        return IntentOperation(manifest.operation.upper())

    @staticmethod
    def _fields(arguments: Any) -> tuple[str, ...]:
        if not isinstance(arguments, Mapping):
            return ()
        value = arguments.get("fields")
        if not isinstance(value, (tuple, list)):
            return ()
        return tuple(str(item).strip().casefold() for item in value if isinstance(item, str) and item.strip())

    @staticmethod
    def _route_matches_manifest(route: RouteDecision, manifest: CapabilityManifest) -> bool:
        return not manifest.destinations or any(
            fnmatch.fnmatchcase(route.destination.casefold(), pattern) for pattern in manifest.destinations
        )

    @staticmethod
    def _custom_capability_in_host_scope(
        context: Any,
        manifest: CapabilityManifest,
        route: RouteDecision,
    ) -> bool:
        """Honor explicit host ceilings while retaining legacy internal tools.

        Empty scope tuples predate intent enforcement and mean "not supplied".
        Once a host supplies an allow/deny scope, custom capabilities must
        satisfy it just like built-in tools.
        """

        dimensions = (
            (
                manifest.name,
                getattr(context, "allowed_capabilities", ()),
                getattr(context, "denied_capabilities", ()),
            ),
            (
                manifest.operation,
                getattr(context, "allowed_operations", ()),
                getattr(context, "denied_operations", ()),
            ),
            (
                route.destination,
                getattr(context, "allowed_destinations", ()),
                getattr(context, "denied_destinations", ()),
            ),
        )
        for value, allowed_values, denied_values in dimensions:
            normalized = value.casefold()
            allowed = tuple(str(item).strip().casefold() for item in (allowed_values or ()))
            denied = tuple(str(item).strip().casefold() for item in (denied_values or ()))
            if any(fnmatch.fnmatchcase(normalized, pattern) for pattern in denied):
                return False
            if allowed and not any(fnmatch.fnmatchcase(normalized, pattern) for pattern in allowed):
                return False
        allowed_effects = tuple(
            str(item).strip().casefold() for item in (getattr(context, "allowed_effects", ()) or ())
        )
        denied_effects = tuple(str(item).strip().casefold() for item in (getattr(context, "denied_effects", ()) or ()))
        for effect in manifest.effects:
            normalized = effect.casefold()
            if any(fnmatch.fnmatchcase(normalized, pattern) for pattern in denied_effects):
                return False
            if allowed_effects and not any(fnmatch.fnmatchcase(normalized, pattern) for pattern in allowed_effects):
                return False
        return True

    def _lineage_report(self, context: Any) -> Any:
        try:
            report = self.lineage_tracker.report(context)
        except Exception:
            return None
        return report if getattr(report, "chain_valid", False) is True else None

    @staticmethod
    def _lineage_binding(report: Any) -> tuple[str, ...]:
        artifact_ids = tuple(sorted(str(node.artifact_id) for node in getattr(report, "nodes", ())))
        events = tuple(getattr(report, "events", ()))
        if not events:
            return artifact_ids
        head = str(getattr(events[-1], "event_hash", ""))
        if not head:
            raise ValueError("The lineage report has no authenticated chain head")
        return (*artifact_ids, f"chain_head:{head}")

    def _blocked(
        self,
        context: Any,
        code: str,
        *,
        route: RouteDecision | None = None,
        intent: IntentDecision | None = None,
    ) -> SecurityReviewResult:
        result = SecurityReviewResult(
            allowed=False,
            code=code,
            reason="The proposed tool action failed deterministic security review.",
            route=route,
            intent=intent,
        )
        self._audit(context, result)
        return result

    def _audit(self, context: Any, result: SecurityReviewResult) -> bool:
        try:
            metadata = {}
            if result.intent and result.intent.intent_id:
                metadata["intent_id"] = result.intent.intent_id
            if result.permit:
                metadata["permit_id"] = result.permit.permit_id
                metadata["manifest_digest"] = result.permit.manifest_digest
            self.audit_logger.log(
                run_id=getattr(context, "run_id", "unknown"),
                event_type="security_review",
                stage="tool_input",
                tool=result.permit.capability if result.permit else None,
                destination=result.route.destination if result.route else None,
                status="ALLOWED" if result.allowed else "BLOCKED",
                reason=result.reason,
                metadata=metadata,
            )
        except Exception:
            return False
        return True

    def _abort_safely(self, operation_id: str | None, context: Any) -> None:
        if not operation_id:
            return
        try:
            self.lineage_tracker.abort_operation(operation_id, context=context)
        except Exception:
            pass


__all__ = ["SecurityReviewEngine"]
