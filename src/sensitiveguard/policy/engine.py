"""Deterministic SensitiveGuard policy engine."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from pathlib import Path

from sensitiveguard.detector.labels import INJECTION_LABEL, SECRET_LABELS
from sensitiveguard.models import (
    Action,
    DecisionSet,
    Finding,
    GuardStage,
    PolicyDecision,
    Severity,
)
from sensitiveguard.policy.defaults import default_policy_rules
from sensitiveguard.policy.loader import load_policy_config
from sensitiveguard.policy.rules import PolicyRule
from sensitiveguard.privacy.context import PrivacyContext
from sensitiveguard.privacy.necessity import NecessityChecker
from sensitiveguard.privacy.risk import RiskEngine


_TRANSFORM_ACTIONS = {
    Action.MASK,
    Action.REDACT,
    Action.PSEUDONYMIZE,
    Action.TOKENIZE,
    Action.GENERALIZE,
}

_EGRESS_STAGES = {
    GuardStage.DATA_ACQUISITION,
    GuardStage.TOOL_INPUT,
    GuardStage.FINAL_OUTPUT,
    GuardStage.HANDOFF,
    GuardStage.MCP_INPUT,
    GuardStage.MCP_OUTPUT,
}

_INTERNAL_DESTINATIONS = frozenset(
    {
        "agent_memory",
        "database",
        "internal",
        "internal_database",
        "internal_file",
        "local",
        "memory",
        "rag",
    }
)

_MASK_BY_DEFAULT = frozenset(
    {
        "PASSPORTID",
        "IDCARD",
        "DRIVERID",
        "INSURANCEID",
        "HEALTHCARD",
        "RESIDENCEID",
        "MILITARYID",
        "TAXID",
        "VISAAUTH",
        "SOCIALID",
        "MOBILE",
        "EMAIL",
        "LICENSEPLATE",
        "VIN",
        "FAX",
        "TEL",
        "IPV4",
        "IPV6",
        "MAC",
        "IMEI",
        "IMSI",
        "MEID",
        "OUTPATIENTID",
        "PATIENTID",
    }
)


class PolicyEngine:
    """Evaluate normalized findings against ordered deterministic rules."""

    def __init__(
        self,
        rules: Iterable[PolicyRule] | None = None,
        *,
        necessity_checker: NecessityChecker | None = None,
        risk_engine: RiskEngine | None = None,
        known_external_destinations: Iterable[str] = ("external_llm",),
        policy_version: str = "builtin-v1",
    ) -> None:
        supplied_rules = default_policy_rules() if rules is None else tuple(rules)
        if any(not isinstance(rule, PolicyRule) for rule in supplied_rules):
            raise TypeError("PolicyEngine rules must be PolicyRule instances")
        indexed = list(enumerate(supplied_rules))
        indexed.sort(key=lambda item: (-item[1].priority, -item[1].specificity, item[0]))
        self.rules = tuple(rule for _, rule in indexed)
        self.necessity_checker = necessity_checker or NecessityChecker()
        self.risk_engine = risk_engine or RiskEngine()
        self.known_external_destinations = tuple(
            str(destination).strip().casefold() for destination in known_external_destinations
        )
        self.policy_version = str(policy_version)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        **kwargs: object,
    ) -> PolicyEngine:
        config = load_policy_config(Path(path))
        return cls(config.rules, policy_version=config.version, **kwargs)

    def evaluate(
        self,
        findings: Iterable[Finding],
        context: PrivacyContext,
        stage: GuardStage,
        destination: str | None = None,
        recipient: str | None = None,
    ) -> DecisionSet:
        if not isinstance(context, PrivacyContext):
            raise TypeError("PolicyEngine.evaluate expects a PrivacyContext")
        if not isinstance(stage, GuardStage):
            stage = GuardStage(str(stage))

        changes: dict[str, str | None] = {}
        if destination is not None:
            changes["destination"] = destination
        if recipient is not None:
            changes["recipient"] = recipient
        effective_context = context.with_overrides(**changes) if changes else context

        decisions: list[PolicyDecision] = []
        for finding in findings:
            if not isinstance(finding, Finding):
                raise TypeError("PolicyEngine.evaluate findings must contain Finding instances")
            necessity = self.necessity_checker.check(finding, effective_context)
            risk = self.risk_engine.assess(finding, effective_context, necessity.necessary)
            rule = self._matching_rule(
                finding,
                effective_context,
                stage,
                necessity.necessary,
                risk.score,
                destination=destination,
                recipient=recipient,
            )
            action, reason, policy_id, severity, allowed_after_transform = self._resolve(
                finding,
                effective_context,
                stage,
                necessity.necessary,
                necessity.reason,
                rule,
            )
            decisions.append(
                PolicyDecision(
                    finding=finding,
                    action=action,
                    reason=reason,
                    policy_id=policy_id,
                    severity=severity,
                    allowed_after_transform=allowed_after_transform,
                    necessary=necessity.necessary,
                    risk=risk,
                )
            )
        return DecisionSet(tuple(decisions))

    def _matching_rule(
        self,
        finding: Finding,
        context: PrivacyContext,
        stage: GuardStage,
        necessary: bool,
        risk_score: float,
        *,
        destination: str | None,
        recipient: str | None,
    ) -> PolicyRule | None:
        for rule in self.rules:
            if rule.matches(
                finding,
                context,
                stage,
                necessary=necessary,
                risk_score=risk_score,
                destination=destination,
                recipient=recipient,
            ):
                return rule
        return None

    def _resolve(
        self,
        finding: Finding,
        context: PrivacyContext,
        stage: GuardStage,
        necessary: bool,
        necessity_reason: str,
        rule: PolicyRule | None,
    ) -> tuple[Action, str, str, Severity, bool]:
        # Context authorization and injection findings are non-overridable.
        if context.is_forbidden(finding.label):
            return (
                Action.BLOCK,
                f"{finding.label} is explicitly forbidden by the privacy context",
                "SG-CONTEXT-FORBIDDEN",
                finding.severity,
                False,
            )
        if finding.label == INJECTION_LABEL:
            return (
                Action.BLOCK,
                "Prompt-injection content cannot authorize tool execution or disclosure",
                "SG-INJECTION-001",
                Severity.CRITICAL,
                False,
            )

        if rule is not None:
            allowed = rule.allowed_after_transform
            if allowed is None:
                allowed = rule.action is Action.ALLOW or rule.action in _TRANSFORM_ACTIONS
            return (
                rule.action,
                rule.reason,
                rule.policy_id,
                rule.severity or finding.severity,
                bool(allowed),
            )

        if self._is_unknown_external(context):
            return (
                Action.BLOCK,
                "No explicit policy authorizes sensitive data for this external destination",
                "SG-EXTERNAL-DEFAULT-DENY",
                finding.severity,
                False,
            )

        action, policy_id = self._fallback_action(finding, context, stage, necessary)
        allowed = action is Action.ALLOW or action in _TRANSFORM_ACTIONS
        if action is Action.REQUIRE_APPROVAL:
            reason = f"{finding.label} is necessary but requires approval across this trust boundary"
        elif action is Action.ALLOW:
            reason = necessity_reason
        else:
            reason = f"{necessity_reason}; applying {action.value}"
        return action, reason, policy_id, finding.severity, allowed

    def _fallback_action(
        self,
        finding: Finding,
        context: PrivacyContext,
        stage: GuardStage,
        necessary: bool,
    ) -> tuple[Action, str]:
        if not necessary:
            if stage is GuardStage.DATA_ACQUISITION:
                return Action.BLOCK, "SG-MINIMIZE-NOT-ACQUIRE"
            if finding.label in SECRET_LABELS:
                if stage in _EGRESS_STAGES or stage is GuardStage.MEMORY:
                    return Action.BLOCK, "SG-SECRET-BLOCK"
                return Action.REDACT, "SG-SECRET-REDACT"
            if finding.label in {"BANKACCOUNT", "FINACCOUNT"}:
                return Action.TOKENIZE, "SG-MINIMIZE-TOKENIZE"
            if finding.label == "NAME":
                return Action.PSEUDONYMIZE, "SG-MINIMIZE-PSEUDONYMIZE"
            if finding.label == "ADDRESS":
                return Action.GENERALIZE, "SG-MINIMIZE-GENERALIZE"
            if finding.label in _MASK_BY_DEFAULT:
                return Action.MASK, "SG-MINIMIZE-MASK"
            return Action.REDACT, "SG-MINIMIZE-REDACT"

        if (
            stage in _EGRESS_STAGES
            and context.crosses_trust_boundary
            and finding.severity
            in {
                Severity.HIGH,
                Severity.CRITICAL,
            }
        ):
            return Action.REQUIRE_APPROVAL, "SG-EXTERNAL-APPROVAL"
        return Action.ALLOW, "SG-NECESSARY-ALLOW"

    def _is_unknown_external(self, context: PrivacyContext) -> bool:
        destination = (context.destination or "").strip().casefold()
        if not destination:
            return False
        if destination in _INTERNAL_DESTINATIONS:
            return False
        if any(fnmatch.fnmatchcase(destination, pattern) for pattern in self.known_external_destinations):
            return False
        if destination.startswith(("internal_", "local_")):
            return False
        return context.crosses_trust_boundary or destination.startswith(
            ("http:", "https:", "message:", "mcp:", "agent:")
        )


__all__ = ["PolicyEngine"]
