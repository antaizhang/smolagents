"""Evaluate facts against a policy. Deterministically, and without a model.

The engine walks the rules in order, records every rule it considered and why
each one lost, and stops at the first match. That record is the decision path:
"why was this one blocked" is a thing you can print, attach to an audit event,
and hand to someone who was not in the room.

This module imports no model, no agent and no network client, and it never will
— the whole value of moving the decision out of a prompt is that the answer
depends on the rule file and nothing else. Two runs on the same fact and the
same context return the same verdict, forever.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ..facts import Finding
from .model import (
    DEFAULT_RULE_ID,
    Action,
    Decision,
    Expectation,
    Policy,
    RequestContext,
    RuleEvaluation,
)


@dataclass(frozen=True)
class ExpectationFailure:
    """One policy test vector that did not get the verdict it declared."""

    expectation: Expectation
    actual_action: Action
    actual_rule: str

    def describe(self) -> str:
        expected_rule = self.expectation.expect_rule
        detail = f"{self.actual_action} via {self.actual_rule}"
        wanted = f"{self.expectation.expect_action}"
        if expected_rule:
            wanted += f" via {expected_rule}"
        return f"{self.expectation.name}: expected {wanted}, got {detail}"


class PolicyEngine:
    """Turns facts into verdicts, one rule file at a time."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    @property
    def label(self) -> str:
        return self.policy.label

    def decide_label(
        self, label: str, confidence: float, context: RequestContext
    ) -> tuple[Action, str, tuple[RuleEvaluation, ...]]:
        """Resolve one ``label × confidence × context`` to an action and a path."""

        trace: list[RuleEvaluation] = []
        for rule in self.policy.rules:
            failure = rule.matches(label, confidence, context)
            if failure is None:
                trace.append(RuleEvaluation(rule.id, matched=True))
                return rule.action, rule.id, tuple(trace)
            trace.append(RuleEvaluation(rule.id, matched=False, failed_predicate=failure))
        trace.append(RuleEvaluation(DEFAULT_RULE_ID, matched=True))
        return self.policy.default_action, DEFAULT_RULE_ID, tuple(trace)

    def decide(self, finding: Finding, context: RequestContext) -> Decision:
        """Resolve one fact into a verdict carrying its own decision path."""

        action, rule_id, trace = self.decide_label(finding.label, finding.confidence, context)
        rule = self.policy.rule(rule_id)
        return Decision(
            label=finding.label,
            confidence=finding.confidence,
            span=(finding.span.start, finding.span.end),
            detector=finding.detector,
            tier=finding.tier,
            action=action,
            rule_id=rule_id,
            reason=rule.reason if rule is not None else self.policy.default_reason,
            alert=rule.alert if rule is not None else False,
            restore_on_response=rule.restore_on_response if rule is not None else False,
            policy_label=self.policy.label,
            policy_fingerprint=self.policy.fingerprint(),
            context=context,
            trace=trace,
        )

    def decide_all(self, findings: Iterable[Finding], context: RequestContext) -> tuple[Decision, ...]:
        return tuple(self.decide(finding, context) for finding in findings)

    def self_test(self, expectations: Sequence[Expectation] | None = None) -> list[ExpectationFailure]:
        """Run the test vectors the policy ships with.

        Returns the failures, so a caller can assert on an empty list in CI and
        get every mismatch at once instead of one per run.
        """

        failures: list[ExpectationFailure] = []
        for expectation in expectations if expectations is not None else self.policy.expectations:
            action, rule_id, _ = self.decide_label(expectation.label, expectation.confidence, expectation.context)
            if action is not expectation.expect_action or (
                expectation.expect_rule is not None and rule_id != expectation.expect_rule
            ):
                failures.append(ExpectationFailure(expectation, action, rule_id))
        return failures

    def unreachable_rules(self) -> tuple[str, ...]:
        """Rules that a strictly broader earlier rule already shadows.

        First-match-wins makes ordering load-bearing; a rule that can never be
        reached is a review finding, not a runtime error.
        """

        shadowed: list[str] = []
        for index, rule in enumerate(self.policy.rules):
            for earlier in self.policy.rules[:index]:
                if _covers(earlier.condition, rule.condition):
                    shadowed.append(rule.id)
                    break
        return tuple(shadowed)

    def __repr__(self) -> str:
        return f"<PolicyEngine policy={self.policy.label} rules={len(self.policy.rules)}>"


def _covers(broad, narrow) -> bool:
    """True when everything ``narrow`` matches, ``broad`` matches too."""

    for name in ("labels", "destinations", "caller_roles", "purposes", "kinds"):
        broad_values = getattr(broad, name)
        narrow_values = getattr(narrow, name)
        if not broad_values:
            continue
        if not narrow_values or not narrow_values <= broad_values:
            return False
    return broad.min_confidence <= narrow.min_confidence and broad.max_confidence >= narrow.max_confidence


__all__ = ["ExpectationFailure", "PolicyEngine"]
