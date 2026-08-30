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

import itertools
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from ..facts import Finding
from .model import (
    DEFAULT_RULE_ID,
    Action,
    Condition,
    Decision,
    Expectation,
    Policy,
    RequestContext,
    Rule,
    RuleEvaluation,
)


#: How many candidate values the witness search will try per condition
#: dimension, and how many combinations in total. A policy is a small file; the
#: caps exist so a pathological one cannot turn a lint into a hang.
_MAX_CANDIDATES_PER_DIMENSION = 6
_MAX_WITNESS_COMBINATIONS = 4096


@dataclass(frozen=True)
class LintFinding:
    """One structural problem with a rule set, found without running traffic.

    ``severity`` is what a build should do about it:

    ``error``
        The rule set does not mean what it looks like it means. A dead rule, or
        an ``allow`` that did not say where it allows to.
    ``warning``
        Ordering is load-bearing here and nothing pins it, so reordering the
        file would silently change a verdict.
    ``info``
        Ordering is load-bearing here and an expectation already pins it, which
        is the state a reviewed policy is supposed to be in.
    """

    code: str
    severity: str
    rule_id: str
    message: str
    related: tuple[str, ...] = ()
    witness: dict[str, str] | None = None

    def describe(self) -> str:
        line = f"[{self.severity}] {self.code} {self.rule_id}: {self.message}"
        if self.witness:
            rendered = " ".join(f"{key}={value}" for key, value in self.witness.items())
            line += f" (witness: {rendered})"
        return line

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "rule": self.rule_id,
            "message": self.message,
            "related": list(self.related),
            "witness": dict(self.witness) if self.witness else None,
        }


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

    def lint(self) -> tuple[LintFinding, ...]:
        """Check the rule set for problems that traffic would not reveal.

        Three of them, in the order a reviewer cares about:

        ``unreachable``
            An earlier rule already covers everything this one matches, so this
            rule is dead. :meth:`unreachable_rules` is the same check.
        ``unscoped-allow``
            A rule that releases content without naming the destinations it
            releases to. It reads as "allow this everywhere" but usually means
            "allow this in the places the rules above did not already claim",
            which is a fact about line numbers, not about the policy. Naming the
            destinations makes the intent survive a reordering.
        ``order-sensitive`` / ``order-pinned``
            Two rules that both match the same request and disagree about what
            to do with it, where the file's order is the only thing deciding
            between them. Each finding carries a witness — a concrete
            ``label x confidence x context`` that both rules claim — so it can be
            checked rather than argued about. If one of the policy's own
            expectations already exercises that contested region, the finding is
            downgraded to ``order-pinned``: ordering still matters, but a
            regression test is holding it in place.
        """

        findings: list[LintFinding] = []
        rules = self.policy.rules

        for index, rule in enumerate(rules):
            for earlier in rules[:index]:
                if _covers(earlier.condition, rule.condition):
                    findings.append(
                        LintFinding(
                            code="unreachable",
                            severity="error",
                            rule_id=rule.id,
                            message=f"rule {earlier.id!r} already matches everything this rule matches",
                            related=(earlier.id,),
                        )
                    )
                    break

        for rule in rules:
            if rule.action is Action.ALLOW and not rule.condition.destinations:
                findings.append(
                    LintFinding(
                        code="unscoped-allow",
                        severity="error",
                        rule_id=rule.id,
                        message=(
                            "an allow rule must name the destinations it allows to; without them the rule "
                            "only means what it means because of the rules that happen to sit above it"
                        ),
                    )
                )

        shadowed = {finding.rule_id for finding in findings if finding.code == "unreachable"}
        for first, second in itertools.combinations(range(len(rules)), 2):
            earlier, later = rules[first], rules[second]
            if later.id in shadowed or earlier.action is later.action:
                continue
            witness = self._contested_witness(earlier, later)
            if witness is None:
                continue
            pinned = self._expectation_pinning(earlier, later)
            findings.append(
                LintFinding(
                    code="order-pinned" if pinned else "order-sensitive",
                    severity="info" if pinned else "warning",
                    rule_id=earlier.id,
                    message=(
                        f"both this rule and {later.id!r} match the same request and disagree "
                        f"({earlier.action.value} vs {later.action.value}); swapping them changes the verdict"
                        + (f", pinned by expectation {pinned!r}" if pinned else ", and no expectation pins it")
                    ),
                    related=(later.id,),
                    witness=witness,
                )
            )
        return tuple(findings)

    def _contested_witness(self, earlier: Rule, later: Rule) -> dict[str, str] | None:
        """Find a request both rules match and ``earlier`` currently wins.

        Returning a concrete request rather than a claim is the point: the
        finding can be pasted into a test. A candidate that some third rule
        catches first is discarded, so the search never reports a conflict the
        engine would not actually reach.
        """

        confidences = _confidence_candidates(earlier.condition, later.condition)
        if not confidences:
            return None
        dimensions = {
            "labels": self.policy.vocabulary or frozenset({"PHONE"}),
            "destinations": self.policy.destinations(),
            "caller_roles": self.policy.caller_roles(),
            "purposes": self.policy.purposes(),
            "kinds": frozenset({"text"})
            | frozenset(kind for rule in self.policy.rules for kind in rule.condition.kinds),
        }
        axes = []
        for name, universe in dimensions.items():
            values = _value_candidates(getattr(earlier.condition, name), getattr(later.condition, name), universe)
            if not values:
                return None
            axes.append(values)

        budget = _MAX_WITNESS_COMBINATIONS
        for label, destination, caller_role, purpose, kind in itertools.product(*axes):
            for confidence in confidences:
                budget -= 1
                if budget < 0:
                    return None
                context = RequestContext(destination=destination, caller_role=caller_role, purpose=purpose, kind=kind)
                if later.matches(label, confidence, context) is not None:
                    continue
                _, winner, _ = self.decide_label(label, confidence, context)
                if winner != earlier.id:
                    continue
                return {
                    "label": label,
                    "confidence": f"{confidence:.2f}",
                    "destination": destination,
                    "caller_role": caller_role,
                    "purpose": purpose,
                    "kind": kind,
                }
        return None

    def _expectation_pinning(self, earlier: Rule, later: Rule) -> str | None:
        """Name an expectation that already holds this contested region in place."""

        for expectation in self.policy.expectations:
            if later.matches(expectation.label, expectation.confidence, expectation.context) is not None:
                continue
            _, winner, _ = self.decide_label(expectation.label, expectation.confidence, expectation.context)
            if winner == earlier.id:
                return expectation.name
        return None

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
    if broad.min_confidence > narrow.min_confidence:
        return False
    if broad.max_confidence is None:
        return True
    return narrow.max_confidence is not None and narrow.max_confidence <= broad.max_confidence


#: Stands in for "any value at all" when neither rule constrains a dimension and
#: the policy never names one either. It has to be a real string, because the
#: witness is verified by running it through the engine, and it has to be one no
#: rule could match by accident.
UNCONSTRAINED = "__any__"


def _value_candidates(earlier: frozenset[str], later: frozenset[str], universe: frozenset[str]) -> list[str]:
    """Values both conditions accept for one dimension.

    An empty set on a condition means "anything", so it contributes no
    constraint; when neither side constrains the dimension the search falls back
    to the values the policy mentions elsewhere, because a value no rule names
    cannot be what makes two rules collide. If the policy names none either —
    no rule anywhere cares about the caller's role, say — the dimension is free,
    and the search says so rather than giving up: returning nothing here would
    make every pair look conflict-free for the silent reason that there was
    nothing to try.
    """

    if earlier and later:
        shared = earlier & later
    else:
        shared = earlier or later or universe
    if not shared:
        return [UNCONSTRAINED]
    return sorted(shared)[:_MAX_CANDIDATES_PER_DIMENSION]


def _confidence_candidates(earlier: Condition, later: Condition) -> list[float]:
    """Confidences inside both intervals: the ends, and the middle."""

    low = max(earlier.min_confidence, later.min_confidence)
    ceilings = [value for value in (earlier.max_confidence, later.max_confidence) if value is not None]
    high = min(ceilings) if ceilings else 1.0
    if low > high or (ceilings and low >= high):
        return []
    inside = {low, (low + high) / 2}
    if not ceilings:
        inside.add(high)
    return sorted(round(value, 6) for value in inside)


__all__ = ["UNCONSTRAINED", "ExpectationFailure", "LintFinding", "PolicyEngine"]
