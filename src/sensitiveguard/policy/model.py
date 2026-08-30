"""The policy data model: declarative, versioned, diffable, testable.

A detector says ``span=[12,23], label=PHONE, conf=0.87``. That is a fact. What
to do about it — pass it through, mask it, tokenise it, block it, hand it to a
human — is a different question with a different answer for every destination
the fact might travel to.

That second question is deliberately kept away from a model. Not because a model
would answer it badly, but because an answer has to be auditable: a rule set can
be reviewed, versioned, diffed between releases and unit-tested, and it can print
the exact path that led to a verdict. The same decision expressed as a prompt
changes behaviour when the model changes, cannot be diffed, and leaves nothing to
regression-test.

Everything in this module is inert data. Nothing in it imports a model.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    """What a verdict does to one fact."""

    ALLOW = "allow"
    MASK = "mask"
    HASH = "hash"
    TOKENIZE = "tokenize"
    BLOCK = "block"
    REVIEW = "review"

    def __str__(self) -> str:
        return self.value


#: Rule id recorded on a verdict that fell through to the policy default.
DEFAULT_RULE_ID = "__default__"

#: Actions that rewrite the span in place.
TRANSFORMING_ACTIONS = frozenset({Action.MASK, Action.HASH, Action.TOKENIZE})

#: Actions that stop the content from being released at all.
WITHHOLDING_ACTIONS = frozenset({Action.BLOCK, Action.REVIEW})

#: The only action whose output can be turned back into the original value.
#: Masking and hashing are one-way by construction; tokenisation is reversible
#: because a vault holds the mapping. Whether a response is actually restored is
#: a separate policy switch — see :attr:`Rule.restore_on_response`.
REVERSIBLE_ACTIONS = frozenset({Action.TOKENIZE})

#: Used only to resolve two verdicts landing on overlapping spans: the more
#: protective one wins.
_SEVERITY = {
    Action.ALLOW: 0,
    Action.TOKENIZE: 1,
    Action.HASH: 2,
    Action.MASK: 3,
    Action.REVIEW: 4,
    Action.BLOCK: 5,
}


def severity(action: Action) -> int:
    return _SEVERITY[action]


@dataclass(frozen=True)
class RequestContext:
    """Everything about the request that is *not* the content.

    These values are supplied by the caller that owns the request — the tool
    gateway, the log writer, the editor session. None of them is ever parsed out
    of the content being inspected, which is what stops a document from choosing
    its own destination and talking its way past the rules that guard the real
    one.
    """

    destination: str
    caller_role: str
    purpose: str = "unspecified"
    kind: str = "text"

    def __post_init__(self) -> None:
        for name in ("destination", "caller_role", "purpose", "kind"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")

    def as_dict(self) -> dict[str, str]:
        return {
            "destination": self.destination,
            "caller_role": self.caller_role,
            "purpose": self.purpose,
            "kind": self.kind,
        }

    def describe(self) -> str:
        return " ".join(f"{key}={value}" for key, value in self.as_dict().items())


@dataclass(frozen=True)
class Condition:
    """When a rule applies.

    An empty set matches anything, so a rule states only what it actually cares
    about. Confidence is a closed interval: ``min_confidence`` is inclusive so a
    threshold reads the way a reviewer expects it to.
    """

    labels: frozenset[str] = frozenset()
    destinations: frozenset[str] = frozenset()
    caller_roles: frozenset[str] = frozenset()
    purposes: frozenset[str] = frozenset()
    kinds: frozenset[str] = frozenset()
    min_confidence: float = 0.0
    max_confidence: float = 1.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_confidence <= 1.0:
            raise ValueError(f"min_confidence must be within [0, 1], got {self.min_confidence}")
        if not 0.0 <= self.max_confidence <= 1.0:
            raise ValueError(f"max_confidence must be within [0, 1], got {self.max_confidence}")
        if self.min_confidence > self.max_confidence:
            raise ValueError(
                f"min_confidence {self.min_confidence} is above max_confidence {self.max_confidence}: "
                "this condition can never match"
            )

    def evaluate(self, label: str, confidence: float, context: RequestContext) -> str | None:
        """Return ``None`` when the condition holds, else why it did not."""

        checks = (
            ("label", label, self.labels),
            ("destination", context.destination, self.destinations),
            ("caller_role", context.caller_role, self.caller_roles),
            ("purpose", context.purpose, self.purposes),
            ("kind", context.kind, self.kinds),
        )
        for name, value, allowed in checks:
            if allowed and value not in allowed:
                return f"{name} {value!r} not in {{{', '.join(sorted(allowed))}}}"
        if confidence < self.min_confidence:
            return f"confidence {confidence:.2f} below min_confidence {self.min_confidence:.2f}"
        if confidence > self.max_confidence:
            return f"confidence {confidence:.2f} above max_confidence {self.max_confidence:.2f}"
        return None

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for name in ("labels", "destinations", "caller_roles", "purposes", "kinds"):
            values = getattr(self, name)
            if values:
                data[name] = sorted(values)
        if self.min_confidence > 0.0:
            data["min_confidence"] = self.min_confidence
        if self.max_confidence < 1.0:
            data["max_confidence"] = self.max_confidence
        return data

    def describe(self) -> str:
        rendered = self.as_dict()
        if not rendered:
            return "anything"
        return ", ".join(f"{key}={value}" for key, value in rendered.items())


@dataclass(frozen=True)
class Rule:
    """One ``when → then`` row of the policy."""

    id: str
    action: Action
    condition: Condition = field(default_factory=Condition)
    reason: str = ""
    alert: bool = False
    restore_on_response: bool = False

    def __post_init__(self) -> None:
        if not self.id or not self.id.strip():
            raise ValueError("every rule needs a non-empty id")
        if not isinstance(self.action, Action):
            raise TypeError(f"rule {self.id!r}: action must be an Action, got {type(self.action).__name__}")
        if self.restore_on_response and self.action not in REVERSIBLE_ACTIONS:
            raise ValueError(
                f"rule {self.id!r}: restore_on_response requires a reversible action "
                f"({', '.join(sorted(action.value for action in REVERSIBLE_ACTIONS))}), got {self.action.value}"
            )

    @property
    def reversible(self) -> bool:
        return self.action in REVERSIBLE_ACTIONS

    def matches(self, label: str, confidence: float, context: RequestContext) -> str | None:
        return self.condition.evaluate(label, confidence, context)

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"id": self.id, "action": self.action.value}
        condition = self.condition.as_dict()
        if condition:
            data["when"] = condition
        if self.reason:
            data["reason"] = self.reason
        if self.alert:
            data["alert"] = True
        if self.restore_on_response:
            data["restore_on_response"] = True
        return data

    def describe(self) -> str:
        suffix = " +alert" if self.alert else ""
        if self.restore_on_response:
            suffix += " +restore"
        return f"{self.id}: when {self.condition.describe()} -> {self.action.value}{suffix}"


@dataclass(frozen=True)
class RuleEvaluation:
    """One step of the decision path: which rule was considered, and why it lost."""

    rule_id: str
    matched: bool
    failed_predicate: str | None = None

    def describe(self) -> str:
        if self.matched:
            return f"MATCH {self.rule_id}"
        return f"skip  {self.rule_id} ({self.failed_predicate})"


@dataclass(frozen=True)
class Expectation:
    """A test vector that ships inside the policy file.

    A policy that carries its own expected verdicts can be regression-tested the
    same way code is, and a rule reordering that changes an answer fails the
    build instead of surprising an auditor.
    """

    name: str
    label: str
    confidence: float
    context: RequestContext
    expect_action: Action
    expect_rule: str | None = None

    def describe(self) -> str:
        target = f" via {self.expect_rule}" if self.expect_rule else ""
        return f"{self.name}: {self.label}@{self.confidence:.2f} {self.context.describe()} -> {self.expect_action}{target}"


@dataclass(frozen=True)
class Policy:
    """An ordered, versioned rule set. First match wins."""

    name: str
    version: str
    rules: tuple[Rule, ...]
    default_action: Action = Action.REVIEW
    default_reason: str = "no rule matched; the policy fails closed"
    expectations: tuple[Expectation, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("a policy needs a name")
        if not self.version.strip():
            raise ValueError("a policy needs a version")
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(rule.id for rule in self.rules)

    def rule(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "default_action": self.default_action.value,
            "default_reason": self.default_reason,
            "rules": [rule.as_dict() for rule in self.rules],
        }

    def fingerprint(self) -> str:
        """A content hash of the rules, for pinning a verdict to an exact policy.

        Two deployments claiming the same version but disagreeing on a rule show
        up as different fingerprints in the audit trail.
        """

        canonical = json.dumps(self.as_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}"

    def describe(self) -> str:
        lines = [f"policy {self.label} fingerprint={self.fingerprint()}"]
        for index, rule in enumerate(self.rules, start=1):
            lines.append(f"  {index:>2}. {rule.describe()}")
        lines.append(f"  default -> {self.default_action.value}")
        return "\n".join(lines)


@dataclass(frozen=True)
class Decision:
    """A verdict about one fact, with the path that produced it."""

    label: str
    confidence: float
    span: tuple[int, int]
    detector: str
    tier: int
    action: Action
    rule_id: str
    reason: str
    alert: bool
    restore_on_response: bool
    policy_label: str
    policy_fingerprint: str
    context: RequestContext
    trace: tuple[RuleEvaluation, ...] = ()

    @property
    def reversible(self) -> bool:
        return self.action in REVERSIBLE_ACTIONS

    @property
    def transforms(self) -> bool:
        return self.action in TRANSFORMING_ACTIONS

    @property
    def withholds(self) -> bool:
        return self.action in WITHHOLDING_ACTIONS

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "span": list(self.span),
            "detector": self.detector,
            "tier": self.tier,
            "action": self.action.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "alert": self.alert,
            "reversible": self.reversible,
            "restore_on_response": self.restore_on_response,
            "policy": self.policy_label,
            "policy_fingerprint": self.policy_fingerprint,
            "context": self.context.as_dict(),
            "trace": [
                {"rule": step.rule_id, "matched": step.matched, "why": step.failed_predicate} for step in self.trace
            ],
        }

    def explain(self) -> str:
        """The printable answer to "why was this one blocked?"."""

        if self.transforms:
            verdict = f"{self.action.value} ({'reversible' if self.reversible else 'one-way'})"
        else:
            verdict = self.action.value
        lines = [
            f"fact    {self.label} span=[{self.span[0]},{self.span[1]}] conf={self.confidence:.2f} "
            f"detector={self.detector} tier={self.tier}",
            f"context {self.context.describe()}",
            f"policy  {self.policy_label} fingerprint={self.policy_fingerprint}",
        ]
        for step in self.trace:
            lines.append(f"  {step.describe()}")
        lines.append(f"verdict {verdict} by rule {self.rule_id}")
        if self.reason:
            lines.append(f"reason  {self.reason}")
        if self.alert:
            lines.append("alert   raised")
        if self.restore_on_response:
            lines.append("restore the original value when the response comes back")
        return "\n".join(lines)


__all__ = [
    "DEFAULT_RULE_ID",
    "REVERSIBLE_ACTIONS",
    "TRANSFORMING_ACTIONS",
    "WITHHOLDING_ACTIONS",
    "Action",
    "Condition",
    "Decision",
    "Expectation",
    "Policy",
    "RequestContext",
    "Rule",
    "RuleEvaluation",
    "severity",
]
