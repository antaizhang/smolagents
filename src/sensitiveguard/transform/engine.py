"""Deterministic span transformation engine."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sensitiveguard.models import Action, DecisionSet, PolicyDecision, Severity

from .generalize import generalize_value
from .mask import mask_value
from .pseudonymize import Pseudonymizer
from .redact import redact_value
from .tokenize import TokenVault


class TransformationError(RuntimeError):
    """Base class for transformation failures."""


class InvalidSpanError(TransformationError):
    """Raised when detector coordinates no longer match the supplied text."""


class TransformationBlockedError(TransformationError):
    """Raised when policy says content must not be transformed and released."""

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Policy {decision.policy_id} requires {decision.action.value}; transformed content cannot be released"
        )


@dataclass(frozen=True, slots=True)
class AppliedTransformation:
    label: str
    action: Action
    start: int
    end: int
    replacement: str
    policy_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "action": self.action.value,
            "start": self.start,
            "end": self.end,
            "replacement": self.replacement,
            "policy_id": self.policy_id,
        }


@dataclass(frozen=True, slots=True)
class TransformationResult:
    content: str
    transformations: tuple[AppliedTransformation, ...]

    @property
    def transformed(self) -> bool:
        return bool(self.transformations)

    def to_dict(self) -> dict[str, object]:
        return {
            "content": self.content,
            "transformed": self.transformed,
            "transformations": [item.to_dict() for item in self.transformations],
        }


@dataclass(slots=True)
class _DecisionCluster:
    start: int
    end: int
    decisions: list[PolicyDecision]


_TRANSFORM_ACTIONS = {
    Action.GENERALIZE,
    Action.MASK,
    Action.PSEUDONYMIZE,
    Action.REDACT,
    Action.TOKENIZE,
}
_ACTION_STRENGTH = {
    Action.GENERALIZE: 1,
    Action.MASK: 2,
    Action.PSEUDONYMIZE: 3,
    Action.TOKENIZE: 4,
    Action.REDACT: 5,
}
_SEVERITY_STRENGTH = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class TransformationEngine:
    """Apply policy decisions without allowing overlap order to leak text."""

    def __init__(
        self,
        *,
        pseudonymizer: Pseudonymizer | None = None,
        token_vault: TokenVault | None = None,
        mask_char: str = "*",
    ) -> None:
        self.pseudonymizer = pseudonymizer or Pseudonymizer()
        self.token_vault = token_vault or TokenVault()
        if len(mask_char) != 1:
            raise ValueError("mask_char must contain exactly one character")
        self.mask_char = mask_char

    def apply(
        self,
        text: str,
        decisions: DecisionSet | Iterable[PolicyDecision],
        run_id: str,
    ) -> str:
        """Return transformed text.

        Overlapping transform spans are merged, assigned the strongest action,
        and replaced from the end of the string to the beginning. Merging the
        union is conservative: a narrow REDACT cannot expose the remainder of
        a wider overlapping MASK span.
        """

        return self.apply_with_report(text, decisions, run_id).content

    def apply_with_report(
        self,
        text: str,
        decisions: DecisionSet | Iterable[PolicyDecision],
        run_id: str,
    ) -> TransformationResult:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if not run_id:
            raise ValueError("run_id must not be empty")

        policy_decisions = self._materialize(decisions)
        for decision in policy_decisions:
            self._validate_span(text, decision)
            if decision.action in {Action.BLOCK, Action.REQUIRE_APPROVAL}:
                raise TransformationBlockedError(decision)

        transform_decisions = [decision for decision in policy_decisions if decision.action in _TRANSFORM_ACTIONS]
        clusters = self._resolve_overlaps(transform_decisions)
        transformed = text
        applied: list[AppliedTransformation] = []

        for cluster in sorted(clusters, key=lambda item: (item.start, item.end), reverse=True):
            winner = self._strongest_decision(cluster.decisions)
            original = text[cluster.start : cluster.end]
            replacement = self._transform_value(original, winner, run_id)
            transformed = f"{transformed[: cluster.start]}{replacement}{transformed[cluster.end :]}"
            applied.append(
                AppliedTransformation(
                    label=winner.finding.label,
                    action=winner.action,
                    start=cluster.start,
                    end=cluster.end,
                    replacement=replacement,
                    policy_id=winner.policy_id,
                )
            )

        applied.sort(key=lambda item: (item.start, item.end, item.label, item.action.value))
        return TransformationResult(content=transformed, transformations=tuple(applied))

    @staticmethod
    def _materialize(decisions: DecisionSet | Iterable[PolicyDecision]) -> tuple[PolicyDecision, ...]:
        values = decisions.decisions if isinstance(decisions, DecisionSet) else tuple(decisions)
        if not all(isinstance(decision, PolicyDecision) for decision in values):
            raise TypeError("decisions must contain only PolicyDecision objects")
        return tuple(values)

    @staticmethod
    def _validate_span(text: str, decision: PolicyDecision) -> None:
        finding = decision.finding
        if finding.end > len(text):
            raise InvalidSpanError(
                f"Finding {finding.label} span ({finding.start}, {finding.end}) exceeds text length {len(text)}"
            )
        if finding.value and text[finding.start : finding.end] != finding.value:
            raise InvalidSpanError(f"Finding {finding.label} no longer matches text at its recorded span")

    @staticmethod
    def _resolve_overlaps(decisions: list[PolicyDecision]) -> list[_DecisionCluster]:
        ordered = sorted(
            decisions,
            key=lambda decision: (
                decision.finding.start,
                decision.finding.end,
                decision.finding.label,
                decision.action.value,
                decision.policy_id,
            ),
        )
        clusters: list[_DecisionCluster] = []
        for decision in ordered:
            start, end = decision.finding.start, decision.finding.end
            if not clusters or start >= clusters[-1].end:
                clusters.append(_DecisionCluster(start=start, end=end, decisions=[decision]))
                continue
            cluster = clusters[-1]
            cluster.end = max(cluster.end, end)
            cluster.decisions.append(decision)
        return clusters

    @staticmethod
    def _strongest_decision(decisions: list[PolicyDecision]) -> PolicyDecision:
        return sorted(
            decisions,
            key=lambda decision: (
                -_ACTION_STRENGTH[decision.action],
                -_SEVERITY_STRENGTH[decision.severity],
                -decision.finding.score,
                -(decision.finding.end - decision.finding.start),
                decision.finding.label,
                decision.policy_id,
                decision.finding.start,
                -decision.finding.end,
            ),
        )[0]

    def _transform_value(self, value: str, decision: PolicyDecision, run_id: str) -> str:
        label = decision.finding.label
        if decision.action is Action.MASK:
            return mask_value(value, label, mask_char=self.mask_char)
        if decision.action is Action.REDACT:
            return redact_value(label)
        if decision.action is Action.PSEUDONYMIZE:
            return self.pseudonymizer.pseudonymize(value, label, run_id)
        if decision.action is Action.TOKENIZE:
            return self.token_vault.tokenize(value, label, run_id)
        if decision.action is Action.GENERALIZE:
            return generalize_value(value, label)
        raise TransformationError(f"Unsupported transformation action: {decision.action.value}")

    def clear_run(self, run_id: str) -> None:
        self.pseudonymizer.clear_run(run_id)
        self.token_vault.clear_run(run_id)
