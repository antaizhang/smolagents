"""Deterministic data-minimization decisions."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from sensitiveguard.models import Finding, NecessityDecision
from sensitiveguard.privacy.context import PrivacyContext


def _normalize_requirements(
    requirements: Mapping[str, Iterable[str]] | None,
) -> dict[str, frozenset[str]]:
    normalized: dict[str, frozenset[str]] = {}
    for purpose, labels in (requirements or {}).items():
        if isinstance(labels, str):
            labels = (labels,)
        normalized[str(purpose).strip().casefold()] = frozenset(str(label).strip().casefold() for label in labels)
    return normalized


class NecessityChecker:
    """Resolve necessity from explicit context and static purpose rules.

    Unknown fields are unnecessary by default. This is intentional: an LLM's
    claim that a value is useful must not silently expand the authorized scope.
    """

    def __init__(self, purpose_requirements: Mapping[str, Iterable[str]] | None = None) -> None:
        self.purpose_requirements = _normalize_requirements(purpose_requirements)

    def check(self, finding: Finding, context: PrivacyContext) -> NecessityDecision:
        if not isinstance(finding, Finding):
            raise TypeError("NecessityChecker.check expects a Finding")
        if not isinstance(context, PrivacyContext):
            raise TypeError("NecessityChecker.check expects a PrivacyContext")

        label = finding.label
        if context.is_forbidden(label):
            return NecessityDecision(label, False, f"{label} is explicitly forbidden by the privacy context")
        if not context.scope_allows(label):
            return NecessityDecision(label, False, f"{label} is outside the authorized data scope")
        if context.is_required(label):
            return NecessityDecision(label, True, f"{label} is explicitly required for the task")

        purpose_labels = self.purpose_requirements.get(context.purpose.casefold(), frozenset())
        if label.casefold() in purpose_labels or "*" in purpose_labels:
            return NecessityDecision(label, True, f"{label} is required by purpose policy {context.purpose!r}")
        if context.is_optional(label):
            return NecessityDecision(label, False, f"{label} is optional and not necessary for the task")
        return NecessityDecision(label, False, f"{label} is not declared necessary for purpose {context.purpose!r}")

    def check_many(self, findings: Iterable[Finding], context: PrivacyContext) -> tuple[NecessityDecision, ...]:
        return tuple(self.check(finding, context) for finding in findings)


__all__ = ["NecessityChecker"]
