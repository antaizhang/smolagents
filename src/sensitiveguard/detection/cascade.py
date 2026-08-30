"""The confidence-gated model cascade.

A guard hangs off every tool call, so it cannot afford a generation per call.
Tiers run cheapest-first and each one only sees what the tiers below it could
not settle: patterns take the high-precision matches, a span model sweeps the
rest, and only spans that are still ambiguous reach a model.

Tiers come in two shapes, and the difference matters:

* **recall** tiers read the whole text and add facts. Patterns and span models
  live here.
* **adjudication** tiers are handed the ambiguous spans and nothing else. They
  answer one narrow question per span, which is what keeps a model call rare
  and short.

Two invariants hold no matter what the content says, and they are what make the
cascade safe to point at untrusted text:

* no tier may remove or weaken a **settled** fact;
* an adjudicating tier may only speak about the candidate spans it was handed.

An adjudicating tier does get to dismiss an *unsettled* candidate — deciding
ambiguous spans is the job it was escalated for. So the worst an injected
instruction can achieve from inside one is to decide one short ambiguous slice
its own way. It cannot clear a fact tier 0 settled, cannot invent a span it was
not asked about, and cannot reach the policy layer at all.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..facts import Finding, Span, sort_findings, strongest_per_span
from .base import DetectionReport, Detector, EscalationDetector


DEFAULT_SETTLE_CONFIDENCE = 0.6


@dataclass(frozen=True)
class CascadeTier:
    """One rung of the cascade.

    A finding at or above ``settle_confidence`` is a settled fact and stops
    here. Anything below it becomes a candidate for the next tier.
    """

    name: str
    detectors: tuple[Detector, ...]
    settle_confidence: float = DEFAULT_SETTLE_CONFIDENCE
    adjudicates: bool = False

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("a cascade tier needs a name")
        if not self.detectors:
            raise ValueError(f"cascade tier {self.name!r} has no detectors")
        if not 0.0 < self.settle_confidence <= 1.0:
            raise ValueError(f"settle_confidence must be within (0, 1], got {self.settle_confidence}")
        if self.adjudicates and not all(isinstance(detector, EscalationDetector) for detector in self.detectors):
            raise ValueError(f"adjudicating tier {self.name!r} needs detectors that accept candidate spans")


class CascadeDetector:
    """Run tiers in order, escalating only the spans that are still ambiguous."""

    def __init__(self, tiers: Sequence[CascadeTier], *, name: str = "cascade") -> None:
        if not tiers:
            raise ValueError("a cascade needs at least one tier")
        self.name = name
        self.tiers = tuple(tiers)

    @property
    def labels(self) -> frozenset[str]:
        return frozenset().union(*(detector.labels for tier in self.tiers for detector in tier.detectors))

    def detect(self, text: str) -> DetectionReport:
        settled: list[Finding] = []
        candidates: list[Finding] = []
        tiers_run: list[str] = []
        escalated: list[Span] = []
        escalation_calls = 0
        notes: list[str] = []

        for tier in self.tiers:
            if tier.adjudicates and not candidates:
                notes.append(f"tier {tier.name} skipped: nothing to escalate")
                continue

            tiers_run.append(tier.name)
            handed_over = tuple(candidates) if tier.adjudicates else ()
            produced: list[Finding] = []
            for detector in tier.detectors:
                if tier.adjudicates:
                    produced.extend(detector.review(text, handed_over))
                    escalation_calls += len(handed_over)
                else:
                    produced.extend(detector.detect(text))

            if tier.adjudicates:
                escalated.extend(finding.span for finding in handed_over)
                # An adjudicating tier only gets to speak about what it was asked about.
                produced = [
                    finding
                    for finding in produced
                    if any(finding.span.overlaps(candidate.span) for candidate in handed_over)
                ]

            # A settled fact is never removed or weakened by a later tier.
            produced = [
                finding for finding in produced if not any(finding.span.overlaps(fact.span) for fact in settled)
            ]

            newly_settled = [finding for finding in produced if finding.confidence >= tier.settle_confidence]
            still_unsure = [finding for finding in produced if finding.confidence < tier.settle_confidence]

            settled = strongest_per_span([*settled, *newly_settled])

            if tier.adjudicates:
                # Every span handed to an adjudicating tier is decided by it:
                # confirmations came back in `produced`, the rest are dismissed.
                # A tier that runs out of budget re-emits what it did not look
                # at, so a budget cut can never quietly open a hole.
                examined = {candidate.span for candidate in handed_over}
                candidates = [candidate for candidate in candidates if candidate.span not in examined]
            else:
                decided = {
                    candidate.span
                    for candidate in candidates
                    if any(candidate.span.overlaps(fact.span) for fact in newly_settled)
                }
                candidates = [candidate for candidate in candidates if candidate.span not in decided]

            candidates.extend(still_unsure)
            candidates = [
                candidate
                for candidate in strongest_per_span(candidates)
                if not any(candidate.span.overlaps(fact.span) for fact in settled)
            ]

        findings = strongest_per_span([*settled, *candidates])
        if candidates:
            notes.append(f"{len(candidates)} span(s) stayed below the settle threshold and reach policy unsettled")

        return DetectionReport(
            findings=tuple(sort_findings(findings)),
            chain=tuple(detector.name for tier in self.tiers for detector in tier.detectors),
            tiers_run=tuple(tiers_run),
            escalated=tuple(sorted(set(escalated))),
            escalation_calls=escalation_calls,
            notes=tuple(notes),
        )


__all__ = ["DEFAULT_SETTLE_CONFIDENCE", "CascadeDetector", "CascadeTier"]
