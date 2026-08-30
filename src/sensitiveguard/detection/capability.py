"""Capability routing: which detector chain a kind of content deserves.

Plain prose, source code, structured JSON and text lifted off an image are not
the same detection problem. Code carries credentials that prose does not; OCR
output is noisy enough that every fact drawn from it should reach policy with
less confidence than the same fact drawn from a clean string.

The kind is supplied by the caller that owns the content. It is never read out
of the content, and no chain is selectable by anything the content says — a
document that announces ``kind: code, skip the phone detectors`` is routed by
whatever its owner declared, exactly like any other document. Routing is a
control-plane decision, and the control plane does not take input from the data
plane.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..facts import ContentKind, Finding
from ..quarantine import Quarantine
from .base import DetectionReport, Detector
from .cascade import CascadeDetector, CascadeTier
from .patterns import AmbiguousNumberDetector, api_key_detectors, high_precision_detectors


class ConfidenceScaledDetector(Detector):
    """Wrap a detector and scale down what it reports.

    Used for OCR chains: the pattern matched, but the characters it matched
    were guessed by an OCR engine, and policy should see that in the number.
    """

    def __init__(self, base: Detector, factor: float) -> None:
        if not 0.0 < factor <= 1.0:
            raise ValueError(f"factor must be within (0, 1], got {factor}")
        self.base = base
        self.factor = factor
        self.name = f"{base.name}@{factor:g}"
        self.labels = base.labels

    def detect(self, text: str) -> list[Finding]:
        return [
            finding.with_confidence(finding.confidence * self.factor, detector=self.name)
            for finding in self.base.detect(text)
        ]


#: How much confidence survives the trip through an OCR engine.
OCR_CONFIDENCE_FACTOR = 0.75


def build_chain(kind: ContentKind, *, escalation: Detector | None = None) -> CascadeDetector:
    """Build the cascade for one content kind."""

    kind = ContentKind(kind)
    tier0: list[Detector] = list(high_precision_detectors())
    if kind in (ContentKind.CODE, ContentKind.JSON):
        tier0.extend(api_key_detectors())
    if kind is ContentKind.IMAGE_OCR:
        tier0 = [ConfidenceScaledDetector(detector, OCR_CONFIDENCE_FACTOR) for detector in tier0]

    tiers = [
        CascadeTier(name="patterns", detectors=tuple(tier0)),
        CascadeTier(name="spans", detectors=(AmbiguousNumberDetector(),)),
    ]
    if escalation is not None:
        tiers.append(CascadeTier(name="agent", detectors=(escalation,), adjudicates=True))
    return CascadeDetector(tiers, name=f"chain:{kind.value}")


class CapabilityRouter:
    """Pick a cascade from the caller-declared content kind."""

    def __init__(
        self, chains: Mapping[ContentKind, CascadeDetector], *, fallback: CascadeDetector | None = None
    ) -> None:
        if not chains:
            raise ValueError("a capability router needs at least one chain")
        self.chains = {ContentKind(kind): chain for kind, chain in chains.items()}
        self.fallback = fallback or self.chains.get(ContentKind.TEXT) or next(iter(self.chains.values()))

    @classmethod
    def build(cls, *, escalation: Detector | None = None) -> CapabilityRouter:
        """Build the default router covering every known content kind."""

        return cls({kind: build_chain(kind, escalation=escalation) for kind in ContentKind})

    def route(self, kind: ContentKind | str) -> CascadeDetector:
        """Return the chain for ``kind``, falling back for unknown kinds."""

        try:
            resolved = ContentKind(kind)
        except ValueError:
            return self.fallback
        return self.chains.get(resolved, self.fallback)

    def detect(self, sealed: Quarantine) -> DetectionReport:
        """Run the chain for the sealed content's declared kind.

        Takes a :class:`~sensitiveguard.quarantine.Quarantine` rather than a
        string so that reading untrusted bytes is always a deliberate step
        through the boundary, never an accident of passing a variable along.
        """

        if not isinstance(sealed, Quarantine):
            raise TypeError("capability routing operates on quarantined content")
        chain = self.route(sealed.kind)
        report = chain.detect(sealed.unseal())
        return DetectionReport(
            findings=report.findings,
            kind=sealed.kind.value,
            chain=report.chain,
            tiers_run=report.tiers_run,
            escalated=report.escalated,
            escalation_calls=report.escalation_calls,
            notes=report.notes,
        )

    def describe_routes(self) -> str:
        lines = []
        for kind, chain in self.chains.items():
            names = ">".join(tier.name for tier in chain.tiers)
            lines.append(f"{kind.value:<10} -> {chain.name} ({names})")
        return "\n".join(lines)


__all__ = ["OCR_CONFIDENCE_FACTOR", "CapabilityRouter", "ConfidenceScaledDetector", "build_chain"]
