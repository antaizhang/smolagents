"""Composition and deterministic overlap resolution for detectors."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sensitiveguard.detector.base import Detector
from sensitiveguard.models import DetectionResult, Finding, Severity


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def _overlaps(left: Finding, right: Finding) -> bool:
    return left.start < right.end and right.start < left.end


def deduplicate_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Return a stable set of non-overlapping findings.

    Higher severity wins first, followed by confidence, covered span length,
    and original detector order. The final tuple is ordered by source span so
    transformation code can consume it predictably.
    """

    indexed = list(enumerate(findings))
    for _, finding in indexed:
        if not isinstance(finding, Finding):
            raise TypeError("Detectors must return Finding instances")

    ranked = sorted(
        indexed,
        key=lambda item: (
            -_SEVERITY_RANK[item[1].severity],
            -item[1].score,
            -(item[1].end - item[1].start),
            item[0],
            item[1].label,
        ),
    )

    selected: list[tuple[int, Finding]] = []
    for original_index, candidate in ranked:
        if any(_overlaps(candidate, accepted) for _, accepted in selected):
            continue
        selected.append((original_index, candidate))

    selected.sort(key=lambda item: (item[1].start, item[1].end, item[0], item[1].label))
    return tuple(finding for _, finding in selected)


class CompositeDetector(Detector):
    """Run multiple detectors and merge their findings deterministically."""

    name = "composite"

    def __init__(self, detectors: Iterable[Detector]) -> None:
        self.detectors = tuple(detectors)
        if any(not isinstance(detector, Detector) for detector in self.detectors):
            raise TypeError("CompositeDetector accepts Detector instances only")

    def detect(self, content: str, context: Any = None) -> DetectionResult:
        self.validate_content(content)
        findings: list[Finding] = []
        for detector in self.detectors:
            result = detector.detect(content, context=context)
            if not isinstance(result, DetectionResult):
                raise TypeError(f"{detector.name} returned {type(result).__name__}, expected DetectionResult")
            findings.extend(result.findings)
        return DetectionResult(deduplicate_findings(findings))


__all__ = ["CompositeDetector", "deduplicate_findings"]
